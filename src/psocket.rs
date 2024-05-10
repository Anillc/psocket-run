use std::collections::HashMap;
use std::fmt::Debug;
use std::os::unix::process::CommandExt;
use std::process::Command;

use libc::user_regs_struct;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::sys::ptrace;
use nix::unistd::Pid;

use once_cell::sync::Lazy;

use crate::handlers::clone::CloneHandler;
use crate::handlers::fwmark::FwmarkHandler;
use crate::handlers::proxy::ProxyHandler;
use crate::handlers::rsrc::RsrcHandler;
use crate::utils::{get_fd, Result, PsocketError, Pidfd};
use crate::Config;

#[derive(Debug)]
pub(crate) struct Psocket {
    config: Config,
    handlers: Vec<Box<dyn SyscallHandler>>,
}

#[derive(Debug)]
pub(crate) struct Syscall {
    pub(crate) pid: Pid,
    pub(crate) regs: user_regs_struct,
    pub(crate) orig_rax: i64,
    pub(crate) rax: i32,
    pub(crate) socket_rax: Lazy<Result<Pidfd>, Box<dyn FnOnce() -> Result<Pidfd>>>,
    pub(crate) socket_rdi: Lazy<Result<Pidfd>, Box<dyn FnOnce() -> Result<Pidfd>>>,
}

pub(crate) trait SyscallHandler: Debug {
    unsafe fn handle(&mut self, syscall: &mut Syscall) -> Result<()>;
    fn process_exit(&mut self, pid: &Pid);
}

const WALL: Option<WaitPidFlag> = Some(WaitPidFlag::__WALL);

impl Psocket {

    pub(crate) fn new(config: Config) -> Psocket {
        Psocket {
            handlers: vec![
                Box::new(FwmarkHandler::new(config.clone())),
                Box::new(RsrcHandler::new(config.clone())),
                Box::new(ProxyHandler::new(config.clone())),
                Box::new(CloneHandler::new(config.clone())),
            ],
            config,
        }
    }

    unsafe fn handle_syscall(&mut self, pid: Pid, tgid: Pid) -> Result<()> {
        let regs = ptrace::getregs(pid).map_err(|_| PsocketError::SyscallFailed)?;
        let rax = regs.rax as i32;
        let rdi = regs.rdi as i32;
        let mut syscall = Syscall {
            pid, regs, rax,
            orig_rax: regs.orig_rax as i64,
            socket_rax: Lazy::new(Box::new(move || get_fd(tgid, rax))),
            socket_rdi: Lazy::new(Box::new(move || get_fd(tgid, rdi))),
        };
        let success = self.handlers.iter_mut()
            .map(|handler| handler.handle(&mut syscall))
            .all(|result| result.is_ok());
        if regs != syscall.regs {
            ptrace::setregs(syscall.pid, syscall.regs).map_err(|_| PsocketError::SyscallFailed)?;
        }
        if success { Ok(()) } else { Err(PsocketError::SyscallFailed) }
    }

    pub(crate) fn child(&self) {
        ptrace::traceme().unwrap();
        Command::new("/bin/sh").args(["-c", self.config.command.as_str()]).exec();
    }

    pub(crate) fn parent(&mut self, child: Pid) {
        waitpid(child, WALL).unwrap();
        let mut options =
              ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACEEXIT
            | ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACEVFORKDONE;
        if !self.config.no_kill {
            options |= ptrace::Options::PTRACE_O_EXITKILL;
        }
        ptrace::setoptions(child, options).unwrap();
        ptrace::syscall(child, None).unwrap();

        // pid -> tgid
        let mut pids: HashMap<Pid, Pid> = HashMap::from([(child, child)]);
        loop {
            let status = waitpid(Some(Pid::from_raw(-1)), WALL).unwrap();
            let pid = status.pid().unwrap();
            // ptrace event will be emited after clone or clone3 enter or before exit. Fallback here.
            let tgid = *pids.get(&pid).unwrap_or(&pid);
            let mut signal: Option<Signal> = None;
            match status {
                WaitStatus::PtraceSyscall(_) => {
                    if let Err(err) = unsafe { self.handle_syscall(pid, tgid) } {
                        if self.config.verbose { dbg!(err); }
                    }
                },
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                    for handler in &mut self.handlers {
                        handler.process_exit(&pid);
                    }
                    pids.retain(|_, v| *v != pid);
                    if pid == child { break; } else { continue; }
                },
                // TODO: VFORK_DONE
                | WaitStatus::PtraceEvent(_, _, event@libc::PTRACE_EVENT_FORK)
                | WaitStatus::PtraceEvent(_, _, event@libc::PTRACE_EVENT_VFORK)
                | WaitStatus::PtraceEvent(_, _, event@libc::PTRACE_EVENT_CLONE) => {
                    let new_pid = Pid::from_raw(ptrace::getevent(pid).unwrap() as i32);
                    // add (new_pid, new_pid) for threads of new process geting its tgid
                    let tgid = if event == libc::PTRACE_EVENT_CLONE { tgid } else { new_pid };
                    pids.insert(new_pid, tgid);
                },
                WaitStatus::Stopped(_, Signal::SIGSTOP) => (),
                WaitStatus::Stopped(_, sig) => signal = Some(sig),
                _ => (),
            };
            ptrace::syscall(pid, signal).ok();
        }
    }
}