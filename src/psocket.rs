
use std::cell::RefCell;
use std::os::unix::process::CommandExt;
use std::process::Command;

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::sys::ptrace;
use nix::unistd::Pid;

use once_cell::sync::Lazy;

use crate::handlers::fwmark::FwmarkHandler;
use crate::handlers::rsrc::RsrcHandler;
use crate::utils::{get_fd, Result, PsocketError};

#[derive(Debug)]
pub(crate) struct Psocket<'a> {
    pub(crate) command: String,
    pub(crate) fwmark: Option<u32>,
    pub(crate) cidr: Option<(u128, u8)>,
    fwmark_handler: RefCell<Option<FwmarkHandler<'a>>>,
    rsrc_handler: RefCell<Option<RsrcHandler<'a>>>,
}

#[derive(Debug)]
pub(crate) struct Syscall {
    pub(crate) pid: Pid,
    pub(crate) enter: bool,
    pub(crate) orig_rax: i64,
    pub(crate) rax: i32,
    pub(crate) rdi: i32,
    pub(crate) socket: Lazy<Result<i32>, Box<dyn FnOnce() -> Result<i32>>>,
}

pub(crate) trait SyscallHandler {
    unsafe fn handle(&mut self, syscall: &Syscall) -> Result<()>;
}

const WALL: Option<WaitPidFlag> = Some(WaitPidFlag::__WALL);

impl Psocket<'_> {

    pub(crate) fn new_leak(command: String, fwmark: Option<u32>, cidr: Option<(u128, u8)>) -> &'static Psocket<'static> {
        let psocket: &'static mut _ = Box::leak(Box::new(Psocket {
            command, fwmark, cidr,
            fwmark_handler: RefCell::new(None),
            rsrc_handler: RefCell::new(None),
        }));
        *psocket.fwmark_handler.borrow_mut() = Some(FwmarkHandler::new(psocket));
        *psocket.rsrc_handler.borrow_mut() = Some(RsrcHandler::new(psocket));
        psocket
    }

    unsafe fn handle_syscall(&self, pid: Pid, enter: bool) -> Result<()> {
        let regs = ptrace::getregs(pid).map_err(|_| PsocketError::GetRegsFailed)?;
        let rax = regs.rax as i32;
        let syscall = Syscall {
            pid, enter, rax,
            orig_rax: regs.orig_rax as i64,
            rdi: regs.rdi as i32,
            socket: Lazy::new(Box::new(move || get_fd(pid, rax as i32))),
        };
        self.fwmark_handler.borrow_mut().as_mut().unwrap().handle(&syscall).ok();
        self.rsrc_handler.borrow_mut().as_mut().unwrap().handle(&syscall).ok();
        Ok(())
    }

    pub(crate) fn child(&self) {
        ptrace::traceme().unwrap();
        Command::new("/bin/sh").args(["-c", self.command.as_str()]).exec();
    }

    pub(crate) fn parent(&self, child: Pid) {
        waitpid(child, WALL).unwrap();
        let options =
              ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_EXITKILL
            | ptrace::Options::PTRACE_O_TRACEEXIT
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORKDONE
            | ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_TRACEVFORK;
        ptrace::setoptions(child, options).unwrap();
        ptrace::syscall(child, None).unwrap();
        let mut enter = false;
        loop {
            let status = waitpid(None, WALL).unwrap();
            let pid = status.pid().unwrap();
            let mut signal: Option<Signal> = None;
            enter = !enter;
            match status {
                WaitStatus::PtraceSyscall(_) => {
                    unsafe { self.handle_syscall(pid, enter).ok() };
                },
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                    enter = true;
                    self.rsrc_handler.borrow_mut().as_mut().unwrap().remove_pid(&pid);
                    if pid == child { break; } else { continue; }
                },
                WaitStatus::PtraceEvent(_, _, _) => enter = true,
                WaitStatus::Stopped(_, Signal::SIGSTOP) => (),
                WaitStatus::Stopped(_, sig) => signal = Some(sig),
                _ => (),
            };
            ptrace::syscall(pid, signal).ok();
        }
    }
}