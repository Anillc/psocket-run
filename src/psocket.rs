use std::fmt::Debug;
use std::os::unix::process::CommandExt;
use std::process::Command;

use libc::user_regs_struct;
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::sys::ptrace;
use nix::unistd::Pid;

use anyhow::{Ok, Result};

use crate::handlers::clone::CloneHandler;
use crate::handlers::fwmark::FwmarkHandler;
use crate::handlers::proxy::ProxyHandler;
use crate::handlers::rsrc::RsrcHandler;
use crate::utils::PsocketError;
use crate::Config;

#[derive(Debug)]
pub(crate) struct Psocket {
    config: Config,
    handlers: Vec<Box<dyn SyscallHandler>>,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum SyscallType {
    Enter, Exit
}

#[derive(Debug)]
pub(crate) struct Syscall {
    pub(crate) ty: SyscallType,
    pub(crate) pid: Pid,
    pub(crate) regs: user_regs_struct,
    pub(crate) orig_rax: i64,
}

pub(crate) trait SyscallHandler: Debug {
    unsafe fn handle(&mut self, syscall: &mut Syscall) -> Result<()>;
    fn process_exit(&mut self, pid: &Pid);
}

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

    unsafe fn handle_syscall(&mut self, pid: Pid, ty: SyscallType) -> Result<()> {
        let regs = ptrace::getregs(pid)?;
        let mut syscall = Syscall {
            ty, pid, regs,
            orig_rax: regs.orig_rax as i64,
        };
        let results = self.handlers.iter_mut()
            .map(|handler| handler.handle(&mut syscall))
            .fold(Ok(()), |result, x| result.and(x));
        if regs != syscall.regs {
            ptrace::setregs(syscall.pid, syscall.regs).map_err(|_| PsocketError::SyscallFailed)?;
        }
        results?;
        Ok(())
    }

    pub(crate) fn child(&self) {
        ptrace::traceme().unwrap();
        Command::new("/bin/sh").args(["-c", self.config.command.as_str()]).exec();
    }

    pub(crate) fn parent(&mut self, child: Pid) -> Result<()> {
        wait()?;
        let mut options =
              ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACEEXIT
            | ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK;
        if !self.config.no_kill {
            options |= ptrace::Options::PTRACE_O_EXITKILL;
        }
        ptrace::setoptions(child, options)?;
        ptrace::syscall(child, None)?;

        loop {
            let status = match wait() {
                std::result::Result::Ok(status) => status,
                // child process died
                std::result::Result::Err(_) => break,
            };
            match status {
                WaitStatus::Stopped(pid, Signal::SIGTRAP | Signal::SIGSTOP) => ptrace::syscall(pid, None)?,
                WaitStatus::Stopped(pid, sig) => ptrace::syscall(pid, sig)?,
                WaitStatus::Exited(pid, _) => {
                    for handler in &mut self.handlers {
                        handler.process_exit(&pid);
                    }
                    if pid == child { break; }
                },
                WaitStatus::PtraceEvent(pid, sig, _) => ptrace::syscall(pid, sig)?,
                WaitStatus::Signaled(_, _, _) => break,
                WaitStatus::Continued(_) | WaitStatus::StillAlive => (),
                WaitStatus::PtraceSyscall(pid) => {
                    let event = ptrace::getevent(pid)? as u8;
                    let ty = match event {
                        libc::PTRACE_SYSCALL_INFO_ENTRY => SyscallType::Enter,
                        libc::PTRACE_SYSCALL_INFO_EXIT => SyscallType::Exit,
                        _ => Err(PsocketError::SyscallFailed)?,
                    };
                    unsafe {
                        if let Err(error) = self.handle_syscall(pid,  ty) {
                            if self.config.verbose { dbg!(error); }
                        }
                    };
                    ptrace::syscall(pid, None).ok();
                },
            };
        }
        Ok(())
    }
}