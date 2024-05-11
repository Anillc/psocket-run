use nix::unistd::Pid;

use anyhow::Result;

use crate::{psocket::{Syscall, SyscallHandler}, utils::PsocketError, Config};

#[derive(Debug)]
pub(crate) struct FwmarkHandler {
    config: Config,
    socket_enter: bool,
}

impl FwmarkHandler {
    pub(crate) fn new(config: Config) -> FwmarkHandler {
        FwmarkHandler { config, socket_enter: false }
    }
}

impl SyscallHandler for FwmarkHandler {
    unsafe fn handle(&mut self, &mut Syscall {
        orig_rax, ref socket_rax, ..
    }: &mut Syscall) -> Result<()> {
        let fwmark = match self.config.fwmark {
            Some(fwmark) => fwmark,
            None => return Ok(()),
        };
        if orig_rax == libc::SYS_socket {
            self.socket_enter = !self.socket_enter;
            if self.socket_enter { return Ok(()); }
            let pfd = socket_rax.as_ref().map_err(|_| PsocketError::SyscallFailed)?.fd;
            let mark = &fwmark as *const u32 as *const libc::c_void;
            let ret = libc::setsockopt(
                pfd, libc::SOL_SOCKET, libc::SO_MARK,
                mark, std::mem::size_of::<u32>() as u32
            );
            if ret == -1 { Err(PsocketError::SyscallFailed)? }
        }
        Ok(())
    }

    fn process_exit(&mut self, _pid: &Pid) {}
}