use crate::{psocket::{Psocket, Syscall, SyscallHandler}, utils::{Result, PsocketError}};

#[derive(Debug)]
pub(crate) struct FwmarkHandler<'a> {
    psocket: &'a Psocket<'a>,
    socket_enter: bool,
}

impl FwmarkHandler<'_> {
    pub(crate) fn new<'a>(psocket: &'a Psocket<'a>) -> FwmarkHandler<'a> {
        FwmarkHandler { psocket, socket_enter: false }
    }
}

impl SyscallHandler for FwmarkHandler<'_> {
    unsafe fn handle(&mut self, &Syscall {
        orig_rax, ref socket_rax, ..
    }: &Syscall) -> Result<()> {
        let fwmark = match self.psocket.fwmark {
            Some(fwmark) => fwmark,
            None => return Ok(()),
        };
        if orig_rax == libc::SYS_socket {
            self.socket_enter = !self.socket_enter;
            if self.socket_enter { return Ok(()); }
            let pfd = socket_rax.as_ref().map_err(|e| *e)?.fd;
            let mark = &fwmark as *const u32 as *const libc::c_void;
            let ret = libc::setsockopt(
                pfd, libc::SOL_SOCKET, libc::SO_MARK,
                mark, std::mem::size_of::<u32>() as u32
            );
            if ret == -1 { return Err(PsocketError::SyscallFailed); }
        }
        Ok(())
    }
}