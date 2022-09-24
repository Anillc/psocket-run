use std::mem::size_of;

use crate::{psocket::{Psocket, Syscall, SyscallHandler}, utils::Result};

#[derive(Debug)]
pub(crate) struct FwmarkHandler<'a> {
    psocket: &'a Psocket<'a>,
}

impl FwmarkHandler<'_> {
    pub(crate) fn new<'a>(psocket: &'a Psocket<'a>) -> FwmarkHandler<'a> {
        FwmarkHandler { psocket }
    }
}

impl SyscallHandler for FwmarkHandler<'_> {
    unsafe fn handle(&mut self, &Syscall {
        enter, orig_rax, ref socket, ..
    }: &Syscall) -> Result<()> {
        if orig_rax == libc::SYS_socket {
            if enter { return Ok(()); }
            let pfd = (**socket)?;
            if let Some(fwmark) = self.psocket.fwmark {
                let mark = &fwmark as *const u32 as *const libc::c_void;
                libc::setsockopt(pfd, libc::SOL_SOCKET, libc::SO_MARK, mark, size_of::<u32>() as u32);
            }
        }
        Ok(())
    }
}