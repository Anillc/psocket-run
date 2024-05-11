use nix::unistd::Pid;

use anyhow::Result;

use crate::{psocket::{Syscall, SyscallHandler, SyscallType}, utils::{read_struct, write_struct}, Config};

#[derive(Debug)]
pub(crate) struct CloneHandler;

impl CloneHandler {
    pub(crate) fn new<'a>(_config: Config) -> CloneHandler {
        CloneHandler
    }
}

impl SyscallHandler for CloneHandler {
    unsafe fn handle(&mut self, &mut Syscall {
        ty, ref mut regs, pid, orig_rax, ..
    }: &mut Syscall) -> Result<()> {
        match orig_rax {
            libc::SYS_clone => {
                if let SyscallType::Enter = ty {
                    let flags = regs.rdi & !(libc::CLONE_UNTRACED as u64);
                    regs.rdi = flags;
                }
            },
            libc::SYS_clone3 => {
                if let SyscallType::Enter = ty {
                    let mut args: libc::clone_args = read_struct(pid, regs.rdi).unwrap();
                    args.flags = args.flags & !(libc::CLONE_UNTRACED as u64);
                    write_struct(pid, regs.rdi, args).unwrap();
                }
            },
            _ => (),
        }
        Ok(())
    }

    fn process_exit(&mut self, _pid: &Pid) {}
}