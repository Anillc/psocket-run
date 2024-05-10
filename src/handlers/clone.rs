use nix::unistd::Pid;

use crate::{psocket::{Syscall, SyscallHandler}, utils::{read_struct, write_struct, Result}, Config};

#[derive(Debug)]
pub(crate) struct CloneHandler {
    clone_enter: bool,
    clone3_enter: bool,
}

impl CloneHandler {
    pub(crate) fn new<'a>(_config: Config) -> CloneHandler {
        CloneHandler { clone_enter: false, clone3_enter: false }
    }
}

impl SyscallHandler for CloneHandler {
    unsafe fn handle(&mut self, &mut Syscall {
        ref mut regs, pid, orig_rax, ..
    }: &mut Syscall) -> Result<()> {
        match orig_rax {
            libc::SYS_clone => {
                self.clone_enter = !self.clone_enter;
                if self.clone_enter {
                    let flags = (regs.rdx as i32 & !libc::CLONE_UNTRACED) as u64;
                    regs.rdx = flags;
                }
            },
            libc::SYS_clone3 => {
                self.clone3_enter = !self.clone3_enter;
                if self.clone3_enter {
                    let mut args: libc::clone_args = read_struct(pid, regs.rdi).unwrap();
                    args.flags = (args.flags as i32 & !libc::CLONE_UNTRACED) as u64;
                    write_struct(pid, regs.rdi, args).unwrap();
                }
            },
            _ => (),
        }
        Ok(())
    }

    fn process_exit(&mut self, _pid: &Pid) {}
}