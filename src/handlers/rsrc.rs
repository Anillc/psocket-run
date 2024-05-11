use std::{collections::HashMap, mem::size_of};
use nix::unistd::Pid;
use rand::rngs::ThreadRng;
use anyhow::{Ok, Result};

use crate::{psocket::{Syscall, SyscallHandler, SyscallType}, utils::{get_fd, random_address, PsocketError}, Config};

#[derive(Debug)]
pub(crate) struct RsrcHandler {
    config: Config,
    rng: ThreadRng,
    bound: HashMap<Pid, Vec<i32>>,
}

impl RsrcHandler {
    pub(crate) fn new(config: Config) -> RsrcHandler {
        RsrcHandler {
            config,
            rng: rand::thread_rng(),
            bound: HashMap::new(),
        }
    }
}

impl SyscallHandler for RsrcHandler {
    unsafe fn handle(&mut self, &mut Syscall {
        ty, ref mut regs, orig_rax, pid, ..
    }: &mut Syscall) -> Result<()> {
        let cidr = match self.config.cidr {
            Some(cidr) => cidr,
            None => return Ok(()),
        };
        match orig_rax {
            libc::SYS_bind => {
                if let SyscallType::Enter = ty {
                    self.bound.entry(pid)
                        .or_insert(Vec::new())
                        .push(regs.rdi as i32);
                }
            },
            libc::SYS_close => {
                if let SyscallType::Enter = ty {
                    self.bound.entry(pid).and_modify(|bound| {
                        bound.retain(|x| *x != regs.rdi as i32);
                    });
                }
            }
            libc::SYS_connect => {
                if let SyscallType::Exit = ty { return Ok(()); }
                // skip bound sockets
                let bound = self.bound.entry(pid).or_insert(Vec::new());
                if bound.contains(&(regs.rdi as i32)) {
                    return Ok(());
                }
                if let Result::Ok(pidfd) = get_fd(pid, regs.rdi as i32) {
                    let addr = libc::in6_addr {
                        s6_addr: random_address(&cidr, &mut self.rng).to_be_bytes(),
                    };
                    let sockaddr: *const libc::sockaddr_in6 = &libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as u16,
                        sin6_port: 0u16.to_be(),
                        sin6_flowinfo: 0,
                        sin6_addr: addr,
                        sin6_scope_id: 0,
                    };
                    let ret = libc::bind(
                        pidfd.fd, sockaddr as *const libc::sockaddr,
                        size_of::<libc::sockaddr_in6>() as u32
                    );
                    if ret == -1 { Err(PsocketError::SyscallFailed)?; }
                    bound.push(regs.rdi as i32);
                }
            },
            _ => (),
        };
        Ok(())
    }

    fn process_exit(&mut self, pid: &Pid) {
        self.bound.remove(pid);
    }
}