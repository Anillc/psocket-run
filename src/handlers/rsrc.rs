use std::{collections::HashMap, mem::size_of};
use nix::unistd::Pid;
use rand::rngs::ThreadRng;

use crate::{psocket::{Psocket, SyscallHandler, Syscall}, utils::{random_address, Result}};

#[derive(Debug)]
pub(crate) struct RsrcHandler<'a> {
    psocket: &'a Psocket<'a>,
    // pid, socket fd, pidfd socket fd
    sockets: HashMap<Pid, HashMap<i32, i32>>,
    rng: ThreadRng,
}

impl RsrcHandler<'_> {
    pub(crate) fn new<'a>(psocket: &'a Psocket<'a>) -> RsrcHandler<'a> {
        RsrcHandler { psocket, sockets: HashMap::new(), rng: rand::thread_rng() }
    }
}

impl RsrcHandler<'_> {
    fn get_sockets(&mut self, pid: Pid) -> &mut HashMap<i32, i32> {
        if !self.sockets.contains_key(&pid) {
            self.sockets.insert(pid, HashMap::new());
        }
        self.sockets.get_mut(&pid).unwrap()
    }

    pub(crate) fn remove_pid(&mut self, pid: &Pid) {
        self.sockets.remove(pid);
    }
}

impl SyscallHandler for RsrcHandler<'_> {
    unsafe fn handle(&mut self, &Syscall {
        orig_rax, enter, ref socket, rax, rdi, pid, ..
    }: &Syscall) -> Result<()> {
        match orig_rax {
            libc::SYS_socket => {
                if enter { return Ok(()); }
                let pfd = (**socket)?;
                if rdi == libc::AF_INET6 && self.psocket.cidr.is_some() {
                    self.get_sockets(pid).insert(rax, pfd);
                }
                if let Some(fwmark) = self.psocket.fwmark {
                    let mark = &fwmark as *const u32 as *const libc::c_void;
                    libc::setsockopt(pfd, libc::SOL_SOCKET, libc::SO_MARK, mark, size_of::<u32>() as u32);
                }
            },
            libc::SYS_close | libc::SYS_bind => {
                if !enter { return Ok(()); }
                self.get_sockets(pid).remove(&rdi);
            },
            libc::SYS_connect => {
                if !enter || self.psocket.cidr.is_none() { return Ok(()); }
                let fd = self.get_sockets(pid).remove(&rdi);
                if let Some(fd) = fd {
                    let cidr = self.psocket.cidr.unwrap();
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
                    libc::bind(fd, sockaddr as *const libc::sockaddr, size_of::<libc::sockaddr_in6>() as u32);

                }
            }
            _ => (),
        };
        Ok(())
    }
}