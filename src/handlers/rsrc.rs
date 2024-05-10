use std::{collections::HashMap, mem::size_of};
use nix::unistd::Pid;
use rand::rngs::ThreadRng;

use crate::{psocket::{Syscall, SyscallHandler}, utils::{random_address, PsocketError, Result}, Config};

#[derive(Debug)]
pub(crate) struct RsrcHandler {
    config: Config,
    // pid, socket fd, pidfd socket fd
    sockets: HashMap<Pid, HashMap<i32, i32>>,
    rng: ThreadRng,
    socket_enter: bool,
    close_enter: bool,
    connect_enter: bool,
}

impl RsrcHandler {
    pub(crate) fn new(config: Config) -> RsrcHandler {
        RsrcHandler {
            config,
            sockets: HashMap::new(),
            rng: rand::thread_rng(),
            socket_enter: false,
            close_enter: false,
            connect_enter: false,
        }
    }
}

impl RsrcHandler {
    fn get_sockets(&mut self, pid: Pid) -> &mut HashMap<i32, i32> {
        if !self.sockets.contains_key(&pid) {
            self.sockets.insert(pid, HashMap::new());
        }
        self.sockets.get_mut(&pid).unwrap()
    }
}

impl SyscallHandler for RsrcHandler {
    unsafe fn handle(&mut self, &mut Syscall {
        ref mut regs, orig_rax, ref socket_rax, rax, pid, ..
    }: &mut Syscall) -> Result<()> {
        if self.config.cidr.is_none() { return Ok(()); }
        let cidr = match self.config.cidr {
            Some(cidr) => cidr,
            None => return Ok(()),
        };
        let rdi = regs.rdi as i32;
        match orig_rax {
            libc::SYS_socket => {
                self.socket_enter = !self.socket_enter;
                if self.socket_enter { return Ok(()); }
                let pfd = socket_rax.as_ref().map_err(|e| *e)?.fd;
                if rdi == libc::AF_INET6 {
                    self.get_sockets(pid).insert(rax, pfd);
                }
            },
            libc::SYS_close | libc::SYS_bind => {
                self.close_enter = !self.close_enter;
                if self.close_enter { return Ok(()); }
                self.get_sockets(pid).remove(&rdi);
            },
            libc::SYS_connect => {
                self.connect_enter = !self.connect_enter;
                if !self.connect_enter { return Ok(()); }
                let fd = self.get_sockets(pid).remove(&rdi);
                if let Some(fd) = fd {
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
                        fd, sockaddr as *const libc::sockaddr,
                        size_of::<libc::sockaddr_in6>() as u32
                    );
                    if ret == -1 { return Err(PsocketError::SyscallFailed); }
                }
            }
            _ => (),
        };
        Ok(())
    }

    fn process_exit(&mut self, pid: &Pid) {
        self.sockets.remove(pid);
    }
}