use nix::{unistd::Pid, Error};

use anyhow::Result;

use crate::{psocket::{Syscall, SyscallHandler, SyscallType}, utils::{get_fd, read_struct, Pidfd, PsocketError}, Config};

#[derive(Debug)]
pub(crate) struct ProxyHandler {
    config: Config,
    entered: Option<(Pidfd, libc::sockaddr_in)>,
}

impl ProxyHandler {
    pub(crate) fn new(config: Config) -> ProxyHandler {
        ProxyHandler { config, entered: None }
    }
}

impl SyscallHandler for ProxyHandler {
    unsafe fn handle(&mut self, &mut Syscall {
        ty, pid, ref mut regs, orig_rax, ..
    }: &mut Syscall) -> Result<()> {
        let proxy = match self.config.proxy {
            Some(proxy) => proxy,
            None => return Ok(()),
        };
        let proxy_addr: u32 = std::mem::transmute(*proxy.ip());
        let proxy_port = proxy.port();
        match orig_rax {
            libc::SYS_connect => {
                if let SyscallType::Exit = ty {
                    self.entered = None;
                    return Ok(())
                }

                let orig_sockaddr: libc::sockaddr_in = read_struct(pid, regs.rsi)?;
                if orig_sockaddr.sin_family as i32 != libc::AF_INET {
                    return Ok(());
                }

                let pfd = get_fd(pid, regs.rdi as i32)?;
                let mut socket_type: u32 = std::mem::zeroed();
                let ret = libc::getsockopt(
                    pfd.fd, libc::SOL_SOCKET, libc::SO_TYPE,
                    &mut socket_type as *mut _ as *mut _,
                    &mut std::mem::size_of::<u32>() as *mut _ as *mut _,
                );
                if ret == -1 {
                    Err(PsocketError::SyscallFailed)?;
                }
                // process tcp
                // udp won't call connect
                if socket_type as i32 != libc::SOCK_STREAM {
                    return Ok(());
                }

                // cancel origin connect
                regs.orig_rax = i64::MAX as u64;
                self.entered = Some((pfd, orig_sockaddr))
            },
            i64::MAX if self.entered.is_some() => {
                let (pfd, orig_sockaddr) = std::mem::replace(&mut self.entered, None).unwrap();

                let mut sockaddr = orig_sockaddr.clone();
                sockaddr.sin_addr = libc::in_addr { s_addr: proxy_addr };
                sockaddr.sin_port = proxy_port.to_be();
                let ret = libc::connect(
                    pfd.fd, &sockaddr as *const _ as *const _,
                    std::mem::size_of::<libc::sockaddr_in>() as u32
                );
                regs.rax = if ret == 0 { 0 } else {
                    -Error::last_raw() as u64
                };
                if ret != 0 && Error::last_raw() != libc::EINPROGRESS && Error::last_raw() != libc::EALREADY {
                    Err(PsocketError::SyscallFailed)?;
                }

                let flags = libc::fcntl(pfd.fd, libc::F_GETFL, 0);
                if flags & libc::O_NONBLOCK != 0 {
                    let ret = libc::fcntl(pfd.fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                    if ret != 0 {
                        Err(PsocketError::SyscallFailed)?;
                    }
                }

                let send_result = send_proxy_packets(pfd.fd, orig_sockaddr);

                let ret = libc::fcntl(pfd.fd, libc::F_SETFL, flags);
                if ret != 0 {
                    Err(PsocketError::SyscallFailed)?;
                }

                send_result?;
            }
            _ => (),
        };
        Ok(())
    }

    fn process_exit(&mut self, _pid: &Pid) {}
}

unsafe fn send_proxy_packets(pfd: i32, sockaddr: libc::sockaddr_in) -> Result<()> {
    let addr = sockaddr.sin_addr.s_addr.to_le_bytes()
        .map(|e| e.to_string()).join(".");
    let port = sockaddr.sin_port.to_be();
    let request = format!("CONNECT {}:{} HTTP/1.0\r\n\r\n", addr, port);
    let bytes = request.as_bytes();
    let len = bytes.len();
    let ret = libc::send(pfd, bytes as *const _ as *const _, len, 0);
    if ret != len as isize {
        Err(PsocketError::SyscallFailed)?;
    }

    let mut recv: Vec<u8> = vec![];
    loop {
        let mut byte = 0;
        let read = libc::read(pfd, &mut byte as *mut _ as *mut _, 1);
        if read != 1 {
            Err(PsocketError::SyscallFailed)?;
        }
        recv.push(byte);
        if recv.len() >= 4 && recv.ends_with(&[
            '\r' as u8, '\n' as u8,
            '\r' as u8, '\n' as u8]
        ) {
            break;
        }
    }

    if recv[9..12] != ['2' as u8, '0' as u8, '0' as u8] {
        Err(PsocketError::SyscallFailed)?;
    }

    Ok(())
}