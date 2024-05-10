use nix::Error;

use crate::{psocket::{Psocket, SyscallHandler, Syscall}, utils::{Result, PsocketError, read_struct}};

#[derive(Debug)]
pub(crate) struct ProxyHandler<'a> {
    psocket: &'a Psocket<'a>,
    connect_enter: bool,
}

impl ProxyHandler<'_> {
    pub(crate) fn new<'a>(psocket: &'a Psocket<'a>) -> ProxyHandler {
        ProxyHandler { psocket, connect_enter: false }
    }
}

impl SyscallHandler for ProxyHandler<'_> {
    unsafe fn handle(&mut self, &mut Syscall {
        pid, ref mut regs, orig_rax, ref socket_rdi, ..
    }: &mut Syscall) -> Result<()> {
        let proxy = match self.psocket.proxy {
            Some(proxy) => proxy,
            None => return Ok(()),
        };
        let proxy_addr: u32 = std::mem::transmute(*proxy.ip());
        let proxy_port = proxy.port();
        match orig_rax {
            // right now enter is !connect_enter
            libc::SYS_connect | i64::MAX if orig_rax != i64::MAX || self.connect_enter => {
                self.connect_enter = !self.connect_enter;
                let orig_sockaddr: libc::sockaddr_in = read_struct(pid, regs.rsi)?;
                // if orig_sockaddr.sin_family as i32 == libc::AF_INET6 {
                //     regs.orig_rax = i32::MAX as u64;
                //     return Ok(());
                // }
                if orig_sockaddr.sin_family as i32 != libc::AF_INET {
                    return Ok(());
                }

                let pfd = socket_rdi.as_ref().map_err(|e| *e)?.fd;
                let mut socket_type: u32 = std::mem::zeroed();
                let ret = libc::getsockopt(
                    pfd, libc::SOL_SOCKET, libc::SO_TYPE,
                    &mut socket_type as *mut _ as *mut _,
                    &mut std::mem::size_of::<u32>() as *mut _ as *mut _,
                );
                if ret == -1 {
                    return Err(PsocketError::SyscallFailed);
                }
                // tcp
                // udp won't call connect
                if socket_type as i32 != libc::SOCK_STREAM {
                    return Ok(());
                }

                // block before syscall and call connect after syscall
                if self.connect_enter {
                    regs.orig_rax = i64::MAX as u64;
                    return Ok(());
                }

                let mut sockaddr = orig_sockaddr.clone();
                sockaddr.sin_addr = libc::in_addr { s_addr: proxy_addr };
                sockaddr.sin_port = proxy_port.to_be();
                let ret = libc::connect(
                    pfd, &sockaddr as *const _ as *const _,
                    std::mem::size_of::<libc::sockaddr_in>() as u32
                );
                regs.rax = if ret == 0 { 0 } else {
                    -Error::last_raw() as u64
                };
                if ret != 0 && Error::last_raw() != libc::EINPROGRESS && Error::last_raw() != libc::EALREADY {
                    return Err(PsocketError::SyscallFailed);
                }

                let flags = libc::fcntl(pfd, libc::F_GETFL, 0);
                if flags & libc::O_NONBLOCK != 0 {
                    let ret = libc::fcntl(pfd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
                    if ret != 0 {
                        return Err(PsocketError::SyscallFailed);
                    }
                }

                let send_result = send_proxy_packets(pfd, orig_sockaddr);

                let ret = libc::fcntl(pfd, libc::F_SETFL, flags);
                if ret != 0 {
                    return Err(PsocketError::SyscallFailed);
                }

                // TODO
                send_result?;
            },
            // TODO
            // libc::SYS_sendto => {
            //     // dbg!(456);
            // },
            _ => (),
        };
        Ok(())
    }
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
        return Err(PsocketError::SyscallFailed);
    }

    let mut recv: Vec<u8> = vec![];
    loop {
        let mut byte = 0;
        let read = libc::read(pfd, &mut byte as *mut _ as *mut _, 1);
        if read != 1 {
            return Err(PsocketError::SyscallFailed);
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
        return Err(PsocketError::SyscallFailed);
    }

    Ok(())
}