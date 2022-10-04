use nix::{unistd::Pid, sys::ptrace};
use rand::{rngs::ThreadRng, Rng};
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, PsocketError>;

#[derive(Debug, Error, Clone, Copy)]
pub(crate) enum PsocketError {
    #[error("failed to call syscall")]
    SyscallFailed,
}

#[derive(Debug)]
pub(crate) struct Pidfd {
    pidfd: i32,
    pub(crate) fd: i32,
}

// FIXME: rsrc saves fd
impl Drop for Pidfd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
            libc::close(self.pidfd);
        };
    }
}

pub(crate) fn get_fd(pid: Pid, raw_fd: i32) -> Result<Pidfd> {
    unsafe {
        let pidfd = libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32;
        if pidfd < 0 { return Err(PsocketError::SyscallFailed); }
        let fd = libc::syscall(libc::SYS_pidfd_getfd, pidfd, raw_fd, 0) as i32;
        if fd < 0 { return Err(PsocketError::SyscallFailed); }
        Ok(Pidfd { pidfd, fd })
    }
}

pub(crate) fn random_address((addr, length): &(u128, u8), rng: &mut ThreadRng) -> u128 {
    let left = length / 8;
    let right = (128 - length) / 8;
    let left = vec![0; left as usize];
    let right = (0..right)
        .map(|_| rng.gen())
        .collect::<Vec<u8>>();
    let random: [u8; 16] = [left, right].concat().try_into().unwrap();
    addr | u128::from_be_bytes(random)
}

pub(crate) unsafe fn read_struct<T>(pid: Pid, addr: u64) -> Result<T> {
    let unit_len = std::mem::size_of::<libc::c_long>();
    let len = std::mem::size_of::<T>() / unit_len + 1;
    let mut units: Vec<libc::c_long> = vec![0; len];
    let mut i = 0;
    while i < len {
        let read = ptrace::read(pid, (addr + (i * unit_len) as u64) as *mut _)
            .map_err(|_| PsocketError::SyscallFailed)?;
        units[i] = read;
        i += 1;
    };
    Ok(std::ptr::read(units.as_slice() as *const _ as *const _))
}

pub(crate) unsafe fn write_struct<T>(pid: Pid, addr: u64, t: T) -> Result<()> {
    let unit_len = std::mem::size_of::<libc::c_long>();
    let len = std::mem::size_of::<T>() / unit_len;
    let t = &t as *const _ as u64;
    let mut i = 0;
    while i < len {
        let offset = (i * unit_len) as u64;
        ptrace::write(pid, (addr + offset) as *mut _, *((t + offset) as *mut _))
            .map_err(|_| PsocketError::SyscallFailed)?;
        i += 1;
    }
    Ok(())
}
