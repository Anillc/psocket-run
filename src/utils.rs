use nix::unistd::Pid;
use rand::{rngs::ThreadRng, Rng};
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, PsocketError>;

#[derive(Debug, Error, Clone, Copy)]
pub(crate) enum PsocketError {
    #[error("failled to call syscall")]
    SyscallFailed,
    #[error("failed to get regs")]
    GetRegsFailed,
}

pub(crate) fn get_fd(pid: Pid, raw_fd: i32) -> Result<i32> {
    unsafe {
        let pidfd = libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) as i32;
        if pidfd < 0 { return Err(PsocketError::SyscallFailed); }
        let fd = libc::syscall(libc::SYS_pidfd_getfd, pidfd, raw_fd, 0) as i32;
        if fd < 0 { return Err(PsocketError::SyscallFailed); }
        Ok(fd)
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
