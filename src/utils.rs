use std::fs::{File, read_dir};
use std::io::{BufReader, BufRead};
use nix::unistd::Pid;
use rand::{rngs::ThreadRng, Rng};
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, PsocketError>;

#[derive(Debug, Error, Clone, Copy)]
pub(crate) enum PsocketError {
    #[error("failed to call syscall")]
    SyscallFailed,
    #[error("failed to read file")]
    ReadFailed,
}

#[derive(Debug)]
pub(crate) struct Pidfd {
    pidfd: i32,
    pub(crate) fd: i32,
}

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
        let pid = get_pid_from_tid(pid.as_raw())?;
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

pub(crate) fn get_pid_from_tid(tid: i32) -> Result<i32> {
    let task = find_task(tid).ok_or(PsocketError::ReadFailed)?;
    let status_file = File::open(task)
        .map_err(|_| PsocketError::ReadFailed)?;
    let mut pid = None;
    for line in BufReader::new(status_file).lines() {
        let line = line.map_err(|_| PsocketError::ReadFailed)?;
        if line.starts_with("Tgid:") {
            let pid_str = line.split("\t").last().unwrap();
            pid = Some(str::parse(&pid_str).unwrap())
        }
    }
    Ok(pid.unwrap())
}

pub(crate) fn find_task(tid: i32) -> Option<String> {
    let proc_list = read_dir("/proc").ok()?;
    for proc in proc_list {
        let proc = proc.ok()?;
        let mut path = proc.path();
        path.push(format!("task/{}/status", tid));
        if path.is_file() {
            return Some(path.into_os_string().into_string().unwrap());
        } else {
            continue;
        }
    }
    None
}