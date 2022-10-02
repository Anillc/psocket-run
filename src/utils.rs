use std::fs::{File, read_dir};
use std::io::{BufReader, BufRead};
use std::num::NonZeroUsize;
use lru::LruCache;
use nix::unistd::Pid;
use once_cell::sync::OnceCell;
use rand::{rngs::ThreadRng, Rng};
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, PsocketError>;

#[derive(Debug, Error, Clone, Copy)]
pub(crate) enum PsocketError {
    #[error("failed to call syscall")]
    SyscallFailed,
    #[error("failed to read file")]
    ReadFailed,
    #[error("failed to find pid")]
    PidNotFound,
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

fn get_pid_lru() -> &'static mut LruCache<i32, i32> {
    static mut INSTANCE: OnceCell<LruCache<i32, i32>> = OnceCell::new();
    unsafe {
        match INSTANCE.get_mut() {
            Some(lru) => lru,
            None => {
                INSTANCE.set(LruCache::new(NonZeroUsize::new(100).unwrap())).unwrap();
                INSTANCE.get_mut().unwrap()
            },
        }
    }
}

pub(crate) fn get_pid_from_tid(tid: i32) -> Result<i32> {
    let lru = get_pid_lru();
    if let Some(pid) = lru.get(&tid) {
        return Ok(*pid);
    }
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
    if pid == None {
        Err(PsocketError::PidNotFound)
    } else {
        let pid = pid.unwrap();
        lru.put(tid, pid);
        Ok(pid)
    }
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