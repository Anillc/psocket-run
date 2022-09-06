use std::convert::TryInto;
use std::mem::size_of;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::str::FromStr;

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::sys::ptrace;
use nix::unistd::{ForkResult, Pid, fork};

use cidr::Ipv6Cidr;

use clap::Parser;
use rand::Rng;
use rand::rngs::ThreadRng;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long)]
    fwmark: Option<String>,
    #[clap(short, long)]
    cidr: Option<String>,
    #[clap(default_value = "bash")]
    command: String,
}

struct Psocket<'a> {
    command: String,
    fwmark: Option<u32>,
    cidr: Option<(u128, u8)>,
    rng: &'a mut ThreadRng,
}

const WALL: Option<WaitPidFlag> = Some(WaitPidFlag::__WALL);

impl Psocket<'_> {
    fn handle_syscall(&mut self, pid: Pid) {
        if let Ok(regs) = ptrace::getregs(pid) {
            let socket = regs.rax as i32;
            if regs.orig_rax != libc::SYS_socket as u64 || socket < 0 {
                return
            }
            unsafe {
                let pidfd = libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) as i32;
                if pidfd < 0 { return }
                let pfd = libc::syscall(libc::SYS_pidfd_getfd, pidfd, socket, 0) as i32;
                if pfd < 0 { return }
                if let Some(fwmark) = self.fwmark {
                    let mark = &fwmark as *const u32 as *const libc::c_void;
                    libc::setsockopt(pfd, libc::SOL_SOCKET, libc::SO_MARK, mark, size_of::<u32>() as u32);
                }
                if let Some(cidr) = self.cidr {
                    if regs.rdi != libc::AF_INET6 as u64 {
                        return;
                    }
                    let addr = libc::in6_addr {
                        s6_addr: random_address(&cidr, self.rng).to_be_bytes(),
                    };
                    let sockaddr: *const libc::sockaddr_in6 = &libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as u16,
                        sin6_port: 0u16.to_be(),
                        sin6_flowinfo: 0,
                        sin6_addr: addr,
                        sin6_scope_id: 0,
                    };
                    libc::bind(pfd, sockaddr as *const libc::sockaddr, size_of::<libc::sockaddr_in6>() as u32);
                }
            };
        }
    }

    fn child(&mut self) {
        ptrace::traceme().unwrap();
        Command::new("/bin/sh").args(["-c", self.command.as_str()]).exec();
    }

    fn parent(&mut self, child: Pid) {
        waitpid(child, WALL).unwrap();
        let options =
              ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_EXITKILL
            | ptrace::Options::PTRACE_O_TRACEEXIT
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORKDONE
            | ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_TRACEVFORK;
        ptrace::setoptions(child, options).unwrap();
        ptrace::syscall(child, None).unwrap();
        loop {
            let status = waitpid(None, WALL).unwrap();
            let pid = status.pid().unwrap();
            let mut signal: Option<Signal> = None;
            match status {
                WaitStatus::PtraceSyscall(_) => self.handle_syscall(pid),
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                    if pid == child { break; } else { continue; }
                },
                WaitStatus::Stopped(_, Signal::SIGSTOP) => (),
                WaitStatus::Stopped(_, sig) => signal = Some(sig),
                _ => (),
            };
            ptrace::syscall(pid, signal).unwrap_or_default();
        }
    }
}

fn random_address((addr, length): &(u128, u8), rng: &mut ThreadRng) -> u128 {
    let left = length / 8;
    let right = (128 - length) / 8;
    let left = vec![0; left as usize];
    let right = (0..right)
        .map(|_| rng.gen_range(0..0xFF))
        .collect::<Vec<u8>>();
    let random: [u8; 16] = [left, right].concat().try_into().expect("unknown error");
    addr | u128::from_be_bytes(random)
}

fn main() {
    let args = Args::parse();
    let fwmark: Option<u32> = if let Some(fwmark) = args.fwmark {
        Some(u32::from_str_radix(fwmark.trim_start_matches("0x"), 16).expect("invaild fwmark"))
    } else { None };
    let cidr: Option<(u128, u8)> = if let Some(cidr) = args.cidr {
        let cidr = Ipv6Cidr::from_str(cidr.as_str()).expect("invaild cidr");
        let length = cidr.network_length() as u8;
        if length % 8 != 0 {
            panic!("cidr is not divisible by 8")
        }
        let addr: u128 = unsafe {
            std::mem::transmute(cidr.first_address())
        };
        Some((addr.to_be(), length))
    } else { None };
    let mut psocket = Psocket {
        command: args.command,
        fwmark,
        cidr,
        rng: &mut rand::thread_rng()
    };
    match unsafe { fork() } {
        Ok(ForkResult::Child) => psocket.child(),
        Ok(ForkResult::Parent { child }) => psocket.parent(child),
        Err(err) => panic!("error {}", err),
    }
}
