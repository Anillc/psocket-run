use std::os::unix::process::CommandExt;
use std::process::Command;

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::sys::ptrace;
use nix::unistd::{ForkResult, Pid, fork};

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    fwmark: String,
    #[clap(default_value = "bash")]
    command: String,
}

const WALL: Option<WaitPidFlag> = Some(WaitPidFlag::__WALL);

fn main() {
    let args = Args::parse();
    let fwmark = u32::from_str_radix(&args.fwmark.trim_start_matches("0x"), 16)
        .expect("invaild fwmark");
    match unsafe { fork() } {
        Ok(ForkResult::Child) => child(args.command),
        Ok(ForkResult::Parent { child }) => parent(child, fwmark),
        Err(err) => panic!("error {}", err),
    }
}

fn handle_syscall(pid: Pid, fwmark: u32) {
    if let Ok(regs) = ptrace::getregs(pid) {
        let socket = regs.rax as i32;
        if regs.orig_rax != libc::SYS_socket as u64 || socket < 0 {
            return
        }
        let mark = &fwmark as *const u32 as *const libc::c_void;
        unsafe {
            let pidfd = libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) as i32;
            if pidfd < 0 { return }
            let psocket = libc::syscall(libc::SYS_pidfd_getfd, pidfd, socket, 0) as i32;
            if psocket < 0 { return }
            libc::setsockopt(psocket, libc::SOL_SOCKET, libc::SO_MARK, mark, 4);
        };
    }
}

fn child(command: String) {
    ptrace::traceme().unwrap();
    Command::new("/bin/sh").args(["-c", command.as_str()]).exec();
}

fn parent(child: Pid, fwmark: u32) {
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
            WaitStatus::PtraceSyscall(_) => handle_syscall(pid, fwmark),
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
