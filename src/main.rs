use std::ffi::{CString, CStr};

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::sys::ptrace;
use nix::unistd::{fork, ForkResult, execvp, Pid};

const WALL: Option<WaitPidFlag> = Some(WaitPidFlag::__WALL);

fn main() {
    match unsafe { fork() } {
        Ok(ForkResult::Child) => child(),
        Ok(ForkResult::Parent { child }) => parent(child),
        Err(err) => panic!("error {}", err),
    }
}

fn handle_syscall(pid: Pid) {
    if let Ok(regs) = ptrace::getregs(pid) {
        let socket = regs.rax as i32;
        if regs.orig_rax != libc::SYS_socket as u64 || socket < 0 {
            return
        }
        let mark = &0x66CCFF as *const i32 as *const libc::c_void;
        unsafe {
            let pidfd = libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) as i32;
            if pidfd < 0 { return }
            let psocket = libc::syscall(libc::SYS_pidfd_getfd, pidfd, socket, 0) as i32;
            if psocket < 0 { return }
            libc::setsockopt(psocket, libc::SOL_SOCKET, libc::SO_MARK, mark, 4);
        };
    }
}

fn child() {
    ptrace::traceme().unwrap();
    execvp(CString::new("bash").unwrap().as_c_str(), &[] as &[&CStr; 0]).unwrap();
}

fn parent(child: Pid) {
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
            WaitStatus::PtraceSyscall(_) => handle_syscall(pid),
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
