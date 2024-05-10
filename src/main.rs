use std::net::SocketAddrV4;
use std::str::FromStr;
use nix::sys::ptrace;
use nix::unistd::{ForkResult, Pid, fork};
use cidr::Ipv6Cidr;
use clap::Parser;
use crate::psocket::Psocket;

mod utils;
mod psocket;
mod handlers;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long)]
    fwmark: Option<String>,
    #[clap(short, long)]
    cidr: Option<String>,
    #[clap(short, long)]
    attach: Option<i32>,
    #[clap(short, long)]
    proxy: Option<String>,
    #[clap(short, long)]
    no_kill: bool,
    #[clap(short, long)]
    verbose: bool,
    #[clap(default_value = "bash")]
    command: String,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) command: String,
    pub(crate) fwmark: Option<u32>,
    pub(crate) cidr: Option<(u128, u8)>,
    pub(crate) proxy: Option<SocketAddrV4>,
    pub(crate) no_kill: bool,
    pub(crate) verbose: bool,
}


pub fn main() {
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

    let proxy: Option<SocketAddrV4> = args.proxy.and_then(
        |proxy| Some(proxy.parse().expect("invaild proxy address"))
    );

    let config = Config {
        command: args.command,
        no_kill: args.no_kill,
        verbose: args.verbose,
        fwmark, cidr, proxy,
    };
    let mut psocket = Psocket::new(config);

    if let Some(pid) = args.attach {
        let pid = Pid::from_raw(pid);
        ptrace::attach(pid).expect("failed to attach to process");
        psocket.parent(pid);
    } else {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => psocket.child(),
            Ok(ForkResult::Parent { child }) => psocket.parent(child),
            Err(err) => panic!("error {}", err),
        }
    }
}
