//! CLI tool for managing feth (fake ethernet) interfaces.
//!
//! Must be run as root:
//!
//!     sudo cargo run --example fethctl -- <command>

use std::{net::Ipv4Addr, process::ExitCode};

use clap::{Parser, Subcommand, ValueEnum};
use feth_rs::feth::{Feth, FethStatus};

#[derive(Parser)]
#[command(
    name = "fethctl",
    about = "Manage macOS feth (fake ethernet) interfaces"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Clone, ValueEnum)]
enum State {
    Up,
    Down,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create feth interfaces with the given unit numbers.
    Create {
        /// Unit numbers (e.g. 0 1 creates feth0 and feth1).
        units: Vec<u32>,
    },

    /// Destroy feth interfaces.
    Destroy {
        /// Interface names (e.g. feth0 feth1).
        names: Vec<String>,
    },

    /// Set feth interface parameters (peer, address, MTU, state).
    Set {
        /// Interface name (e.g. feth0).
        name: String,

        /// Set peer interface (e.g. feth1). Use "none" to remove.
        #[arg(long)]
        peer: Option<String>,

        /// Set IPv4 address in CIDR notation (e.g. 10.0.0.1/24).
        #[arg(long)]
        addr: Option<String>,

        /// Set MTU.
        #[arg(long)]
        mtu: Option<u32>,

        /// Bring interface up or down.
        #[arg(long)]
        state: Option<State>,
    },

    /// Show the status of a feth interface.
    Status {
        /// Interface name (e.g. feth0).
        name: String,
    },
}

const IFF_FLAGS: &[(u16, &str)] = &[
    (0x0001, "UP"),
    (0x0002, "BROADCAST"),
    (0x0008, "LOOPBACK"),
    (0x0010, "POINTOPOINT"),
    (0x0100, "NOTRAILERS"),
    (0x0200, "RUNNING"),
    (0x0400, "NOARP"),
    (0x0800, "PROMISC"),
    (0x1000, "ALLMULTI"),
    (0x2000, "OACTIVE"),
    (0x4000, "SIMPLEX"),
    (0x8000, "MULTICAST"),
];

fn format_flags(flags: u16) -> String {
    let names: Vec<&str> = IFF_FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if names.is_empty() {
        format!("{flags:x}<>")
    } else {
        format!("{flags:x}<{}>", names.join(","))
    }
}

fn netmask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn print_status(s: &FethStatus) {
    // Line 1: name, flags, mtu
    println!("{}: flags={} mtu {}", s.name, format_flags(s.flags), s.mtu);

    // inet line
    if let Some(addr) = s.inet {
        let prefix = s.netmask.map_or(0, netmask_to_prefix);
        let netmask_hex = s
            .netmask
            .map(|m| format!("0x{:08x}", u32::from(m)))
            .unwrap_or_default();
        println!("\tinet {addr} netmask {netmask_hex} prefix {prefix}");
    }

    // peer line
    if let Some(peer) = &s.peer {
        println!("\tpeer: {peer}");
    }

    // status line
    println!(
        "\tstatus: {}",
        if s.is_up() { "active" } else { "inactive" }
    );
}

fn parse_cidr(s: &str) -> Result<(String, u8), Box<dyn std::error::Error>> {
    let (addr, prefix) = s.split_once('/').ok_or_else(|| {
        format!("invalid CIDR notation: {s} (expected addr/prefix, e.g. 10.0.0.1/24)")
    })?;
    let prefix_len: u8 = prefix.parse()?;
    Ok((addr.to_string(), prefix_len))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Cmd::Create { units } => {
            for unit in units {
                let feth = Feth::create(unit)?;
                println!("created {}", feth.name());
            }
        }
        Cmd::Destroy { names } => {
            for name in &names {
                let feth = Feth::from_existing(name)?;
                feth.destroy()?;
                println!("destroyed {name}");
            }
        }
        Cmd::Set {
            name,
            peer,
            addr,
            mtu,
            state,
        } => {
            let feth = Feth::from_existing(&name)?;

            if let Some(peer) = &peer {
                if peer == "none" {
                    feth.remove_peer()?;
                    println!("removed peer from {name}");
                } else {
                    feth.set_peer(peer)?;
                    println!("set peer {name} -> {peer}");
                }
            }

            if let Some(cidr) = &addr {
                let (ip, prefix_len) = parse_cidr(cidr)?;
                feth.set_inet(&ip, prefix_len)?;
                println!("set {name} addr {ip}/{prefix_len}");
            }

            if let Some(mtu) = mtu {
                feth.set_mtu(mtu)?;
                println!("set {name} mtu {mtu}");
            }

            if let Some(state) = &state {
                match state {
                    State::Up => {
                        feth.up()?;
                        println!("{name} is up");
                    }
                    State::Down => {
                        feth.down()?;
                        println!("{name} is down");
                    }
                }
            }
        }
        Cmd::Status { name } => {
            let feth = Feth::from_existing(&name)?;
            let s = feth.status()?;
            print_status(&s);
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
