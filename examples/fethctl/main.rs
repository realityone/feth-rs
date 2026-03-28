//! CLI tool for managing feth (fake ethernet) interfaces.
//!
//! Must be run as root:
//!
//!     sudo cargo run --example fethctl -- <command>

mod packet;

use std::{net::Ipv4Addr, process::ExitCode, str::FromStr};

use clap::{Parser, Subcommand, ValueEnum};
use feth_rs::{
    feth_tokio::AsyncFethIO,
    feth::{Feth, FethStatus},
    feth_io::FethIO,
};
use packet::{
    ArpOp, ArpPacket, EtherType, EthernetBuilder, EthernetFrame, IcmpEcho, IcmpType, Ipv4Builder,
    Ipv4Header, Ipv4Packet, MacAddr,
};

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

    /// Capture and log L2 frames on a feth interface.
    Capture {
        /// Interface name (e.g. feth0).
        name: String,
    },

    /// Respond to ARP and ICMP echo requests on a feth interface.
    Icmp {
        /// Interface name (e.g. feth101).
        name: String,

        /// IPv4 address to claim (e.g. 10.0.0.2).
        addr: String,
    },
}

// ── Status display ──

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
    println!("{}: flags={} mtu {}", s.name, format_flags(s.flags), s.mtu);
    if let Some(addr) = s.inet {
        let prefix = s.netmask.map_or(0, netmask_to_prefix);
        let netmask_hex = s
            .netmask
            .map(|m| format!("0x{:08x}", u32::from(m)))
            .unwrap_or_default();
        println!("\tinet {addr} netmask {netmask_hex} prefix {prefix}");
    }
    if let Some(peer) = &s.peer {
        println!("\tpeer: {peer}");
    }
    println!(
        "\tstatus: {}",
        if s.is_up() { "active" } else { "inactive" }
    );
}

// ── Capture display ──

fn print_frame(seq: u64, buf: &[u8]) {
    let Some(eth) = EthernetFrame::parse(buf) else {
        println!("#{seq} <short frame, {len} bytes>", len = buf.len());
        return;
    };
    let et = eth.ethertype();
    println!(
        "#{seq} {src} -> {dst}  {et} (0x{raw:04x})  {len} bytes",
        src = eth.src(),
        dst = eth.dst(),
        raw = et.0,
        len = buf.len(),
    );
}

// ── ICMP responder ──

fn handle_arp(
    frame: &EthernetFrame<'_>,
    our_ip: Ipv4Addr,
    our_mac: MacAddr,
    io: &AsyncFethIO,
) -> std::io::Result<bool> {
    let Some(arp) = ArpPacket::parse(frame.payload) else {
        return Ok(false);
    };
    if arp.op() != ArpOp::REQUEST || arp.target_ip() != our_ip {
        return Ok(false);
    }

    let reply = ArpPacket::reply(our_mac, our_ip, arp);
    io.send(&reply.to_frame(arp.sender_mac))?;
    println!("  ARP reply: {our_ip} is-at {our_mac}");
    println!("    (to {} at {})", arp.sender_ip(), arp.sender_mac);
    Ok(true)
}

fn handle_icmp(
    frame: &EthernetFrame<'_>,
    our_ip: Ipv4Addr,
    our_mac: MacAddr,
    io: &AsyncFethIO,
) -> std::io::Result<bool> {
    let Some(ip) = Ipv4Packet::parse(frame.payload) else {
        return Ok(false);
    };
    if ip.header.protocol() != Ipv4Header::PROTO_ICMP || ip.header.dst() != our_ip {
        return Ok(false);
    }
    let Some(echo) = IcmpEcho::parse(ip.payload) else {
        return Ok(false);
    };
    if echo.icmp_type() != IcmpType::ECHO_REQUEST {
        return Ok(false);
    }

    let icmp_reply = echo.reply();
    let ip_reply =
        Ipv4Builder::new(our_ip, ip.header.src(), Ipv4Header::PROTO_ICMP).build(&icmp_reply);
    let eth_reply = EthernetBuilder::new(frame.src(), our_mac, EtherType::IPV4).build(&ip_reply);
    io.send(&eth_reply)?;
    println!(
        "  ICMP reply: {our_ip} -> {src}  id={id} seq={seq} {len} bytes",
        src = ip.header.src(),
        id = echo.id(),
        seq = echo.seq(),
        len = icmp_reply.len(),
    );
    Ok(true)
}

async fn run_icmp_responder(name: &str, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ip = Ipv4Addr::from_str(addr)?;
    let our_mac = MacAddr::from_ipv4(ip);
    let mut io = AsyncFethIO::open(name)?;
    let mut buf = vec![0u8; 65536];
    println!("listening on {name} as {ip} ({our_mac})");
    loop {
        let n = io.recv(&mut buf).await?;
        let Some(eth) = EthernetFrame::parse(&buf[..n]) else {
            continue;
        };
        match eth.ethertype() {
            EtherType::ARP => {
                handle_arp(&eth, ip, our_mac, &io)?;
            }
            EtherType::IPV4 => {
                handle_icmp(&eth, ip, our_mac, &io)?;
            }
            _ => {}
        }
    }
}

// ── CLI helpers ──

fn parse_cidr(s: &str) -> Result<(String, u8), Box<dyn std::error::Error>> {
    let (addr, prefix) = s.split_once('/').ok_or_else(|| {
        format!("invalid CIDR notation: {s} (expected addr/prefix, e.g. 10.0.0.1/24)")
    })?;
    let prefix_len: u8 = prefix.parse()?;
    Ok((addr.to_string(), prefix_len))
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
                if cidr == "none" {
                    feth.remove_inet()?;
                    println!("removed addr from {name}");
                } else {
                    let (ip, prefix_len) = parse_cidr(cidr)?;
                    feth.set_inet(&ip, prefix_len)?;
                    println!("set {name} addr {ip}/{prefix_len}");
                }
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
        Cmd::Capture { name } => {
            let mut io = FethIO::open(&name)?;
            let mut buf = vec![0u8; 65536];
            let mut seq = 0u64;
            println!("capturing on {name} ...");
            loop {
                let n = io.recv(&mut buf)?;
                seq += 1;
                print_frame(seq, &buf[..n]);
            }
        }
        Cmd::Icmp { name, addr } => {
            run_icmp_responder(&name, &addr).await?;
        }
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
