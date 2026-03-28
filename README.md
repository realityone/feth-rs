# feth-rs

A Rust library for creating and managing macOS fake ethernet (feth) interface pairs, providing TAP-like virtual network devices.

feth interfaces are virtual ethernet interfaces available on macOS that can be paired together. Traffic sent on one side of the pair is received on the other, making them useful for building VPNs, network tunnels, packet capture tools, and testing network stacks without real hardware.

## Features

- Create, configure, and destroy feth interface pairs via ioctl (no subprocess spawning)
- Raw L2 frame I/O using BPF (receive) and `AF_NDRV` (send)
- Async support via tokio (`AsyncFd` integration)
- Vectored writes (`writev` / `IoSlice`) for zero-copy packet assembly
- Zero unsafe abstraction leaks -- all FFI is internal

## Architecture

A feth pair consists of two interfaces linked as peers:

```
┌─────────────────────┐         ┌─────────────────────┐
│  feth0 (virtual)    │  peer   │  feth1 (I/O side)   │
│                     │◄───────►│                     │
│  IP: 10.0.0.1/24    │         │  BPF + AF_NDRV      │
│  Managed by kernel  │         │  Raw frame access   │
└─────────────────────┘         └─────────────────────┘
```

- **Virtual side** (feth0): Has IP configuration, behaves like a normal network interface. The kernel handles ARP, routing, etc.
- **I/O side** (feth1): Used for raw frame capture and injection. Your application reads/writes complete ethernet frames here.

BPF (`/dev/bpfN`) is used for receiving because it captures all frames including IP traffic. `AF_NDRV` sockets are used for sending because BPF limits injected packet MTU to 2048 bytes.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
feth-rs = { git = "https://github.com/realityone/feth-rs" }

# For async/tokio support:
feth-rs = { git = "https://github.com/realityone/feth-rs", features = ["tokio"] }
```

### Creating a feth pair

```rust
use feth_rs::feth::{create_pair, FethPairSide};

// Create a pair with full configuration in one call
let (virt, io_side) = create_pair(
    0,
    FethPairSide { addr: Some("10.0.0.1"), prefix_len: Some(24), up: Some(true), ..Default::default() },
    101,
    FethPairSide { up: Some(true), ..Default::default() },
)?;

// Minimal — just create and peer, configure later
let (a, b) = create_pair(0, FethPairSide::default(), 1, FethPairSide::default())?;

// Or step by step:
let feth0 = Feth::create(0)?;
let feth1 = Feth::create(1)?;
feth0.set_peer(feth1.name())?;
feth0.set_inet("10.0.0.1", 24)?;
feth0.up()?;
feth1.up()?;
```

### Synchronous I/O

```rust
use feth_rs::feth_io::FethIO;

let mut io = FethIO::open("feth1")?;

// Receive a frame
let mut buf = vec![0u8; 65536];
let n = io.recv(&mut buf)?;
let frame = &buf[..n];

// Send a frame
io.send(frame)?;
```

### Async I/O (tokio)

```rust
use feth_rs::feth_tokio::AsyncFethIO;

let mut io = AsyncFethIO::open("feth1")?;

let mut buf = vec![0u8; 65536];
let n = io.recv(&mut buf).await?;
io.send(&buf[..n])?;
```

> **Note:** `recv()` is async (uses tokio's `AsyncFd` on the BPF descriptor). `send()` is synchronous because writes to `AF_NDRV` are effectively instantaneous kernel buffer copies, and macOS kqueue does not support event filters on `AF_NDRV` sockets.

## Example: fethctl

`fethctl` is a CLI tool included as an example that demonstrates the full library API. It can create/destroy interfaces, configure them, capture frames, and respond to ARP/ICMP requests.

**Requires root privileges** (BPF and interface management need elevated permissions).

### Setup a feth pair and respond to ICMP

This walkthrough creates a feth pair where one side has an IP address managed by the kernel, and the other side runs a userspace ICMP responder.

**Step 1: Create the interfaces**

```bash
sudo cargo run --example fethctl --features tokio -- create 0 101
```

This creates `feth0` and `feth101`.

**Step 2: Peer them together**

```bash
sudo cargo run --example fethctl --features tokio -- set feth0 --peer feth101
sudo cargo run --example fethctl --features tokio -- set feth101 --peer feth0
```

**Step 3: Configure the virtual side with an IP address and bring it up**

```bash
sudo cargo run --example fethctl --features tokio -- set feth0 --addr 10.0.0.1/24 --state up
sudo cargo run --example fethctl --features tokio -- set feth101 --state up
```

`feth0` is now a normal network interface with IP `10.0.0.1/24`.

**Step 4: Verify the setup**

```bash
sudo cargo run --example fethctl --features tokio -- status feth0
# feth0: flags=8963<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
#     inet 10.0.0.1 netmask 0xffffff00 prefix 24
#     peer: feth101
#     status: active
```

**Step 5: Start the ICMP responder on the I/O side**

```bash
sudo cargo run --example fethctl --features tokio -- icmp feth101 10.0.0.2
# listening on feth101 as 10.0.0.2 (02:00:0a:00:00:02)
```

This claims IP `10.0.0.2` on `feth101`, responding to ARP requests and ICMP echo (ping) requests at the ethernet frame level.

**Step 6: Ping from another terminal**

```bash
ping 10.0.0.2
# PING 10.0.0.2 (10.0.0.2): 56 data bytes
# 64 bytes from 10.0.0.2: icmp_seq=0 ttl=64 time=0.456 ms
# 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.327 ms
```

The ICMP responder terminal will show:

```
  ARP reply: 10.0.0.2 is-at 02:00:0a:00:00:02
    (to 10.0.0.1 at aa:bb:cc:dd:ee:ff)
  ICMP reply: 10.0.0.2 -> 10.0.0.1  id=12345 seq=0 64 bytes
  ICMP reply: 10.0.0.2 -> 10.0.0.1  id=12345 seq=1 64 bytes
```

### Other fethctl commands

```bash
# Capture raw frames on an interface
sudo cargo run --example fethctl --features tokio -- capture feth101

# Remove an IP address
sudo cargo run --example fethctl --features tokio -- set feth0 --addr none

# Set MTU
sudo cargo run --example fethctl --features tokio -- set feth0 --mtu 9000

# Bring interface down
sudo cargo run --example fethctl --features tokio -- set feth0 --state down

# Destroy interfaces
sudo cargo run --example fethctl --features tokio -- destroy feth0 feth101
```

## Requirements

- macOS (feth interfaces are a macOS-specific feature)
- Root privileges for interface management and BPF access
- Rust 2024 edition

## License

Apache-2.0

## Thanks

![vibe](assets/vibe.jpg)