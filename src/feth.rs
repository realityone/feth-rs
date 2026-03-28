use std::{fmt, io, mem, net::Ipv4Addr, str::FromStr};

/// A 6-byte IEEE 802 MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Generate a random locally-administered unicast MAC address.
    ///
    /// The first octet has bit 1 set (locally administered) and bit 0 clear
    /// (unicast).
    pub fn random() -> Self {
        let mut bytes = [0u8; 6];
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut bytes);
        }
        // Set locally administered bit, clear multicast bit
        bytes[0] = (bytes[0] | 0x02) & 0xFE;
        Self(bytes)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({})", self)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(format!("invalid MAC address: {s}"));
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] =
                u8::from_str_radix(part, 16).map_err(|_| format!("invalid MAC address: {s}"))?;
        }
        Ok(MacAddr(bytes))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

use crate::xnu;

// ── Error type ──

#[derive(Debug)]
pub enum Error {
    Ioctl {
        operation: &'static str,
        source: io::Error,
    },
    InvalidName(String),
    InvalidAddress {
        input: String,
        source: std::net::AddrParseError,
    },
    InvalidPrefixLen(u8),
    Socket(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Ioctl { operation, source } => {
                write!(f, "ioctl {operation} failed: {source}")
            }
            Error::InvalidName(name) => write!(f, "invalid interface name: {name}"),
            Error::InvalidAddress { input, source } => {
                write!(f, "invalid address: {input}: {source}")
            }
            Error::InvalidPrefixLen(len) => {
                write!(f, "invalid prefix length: {len} (must be 0-32)")
            }
            Error::Socket(e) => write!(f, "failed to create socket: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Ioctl { source, .. } | Error::Socket(source) => Some(source),
            Error::InvalidAddress { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Socket(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ── Internal helpers ──

fn ioctl_err(op: &'static str) -> impl FnOnce(nix::errno::Errno) -> Error {
    move |e| Error::Ioctl {
        operation: op,
        source: e.into(),
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(Error::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_prefix_len(prefix_len: u8) -> Result<()> {
    if prefix_len > 32 {
        return Err(Error::InvalidPrefixLen(prefix_len));
    }
    Ok(())
}

fn parse_addr(addr: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(addr).map_err(|e| Error::InvalidAddress {
        input: addr.to_string(),
        source: e,
    })
}

fn prefix_to_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(!0u32 << (32 - prefix_len))
    }
}

fn broadcast_addr(addr: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(addr) | !u32::from(mask))
}

// ── Public types ──

/// Status information for a feth interface, queried via ioctl.
#[derive(Debug, Clone)]
pub struct FethStatus {
    pub name: String,
    pub flags: u16,
    pub mtu: u32,
    pub peer: Option<String>,
    pub inet: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
}

impl FethStatus {
    pub fn is_up(&self) -> bool {
        self.flags & (xnu::IFF_UP as u16) != 0
    }
}

// ── Feth interface handle ──

/// A handle representing a feth (fake ethernet) interface.
///
/// All operations use direct `ioctl()` system calls (via the `nix` crate)
/// rather than spawning `ifconfig` subprocesses.
#[derive(Debug, Clone)]
pub struct Feth {
    name: String,
}

impl Feth {
    /// Create a new feth interface with the given unit number.
    ///
    /// Issues `SIOCIFCREATE2` with name `"feth<unit>"`.
    pub fn create(unit: u32) -> Result<Self> {
        let name = format!("feth{unit}");
        validate_name(&name)?;
        xnu::with_socket(|fd| {
            let mut ifr = xnu::make_ifreq(&name);
            unsafe { xnu::ioctl::siocifcreate2(fd, &mut ifr) }
                .map_err(ioctl_err("SIOCIFCREATE2"))?;
            let actual_name = xnu::read_name(&ifr.ifr_name);
            Ok(Self { name: actual_name })
        })
    }

    /// Create a new feth interface with an auto-assigned unit number.
    ///
    /// Issues `SIOCIFCREATE2` with name `"feth"`. The kernel assigns the
    /// next available unit number and returns the full name.
    pub fn create_auto() -> Result<Self> {
        xnu::with_socket(|fd| {
            let mut ifr = xnu::make_ifreq("feth");
            unsafe { xnu::ioctl::siocifcreate2(fd, &mut ifr) }
                .map_err(ioctl_err("SIOCIFCREATE2"))?;
            let actual_name = xnu::read_name(&ifr.ifr_name);
            if actual_name.is_empty() {
                return Err(Error::InvalidName(
                    "empty name returned by kernel".to_string(),
                ));
            }
            Ok(Self { name: actual_name })
        })
    }

    /// Create a new feth interface and immediately set its peer.
    ///
    /// Equivalent to `ifconfig feth<unit> create peer <peer_name>`.
    pub fn create_with_peer(unit: u32, peer_name: &str) -> Result<Self> {
        let feth = Self::create(unit)?;
        feth.set_peer(peer_name)?;
        Ok(feth)
    }

    /// Wrap an existing feth interface by name (no ioctl issued).
    pub fn from_existing(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_name(&name)?;
        Ok(Self { name })
    }

    /// Return the interface name (e.g. `"feth0"`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Destroy this feth interface.
    ///
    /// Issues `SIOCIFDESTROY`.
    pub fn destroy(&self) -> Result<()> {
        xnu::with_socket(|fd| {
            let ifr = xnu::make_ifreq(&self.name);
            unsafe { xnu::ioctl::siocifdestroy(fd, &ifr) }.map_err(ioctl_err("SIOCIFDESTROY"))?;
            Ok(())
        })
    }

    /// Set the peer for this interface.
    ///
    /// Issues `SIOCSDRVSPEC` with `IF_FAKE_S_CMD_SET_PEER`.
    pub fn set_peer(&self, peer_name: &str) -> Result<()> {
        validate_name(peer_name)?;
        xnu::with_socket(|fd| {
            let mut iffr: xnu::if_fake_request = unsafe { mem::zeroed() };
            xnu::copy_name(&mut iffr.iffr_peer_name, peer_name);

            let mut ifd: xnu::ifdrv = unsafe { mem::zeroed() };
            xnu::copy_name(&mut ifd.ifd_name, &self.name);
            ifd.ifd_cmd = xnu::IF_FAKE_S_CMD_SET_PEER;
            ifd.ifd_len = size_of::<xnu::if_fake_request>();
            ifd.ifd_data = &mut iffr as *mut xnu::if_fake_request as *mut libc::c_void;

            unsafe { xnu::ioctl::siocsdrvspec(fd, &ifd) }
                .map_err(ioctl_err("SIOCSDRVSPEC set peer"))?;
            Ok(())
        })
    }

    /// Remove the peer association.
    ///
    /// Issues `SIOCSDRVSPEC` with `IF_FAKE_S_CMD_SET_PEER` and an empty
    /// peer name, which the kernel interprets as "clear the peer".
    pub fn remove_peer(&self) -> Result<()> {
        xnu::with_socket(|fd| {
            let mut iffr: xnu::if_fake_request = unsafe { mem::zeroed() };
            // iffr_peer_name stays all zeros = empty string → clears peer

            let mut ifd: xnu::ifdrv = unsafe { mem::zeroed() };
            xnu::copy_name(&mut ifd.ifd_name, &self.name);
            ifd.ifd_cmd = xnu::IF_FAKE_S_CMD_SET_PEER;
            ifd.ifd_len = size_of::<xnu::if_fake_request>();
            ifd.ifd_data = &mut iffr as *mut xnu::if_fake_request as *mut libc::c_void;

            unsafe { xnu::ioctl::siocsdrvspec(fd, &ifd) }
                .map_err(ioctl_err("SIOCSDRVSPEC remove peer"))?;
            Ok(())
        })
    }

    /// Get the current peer name, if any.
    ///
    /// Issues `SIOCGDRVSPEC` with `IF_FAKE_G_CMD_GET_PEER`.
    pub fn get_peer(&self) -> Result<Option<String>> {
        xnu::with_socket(|fd| {
            let mut iffr: xnu::if_fake_request = unsafe { mem::zeroed() };

            let mut ifd: xnu::ifdrv = unsafe { mem::zeroed() };
            xnu::copy_name(&mut ifd.ifd_name, &self.name);
            ifd.ifd_cmd = xnu::IF_FAKE_G_CMD_GET_PEER;
            ifd.ifd_len = size_of::<xnu::if_fake_request>();
            ifd.ifd_data = &mut iffr as *mut xnu::if_fake_request as *mut libc::c_void;

            unsafe { xnu::ioctl::siocgdrvspec(fd, &mut ifd) }
                .map_err(ioctl_err("SIOCGDRVSPEC get peer"))?;

            let name = xnu::read_name(&iffr.iffr_peer_name);
            if name.is_empty() {
                Ok(None)
            } else {
                Ok(Some(name))
            }
        })
    }

    /// Set an IPv4 address with prefix length on this interface.
    ///
    /// Issues `SIOCAIFADDR` with the address, broadcast, and netmask
    /// derived from `addr` and `prefix_len`.
    pub fn set_inet(&self, addr: &str, prefix_len: u8) -> Result<()> {
        validate_prefix_len(prefix_len)?;
        let ip = parse_addr(addr)?;
        let mask = prefix_to_mask(prefix_len);
        let bcast = broadcast_addr(ip, mask);

        xnu::with_socket(|fd| {
            let mut req: xnu::in_aliasreq = unsafe { mem::zeroed() };
            xnu::copy_name(&mut req.ifra_name, &self.name);
            req.ifra_addr = xnu::make_sockaddr_in(ip);
            req.ifra_broadaddr = xnu::make_sockaddr_in(bcast);
            req.ifra_mask = xnu::make_sockaddr_in(mask);

            unsafe { xnu::ioctl::siocaifaddr(fd, &req) }.map_err(ioctl_err("SIOCAIFADDR"))?;
            Ok(())
        })
    }

    /// Remove the IPv4 address from this interface.
    ///
    /// Issues `SIOCDIFADDR`.
    pub fn remove_inet(&self) -> Result<()> {
        xnu::with_socket(|fd| {
            let ifr = xnu::make_ifreq(&self.name);
            unsafe { xnu::ioctl::siocdifaddr(fd, &ifr) }.map_err(ioctl_err("SIOCDIFADDR"))?;
            Ok(())
        })
    }

    /// Set the MTU for this interface.
    ///
    /// Issues `SIOCSIFMTU`.
    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        xnu::with_socket(|fd| {
            let mut ifr = xnu::make_ifreq(&self.name);
            ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;
            unsafe { xnu::ioctl::siocsifmtu(fd, &ifr) }.map_err(ioctl_err("SIOCSIFMTU"))?;
            Ok(())
        })
    }

    /// Bring the interface up.
    ///
    /// Issues `SIOCGIFFLAGS` then `SIOCSIFFLAGS` with `IFF_UP` set.
    pub fn up(&self) -> Result<()> {
        xnu::with_socket(|fd| {
            let mut ifr = xnu::make_ifreq(&self.name);
            unsafe { xnu::ioctl::siocgifflags(fd, &mut ifr) }.map_err(ioctl_err("SIOCGIFFLAGS"))?;
            unsafe { ifr.ifr_ifru.ifru_flags |= xnu::IFF_UP };
            unsafe { xnu::ioctl::siocsifflags(fd, &ifr) }.map_err(ioctl_err("SIOCSIFFLAGS"))?;
            Ok(())
        })
    }

    /// Bring the interface down.
    ///
    /// Issues `SIOCGIFFLAGS` then `SIOCSIFFLAGS` with `IFF_UP` cleared.
    pub fn down(&self) -> Result<()> {
        xnu::with_socket(|fd| {
            let mut ifr = xnu::make_ifreq(&self.name);
            unsafe { xnu::ioctl::siocgifflags(fd, &mut ifr) }.map_err(ioctl_err("SIOCGIFFLAGS"))?;
            unsafe { ifr.ifr_ifru.ifru_flags &= !xnu::IFF_UP };
            unsafe { xnu::ioctl::siocsifflags(fd, &ifr) }.map_err(ioctl_err("SIOCSIFFLAGS"))?;
            Ok(())
        })
    }

    /// Set the MAC (link-layer) address for this interface.
    ///
    /// Issues `SIOCSIFLLADDR`.
    pub fn set_mac(&self, mac: &MacAddr) -> Result<()> {
        xnu::with_socket(|fd| {
            let mut ifr = xnu::make_ifreq(&self.name);
            // Fill ifr_addr as a sockaddr with AF_LINK and the 6 MAC bytes.
            unsafe {
                let sa = &mut ifr.ifr_ifru.ifru_addr;
                sa.sa_len = 6;
                sa.sa_family = libc::AF_LINK as u8;
                for (i, &b) in mac.0.iter().enumerate() {
                    sa.sa_data[i] = b as libc::c_char;
                }
            }
            unsafe { xnu::ioctl::siocsiflladdr(fd, &ifr) }
                .map_err(ioctl_err("SIOCSIFLLADDR"))?;
            Ok(())
        })
    }

    /// Configure the interface in one shot: set peer, assign address, bring up.
    pub fn configure(&self, peer_name: &str, addr: &str, prefix_len: u8) -> Result<()> {
        self.set_peer(peer_name)?;
        self.set_inet(addr, prefix_len)?;
        self.up()
    }

    /// Query the current status of this interface via ioctl.
    pub fn status(&self) -> Result<FethStatus> {
        xnu::with_socket(|fd| {
            // Flags
            let mut ifr = xnu::make_ifreq(&self.name);
            unsafe { xnu::ioctl::siocgifflags(fd, &mut ifr) }.map_err(ioctl_err("SIOCGIFFLAGS"))?;
            let flags = unsafe { ifr.ifr_ifru.ifru_flags } as u16;

            // MTU
            let mut ifr = xnu::make_ifreq(&self.name);
            unsafe { xnu::ioctl::siocgifmtu(fd, &mut ifr) }.map_err(ioctl_err("SIOCGIFMTU"))?;
            let mtu = unsafe { ifr.ifr_ifru.ifru_mtu } as u32;

            // Peer (via driver-specific ioctl)
            let peer = {
                let mut iffr: xnu::if_fake_request = unsafe { mem::zeroed() };
                let mut ifd: xnu::ifdrv = unsafe { mem::zeroed() };
                xnu::copy_name(&mut ifd.ifd_name, &self.name);
                ifd.ifd_cmd = xnu::IF_FAKE_G_CMD_GET_PEER;
                ifd.ifd_len = size_of::<xnu::if_fake_request>();
                ifd.ifd_data = &mut iffr as *mut xnu::if_fake_request as *mut libc::c_void;

                if unsafe { xnu::ioctl::siocgdrvspec(fd, &mut ifd) }.is_ok() {
                    let name = xnu::read_name(&iffr.iffr_peer_name);
                    if name.is_empty() { None } else { Some(name) }
                } else {
                    None
                }
            };

            // IPv4 address (may fail if none configured)
            let inet = {
                let mut ifr = xnu::make_ifreq(&self.name);
                if unsafe { xnu::ioctl::siocgifaddr(fd, &mut ifr) }.is_ok() {
                    xnu::ifreq_get_addr(&ifr)
                } else {
                    None
                }
            };

            // Netmask
            let netmask = {
                let mut ifr = xnu::make_ifreq(&self.name);
                if unsafe { xnu::ioctl::siocgifnetmask(fd, &mut ifr) }.is_ok() {
                    xnu::ifreq_get_addr(&ifr)
                } else {
                    None
                }
            };

            Ok(FethStatus {
                name: self.name.clone(),
                flags,
                mtu,
                peer,
                inet,
                netmask,
            })
        })
    }
}

/// Configuration for one side of a feth pair.
#[derive(Clone, Copy, Default)]
pub struct FethPairSide<'a> {
    /// IPv4 address (e.g. `"10.0.0.1"`).
    pub addr: Option<&'a str>,
    /// Subnet prefix length (e.g. `24`). Required if `addr` is set.
    pub prefix_len: Option<u8>,
    /// MTU to set on this interface.
    pub mtu: Option<u32>,
    /// Whether to bring the interface up (default: not changed).
    pub up: Option<bool>,
    /// MAC address. If `None`, a random locally-administered address is used.
    pub mac: Option<MacAddr>,
}

/// Create a linked pair of feth interfaces.
///
/// Creates both interfaces and peers them bidirectionally. Address
/// assignment, MTU, and link state are applied per-side when specified.
/// On any failure the interfaces are destroyed before returning.
pub fn create_pair(unit_a: u32, side_a: FethPairSide<'_>, unit_b: u32, side_b: FethPairSide<'_>) -> Result<(Feth, Feth)> {
    let a = Feth::create(unit_a)?;
    let b = match Feth::create(unit_b) {
        Ok(b) => b,
        Err(e) => {
            let _ = a.destroy();
            return Err(e);
        }
    };

    let cleanup = |e| {
        let _ = b.destroy();
        let _ = a.destroy();
        e
    };

    // The kernel establishes the bidirectional link — only one side needs to set the peer.
    a.set_peer(b.name()).map_err(&cleanup)?;

    for (feth, side) in [(&a, &side_a), (&b, &side_b)] {
        let mac = side.mac.unwrap_or_else(MacAddr::random);
        feth.set_mac(&mac).map_err(&cleanup)?;
        if let Some(addr) = side.addr {
            let prefix_len = side.prefix_len.unwrap_or(24);
            feth.set_inet(addr, prefix_len).map_err(&cleanup)?;
        }
        if let Some(mtu) = side.mtu {
            feth.set_mtu(mtu).map_err(&cleanup)?;
        }
        if let Some(true) = side.up {
            feth.up().map_err(&cleanup)?;
        }
        if let Some(false) = side.up {
            feth.down().map_err(&cleanup)?;
        }
    }

    Ok((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Validation tests ──

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("feth0").is_ok());
        assert!(validate_name("feth123").is_ok());
        assert!(validate_name("lo0").is_ok());
        assert!(validate_name("a23456789012345").is_ok());
    }

    #[test]
    fn test_validate_name_empty() {
        assert!(matches!(validate_name(""), Err(Error::InvalidName(_))));
    }

    #[test]
    fn test_validate_name_too_long() {
        assert!(matches!(
            validate_name("a234567890123456"),
            Err(Error::InvalidName(_))
        ));
    }

    #[test]
    fn test_validate_prefix_len() {
        assert!(validate_prefix_len(0).is_ok());
        assert!(validate_prefix_len(24).is_ok());
        assert!(validate_prefix_len(32).is_ok());
        assert!(matches!(
            validate_prefix_len(33),
            Err(Error::InvalidPrefixLen(33))
        ));
    }

    #[test]
    fn test_parse_addr_valid() {
        assert_eq!(parse_addr("10.0.0.1").unwrap(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            parse_addr("192.168.1.1").unwrap(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
    }

    #[test]
    fn test_parse_addr_invalid() {
        assert!(matches!(
            parse_addr("not-an-ip"),
            Err(Error::InvalidAddress { .. })
        ));
        assert!(matches!(
            parse_addr("256.0.0.1"),
            Err(Error::InvalidAddress { .. })
        ));
    }

    // ── Netmask / broadcast computation ──

    #[test]
    fn test_prefix_to_mask() {
        assert_eq!(prefix_to_mask(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(prefix_to_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_mask(32), Ipv4Addr::BROADCAST);
        assert_eq!(prefix_to_mask(25), Ipv4Addr::new(255, 255, 255, 128));
    }

    #[test]
    fn test_broadcast_addr() {
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mask = prefix_to_mask(24);
        assert_eq!(broadcast_addr(addr, mask), Ipv4Addr::new(10, 0, 0, 255));

        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let mask = prefix_to_mask(16);
        assert_eq!(
            broadcast_addr(addr, mask),
            Ipv4Addr::new(192, 168, 255, 255)
        );
    }

    // ── from_existing validation ──

    #[test]
    fn test_from_existing_valid() {
        let feth = Feth::from_existing("feth0").unwrap();
        assert_eq!(feth.name(), "feth0");
    }

    #[test]
    fn test_from_existing_invalid_name() {
        assert!(Feth::from_existing("").is_err());
        assert!(Feth::from_existing("a234567890123456").is_err());
    }

    // ── FethStatus helpers ──

    #[test]
    fn test_feth_status_is_up() {
        let status = FethStatus {
            name: "feth0".into(),
            flags: xnu::IFF_UP as u16,
            mtu: 1500,
            peer: None,
            inet: None,
            netmask: None,
        };
        assert!(status.is_up());

        let status = FethStatus {
            name: "feth0".into(),
            flags: 0,
            mtu: 1500,
            peer: None,
            inet: None,
            netmask: None,
        };
        assert!(!status.is_up());
    }
}
