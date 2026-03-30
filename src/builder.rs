//! Builder-pattern API for creating and configuring feth interfaces.
//!
//! The builder supports two backends — [`Backend::Ioctl`] (direct system calls,
//! the default) and [`Backend::Ifconfig`] (shells out to `/sbin/ifconfig`).
//!
//! # Examples
//!
//! ```no_run
//! use feth_rs::builder::{FethBuilder, Backend};
//! use feth_rs::feth::MacAddr;
//!
//! // Create with ioctl backend (default)
//! let feth = FethBuilder::new()
//!     .unit(100)
//!     .peer("feth101")
//!     .addr("10.0.0.1", 24)
//!     .mtu(1400)
//!     .mac(MacAddr::random())
//!     .up()
//!     .build()?;
//!
//! // Create with ifconfig backend
//! let feth = FethBuilder::new()
//!     .backend(Backend::Ifconfig)
//!     .unit(200)
//!     .peer("feth201")
//!     .addr("10.0.0.2", 24)
//!     .up()
//!     .build()?;
//!
//! // Both return a FethHandle that can query status and be destroyed
//! println!("{}", feth.name());
//! feth.destroy()?;
//! # Ok::<(), feth_rs::feth::Error>(())
//! ```

use crate::feth::{self, Error, FethStatus, MacAddr, Result};
use crate::ifconfig::IfconfigFeth;

/// The backend used to manage the feth interface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Backend {
    /// Direct ioctl system calls (default).
    #[default]
    Ioctl,
    /// Shell out to `/sbin/ifconfig`.
    Ifconfig,
}

/// A unified handle that wraps either an ioctl-based or ifconfig-based feth interface.
#[derive(Debug, Clone)]
pub enum FethHandle {
    Ioctl(feth::Feth),
    Ifconfig(IfconfigFeth),
}

impl FethHandle {
    /// Return the interface name.
    pub fn name(&self) -> &str {
        match self {
            Self::Ioctl(f) => f.name(),
            Self::Ifconfig(f) => f.name(),
        }
    }

    /// Destroy this interface.
    pub fn destroy(&self) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.destroy(),
            Self::Ifconfig(f) => f.destroy(),
        }
    }

    /// Query the current status.
    pub fn status(&self) -> Result<FethStatus> {
        match self {
            Self::Ioctl(f) => f.status(),
            Self::Ifconfig(f) => f.status(),
        }
    }

    /// Set the peer interface.
    pub fn set_peer(&self, peer_name: &str) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.set_peer(peer_name),
            Self::Ifconfig(f) => f.set_peer(peer_name),
        }
    }

    /// Remove the peer association.
    pub fn remove_peer(&self) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.remove_peer(),
            Self::Ifconfig(f) => f.remove_peer(),
        }
    }

    /// Assign an IPv4 address.
    pub fn set_inet(&self, addr: &str, prefix_len: u8) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.set_inet(addr, prefix_len),
            Self::Ifconfig(f) => f.set_inet(addr, prefix_len),
        }
    }

    /// Remove the IPv4 address.
    pub fn remove_inet(&self) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.remove_inet(),
            Self::Ifconfig(f) => f.remove_inet(),
        }
    }

    /// Set the MTU.
    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.set_mtu(mtu),
            Self::Ifconfig(f) => f.set_mtu(mtu),
        }
    }

    /// Bring the interface up.
    pub fn up(&self) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.up(),
            Self::Ifconfig(f) => f.up(),
        }
    }

    /// Bring the interface down.
    pub fn down(&self) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.down(),
            Self::Ifconfig(f) => f.down(),
        }
    }

    /// Set the MAC address.
    pub fn set_mac(&self, mac: &MacAddr) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.set_mac(mac),
            Self::Ifconfig(f) => f.set_mac(mac),
        }
    }

    /// Configure IPv6 NDP parameters.
    pub fn configure_ipv6(&self, perform_nud: bool, accept_router_adverts: bool) -> Result<()> {
        match self {
            Self::Ioctl(f) => f.configure_ipv6(perform_nud, accept_router_adverts),
            Self::Ifconfig(f) => f.configure_ipv6(perform_nud, accept_router_adverts),
        }
    }
}

/// Builder for creating and configuring a feth interface.
///
/// Collects configuration and applies it atomically in [`build()`](FethBuilder::build).
/// On failure during configuration, the interface is destroyed before returning.
#[must_use]
pub struct FethBuilder {
    backend: Backend,
    unit: Option<u32>,
    existing: Option<String>,
    peer: Option<String>,
    addr: Option<(String, u8)>,
    mtu: Option<u32>,
    mac: Option<MacAddr>,
    bring_up: bool,
    ipv6: Option<(bool, bool)>,
}

impl FethBuilder {
    /// Create a new builder with default settings (ioctl backend, auto-assigned unit).
    pub fn new() -> Self {
        Self {
            backend: Backend::default(),
            unit: None,
            existing: None,
            peer: None,
            addr: None,
            mtu: None,
            mac: None,
            bring_up: false,
            ipv6: None,
        }
    }

    /// Select the backend.
    pub fn backend(mut self, backend: Backend) -> Self {
        self.backend = backend;
        self
    }

    /// Set the unit number for the interface (e.g. `100` creates `feth100`).
    ///
    /// If not set, the kernel auto-assigns the next available unit.
    pub fn unit(mut self, unit: u32) -> Self {
        self.unit = Some(unit);
        self.existing = None;
        self
    }

    /// Wrap an existing interface by name instead of creating a new one.
    pub fn existing(mut self, name: impl Into<String>) -> Self {
        self.existing = Some(name.into());
        self.unit = None;
        self
    }

    /// Set the peer interface name.
    pub fn peer(mut self, peer_name: impl Into<String>) -> Self {
        self.peer = Some(peer_name.into());
        self
    }

    /// Assign an IPv4 address with the given prefix length.
    pub fn addr(mut self, addr: impl Into<String>, prefix_len: u8) -> Self {
        self.addr = Some((addr.into(), prefix_len));
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the MAC address.
    pub fn mac(mut self, mac: MacAddr) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Bring the interface up after configuration.
    pub fn up(mut self) -> Self {
        self.bring_up = true;
        self
    }

    /// Configure IPv6 NDP parameters.
    pub fn ipv6(mut self, perform_nud: bool, accept_router_adverts: bool) -> Self {
        self.ipv6 = Some((perform_nud, accept_router_adverts));
        self
    }

    /// Build the feth interface, applying all configured options.
    ///
    /// If creation succeeds but a subsequent configuration step fails,
    /// the interface is destroyed before the error is returned (unless
    /// wrapping an existing interface).
    pub fn build(self) -> Result<FethHandle> {
        match self.backend {
            Backend::Ioctl => self.build_ioctl(),
            Backend::Ifconfig => self.build_ifconfig(),
        }
    }

    fn build_ioctl(self) -> Result<FethHandle> {
        let created = self.existing.is_none();
        let feth = if let Some(name) = self.existing {
            feth::Feth::from_existing(name)?
        } else if let Some(unit) = self.unit {
            feth::Feth::create(unit)?
        } else {
            feth::Feth::create_auto()?
        };

        let cleanup = |e: Error| {
            if created {
                let _ = feth.destroy();
            }
            e
        };

        if let Some(ref peer) = self.peer {
            feth.set_peer(peer).map_err(&cleanup)?;
        }
        if let Some(mac) = self.mac {
            feth.set_mac(&mac).map_err(&cleanup)?;
        }
        if let Some((ref addr, prefix_len)) = self.addr {
            feth.set_inet(addr, prefix_len).map_err(&cleanup)?;
        }
        if let Some(mtu) = self.mtu {
            feth.set_mtu(mtu).map_err(&cleanup)?;
        }
        if self.bring_up {
            feth.up().map_err(&cleanup)?;
        }
        if let Some((perform_nud, accept_ra)) = self.ipv6 {
            feth.configure_ipv6(perform_nud, accept_ra)
                .map_err(&cleanup)?;
        }

        Ok(FethHandle::Ioctl(feth))
    }

    fn build_ifconfig(self) -> Result<FethHandle> {
        let created = self.existing.is_none();
        let feth = if let Some(name) = self.existing {
            IfconfigFeth::from_existing(name)?
        } else if let Some(unit) = self.unit {
            IfconfigFeth::create(unit)?
        } else {
            IfconfigFeth::create_auto()?
        };

        let cleanup = |e: Error| {
            if created {
                let _ = feth.destroy();
            }
            e
        };

        if let Some(ref peer) = self.peer {
            feth.set_peer(peer).map_err(&cleanup)?;
        }
        if let Some(mac) = self.mac {
            feth.set_mac(&mac).map_err(&cleanup)?;
        }
        if let Some((ref addr, prefix_len)) = self.addr {
            feth.set_inet(addr, prefix_len).map_err(&cleanup)?;
        }
        if let Some(mtu) = self.mtu {
            feth.set_mtu(mtu).map_err(&cleanup)?;
        }
        if self.bring_up {
            feth.up().map_err(&cleanup)?;
        }
        if let Some((perform_nud, accept_ra)) = self.ipv6 {
            feth.configure_ipv6(perform_nud, accept_ra)
                .map_err(&cleanup)?;
        }

        Ok(FethHandle::Ifconfig(feth))
    }
}

impl Default for FethBuilder {
    fn default() -> Self {
        Self::new()
    }
}
