//! Ifconfig-based backend for feth interface management.
//!
//! This module provides an alternative to the ioctl-based approach in [`crate::feth`],
//! executing `/sbin/ifconfig` commands to manage feth interfaces. This can be
//! useful when ioctl calls fail (e.g. IPv6 NDP on interfaces not yet fully up) or
//! when running in environments where direct ioctl access is restricted.

use std::{io, net::Ipv4Addr, process::Command};

use crate::feth::{self, Error, FethStatus, MacAddr, Result};

/// Execute an ifconfig command with the given arguments.
fn ifconfig(args: &[&str]) -> Result<String> {
    let output = Command::new("/sbin/ifconfig")
        .args(args)
        .output()
        .map_err(|e| Error::Ifconfig {
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            source: e,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(Error::Ifconfig {
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            source: io::Error::other(stderr),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// A handle representing a feth interface managed via ifconfig commands.
///
/// This is functionally equivalent to [`crate::feth::Feth`] but uses
/// `/sbin/ifconfig` instead of direct ioctl calls.
#[derive(Debug, Clone)]
pub struct IfconfigFeth {
    name: String,
}

impl IfconfigFeth {
    /// Create a new feth interface with the given unit number.
    pub fn create(unit: u32) -> Result<Self> {
        let name = format!("feth{unit}");
        feth::validate_name(&name)?;
        let output = ifconfig(&[&name, "create"])?;
        let actual_name = output.trim();
        let actual_name = if actual_name.is_empty() {
            name
        } else {
            actual_name.to_owned()
        };
        Ok(Self { name: actual_name })
    }

    /// Create a new feth interface with an auto-assigned unit number.
    pub fn create_auto() -> Result<Self> {
        let output = ifconfig(&["feth", "create"])?;
        let actual_name = output.trim().to_owned();
        if actual_name.is_empty() {
            return Err(Error::InvalidName(
                "empty name returned by ifconfig".to_string(),
            ));
        }
        Ok(Self { name: actual_name })
    }

    /// Wrap an existing feth interface by name (no command issued).
    pub fn from_existing(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        feth::validate_name(&name)?;
        Ok(Self { name })
    }

    /// Return the interface name (e.g. `"feth0"`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Destroy this feth interface.
    pub fn destroy(&self) -> Result<()> {
        ifconfig(&[&self.name, "destroy"])?;
        Ok(())
    }

    /// Set the peer interface.
    pub fn set_peer(&self, peer_name: &str) -> Result<()> {
        feth::validate_name(peer_name)?;
        ifconfig(&[&self.name, "peer", peer_name])?;
        Ok(())
    }

    /// Remove the peer association.
    pub fn remove_peer(&self) -> Result<()> {
        ifconfig(&[&self.name, "-peer"])?;
        Ok(())
    }

    /// Assign an IPv4 address with the given prefix length.
    pub fn set_inet(&self, addr: &str, prefix_len: u8) -> Result<()> {
        feth::validate_prefix_len(prefix_len)?;
        let parsed: Ipv4Addr = addr.parse().map_err(|e| Error::InvalidAddress {
            input: addr.to_string(),
            source: e,
        })?;
        let mask = feth::prefix_to_mask(prefix_len);
        let broadcast = feth::broadcast_addr(parsed, mask);
        ifconfig(&[
            &self.name,
            "inet",
            addr,
            "netmask",
            &format!("0x{:08x}", u32::from(mask)),
            "broadcast",
            &broadcast.to_string(),
        ])?;
        Ok(())
    }

    /// Remove the IPv4 address from this interface.
    pub fn remove_inet(&self) -> Result<()> {
        ifconfig(&[&self.name, "inet", "delete"])?;
        Ok(())
    }

    /// Set the MTU on this interface.
    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        ifconfig(&[&self.name, "mtu", &mtu.to_string()])?;
        Ok(())
    }

    /// Bring the interface up.
    pub fn up(&self) -> Result<()> {
        ifconfig(&[&self.name, "up"])?;
        Ok(())
    }

    /// Bring the interface down.
    pub fn down(&self) -> Result<()> {
        ifconfig(&[&self.name, "down"])?;
        Ok(())
    }

    /// Set the MAC (link-layer) address.
    pub fn set_mac(&self, mac: &MacAddr) -> Result<()> {
        ifconfig(&[&self.name, "lladdr", &mac.to_string()])?;
        Ok(())
    }

    /// Configure IPv6 NDP parameters.
    ///
    /// Uses `inet6` flags via ifconfig:
    /// - `perform_nud`: toggles `performnud` / `-performnud`
    /// - `accept_router_adverts`: toggles `autoconf` / `-autoconf`
    pub fn configure_ipv6(&self, perform_nud: bool, accept_router_adverts: bool) -> Result<()> {
        let nud_flag = if perform_nud {
            "performnud"
        } else {
            "-performnud"
        };
        ifconfig(&[&self.name, "inet6", nud_flag])?;

        let autoconf_flag = if accept_router_adverts {
            "autoconf"
        } else {
            "-autoconf"
        };
        ifconfig(&[&self.name, "inet6", autoconf_flag])?;
        Ok(())
    }

    /// Query the current status of this interface via ifconfig output parsing.
    pub fn status(&self) -> Result<FethStatus> {
        let output = ifconfig(&[&self.name])?;
        Ok(parse_ifconfig_status(&self.name, &output))
    }
}

/// Parse ifconfig output into a `FethStatus`.
fn parse_ifconfig_status(name: &str, output: &str) -> FethStatus {
    let mut flags: u16 = 0;
    let mut mtu: u32 = 0;
    let mut peer: Option<String> = None;
    let mut inet: Option<Ipv4Addr> = None;
    let mut netmask: Option<Ipv4Addr> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        // Parse "flags=8863<UP,...> mtu 1500"
        if let Some(rest) = trimmed.strip_prefix("flags=") {
            if let Some(flags_end) = rest.find('<')
                && let Ok(v) = u16::from_str_radix(&rest[..flags_end], 16)
            {
                flags = v;
            }
            if let Some(mtu_pos) = trimmed.find("mtu ") {
                let mtu_str = &trimmed[mtu_pos + 4..];
                let mtu_end = mtu_str
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(mtu_str.len());
                if let Ok(v) = mtu_str[..mtu_end].parse() {
                    mtu = v;
                }
            }
        }

        // Parse "peer: fethN"
        if let Some(rest) = trimmed.strip_prefix("peer: ") {
            peer = Some(rest.trim().to_owned());
        }

        // Parse "inet 10.0.0.1 netmask 0xffffff00 broadcast 10.0.0.255"
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if let Some(addr_str) = parts.first() {
                inet = addr_str.parse().ok();
            }
            if let Some(i) = parts.iter().position(|&s| s == "netmask")
                && let Some(mask_str) = parts.get(i + 1)
            {
                netmask =
                    parse_hex_mask(mask_str).or_else(|| mask_str.parse::<Ipv4Addr>().ok());
            }
        }
    }

    FethStatus {
        name: name.to_owned(),
        flags,
        mtu,
        peer,
        inet,
        netmask,
    }
}

/// Parse a hex netmask like "0xffffff00" into an `Ipv4Addr`.
fn parse_hex_mask(s: &str) -> Option<Ipv4Addr> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    let val = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(val))
}
