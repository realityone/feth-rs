//! XNU kernel definitions for network interface management.
//!
//! Contains FFI struct definitions, ioctl wrappers, and low-level helpers
//! for interacting with macOS/XNU network interfaces via `ioctl()`.
//!
//! Type names follow the XNU source naming convention (`snake_case` matching
//! the C identifiers in `bsd/net/if.h`, `bsd/net/if_fake_var.h`, and
//! `bsd/netinet/in_var.h`).

#![allow(non_camel_case_types, clippy::struct_field_names)]

use std::{ffi::CStr, io, mem, net::Ipv4Addr};

// ── Constants (bsd/net/if.h) ──

pub const IFF_UP: libc::c_short = 0x1;

// ── Constants (bsd/net/if_fake_var.h, private) ──

pub const IF_FAKE_S_CMD_SET_PEER: libc::c_ulong = 1;
pub const IF_FAKE_G_CMD_GET_PEER: libc::c_ulong = 1;

// ── FFI struct definitions (only those not provided by libc) ──

/// `struct ifdrv` (bsd/net/if.h) — 40 bytes on 64-bit macOS.
///
/// The C header uses `#pragma pack(4)`, but on 64-bit the layout is
/// identical to the natural `repr(C)` layout for this particular struct.
/// Not available in `libc` for macOS targets.
#[repr(C)]
pub struct ifdrv {
    pub ifd_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifd_cmd: libc::c_ulong,
    pub ifd_len: libc::size_t,
    pub ifd_data: *mut libc::c_void,
}

/// `struct if_fake_request` (`bsd/net/if_fake_var.h`, private) — 160 bytes.
///
/// Layout: 32 bytes reserved + 128-byte union containing `iffr_peer_name`.
/// Private kernel struct, not available in any public SDK.
#[repr(C)]
pub struct if_fake_request {
    pub iffr_reserved: [u64; 4],
    pub iffr_peer_name: [libc::c_char; libc::IFNAMSIZ],
    pub pad: [u8; 128 - libc::IFNAMSIZ],
}

/// `struct in_aliasreq` (`bsd/netinet/in_var.h`) — 64 bytes.
///
/// 16-byte name + 3 × `sockaddr_in`. Not available in `libc` for macOS targets.
#[repr(C)]
pub struct in_aliasreq {
    pub ifra_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifra_addr: libc::sockaddr_in,
    pub ifra_broadaddr: libc::sockaddr_in,
    pub ifra_mask: libc::sockaddr_in,
}

// Compile-time layout assertions matching the C ABI.
const _: () = assert!(size_of::<libc::ifreq>() == 32);
const _: () = assert!(size_of::<ifdrv>() == 40);
const _: () = assert!(size_of::<if_fake_request>() == 160);
const _: () = assert!(size_of::<libc::sockaddr_in>() == 16);
const _: () = assert!(size_of::<in_aliasreq>() == 64);

// ── ioctl definitions via nix macros (bsd/sys/sockio.h) ──
//
// Each macro computes the ioctl request code from the group ('i'), sequence
// number, and struct size — matching the macOS `_IOW` / `_IOWR` encoding.
//
// _IOWR (read-write) → ioctl_readwrite!  → fn(fd, *mut T)
// _IOW  (write)      → ioctl_write_ptr!  → fn(fd, *const T)

pub mod ioctl {
    use super::{ifdrv, in_aliasreq};

    // SIOCIFCREATE2: _IOWR('i', 122, struct ifreq)
    nix::ioctl_readwrite!(siocifcreate2, b'i', 122, libc::ifreq);
    // SIOCIFDESTROY: _IOW('i', 121, struct ifreq)
    nix::ioctl_write_ptr!(siocifdestroy, b'i', 121, libc::ifreq);
    // SIOCSDRVSPEC: _IOW('i', 123, struct ifdrv)
    nix::ioctl_write_ptr!(siocsdrvspec, b'i', 123, ifdrv);
    // SIOCGDRVSPEC: _IOWR('i', 123, struct ifdrv)
    nix::ioctl_readwrite!(siocgdrvspec, b'i', 123, ifdrv);
    // SIOCSIFFLAGS: _IOW('i', 16, struct ifreq)
    nix::ioctl_write_ptr!(siocsifflags, b'i', 16, libc::ifreq);
    // SIOCGIFFLAGS: _IOWR('i', 17, struct ifreq)
    nix::ioctl_readwrite!(siocgifflags, b'i', 17, libc::ifreq);
    // SIOCSIFMTU: _IOW('i', 52, struct ifreq)
    nix::ioctl_write_ptr!(siocsifmtu, b'i', 52, libc::ifreq);
    // SIOCGIFMTU: _IOWR('i', 51, struct ifreq)
    nix::ioctl_readwrite!(siocgifmtu, b'i', 51, libc::ifreq);
    // SIOCAIFADDR: _IOW('i', 26, struct in_aliasreq)
    nix::ioctl_write_ptr!(siocaifaddr, b'i', 26, in_aliasreq);
    // SIOCGIFADDR: _IOWR('i', 33, struct ifreq)
    nix::ioctl_readwrite!(siocgifaddr, b'i', 33, libc::ifreq);
    // SIOCGIFNETMASK: _IOWR('i', 37, struct ifreq)
    nix::ioctl_readwrite!(siocgifnetmask, b'i', 37, libc::ifreq);
}

// ── Low-level helpers ──

/// Copy an interface name string into a `c_char` name buffer.
pub fn copy_name(dst: &mut [libc::c_char; libc::IFNAMSIZ], src: &str) {
    let bytes = src.as_bytes();
    let len = bytes.len().min(libc::IFNAMSIZ - 1);
    // SAFETY: `c_char` and `u8` have the same size and alignment.
    let dst_bytes: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<u8>(), libc::IFNAMSIZ) };
    dst_bytes[..len].copy_from_slice(&bytes[..len]);
    dst_bytes[len] = 0;
}

/// Read a null-terminated interface name from a `c_char` buffer.
pub fn read_name(buf: &[libc::c_char; libc::IFNAMSIZ]) -> String {
    // SAFETY: buf is a fixed-size c_char array, safe to interpret as CStr.
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
    cstr.to_string_lossy().into_owned()
}

/// Create a zeroed `ifreq` with the given interface name.
pub fn make_ifreq(name: &str) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    copy_name(&mut ifr.ifr_name, name);
    ifr
}

/// Create a `sockaddr_in` for the given IPv4 address.
pub fn make_sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr_in {
    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
    sin.sin_family = libc::AF_INET as u8;
    sin.sin_port = 0;
    sin.sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
    sin
}

/// Read `ifr_ifru.ifru_addr` as a `sockaddr_in` and extract the IPv4 address.
pub fn ifreq_get_addr(ifr: &libc::ifreq) -> Option<Ipv4Addr> {
    unsafe {
        let sa = &ifr.ifr_ifru.ifru_addr;
        if sa.sa_family != libc::AF_INET as libc::sa_family_t {
            return None;
        }
        let sin = &*(sa as *const libc::sockaddr as *const libc::sockaddr_in);
        let octets = sin.sin_addr.s_addr.to_ne_bytes();
        Some(Ipv4Addr::from(octets))
    }
}

/// Execute a closure with a temporary `AF_INET/SOCK_DGRAM` socket.
pub fn with_socket<F, T, E>(f: F) -> Result<T, E>
where
    F: FnOnce(libc::c_int) -> Result<T, E>,
    E: From<io::Error>,
{
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(E::from(io::Error::last_os_error()));
    }
    let result = f(fd);
    unsafe {
        libc::close(fd);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_and_read_name() {
        let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
        copy_name(&mut buf, "feth0");
        assert_eq!(read_name(&buf), "feth0");
    }

    #[test]
    fn test_copy_name_max_length() {
        let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
        let long_name = "a23456789012345"; // 15 chars, max
        copy_name(&mut buf, long_name);
        assert_eq!(read_name(&buf), long_name);
    }

    #[test]
    fn test_read_name_empty() {
        let buf = [0 as libc::c_char; libc::IFNAMSIZ];
        assert_eq!(read_name(&buf), "");
    }

    #[test]
    fn test_make_sockaddr_in() {
        let sa = make_sockaddr_in(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(sa.sin_len, 16);
        assert_eq!(sa.sin_family, libc::AF_INET as u8);
        assert_eq!(sa.sin_port, 0);
        assert_eq!(sa.sin_addr.s_addr.to_ne_bytes(), [10, 0, 0, 1]);
    }

    #[test]
    fn test_ifreq_flags_roundtrip() {
        let mut ifr = make_ifreq("feth0");
        ifr.ifr_ifru.ifru_flags = 0x1234;
        assert_eq!(unsafe { ifr.ifr_ifru.ifru_flags }, 0x1234);
    }

    #[test]
    fn test_ifreq_mtu_roundtrip() {
        let mut ifr = make_ifreq("feth0");
        ifr.ifr_ifru.ifru_mtu = 9000;
        assert_eq!(unsafe { ifr.ifr_ifru.ifru_mtu }, 9000);
    }
}
