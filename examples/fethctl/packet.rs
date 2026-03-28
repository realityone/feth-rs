//! Zero-copy packet parsing and building for Ethernet, ARP, IPv4, and ICMP.
//!
//! Header structs use `#[repr(C)]` matching the wire format, so parsing is a
//! pointer cast with no field copying. All multi-byte fields are stored as
//! byte arrays (network byte order) with accessor methods for host values.

#![allow(
    dead_code,
    clippy::trivially_copy_pass_by_ref,
    clippy::wrong_self_convention
)]

use std::{fmt, net::Ipv4Addr};

// ── Internet checksum (RFC 1071) ──

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

// ── MAC address ──

/// A 6-byte IEEE 802 MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0; 6]);

    /// Generate a locally-administered MAC from an IPv4 address: `02:fe:a:b:c:d`.
    pub fn from_ipv4(ip: Ipv4Addr) -> Self {
        let o = ip.octets();
        Self([0x02, 0xfe, o[0], o[1], o[2], o[3]])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

// ── EtherType ──

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: Self = Self(0x0800);
    pub const ARP: Self = Self(0x0806);
    pub const IPV6: Self = Self(0x86DD);
    pub const VLAN: Self = Self(0x8100);
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::IPV4 => f.write_str("IPv4"),
            Self::ARP => f.write_str("ARP"),
            Self::IPV6 => f.write_str("IPv6"),
            Self::VLAN => f.write_str("802.1Q"),
            _ => write!(f, "0x{:04x}", self.0),
        }
    }
}

// ── Ethernet ──

/// Wire-format Ethernet header (14 bytes).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct EthernetHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    ethertype: [u8; 2],
}

const _: () = assert!(size_of::<EthernetHeader>() == 14);

impl EthernetHeader {
    pub fn ethertype(&self) -> EtherType {
        EtherType(u16::from_be_bytes(self.ethertype))
    }

    pub fn set_ethertype(&mut self, et: EtherType) {
        self.ethertype = et.0.to_be_bytes();
    }
}

/// Parsed ethernet frame: zero-copy header reference + payload slice.
pub struct EthernetFrame<'a> {
    pub header: &'a EthernetHeader,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < size_of::<EthernetHeader>() {
            return None;
        }
        let header = unsafe { &*(data.as_ptr() as *const EthernetHeader) };
        let payload = &data[size_of::<EthernetHeader>()..];
        Some(Self { header, payload })
    }

    // Convenience accessors delegating to header.
    pub fn dst(&self) -> MacAddr {
        self.header.dst
    }
    pub fn src(&self) -> MacAddr {
        self.header.src
    }
    pub fn ethertype(&self) -> EtherType {
        self.header.ethertype()
    }
}

/// Builder for ethernet frames.
pub struct EthernetBuilder {
    dst: MacAddr,
    src: MacAddr,
    ethertype: EtherType,
}

impl EthernetBuilder {
    pub fn new(dst: MacAddr, src: MacAddr, ethertype: EtherType) -> Self {
        Self {
            dst,
            src,
            ethertype,
        }
    }

    pub fn build(&self, payload: &[u8]) -> Vec<u8> {
        let hdr_len = size_of::<EthernetHeader>();
        let mut frame = vec![0u8; hdr_len + payload.len()];
        let header = unsafe { &mut *(frame.as_mut_ptr() as *mut EthernetHeader) };
        header.dst = self.dst;
        header.src = self.src;
        header.set_ethertype(self.ethertype);
        frame[hdr_len..].copy_from_slice(payload);
        frame
    }
}

// ── ARP ──

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpOp(pub u16);

impl ArpOp {
    pub const REQUEST: Self = Self(1);
    pub const REPLY: Self = Self(2);
}

impl fmt::Display for ArpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::REQUEST => f.write_str("request"),
            Self::REPLY => f.write_str("reply"),
            _ => write!(f, "op({})", self.0),
        }
    }
}

/// Wire-format ARP packet for IPv4-over-Ethernet (28 bytes).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ArpPacket {
    hw_type: [u8; 2],
    proto_type: [u8; 2],
    hw_len: u8,
    proto_len: u8,
    op: [u8; 2],
    pub sender_mac: MacAddr,
    sender_ip: [u8; 4],
    pub target_mac: MacAddr,
    target_ip: [u8; 4],
}

const _: () = assert!(size_of::<ArpPacket>() == 28);

impl ArpPacket {
    /// Parse an ARP packet from the ethernet payload (zero-copy).
    pub fn parse(data: &[u8]) -> Option<&Self> {
        if data.len() < size_of::<Self>() {
            return None;
        }
        let pkt = unsafe { &*(data.as_ptr() as *const Self) };
        // Validate: hw_type=1 (Ethernet), proto=0x0800 (IPv4), hw_len=6, proto_len=4
        if pkt.hw_type != [0, 1]
            || pkt.proto_type != [0x08, 0x00]
            || pkt.hw_len != 6
            || pkt.proto_len != 4
        {
            return None;
        }
        Some(pkt)
    }

    pub fn op(&self) -> ArpOp {
        ArpOp(u16::from_be_bytes(self.op))
    }

    pub fn sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.sender_ip)
    }

    pub fn target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.target_ip)
    }

    /// Create an ARP reply.
    pub fn reply(sender_mac: MacAddr, sender_ip: Ipv4Addr, target: &Self) -> Self {
        Self {
            hw_type: [0, 1],
            proto_type: [0x08, 0x00],
            hw_len: 6,
            proto_len: 4,
            op: ArpOp::REPLY.0.to_be_bytes(),
            sender_mac,
            sender_ip: sender_ip.octets(),
            target_mac: target.sender_mac,
            target_ip: target.sender_ip,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        unsafe { std::mem::transmute_copy(self) }
    }

    /// Build a complete ethernet frame containing this ARP packet.
    pub fn to_frame(&self, dst: MacAddr) -> Vec<u8> {
        EthernetBuilder::new(dst, self.sender_mac, EtherType::ARP).build(&self.to_bytes())
    }
}

// ── IPv4 ──

/// Wire-format IPv4 header (20 bytes, no options).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_len: [u8; 2],
    identification: [u8; 2],
    flags_fragment: [u8; 2],
    ttl: u8,
    protocol: u8,
    header_checksum: [u8; 2],
    src: [u8; 4],
    dst: [u8; 4],
}

const _: () = assert!(size_of::<Ipv4Header>() == 20);

impl Ipv4Header {
    pub const PROTO_ICMP: u8 = 1;
    pub const PROTO_TCP: u8 = 6;
    pub const PROTO_UDP: u8 = 17;

    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Internet Header Length in bytes.
    pub fn ihl(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes(self.total_len)
    }

    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src)
    }

    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst)
    }

    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            Self::PROTO_ICMP => "ICMP",
            Self::PROTO_TCP => "TCP",
            Self::PROTO_UDP => "UDP",
            _ => "unknown",
        }
    }
}

/// Parsed IPv4 packet: zero-copy header reference + payload slice.
pub struct Ipv4Packet<'a> {
    pub header: &'a Ipv4Header,
    /// Full header bytes including options (may be longer than 20 bytes).
    pub header_bytes: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parse an IPv4 packet from raw bytes (zero-copy).
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < size_of::<Ipv4Header>() {
            return None;
        }
        let header = unsafe { &*(data.as_ptr() as *const Ipv4Header) };
        if header.version() != 4 {
            return None;
        }
        let ihl = header.ihl();
        if ihl < size_of::<Ipv4Header>() || data.len() < ihl {
            return None;
        }
        let end = (header.total_len() as usize).min(data.len());
        Some(Self {
            header,
            header_bytes: &data[..ihl],
            payload: &data[ihl..end],
        })
    }
}

/// Builder for IPv4 packets.
pub struct Ipv4Builder {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub protocol: u8,
}

impl Ipv4Builder {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8) -> Self {
        Self {
            src,
            dst,
            ttl: 64,
            protocol,
        }
    }

    pub fn build(&self, payload: &[u8]) -> Vec<u8> {
        let hdr_len = size_of::<Ipv4Header>();
        let total_len = (hdr_len + payload.len()) as u16;
        let mut pkt = vec![0u8; total_len as usize];

        let header = unsafe { &mut *(pkt.as_mut_ptr() as *mut Ipv4Header) };
        header.version_ihl = 0x45; // version=4, ihl=5
        header.total_len = total_len.to_be_bytes();
        header.ttl = self.ttl;
        header.protocol = self.protocol;
        header.src = self.src.octets();
        header.dst = self.dst.octets();
        header.header_checksum = checksum(&pkt[..hdr_len]).to_be_bytes();

        pkt[hdr_len..].copy_from_slice(payload);
        pkt
    }
}

// ── ICMP ──

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpType(pub u8);

impl IcmpType {
    pub const ECHO_REPLY: Self = Self(0);
    pub const ECHO_REQUEST: Self = Self(8);
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ECHO_REPLY => f.write_str("echo-reply"),
            Self::ECHO_REQUEST => f.write_str("echo-request"),
            _ => write!(f, "type({})", self.0),
        }
    }
}

/// Wire-format ICMP echo header (8 bytes).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IcmpEchoHeader {
    icmp_type: u8,
    code: u8,
    checksum: [u8; 2],
    id: [u8; 2],
    seq: [u8; 2],
}

const _: () = assert!(size_of::<IcmpEchoHeader>() == 8);

impl IcmpEchoHeader {
    pub fn icmp_type(&self) -> IcmpType {
        IcmpType(self.icmp_type)
    }

    pub fn code(&self) -> u8 {
        self.code
    }

    pub fn id(&self) -> u16 {
        u16::from_be_bytes(self.id)
    }

    pub fn seq(&self) -> u16 {
        u16::from_be_bytes(self.seq)
    }
}

/// Parsed ICMP echo: zero-copy header reference + data slice.
pub struct IcmpEcho<'a> {
    pub header: &'a IcmpEchoHeader,
    pub data: &'a [u8],
}

impl<'a> IcmpEcho<'a> {
    /// Parse an ICMP echo request or reply (zero-copy).
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < size_of::<IcmpEchoHeader>() {
            return None;
        }
        let header = unsafe { &*(data.as_ptr() as *const IcmpEchoHeader) };
        let ty = header.icmp_type();
        if ty != IcmpType::ECHO_REQUEST && ty != IcmpType::ECHO_REPLY {
            return None;
        }
        Some(Self {
            header,
            data: &data[size_of::<IcmpEchoHeader>()..],
        })
    }

    // Convenience accessors.
    pub fn icmp_type(&self) -> IcmpType {
        self.header.icmp_type()
    }
    pub fn id(&self) -> u16 {
        self.header.id()
    }
    pub fn seq(&self) -> u16 {
        self.header.seq()
    }

    /// Build a reply to this ICMP echo request.
    pub fn reply(&self) -> Vec<u8> {
        let hdr_len = size_of::<IcmpEchoHeader>();
        let len = hdr_len + self.data.len();
        let mut buf = vec![0u8; len];

        let reply_hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut IcmpEchoHeader) };
        reply_hdr.icmp_type = IcmpType::ECHO_REPLY.0;
        reply_hdr.code = 0;
        reply_hdr.id = self.header.id;
        reply_hdr.seq = self.header.seq;

        buf[hdr_len..].copy_from_slice(self.data);
        let cksum = checksum(&buf);
        reply_hdr.checksum = cksum.to_be_bytes();
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_display() {
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]);
        assert_eq!(mac.to_string(), "aa:bb:cc:01:02:03");
    }

    #[test]
    fn test_mac_from_ipv4() {
        let mac = MacAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(mac.0, [0x02, 0xfe, 10, 0, 0, 1]);
    }

    #[test]
    fn test_checksum() {
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&data), 0xb861);
    }

    #[test]
    fn test_checksum_verify() {
        let data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&data), 0);
    }

    #[test]
    fn test_ethernet_parse_zero_copy() {
        let mut frame = vec![0u8; 20];
        frame[0..6].copy_from_slice(&[0xFF; 6]);
        frame[6..12].copy_from_slice(&[0x02, 0xfe, 10, 0, 0, 1]);
        frame[12..14].copy_from_slice(&EtherType::ARP.0.to_be_bytes());
        frame[14..20].copy_from_slice(&[1, 2, 3, 4, 5, 6]);

        let eth = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(eth.dst(), MacAddr::BROADCAST);
        assert_eq!(eth.ethertype(), EtherType::ARP);
        assert_eq!(eth.payload, &[1, 2, 3, 4, 5, 6]);
        // Verify zero-copy: header points into the original buffer.
        let hdr_ptr = eth.header as *const EthernetHeader as *const u8;
        assert!(std::ptr::eq(hdr_ptr, frame.as_ptr()));
    }

    #[test]
    fn test_ethernet_build() {
        let src = MacAddr([0x02, 0xfe, 10, 0, 0, 1]);
        let frame = EthernetBuilder::new(MacAddr::BROADCAST, src, EtherType::ARP).build(&[42]);

        let parsed = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(parsed.dst(), MacAddr::BROADCAST);
        assert_eq!(parsed.src(), src);
        assert_eq!(parsed.ethertype(), EtherType::ARP);
        assert_eq!(parsed.payload, &[42]);
    }

    #[test]
    fn test_arp_parse_zero_copy() {
        let pkt = ArpPacket::reply(
            MacAddr([0x22; 6]),
            Ipv4Addr::new(10, 0, 0, 2),
            &ArpPacket {
                hw_type: [0, 1],
                proto_type: [0x08, 0x00],
                hw_len: 6,
                proto_len: 4,
                op: ArpOp::REQUEST.0.to_be_bytes(),
                sender_mac: MacAddr([0x11; 6]),
                sender_ip: Ipv4Addr::new(10, 0, 0, 1).octets(),
                target_mac: MacAddr::ZERO,
                target_ip: Ipv4Addr::new(10, 0, 0, 2).octets(),
            },
        );
        let bytes = pkt.to_bytes();
        let parsed = ArpPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.op(), ArpOp::REPLY);
        assert_eq!(parsed.sender_ip(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(parsed.target_ip(), Ipv4Addr::new(10, 0, 0, 1));
        // Zero-copy: points into bytes.
        assert!(std::ptr::eq(
            parsed as *const ArpPacket as *const u8,
            bytes.as_ptr()
        ));
    }

    #[test]
    fn test_arp_reply() {
        // Build a request first using raw struct
        let request_bytes = {
            let mut buf = [0u8; 28];
            buf[0..2].copy_from_slice(&[0, 1]);
            buf[2..4].copy_from_slice(&[0x08, 0x00]);
            buf[4] = 6;
            buf[5] = 4;
            buf[6..8].copy_from_slice(&ArpOp::REQUEST.0.to_be_bytes());
            buf[8..14].copy_from_slice(&[0x11; 6]);
            buf[14..18].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
            buf[24..28].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
            buf
        };
        let request = ArpPacket::parse(&request_bytes).unwrap();
        let our_mac = MacAddr([0x22; 6]);
        let reply = ArpPacket::reply(our_mac, Ipv4Addr::new(10, 0, 0, 2), request);
        assert_eq!(reply.op(), ArpOp::REPLY);
        assert_eq!(reply.sender_mac, our_mac);
        assert_eq!(reply.sender_ip(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(reply.target_mac, MacAddr([0x11; 6]));
        assert_eq!(reply.target_ip(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_ipv4_build_and_parse() {
        let builder = Ipv4Builder::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Header::PROTO_ICMP,
        );
        let pkt = builder.build(&[1, 2, 3, 4]);

        let parsed = Ipv4Packet::parse(&pkt).unwrap();
        assert_eq!(parsed.header.src(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(parsed.header.dst(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(parsed.header.protocol(), Ipv4Header::PROTO_ICMP);
        assert_eq!(parsed.header.ttl(), 64);
        assert_eq!(parsed.payload, &[1, 2, 3, 4]);
        assert_eq!(checksum(parsed.header_bytes), 0);
    }

    #[test]
    fn test_icmp_echo_reply() {
        let request_data = [8, 0, 0, 0, 0, 1, 0, 1, 0xAA, 0xBB];
        let echo = IcmpEcho::parse(&request_data).unwrap();
        assert_eq!(echo.icmp_type(), IcmpType::ECHO_REQUEST);
        assert_eq!(echo.id(), 1);
        assert_eq!(echo.seq(), 1);
        assert_eq!(echo.data, &[0xAA, 0xBB]);

        let reply = echo.reply();
        assert_eq!(reply[0], IcmpType::ECHO_REPLY.0);
        assert_eq!(checksum(&reply), 0);
        assert_eq!(&reply[4..6], &0x0001u16.to_be_bytes());
        assert_eq!(&reply[6..8], &0x0001u16.to_be_bytes());
        assert_eq!(&reply[8..], &[0xAA, 0xBB]);
    }
}
