//! Raw I/O on a feth interface via BPF (read) and `AF_NDRV` (write).
//!
//! BPF is used for receiving because it captures all frames (including IP).
//! `AF_NDRV` is used for sending because BPF limits injected packet MTU to 2048.

use std::{
    io::{self, IoSlice, Read, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use crate::xnu;

// ── Constants ──

const BPF_BUFFER_LEN: usize = 131_072;

// ── Helpers ──

/// Wrap a raw fd into an `OwnedFd`, returning an error if it is negative.
fn fd_from_raw(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn set_nonblocking(fd: &OwnedFd, nonblocking: bool) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(raw, libc::F_SETFL, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ── BPF helpers ──

/// Open the first available `/dev/bpfN` device.
fn open_bpf() -> io::Result<OwnedFd> {
    for i in 0..256 {
        let path = format!("/dev/bpf{i}\0");
        let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR) };
        match fd_from_raw(fd) {
            Ok(fd) => return Ok(fd),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no available /dev/bpf device",
    ))
}

/// Configure a BPF fd for raw frame capture on the given interface.
fn configure_bpf(bpf: &OwnedFd, ifname: &str) -> io::Result<()> {
    unsafe {
        let fd = bpf.as_raw_fd();

        // Set buffer length.
        let mut buf_len: libc::c_int = BPF_BUFFER_LEN as libc::c_int;
        if libc::ioctl(fd, libc::BIOCSBLEN, &mut buf_len) != 0 {
            return Err(io::Error::last_os_error());
        }

        // Return packets immediately (don't wait for buffer to fill).
        let mut enable: libc::c_int = 1;
        if libc::ioctl(fd, libc::BIOCIMMEDIATE, &mut enable) != 0 {
            return Err(io::Error::last_os_error());
        }

        // Don't see our own sent packets.
        let mut disable: libc::c_int = 0;
        if libc::ioctl(fd, libc::BIOCSSEESENT, &mut disable) != 0 {
            return Err(io::Error::last_os_error());
        }

        // Bind to the interface.
        let mut ifr = xnu::make_ifreq(ifname);
        if libc::ioctl(fd, libc::BIOCSETIF, &mut ifr) != 0 {
            return Err(io::Error::last_os_error());
        }

        // We supply complete ethernet headers ourselves.
        let mut enable: libc::c_int = 1;
        if libc::ioctl(fd, libc::BIOCSHDRCMPLT, &mut enable) != 0 {
            return Err(io::Error::last_os_error());
        }

        // Promiscuous mode — capture all frames.
        let mut enable: libc::c_int = 1;
        if libc::ioctl(fd, libc::c_ulong::from(libc::BIOCPROMISC), &mut enable) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// ── NDRV helpers ──

/// Open and connect an `AF_NDRV` socket for raw frame injection.
fn open_ndrv(ifname: &str) -> io::Result<OwnedFd> {
    unsafe {
        let fd = fd_from_raw(libc::socket(libc::AF_NDRV, libc::SOCK_RAW, 0))?;

        let mut nd: libc::sockaddr_ndrv = std::mem::zeroed();
        nd.snd_len = size_of::<libc::sockaddr_ndrv>() as u8;
        nd.snd_family = libc::AF_NDRV as u8;

        let name_bytes = ifname.as_bytes();
        if name_bytes.len() >= nd.snd_name.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long for sockaddr_ndrv",
            ));
        }
        nd.snd_name[..name_bytes.len()].copy_from_slice(name_bytes);

        if libc::bind(
            fd.as_raw_fd(),
            &nd as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ndrv>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }

        if libc::connect(
            fd.as_raw_fd(),
            &nd as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ndrv>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(fd)
    }
}

// ── FethIO ──

/// Raw I/O handle for a feth interface.
///
/// Reads ethernet frames via BPF and writes via `AF_NDRV`.
/// The interface must already exist (use [`crate::feth::Feth`] to create it).
pub struct FethIO {
    name: String,
    bpf: OwnedFd,
    ndrv: OwnedFd,
    /// Buffered BPF data (may contain multiple frames).
    read_buf: Vec<u8>,
    /// Number of valid bytes in `read_buf`.
    read_len: usize,
    /// Current parse offset within `read_buf`.
    read_pos: usize,
}

impl FethIO {
    /// Open raw I/O on the given interface name.
    ///
    /// The interface must already exist and should be the "I/O side" of a
    /// feth pair (the peer that has no IP configuration).
    pub fn open(ifname: &str) -> io::Result<Self> {
        let bpf = open_bpf()?;
        configure_bpf(&bpf, ifname)?;
        let ndrv = open_ndrv(ifname)?;

        Ok(Self {
            name: ifname.to_string(),
            bpf,
            ndrv,
            read_buf: vec![0u8; BPF_BUFFER_LEN],
            read_len: 0,
            read_pos: 0,
        })
    }

    /// The interface name this handle is bound to.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set non-blocking mode on both the BPF and NDRV file descriptors.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        set_nonblocking(&self.bpf, nonblocking)?;
        set_nonblocking(&self.ndrv, nonblocking)?;
        Ok(())
    }

    /// The BPF file descriptor (for use with poll/kqueue).
    pub fn bpf_fd(&self) -> RawFd {
        self.bpf.as_raw_fd()
    }

    /// The NDRV file descriptor (for use with poll/kqueue).
    pub fn ndrv_fd(&self) -> RawFd {
        self.ndrv.as_raw_fd()
    }

    /// Decompose into the raw parts: `(name, bpf_fd, ndrv_fd)`.
    pub fn into_parts(self) -> (String, OwnedFd, OwnedFd) {
        (self.name, self.bpf, self.ndrv)
    }

    /// Send a raw ethernet frame.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.ndrv.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Send a raw ethernet frame from multiple buffers (vectored write).
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let n = unsafe {
            libc::writev(
                self.ndrv.as_raw_fd(),
                bufs.as_ptr().cast(),
                bufs.len() as libc::c_int,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Receive a single ethernet frame.
    ///
    /// BPF may return multiple frames per read; this method buffers
    /// internally and returns one frame at a time.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // Try to extract the next frame from the buffer.
            if let Some(n) = self.next_frame(buf)? {
                return Ok(n);
            }
            // Buffer exhausted — read more from BPF.
            self.fill_bpf_buffer()?;
        }
    }

    /// Read from the BPF fd into the internal buffer.
    fn fill_bpf_buffer(&mut self) -> io::Result<()> {
        let n = unsafe {
            libc::read(
                self.bpf.as_raw_fd(),
                self.read_buf.as_mut_ptr().cast(),
                self.read_buf.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        self.read_len = n as usize;
        self.read_pos = 0;
        Ok(())
    }

    /// Parse the next `bpf_hdr` + payload from the internal buffer.
    /// Returns `None` when the buffer is exhausted.
    fn next_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        if self.read_pos >= self.read_len {
            return Ok(None);
        }

        unsafe {
            let ptr = self.read_buf.as_ptr().add(self.read_pos);
            let hdr = &*(ptr as *const libc::bpf_hdr);
            let hdr_len = hdr.bh_hdrlen as usize;
            let cap_len = hdr.bh_caplen as usize;

            // Advance to the next BPF-aligned record.
            // BPF_WORDALIGN: round up to next 4-byte boundary.
            let total = (hdr_len + cap_len + 3) & !3;
            self.read_pos += total;

            if cap_len == 0 {
                return Ok(None);
            }

            let payload_start = ptr.add(hdr_len);
            if buf.len() < cap_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("buffer too small: need {cap_len} bytes, got {}", buf.len()),
                ));
            }
            std::ptr::copy_nonoverlapping(payload_start, buf.as_mut_ptr(), cap_len);
            Ok(Some(cap_len))
        }
    }
}

impl Read for FethIO {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

impl Write for FethIO {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for FethIO {
    /// Returns the BPF fd (the readable side).
    fn as_raw_fd(&self) -> RawFd {
        self.bpf.as_raw_fd()
    }
}
