//! Async I/O on a feth interface using tokio's `AsyncFd`.
//!
//! This wraps [`FethIO`] for use in async contexts. BPF is used for
//! receiving and `AF_NDRV` for sending, same as the sync version.
//!
//! Only the BPF fd is registered with tokio's reactor (`AsyncFd`).
//! The NDRV fd is kept as a plain `OwnedFd` because writes to a
//! connected `AF_NDRV` socket are effectively instantaneous (kernel
//! buffer copy) and macOS kqueue does not support event filters on
//! `AF_NDRV` sockets.

use std::{
    io::{self, IoSlice},
    os::fd::{AsRawFd, OwnedFd, RawFd},
    sync::Arc,
};

use tokio::io::{unix::AsyncFd, Interest};

use crate::feth_io::FethIO;

/// Async raw I/O handle for a feth interface.
///
/// Created from a [`FethIO`] via [`AsyncFethIO::new`].
/// The BPF fd is set to non-blocking mode and registered with
/// tokio's reactor. The NDRV fd performs synchronous writes.
pub struct AsyncFethIO {
    name: Arc<str>,
    bpf: AsyncFd<OwnedFd>,
    ndrv: OwnedFd,
    read_buf: Vec<u8>,
    read_len: usize,
    read_pos: usize,
}

/// Owned read half of an [`AsyncFethIO`], obtained via [`AsyncFethIO::into_split`].
///
/// Reads ethernet frames from the BPF device. The internal buffer may
/// contain multiple frames per kernel read; use [`recv`](BpfReader::recv)
/// to get one frame at a time.
pub struct BpfReader {
    name: Arc<str>,
    bpf: AsyncFd<OwnedFd>,
    read_buf: Vec<u8>,
    read_len: usize,
    read_pos: usize,
}

/// Owned write half of an [`AsyncFethIO`], obtained via [`AsyncFethIO::into_split`].
///
/// Sends raw ethernet frames via the `AF_NDRV` socket. Writes are
/// synchronous because they are effectively instantaneous kernel
/// buffer copies.
pub struct NdrvWriter {
    name: Arc<str>,
    ndrv: OwnedFd,
}

impl AsyncFethIO {
    /// Create an async I/O handle from a synchronous [`FethIO`].
    ///
    /// The BPF fd is set to non-blocking mode and registered with
    /// tokio's reactor.
    pub fn new(sync_io: FethIO) -> io::Result<Self> {
        sync_io.set_nonblocking(true)?;
        let (name, bpf_fd, ndrv_fd, buf_len) = sync_io.into_parts();

        let bpf = AsyncFd::with_interest(bpf_fd, Interest::READABLE)?;

        Ok(Self {
            name: Arc::from(name),
            bpf,
            ndrv: ndrv_fd,
            read_buf: vec![0u8; buf_len],
            read_len: 0,
            read_pos: 0,
        })
    }

    /// Open an async I/O handle on the given interface name.
    pub fn open(ifname: &str) -> io::Result<Self> {
        let sync_io = FethIO::open(ifname)?;
        Self::new(sync_io)
    }

    /// The interface name this handle is bound to.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The BPF file descriptor (for external use with kqueue).
    pub fn bpf_fd(&self) -> RawFd {
        self.bpf.as_raw_fd()
    }

    /// The NDRV file descriptor (for external use with kqueue).
    pub fn ndrv_fd(&self) -> RawFd {
        self.ndrv.as_raw_fd()
    }

    /// Split into an owned read half and write half.
    ///
    /// The [`BpfReader`] receives frames from the BPF device and the
    /// [`NdrvWriter`] sends frames via the `AF_NDRV` socket. Both
    /// halves can be used independently without synchronisation.
    pub fn into_split(self) -> (BpfReader, NdrvWriter) {
        let reader = BpfReader {
            name: Arc::clone(&self.name),
            bpf: self.bpf,
            read_buf: self.read_buf,
            read_len: self.read_len,
            read_pos: self.read_pos,
        };
        let writer = NdrvWriter {
            name: self.name,
            ndrv: self.ndrv,
        };
        (reader, writer)
    }
}

// ── BpfReader ──────────────────────────────────────────────────────

impl BpfReader {
    /// The interface name this reader is bound to.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The BPF file descriptor.
    pub fn bpf_fd(&self) -> RawFd {
        self.bpf.as_raw_fd()
    }

    /// Receive a single ethernet frame.
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(n) = self.next_frame(buf)? {
                return Ok(n);
            }
            self.fill_bpf_buffer().await?;
        }
    }

    async fn fill_bpf_buffer(&mut self) -> io::Result<()> {
        loop {
            let mut guard = self.bpf.readable().await?;
            if let Ok(result) = guard.try_io(|fd| {
                let n = unsafe {
                    libc::read(
                        fd.as_raw_fd(),
                        self.read_buf.as_mut_ptr().cast(),
                        self.read_buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                let n = result?;
                self.read_len = n;
                self.read_pos = 0;
                return Ok(());
            }
        }
    }

    /// Try to extract the next buffered frame without any I/O.
    pub fn try_next_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        self.next_frame(buf)
    }

    fn next_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        parse_next_frame(&self.read_buf, &mut self.read_pos, self.read_len, buf)
    }
}

// ── NdrvWriter ─────────────────────────────────────────────────────

impl NdrvWriter {
    /// The interface name this writer is bound to.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The NDRV file descriptor.
    pub fn ndrv_fd(&self) -> RawFd {
        self.ndrv.as_raw_fd()
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
}

// ── Shared helpers ─────────────────────────────────────────────────

/// Parse the next `bpf_hdr` + payload from a BPF read buffer.
fn parse_next_frame(
    read_buf: &[u8],
    read_pos: &mut usize,
    read_len: usize,
    buf: &mut [u8],
) -> io::Result<Option<usize>> {
    while *read_pos + size_of::<libc::bpf_hdr>() <= read_len {
        unsafe {
            let ptr = read_buf.as_ptr().add(*read_pos);
            let hdr = &*(ptr as *const libc::bpf_hdr);
            let hdr_len = hdr.bh_hdrlen as usize;
            let cap_len = hdr.bh_caplen as usize;

            // BPF_WORDALIGN: round up to next 4-byte boundary.
            let total = (hdr_len + cap_len + 3) & !3;
            *read_pos += total;

            // Skip zero-length records (padding) and records that
            // extend past the valid data — matches ZeroTier behaviour.
            if cap_len == 0
                || read_pos.wrapping_sub(total) + hdr_len + cap_len > read_len
            {
                continue;
            }

            let payload_start = ptr.add(hdr_len);
            if buf.len() < cap_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("buffer too small: need {cap_len} bytes, got {}", buf.len()),
                ));
            }
            std::ptr::copy_nonoverlapping(payload_start, buf.as_mut_ptr(), cap_len);
            return Ok(Some(cap_len));
        }
    }
    *read_pos = read_len;
    Ok(None)
}
