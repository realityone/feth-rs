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
};

use tokio::io::{unix::AsyncFd, Interest};

use crate::feth_io::FethIO;

/// Async raw I/O handle for a feth interface.
///
/// Created from a [`FethIO`] via [`AsyncFethIO::new`].
/// The BPF fd is set to non-blocking mode and registered with
/// tokio's reactor. The NDRV fd performs synchronous writes.
pub struct AsyncFethIO {
    name: String,
    bpf: AsyncFd<OwnedFd>,
    ndrv: OwnedFd,
    read_buf: Vec<u8>,
    read_len: usize,
    read_pos: usize,
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
            name,
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
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(n) = self.next_frame(buf)? {
                return Ok(n);
            }
            self.fill_bpf_buffer().await?;
        }
    }

    /// Read from the BPF fd into the internal buffer (async).
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
    ///
    /// Returns `Ok(Some(n))` if a frame was available in the BPF buffer,
    /// `Ok(None)` if the buffer is exhausted. Use this to drain all
    /// buffered frames after an initial `recv()`.
    pub fn try_next_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        self.next_frame(buf)
    }

    /// Parse the next `bpf_hdr` + payload from the internal buffer.
    /// Returns `None` when the buffer is exhausted.
    fn next_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        while self.read_pos + size_of::<libc::bpf_hdr>() <= self.read_len {
            unsafe {
                let ptr = self.read_buf.as_ptr().add(self.read_pos);
                let hdr = &*(ptr as *const libc::bpf_hdr);
                let hdr_len = hdr.bh_hdrlen as usize;
                let cap_len = hdr.bh_caplen as usize;

                // BPF_WORDALIGN: round up to next 4-byte boundary.
                let total = (hdr_len + cap_len + 3) & !3;
                self.read_pos += total;

                // Skip zero-length records (padding) and records that
                // extend past the valid data — matches ZeroTier behaviour.
                if cap_len == 0
                    || self.read_pos.wrapping_sub(total) + hdr_len + cap_len > self.read_len
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
        self.read_pos = self.read_len;
        Ok(None)
    }
}
