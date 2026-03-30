pub mod feth;
pub mod feth_io;
mod xnu;

pub use xnu::set_fake_max_mtu;

#[cfg(feature = "tokio")]
pub mod feth_tokio;
