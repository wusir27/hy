//! Hysteria 2 protocol engine (`hy-core`).
//!
//! Protocol codec is sync and has no QUIC/YAML dependency.
//! Auth is h3; after 233, TCP/UDP use native quinn streams/datagrams.

pub mod client;
pub mod congestion;
pub mod error;
pub mod frag;
pub mod io;
pub(crate) mod p9x;
pub mod protocol;
pub mod server;

#[cfg(feature = "transport")]
pub mod transport;

pub use error::Error;

#[cfg(all(test, feature = "transport"))]
mod p1_tests;

#[cfg(all(test, feature = "transport"))]
mod p2_tests;

#[cfg(all(test, feature = "transport"))]
mod p5_tests;
