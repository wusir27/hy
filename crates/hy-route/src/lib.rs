//! Client-side routing (rules, DNS, direct dial).
//!
//! This step: local `.conf` compile + [`Router::decide`]. No RULE-SET
//! download, no DirectDialer / DNS / ICMP.

mod action;
mod dest;
mod error;
mod router;
mod suffix;

pub use action::Action;
pub use dest::{Dest, Proto};
pub use error::Error;
pub use router::{compile, compile_file, Router};
