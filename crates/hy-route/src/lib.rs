//! Client-side routing (rules, DNS, direct dial).
//!
//! This step: compile + [`Router::decide`] + [`DirectDialer`] + [`dns`].
//! No RULE-SET download, SNI peek, or ICMP.

mod action;
mod dest;
mod direct;
pub mod dns;
mod error;
mod router;
mod suffix;

pub use action::Action;
pub use dest::{Dest, Proto};
pub use direct::{
    is_utun_name, parse_darwin_route_get, pick_non_utun_default, DirectDialer, IfaceCandidate,
    DEFAULT_FWMARK,
};
pub use error::Error;
pub use router::{compile, compile_file, Router};

#[cfg(target_os = "linux")]
pub use direct::{can_set_so_mark, so_mark_tcp, so_mark_udp};
