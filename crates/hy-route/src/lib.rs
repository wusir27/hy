//! Client-side routing (rules, DNS, direct dial).
//!
//! This step is a skeleton: destination types only. No compile/router/direct/dns/icmp.

mod dest;

pub use dest::{Dest, Proto};
