//! quinn + h3 wiring.
//!
//! Auth goes through h3; afterwards TCP is `open_bi`/`accept_bi` with
//! frame 0x401, UDP is quinn datagrams. Chrome parrot is a no-op in v1.

pub mod h3_auth;
pub mod quic;
