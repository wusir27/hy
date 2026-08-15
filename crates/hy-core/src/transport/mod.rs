//! quinn + h3 wiring.
//!
//! Auth goes through h3; afterwards TCP is `open_bi`/`accept_bi` with
//! frame 0x401, UDP is quinn datagrams. Chrome parrot: client default CID
//! length 0 (`quic.disableChromeParrot` restores the hashed 8-byte CID).

pub mod h3_auth;
pub mod quic;
