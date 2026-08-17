//! quinn + h3 wiring.
//!
//! Auth is a one-shot h3 accept (`h3_quinn::Connection`). After 233, TCP uses
//! native `accept_bi` (0x401) and UDP uses quinn datagrams. Chrome parrot:
//! client default CID length 0 (`quic.disableChromeParrot` restores the hashed
//! 8-byte CID).

pub mod h3_auth;
pub mod quic;
