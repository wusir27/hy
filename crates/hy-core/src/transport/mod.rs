//! quinn + h3 wiring.
//!
//! Auth is a one-shot h3 accept. Incoming unis are filtered (`h3_uni`) so a
//! second 0x00 / 0x02 / 0x03 never reaches rust `h3`. Auth-phase bidis are peeked:
//! `0x401` is queued (not given to h3); HTTP bytes are restored. After 233,
//! TCP uses native `accept_bi` (and the queued 0x401 drain). UDP uses quinn
//! datagrams. Chrome parrot: client default CID length 0
//! (`quic.disableChromeParrot` restores the hashed 8-byte CID).

pub mod h3_auth;
pub mod h3_uni;
pub mod quic;
