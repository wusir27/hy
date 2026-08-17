//! quinn + h3 wiring.
//!
//! Auth goes through h3 and stays on h3 for the QUIC lifetime (ServeQUICConn).
//! TCP is hijacked from incoming bidi streams when the first varint is 0x401.
//! UDP is quinn datagrams. Chrome parrot: client default CID length 0
//! (`quic.disableChromeParrot` restores the hashed 8-byte CID).

pub mod h3_auth;
pub(crate) mod h3_dispatch;
pub mod quic;
