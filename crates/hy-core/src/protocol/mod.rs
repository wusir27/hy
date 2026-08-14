//! Wire format: HTTP/3 auth headers, TCP 0x401 frames, UDP datagrams.

mod http;
mod padding;
mod tcp;
mod udp;
mod varint;

pub use http::*;
pub use padding::*;
pub use tcp::*;
pub use udp::*;
pub use varint::*;

/// TCP request frame type (QUIC varint 0x401).
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

pub const MAX_ADDRESS_LENGTH: u64 = 2048;
pub const MAX_MESSAGE_LENGTH: u64 = 2048;
pub const MAX_PADDING_LENGTH: u64 = 4096;

pub const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;
pub const MAX_UDP_SIZE: usize = 4096;

/// HTTP/3 close codes used by Hysteria.
pub const CLOSE_OK: u64 = 0x100;
pub const CLOSE_PROTOCOL_ERROR: u64 = 0x101;
pub const CLOSE_EXCESSIVE_LOAD: u64 = 0x107;
