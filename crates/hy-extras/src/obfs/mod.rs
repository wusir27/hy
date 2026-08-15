//! Packet-level obfuscation: Salamander + Gecko.

mod salamander;
mod gecko_frame;
mod gecko;

pub use salamander::{deobfs, obfs, ObfsSalamander, SALT_LEN};
pub use gecko_frame::{decode_frame, encode_frame, FrameHeader, GECKO_HEADER_SIZE};
pub use gecko::{GeckoFactory, ObfsGecko};
