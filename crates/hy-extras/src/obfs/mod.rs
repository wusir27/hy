//! Packet-level obfuscation. Gecko is P5.

mod salamander;

pub use salamander::{deobfs, obfs, ObfsSalamander, SALT_LEN};
