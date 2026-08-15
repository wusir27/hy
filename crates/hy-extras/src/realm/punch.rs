//! Punch packet encode/decode (1:1 official `punch.go`).

use rand::RngCore;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

pub const MAX_PUNCH_PADDING: usize = 1024;
pub const PUNCH_NONCE_SIZE: usize = 16;
pub const PUNCH_OBFS_KEY_SIZE: usize = 32;

const PUNCH_SALT_LEN: usize = 8;
const PUNCH_HEADER_LEN: usize = 25; // magic(8) + type(1) + nonce(16)
pub const PUNCH_MIN_WIRE_LEN: usize = PUNCH_SALT_LEN + PUNCH_HEADER_LEN;
pub const PUNCH_MAX_WIRE_LEN: usize = PUNCH_MIN_WIRE_LEN + MAX_PUNCH_PADDING;

const PUNCH_MAGIC: [u8; 8] = *b"HYRLMv1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrInvalidPunchPacket;

impl std::fmt::Display for ErrInvalidPunchPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid punch packet")
    }
}
impl std::error::Error for ErrInvalidPunchPacket {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PunchPacketType {
    Hello = 0x01,
    Ack = 0x02,
}

impl PunchPacketType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Ack),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchPacket {
    pub ty: PunchPacketType,
    pub padding_length: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PunchMetadata {
    pub nonce: String,
    pub obfs: String,
}

pub fn new_punch_metadata() -> PunchMetadata {
    PunchMetadata {
        nonce: rand_hex(PUNCH_NONCE_SIZE),
        obfs: rand_hex(PUNCH_OBFS_KEY_SIZE),
    }
}

pub fn encode_punch_packet(
    packet_type: PunchPacketType,
    meta: &PunchMetadata,
) -> Result<Vec<u8>, ErrInvalidPunchPacket> {
    let (nonce, obfs_key) = decode_punch_metadata(meta)?;
    let padding_length = {
        let mut rng = rand::thread_rng();
        (rng.next_u32() as usize) % (MAX_PUNCH_PADDING + 1)
    };
    let mut plain = vec![0u8; PUNCH_HEADER_LEN + padding_length];
    plain[..8].copy_from_slice(&PUNCH_MAGIC);
    plain[8] = packet_type as u8;
    plain[9..PUNCH_HEADER_LEN].copy_from_slice(&nonce);
    if padding_length > 0 {
        rand::thread_rng().fill_bytes(&mut plain[PUNCH_HEADER_LEN..]);
    }
    let mut packet = vec![0u8; PUNCH_SALT_LEN + plain.len()];
    rand::thread_rng().fill_bytes(&mut packet[..PUNCH_SALT_LEN]);
    let salt = packet[..PUNCH_SALT_LEN].to_vec();
    packet[PUNCH_SALT_LEN..].copy_from_slice(&plain);
    xor_punch_packet(&mut packet[PUNCH_SALT_LEN..], &obfs_key, &salt);
    Ok(packet)
}

pub fn decode_punch_packet(
    packet: &[u8],
    meta: &PunchMetadata,
) -> Result<PunchPacket, ErrInvalidPunchPacket> {
    if packet.len() < PUNCH_MIN_WIRE_LEN || packet.len() > PUNCH_MAX_WIRE_LEN {
        return Err(ErrInvalidPunchPacket);
    }
    let (nonce, obfs_key) = decode_punch_metadata(meta)?;
    let salt = &packet[..PUNCH_SALT_LEN];
    let mut plain = packet[PUNCH_SALT_LEN..].to_vec();
    xor_punch_packet(&mut plain, &obfs_key, salt);
    if plain[..8] != PUNCH_MAGIC {
        return Err(ErrInvalidPunchPacket);
    }
    let packet_type = PunchPacketType::from_u8(plain[8]).ok_or(ErrInvalidPunchPacket)?;
    if plain[9..PUNCH_HEADER_LEN] != nonce[..] {
        return Err(ErrInvalidPunchPacket);
    }
    Ok(PunchPacket {
        ty: packet_type,
        padding_length: plain.len() - PUNCH_HEADER_LEN,
    })
}

pub(crate) fn decode_punch_metadata(
    meta: &PunchMetadata,
) -> Result<(Vec<u8>, Vec<u8>), ErrInvalidPunchPacket> {
    let nonce = decode_hex_size("nonce", &meta.nonce, PUNCH_NONCE_SIZE)?;
    let obfs_key = decode_hex_size("obfs", &meta.obfs, PUNCH_OBFS_KEY_SIZE)?;
    Ok((nonce, obfs_key))
}

fn decode_hex_size(name: &str, value: &str, size: usize) -> Result<Vec<u8>, ErrInvalidPunchPacket> {
    let _ = name;
    let b = decode_hex(value).ok_or(ErrInvalidPunchPacket)?;
    if b.len() != size {
        return Err(ErrInvalidPunchPacket);
    }
    Ok(b)
}

fn xor_punch_packet(packet: &mut [u8], obfs_key: &[u8], salt: &[u8]) {
    let mut combined = Vec::with_capacity(obfs_key.len() + salt.len());
    combined.extend_from_slice(obfs_key);
    combined.extend_from_slice(salt);
    let mask = digest(&SHA256, &combined);
    let mask = mask.as_ref();
    for (i, b) in packet.iter_mut().enumerate() {
        *b ^= mask[i % mask.len()];
    }
}

fn rand_hex(size: usize) -> String {
    let mut b = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut b);
    encode_hex(&b)
}

pub(crate) fn encode_hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let h = from_hex(bytes[i])?;
        let l = from_hex(bytes[i + 1])?;
        out.push((h << 4) | l);
        i += 2;
    }
    Some(out)
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_meta() -> PunchMetadata {
        PunchMetadata {
            nonce: "00112233445566778899aabbccddeeff".into(),
            obfs: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
        }
    }

    #[test]
    fn encode_decode_hello_ack() {
        let meta = test_meta();
        for ty in [PunchPacketType::Hello, PunchPacketType::Ack] {
            let wire = encode_punch_packet(ty, &meta).unwrap();
            assert!(wire.len() >= PUNCH_MIN_WIRE_LEN && wire.len() <= PUNCH_MAX_WIRE_LEN);
            assert!(!wire.windows(8).any(|w| w == PUNCH_MAGIC));
            let decoded = decode_punch_packet(&wire, &meta).unwrap();
            assert_eq!(decoded.ty, ty);
            assert_eq!(decoded.padding_length, wire.len() - PUNCH_MIN_WIRE_LEN);
        }
    }

    #[test]
    fn salt_varies_wire() {
        let meta = test_meta();
        let a = encode_punch_packet(PunchPacketType::Hello, &meta).unwrap();
        let b = encode_punch_packet(PunchPacketType::Hello, &meta).unwrap();
        assert_ne!(&a[..PUNCH_SALT_LEN], &b[..PUNCH_SALT_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_bad_magic_nonce_type_length() {
        let meta = test_meta();
        let mut wire = encode_punch_packet(PunchPacketType::Ack, &meta).unwrap();
        wire[0] ^= 0xff;
        assert!(decode_punch_packet(&wire, &meta).is_err());

        let wire = encode_punch_packet(PunchPacketType::Hello, &meta).unwrap();
        let bad_nonce = PunchMetadata {
            nonce: "ffffffffffffffffffffffffffffffff".into(),
            obfs: meta.obfs.clone(),
        };
        assert!(decode_punch_packet(&wire, &bad_nonce).is_err());

        assert!(decode_punch_packet(&vec![0u8; PUNCH_MIN_WIRE_LEN - 1], &meta).is_err());
        assert!(decode_punch_packet(&vec![0u8; PUNCH_MAX_WIRE_LEN + 1], &meta).is_err());

        // unknown type
        let (nonce, obfs_key) = decode_punch_metadata(&meta).unwrap();
        let mut packet = vec![0u8; PUNCH_MIN_WIRE_LEN];
        packet[..PUNCH_SALT_LEN].copy_from_slice(b"12345678");
        let plain = &mut packet[PUNCH_SALT_LEN..];
        plain[..8].copy_from_slice(&PUNCH_MAGIC);
        plain[8] = 0xff;
        plain[9..PUNCH_HEADER_LEN].copy_from_slice(&nonce);
        let salt = packet[..PUNCH_SALT_LEN].to_vec();
        xor_punch_packet(&mut packet[PUNCH_SALT_LEN..], &obfs_key, &salt);
        assert!(decode_punch_packet(&packet, &meta).is_err());
    }
}
