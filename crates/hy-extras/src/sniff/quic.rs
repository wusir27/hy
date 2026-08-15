//! QUIC Initial CRYPTO payload extraction (ported from hysteria extras/sniff/internal/quic).

use ring::aead::{self, LessSafeKey, UnboundKey, AES_128_GCM};
use ring::aead::quic::{self, HeaderProtectionKey};
use ring::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};

const V1: u32 = 0x1;
const V2: u32 = 0x6b3343cf;

const HKDF_LABEL_KEY_V1: &str = "quic key";
const HKDF_LABEL_KEY_V2: &str = "quicv2 key";
const HKDF_LABEL_IV_V1: &str = "quic iv";
const HKDF_LABEL_IV_V2: &str = "quicv2 iv";
const HKDF_LABEL_HP_V1: &str = "quic hp";
const HKDF_LABEL_HP_V2: &str = "quicv2 hp";

const QUIC_SALT_V1: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_SALT_V2: &[u8] = &[
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
    0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

const MAX_CRYPTO_FRAME_DATA_LEN: usize = 256 * 1024;
const MAX_CRYPTO_PAYLOAD_LEN: usize = 256 * 1024;

struct Header {
    version: u32,
    dest_connection_id: Vec<u8>,
    length: i64,
}

struct OkmLen(usize);

impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Decrypt QUIC Initial packet and assemble CRYPTO frames (TLS handshake bytes).
pub fn read_crypto_payload(packet: &[u8]) -> Option<Vec<u8>> {
    let (hdr, offset) = parse_initial_header(packet)?;
    if hdr.version != V1 && hdr.version != V2 {
        return None;
    }
    if offset == 0 || hdr.length == 0 {
        return None;
    }
    let end = offset.checked_add(hdr.length as usize)?;
    if packet.len() < end {
        return None;
    }

    let salt = if hdr.version == V2 {
        QUIC_SALT_V2
    } else {
        QUIC_SALT_V1
    };
    let initial_secret = Salt::new(HKDF_SHA256, salt).extract(&hdr.dest_connection_id);
    let client_secret = hkdf_expand_label(&initial_secret, "client in", &[], 32);

    let key_label = if hdr.version == V2 {
        HKDF_LABEL_KEY_V2
    } else {
        HKDF_LABEL_KEY_V1
    };
    let iv_label = if hdr.version == V2 {
        HKDF_LABEL_IV_V2
    } else {
        HKDF_LABEL_IV_V1
    };
    let hp_label = if hdr.version == V2 {
        HKDF_LABEL_HP_V2
    } else {
        HKDF_LABEL_HP_V1
    };

    // Expand from client_secret bytes via new PRK.
    let client_prk = Prk::new_less_safe(HKDF_SHA256, &client_secret);
    let aead_key = hkdf_expand_label(&client_prk, key_label, &[], 16);
    let iv = hkdf_expand_label(&client_prk, iv_label, &[], 12);
    let hp_key = hkdf_expand_label(&client_prk, hp_label, &[], 16);

    let mut pkt = packet[..end].to_vec();
    let payload = unprotect(&mut pkt, offset, 2, &aead_key, &iv, &hp_key)?;
    let frames = extract_crypto_frames(&payload)?;
    assemble_crypto_frames(&frames)
}

fn parse_initial_header(data: &[u8]) -> Option<(Header, usize)> {
    if data.is_empty() {
        return None;
    }
    let mut i = 0usize;
    let type_byte = *data.get(i)?;
    i += 1;
    if data.len() < i + 4 {
        return None;
    }
    let version = u32::from_be_bytes(data[i..i + 4].try_into().ok()?);
    i += 4;
    if version != 0 && type_byte & 0x40 == 0 {
        return None;
    }
    let dcid_len = *data.get(i)? as usize;
    i += 1;
    if data.len() < i + dcid_len {
        return None;
    }
    let dest_connection_id = data[i..i + dcid_len].to_vec();
    i += dcid_len;
    let scid_len = *data.get(i)? as usize;
    i += 1;
    if data.len() < i + scid_len {
        return None;
    }
    i += scid_len;

    let initial_packet_type: u8 = if version == V2 { 0b01 } else { 0b00 };
    if ((type_byte >> 4) & 0b11) == initial_packet_type {
        let (token_len, n) = read_varint(&data[i..])?;
        i += n;
        if data.len() < i + token_len as usize {
            return None;
        }
        i += token_len as usize;
    }

    let (pl, n) = read_varint(&data[i..])?;
    i += n;
    Some((
        Header {
            version,
            dest_connection_id,
            length: pl as i64,
        },
        i,
    ))
}

fn unprotect(
    packet: &mut [u8],
    pn_offset: usize,
    pn_max: i64,
    aead_key: &[u8],
    iv: &[u8],
    hp_key: &[u8],
) -> Option<Vec<u8>> {
    if packet.is_empty() || !is_long_header(packet[0]) {
        return None;
    }
    if packet.len() < pn_offset + 4 + 16 {
        return None;
    }
    let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 4 + 16].try_into().ok()?;
    let hpk = HeaderProtectionKey::new(&quic::AES_128, hp_key).ok()?;
    let mask = hpk.new_mask(&sample).ok()?;

    packet[0] ^= mask[0] & 0x0f;
    let pn_len = (packet[0] & 0x3) as usize + 1;
    let mut pn: i64 = 0;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | packet[pn_offset + i] as i64;
    }
    pn = decode_packet_number(pn_max, pn, pn_len as u8);

    let hdr_end = pn_offset + pn_len;
    let mut ciphertext = packet[hdr_end..].to_vec();
    let nonce = aead_nonce(iv, pn);
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, aead_key).ok()?);
    let opened = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&packet[..hdr_end]),
            &mut ciphertext,
        )
        .ok()?;
    Some(opened.to_vec())
}

fn aead_nonce(iv: &[u8], pn: i64) -> [u8; 12] {
    let mut out = [0u8; 12];
    let n = std::cmp::min(iv.len(), 12);
    out[..n].copy_from_slice(&iv[..n]);
    let mut pn_pad = [0u8; 12];
    pn_pad[4..].copy_from_slice(&(pn as u64).to_be_bytes());
    for i in 0..12 {
        out[i] ^= pn_pad[i];
    }
    out
}

fn decode_packet_number(largest: i64, truncated: i64, nbits: u8) -> i64 {
    let expected = largest + 1;
    let win = 1i64 << (nbits * 8);
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate <= expected - hwin && candidate < (1 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

fn hkdf_expand_label(prk: &Prk, label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    let full_label = format!("tls13 {label}");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let info = [&hkdf_label[..]];
    let okm = prk.expand(&info, OkmLen(length)).expect("hkdf expand");
    let mut out = vec![0u8; length];
    okm.fill(&mut out).expect("hkdf fill");
    out
}

fn is_long_header(b: u8) -> bool {
    b & 0x80 != 0
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let n = 1usize << (first >> 6);
    if data.len() < n {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for b in &data[1..n] {
        val = (val << 8) | *b as u64;
    }
    Some((val, n))
}

struct CryptoFrame {
    offset: i64,
    data: Vec<u8>,
}

fn extract_crypto_frames(payload: &[u8]) -> Option<Vec<CryptoFrame>> {
    let mut frames = Vec::new();
    let mut i = 0usize;
    while i < payload.len() {
        let (typ, n) = read_varint(&payload[i..])?;
        i += n;
        if typ == 0x00 || typ == 0x01 {
            continue;
        }
        if typ != 0x06 {
            return None;
        }
        let (offset, n) = read_varint(&payload[i..])?;
        i += n;
        if offset > i64::MAX as u64 {
            return None;
        }
        let (data_len, n) = read_varint(&payload[i..])?;
        i += n;
        if data_len > MAX_CRYPTO_FRAME_DATA_LEN as u64 {
            return None;
        }
        let data_len = data_len as usize;
        if payload.len() < i + data_len {
            return None;
        }
        frames.push(CryptoFrame {
            offset: offset as i64,
            data: payload[i..i + data_len].to_vec(),
        });
        i += data_len;
    }
    Some(frames)
}

fn assemble_crypto_frames(frames: &[CryptoFrame]) -> Option<Vec<u8>> {
    if frames.is_empty() {
        return None;
    }
    if frames.len() == 1 {
        return Some(frames[0].data.clone());
    }
    let mut sorted: Vec<&CryptoFrame> = frames.iter().collect();
    sorted.sort_by_key(|f| f.offset);
    for i in 1..sorted.len() {
        if sorted[i].offset != sorted[i - 1].offset + sorted[i - 1].data.len() as i64 {
            return None;
        }
    }
    let last = *sorted.last()?;
    if last.offset < 0 || last.offset > MAX_CRYPTO_PAYLOAD_LEN as i64 {
        return None;
    }
    let end = last.offset + last.data.len() as i64;
    if end < 0 || end > MAX_CRYPTO_PAYLOAD_LEN as i64 {
        return None;
    }
    let mut data = vec![0u8; end as usize];
    for f in sorted {
        let start = f.offset as usize;
        data[start..start + f.data.len()].copy_from_slice(&f.data);
    }
    Some(data)
}
