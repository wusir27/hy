//! QUIC variable-length integer (RFC 9000 §16).

use crate::error::Error;
use std::io::{self, Read};

const MAX_VARINT_1: u64 = 63;
const MAX_VARINT_2: u64 = 16_383;
const MAX_VARINT_4: u64 = 1_073_741_823;
const MAX_VARINT_8: u64 = 4_611_686_018_427_387_903;

/// Encoded length of `v` as a QUIC varint.
pub fn varint_len(v: u64) -> usize {
    if v <= MAX_VARINT_1 {
        1
    } else if v <= MAX_VARINT_2 {
        2
    } else if v <= MAX_VARINT_4 {
        4
    } else if v <= MAX_VARINT_8 {
        8
    } else {
        panic!("{v:#x} doesn't fit into 62 bits");
    }
}

/// Write `v` into a fixed buffer. Returns bytes written.
pub fn varint_put(buf: &mut [u8], v: u64) -> usize {
    if v <= MAX_VARINT_1 {
        buf[0] = v as u8;
        1
    } else if v <= MAX_VARINT_2 {
        buf[0] = ((v >> 8) as u8) | 0x40;
        buf[1] = v as u8;
        2
    } else if v <= MAX_VARINT_4 {
        buf[0] = ((v >> 24) as u8) | 0x80;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = v as u8;
        4
    } else if v <= MAX_VARINT_8 {
        buf[0] = ((v >> 56) as u8) | 0xc0;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = v as u8;
        8
    } else {
        panic!("{v:#x} doesn't fit into 62 bits");
    }
}

/// Read one QUIC varint from `r`.
pub fn varint_read<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first)?;
    let tag = first[0] >> 6;
    let rest_len = match tag {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        _ => unreachable!(),
    };
    let mut rest = [0u8; 7];
    if rest_len > 0 {
        r.read_exact(&mut rest[..rest_len])?;
    }
    let mut v = u64::from(first[0] & 0x3f);
    for b in rest.iter().take(rest_len) {
        v = (v << 8) | u64::from(*b);
    }
    Ok(v)
}

/// Read a varint from a byte slice. Returns (value, bytes_consumed).
pub fn varint_decode(buf: &[u8]) -> Result<(u64, usize), Error> {
    if buf.is_empty() {
        return Err(Error::protocol("truncated varint"));
    }
    let tag = buf[0] >> 6;
    let n = match tag {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    if buf.len() < n {
        return Err(Error::protocol("truncated varint"));
    }
    let mut v = u64::from(buf[0] & 0x3f);
    for b in &buf[1..n] {
        v = (v << 8) | u64::from(*b);
    }
    Ok((v, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_lengths() {
        let cases = [
            (0, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (0x401, 2),
        ];
        for (v, want_len) in cases {
            assert_eq!(varint_len(v), want_len, "len {v}");
            let mut buf = [0u8; 8];
            let n = varint_put(&mut buf, v);
            assert_eq!(n, want_len);
            let (got, consumed) = varint_decode(&buf[..n]).unwrap();
            assert_eq!(got, v);
            assert_eq!(consumed, n);
        }
    }

    #[test]
    fn tcp_request_id_is_0x4401() {
        let mut buf = [0u8; 2];
        assert_eq!(varint_put(&mut buf, 0x401), 2);
        assert_eq!(&buf, &[0x44, 0x01]);
    }
}
