//! Gecko fragment frame codec (after Salamander decrypt).
//!
//! Wire layout:
//! ```text
//! [1] 0x80
//! [1] msgID
//! [1] chunkIdx:4 | totalChunks:4     # totalChunks ∈ [2,8]
//! [2] padLen BE
//! [padLen] random
//! [rest] chunk
//! ```

use rand::RngCore;

pub const GECKO_FLAG_FRAGMENT: u8 = 0x80;
pub const GECKO_HEADER_SIZE: usize = 5;
pub const GECKO_MIN_FRAGMENT_CHUNKS: u8 = 2;
pub const GECKO_MAX_FRAGMENT_CHUNKS: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub pad_len: u16,
    pub msg_id: u8,
    pub chunk_idx: u8,
    pub total_chunks: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    Invalid,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Truncated => write!(f, "gecko frame truncated"),
            FrameError::Invalid => write!(f, "gecko frame invalid"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode a frame into `out`. Padding bytes are filled with random data.
/// `out` must be at least `GECKO_HEADER_SIZE + pad_len + payload.len()`.
pub fn encode_frame(h: FrameHeader, payload: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
    if h.total_chunks < GECKO_MIN_FRAGMENT_CHUNKS || h.total_chunks > GECKO_MAX_FRAGMENT_CHUNKS {
        return Err(FrameError::Invalid);
    }
    if h.chunk_idx >= h.total_chunks {
        return Err(FrameError::Invalid);
    }
    let needed = GECKO_HEADER_SIZE + h.pad_len as usize + payload.len();
    if out.len() < needed {
        return Err(FrameError::Truncated);
    }
    out[0] = GECKO_FLAG_FRAGMENT;
    out[1] = h.msg_id;
    out[2] = (h.chunk_idx << 4) | (h.total_chunks & 0x0f);
    out[3] = (h.pad_len >> 8) as u8;
    out[4] = (h.pad_len & 0xff) as u8;
    let pad_end = GECKO_HEADER_SIZE + h.pad_len as usize;
    rand::thread_rng().fill_bytes(&mut out[GECKO_HEADER_SIZE..pad_end]);
    out[pad_end..needed].copy_from_slice(payload);
    Ok(needed)
}

/// Decode a frame. Returned payload is a sub-slice of `input` (zero-copy).
pub fn decode_frame(input: &[u8]) -> Result<(FrameHeader, &[u8]), FrameError> {
    if input.len() < GECKO_HEADER_SIZE {
        return Err(FrameError::Truncated);
    }
    if input[0] & GECKO_FLAG_FRAGMENT == 0 {
        return Err(FrameError::Invalid);
    }
    let h = FrameHeader {
        msg_id: input[1],
        chunk_idx: input[2] >> 4,
        total_chunks: input[2] & 0x0f,
        pad_len: u16::from_be_bytes([input[3], input[4]]),
    };
    if h.total_chunks < GECKO_MIN_FRAGMENT_CHUNKS || h.total_chunks > GECKO_MAX_FRAGMENT_CHUNKS {
        return Err(FrameError::Invalid);
    }
    if h.chunk_idx >= h.total_chunks {
        return Err(FrameError::Invalid);
    }
    let body_start = GECKO_HEADER_SIZE + h.pad_len as usize;
    if body_start > input.len() {
        return Err(FrameError::Truncated);
    }
    Ok((h, &input[body_start..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let h = FrameHeader {
            pad_len: 7,
            msg_id: 42,
            chunk_idx: 1,
            total_chunks: 3,
        };
        let payload = b"hello-gecko-chunk";
        let mut buf = vec![0u8; GECKO_HEADER_SIZE + h.pad_len as usize + payload.len()];
        let n = encode_frame(h, payload, &mut buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(buf[0], GECKO_FLAG_FRAGMENT);
        assert_eq!(buf[1], 42);
        assert_eq!(buf[2], (1 << 4) | 3);

        let (dh, dp) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(dh.msg_id, 42);
        assert_eq!(dh.chunk_idx, 1);
        assert_eq!(dh.total_chunks, 3);
        assert_eq!(dh.pad_len, 7);
        assert_eq!(dp, payload);
    }

    #[test]
    fn invalid_total_chunks() {
        let h = FrameHeader {
            pad_len: 0,
            msg_id: 1,
            chunk_idx: 0,
            total_chunks: 1, // < 2
        };
        let mut buf = [0u8; 16];
        assert_eq!(encode_frame(h, b"x", &mut buf), Err(FrameError::Invalid));

        let h9 = FrameHeader {
            pad_len: 0,
            msg_id: 1,
            chunk_idx: 0,
            total_chunks: 9, // > 8
        };
        assert_eq!(encode_frame(h9, b"x", &mut buf), Err(FrameError::Invalid));

        // Decode path: forge wire with totalChunks=1
        let mut wire = [0u8; 6];
        wire[0] = GECKO_FLAG_FRAGMENT;
        wire[1] = 0;
        wire[2] = (0 << 4) | 1;
        assert_eq!(decode_frame(&wire), Err(FrameError::Invalid));
    }

    #[test]
    fn truncated_frame() {
        assert_eq!(decode_frame(&[0x80, 1, 0x23]), Err(FrameError::Truncated));

        let mut wire = [0u8; 5];
        wire[0] = GECKO_FLAG_FRAGMENT;
        wire[1] = 0;
        wire[2] = (0 << 4) | 2;
        wire[3] = 0;
        wire[4] = 10; // padLen=10 but no body
        assert_eq!(decode_frame(&wire), Err(FrameError::Truncated));

        let h = FrameHeader {
            pad_len: 0,
            msg_id: 0,
            chunk_idx: 0,
            total_chunks: 2,
        };
        let mut tiny = [0u8; 4];
        assert_eq!(encode_frame(h, b"ab", &mut tiny), Err(FrameError::Truncated));
    }

    #[test]
    fn chunk_idx_out_of_range() {
        let h = FrameHeader {
            pad_len: 0,
            msg_id: 0,
            chunk_idx: 2,
            total_chunks: 2,
        };
        let mut buf = [0u8; 8];
        assert_eq!(encode_frame(h, b"x", &mut buf), Err(FrameError::Invalid));
    }
}
