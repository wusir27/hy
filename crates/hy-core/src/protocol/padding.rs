use rand::Rng;

/// Alphabet used by auth / TCP padding. Must stay 1:1 with Go.
pub const PADDING_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Half-open range `[min, max)`.
#[derive(Clone, Copy, Debug)]
pub struct PaddingRange {
    pub min: usize,
    pub max: usize,
}

pub const AUTH_REQUEST_PADDING: PaddingRange = PaddingRange { min: 256, max: 2048 };
pub const AUTH_RESPONSE_PADDING: PaddingRange = PaddingRange { min: 256, max: 2048 };
pub const TCP_REQUEST_PADDING: PaddingRange = PaddingRange { min: 64, max: 512 };
pub const TCP_RESPONSE_PADDING: PaddingRange = PaddingRange { min: 128, max: 1024 };

impl PaddingRange {
    pub fn generate(self) -> String {
        let mut rng = rand::thread_rng();
        let n = self.min + rng.gen_range(0..self.max.saturating_sub(self.min));
        let mut out = String::with_capacity(n);
        for _ in 0..n {
            let i = rng.gen_range(0..PADDING_CHARS.len());
            out.push(PADDING_CHARS[i] as char);
        }
        out
    }
}

pub fn is_padding_charset(s: &str) -> bool {
    s.bytes().all(|b| PADDING_CHARS.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_and_charset() {
        for range in [
            AUTH_REQUEST_PADDING,
            AUTH_RESPONSE_PADDING,
            TCP_REQUEST_PADDING,
            TCP_RESPONSE_PADDING,
        ] {
            for _ in 0..32 {
                let s = range.generate();
                assert!(s.len() >= range.min && s.len() < range.max, "len {}", s.len());
                assert!(is_padding_charset(&s));
            }
        }
    }
}
