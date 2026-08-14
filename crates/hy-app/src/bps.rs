use hy_core::Error;

/// Official-style bandwidth. `mbps`/`kbps`/`gbps`/`bps` are bits/s.
/// Bare number / `k`/`m`/`g` are B/s (converted to bits/s).
pub fn parse_bps(s: &str) -> Result<u64, Error> {
    let t = s.trim().to_ascii_lowercase().replace(' ', "");
    if t.is_empty() || t == "0" {
        return Ok(0);
    }
    let (num, unit) = split_num_unit(&t).ok_or_else(|| Error::config("Bandwidth", format!("bad value {s}")))?;
    let n: f64 = num.parse().map_err(|_| Error::config("Bandwidth", format!("bad value {s}")))?;
    if n < 0.0 {
        return Err(Error::config("Bandwidth", "must be >= 0"));
    }
    let bits = match unit {
        "" => n * 8.0,
        "k" | "kb" => n * 1000.0 * 8.0,
        "m" | "mb" => n * 1_000_000.0 * 8.0,
        "g" | "gb" => n * 1_000_000_000.0 * 8.0,
        "bps" => n,
        "kbps" => n * 1_000.0,
        "mbps" => n * 1_000_000.0,
        "gbps" => n * 1_000_000_000.0,
        _ => return Err(Error::config("Bandwidth", format!("unknown unit {unit}"))),
    };
    Ok(bits as u64)
}

fn split_num_unit(s: &str) -> Option<(&str, &str)> {
    match s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        None => Some((s, "")),
        Some(0) => None,
        Some(i) => Some((&s[..i], &s[i..])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(parse_bps("100mbps").unwrap(), 100_000_000);
        assert_eq!(parse_bps("200 mbps").unwrap(), 200_000_000);
        assert_eq!(parse_bps("1g").unwrap(), 8_000_000_000);
        assert_eq!(parse_bps("1000").unwrap(), 8000);
        assert_eq!(parse_bps("").unwrap(), 0);
    }

    #[test]
    fn bad_unit() {
        assert!(parse_bps("10xx").is_err());
    }
}
