//! Portable Darwin TUN planning: name, 4-byte family header, auto-route ranges.
//! No syscalls. Safe to unit-test on Linux.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Official `fmt.Sscanf(name, "utun%d")`: `utun` + decimal digits only.
pub fn parse_utun_unit(name: &str) -> Result<u32, ()> {
    let rest = name.strip_prefix("utun").ok_or(())?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    rest.parse::<u32>().map_err(|_| ())
}

pub const FAMILY_LEN: usize = 4;
/// Darwin `AF_INET` / `AF_INET6` (not Linux's 10).
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 30;

pub fn strip_family(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() <= FAMILY_LEN {
        return None;
    }
    Some(&frame[FAMILY_LEN..])
}

pub fn prepend_family(ip: &[u8]) -> Vec<u8> {
    let fam = match ip.first().map(|b| b >> 4) {
        Some(6) => AF_INET6,
        _ => AF_INET,
    };
    let mut out = Vec::with_capacity(FAMILY_LEN + ip.len());
    out.extend_from_slice(&[0, 0, 0, fam]);
    out.extend_from_slice(ip);
    out
}

pub fn darwin_default_ipv4() -> Vec<(Ipv4Addr, u8)> {
    vec![
        (Ipv4Addr::new(1, 0, 0, 0), 8),
        (Ipv4Addr::new(2, 0, 0, 0), 7),
        (Ipv4Addr::new(4, 0, 0, 0), 6),
        (Ipv4Addr::new(8, 0, 0, 0), 5),
        (Ipv4Addr::new(16, 0, 0, 0), 4),
        (Ipv4Addr::new(32, 0, 0, 0), 3),
        (Ipv4Addr::new(64, 0, 0, 0), 2),
        (Ipv4Addr::new(128, 0, 0, 0), 1),
    ]
}

pub fn darwin_default_ipv6() -> Vec<(Ipv6Addr, u8)> {
    let mk = |b0: u8, bits: u8| {
        let mut o = [0u8; 16];
        o[0] = b0;
        (Ipv6Addr::from(o), bits)
    };
    vec![
        mk(1, 8),
        mk(2, 7),
        mk(4, 6),
        mk(8, 5),
        mk(16, 4),
        mk(32, 3),
        mk(64, 2),
        mk(128, 1),
    ]
}

fn mask32(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        !0u32 << (32 - bits)
    }
}

fn net32(addr: Ipv4Addr, bits: u8) -> u32 {
    u32::from(addr) & mask32(bits)
}

/// Subtract one IPv4 prefix from another (walk siblings).
fn subtract32(base: (u32, u8), excl: (u32, u8)) -> Vec<(u32, u8)> {
    let (bn, bb) = base;
    let (en, eb) = excl;
    let maxb = bb.min(eb);
    if (bn ^ en) & mask32(maxb) != 0 {
        return vec![base];
    }
    if eb <= bb {
        return vec![];
    }
    let mut out = Vec::new();
    let mut cur_bits = bb;
    let mut cur_net = bn;
    while cur_bits < eb {
        let next_bits = cur_bits + 1;
        let half = 1u32 << (32 - next_bits);
        let left = cur_net;
        let right = cur_net + half;
        if (en & mask32(next_bits)) == right {
            out.push((left, next_bits));
            cur_net = right;
        } else {
            out.push((right, next_bits));
            cur_net = left;
        }
        cur_bits = next_bits;
    }
    out
}

pub fn subtract_ipv4(
    bases: &[(Ipv4Addr, u8)],
    excludes: &[(Ipv4Addr, u8)],
) -> Vec<(Ipv4Addr, u8)> {
    let mut cur: Vec<(u32, u8)> = bases.iter().map(|(a, b)| (net32(*a, *b), *b)).collect();
    for (ea, eb) in excludes {
        let e = (net32(*ea, *eb), *eb);
        let mut next = Vec::new();
        for b in cur {
            next.extend(subtract32(b, e));
        }
        cur = next;
    }
    cur.into_iter()
        .map(|(n, b)| (Ipv4Addr::from(n), b))
        .collect()
}

fn mask128(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        !0u128 << (128 - bits)
    }
}

fn net128(addr: Ipv6Addr, bits: u8) -> u128 {
    u128::from(addr) & mask128(bits)
}

fn subtract128(base: (u128, u8), excl: (u128, u8)) -> Vec<(u128, u8)> {
    let (bn, bb) = base;
    let (en, eb) = excl;
    let maxb = bb.min(eb);
    if (bn ^ en) & mask128(maxb) != 0 {
        return vec![base];
    }
    if eb <= bb {
        return vec![];
    }
    let mut out = Vec::new();
    let mut cur_bits = bb;
    let mut cur_net = bn;
    while cur_bits < eb {
        let next_bits = cur_bits + 1;
        let half = 1u128 << (128 - next_bits);
        let left = cur_net;
        let right = cur_net + half;
        if (en & mask128(next_bits)) == right {
            out.push((left, next_bits));
            cur_net = right;
        } else {
            out.push((right, next_bits));
            cur_net = left;
        }
        cur_bits = next_bits;
    }
    out
}

pub fn subtract_ipv6(
    bases: &[(Ipv6Addr, u8)],
    excludes: &[(Ipv6Addr, u8)],
) -> Vec<(Ipv6Addr, u8)> {
    let mut cur: Vec<(u128, u8)> = bases.iter().map(|(a, b)| (net128(*a, *b), *b)).collect();
    for (ea, eb) in excludes {
        let e = (net128(*ea, *eb), *eb);
        let mut next = Vec::new();
        for b in cur {
            next.extend(subtract128(b, e));
        }
        cur = next;
    }
    cur.into_iter()
        .map(|(n, b)| (Ipv6Addr::from(n), b))
        .collect()
}

pub fn parse_v4_prefix(s: &str) -> Result<(Ipv4Addr, u8), String> {
    let (a, bits) = if let Some((h, t)) = s.split_once('/') {
        (h.parse::<Ipv4Addr>().map_err(|e| e.to_string())?, t.parse::<u8>().map_err(|e| e.to_string())?)
    } else {
        (s.parse::<Ipv4Addr>().map_err(|e| e.to_string())?, 32)
    };
    if bits > 32 {
        return Err("ipv4 prefix length".into());
    }
    Ok((a, bits))
}

pub fn parse_v6_prefix(s: &str) -> Result<(Ipv6Addr, u8), String> {
    let (a, bits) = if let Some((h, t)) = s.split_once('/') {
        (h.parse::<Ipv6Addr>().map_err(|e| e.to_string())?, t.parse::<u8>().map_err(|e| e.to_string())?)
    } else {
        (s.parse::<Ipv6Addr>().map_err(|e| e.to_string())?, 128)
    };
    if bits > 128 {
        return Err("ipv6 prefix length".into());
    }
    Ok((a, bits))
}

/// Official `BuildAutoRouteRanges` for Darwin (`autoRouteUseSubRanges`).
pub fn darwin_ipv4_install_list(
    user: &[String],
    exclude: &[String],
) -> Result<Vec<(Ipv4Addr, u8)>, String> {
    let bases = if user.is_empty() {
        darwin_default_ipv4()
    } else {
        user.iter().map(|s| parse_v4_prefix(s)).collect::<Result<Vec<_>, _>>()?
    };
    let ex = exclude
        .iter()
        .map(|s| parse_v4_prefix(s))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(subtract_ipv4(&bases, &ex))
}

pub fn darwin_ipv6_install_list(
    user: &[String],
    exclude: &[String],
) -> Result<Vec<(Ipv6Addr, u8)>, String> {
    let bases = if user.is_empty() {
        darwin_default_ipv6()
    } else {
        user.iter().map(|s| parse_v6_prefix(s)).collect::<Result<Vec<_>, _>>()?
    };
    let ex = exclude
        .iter()
        .map(|s| parse_v6_prefix(s))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(subtract_ipv6(&bases, &ex))
}
