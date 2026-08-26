//! Local ICMP echo replies for TUN. Never forwarded into the hy tunnel.

use std::net::Ipv6Addr;

const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_ICMPV6: u8 = 58;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// If `pkt` is IPv4 + ICMP echo request (type 8), return a full IPv4 echo reply.
/// Other ICMP types, truncated packets, and non-IPv4 yield `None`.
pub fn echo_reply_v4(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 20 {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ihl + 8 || total_len > pkt.len() {
        return None;
    }
    if pkt[9] != IP_PROTO_ICMP {
        return None;
    }
    let icmp_off = ihl;
    if pkt[icmp_off] != ICMP_ECHO_REQUEST {
        return None;
    }

    let mut out = pkt[..total_len].to_vec();
    let src = [out[12], out[13], out[14], out[15]];
    let dst = [out[16], out[17], out[18], out[19]];
    out[12..16].copy_from_slice(&dst);
    out[16..20].copy_from_slice(&src);

    out[icmp_off] = ICMP_ECHO_REPLY;
    out[icmp_off + 2] = 0;
    out[icmp_off + 3] = 0;
    let icmp_csum = internet_checksum(&out[icmp_off..]);
    out[icmp_off + 2..icmp_off + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    out[10] = 0;
    out[11] = 0;
    let ip_csum = internet_checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    Some(out)
}

/// If `pkt` is IPv6 + ICMPv6 echo request (type 128), return type 129 with
/// swapped addresses and a valid ICMPv6 checksum (pseudo-header).
pub fn echo_reply_v6(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 40 + 8 {
        return None;
    }
    if pkt[0] >> 4 != 6 {
        return None;
    }
    if pkt[6] != IP_PROTO_ICMPV6 {
        return None;
    }
    let plen = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let total = 40 + plen;
    if plen < 8 || total > pkt.len() {
        return None;
    }
    if pkt[40] != ICMPV6_ECHO_REQUEST {
        return None;
    }

    let mut out = pkt[..total].to_vec();
    let src = out[8..24].to_vec();
    let dst = out[24..40].to_vec();
    out[8..24].copy_from_slice(&dst);
    out[24..40].copy_from_slice(&src);
    out[40] = ICMPV6_ECHO_REPLY;
    out[42] = 0;
    out[43] = 0;
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&out[8..24]).ok()?);
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&out[24..40]).ok()?);
    let csum = icmpv6_checksum(src_ip, dst_ip, &out[40..]);
    out[42..44].copy_from_slice(&csum.to_be_bytes());
    Some(out)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in chunks.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += (b as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut p = Vec::with_capacity(40 + icmp.len());
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, IP_PROTO_ICMPV6]);
    p.extend_from_slice(icmp);
    internet_checksum(&p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn craft_echo_v4(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IP_PROTO_ICMP;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20] = ICMP_ECHO_REQUEST;
        pkt[24..26].copy_from_slice(&id.to_be_bytes());
        pkt[26..28].copy_from_slice(&seq.to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        let icmp_csum = internet_checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&icmp_csum.to_be_bytes());
        let ip_csum = internet_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        pkt
    }

    fn craft_echo_v6(src: Ipv6Addr, dst: Ipv6Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let plen = 8 + payload.len();
        let mut pkt = vec![0u8; 40 + plen];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(plen as u16).to_be_bytes());
        pkt[6] = IP_PROTO_ICMPV6;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src.octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt[40] = ICMPV6_ECHO_REQUEST;
        pkt[44..46].copy_from_slice(&id.to_be_bytes());
        pkt[46..48].copy_from_slice(&seq.to_be_bytes());
        pkt[48..].copy_from_slice(payload);
        let csum = icmpv6_checksum(src, dst, &pkt[40..]);
        pkt[42..44].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    #[test]
    fn echo_reply_v4_swaps_and_preserves_payload() {
        let payload = b"ping-payload";
        let pkt = craft_echo_v4([10, 0, 0, 2], [1, 1, 1, 1], 0x1234, 0x0007, payload);
        let reply = echo_reply_v4(&pkt).expect("echo reply");
        assert_eq!(reply[0] >> 4, 4);
        assert_eq!(reply[9], IP_PROTO_ICMP);
        assert_eq!(
            Ipv4Addr::new(reply[12], reply[13], reply[14], reply[15]),
            Ipv4Addr::new(1, 1, 1, 1)
        );
        assert_eq!(
            Ipv4Addr::new(reply[16], reply[17], reply[18], reply[19]),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(reply[20], ICMP_ECHO_REPLY);
        assert_eq!(&reply[24..26], &0x1234u16.to_be_bytes());
        assert_eq!(&reply[26..28], &0x0007u16.to_be_bytes());
        assert_eq!(&reply[28..], payload);
        assert_eq!(internet_checksum(&reply[..20]), 0, "IPv4 header checksum");
        assert_eq!(internet_checksum(&reply[20..]), 0, "ICMP checksum");
    }

    #[test]
    fn echo_reply_v4_truncated_or_wrong_type_is_none() {
        let pkt = craft_echo_v4([10, 0, 0, 2], [8, 8, 8, 8], 1, 1, b"hi");
        assert!(echo_reply_v4(&pkt[..20]).is_none());
        assert!(echo_reply_v4(&pkt[..27]).is_none());
        assert!(echo_reply_v4(&[]).is_none());
        let mut dest_unreach = pkt.clone();
        dest_unreach[20] = 3;
        dest_unreach[22] = 0;
        dest_unreach[23] = 0;
        let c = internet_checksum(&dest_unreach[20..]);
        dest_unreach[22..24].copy_from_slice(&c.to_be_bytes());
        dest_unreach[10] = 0;
        dest_unreach[11] = 0;
        let c = internet_checksum(&dest_unreach[..20]);
        dest_unreach[10..12].copy_from_slice(&c.to_be_bytes());
        assert!(echo_reply_v4(&dest_unreach).is_none());
        let v6 = craft_echo_v6(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            1,
            1,
            b"x",
        );
        assert!(echo_reply_v4(&v6).is_none());
    }

    #[test]
    fn echo_reply_v6_type_129_swapped_addrs() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let payload = b"v6ping";
        let pkt = craft_echo_v6(src, dst, 0xaaa, 0x2, payload);
        let reply = echo_reply_v6(&pkt).expect("echo reply");
        assert_eq!(reply[0] >> 4, 6);
        assert_eq!(reply[6], IP_PROTO_ICMPV6);
        assert_eq!(&reply[8..24], dst.octets().as_slice());
        assert_eq!(&reply[24..40], src.octets().as_slice());
        assert_eq!(reply[40], ICMPV6_ECHO_REPLY);
        assert_eq!(&reply[44..46], &0xaaau16.to_be_bytes());
        assert_eq!(&reply[46..48], &0x2u16.to_be_bytes());
        assert_eq!(&reply[48..], payload);
        let reply_src = Ipv6Addr::from(<[u8; 16]>::try_from(&reply[8..24]).unwrap());
        let reply_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&reply[24..40]).unwrap());
        let mut icmp = reply[40..].to_vec();
        icmp[2] = 0;
        icmp[3] = 0;
        let expect = icmpv6_checksum(reply_src, reply_dst, &icmp);
        assert_eq!(&reply[42..44], &expect.to_be_bytes());
        assert!(echo_reply_v6(&pkt[..40]).is_none());
        let mut other = pkt.clone();
        other[40] = 1; // Destination Unreachable
        assert!(echo_reply_v6(&other).is_none());
        assert!(echo_reply_v6(&craft_echo_v4([1, 2, 3, 4], [5, 6, 7, 8], 1, 1, b"x")).is_none());
    }
}
