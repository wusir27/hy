//! UDP datagram fragmentation. Matches `core/internal/frag`.
//!
//! Defragger holds **one** `packet_id` at a time; a new id discards the old
//! reassembly. `frag_id >= frag_count` is dropped.

use crate::protocol::UdpMessage;

pub fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> {
    if m.size() <= max_size {
        return vec![m.clone()];
    }
    let full = &m.data;
    let max_payload = max_size.saturating_sub(m.header_size());
    if max_payload == 0 {
        return Vec::new();
    }
    let frag_count = ((full.len() + max_payload - 1) / max_payload) as u8;
    let mut frags = Vec::with_capacity(frag_count as usize);
    let mut off = 0;
    let mut frag_id = 0u8;
    while off < full.len() {
        let mut payload = full.len() - off;
        if payload > max_payload {
            payload = max_payload;
        }
        let mut frag = m.clone();
        frag.frag_id = frag_id;
        frag.frag_count = frag_count;
        frag.data = full[off..off + payload].to_vec();
        frags.push(frag);
        off += payload;
        frag_id += 1;
    }
    frags
}

#[derive(Default)]
pub struct Defragger {
    pkt_id: u16,
    frags: Vec<Option<UdpMessage>>,
    count: u8,
    size: usize,
}

impl Defragger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one fragment. Returns the assembled message when complete.
    pub fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        if m.frag_count <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_count {
            return None;
        }
        if m.packet_id != self.pkt_id || m.frag_count as usize != self.frags.len() {
            self.pkt_id = m.packet_id;
            self.frags = vec![None; m.frag_count as usize];
            let id = m.frag_id as usize;
            self.size = m.data.len();
            self.count = 1;
            self.frags[id] = Some(m);
        } else if self.frags[m.frag_id as usize].is_none() {
            let id = m.frag_id as usize;
            self.size += m.data.len();
            self.count += 1;
            self.frags[id] = Some(m);
            if self.count as usize == self.frags.len() {
                let mut data = Vec::with_capacity(self.size);
                for frag in &self.frags {
                    data.extend_from_slice(&frag.as_ref().unwrap().data);
                }
                let mut out = self.frags[0].clone().unwrap();
                // last fragment's addr/session is what Go returns (it mutates `m`)
                // Go: mutates the *fed* message `m`, not frags[0].
                // We need to return the last fed message with assembled data.
                // The test expects session/packet/addr from the last fragment,
                // frag_id=0, frag_count=1, assembled data.
                // All fragments share those fields except data/frag_id.
                out.data = data;
                out.frag_id = 0;
                out.frag_count = 1;
                return Some(out);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::UdpMessage;

    fn msg(data: &[u8], frag_id: u8, frag_count: u8, pkt: u16) -> UdpMessage {
        UdpMessage {
            session_id: 123,
            packet_id: pkt,
            frag_id,
            frag_count,
            addr: "test:123".into(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn frag_no_split() {
        let m = msg(b"hello", 0, 1, 123);
        let got = frag_udp_message(&m, 100);
        assert_eq!(got, vec![m]);
    }

    #[test]
    fn frag_two() {
        let m = msg(b"hello", 0, 1, 123);
        let got = frag_udp_message(&m, 20);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].data, b"hel");
        assert_eq!(got[1].data, b"lo");
        assert_eq!(got[0].frag_count, 2);
        assert_eq!(got[1].frag_id, 1);
    }

    #[test]
    fn frag_four() {
        let m = msg(b"abcdefgh", 0, 1, 123);
        let got = frag_udp_message(&m, 19);
        assert_eq!(got.len(), 4);
        assert_eq!(got[0].data, b"ab");
        assert_eq!(got[1].data, b"cd");
        assert_eq!(got[2].data, b"ef");
        assert_eq!(got[3].data, b"gh");
        assert!(got.iter().all(|f| f.frag_count == 4));
    }

    #[test]
    fn defrag_go_sequence() {
        // Sequential Feed() cases from frag_test.go, one shared Defragger.
        let mut d = Defragger::new();
        let steps: &[(&str, UdpMessage, Option<UdpMessage>)] = &[
            (
                "no frag",
                msg(b"hello", 0, 1, 987),
                Some(msg(b"hello", 0, 1, 987)),
            ),
            ("frag 0 - 1/2", msg(b"hello ", 0, 2, 987), None),
            (
                "frag 0 - 2/2",
                msg(b"moto", 1, 2, 987),
                Some(msg(b"hello moto", 0, 1, 987)),
            ),
            ("frag 1 - 1/3", msg(b"deco", 0, 3, 987), None),
            ("frag 1 - 2/3", msg(b"*", 1, 3, 987), None),
            (
                "frag 1 - 3/3",
                msg(b"27", 2, 3, 987),
                Some(msg(b"deco*27", 0, 1, 987)),
            ),
            ("frag 2 - 1/2", msg(b"shinsekai", 1, 2, 233), None),
            ("frag 3 - 2/2", msg(b"what???", 1, 2, 244), None),
            ("frag 2 - 2/2", msg(b" annaijo", 1, 2, 233), None),
            ("invalid id", msg(b"shinsekai", 88, 2, 233), None),
            (
                "frag 2 - 1/2 re",
                msg(b"shinsekai", 0, 2, 233),
                Some(msg(b"shinsekai annaijo", 0, 1, 233)),
            ),
        ];
        for (name, input, want) in steps {
            let got = d.feed(input.clone());
            assert_eq!(got, *want, "{name}");
        }
    }

    #[test]
    fn official_1400_splits_at_1200() {
        let m = UdpMessage {
            session_id: 1,
            packet_id: 1,
            frag_id: 0,
            frag_count: 1,
            addr: "127.0.0.1:9".into(),
            data: vec![0u8; 1400],
        };
        assert!(m.size() > crate::protocol::MAX_DATAGRAM_FRAME_SIZE);
        let frags = frag_udp_message(&m, crate::protocol::MAX_DATAGRAM_FRAME_SIZE);
        assert!(frags.len() >= 2);
        assert!(frags.iter().all(|f| f.size() <= crate::protocol::MAX_DATAGRAM_FRAME_SIZE));
        let mut d = Defragger::new();
        let mut out = None;
        for f in frags {
            if let Some(done) = d.feed(f) {
                out = Some(done);
            }
        }
        assert_eq!(out.unwrap().data.len(), 1400);
    }
}

