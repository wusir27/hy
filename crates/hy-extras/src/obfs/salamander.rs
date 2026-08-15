//! Salamander: `[8B salt] + XOR(plain, BLAKE2b-256(PSK || salt))`.

use async_trait::async_trait;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use hy_core::io::DatagramIo;
use hy_core::Error;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

type Blake2b256 = Blake2b<U32>;

pub const SALT_LEN: usize = 8;
const PSK_MIN: usize = 4;
const KEY_LEN: usize = 32;
/// Official `udpBufferSize`: QUIC packets ≤1500, 2k is enough.
const UDP_BUF: usize = 2048;

/// DatagramIo decorator. `send_to`/`recv_from` `n` is plaintext length.
pub struct ObfsSalamander {
    inner: Arc<dyn DatagramIo>,
    psk: Vec<u8>,
    /// Reused `psk || salt` (official `keyInput`).
    key_input: Mutex<Vec<u8>>,
    rng: Mutex<StdRng>,
    read_buf: Mutex<Vec<u8>>,
    write_buf: Mutex<Vec<u8>>,
}

impl ObfsSalamander {
    pub fn new(inner: Arc<dyn DatagramIo>, psk: &[u8]) -> Result<Self, Error> {
        if psk.len() < PSK_MIN {
            return Err(Error::config("PSK", "must be at least 4 bytes"));
        }
        let mut key_input = vec![0u8; psk.len() + SALT_LEN];
        key_input[..psk.len()].copy_from_slice(psk);
        Ok(Self {
            inner,
            psk: psk.to_vec(),
            key_input: Mutex::new(key_input),
            rng: Mutex::new(StdRng::from_entropy()),
            read_buf: Mutex::new(vec![0u8; UDP_BUF]),
            write_buf: Mutex::new(vec![0u8; UDP_BUF]),
        })
    }

    fn key_locked(key_input: &mut [u8], psk_len: usize, salt: &[u8]) -> [u8; KEY_LEN] {
        key_input[psk_len..psk_len + SALT_LEN].copy_from_slice(&salt[..SALT_LEN]);
        let mut h = Blake2b256::new();
        h.update(&*key_input);
        let out = h.finalize();
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&out);
        k
    }
}

pub fn key(psk: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let mut h = Blake2b256::new();
    h.update(psk);
    h.update(salt);
    let out = h.finalize();
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&out);
    k
}

/// XOR `src` into `dst` with a repeating 32-byte key, 32B chunks then tail.
fn xor_keyed(dst: &mut [u8], src: &[u8], k: &[u8; KEY_LEN]) {
    let n = src.len().min(dst.len());
    let mut i = 0;
    while i + KEY_LEN <= n {
        for j in 0..KEY_LEN {
            dst[i + j] = src[i + j] ^ k[j];
        }
        i += KEY_LEN;
    }
    while i < n {
        dst[i] = src[i] ^ k[i % KEY_LEN];
        i += 1;
    }
}

/// `out[0..8]=salt; out[8+i]=in[i]^key[i%32]`. Returns wire length, or 0 if `out` is short.
pub fn obfs(psk: &[u8], plain: &[u8], out: &mut [u8]) -> usize {
    let n = plain.len() + SALT_LEN;
    if out.len() < n {
        return 0;
    }
    rand::thread_rng().fill_bytes(&mut out[..SALT_LEN]);
    let k = key(psk, &out[..SALT_LEN]);
    xor_keyed(&mut out[SALT_LEN..n], plain, &k);
    n
}

/// Reverse of [`obfs`]. `in.len()<=8` or `out` too small → 0.
pub fn deobfs(psk: &[u8], wire: &[u8], out: &mut [u8]) -> usize {
    if wire.len() <= SALT_LEN {
        return 0;
    }
    let n = wire.len() - SALT_LEN;
    if out.len() < n {
        return 0;
    }
    let k = key(psk, &wire[..SALT_LEN]);
    xor_keyed(&mut out[..n], &wire[SALT_LEN..], &k);
    n
}

fn take_buf(slot: &Mutex<Vec<u8>>) -> Vec<u8> {
    let mut g = slot.lock().unwrap_or_else(|e| e.into_inner());
    let mut v = std::mem::take(&mut *g);
    if v.len() < UDP_BUF {
        v.resize(UDP_BUF, 0);
    }
    v
}

fn put_buf(slot: &Mutex<Vec<u8>>, v: Vec<u8>) {
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = v;
}

#[async_trait]
impl DatagramIo for ObfsSalamander {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let mut wire = take_buf(&self.read_buf);
            let recv = self.inner.recv_from(&mut wire).await;
            let (n, addr) = match recv {
                Ok(v) => v,
                Err(e) => {
                    put_buf(&self.read_buf, wire);
                    return Err(e);
                }
            };
            let plain = if n > SALT_LEN && buf.len() >= n - SALT_LEN {
                let mut ki = self.key_input.lock().unwrap_or_else(|e| e.into_inner());
                let k = Self::key_locked(&mut ki, self.psk.len(), &wire[..SALT_LEN]);
                drop(ki);
                let body = n - SALT_LEN;
                xor_keyed(&mut buf[..body], &wire[SALT_LEN..n], &k);
                body
            } else {
                0
            };
            put_buf(&self.read_buf, wire);
            if plain > 0 {
                return Ok((plain, addr));
            }
        }
    }

    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        let need = buf.len() + SALT_LEN;
        if need > UDP_BUF {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salamander buffer too small",
            ));
        }
        let mut out = take_buf(&self.write_buf);
        {
            let mut rng = self.rng.lock().unwrap_or_else(|e| e.into_inner());
            rng.fill_bytes(&mut out[..SALT_LEN]);
        }
        let k = {
            let mut ki = self.key_input.lock().unwrap_or_else(|e| e.into_inner());
            Self::key_locked(&mut ki, self.psk.len(), &out[..SALT_LEN])
        };
        xor_keyed(&mut out[SALT_LEN..need], buf, &k);
        let send = self.inner.send_to(&out[..need], dest).await;
        put_buf(&self.write_buf, out);
        send?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn set_read_buffer(&self, n: usize) -> io::Result<()> {
        self.inner.set_read_buffer(n)
    }

    fn set_write_buffer(&self, n: usize) -> io::Result<()> {
        self.inner.set_write_buffer(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hy_core::io::StdUdp;
    use std::sync::Arc;

    #[test]
    fn psk_too_short() {
        let err = match ObfsSalamander::new(dummy_io(), b"abc") {
            Ok(_) => panic!("expected err"),
            Err(e) => e,
        };
        match err {
            Error::Config { field, .. } => assert_eq!(field, "PSK"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn obfs_deobfs_roundtrip() {
        let psk = b"test-psk";
        let plain = b"hello-salamander";
        let mut wire = [0u8; 64];
        let n = obfs(psk, plain, &mut wire);
        assert_eq!(n, plain.len() + SALT_LEN);
        assert_ne!(&wire[SALT_LEN..n], plain.as_slice());
        let mut out = [0u8; 64];
        let m = deobfs(psk, &wire[..n], &mut out);
        assert_eq!(&out[..m], plain);
    }

    #[test]
    fn xor_32b_chunks_and_tail() {
        let psk = b"test-psk";
        for len in [1usize, 31, 32, 33, 64, 1200] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut wire = vec![0u8; len + SALT_LEN];
            let n = obfs(psk, &plain, &mut wire);
            assert_eq!(n, len + SALT_LEN);
            let mut out = vec![0u8; len];
            let m = deobfs(psk, &wire[..n], &mut out);
            assert_eq!(m, len);
            assert_eq!(out, plain);
        }
    }

    #[test]
    fn deobfs_short_is_zero() {
        let mut out = [0u8; 16];
        assert_eq!(deobfs(b"test-psk", b"short", &mut out), 0);
        assert_eq!(deobfs(b"test-psk", &[0u8; 8], &mut out), 0);
    }

    #[test]
    fn obfs_out_too_small() {
        let mut out = [0u8; 4];
        assert_eq!(obfs(b"test-psk", b"hello", &mut out), 0);
    }

    #[tokio::test]
    async fn loopback_plain_len() {
        let a = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dest = b.local_addr().unwrap();
        let psk = b"abcd";
        let send = ObfsSalamander::new(Arc::new(a), psk).unwrap();
        let recv = ObfsSalamander::new(Arc::new(b), psk).unwrap();
        let msg = b"quic-looking-but-not";
        let n = send.send_to(msg, dest).await.unwrap();
        assert_eq!(n, msg.len());
        let mut buf = [0u8; 64];
        let (m, _) = recv.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..m], msg);
    }

    #[tokio::test]
    async fn loopback_1200() {
        let a = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dest = b.local_addr().unwrap();
        let send = ObfsSalamander::new(Arc::new(a), b"abcd").unwrap();
        let recv = ObfsSalamander::new(Arc::new(b), b"abcd").unwrap();
        let msg = vec![0x5Au8; 1200];
        send.send_to(&msg, dest).await.unwrap();
        let mut buf = [0u8; 2048];
        let (m, _) = recv.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..m], msg.as_slice());
    }

    struct DummyIo;
    #[async_trait]
    impl DatagramIo for DummyIo {
        async fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("dummy"))
        }
        async fn send_to(&self, _: &[u8], _: SocketAddr) -> io::Result<usize> {
            Err(io::Error::other("dummy"))
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::other("dummy"))
        }
        fn set_read_buffer(&self, _: usize) -> io::Result<()> {
            Ok(())
        }
        fn set_write_buffer(&self, _: usize) -> io::Result<()> {
            Ok(())
        }
    }
    fn dummy_io() -> Arc<dyn DatagramIo> {
        Arc::new(DummyIo)
    }
}
