//! Salamander: `[8B salt] + XOR(plain, BLAKE2b-256(PSK || salt))`.

use async_trait::async_trait;
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;
type Blake2b256 = Blake2b<U32>;
use hy_core::io::DatagramIo;
use hy_core::Error;
use rand::RngCore;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

pub const SALT_LEN: usize = 8;
const PSK_MIN: usize = 4;
const KEY_LEN: usize = 32;
const SEND_BUF: usize = 2048;

/// DatagramIo decorator. `send_to`/`recv_from` `n` is plaintext length.
pub struct ObfsSalamander {
    inner: Arc<dyn DatagramIo>,
    psk: Vec<u8>,
}

impl ObfsSalamander {
    pub fn new(inner: Arc<dyn DatagramIo>, psk: &[u8]) -> Result<Self, Error> {
        if psk.len() < PSK_MIN {
            return Err(Error::config("PSK", "must be at least 4 bytes"));
        }
        Ok(Self {
            inner,
            psk: psk.to_vec(),
        })
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

/// `out[0..8]=salt; out[8+i]=in[i]^key[i%32]`. Returns wire length, or 0 if `out` is short.
pub fn obfs(psk: &[u8], plain: &[u8], out: &mut [u8]) -> usize {
    let n = plain.len() + SALT_LEN;
    if out.len() < n {
        return 0;
    }
    rand::thread_rng().fill_bytes(&mut out[..SALT_LEN]);
    let k = key(psk, &out[..SALT_LEN]);
    for (i, b) in plain.iter().enumerate() {
        out[SALT_LEN + i] = b ^ k[i % KEY_LEN];
    }
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
    for (i, b) in wire[SALT_LEN..].iter().enumerate() {
        out[i] = b ^ k[i % KEY_LEN];
    }
    n
}

#[async_trait]
impl DatagramIo for ObfsSalamander {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = [0u8; 65535];
        loop {
            let (n, addr) = self.inner.recv_from(&mut wire).await?;
            let plain = deobfs(&self.psk, &wire[..n], buf);
            if plain > 0 {
                return Ok((plain, addr));
            }
        }
    }

    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        let mut out = [0u8; SEND_BUF];
        let n = obfs(&self.psk, buf, &mut out);
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salamander buffer too small",
            ));
        }
        self.inner.send_to(&out[..n], dest).await?;
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
        let err = match ObfsSalamander::new(dummy_io(), b"abc") { Ok(_) => panic!("expected err"), Err(e) => e };
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
        fn set_read_buffer(&self, _: usize) -> io::Result<()> { Ok(()) }
        fn set_write_buffer(&self, _: usize) -> io::Result<()> { Ok(()) }
    }
    fn dummy_io() -> Arc<dyn DatagramIo> {
        Arc::new(DummyIo)
    }
}
