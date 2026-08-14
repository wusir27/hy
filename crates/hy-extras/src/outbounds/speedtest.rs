//! In-memory speedtest outbound (§10.6). Wire format matches official Go.

use super::{AddrEx, PluggableOutbound};
use async_trait::async_trait;
use hy_core::error::Error;
use hy_core::server::{HyTcpStream, HyUdpSocket};
use rand::RngCore;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

pub const SPEEDTEST_DEST: &str = "@SpeedTest";
const TYPE_DOWNLOAD: u8 = 0x01;
const TYPE_UPLOAD: u8 = 0x02;
const CHUNK_SIZE: usize = 64 * 1024;
/// Duplex buffer large enough for one chunk plus response headers.
const PIPE_BUF: usize = CHUNK_SIZE * 2;

pub struct SpeedtestHandler {
    pub next: Arc<dyn PluggableOutbound>,
}

pub fn is_speedtest_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower == "@speedtest" || lower.starts_with("@speedtest")
}

#[allow(dead_code)] // protocol helpers for clients / unit tests
pub fn write_download_request(buf: &mut Vec<u8>, length: u32) {
    buf.push(TYPE_DOWNLOAD);
    buf.extend_from_slice(&length.to_be_bytes());
}

#[allow(dead_code)]
pub fn write_upload_request(buf: &mut Vec<u8>, length: u32) {
    buf.push(TYPE_UPLOAD);
    buf.extend_from_slice(&length.to_be_bytes());
}

/// After the type byte has been consumed: read u32 BE length.
#[allow(dead_code)]
pub fn parse_length_be(data: &[u8]) -> Result<u32, Error> {
    if data.len() < 4 {
        return Err(Error::protocol("speedtest length truncated"));
    }
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

fn new_server_conn() -> Box<dyn HyTcpStream> {
    let (client, server) = tokio::io::duplex(PIPE_BUF);
    tokio::spawn(async move {
        let _ = run_server(server).await;
    });
    Box::new(DuplexTcp(client))
}

async fn run_server(mut conn: DuplexStream) -> Result<(), Error> {
    let mut typ = [0u8; 1];
    conn.read_exact(&mut typ).await.map_err(Error::Io)?;
    match typ[0] {
        TYPE_DOWNLOAD => handle_download(&mut conn).await,
        TYPE_UPLOAD => handle_upload(&mut conn).await,
        _ => Err(Error::protocol(format!("unknown speedtest type: {}", typ[0]))),
    }
}

async fn write_status_ok<W: AsyncWrite + Unpin>(w: &mut W) -> Result<(), Error> {
    // status(0) + u16 BE msg len + "OK"
    let mut hdr = [0u8; 1 + 2 + 2];
    hdr[0] = 0;
    hdr[1] = 0;
    hdr[2] = 2; // len("OK")
    hdr[3] = b'O';
    hdr[4] = b'K';
    w.write_all(&hdr).await.map_err(Error::Io)
}

async fn handle_download<C: AsyncRead + AsyncWrite + Unpin>(conn: &mut C) -> Result<(), Error> {
    let mut len_buf = [0u8; 4];
    conn.read_exact(&mut len_buf).await.map_err(Error::Io)?;
    let length = u32::from_be_bytes(len_buf);
    write_status_ok(conn).await?;

    let mut chunk = vec![0u8; CHUNK_SIZE];
    rand::thread_rng().fill_bytes(&mut chunk);
    let mut remaining = length;
    while remaining > 0 {
        let n = remaining.min(CHUNK_SIZE as u32) as usize;
        conn.write_all(&chunk[..n]).await.map_err(Error::Io)?;
        remaining -= n as u32;
    }
    Ok(())
}

async fn handle_upload<C: AsyncRead + AsyncWrite + Unpin>(conn: &mut C) -> Result<(), Error> {
    let mut len_buf = [0u8; 4];
    conn.read_exact(&mut len_buf).await.map_err(Error::Io)?;
    let length = u32::from_be_bytes(len_buf);
    write_status_ok(conn).await?;

    let mut chunk = vec![0u8; CHUNK_SIZE];
    let start = Instant::now();
    let mut remaining = length;
    while remaining > 0 {
        let n = remaining.min(CHUNK_SIZE as u32) as usize;
        match conn.read(&mut chunk[..n]).await.map_err(Error::Io)? {
            0 => {
                if remaining == 0 {
                    break;
                }
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "speedtest upload short read",
                )));
            }
            rn => remaining -= rn as u32,
        }
    }
    let duration_ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
    let mut summary = [0u8; 8];
    summary[..4].copy_from_slice(&duration_ms.to_be_bytes());
    summary[4..].copy_from_slice(&length.to_be_bytes());
    conn.write_all(&summary).await.map_err(Error::Io)
}

struct DuplexTcp(DuplexStream);

#[async_trait]
impl HyTcpStream for DuplexTcp {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.0.read(buf).await.map_err(Error::Io)
    }
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0.write(buf).await.map_err(Error::Io)
    }
    async fn close(&mut self) -> Result<(), Error> {
        let _ = self.0.shutdown().await;
        Ok(())
    }
}

#[async_trait]
impl PluggableOutbound for SpeedtestHandler {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        if is_speedtest_host(&addr.host) {
            return Ok(new_server_conn());
        }
        self.next.tcp(addr).await
    }

    async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        if is_speedtest_host(&addr.host) {
            return Err(Error::Dial("speedtest is tcp only".into()));
        }
        self.next.udp(addr).await
    }

    async fn check_udp(&self, addr: &mut AddrEx) -> Result<(), Error> {
        if is_speedtest_host(&addr.host) {
            return Err(Error::Dial("speedtest is tcp only".into()));
        }
        self.next.check_udp(addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn write_parse_download_request() {
        let mut buf = Vec::new();
        write_download_request(&mut buf, 64);
        assert_eq!(buf, [0x01, 0x00, 0x00, 0x00, 0x40]);
        assert_eq!(parse_length_be(&buf[1..]).unwrap(), 64);

        let mut buf = Vec::new();
        write_download_request(&mut buf, 78909912);
        assert_eq!(buf, [0x01, 0x04, 0xB4, 0x11, 0xD8]);
        assert_eq!(parse_length_be(&buf[1..]).unwrap(), 78909912);
    }

    #[test]
    fn write_parse_upload_request() {
        let mut buf = Vec::new();
        write_upload_request(&mut buf, 0);
        assert_eq!(buf, [0x02, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(parse_length_be(&buf[1..]).unwrap(), 0);

        let mut buf = Vec::new();
        write_upload_request(&mut buf, 2291758882);
        assert_eq!(buf, [0x02, 0x88, 0x99, 0x77, 0x22]);
        assert_eq!(parse_length_be(&buf[1..]).unwrap(), 2291758882);
    }

    #[test]
    fn speedtest_host_match() {
        assert!(is_speedtest_host("@SpeedTest"));
        assert!(is_speedtest_host("@speedtest"));
        assert!(is_speedtest_host("@SPEEDTEST"));
        assert!(is_speedtest_host("@speedtest-extra"));
        assert!(!is_speedtest_host("example.com"));
        assert!(!is_speedtest_host("@other"));
    }

    struct Rec(Mutex<Option<AddrEx>>);

    #[async_trait]
    impl PluggableOutbound for Rec {
        async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
            *self.0.lock().unwrap() = Some(addr.clone());
            Err(Error::Dial("rec".into()))
        }
        async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
            *self.0.lock().unwrap() = Some(addr.clone());
            Err(Error::Dial("rec".into()))
        }
        async fn check_udp(&self, addr: &mut AddrEx) -> Result<(), Error> {
            *self.0.lock().unwrap() = Some(addr.clone());
            Err(Error::Dial("rec".into()))
        }
    }

    async fn read_exact_hy(s: &mut dyn HyTcpStream, buf: &mut [u8]) -> Result<(), Error> {
        let mut off = 0;
        while off < buf.len() {
            let n = s.read(&mut buf[off..]).await?;
            if n == 0 {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
            off += n;
        }
        Ok(())
    }

    #[tokio::test]
    async fn tcp_download_speedtest() {
        for host in ["@SpeedTest", "@speedtest"] {
            let rec = Arc::new(Rec(Mutex::new(None)));
            let h = SpeedtestHandler { next: rec.clone() };
            let mut addr = AddrEx {
                host: host.into(),
                port: 0,
                resolve: None,
            };
            let mut stream = h.tcp(&mut addr).await.unwrap();
            assert!(rec.0.lock().unwrap().is_none());

            let mut req = Vec::new();
            write_download_request(&mut req, 64);
            assert_eq!(stream.write(&req).await.unwrap(), req.len());

            let mut hdr = [0u8; 5];
            read_exact_hy(&mut *stream, &mut hdr).await.unwrap();
            assert_eq!(hdr[0], 0);
            assert_eq!(u16::from_be_bytes([hdr[1], hdr[2]]), 2);
            assert_eq!(&hdr[3..], b"OK");

            let mut data = [0u8; 64];
            read_exact_hy(&mut *stream, &mut data).await.unwrap();
            let _ = stream.close().await;
        }
    }

    #[tokio::test]
    async fn udp_speedtest_tcp_only() {
        let rec = Arc::new(Rec(Mutex::new(None)));
        let h = SpeedtestHandler { next: rec.clone() };
        for host in ["@SpeedTest", "@speedtest"] {
            let mut addr = AddrEx {
                host: host.into(),
                port: 0,
                resolve: None,
            };
            let e = match h.udp(&mut addr).await {
                Err(e) => e,
                Ok(_) => panic!("expected udp error"),
            };
            match e {
                Error::Dial(s) => assert!(s.contains("tcp only"), "{s}"),
                other => panic!("{other:?}"),
            }
            let e = match h.check_udp(&mut addr).await {
                Err(e) => e,
                Ok(()) => panic!("expected check_udp error"),
            };
            match e {
                Error::Dial(s) => assert!(s.contains("tcp only"), "{s}"),
                other => panic!("{other:?}"),
            }
            assert!(rec.0.lock().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn non_speedtest_falls_through() {
        let rec = Arc::new(Rec(Mutex::new(None)));
        let h = SpeedtestHandler { next: rec.clone() };
        let mut addr = AddrEx {
            host: "example.com".into(),
            port: 443,
            resolve: None,
        };
        let e = match h.tcp(&mut addr).await {
            Err(e) => e,
            Ok(_) => panic!("expected fallthrough dial error"),
        };
        match e {
            Error::Dial(s) => assert_eq!(s, "rec"),
            other => panic!("{other:?}"),
        }
        let seen = rec.0.lock().unwrap().clone().unwrap();
        assert_eq!(seen.host, "example.com");
        assert_eq!(seen.port, 443);
    }
}
