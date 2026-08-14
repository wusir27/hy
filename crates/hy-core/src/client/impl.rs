//! Client `connect` + TCP/UDP over native quinn.

use super::udp::ClientUdpSm;
use super::{Client, Config, HandshakeInfo, HyTcpConn, HyUdpConn, TlsConfig};
use crate::congestion::{apply_cc_mode, client_send_cc, CcChoice};
use crate::error::Error;
use crate::io::{ConnFactory, StdUdpFactory};
use crate::protocol::{
    read_tcp_response_bytes, write_tcp_request_bytes, CLOSE_OK, CLOSE_PROTOCOL_ERROR,
    STATUS_AUTH_OK,
};
use crate::transport::h3_auth;
use crate::transport::quic;
use async_trait::async_trait;
use quinn::{Connection, RecvStream, SendStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

struct ClientInner {
    cfg: Config,
    endpoint: quinn::Endpoint,
    conn: RwLock<Option<Connection>>,
    closed: AtomicBool,
    udp_enabled: bool,
    udp_sm: RwLock<Option<Arc<ClientUdpSm>>>,
}

/// Establish QUIC + HTTP/3 `/auth`. Non-233 → `Error::Auth` + close `0x101`.
pub async fn connect(mut cfg: Config) -> Result<(Arc<dyn Client>, HandshakeInfo), Error> {
    cfg.verify_and_fill()?;
    let server_addr = cfg.server_addr.expect("filled");

    let factory: Arc<dyn ConnFactory> = cfg
        .conn_factory
        .clone()
        .unwrap_or_else(|| Arc::new(StdUdpFactory));
    let io = factory.open(server_addr).await?;

    let (endpoint, _client_cfg) = quic::build_client_endpoint(
        io,
        &cfg.tls,
        &cfg.quic,
        &cfg.congestion.ty,
        cfg.bandwidth.disable_loss_compensation,
    )?;

    let sni = sni_name(&cfg.tls, server_addr);
    let connecting = endpoint
        .connect(server_addr, &sni)
        .map_err(|e| Error::Connect(e.to_string()))?;
    let conn = connecting
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;

    let (status, auth_resp, h3_hold) =
        h3_auth::client_auth(conn.clone(), &cfg.auth, cfg.bandwidth.max_rx).await?;

    if status != STATUS_AUTH_OK {
        conn.close(
            quinn::VarInt::from_u32(CLOSE_PROTOCOL_ERROR as u32),
            b"auth failed",
        );
        return Err(Error::Auth { status });
    }

    let cc_choice = client_send_cc(auth_resp.rx_auto, auth_resp.rx, cfg.bandwidth.max_tx);
    apply_cc_mode(&conn, cc_choice);
    let tx = match cc_choice {
        CcChoice::Brutal { bps } => bps,
        CcChoice::Configured => 0,
    };

    let info = HandshakeInfo {
        udp_enabled: auth_resp.udp_enabled,
        tx,
        server_addr,
        ech_accepted: false,
    };

    let udp_sm = if auth_resp.udp_enabled {
        Some(ClientUdpSm::start(conn.clone()))
    } else {
        None
    };

    // Hold h3 so Drop does not close QUIC (same as server).
    let hold_conn = conn.clone();
    tokio::spawn(async move {
        let _h3 = h3_hold;
        let _ = hold_conn.closed().await;
    });

    let inner = Arc::new(ClientInner {
        cfg,
        endpoint,
        conn: RwLock::new(Some(conn)),
        closed: AtomicBool::new(false),
        udp_enabled: info.udp_enabled,
        udp_sm: RwLock::new(udp_sm),
    });
    Ok((inner as Arc<dyn Client>, info))
}

fn sni_name(tls: &TlsConfig, server_addr: std::net::SocketAddr) -> String {
    if !tls.server_name.is_empty() {
        return tls.server_name.clone();
    }
    match server_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6.to_string(),
    }
}

#[async_trait]
impl Client for ClientInner {
    async fn tcp(&self, addr: &str) -> Result<Box<dyn HyTcpConn>, Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed(None));
        }
        let conn = {
            let guard = self.conn.read().await;
            guard
                .clone()
                .ok_or_else(|| Error::Closed(Some("no connection".into())))?
        };

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Closed(Some(e.to_string())))?;

        let req = write_tcp_request_bytes(addr);
        send.write_all(&req)
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        let mut established = true;
        let mut pending = Vec::new();
        if !self.cfg.fast_open {
            let mut buf = Vec::with_capacity(512);
            loop {
                let mut tmp = [0u8; 256];
                let n = recv
                    .read(&mut tmp)
                    .await
                    .map_err(|e| Error::Closed(Some(e.to_string())))?
                    .ok_or_else(|| Error::Closed(Some("eof before tcp response".into())))?;
                buf.extend_from_slice(&tmp[..n]);
                match read_tcp_response_bytes(&buf) {
                    Ok((ok, msg, consumed)) => {
                        if !ok {
                            let _ = send.finish();
                            let _ = recv.stop(quinn::VarInt::from_u32(0));
                            return Err(Error::Dial(msg));
                        }
                        if consumed < buf.len() {
                            pending.extend_from_slice(&buf[consumed..]);
                        }
                        break;
                    }
                    Err(Error::Protocol(_)) if buf.len() < 8192 => continue,
                    Err(e) => return Err(e),
                }
            }
        } else {
            established = false;
        }

        Ok(Box::new(TcpConn {
            send: tokio::sync::Mutex::new(send),
            recv: tokio::sync::Mutex::new(RecvHalf {
                recv,
                established,
                pending,
                resp_buf: Vec::new(),
            }),
        }))
    }

    async fn udp(&self) -> Result<Box<dyn HyUdpConn>, Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed(None));
        }
        if !self.udp_enabled {
            return Err(Error::Dial("UDP not enabled".into()));
        }
        let sm = {
            let guard = self.udp_sm.read().await;
            guard
                .clone()
                .ok_or_else(|| Error::Dial("UDP not enabled".into()))?
        };
        sm.new_udp()
    }

    async fn close(&self) -> Result<(), Error> {
        self.closed.store(true, Ordering::SeqCst);
        *self.udp_sm.write().await = None;
        if let Some(conn) = self.conn.write().await.take() {
            conn.close(quinn::VarInt::from_u32(CLOSE_OK as u32), b"");
        }
        self.endpoint
            .close(quinn::VarInt::from_u32(CLOSE_OK as u32), b"");
        Ok(())
    }
}

struct RecvHalf {
    recv: RecvStream,
    established: bool,
    pending: Vec<u8>,
    resp_buf: Vec<u8>,
}

struct TcpConn {
    send: tokio::sync::Mutex<SendStream>,
    recv: tokio::sync::Mutex<RecvHalf>,
}

#[async_trait]
impl HyTcpConn for TcpConn {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut r = self.recv.lock().await;
        if !r.established {
            loop {
                match read_tcp_response_bytes(&r.resp_buf) {
                    Ok((ok, msg, consumed)) => {
                        if !ok {
                            return Err(Error::Dial(msg));
                        }
                        let rest = r.resp_buf.split_off(consumed);
                        r.pending.extend_from_slice(&rest);
                        r.resp_buf.clear();
                        r.established = true;
                        break;
                    }
                    Err(Error::Protocol(_)) => {
                        let mut tmp = [0u8; 256];
                        let n = r
                            .recv
                            .read(&mut tmp)
                            .await
                            .map_err(|e| Error::Closed(Some(e.to_string())))?
                            .ok_or_else(|| Error::Closed(Some("eof before tcp response".into())))?;
                        r.resp_buf.extend_from_slice(&tmp[..n]);
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        if !r.pending.is_empty() {
            let n = r.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&r.pending[..n]);
            r.pending.drain(..n);
            return Ok(n);
        }

        match r.recv.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(e) => Err(Error::Closed(Some(e.to_string()))),
        }
    }

    async fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        // FastOpen: write allowed before response (aligned with Go).
        self.send
            .lock()
            .await
            .write_all(buf)
            .await
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        Ok(buf.len())
    }

    async fn close(&self) -> Result<(), Error> {
        let _ = self.send.lock().await.finish();
        let _ = self.recv.lock().await.recv.stop(quinn::VarInt::from_u32(0));
        Ok(())
    }
}
