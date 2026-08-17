//! Quinn endpoint + `DatagramIo` adapter. No GSO. ALPN `h3`.

use crate::client::{QuicConfig as ClientQuicConfig, TlsConfig as ClientTlsConfig};
use crate::congestion::{normalize_type, CongestionType, SwitchableFactory};
use crate::error::Error;
use crate::protocol::MAX_DATAGRAM_FRAME_SIZE;
use crate::io::DatagramIo;
use crate::server::{QuicConfig as ServerQuicConfig, TlsConfig as ServerTlsConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime,
    TransportConfig, UdpPoller, VarInt,
};
use quinn_proto::RandomConnectionIdGenerator;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, ServerConfig as RustlsServerConfig, SignatureScheme};
use std::fmt;
use std::io::{self, Cursor, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Once};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::sync::mpsc;

static INSTALL_PROVIDER: Once = Once::new();

pub(crate) fn ensure_crypto_provider() {
    INSTALL_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

const ALPN_H3: &[u8] = b"h3";
const RECV_QUEUE: usize = 256;
const SEND_QUEUE: usize = 256;

struct Packet {
    data: Vec<u8>,
    addr: SocketAddr,
}

/// Adapts `Arc<dyn DatagramIo>` to quinn's `AsyncUdpSocket`.
///
/// Recv/send go through background tasks + mpsc — never `block_on` inside poll.
pub struct QuinnUdpAdapter {
    local: SocketAddr,
    rx: Mutex<mpsc::Receiver<Packet>>,
    tx: mpsc::Sender<Packet>,
    recv_waker: Arc<Mutex<Option<Waker>>>,
    send_waker: Arc<Mutex<Option<Waker>>>,
}

impl fmt::Debug for QuinnUdpAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnUdpAdapter")
            .field("local", &self.local)
            .finish()
    }
}

impl QuinnUdpAdapter {
    pub fn new(io: Arc<dyn DatagramIo>) -> io::Result<Arc<Self>> {
        let local = io.local_addr()?;
        let (incoming_tx, incoming_rx) = mpsc::channel(RECV_QUEUE);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Packet>(SEND_QUEUE);
        let recv_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
        let send_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));

        let recv_io = Arc::clone(&io);
        let waker_slot = Arc::clone(&recv_waker);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match recv_io.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let pkt = Packet {
                            data: buf[..n].to_vec(),
                            addr,
                        };
                        if incoming_tx.send(pkt).await.is_err() {
                            break;
                        }
                        if let Some(w) = waker_slot.lock().unwrap().take() {
                            w.wake();
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let send_io = Arc::clone(&io);
        let send_waker_slot = Arc::clone(&send_waker);
        tokio::spawn(async move {
            while let Some(pkt) = outgoing_rx.recv().await {
                if let Some(w) = send_waker_slot.lock().unwrap().take() {
                    w.wake();
                }
                let _ = send_io.send_to(&pkt.data, pkt.addr).await;
            }
        });

        Ok(Arc::new(Self {
            local,
            rx: Mutex::new(incoming_rx),
            tx: outgoing_tx,
            recv_waker,
            send_waker,
        }))
    }
}

impl AsyncUdpSocket for QuinnUdpAdapter {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SendPoller {
            tx: self.tx.clone(),
            send_waker: Arc::clone(&self.send_waker),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        match self.tx.try_send(Packet {
            data: transmit.contents.to_vec(),
            addr: transmit.destination,
        }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "send queue full",
            )),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "datagram io closed",
            )),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().unwrap();
        let mut count = 0;
        while count < bufs.len() && count < meta.len() {
            match rx.try_recv() {
                Ok(pkt) => {
                    // Truncating a QUIC packet corrupts it; drop instead.
                    if pkt.data.len() > bufs[count].len() {
                        continue;
                    }
                    let n = pkt.data.len();
                    bufs[count][..n].copy_from_slice(&pkt.data[..n]);
                    meta[count] = RecvMeta {
                        addr: pkt.addr,
                        len: n,
                        stride: n,
                        ecn: None,
                        dst_ip: Some(self.local.ip()),
                    };
                    count += 1;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if count == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "datagram io closed",
                        )));
                    }
                    break;
                }
            }
        }
        if count > 0 {
            return Poll::Ready(Ok(count));
        }
        *self.recv_waker.lock().unwrap() = Some(cx.waker().clone());
        // Recheck after registering waker to avoid lost wakeup.
        match rx.try_recv() {
            Ok(pkt) => {
                if pkt.data.len() > bufs[0].len() {
                    return Poll::Pending;
                }
                let n = pkt.data.len();
                bufs[0][..n].copy_from_slice(&pkt.data[..n]);
                meta[0] = RecvMeta {
                    addr: pkt.addr,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: Some(self.local.ip()),
                };
                Poll::Ready(Ok(1))
            }
            Err(_) => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        false
    }

    fn max_transmit_segments(&self) -> usize {
        1 // no GSO
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[derive(Debug)]
struct SendPoller {
    tx: mpsc::Sender<Packet>,
    send_waker: Arc<Mutex<Option<Waker>>>,
}

impl UdpPoller for SendPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.tx.capacity() > 0 {
            return Poll::Ready(Ok(()));
        }
        *self.send_waker.lock().unwrap() = Some(cx.waker().clone());
        if self.tx.capacity() > 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}


fn endpoint_config() -> EndpointConfig {
    let mut cfg = EndpointConfig::default();
    // Official hysteria/quic-go may send a full UDP message in one QUIC packet
    // when we advertise a large max_datagram_frame_size. Cap at 1200 so official 2.8.1 fragments instead of queueing a datagram that never fits with an ACK.
    let _ = cfg.max_udp_payload_size(1472);
    cfg
}

/// Client endpoint: zero-length local CID unless `disableChromeParrot`.
/// Server keeps the hashed 8-byte generator (official parrot is client-only).
fn client_endpoint_config(quic: &ClientQuicConfig) -> EndpointConfig {
    let mut cfg = endpoint_config();
    if !quic.disable_chrome_parrot {
        cfg.cid_generator(|| Box::new(RandomConnectionIdGenerator::new(0)));
    }
    cfg
}

/// Official client `MaxDatagramFrameSize` is 1200 and it drops larger datagrams.
/// Quinn advertises `datagram_receive_buffer_size` (38400) as the TP, so we must
/// cap sends ourselves — `send_datagram` succeeding is not enough.
pub(crate) fn datagram_send_budget(conn: &quinn::Connection) -> usize {
    conn.max_datagram_size()
        .unwrap_or(MAX_DATAGRAM_FRAME_SIZE)
        .min(MAX_DATAGRAM_FRAME_SIZE)
}

/// Build client transport with SwitchableController (handshake = BBR).
pub fn build_client_transport(
    quic: &ClientQuicConfig,
    congestion_ty: &str,
    disable_loss_comp: bool,
) -> Result<TransportConfig, Error> {
    let mut t = TransportConfig::default();
    t.stream_receive_window(VarInt::from_u64(quic.max_stream_receive_window).unwrap_or(VarInt::MAX));
    t.receive_window(VarInt::from_u64(quic.max_connection_receive_window).unwrap_or(VarInt::MAX));
    t.send_window(quic.max_connection_receive_window);
    let idle = quic.max_idle_timeout;
    t.max_idle_timeout(Some(
        IdleTimeoutMs(idle).try_into_idle().unwrap_or_default(),
    ));
    t.keep_alive_interval(Some(quic.keep_alive_period));
    t.datagram_receive_buffer_size(Some(1200 * 32));
    t.initial_mtu(1200);
    if quic.disable_path_mtu_discovery {
        t.mtu_discovery_config(None);
    }
    let configured = normalize_type(congestion_ty).unwrap_or(CongestionType::Bbr);
    t.congestion_controller_factory(Arc::new(SwitchableFactory {
        configured,
        disable_loss_comp,
    }));
    Ok(t)
}

pub fn build_server_transport(
    quic: &ServerQuicConfig,
    congestion_ty: &str,
    disable_loss_comp: bool,
) -> Result<TransportConfig, Error> {
    let mut t = TransportConfig::default();
    t.stream_receive_window(VarInt::from_u64(quic.max_stream_receive_window).unwrap_or(VarInt::MAX));
    t.receive_window(VarInt::from_u64(quic.max_connection_receive_window).unwrap_or(VarInt::MAX));
    t.send_window(quic.max_connection_receive_window);
    t.max_concurrent_bidi_streams(VarInt::from_u32(quic.max_incoming_streams));
    let idle = quic.max_idle_timeout;
    t.max_idle_timeout(Some(
        IdleTimeoutMs(idle).try_into_idle().unwrap_or_default(),
    ));
    t.datagram_receive_buffer_size(Some(1200 * 32));
    t.initial_mtu(1200);
    if quic.disable_path_mtu_discovery {
        t.mtu_discovery_config(None);
    }
    let configured = normalize_type(congestion_ty).unwrap_or(CongestionType::Bbr);
    t.congestion_controller_factory(Arc::new(SwitchableFactory {
        configured,
        disable_loss_comp,
    }));
    Ok(t)
}

struct IdleTimeoutMs(Duration);

impl IdleTimeoutMs {
    fn try_into_idle(self) -> Result<quinn::IdleTimeout, Error> {
        let ms = self.0.as_millis();
        let v = u64::try_from(ms).map_err(|_| Error::Quic("idle timeout too large".into()))?;
        Ok(VarInt::from_u64(v)
            .map_err(|_| Error::Quic("idle timeout varint".into()))?
            .into())
    }
}

pub fn build_client_endpoint(
    io: Arc<dyn DatagramIo>,
    tls: &ClientTlsConfig,
    quic: &ClientQuicConfig,
    congestion_ty: &str,
    disable_loss_comp: bool,
) -> Result<(Endpoint, ClientConfig), Error> {
    ensure_crypto_provider();
    let adapter = QuinnUdpAdapter::new(io).map_err(Error::Io)?;
    let rustls = build_rustls_client(tls)?;
    let mut client_cfg = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(rustls).map_err(|e| Error::Quic(e.to_string()))?,
    ));
    client_cfg.transport_config(Arc::new(build_client_transport(
        quic,
        congestion_ty,
        disable_loss_comp,
    )?));

    let mut endpoint = Endpoint::new_with_abstract_socket(
        client_endpoint_config(quic),
        None,
        adapter,
        Arc::new(TokioRuntime),
    )
    .map_err(Error::Io)?;
    endpoint.set_default_client_config(client_cfg.clone());
    Ok((endpoint, client_cfg))
}

pub fn build_server_endpoint(
    io: Arc<dyn DatagramIo>,
    tls: &ServerTlsConfig,
    quic: &ServerQuicConfig,
    congestion_ty: &str,
    disable_loss_comp: bool,
) -> Result<Endpoint, Error> {
    ensure_crypto_provider();
    let adapter = QuinnUdpAdapter::new(io).map_err(Error::Io)?;
    let rustls = build_rustls_server(tls)?;
    let mut server_cfg = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(rustls).map_err(|e| Error::Quic(e.to_string()))?,
    ));
    server_cfg.transport_config(Arc::new(build_server_transport(
        quic,
        congestion_ty,
        disable_loss_comp,
    )?));

    Endpoint::new_with_abstract_socket(
        endpoint_config(),
        Some(server_cfg),
        adapter,
        Arc::new(TokioRuntime),
    )
    .map_err(Error::Io)
}

fn finish_client_auth(
    builder: rustls::ConfigBuilder<RustlsClientConfig, rustls::client::WantsClientCert>,
    tls: &ClientTlsConfig,
) -> Result<RustlsClientConfig, Error> {
    if tls.client_cert_pem.is_empty() {
        return Ok(builder.with_no_client_auth());
    }
    let certs = load_certs(&tls.client_cert_pem)?;
    let key = load_private_key(&tls.client_key_pem)?;
    builder
        .with_client_auth_cert(certs, key)
        .map_err(|e| Error::config("tls.clientCertificate", e.to_string()))
}

pub(crate) fn build_rustls_client(tls: &ClientTlsConfig) -> Result<RustlsClientConfig, Error> {
    let builder = rustls::ClientConfig::builder();
    let mut cfg = if tls.insecure_skip_verify {
        finish_client_auth(
            builder
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new()),
            tls,
        )?
    } else if let Some(ref pin) = tls.pin_sha256 {
        finish_client_auth(
            builder
                .dangerous()
                .with_custom_certificate_verifier(PinSha256Verifier::new(pin)?),
            tls,
        )?
    } else {
        let roots = load_root_store(tls)?;
        finish_client_auth(builder.with_root_certificates(roots), tls)?
    };
    cfg.alpn_protocols = vec![ALPN_H3.to_vec()];
    cfg.enable_early_data = true;
    let _ = &tls.server_name;
    let _ = &tls.ech_config_list;
    Ok(cfg)
}


fn load_root_store(tls: &ClientTlsConfig) -> Result<rustls::RootCertStore, Error> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if !tls.ca_pem.is_empty() {
        for c in load_certs(&tls.ca_pem)? {
            roots
                .add(c)
                .map_err(|e| Error::config("TLSConfig", e.to_string()))?;
        }
    }
    if roots.is_empty() {
        return Err(Error::config("TLSConfig", "no root certificates"));
    }
    Ok(roots)
}

pub(crate) fn build_rustls_server(tls: &ServerTlsConfig) -> Result<RustlsServerConfig, Error> {
    let certs = load_certs(&tls.cert_pem)?;
    let key = load_private_key(&tls.key_pem)?;
    let builder = RustlsServerConfig::builder();
    let mut cfg = if tls.client_ca_pem.is_empty() {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::config("TLSConfig", e.to_string()))?
    } else {
        let mut roots = rustls::RootCertStore::empty();
        for c in load_certs(&tls.client_ca_pem)? {
            roots
                .add(c)
                .map_err(|e| Error::config("tls.clientCA", e.to_string()))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| Error::config("tls.clientCA", e.to_string()))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| Error::config("TLSConfig", e.to_string()))?
    };
    cfg.alpn_protocols = vec![ALPN_H3.to_vec()];
    cfg.max_early_data_size = 0;
    Ok(cfg)
}

fn load_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut reader = Cursor::new(pem);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| Error::config("TLSConfig", e.to_string()))?;
    if certs.is_empty() {
        return Err(Error::config("TLSConfig", "no certificates in PEM"));
    }
    Ok(certs)
}

fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, Error> {
    let mut reader = Cursor::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::config("TLSConfig", e.to_string()))?
        .ok_or_else(|| Error::config("TLSConfig", "no private key in PEM"))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct PinSha256Verifier {
    pin_hex: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinSha256Verifier {
    fn new(pin: &str) -> Result<Arc<Self>, Error> {
        let pin_hex = pin.replace(':', "").to_ascii_lowercase();
        if pin_hex.len() != 64 || !pin_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::config("tls.pinSHA256", "expected 32-byte hex"));
        }
        Ok(Arc::new(Self {
            pin_hex,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }))
    }
}

impl ServerCertVerifier for PinSha256Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let hash = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        let got = hex_encode(hash.as_ref());
        if got == self.pin_hex {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pin SHA-256 mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::TlsConfig as ClientTls;
    use crate::server::TlsConfig as ServerTls;

    fn self_signed_pem() -> (Vec<u8>, Vec<u8>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (
            certified.cert.pem().into_bytes(),
            certified.key_pair.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn server_0rtt_disabled_client_early_data_still_enabled() {
        ensure_crypto_provider();
        let (cert_pem, key_pem) = self_signed_pem();
        let server_cfg = build_rustls_server(&ServerTls {
            cert_pem,
            key_pem,
            ..Default::default()
        })
        .expect("server rustls config");
        assert_eq!(server_cfg.max_early_data_size, 0);

        let client_cfg = build_rustls_client(&ClientTls {
            insecure_skip_verify: true,
            ..Default::default()
        })
        .expect("client rustls config");
        assert!(client_cfg.enable_early_data);
    }
}
