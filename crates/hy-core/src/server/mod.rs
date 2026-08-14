//! Server interface and config. Transport impl is P1.

use crate::congestion::normalize_type;
use crate::error::Error;
use crate::io::DatagramIo;
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 8_388_608;
pub const DEFAULT_CONN_RECEIVE_WINDOW: u64 = DEFAULT_STREAM_RECEIVE_WINDOW * 5 / 2;
pub const DEFAULT_MAX_IDLE: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_INCOMING_STREAMS: u32 = 1024;
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(60);

#[cfg(feature = "transport")]
#[path = "impl.rs"]
mod imp;

#[cfg(feature = "transport")]
#[path = "udp.rs"]
mod udp;

#[cfg(feature = "transport")]
pub use imp::{serve, DefaultMasq, DefaultOutbound, PasswordAuthenticator};

#[async_trait]
pub trait Server: Send + Sync {
    async fn serve(&self) -> Result<(), Error>;
    async fn close(&self) -> Result<(), Error>;
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, addr: SocketAddr, auth: &str, tx: u64) -> (bool, String);
}

#[async_trait]
pub trait HyTcpStream: Send {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Error>;
    async fn close(&mut self) -> Result<(), Error>;
}

#[async_trait]
pub trait HyUdpSocket: Send {
    async fn read_from(&mut self, buf: &mut [u8]) -> Result<(usize, String), Error>;
    async fn write_to(&mut self, buf: &[u8], addr: &str) -> Result<usize, Error>;
    async fn close(&mut self) -> Result<(), Error>;
}

#[async_trait]
pub trait Outbound: Send + Sync {
    async fn tcp(&self, req_addr: &str) -> Result<Box<dyn HyTcpStream>, Error>;
    async fn udp(&self, req_addr: &str) -> Result<Box<dyn HyUdpSocket>, Error>;
    async fn check_udp(&self, req_addr: &str) -> Result<(), Error>;
}

#[async_trait]
pub trait RequestHook: Send + Sync {
    fn check(&self, is_udp: bool, req_addr: &str) -> bool;
    async fn tcp(
        &self,
        stream: &mut dyn HyTcpStream,
        req_addr: &mut String,
    ) -> Result<Vec<u8>, Error>;
    async fn udp(&self, data: &[u8], req_addr: &mut String) -> Result<(), Error>;
}

pub trait EventLogger: Send + Sync {
    fn connect(&self, addr: SocketAddr, id: &str, tx: u64);
    fn disconnect(&self, addr: SocketAddr, id: &str, err: Option<&Error>);
    fn tcp_request(&self, addr: SocketAddr, id: &str, req_addr: &str);
    fn tcp_error(&self, addr: SocketAddr, id: &str, req_addr: &str, err: Option<&Error>);
    fn udp_request(&self, addr: SocketAddr, id: &str, session_id: u32, req_addr: &str);
    fn udp_error(&self, addr: SocketAddr, id: &str, session_id: u32, err: Option<&Error>);
}

#[derive(Debug, Clone, Default)]
pub enum StreamState {
    #[default]
    Initial,
    Hooking,
    Connecting,
    Established,
}

#[derive(Debug, Default)]
pub struct StreamStats {
    pub auth_id: String,
    pub conn_id: u32,
    pub req_addr: String,
    pub hooked_req_addr: Option<String>,
    pub state: StreamState,
    pub tx: u64,
    pub rx: u64,
}

pub trait TrafficLogger: Send + Sync {
    /// false → close connection 0x107.
    fn log_traffic(&self, id: &str, tx: u64, rx: u64) -> bool;
    fn log_online_state(&self, id: &str, online: bool);
    fn trace_stream(&self, stream_id: u64, stats: Arc<StreamStats>);
    fn untrace_stream(&self, stream_id: u64);
}

#[async_trait]
pub trait MasqHandler: Send + Sync {
    async fn handle(&self, method: &str, host: &str, path: &str) -> MasqResponse;
}

pub struct MasqResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

#[derive(Clone, Default)]
pub struct TlsConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub client_ca_pem: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct QuicConfig {
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout: Duration,
    pub max_incoming_streams: u32,
    pub disable_path_mtu_discovery: bool,
    pub disable_gso: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CongestionConfig {
    pub ty: String,
    pub bbr_profile: String,
}

#[derive(Debug, Clone, Default)]
pub struct BandwidthConfig {
    pub max_tx: u64,
    pub max_rx: u64,
    pub disable_loss_compensation: bool,
}

pub struct Config {
    pub tls: TlsConfig,
    pub quic: QuicConfig,
    pub conn: Option<Arc<dyn DatagramIo>>,
    pub request_hook: Option<Arc<dyn RequestHook>>,
    pub outbound: Option<Arc<dyn Outbound>>,
    pub congestion: CongestionConfig,
    pub bandwidth: BandwidthConfig,
    pub ignore_client_bandwidth: bool,
    pub disable_udp: bool,
    pub udp_idle_timeout: Duration,
    pub authenticator: Option<Arc<dyn Authenticator>>,
    pub event_logger: Option<Arc<dyn EventLogger>>,
    pub traffic_logger: Option<Arc<dyn TrafficLogger>>,
    pub masq_handler: Option<Arc<dyn MasqHandler>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tls: TlsConfig::default(),
            quic: QuicConfig::default(),
            conn: None,
            request_hook: None,
            outbound: None,
            congestion: CongestionConfig::default(),
            bandwidth: BandwidthConfig::default(),
            ignore_client_bandwidth: false,
            disable_udp: false,
            udp_idle_timeout: Duration::ZERO,
            authenticator: None,
            event_logger: None,
            traffic_logger: None,
            masq_handler: None,
        }
    }
}

impl Config {
    pub fn fill(&mut self) -> Result<(), Error> {
        if self.tls.cert_pem.is_empty() && self.tls.key_pem.is_empty() {
            return Err(Error::config(
                "TLSConfig",
                "must set at least one of Certificates or GetCertificate",
            ));
        }
        fill_window(
            &mut self.quic.initial_stream_receive_window,
            DEFAULT_STREAM_RECEIVE_WINDOW,
            "QUICConfig.InitialStreamReceiveWindow",
        )?;
        fill_window(
            &mut self.quic.max_stream_receive_window,
            DEFAULT_STREAM_RECEIVE_WINDOW,
            "QUICConfig.MaxStreamReceiveWindow",
        )?;
        fill_window(
            &mut self.quic.initial_connection_receive_window,
            DEFAULT_CONN_RECEIVE_WINDOW,
            "QUICConfig.InitialConnectionReceiveWindow",
        )?;
        fill_window(
            &mut self.quic.max_connection_receive_window,
            DEFAULT_CONN_RECEIVE_WINDOW,
            "QUICConfig.MaxConnectionReceiveWindow",
        )?;
        if self.quic.max_idle_timeout.is_zero() {
            self.quic.max_idle_timeout = DEFAULT_MAX_IDLE;
        } else if self.quic.max_idle_timeout < Duration::from_secs(4)
            || self.quic.max_idle_timeout > Duration::from_secs(120)
        {
            return Err(Error::config(
                "QUICConfig.MaxIdleTimeout",
                "must be between 4s and 120s",
            ));
        }
        if self.quic.max_incoming_streams == 0 {
            self.quic.max_incoming_streams = DEFAULT_MAX_INCOMING_STREAMS;
        } else if self.quic.max_incoming_streams < 8 {
            return Err(Error::config(
                "QUICConfig.MaxIncomingStreams",
                "must be at least 8",
            ));
        }
        let _ = normalize_type(&self.congestion.ty)?;
        if self.conn.is_none() {
            return Err(Error::config("Conn", "must be set"));
        }
        if self.bandwidth.max_tx != 0 && self.bandwidth.max_tx < 65536 {
            return Err(Error::config("BandwidthConfig.MaxTx", "must be at least 65536"));
        }
        if self.bandwidth.max_rx != 0 && self.bandwidth.max_rx < 65536 {
            return Err(Error::config("BandwidthConfig.MaxRx", "must be at least 65536"));
        }
        if self.udp_idle_timeout.is_zero() {
            self.udp_idle_timeout = DEFAULT_UDP_IDLE;
        } else if self.udp_idle_timeout < Duration::from_secs(2)
            || self.udp_idle_timeout > Duration::from_secs(600)
        {
            return Err(Error::config(
                "UDPIdleTimeout",
                "must be between 2s and 600s",
            ));
        }
        if self.authenticator.is_none() {
            return Err(Error::config("Authenticator", "must be set"));
        }
        Ok(())
    }
}

fn fill_window(field: &mut u64, default: u64, name: &'static str) -> Result<(), Error> {
    if *field == 0 {
        *field = default;
    } else if *field < 16384 {
        return Err(Error::config(name, "must be at least 16384"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::StdUdp;
    use async_trait::async_trait;

    struct DummyAuth;

    #[async_trait]
    impl Authenticator for DummyAuth {
        async fn authenticate(&self, _addr: SocketAddr, _auth: &str, _tx: u64) -> (bool, String) {
            (true, "user".into())
        }
    }

    #[tokio::test]
    async fn requires_tls_conn_auth() {
        let mut c = Config::default();
        assert!(matches!(c.fill(), Err(Error::Config { field, .. }) if field == "TLSConfig"));
        c.tls.cert_pem = b"dummy".to_vec();
        assert!(matches!(c.fill(), Err(Error::Config { field, .. }) if field == "Conn"));
        let udp = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        c.conn = Some(Arc::new(udp));
        assert!(matches!(c.fill(), Err(Error::Config { field, .. }) if field == "Authenticator"));
        c.authenticator = Some(Arc::new(DummyAuth));
        c.fill().unwrap();
        assert_eq!(c.quic.max_incoming_streams, DEFAULT_MAX_INCOMING_STREAMS);
        assert_eq!(c.udp_idle_timeout, DEFAULT_UDP_IDLE);
    }
}
