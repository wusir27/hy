//! Client interface and config. Transport impl is P1.

use crate::congestion::{normalize_bbr_profile, normalize_type, CongestionType};
use crate::error::Error;
use crate::io::ConnFactory;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 8_388_608;
pub const DEFAULT_CONN_RECEIVE_WINDOW: u64 = DEFAULT_STREAM_RECEIVE_WINDOW * 5 / 2;
pub const DEFAULT_MAX_IDLE: Duration = Duration::from_secs(30);
pub const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(10);

#[cfg(feature = "transport")]
#[path = "impl.rs"]
mod imp;

#[cfg(feature = "transport")]
#[path = "udp.rs"]
mod udp;

#[cfg(feature = "transport")]
pub use imp::connect;

#[cfg(feature = "transport")]
#[path = "reconnect.rs"]
mod reconnect;

#[cfg(feature = "transport")]
pub use reconnect::connect_reconnectable;

#[async_trait]
pub trait Client: Send + Sync {
    async fn tcp(&self, addr: &str) -> Result<Box<dyn HyTcpConn>, Error>;
    async fn udp(&self) -> Result<Box<dyn HyUdpConn>, Error>;
    async fn close(&self) -> Result<(), Error>;
}

#[async_trait]
pub trait HyTcpConn: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, Error>;
    async fn write(&self, buf: &[u8]) -> Result<usize, Error>;
    async fn close(&self) -> Result<(), Error>;
}

/// `send` is not concurrency-safe with another `send` (shared send buffer), same as Go.
/// `send` and `receive` may run concurrently (SOCKS5 ASSOCIATE / forwarding).
#[async_trait]
pub trait HyUdpConn: Send + Sync {
    async fn receive(&self) -> Result<(Vec<u8>, String), Error>;
    async fn send(&self, data: &[u8], addr: &str) -> Result<(), Error>;
    async fn close(&self) -> Result<(), Error>;
}

#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub udp_enabled: bool,
    /// 0 if using configured CC (BBR / Reno).
    pub tx: u64,
    pub server_addr: SocketAddr,
    /// v1 always false (ECH not implemented).
    pub ech_accepted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub server_name: String,
    pub insecure_skip_verify: bool,
    pub pin_sha256: Option<String>,
    pub ca_pem: Vec<u8>,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ech_config_list: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct QuicConfig {
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_idle_timeout: Duration,
    pub keep_alive_period: Duration,
    pub disable_path_mtu_discovery: bool,
    pub disable_gso: bool,
    /// v1 no-op: quinn cannot do Chrome zero-length CID.
    pub disable_chrome_parrot: bool,
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

#[derive(Clone)]
pub struct Config {
    pub conn_factory: Option<Arc<dyn ConnFactory>>,
    pub server_addr: Option<SocketAddr>,
    pub auth: String,
    pub tls: TlsConfig,
    pub quic: QuicConfig,
    pub congestion: CongestionConfig,
    pub bandwidth: BandwidthConfig,
    pub fast_open: bool,
    filled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            conn_factory: None,
            server_addr: None,
            auth: String::new(),
            tls: TlsConfig::default(),
            quic: QuicConfig::default(),
            congestion: CongestionConfig::default(),
            bandwidth: BandwidthConfig::default(),
            fast_open: false,
            filled: false,
        }
    }
}

impl Config {
    pub fn verify_and_fill(&mut self) -> Result<(), Error> {
        if self.filled {
            return Ok(());
        }
        if self.server_addr.is_none() {
            return Err(Error::config("ServerAddr", "must be set"));
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
        if self.quic.keep_alive_period.is_zero() {
            self.quic.keep_alive_period = DEFAULT_KEEP_ALIVE;
        } else if self.quic.keep_alive_period < Duration::from_secs(2)
            || self.quic.keep_alive_period > Duration::from_secs(60)
        {
            return Err(Error::config(
                "QUICConfig.KeepAlivePeriod",
                "must be between 2s and 60s",
            ));
        }
        let ty = normalize_type(&self.congestion.ty)?;
        if ty == CongestionType::Bbr {
            let _ = normalize_bbr_profile(&self.congestion.bbr_profile)?;
        }
        self.filled = true;
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
    use std::net::{IpAddr, Ipv4Addr};

    fn addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)
    }

    #[test]
    fn requires_server_addr() {
        let mut c = Config::default();
        assert!(matches!(c.verify_and_fill(), Err(Error::Config { field, .. }) if field == "ServerAddr"));
    }

    #[test]
    fn fills_defaults() {
        let mut c = Config {
            server_addr: Some(addr()),
            ..Default::default()
        };
        c.verify_and_fill().unwrap();
        assert_eq!(c.quic.max_stream_receive_window, DEFAULT_STREAM_RECEIVE_WINDOW);
        assert_eq!(c.quic.max_connection_receive_window, DEFAULT_CONN_RECEIVE_WINDOW);
        assert_eq!(c.quic.max_idle_timeout, DEFAULT_MAX_IDLE);
        assert!(c.conn_factory.is_none());
    }

    #[test]
    fn rejects_tiny_window() {
        let mut c = Config {
            server_addr: Some(addr()),
            quic: QuicConfig {
                initial_stream_receive_window: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(c.verify_and_fill().is_err());
    }
}
