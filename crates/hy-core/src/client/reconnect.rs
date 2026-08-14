//! Reconnectable client. `lazy=true` does not connect until first tcp/udp.

use super::{connect, Client, Config, HyTcpConn, HyUdpConn};
use crate::error::Error;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Reconnectable {
    cfg: Config,
    current: RwLock<Option<Arc<dyn Client>>>,
    dead: AtomicBool,
}

/// If `lazy`, skip the initial handshake. First `tcp`/`udp` connects.
pub async fn connect_reconnectable(cfg: Config, lazy: bool) -> Result<Arc<dyn Client>, Error> {
    let rc = Reconnectable {
        cfg,
        current: RwLock::new(None),
        dead: AtomicBool::new(false),
    };
    if !lazy {
        rc.ensure().await?;
    }
    Ok(Arc::new(rc))
}

impl Reconnectable {
    async fn ensure(&self) -> Result<Arc<dyn Client>, Error> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(Error::Closed(Some("permanently closed".into())));
        }
        {
            let g = self.current.read().await;
            if let Some(c) = g.as_ref() {
                return Ok(Arc::clone(c));
            }
        }
        let mut g = self.current.write().await;
        if self.dead.load(Ordering::SeqCst) {
            return Err(Error::Closed(Some("permanently closed".into())));
        }
        if let Some(c) = g.as_ref() {
            return Ok(Arc::clone(c));
        }
        let (cli, _info) = connect(self.cfg.clone()).await?;
        let cli: Arc<dyn Client> = Arc::from(cli);
        *g = Some(Arc::clone(&cli));
        Ok(cli)
    }

    async fn clear_if_same(&self, used: &Arc<dyn Client>) {
        let mut g = self.current.write().await;
        if let Some(cur) = g.as_ref() {
            if Arc::ptr_eq(cur, used) {
                *g = None;
            }
        }
    }

    fn is_dead(err: &Error) -> bool {
        matches!(err, Error::Closed(_))
    }

    #[cfg(test)]
    async fn inject(&self, c: Arc<dyn Client>) {
        *self.current.write().await = Some(c);
    }
}

#[async_trait]
impl Client for Reconnectable {
    async fn tcp(&self, addr: &str) -> Result<Box<dyn HyTcpConn>, Error> {
        let cli = self.ensure().await?;
        match cli.tcp(addr).await {
            Ok(c) => Ok(c),
            Err(e) if Self::is_dead(&e) && !self.dead.load(Ordering::SeqCst) => {
                self.clear_if_same(&cli).await;
                let cli = self.ensure().await?;
                cli.tcp(addr).await
            }
            Err(e) => Err(e),
        }
    }

    async fn udp(&self) -> Result<Box<dyn HyUdpConn>, Error> {
        let cli = self.ensure().await?;
        match cli.udp().await {
            Ok(c) => Ok(c),
            Err(e) if Self::is_dead(&e) && !self.dead.load(Ordering::SeqCst) => {
                self.clear_if_same(&cli).await;
                let cli = self.ensure().await?;
                cli.udp().await
            }
            Err(e) => Err(e),
        }
    }

    async fn close(&self) -> Result<(), Error> {
        self.dead.store(true, Ordering::SeqCst);
        let mut g = self.current.write().await;
        if let Some(c) = g.take() {
            return c.close().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn cfg() -> Config {
        let mut c = Config::default();
        c.server_addr = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1));
        c
    }

    #[tokio::test]
    async fn lazy_skips_connect() {
        let c = connect_reconnectable(cfg(), true).await.expect("lazy construct");
        // downcast not available; close without ever connecting must succeed
        c.close().await.unwrap();
        match c.tcp("127.0.0.1:9").await {
            Err(Error::Closed(_)) => {}
            Ok(_) => panic!("expected Closed after explicit close"),
            Err(e) => panic!("expected Closed, got {e}"),
        }
    }

    #[tokio::test]
    async fn lazy_first_tcp_attempts_connect() {
        let c = connect_reconnectable(cfg(), true).await.expect("lazy construct");
        match c.tcp("127.0.0.1:9").await {
            Err(Error::Connect(_)) | Err(Error::Io(_)) => {}
            Err(Error::Closed(_)) => panic!("lazy first tcp must connect, not Closed"),
            Ok(_) => panic!("unexpected ok to :1"),
            Err(e) => panic!("unexpected {e}"),
        }
    }

    #[tokio::test]
    async fn eager_connects_immediately() {
        let r = connect_reconnectable(cfg(), false).await;
        assert!(r.is_err(), "eager connect to :1 must fail");
    }

    struct AlwaysClosed;

    #[async_trait]
    impl Client for AlwaysClosed {
        async fn tcp(&self, _addr: &str) -> Result<Box<dyn HyTcpConn>, Error> {
            Err(Error::Closed(Some("stale".into())))
        }
        async fn udp(&self) -> Result<Box<dyn HyUdpConn>, Error> {
            Err(Error::Closed(Some("stale".into())))
        }
        async fn close(&self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn closed_retries_connect() {
        let rc = Reconnectable {
            cfg: cfg(),
            current: RwLock::new(None),
            dead: AtomicBool::new(false),
        };
        rc.inject(Arc::new(AlwaysClosed)).await;
        match rc.tcp("127.0.0.1:9").await {
            Err(Error::Connect(_)) | Err(Error::Io(_)) => {}
            Err(Error::Closed(Some(m))) if m == "stale" => {
                panic!("must retry after Closed, not return stale")
            }
            Err(Error::Closed(_)) => panic!("must retry after Closed, not stay Closed"),
            Ok(_) => panic!("unexpected ok to :1"),
            Err(e) => panic!("unexpected {e}"),
        }
    }
}
