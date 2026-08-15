//! Masquerade handlers: string / file / proxy + optional TCP HTTP(S) façade.

mod file;
mod proxy;
mod tcp;

pub use file::FileMasq;
pub use proxy::ProxyMasq;
pub use tcp::MasqTcpServer;

use async_trait::async_trait;
use bytes::Bytes;
use hy_core::server::{MasqHandler, MasqResponse};

pub struct StringMasq {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl StringMasq {
    pub fn new(status: u16, headers: Vec<(String, String)>, content: impl Into<Vec<u8>>) -> Self {
        let status = if status == 0 { 200 } else { status };
        Self {
            status,
            headers,
            body: Bytes::from(content.into()),
        }
    }
}

#[async_trait]
impl MasqHandler for StringMasq {
    async fn handle(&self, _method: &str, _host: &str, _path: &str) -> MasqResponse {
        MasqResponse {
            status: self.status,
            headers: self.headers.clone(),
            body: self.body.clone(),
        }
    }
}

/// 404 empty body — used when listenHTTP is set without a typed masq handler.
pub struct NotFoundMasq;

#[async_trait]
impl MasqHandler for NotFoundMasq {
    async fn handle(&self, _method: &str, _host: &str, _path: &str) -> MasqResponse {
        MasqResponse {
            status: 404,
            headers: vec![],
            body: Bytes::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn string_returns_configured() {
        let m = StringMasq::new(
            418,
            vec![("content-type".into(), "text/plain".into())],
            b"aint nothin here".to_vec(),
        );
        let r = m.handle("GET", "x", "/").await;
        assert_eq!(r.status, 418);
        assert_eq!(r.body.as_ref(), b"aint nothin here");
        assert_eq!(r.headers[0].1, "text/plain");
    }

    #[tokio::test]
    async fn zero_status_is_200() {
        let m = StringMasq::new(0, Vec::new(), b"ok".to_vec());
        assert_eq!(m.handle("GET", "", "/").await.status, 200);
    }
}
