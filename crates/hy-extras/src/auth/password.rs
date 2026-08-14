use super::ct_eq;
use async_trait::async_trait;
use hy_core::server::Authenticator;
use std::net::SocketAddr;

/// Shared password. Success id is always `"user"`.
pub struct Password(pub String);

#[async_trait]
impl Authenticator for Password {
    async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> (bool, String) {
        if ct_eq(auth.as_bytes(), self.0.as_bytes()) {
            (true, "user".into())
        } else {
            (false, String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepts_password() {
        let a = Password("secret".into());
        let (ok, id) = a.authenticate("127.0.0.1:1".parse().unwrap(), "secret", 0).await;
        assert!(ok);
        assert_eq!(id, "user");
    }

    #[tokio::test]
    async fn rejects_wrong() {
        let a = Password("secret".into());
        let (ok, id) = a.authenticate("127.0.0.1:1".parse().unwrap(), "Secret", 0).await;
        assert!(!ok);
        assert!(id.is_empty());
    }
}
