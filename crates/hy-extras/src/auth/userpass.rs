use super::ct_eq;
use async_trait::async_trait;
use hy_core::server::Authenticator;
use std::collections::HashMap;
use std::net::SocketAddr;

/// `user:pass`. Usernames stored lowercase; password is case-sensitive.
pub struct UserPass(pub HashMap<String, String>);

impl UserPass {
    pub fn new(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut m = HashMap::new();
        for (u, p) in pairs {
            m.insert(u.to_ascii_lowercase(), p);
        }
        Self(m)
    }
}

#[async_trait]
impl Authenticator for UserPass {
    async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> (bool, String) {
        let Some((user, pass)) = auth.split_once(':') else {
            return (false, String::new());
        };
        let key = user.to_ascii_lowercase();
        match self.0.get(&key) {
            Some(expect) if ct_eq(expect.as_bytes(), pass.as_bytes()) => (true, key),
            _ => (false, String::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up() -> UserPass {
        UserPass::new([("Alice".into(), "s3cret".into())])
    }

    #[tokio::test]
    async fn user_case_insensitive() {
        let a = up();
        let (ok, id) = a
            .authenticate("127.0.0.1:1".parse().unwrap(), "ALICE:s3cret", 0)
            .await;
        assert!(ok);
        assert_eq!(id, "alice");
    }

    #[tokio::test]
    async fn pass_case_sensitive() {
        let a = up();
        let (ok, _) = a
            .authenticate("127.0.0.1:1".parse().unwrap(), "alice:S3cret", 0)
            .await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn missing_colon() {
        let a = up();
        let (ok, _) = a
            .authenticate("127.0.0.1:1".parse().unwrap(), "alice", 0)
            .await;
        assert!(!ok);
    }
}
