use async_trait::async_trait;
use hy_core::server::Authenticator;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct CommandAuth {
    pub cmd: PathBuf,
    pub timeout: Duration,
}

impl CommandAuth {
    pub fn new(cmd: impl Into<PathBuf>) -> Self {
        Self {
            cmd: cmd.into(),
            timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
impl Authenticator for CommandAuth {
    async fn authenticate(&self, addr: SocketAddr, auth: &str, tx: u64) -> (bool, String) {
        let cmd = self.cmd.clone();
        let timeout = self.timeout;
        let addr = addr.to_string();
        let auth = auth.to_string();
        let join = tokio::task::spawn_blocking(move || run_cmd(&cmd, &addr, &auth, tx, timeout));
        match join.await {
            Ok(Ok((true, id))) => (true, id),
            _ => (false, String::new()),
        }
    }
}

fn run_cmd(
    cmd: &PathBuf,
    addr: &str,
    auth: &str,
    tx: u64,
    timeout: Duration,
) -> Result<(bool, String), String> {
    let mut child = Command::new(cmd)
        .arg(addr)
        .arg(auth)
        .arg(tx.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut so) = child.stdout.take() {
                    let _ = so.read_to_string(&mut out);
                }
                return Ok((status.success(), out.trim().to_string()));
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("timeout".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn true_cmd() {
        let a = CommandAuth::new("true");
        let (ok, id) = a
            .authenticate("127.0.0.1:1".parse().unwrap(), "x", 1)
            .await;
        assert!(ok);
        assert!(id.is_empty());
    }

    #[tokio::test]
    async fn false_cmd() {
        let a = CommandAuth::new("false");
        let (ok, _) = a
            .authenticate("127.0.0.1:1".parse().unwrap(), "x", 1)
            .await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn timeout_kills() {
        let p = std::env::temp_dir().join("hy_cmd_sleep.sh");
        std::fs::write(&p, "#!/bin/sh\nexec sleep 30\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let a = CommandAuth {
            cmd: p,
            timeout: Duration::from_millis(250),
        };
        let t = std::time::Instant::now();
        let (ok, _) = a
            .authenticate("127.0.0.1:1".parse().unwrap(), "x", 1)
            .await;
        assert!(!ok);
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}
