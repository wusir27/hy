//! Linux XDP helper spawn. This gate ONLY `std::process` launches `mimic.path`.
//! Do not rewrite XDP / eBPF here, and do not vendor mimic.

use hy_core::Error;
use serde::Deserialize;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};

/// Official camelCase YAML `mimic:` block.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MimicYaml {
    pub enabled: Option<bool>,
    pub interface: Option<String>,
    pub xdp_mode: Option<String>,
    pub path: Option<String>,
    pub extra_args: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Validated spawn plan. `fill` never launches the process; [`MimicSpec::start`] does.
#[derive(Debug, Clone)]
pub struct MimicSpec {
    pub path: String,
    pub interface: String,
    pub xdp_mode: Option<String>,
    pub extra_args: Vec<String>,
    pub addr: SocketAddr,
    pub role: Role,
}

/// Child helper. Drop / [`MimicHandle::close`] sends SIGTERM (SIGINT fallback) and waits.
pub struct MimicHandle {
    child: Option<Child>,
}

pub fn unsupported_os_error() -> Error {
    Error::config("mimic", "only supported on Linux")
}

/// Validate YAML. Does not spawn.
///
/// Official looks up PATH when `path` is empty; this gate errors instead
/// (design: 无 path 明确报错).
pub fn fill_mimic(
    y: Option<&MimicYaml>,
    hopping: bool,
    addr: SocketAddr,
    role: Role,
) -> Result<Option<MimicSpec>, Error> {
    let Some(y) = y else {
        return Ok(None);
    };
    if !y.enabled.unwrap_or(false) {
        return Ok(None);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (hopping, addr, role);
        return Err(unsupported_os_error());
    }
    if hopping {
        return Err(Error::config(
            "mimic",
            "cannot be used with port hopping",
        ));
    }
    let path = y.path.as_deref().unwrap_or("").trim();
    if path.is_empty() {
        return Err(Error::config(
            "mimic.path",
            "path is required when mimic is enabled",
        ));
    }
    // Official derives the iface via DialUDP towards the peer when empty.
    // This gate requires it explicitly so we don't probe routes (keep the spawn path small).
    let interface = y.interface.as_deref().unwrap_or("").trim();
    if interface.is_empty() {
        return Err(Error::config("mimic.interface", "must be set"));
    }
    Ok(Some(MimicSpec {
        path: path.to_string(),
        interface: interface.to_string(),
        xdp_mode: y
            .xdp_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        extra_args: y.extra_args.clone().unwrap_or_default(),
        addr,
        role,
    }))
}

impl MimicSpec {
    /// Official whitelist: client `remote=ip:port`; server `local=ip:port,handshake=0:3`.
    pub fn filter(&self) -> String {
        filter_for(self.role, self.addr)
    }

    /// Official argv after the binary: `run <iface> -f <filter> [--xdp-mode <mode>] <extraArgs...>`.
    pub fn args(&self) -> Vec<String> {
        let mut args = vec![
            "run".to_string(),
            self.interface.clone(),
            "-f".to_string(),
            self.filter(),
        ];
        if let Some(mode) = &self.xdp_mode {
            args.push("--xdp-mode".to_string());
            args.push(mode.clone());
        }
        args.extend(self.extra_args.iter().cloned());
        args
    }

    /// Spawn the configured binary. Linux only; no XDP/eBPF in this process.
    pub fn start(&self) -> Result<MimicHandle, Error> {
        start_one(self)
    }
}

pub fn start(spec: Option<&MimicSpec>) -> Result<Option<MimicHandle>, Error> {
    match spec {
        None => Ok(None),
        Some(s) => s.start().map(Some),
    }
}

fn start_one(spec: &MimicSpec) -> Result<MimicHandle, Error> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = spec;
        return Err(unsupported_os_error());
    }
    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new(&spec.path);
        cmd.args(spec.args())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        // Kill the helper if hy dies without Drop (official Pdeathsig=SIGTERM).
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
                    Ok(())
                });
            }
        }
        let child = cmd
            .spawn()
            .map_err(|e| Error::config("mimic", format!("failed to start: {e}")))?;
        tracing::info!(
            path = %spec.path,
            interface = %spec.interface,
            filter = %spec.filter(),
            "mimic started"
        );
        Ok(MimicHandle {
            child: Some(child),
        })
    }
}

fn filter_for(role: Role, addr: SocketAddr) -> String {
    let host = if addr.ip().is_unspecified() {
        "0.0.0.0".to_string()
    } else if addr.is_ipv6() {
        format!("[{}]", addr.ip())
    } else {
        addr.ip().to_string()
    };
    match role {
        Role::Server => format!("local={host}:{},handshake=0:3", addr.port()),
        Role::Client => format!("remote={host}:{}", addr.port()),
    }
}

impl MimicHandle {
    pub fn close(mut self) {
        self.kill_wait();
    }

    fn kill_wait(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        #[cfg(target_os = "linux")]
        {
            let pid = child.id() as i32;
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

impl Drop for MimicHandle {
    fn drop(&mut self) {
        self.kill_wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        fill_client, fill_server, parse_client_yaml, parse_server_yaml, ClientApp, ServerApp,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn disabled_and_absent_fill_client() {
        for extra in ["mimic: { enabled: false }", "mimic: {}"] {
            let y =
                parse_client_yaml(&format!("server: 127.0.0.1:1\nauth: x\n{extra}\n")).unwrap();
            let app = fill_client(&y).unwrap_or_else(|e| panic!("{extra}: {e}"));
            assert!(app.mimic.is_none(), "{extra} must not spawn a plan");
        }
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\n").unwrap();
        fill_client(&y).expect("absent mimic fills");
    }

    #[test]
    fn enabled_without_path_errors() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\nmimic: { enabled: true, interface: lo }\n",
        )
        .unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, reason }) => {
                assert!(
                    field.contains("path") || reason.to_lowercase().contains("path"),
                    "field={field} reason={reason}"
                );
            }
            other => panic!("expected path error, got {}", match &other {
                Ok(_) => "Ok".into(),
                Err(e) => format!("Err({e})"),
            }),
        }
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\nmimic: { enabled: true }\n")
            .unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, reason }) => {
                assert!(
                    field.contains("path") || reason.to_lowercase().contains("path"),
                    "field={field} reason={reason}"
                );
            }
            other => panic!("expected path error, got {}", match &other {
                Ok(_) => "Ok".into(),
                Err(e) => format!("Err({e})"),
            }),
        }
    }

    #[test]
    fn client_hop_plus_mimic_errors() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:443,10000-20000\nauth: x\nmimic: { enabled: true }\n",
        )
        .unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, reason }) => {
                assert_eq!(field, "mimic");
                assert!(
                    reason.to_lowercase().contains("hop"),
                    "field={field} reason={reason}"
                );
            }
            other => panic!("expected hop error, got {}", match &other {
                Ok(_) => "Ok".into(),
                Err(e) => format!("Err({e})"),
            }),
        }
    }

    #[test]
    fn unsupported_os_wording() {
        let e = unsupported_os_error();
        match e {
            Error::Config { field, reason } => {
                assert_eq!(field, "mimic");
                assert!(
                    reason.to_lowercase().contains("linux"),
                    "reason={reason}"
                );
            }
            other => panic!("expected Config, {other:?}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn enabled_non_linux_errors() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\nmimic: { enabled: true, path: /bin/true, interface: lo }\n",
        )
        .unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, reason }) => {
                assert_eq!(field, "mimic");
                assert!(reason.to_lowercase().contains("linux"), "{reason}");
            }
            other => panic!("expected linux-only error, got {other:?}"),
        }
    }

    #[test]
    fn argv_and_filters_match_official() {
        let mut spec = MimicSpec {
            path: "/usr/bin/mimic".into(),
            interface: "eth0".into(),
            xdp_mode: Some("native".into()),
            extra_args: vec!["--padding".into(), "random".into()],
            addr: "1.2.3.4:443".parse().unwrap(),
            role: Role::Client,
        };
        assert_eq!(
            spec.args(),
            [
                "run",
                "eth0",
                "-f",
                "remote=1.2.3.4:443",
                "--xdp-mode",
                "native",
                "--padding",
                "random"
            ]
        );
        spec.xdp_mode = None;
        spec.extra_args.clear();
        spec.role = Role::Server;
        spec.addr = "0.0.0.0:443".parse().unwrap();
        assert_eq!(spec.filter(), "local=0.0.0.0:443,handshake=0:3");
        spec.addr = "[::1]:443".parse().unwrap();
        assert_eq!(spec.filter(), "local=[::1]:443,handshake=0:3");
    }

    fn write_stub(dir: &std::path::Path, argv_file: &std::path::Path) -> std::path::PathBuf {
        let stub = dir.join("mimic-stub");
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\nexec sleep 30\n",
            argv_file.display()
        );
        std::fs::write(&stub, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&stub).unwrap().permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&stub, p).unwrap();
        }
        stub
    }

    fn wait_argv(path: &std::path::Path) -> String {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(s) = std::fs::read_to_string(path) {
                if s.contains("run") && s.contains("-f") {
                    return s;
                }
            }
            if Instant::now() >= deadline {
                return std::fs::read_to_string(path).unwrap_or_default();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn dummy_tls_dir() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "hy-mimic-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("t.crt");
        let key = dir.join("t.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            .unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")
            .unwrap();
        (dir, cert, key)
    }

    fn fill_server_yaml(extra: &str) -> Result<ServerApp, Error> {
        let (dir, cert, key) = dummy_tls_dir();
        let y = parse_server_yaml(&format!(
            "listen: 127.0.0.1:0\ntls: {{ cert: {}, key: {} }}\nauth: {{ type: password, password: test }}\n{extra}\n",
            cert.display(),
            key.display()
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let r = rt.block_on(fill_server(&y));
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    #[test]
    fn disabled_and_absent_fill_server() {
        fill_server_yaml("mimic: { enabled: false }").expect("enabled: false");
        fill_server_yaml("mimic: {}").expect("mimic: {}");
        fill_server_yaml("").expect("absent mimic");
    }

    #[test]
    fn enabled_without_path_errors_server() {
        match fill_server_yaml("mimic: { enabled: true, interface: lo }") {
            Err(Error::Config { field, reason }) => {
                assert!(
                    field.contains("path") || reason.to_lowercase().contains("path"),
                    "field={field} reason={reason}"
                );
            }
            other => panic!("expected path error, got {}", match &other {
                Ok(_) => "Ok".into(),
                Err(e) => format!("Err({e})"),
            }),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_spawn_client_start_writes_argv() {
        let dir = std::env::temp_dir().join(format!("hy-mimic-spawn-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let argv_file = dir.join("argv.txt");
        let stub = write_stub(&dir, &argv_file);
        let y = parse_client_yaml(&format!(
            "server: 127.0.0.1:443\nauth: x\nmimic:\n  enabled: true\n  interface: lo\n  path: {}\n  extraArgs: [\"--padding\", \"random\"]\n",
            stub.display()
        ))
        .unwrap();
        let app: ClientApp = fill_client(&y).expect("fill with stub path");
        assert!(app.core.quic.disable_gso);
        let handle = app.start().expect("start").expect("spawned");
        let argv = wait_argv(&argv_file);
        assert!(argv.lines().any(|l| l == "run"), "argv={argv:?}");
        assert!(argv.lines().any(|l| l == "-f"), "argv={argv:?}");
        assert!(
            argv.contains("remote=127.0.0.1:443"),
            "argv={argv:?}"
        );
        assert!(argv.contains("--padding"), "argv={argv:?}");
        handle.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_spawn_server_start_writes_argv() {
        let dir = std::env::temp_dir().join(format!("hy-mimic-spawn-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let argv_file = dir.join("argv.txt");
        let stub = write_stub(&dir, &argv_file);
        let (tls_dir, cert, key) = dummy_tls_dir();
        let y = parse_server_yaml(&format!(
            "listen: 127.0.0.1:18443\ntls: {{ cert: {}, key: {} }}\nauth: {{ type: password, password: test }}\nmimic:\n  enabled: true\n  interface: lo\n  path: {}\n  xdpMode: skb\n",
            cert.display(),
            key.display(),
            stub.display()
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app: ServerApp = rt.block_on(fill_server(&y)).expect("fill server stub");
        assert!(app.core.quic.disable_gso);
        let handle = app.start().expect("start").expect("spawned");
        let argv = wait_argv(&argv_file);
        assert!(argv.lines().any(|l| l == "run"), "argv={argv:?}");
        assert!(argv.lines().any(|l| l == "-f"), "argv={argv:?}");
        assert!(
            argv.contains("local=127.0.0.1:18443,handshake=0:3"),
            "argv={argv:?}"
        );
        assert!(argv.contains("--xdp-mode"), "argv={argv:?}");
        assert!(argv.contains("skb"), "argv={argv:?}");
        handle.close();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&tls_dir);
    }
}
