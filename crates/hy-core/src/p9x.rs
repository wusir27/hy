//! P9.X diagnostics (hy side). Log-only: no protocol / close / hold / reset changes.
//!
//! Every event is `tracing::debug` with message `"p9x"` and fields
//! `side="hy"`, `conn_seq`, `remote`, `event`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

static CONN_SEQ: AtomicU64 = AtomicU64::new(1);

/// Process-global monotonic sequence allocated when a QUIC connection is accepted.
pub fn alloc_conn_seq() -> u64 {
    CONN_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Identity copied into auth, `AuthUniFilter`, HTTP, and TCP tasks.
#[derive(Clone, Copy, Debug)]
pub struct P9xConn {
    pub conn_seq: u64,
    pub remote: SocketAddr,
}

impl Default for P9xConn {
    fn default() -> Self {
        Self {
            conn_seq: 0,
            remote: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }
}

impl P9xConn {
    pub fn new(conn_seq: u64, remote: SocketAddr) -> Self {
        Self { conn_seq, remote }
    }

    pub fn conn_accept(&self) {
        tracing::debug!(
            side = "hy",
            conn_seq = self.conn_seq,
            remote = %self.remote,
            event = "conn_accept",
            "p9x"
        );
    }

    /// rust-h3 server SETTINGS aligned with official quic-go newRawServerConn.
    pub fn settings(&self) {
        tracing::debug!(
            side = "hy",
            conn_seq = self.conn_seq,
            remote = %self.remote,
            event = "settings",
            extended_connect = 1,
            max_field = 1048576,
            grease = 0,
            "p9x"
        );
    }

    pub fn uni(&self, stream_id: u64, stream_type: Option<u64>, duplicate: bool) {
        match stream_type {
            Some(stream_type) => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "uni",
                stream_id,
                stream_type,
                duplicate,
                "p9x"
            ),
            None => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "uni",
                stream_id,
                duplicate,
                "p9x"
            ),
        }
    }

    pub fn bidi_first(&self, stream_id: u64, first_varint: Option<u64>) {
        match first_varint {
            Some(first_varint) => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "bidi_first",
                stream_id,
                first_varint,
                "p9x"
            ),
            None => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "bidi_first",
                stream_id,
                "p9x"
            ),
        }
    }

    pub fn http_req(&self, method: &str, authority: &str, path: &str) {
        tracing::debug!(
            side = "hy",
            conn_seq = self.conn_seq,
            remote = %self.remote,
            event = "http_req",
            method,
            authority,
            path,
            "p9x"
        );
    }

    pub fn auth_233(&self) {
        tracing::debug!(
            side = "hy",
            conn_seq = self.conn_seq,
            remote = %self.remote,
            event = "auth_233",
            "p9x"
        );
    }

    /// HEADERS+FIN of a 233 have been written (`send_response` + `finish` Ok).
    pub fn auth_233_fin(&self) {
        tracing::debug!(
            side = "hy",
            conn_seq = self.conn_seq,
            remote = %self.remote,
            event = "auth_233_fin",
            "p9x"
        );
    }

    pub fn close_local(&self, close_code: u64) {
        tracing::debug!(
            side = "hy",
            conn_seq = self.conn_seq,
            remote = %self.remote,
            event = "close_local",
            close_initiator = "local",
            close_code,
            "p9x"
        );
    }

    pub fn close_remote(
        &self,
        close_initiator: &'static str,
        close_code: Option<u64>,
        err: &str,
    ) {
        match close_code {
            Some(close_code) => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "close_remote",
                close_initiator,
                close_code,
                err = %err,
                "p9x"
            ),
            None => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "close_remote",
                close_initiator,
                err = %err,
                "p9x"
            ),
        }
    }

    pub fn tcp_start(&self, dest: &str, stream_id: Option<u64>) {
        match stream_id {
            Some(stream_id) => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "tcp_start",
                dest = dest,
                stream_id,
                "p9x"
            ),
            None => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "tcp_start",
                dest = dest,
                "p9x"
            ),
        }
    }

    pub fn tcp_end(
        &self,
        dest: &str,
        tcp_c2s: u64,
        tcp_s2c: u64,
        err: Option<&str>,
        stream_id: Option<u64>,
    ) {
        match (err, stream_id) {
            (Some(err), Some(stream_id)) => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "tcp_end",
                dest = dest,
                tcp_c2s,
                tcp_s2c,
                stream_id,
                err = %err,
                "p9x"
            ),
            (Some(err), None) => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "tcp_end",
                dest = dest,
                tcp_c2s,
                tcp_s2c,
                err = %err,
                "p9x"
            ),
            (None, Some(stream_id)) => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "tcp_end",
                dest = dest,
                tcp_c2s,
                tcp_s2c,
                stream_id,
                "p9x"
            ),
            (None, None) => tracing::debug!(
                side = "hy",
                conn_seq = self.conn_seq,
                remote = %self.remote,
                event = "tcp_end",
                dest = dest,
                tcp_c2s,
                tcp_s2c,
                "p9x"
            ),
        }
    }
}

/// Bidirectional TCP copy counters. `c2s` is client→target; `s2c` is target→client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpByteCounts {
    pub c2s: u64,
    pub s2c: u64,
}

impl TcpByteCounts {
    /// Initial leftover after the 0x401 request plus hook putback, both client→target.
    pub fn add_initial_c2s(&mut self, leftover: &[u8], hook_putback: &[u8]) {
        self.c2s += leftover.len() as u64 + hook_putback.len() as u64;
    }

    pub fn add_c2s(&mut self, n: u64) {
        self.c2s += n;
    }

    pub fn add_s2c(&mut self, n: u64) {
        self.s2c += n;
    }
}

/// Best-effort numeric close code from a displayed QUIC/H3 error.
pub fn parse_close_code(s: &str) -> Option<u64> {
    for needle in [
        "ApplicationClose: 0x",
        "ApplicationClosed: 0x",
        "application error 0x",
        "error 0x",
        "code 0x",
        "0x",
    ] {
        if let Some(idx) = s.find(needle) {
            let rest = &s[idx + needle.len()..];
            let hex: String = rest
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if !hex.is_empty() {
                if let Ok(v) = u64::from_str_radix(&hex, 16) {
                    return Some(v);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_seq_is_monotonic() {
        let a = alloc_conn_seq();
        let b = alloc_conn_seq();
        let c = alloc_conn_seq();
        assert!(b > a);
        assert!(c > b);
        assert_eq!(c - a, 2);
    }

    #[test]
    fn tcp_byte_counts_include_putback_in_c2s() {
        let mut counts = TcpByteCounts::default();
        counts.add_initial_c2s(b"left", b"hook");
        counts.add_c2s(10);
        counts.add_s2c(7);
        assert_eq!(counts.c2s, 4 + 4 + 10);
        assert_eq!(counts.s2c, 7);

        let mut only_leftover = TcpByteCounts::default();
        only_leftover.add_initial_c2s(b"abc", b"");
        assert_eq!(only_leftover.c2s, 3);
        assert_eq!(only_leftover.s2c, 0);

        let mut only_putback = TcpByteCounts::default();
        only_putback.add_initial_c2s(b"", b"xy");
        assert_eq!(only_putback.c2s, 2);
    }

    #[test]
    fn parse_close_code_from_application_close() {
        assert_eq!(parse_close_code("ApplicationClose: 0x0"), Some(0));
        assert_eq!(parse_close_code("ApplicationClose: 0x101"), Some(0x101));
        assert_eq!(
            parse_close_code("Remote error: ApplicationClose: H3_NO_ERROR"),
            None
        );
        assert_eq!(parse_close_code("ConnectionClosed: 0x1c"), Some(0x1c));
    }

    #[test]
    fn p9x_schema_and_propagation() {
        let impl_src = include_str!("server/impl.rs");
        let auth_src = include_str!("transport/h3_auth.rs");
        let uni_src = include_str!("transport/h3_uni.rs");
        let udp_src = include_str!("server/udp.rs");
        let cargo = include_str!("../../../Cargo.toml");

        assert!(
            cargo.contains("version = \"0.0.2\""),
            "P9.X must not bump version"
        );

        for src in [impl_src, auth_src, uni_src] {
            assert!(src.contains("side = \"hy\""));
            assert!(src.contains("\"p9x\"") || src.contains("crate::p9x"));
        }

        assert!(impl_src.contains("alloc_conn_seq"));
        assert!(impl_src.contains("event = \"conn_accept\"") || impl_src.contains(".conn_accept()"));
        assert!(impl_src.contains("handle_conn(conn, cfg, p9x)"));
        assert!(impl_src.contains("server_authenticate("));
        assert!(impl_src.contains("p9x"));
        assert!(
            impl_src.contains(".close_local(") && impl_src.contains("conn.close("),
            "close_local must precede local conn.close"
        );
        let close_kick = impl_src
            .find("CLOSE_EXCESSIVE_LOAD")
            .expect("kicked close");
        let close_local_at = impl_src[..close_kick + 80]
            .rfind("close_local")
            .expect("close_local near kicked close");
        let conn_close_at = impl_src[close_local_at..]
            .find("conn.close(")
            .expect("conn.close after close_local");
        assert!(
            conn_close_at > 0,
            "close_local must be logged before conn.close"
        );

        assert!(auth_src.contains("p9x: P9xConn") || auth_src.contains("p9x: crate::p9x::P9xConn"));
        assert!(auth_src.contains("with_tcp_tx_authed"));
        assert!(auth_src.contains(".auth_233()"));
        assert!(auth_src.contains("server_handle_authed_http"));

        assert!(uni_src.contains("p9x: P9xConn"));
        assert!(uni_src.contains(".uni("));
        assert!(uni_src.contains(".bidi_first("));
        assert!(
            uni_src.contains("event = \"uni\"") || uni_src.contains("self.p9x.uni")
        );

        assert!(udp_src.contains("p9x: crate::p9x::P9xConn") || udp_src.contains("p9x: P9xConn"));
        assert!(udp_src.contains("close_local"));

        for ev in [
            "conn_accept",
            "uni",
            "bidi_first",
            "auth_233",
            "auth_233_fin",
            "http_req",
            "settings",
            "close_local",
            "close_remote",
            "tcp_start",
            "tcp_end",
        ] {
            let needle = format!("event = \"{ev}\"");
            assert!(
                impl_src.contains(&needle)
                    || auth_src.contains(&needle)
                    || uni_src.contains(&needle)
                    || include_str!("p9x.rs").contains(&needle),
                "missing event {ev}"
            );
        }

        for field in [
            "stream_id",
            "stream_type",
            "first_varint",
            "duplicate",
            "close_initiator",
            "close_code",
            "tcp_c2s",
            "tcp_s2c",
            "dest",
            "err",
            "method",
            "authority",
            "path",
            "extended_connect",
            "max_field",
            "grease",
        ] {
            assert!(
                include_str!("p9x.rs").contains(field),
                "schema field {field}"
            );
        }

        assert!(auth_src.contains(".http_req("));
        assert!(auth_src.contains(".auth_233_fin()"));
        let build_at = auth_src.find(".build(").expect("builder.build");
        let settings_log_at = auth_src.find(".settings()").expect(".settings() after build");
        assert!(
            build_at < settings_log_at,
            "p9x settings event must be logged after builder.build"
        );
        assert!(
            auth_src.contains("h3::server::builder()"),
            "server auth path must use h3::server::builder()"
        );
        assert!(
            !auth_src.contains("h3::server::Connection::new"),
            "server auth path must not use Connection::new"
        );
        assert!(
            auth_src.contains("enable_extended_connect(true)"),
            "SETTINGS 0x8 ExtendedConnect = 1"
        );
        assert!(
            auth_src.contains("max_field_section_size(1 << 20)"),
            "MaxFieldSectionSize = 1<<20"
        );
        assert!(
            auth_src.contains("send_grease(false)"),
            "no grease setting / no grease uni"
        );
        assert!(
            !auth_src.contains("enable_webtransport") && !auth_src.contains("enable_datagram"),
            "must not enable webtransport / datagram"
        );
        let p9x_src = include_str!("p9x.rs");
        let settings_at = p9x_src.find("pub fn settings").expect("P9xConn::settings");
        let settings_fn = &p9x_src[settings_at..settings_at + 500];
        assert!(settings_fn.contains("event = \"settings\""));
        assert!(settings_fn.contains("extended_connect = 1"));
        assert!(settings_fn.contains("max_field = 1048576"));
        assert!(settings_fn.contains("grease = 0"));
        let prod = &p9x_src[..p9x_src.find("#[cfg(test)]").unwrap_or(p9x_src.len())];
        assert!(
            prod.contains("tracing::debug!") && !prod.contains("tracing::info!"),
            "p9x events must be tracing::debug, not tracing::info"
        );
    }

    #[test]
    fn p9i_later_http_logs_method_path_auth_and_masq() {
        let auth_src = include_str!("transport/h3_auth.rs");
        let start = auth_src
            .find("pub async fn server_handle_authed_http")
            .expect("server_handle_authed_http");
        let rest = &auth_src[start + 1..];
        let end = rest
            .find("\npub ")
            .or_else(|| rest.find("\nfn "))
            .map(|i| start + 1 + i)
            .unwrap_or(auth_src.len());
        let fn_src = &auth_src[start..end];

        let http_req_at = fn_src.find(".http_req(").expect("later HTTP logs http_req");
        assert!(
            fn_src.contains("http_req(method,") || fn_src.contains("http_req(method, "),
            "http_req must pass :method"
        );
        assert!(
            fn_src.contains("path") && (fn_src.contains("&host") || fn_src.contains("authority")),
            "http_req must pass :authority and :path"
        );

        let auth_ok_at = fn_src.find("send_auth_ok").expect("later /auth 233");
        let masq_at = fn_src.find("send_masq").expect("later non-/auth masq");
        assert!(
            http_req_at < auth_ok_at,
            "http_req before send_auth_ok (later /auth)"
        );
        assert!(
            http_req_at < masq_at,
            "http_req before send_masq (later non-/auth)"
        );
        assert!(
            fn_src.contains("is_hysteria_auth_request"),
            "later HTTP must distinguish /auth vs masq"
        );

        let first_start = auth_src
            .find("pub async fn server_handle_auth_request")
            .expect("server_handle_auth_request");
        let first_rest = &auth_src[first_start + 1..];
        let first_end = first_rest
            .find("\nasync fn send_auth_ok")
            .or_else(|| first_rest.find("\npub async fn "))
            .map(|i| first_start + 1 + i)
            .unwrap_or(auth_src.len());
        let first_fn = &auth_src[first_start..first_end];
        assert!(
            first_fn.contains(".http_req("),
            "first HTTP must log http_req (POST /auth visible)"
        );
        let first_req_at = first_fn.find(".http_req(").unwrap();
        let first_ok_at = first_fn.find("send_auth_ok").expect("first send_auth_ok");
        let first_masq_at = first_fn.find("send_masq").expect("first masq");
        assert!(first_req_at < first_ok_at && first_req_at < first_masq_at);
    }

    #[test]
    fn p9i_first_233_fin_no_goaway_h3_kept() {
        let auth_src = include_str!("transport/h3_auth.rs");
        let impl_src = include_str!("server/impl.rs");

        let send_start = auth_src.find("async fn send_auth_ok").expect("send_auth_ok");
        let send_rest = &auth_src[send_start..];
        let send_end = send_rest
            .find("\nasync fn send_masq")
            .unwrap_or(send_rest.len());
        let send_fn = &send_rest[..send_end];
        let finish_at = send_fn.find(".finish()").expect("finish() of 233");
        let fin_log_at = send_fn
            .find(".auth_233_fin()")
            .expect("auth_233_fin after finish");
        assert!(
            finish_at < fin_log_at,
            "auth_233_fin only after finish() returned (call is after finish await)"
        );
        assert!(send_fn.contains("send_response"));
        assert!(
            auth_src.contains(".auth_233()"),
            "keep existing auth_233 after successful 233"
        );

        let start = impl_src.find("async fn handle_conn").expect("handle_conn");
        let rest = &impl_src[start + 1..];
        let end = rest
            .find("\nfn spawn_tcp")
            .map(|i| start + 1 + i)
            .unwrap_or(impl_src.len());
        let fn_src = &impl_src[start..end];
        let auth_at = fn_src
            .find("server_authenticate")
            .expect("server_authenticate");
        let after_auth_call = &fn_src[auth_at..];
        let some_at = after_auth_call
            .find("let Some((auth_id")
            .expect("successful 233 branch");
        // Body after the unauthenticated `else { drop(h3_keep); return }`.
        let authed = &after_auth_call[some_at..];
        let else_end = authed.find("apply_cc_mode").expect("after auth Some");
        let after_first_233 = &authed[else_end..];
        assert!(
            after_first_233.contains("h3_keep.accept()")
                || after_first_233.contains("h3.accept()"),
            "after first 233 must keep polling the live h3::server::Connection"
        );
        assert!(
            !after_first_233.contains("drop(h3_keep)")
                && !after_first_233.contains("drop(h3_conn)"),
            "must not Drop h3::server::Connection after first 233"
        );
        assert!(
            !after_first_233.contains("h3_keep.shutdown")
                && !after_first_233.contains("h3.shutdown")
                && !after_first_233.contains(".shutdown("),
            "must not call shutdown() on the h3 server conn after first 233"
        );
        let goaway = after_first_233.contains("GOAWAY")
            || after_first_233.contains("GoAway")
            || after_first_233.contains("Goaway")
            || after_first_233.contains("goaway");
        assert!(!goaway, "must not send GOAWAY after first 233");

        assert!(
            !auth_src.contains(".shutdown(") && !auth_src.contains("GOAWAY"),
            "h3_auth must not shutdown / GOAWAY after 233"
        );
    }
}
