//! HTTP/3 auth header constants and (de)serialization.

pub const URL_HOST: &str = "hysteria";
pub const URL_PATH: &str = "/auth";

pub const REQUEST_HEADER_AUTH: &str = "Hysteria-Auth";
pub const RESPONSE_HEADER_UDP_ENABLED: &str = "Hysteria-UDP";
pub const COMMON_HEADER_CC_RX: &str = "Hysteria-CC-RX";
pub const COMMON_HEADER_PADDING: &str = "Hysteria-Padding";

pub const STATUS_AUTH_OK: u16 = 233;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub auth: String,
    /// 0 = unknown; client asks the server to use bandwidth detection.
    pub rx: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub udp_enabled: bool,
    /// 0 = unlimited (when `rx_auto` is false).
    pub rx: u64,
    /// Server asks the client to use bandwidth detection (`Hysteria-CC-RX: auto`).
    pub rx_auto: bool,
}

/// Case-insensitive header lookup (HTTP/3 headers are lowercased on the wire,
/// but we accept any casing the way Go's `http.Header.Get` does).
fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

pub fn auth_request_from_headers(headers: &[(String, String)]) -> AuthRequest {
    let rx = header_get(headers, COMMON_HEADER_CC_RX)
        .parse::<u64>()
        .unwrap_or(0);
    AuthRequest {
        auth: header_get(headers, REQUEST_HEADER_AUTH).to_string(),
        rx,
    }
}

pub fn auth_request_to_headers(req: &AuthRequest) -> Vec<(String, String)> {
    vec![
        (REQUEST_HEADER_AUTH.to_string(), req.auth.clone()),
        (COMMON_HEADER_CC_RX.to_string(), req.rx.to_string()),
        (
            COMMON_HEADER_PADDING.to_string(),
            super::padding::AUTH_REQUEST_PADDING.generate(),
        ),
    ]
}

pub fn auth_response_from_headers(headers: &[(String, String)]) -> AuthResponse {
    let udp = header_get(headers, RESPONSE_HEADER_UDP_ENABLED)
        .parse::<bool>()
        .unwrap_or(false);
    let rx_str = header_get(headers, COMMON_HEADER_CC_RX);
    if rx_str == "auto" {
        AuthResponse {
            udp_enabled: udp,
            rx: 0,
            rx_auto: true,
        }
    } else {
        AuthResponse {
            udp_enabled: udp,
            rx: rx_str.parse::<u64>().unwrap_or(0),
            rx_auto: false,
        }
    }
}

pub fn auth_response_to_headers(resp: &AuthResponse) -> Vec<(String, String)> {
    let cc = if resp.rx_auto {
        "auto".to_string()
    } else {
        resp.rx.to_string()
    };
    vec![
        (
            RESPONSE_HEADER_UDP_ENABLED.to_string(),
            if resp.udp_enabled { "true" } else { "false" }.to_string(),
        ),
        (COMMON_HEADER_CC_RX.to_string(), cc),
        (
            COMMON_HEADER_PADDING.to_string(),
            super::padding::AUTH_RESPONSE_PADDING.generate(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::padding::{is_padding_charset, AUTH_REQUEST_PADDING};

    #[test]
    fn request_roundtrip() {
        let req = AuthRequest {
            auth: "secret".into(),
            rx: 1_000_000,
        };
        let h = auth_request_to_headers(&req);
        let pad = h
            .iter()
            .find(|(k, _)| k == COMMON_HEADER_PADDING)
            .unwrap()
            .1
            .clone();
        assert!(pad.len() >= AUTH_REQUEST_PADDING.min && pad.len() < AUTH_REQUEST_PADDING.max);
        assert!(is_padding_charset(&pad));
        let parsed = auth_request_from_headers(&h);
        assert_eq!(parsed, req);
    }

    #[test]
    fn response_auto_and_numeric() {
        let auto = auth_response_from_headers(&[
            (RESPONSE_HEADER_UDP_ENABLED.into(), "true".into()),
            (COMMON_HEADER_CC_RX.into(), "auto".into()),
        ]);
        assert!(auto.rx_auto && auto.udp_enabled && auto.rx == 0);

        let num = auth_response_from_headers(&[
            (RESPONSE_HEADER_UDP_ENABLED.into(), "false".into()),
            (COMMON_HEADER_CC_RX.into(), "42".into()),
        ]);
        assert!(!num.rx_auto && !num.udp_enabled && num.rx == 42);

        let h = auth_response_to_headers(&AuthResponse {
            udp_enabled: true,
            rx: 0,
            rx_auto: true,
        });
        assert_eq!(
            h.iter().find(|(k, _)| k == COMMON_HEADER_CC_RX).unwrap().1,
            "auto"
        );
    }

    #[test]
    fn constants() {
        assert_eq!(URL_HOST, "hysteria");
        assert_eq!(URL_PATH, "/auth");
        assert_eq!(STATUS_AUTH_OK, 233);
    }
}
