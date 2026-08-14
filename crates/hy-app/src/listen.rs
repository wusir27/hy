use hy_core::Error;
use std::net::SocketAddr;

pub fn parse_listen(s: &str, field: &'static str) -> Result<SocketAddr, Error> {
    let t = s.trim();
    if t.contains(',') {
        return Err(Error::config(field, "port hop not implemented"));
    }
    if let Ok(sa) = t.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Some(port) = t.strip_prefix(':') {
        let p: u16 = port.parse().map_err(|_| Error::config(field, format!("bad listen {s}")))?;
        return Ok(SocketAddr::from(([0, 0, 0, 0], p)));
    }
    if let Ok(p) = t.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], p)));
    }
    Err(Error::config(field, format!("bad listen {s}")))
}

pub fn parse_server(s: &str) -> Result<SocketAddr, Error> {
    let t = s.trim();
    if t.contains(',') {
        return Err(Error::config("Server", "port hop not implemented"));
    }
    t.parse()
        .map_err(|_| Error::config("ServerAddr", format!("bad server {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colon_port() {
        assert_eq!(parse_listen(":1080", "Listen").unwrap().port(), 1080);
    }

    #[test]
    fn hop_rejected() {
        assert!(parse_server("1.1.1.1:443,1.1.1.1:444").is_err());
    }
}
