//! TLS ClientHello SNI extraction (not MITM: no cert, no decrypt).

/// Extract SNI from a TLS handshake record (content type 0x16).
///
/// `payload` is the first TCP payload. Truncated records, non-handshake
/// records, and ClientHellos without `server_name` yield `None`.
pub fn extract_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 {
        return None;
    }
    // TLS record: type(1) + version(2) + length(2) + fragment
    if payload[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let handshake = payload.get(5..5 + rec_len)?;
    extract_sni_from_handshake(handshake)
}

/// `data` is a TLS handshake message starting with type byte (0x01 = ClientHello).
fn extract_sni_from_handshake(data: &[u8]) -> Option<String> {
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }
    let hs_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
    let body = data.get(4..4 + hs_len)?;
    parse_client_hello_sni(body)
}

fn parse_client_hello_sni(body: &[u8]) -> Option<String> {
    // legacy_version(2) + random(32) + session_id + cipher_suites + compression + extensions
    if body.len() < 34 {
        return None;
    }
    let mut i = 34;
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    if body.len() < i + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes(body[i..i + 2].try_into().ok()?) as usize;
    i += 2 + cs_len;
    if body.len() < i + 1 {
        return None;
    }
    let comp_len = body[i] as usize;
    i += 1 + comp_len;
    if body.len() < i + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes(body[i..i + 2].try_into().ok()?) as usize;
    i += 2;
    let ext_end = std::cmp::min(i + ext_len, body.len());
    while i + 4 <= ext_end {
        let typ = u16::from_be_bytes(body[i..i + 2].try_into().ok()?);
        let len = u16::from_be_bytes(body[i + 2..i + 4].try_into().ok()?) as usize;
        i += 4;
        if i + len > ext_end {
            break;
        }
        if typ == 0 {
            return parse_sni_extension(&body[i..i + len]);
        }
        i += len;
    }
    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes(data[0..2].try_into().ok()?) as usize;
    let list = data.get(2..2 + list_len).unwrap_or(&data[2..]);
    let mut pos = 0;
    while pos + 3 <= list.len() {
        let name_type = list[pos];
        let name_len = u16::from_be_bytes(list[pos + 1..pos + 3].try_into().ok()?) as usize;
        pos += 3;
        if pos + name_len > list.len() {
            break;
        }
        if name_type == 0 {
            return std::str::from_utf8(&list[pos..pos + name_len])
                .ok()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
        }
        pos += name_len;
    }
    None
}

/// Build a minimal TLS 1.2 ClientHello record with `server_name` = `sni`.
pub fn client_hello_with_sni(sni: &str) -> Vec<u8> {
    client_hello(Some(sni))
}

/// Build a minimal TLS 1.2 ClientHello record with no SNI extension.
pub fn client_hello_without_sni() -> Vec<u8> {
    client_hello(None)
}

fn client_hello(sni: Option<&str>) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(sni) = sni {
        let sni_bytes = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let name_entry_len = 1 + 2 + sni_bytes.len();
        sni_ext.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        sni_ext.push(0); // host_name
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);

        extensions.extend_from_slice(&0u16.to_be_bytes()); // server_name
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id empty
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
    body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
    body.push(1); // compression methods len
    body.push(0); // null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len = body.len();
    handshake.push(((len >> 16) & 0xff) as u8);
    handshake.push(((len >> 8) & 0xff) as u8);
    handshake.push((len & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_fixture_extracts_example_org() {
        let hello = client_hello_with_sni("example.org");
        assert_eq!(extract_sni(&hello).as_deref(), Some("example.org"));
        // Keep Dest.ip elsewhere; parser returns host only.
        assert!(hello[0] == 0x16);
    }

    #[test]
    fn client_hello_without_sni_is_none() {
        let hello = client_hello_without_sni();
        assert!(extract_sni(&hello).is_none());
    }

    #[test]
    fn truncated_record_is_none() {
        let hello = client_hello_with_sni("example.org");
        assert!(hello.len() > 10);
        assert!(extract_sni(&hello[..5]).is_none());
        assert!(extract_sni(&hello[..10]).is_none());
        assert!(extract_sni(&[0x16, 0x03, 0x01]).is_none());
        assert!(extract_sni(&[]).is_none());
    }

    #[test]
    fn non_handshake_record_is_none() {
        // Application data, not handshake.
        let mut rec = vec![0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        rec.extend_from_slice(&[0u8; 8]);
        assert!(extract_sni(&rec).is_none());
    }
}
