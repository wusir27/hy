use super::{
    varint::{varint_len, varint_put, varint_read},
    FRAME_TYPE_TCP_REQUEST, MAX_ADDRESS_LENGTH, MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH,
};
use crate::error::Error;
use crate::protocol::padding::{TCP_REQUEST_PADDING, TCP_RESPONSE_PADDING};
use std::io::{self, Read, Write};

/// Read a TCP request **after** the 0x401 frame type has been consumed
/// (matches Go `ReadTCPRequest`).
pub fn read_tcp_request<R: Read>(r: &mut R) -> Result<String, Error> {
    let addr_len = varint_read(r).map_err(io_to_err)?;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return Err(Error::protocol("invalid address length"));
    }
    let mut addr = vec![0u8; addr_len as usize];
    r.read_exact(&mut addr).map_err(io_to_err)?;
    let padding_len = varint_read(r).map_err(io_to_err)?;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(Error::protocol("invalid padding length"));
    }
    if padding_len > 0 {
        let mut discard = vec![0u8; padding_len as usize];
        r.read_exact(&mut discard).map_err(io_to_err)?;
    }
    Ok(String::from_utf8_lossy(&addr).into_owned())
}

/// Write a full TCP request including the 0x401 frame type.
pub fn write_tcp_request<W: Write>(w: &mut W, addr: &str) -> Result<(), Error> {
    let padding = TCP_REQUEST_PADDING.generate();
    let addr_len = addr.len();
    let padding_len = padding.len();
    let sz = varint_len(FRAME_TYPE_TCP_REQUEST)
        + varint_len(addr_len as u64)
        + addr_len
        + varint_len(padding_len as u64)
        + padding_len;
    let mut buf = vec![0u8; sz];
    let mut i = varint_put(&mut buf, FRAME_TYPE_TCP_REQUEST);
    i += varint_put(&mut buf[i..], addr_len as u64);
    buf[i..i + addr_len].copy_from_slice(addr.as_bytes());
    i += addr_len;
    i += varint_put(&mut buf[i..], padding_len as u64);
    buf[i..i + padding_len].copy_from_slice(padding.as_bytes());
    w.write_all(&buf).map_err(io_to_err)
}

/// Returns `(ok, message)`.
pub fn read_tcp_response<R: Read>(r: &mut R) -> Result<(bool, String), Error> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status).map_err(io_to_err)?;
    let msg_len = varint_read(r).map_err(io_to_err)?;
    if msg_len > MAX_MESSAGE_LENGTH {
        return Err(Error::protocol("invalid message length"));
    }
    let mut msg = Vec::new();
    if msg_len > 0 {
        msg.resize(msg_len as usize, 0);
        r.read_exact(&mut msg).map_err(io_to_err)?;
    }
    let padding_len = varint_read(r).map_err(io_to_err)?;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(Error::protocol("invalid padding length"));
    }
    if padding_len > 0 {
        let mut discard = vec![0u8; padding_len as usize];
        r.read_exact(&mut discard).map_err(io_to_err)?;
    }
    Ok((status[0] == 0, String::from_utf8_lossy(&msg).into_owned()))
}

pub fn write_tcp_response<W: Write>(w: &mut W, ok: bool, msg: &str) -> Result<(), Error> {
    let padding = TCP_RESPONSE_PADDING.generate();
    let msg_len = msg.len();
    let padding_len = padding.len();
    let sz = 1 + varint_len(msg_len as u64) + msg_len + varint_len(padding_len as u64) + padding_len;
    let mut buf = vec![0u8; sz];
    buf[0] = if ok { 0 } else { 1 };
    let mut i = 1;
    i += varint_put(&mut buf[i..], msg_len as u64);
    buf[i..i + msg_len].copy_from_slice(msg.as_bytes());
    i += msg_len;
    i += varint_put(&mut buf[i..], padding_len as u64);
    buf[i..i + padding_len].copy_from_slice(padding.as_bytes());
    w.write_all(&buf).map_err(io_to_err)
}


/// Full TCP request including the 0x401 frame type.
pub fn write_tcp_request_bytes(addr: &str) -> Vec<u8> {
    let mut w = Vec::new();
    write_tcp_request(&mut w, addr).expect("write to vec cannot fail");
    w
}

/// Read a TCP request **after** 0x401. Returns `(addr, bytes_consumed)`.
pub fn read_tcp_request_bytes(buf: &[u8]) -> Result<(String, usize), Error> {
    let mut r = io::Cursor::new(buf);
    let addr = read_tcp_request(&mut r)?;
    Ok((addr, r.position() as usize))
}

pub fn write_tcp_response_bytes(ok: bool, msg: &str) -> Vec<u8> {
    let mut w = Vec::new();
    write_tcp_response(&mut w, ok, msg).expect("write to vec cannot fail");
    w
}

pub fn read_tcp_response_bytes(buf: &[u8]) -> Result<(bool, String, usize), Error> {
    let mut r = io::Cursor::new(buf);
    let (ok, msg) = read_tcp_response(&mut r)?;
    Ok((ok, msg, r.position() as usize))
}

fn io_to_err(e: io::Error) -> Error {
    Error::protocol(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_tcp_request_vectors() {
        let cases: &[(&[u8], Result<&str, ()>)] = &[
            (b"\x0egoogle.com:443\x00", Ok("google.com:443")),
            (b"\x0bholy.cc:443\x02gg", Ok("holy.cc:443")),
            (b"\x0bhoho", Err(())),
            (b"\x0bholy.cc:443\x05x", Err(())),
        ];
        for (data, want) in cases {
            let mut r = Cursor::new(*data);
            let got = read_tcp_request(&mut r);
            match want {
                Ok(addr) => assert_eq!(got.unwrap(), *addr),
                Err(()) => assert!(got.is_err()),
            }
        }
    }

    #[test]
    fn read_tcp_request_rejects_zero_and_huge_addr() {
        let mut r = Cursor::new([0u8]); // addr_len = 0
        assert!(matches!(
            read_tcp_request(&mut r),
            Err(Error::Protocol(m)) if m.contains("address")
        ));
        // 2-byte varint 2049 (0x0801 | 0x4000 = 0x4801)
        let mut huge = vec![0x48, 0x01];
        huge.extend(std::iter::repeat(b'a').take(2049));
        huge.push(0);
        let mut r = Cursor::new(huge);
        assert!(matches!(
            read_tcp_request(&mut r),
            Err(Error::Protocol(m)) if m.contains("address")
        ));
    }

    #[test]
    fn write_tcp_request_prefix() {
        let cases = [
            ("google.com:443", b"\x44\x01\x0egoogle.com:443".as_slice()),
            (
                "client-api.arkoselabs.com:8080",
                b"\x44\x01\x1eclient-api.arkoselabs.com:8080".as_slice(),
            ),
            ("", b"\x44\x01\x00".as_slice()),
        ];
        for (addr, prefix) in cases {
            let mut w = Vec::new();
            write_tcp_request(&mut w, addr).unwrap();
            assert!(w.starts_with(prefix), "{addr}: {w:?}");
            assert!(w.len() > prefix.len());
        }
    }

    #[test]
    fn read_tcp_response_vectors() {
        let cases: &[(&[u8], Result<(bool, &str), ()>)] = &[
            (b"\x00\x0bhello world\x00", Ok((true, "hello world"))),
            (b"\x01\x06stop!!\x05xxxxx", Ok((false, "stop!!"))),
            (b"\x01\x00\x05xxxxx", Ok((false, ""))),
            (b"\x00\x0bhoho", Err(())),
            (b"\x01\x05jesus\x05x", Err(())),
        ];
        for (data, want) in cases {
            let mut r = Cursor::new(*data);
            let got = read_tcp_response(&mut r);
            match want {
                Ok(v) => assert_eq!(got.unwrap(), (v.0, v.1.to_string())),
                Err(()) => assert!(got.is_err()),
            }
        }
    }

    #[test]
    fn write_tcp_response_prefix() {
        let cases: &[((bool, &str), &[u8])] = &[
            ((true, "hello world"), b"\x00\x0bhello world"),
            ((false, "stop!!"), b"\x01\x06stop!!"),
            ((true, ""), b"\x00\x00"),
        ];
        for ((ok, msg), prefix) in cases {
            let mut w = Vec::new();
            write_tcp_response(&mut w, *ok, msg).unwrap();
            assert!(w.starts_with(prefix), "{msg}: {w:?}");
            assert!(w.len() > prefix.len());
        }
    }


    #[test]
    fn bytes_api_same_vectors_as_io() {
        for addr in ["google.com:443", "holy.cc:443"] {
            let raw = write_tcp_request_bytes(addr);
            assert!(raw.starts_with(b"\x44\x01"), "{addr}");
            let mut cur = Cursor::new(&raw[2..]);
            let via_io = read_tcp_request(&mut cur).unwrap();
            let (via_bytes, n) = read_tcp_request_bytes(&raw[2..]).unwrap();
            assert_eq!(via_io, via_bytes);
            assert_eq!(n, raw.len() - 2);
            assert_eq!(via_bytes, addr);
        }
        let empty = write_tcp_request_bytes("");
        assert!(empty.starts_with(b"\x44\x01\x00"));
        for (ok, msg) in [(true, "hello world"), (false, "stop!!"), (true, "")] {
            let raw = write_tcp_response_bytes(ok, msg);
            let mut cur = Cursor::new(&raw[..]);
            let (ok_io, msg_io) = read_tcp_response(&mut cur).unwrap();
            let (ok_b, msg_b, n) = read_tcp_response_bytes(&raw).unwrap();
            assert_eq!((ok_io, msg_io.as_str()), (ok, msg));
            assert_eq!((ok_b, msg_b.as_str()), (ok, msg));
            assert_eq!(n, raw.len());
        }
        assert!(read_tcp_request_bytes(b"\x0bhoho").is_err());
        assert!(read_tcp_response_bytes(b"\x00\x0bhoho").is_err());
    }
}
