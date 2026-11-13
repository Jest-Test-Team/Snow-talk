//! Minimal HTTP/1.1 client (one request per connection) over a [`Dialer`].
//! Only used for a few small requests (PoW challenge, DoH, remote config), so a full HTTP stack
//! isn't worth its size, and this way every byte goes through the same dialer.
use crate::net::{io_err, Dialer, Endpoint, NetError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Large enough for the sponsor catalog (`snow_config::MAX_CATALOG`).
const MAX_RESPONSE: u64 = 320 * 1024;

pub async fn request(
    dialer: &Dialer,
    ep: &Endpoint,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, Vec<u8>), NetError> {
    let mut s = ep.connect(dialer).await?;
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nhost: {}\r\nuser-agent: snowtalk\r\nconnection: close\r\ncontent-length: {}\r\n",
        ep.host,
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.map_err(io_err)?;
    s.write_all(body).await.map_err(io_err)?;
    s.flush().await.map_err(io_err)?;
    let mut raw = Vec::new();
    // Servers may close TLS without close_notify; keep what we got.
    let _ = (&mut s).take(MAX_RESPONSE).read_to_end(&mut raw).await;
    parse_response(&raw)
}

pub fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), NetError> {
    let bad = || NetError::Io("malformed HTTP response".into());
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(bad)?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| bad())?;
    let rest = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(bad)?;
    let mut chunked = false;
    let mut length = None;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
            chunked = true;
        } else if k == "content-length" {
            length = v.parse::<usize>().ok();
        }
    }
    let body = if chunked {
        dechunk(rest).ok_or_else(bad)?
    } else {
        let n = length.unwrap_or(rest.len());
        rest.get(..n).ok_or_else(bad)?.to_vec()
    };
    Ok((status, body))
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&b[..eol])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..size)?);
        b = b.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_and_chunked() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA";
        assert_eq!(parse_response(r).unwrap(), (200, b"abc".to_vec()));
        let r = b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_response(r).unwrap(), (404, b"abcde".to_vec()));
        assert!(parse_response(b"garbage").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort").is_err());
    }
}
