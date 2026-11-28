//! Tor mode through a local SOCKS5 proxy: Orbot on Android (`127.0.0.1:9050`),
//! or any Tor daemon. (On iOS, Orbot runs as a system VPN, so apps need nothing.)
//!
//! This replaced the embedded Arti client, whose dependency tree carried
//! unfixed advisories (rsa / Marvin, paste, bincode, crypto-bigint 0.5) and ~10 MB.
//!
//! * Hostnames are sent to the proxy (`ATYP = domain`): the Tor exit resolves
//!   them, so no DNS query leaves the device in the clear.
//! * Every chat uses fresh random SOCKS credentials. Tor's `IsolateSOCKSAuth`
//!   (on by default, also in Orbot) then puts each chat on its own circuit,
//!   so two chats can't be linked at an exit relay.
//! * Only loopback proxies are accepted: a remote "proxy" would see everything.
use crate::net::{io_err, BoxStream, NetError};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct Socks {
    proxy: SocketAddr,
    user: String,
    pass: String,
}

impl Socks {
    /// `proxy` like `127.0.0.1:9050`. New random credentials = new circuit.
    pub fn isolated(proxy: &str) -> Result<Self, NetError> {
        let proxy: SocketAddr = proxy
            .parse()
            .map_err(|_| NetError::Io("SOCKS proxy must be ip:port".into()))?;
        if !proxy.ip().is_loopback() {
            return Err(NetError::Io(
                "SOCKS proxy must be on this device (loopback)".into(),
            ));
        }
        Ok(Self {
            proxy,
            user: random_token(),
            pass: random_token(),
        })
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<BoxStream, NetError> {
        let mut s = TcpStream::connect(self.proxy).await.map_err(io_err)?;
        handshake(&mut s, &self.user, &self.pass, host, port).await?;
        Ok(Box::new(s))
    }
}

fn random_token() -> String {
    use rand::Rng;
    let b: [u8; 12] = rand::thread_rng().gen();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn socks_err(what: &str) -> NetError {
    NetError::Io(format!("SOCKS5 proxy: {what}"))
}

/// RFC 1928 CONNECT by domain name, with RFC 1929 username/password auth
/// (falling back to no auth if the proxy doesn't do auth: still works, just
/// without per-chat circuit isolation).
pub(crate) async fn handshake<S>(
    s: &mut S,
    user: &str,
    pass: &str,
    host: &str,
    port: u16,
) -> Result<(), NetError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if host.is_empty() || host.len() > 255 || user.len() > 255 || pass.len() > 255 {
        return Err(socks_err("name too long"));
    }
    s.write_all(&[5, 2, 2, 0]).await.map_err(io_err)?;
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.map_err(io_err)?;
    match m {
        [5, 2] => {
            let mut a = vec![1, user.len() as u8];
            a.extend_from_slice(user.as_bytes());
            a.push(pass.len() as u8);
            a.extend_from_slice(pass.as_bytes());
            s.write_all(&a).await.map_err(io_err)?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await.map_err(io_err)?;
            if r[1] != 0 {
                return Err(socks_err("authentication refused"));
            }
        }
        [5, 0] => {}
        _ => return Err(socks_err("no acceptable auth method")),
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(io_err)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != 5 {
        return Err(socks_err("bad reply"));
    }
    if head[1] != 0 {
        return Err(socks_err(match head[1] {
            1 => "general failure",
            2 => "not allowed by ruleset",
            3 => "network unreachable",
            4 => "host unreachable (is Tor connected?)",
            5 => "connection refused",
            6 => "TTL expired",
            _ => "connect failed",
        }));
    }
    // Skip BND.ADDR + BND.PORT.
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(io_err)?;
            l[0] as usize
        }
        _ => return Err(socks_err("bad address type")),
    } + 2;
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await.map_err(io_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A minimal SOCKS5 server: checks the auth and the domain request, then
    /// echoes. Returns what it saw.
    async fn fake_proxy(l: TcpListener, offer_auth: bool) -> (String, String, String, u16) {
        let (mut s, _) = l.accept().await.unwrap();
        let mut h = [0u8; 4];
        s.read_exact(&mut h).await.unwrap();
        assert_eq!(h, [5, 2, 2, 0]);
        let (mut user, mut pass) = (String::new(), String::new());
        if offer_auth {
            s.write_all(&[5, 2]).await.unwrap();
            let mut v = [0u8; 2];
            s.read_exact(&mut v).await.unwrap();
            let mut u = vec![0u8; v[1] as usize];
            s.read_exact(&mut u).await.unwrap();
            let mut pl = [0u8; 1];
            s.read_exact(&mut pl).await.unwrap();
            let mut p = vec![0u8; pl[0] as usize];
            s.read_exact(&mut p).await.unwrap();
            (user, pass) = (String::from_utf8(u).unwrap(), String::from_utf8(p).unwrap());
            s.write_all(&[1, 0]).await.unwrap();
        } else {
            s.write_all(&[5, 0]).await.unwrap();
        }
        let mut r = [0u8; 5];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(&r[..4], &[5, 1, 0, 3], "CONNECT by domain name");
        let mut host = vec![0u8; r[4] as usize];
        s.read_exact(&mut host).await.unwrap();
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await.unwrap();
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
        (
            String::from_utf8(host).unwrap(),
            user,
            pass,
            u16::from_be_bytes(port),
        )
    }

    #[tokio::test]
    async fn connects_by_name_with_isolating_credentials() {
        for offer_auth in [true, false] {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap().to_string();
            let server = tokio::spawn(fake_proxy(l, offer_auth));
            let socks = Socks::isolated(&addr).unwrap();
            let mut s = socks.connect("relay.example.com", 443).await.unwrap();
            s.write_all(b"ping").await.unwrap();
            let mut back = [0u8; 4];
            s.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"ping");
            let (host, user, pass, port) = server.await.unwrap();
            assert_eq!((host.as_str(), port), ("relay.example.com", 443));
            if offer_auth {
                assert_eq!(
                    (user.as_str(), pass.as_str()),
                    (socks.user.as_str(), socks.pass.as_str())
                );
            }
        }
        let a = Socks::isolated("127.0.0.1:9050").unwrap();
        let b = Socks::isolated("127.0.0.1:9050").unwrap();
        assert_ne!(a.user, b.user, "each chat gets its own circuit");
    }

    #[tokio::test]
    async fn refuses_remote_proxies_and_reports_failures() {
        assert!(Socks::isolated("10.0.0.1:9050").is_err());
        assert!(Socks::isolated("not-an-addr").is_err());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut h = [0u8; 4];
            s.read_exact(&mut h).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut r = vec![0u8; 5 + 9 + 2];
            s.read_exact(&mut r).await.unwrap();
            s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let err = Socks::isolated(&addr)
            .unwrap()
            .connect("gone.test", 80)
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("host unreachable"), "{err}");
    }
}
