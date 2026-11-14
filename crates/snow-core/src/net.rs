//! Transport. Every connection — DoH, the PoW fetch and the WebSockets — goes
//! through one [`Dialer`]: direct TCP, or Tor via the local SOCKS5 proxy in Tor
//! mode. That way no request accidentally bypasses Tor.
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use snow_proto::{decode_frame, encode_frame, ClientMsg, ServerMsg};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, Connector, MaybeTlsStream, WebSocketStream};

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("network: {0}")]
    Io(String),
    #[error("server sent a malformed frame")]
    BadFrame,
    #[error("connection closed")]
    Closed,
    #[error("server refused the connection (HTTP {0})")]
    Rejected(u16),
}

pub fn io_err(e: impl std::fmt::Display) -> NetError {
    NetError::Io(e.to_string())
}

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

/// How TCP connections are made.
#[derive(Clone)]
pub enum Dialer {
    Direct,
    Socks(crate::socks::Socks),
}

impl Dialer {
    pub fn is_proxied(&self) -> bool {
        !matches!(self, Dialer::Direct)
    }

    /// `addrs` (pre-resolved via DoH) are used when dialing directly. Over Tor the
    /// exit relay resolves `host` itself, so our DoH answer isn't needed.
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        addrs: &[SocketAddr],
    ) -> Result<BoxStream, NetError> {
        match self {
            Dialer::Direct if addrs.is_empty() => Ok(Box::new(
                TcpStream::connect((host, port)).await.map_err(io_err)?,
            )),
            Dialer::Direct => Ok(Box::new(TcpStream::connect(addrs).await.map_err(io_err)?)),
            Dialer::Socks(s) => s.connect(host, port).await,
        }
    }
}

/// One server we talk to.
#[derive(Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub addrs: Vec<SocketAddr>,
    /// `None` = plaintext (local development only).
    pub tls: Option<Arc<rustls::ClientConfig>>,
}

impl Endpoint {
    pub async fn connect(&self, dialer: &Dialer) -> Result<BoxStream, NetError> {
        let tcp = dialer.dial(&self.host, self.port, &self.addrs).await?;
        match &self.tls {
            None => Ok(tcp),
            Some(cfg) => {
                let name =
                    rustls::pki_types::ServerName::try_from(self.host.clone()).map_err(io_err)?;
                let tls = tokio_rustls::TlsConnector::from(cfg.clone())
                    .connect(name, tcp)
                    .await
                    .map_err(io_err)?;
                Ok(Box::new(tls))
            }
        }
    }
}

pub fn tls_config(pins: &[[u8; 32]], ech: Option<&[u8]>) -> Result<rustls::ClientConfig, NetError> {
    use rustls::client::{EchConfig, EchMode};
    let roots = Arc::new(rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    });
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone());
    let builder = match ech {
        Some(list) => {
            let cfg = EchConfig::new(
                rustls::pki_types::EchConfigListBytes::from(list.to_vec()),
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .map_err(|e| NetError::Io(format!("ECH config: {e}")))?;
            builder.with_ech(EchMode::Enable(cfg))
        }
        None => builder.with_safe_default_protocol_versions(),
    }
    .map_err(io_err)?;
    let mut cfg = if pins.is_empty() {
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(io_err)?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::pin::PinnedVerifier {
                inner,
                pins: pins.to_vec(),
            }))
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

fn is_local(host: &str) -> bool {
    host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[')
}

/// Connection setup for one chat.
///
/// For a real hostname, the address and ECH config come from DoH (see
/// [`crate::dns`]), so neither the OS resolver nor the TLS SNI reveals which
/// site we connect to. If no DoH resolver is reachable on a direct connection,
/// the system resolver is used instead (without ECH). Localhost / IP literals (development) skip DoH and ECH.
/// With `pins` empty, plain WebPKI validation is used (development only).
#[derive(Clone)]
pub struct Net {
    pub dialer: Dialer,
    pub relay: Endpoint,
    pub ech: bool,
}

impl Net {
    pub async fn new(base: &str, pins: &[String], dialer: Dialer) -> Result<Self, NetError> {
        let url = url::Url::parse(base).map_err(io_err)?;
        let host = url
            .host_str()
            .ok_or(NetError::Io("server URL has no host".into()))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let secure = url.scheme() == "https";
        let pins = crate::pin::parse_pins(pins);
        let resolved = if is_local(&host) {
            crate::dns::Resolved::default()
        } else {
            match crate::dns::resolve(&dialer, &host).await {
                Ok(r) => r,
                // Every DoH resolver is unreachable from this network. Rather
                // than not working at all, use the system resolver (no ECH: the
                // hostname becomes visible to the network). Never over Tor:
                // there the exit resolves, so DoH failing is a real error.
                Err(_) if !dialer.is_proxied() => crate::dns::Resolved::default(),
                Err(e) => return Err(e),
            }
        };
        let tls = secure
            .then(|| tls_config(&pins, resolved.ech.as_deref()))
            .transpose()?
            .map(Arc::new);
        let addrs = if dialer.is_proxied() {
            Vec::new()
        } else {
            resolved
                .addrs
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect()
        };
        Ok(Self {
            dialer,
            relay: Endpoint {
                host,
                port,
                addrs,
                tls,
            },
            ech: resolved.ech.is_some(),
        })
    }
}

pub async fn fetch_pow(net: &Net, bucket: u8) -> Result<Vec<u8>, NetError> {
    let b = bucket.to_string();
    let (status, body) = crate::http::request(
        &net.dialer,
        &net.relay,
        "GET",
        "/pow",
        &[("x-snow-bucket", &b)],
        &[],
    )
    .await?;
    if status != 200 {
        return Err(NetError::Io(format!("PoW fetch: HTTP {status}")));
    }
    Ok(body)
}

pub struct Ws(WebSocketStream<MaybeTlsStream<BoxStream>>);

impl Ws {
    /// Connect to `path` on the relay, passing `param` (`b.<bucket>` / `t.<ticket>`)
    /// as a subprotocol so it never appears in a URL.
    pub async fn connect(net: &Net, path: &str, param: &str) -> Result<Self, NetError> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let ep = &net.relay;
        let scheme = if ep.tls.is_some() { "wss" } else { "ws" };
        let url = format!("{scheme}://{}:{}{path}", ep.host, ep.port);
        let mut req = url.into_client_request().map_err(io_err)?;
        let protocols = format!("snowtalk.v1, {param}")
            .parse()
            .map_err(|_| NetError::BadFrame)?;
        req.headers_mut()
            .insert("sec-websocket-protocol", protocols);
        let tcp = net.dialer.dial(&ep.host, ep.port, &ep.addrs).await?;
        let connector = match &ep.tls {
            Some(cfg) => Connector::Rustls(cfg.clone()),
            None => Connector::Plain,
        };
        let (s, _) =
            tokio_tungstenite::client_async_tls_with_config(req, tcp, None, Some(connector))
                .await
                .map_err(|e| match e {
                    tokio_tungstenite::tungstenite::Error::Http(r)
                        if r.status().is_client_error() =>
                    {
                        NetError::Rejected(r.status().as_u16())
                    }
                    e => io_err(e),
                })?;
        Ok(Self(s))
    }

    pub async fn send(&mut self, m: &ClientMsg) -> Result<(), NetError> {
        let f = encode_frame(m, &mut OsRng).map_err(|_| NetError::BadFrame)?;
        self.0.send(Message::Binary(f.into())).await.map_err(io_err)
    }

    pub async fn recv(&mut self) -> Result<ServerMsg, NetError> {
        loop {
            match self.0.next().await {
                Some(Ok(Message::Binary(b))) => {
                    return decode_frame(&b).map_err(|_| NetError::BadFrame)
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Text(_))) => return Err(NetError::BadFrame),
                Some(Ok(Message::Close(_))) | None => return Err(NetError::Closed),
                Some(Err(e)) => return Err(io_err(e)),
            }
        }
    }

    /// Drop the connection without a WebSocket close frame.
    pub async fn abort(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = match self.0.get_mut() {
            MaybeTlsStream::Plain(s) => s.shutdown().await,
            MaybeTlsStream::Rustls(t) => t.get_mut().0.shutdown().await,
            _ => Ok(()),
        };
    }

    pub async fn close(mut self) {
        let _ = self.0.close(None).await;
    }
}
