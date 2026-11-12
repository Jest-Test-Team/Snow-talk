//! Transport: HTTPS for the PoW challenge, WebSocket for everything else.
//! Every WebSocket message is one fixed-size frame.
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use snow_proto::{decode_frame, encode_frame, ClientMsg, ServerMsg};
use std::sync::Arc;
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

/// TLS + HTTP setup for one chat.
///
/// For a real hostname, the address and ECH config come from DoH (see
/// [`crate::dns`]), so neither the OS resolver nor the TLS SNI reveals which
/// site we connect to. Localhost / IP literals (development) skip DoH and ECH.
/// With `pins` empty, plain WebPKI validation is used (development only).
#[derive(Clone)]
pub struct Net {
    tls: Arc<rustls::ClientConfig>,
    pub http: reqwest::Client,
    /// Pre-resolved addresses for the relay; empty = let the system resolve.
    addrs: Vec<std::net::SocketAddr>,
    pub ech: bool,
}

fn tls_config(pins: &[[u8; 32]], ech: Option<&[u8]>) -> Result<rustls::ClientConfig, NetError> {
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
    .map_err(|e| NetError::Io(e.to_string()))?;
    Ok(if pins.is_empty() {
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|e| NetError::Io(e.to_string()))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::pin::PinnedVerifier {
                inner,
                pins: pins.to_vec(),
            }))
            .with_no_client_auth()
    })
}

fn is_local(host: &str) -> bool {
    host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[')
}

impl Net {
    pub async fn new(base: &str, pins: &[String]) -> Result<Self, NetError> {
        let url = reqwest::Url::parse(base).map_err(|e| NetError::Io(e.to_string()))?;
        let host = url
            .host_str()
            .ok_or(NetError::Io("server URL has no host".into()))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let pins = crate::pin::parse_pins(pins);
        let resolved = if is_local(&host) {
            crate::dns::Resolved::default()
        } else {
            let doh = crate::dns::doh_client(tls_config(&[], None)?);
            crate::dns::resolve(&doh, &host).await?
        };
        let cfg = tls_config(&pins, resolved.ech.as_deref())?;
        let addrs: Vec<_> = resolved
            .addrs
            .iter()
            .map(|ip| std::net::SocketAddr::new(*ip, port))
            .collect();
        let mut http = reqwest::Client::builder()
            .tls_backend_preconfigured(cfg.clone())
            .user_agent("snowtalk"); // no version / device details
        if !addrs.is_empty() {
            http = http.resolve_to_addrs(&host, &addrs);
        }
        Ok(Self {
            tls: Arc::new(cfg),
            http: http.build().map_err(|e| NetError::Io(e.to_string()))?,
            addrs,
            ech: resolved.ech.is_some(),
        })
    }
}

pub async fn fetch_pow(net: &Net, base: &str, bucket: u8) -> Result<Vec<u8>, NetError> {
    let r = net
        .http
        .get(format!("{base}/pow"))
        .header("x-snow-bucket", bucket.to_string())
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| NetError::Io(e.to_string()))?;
    Ok(r.bytes()
        .await
        .map_err(|e| NetError::Io(e.to_string()))?
        .to_vec())
}

pub struct Ws(WebSocketStream<MaybeTlsStream<TcpStream>>);

pub fn ws_url(base: &str, path: &str) -> String {
    let b = base.strip_prefix("https://").map(|r| format!("wss://{r}"));
    let b = b.or_else(|| base.strip_prefix("http://").map(|r| format!("ws://{r}")));
    format!("{}{path}", b.unwrap_or_else(|| base.to_string()))
}

impl Ws {
    /// Connect, passing `param` (`b.<bucket>` / `t.<ticket>`) as a subprotocol so it
    /// never appears in a URL.
    pub async fn connect(net: &Net, url: &str, param: &str) -> Result<Self, NetError> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = url
            .into_client_request()
            .map_err(|e| NetError::Io(e.to_string()))?;
        let protocols = format!("snowtalk.v1, {param}")
            .parse()
            .map_err(|_| NetError::BadFrame)?;
        req.headers_mut()
            .insert("sec-websocket-protocol", protocols);
        let connector = Some(Connector::Rustls(net.tls.clone()));
        let result = if net.addrs.is_empty() {
            tokio_tungstenite::connect_async_tls_with_config(req, None, false, connector).await
        } else {
            let tcp = TcpStream::connect(&net.addrs[..])
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
            tokio_tungstenite::client_async_tls_with_config(req, tcp, None, connector).await
        };
        let (s, _) = result.map_err(|e| match e {
            tokio_tungstenite::tungstenite::Error::Http(r) if r.status().is_client_error() => {
                NetError::Rejected(r.status().as_u16())
            }
            e => NetError::Io(e.to_string()),
        })?;
        Ok(Self(s))
    }

    pub async fn send(&mut self, m: &ClientMsg) -> Result<(), NetError> {
        let f = encode_frame(m, &mut OsRng).map_err(|_| NetError::BadFrame)?;
        self.0
            .send(Message::Binary(f.into()))
            .await
            .map_err(|e| NetError::Io(e.to_string()))
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
                Some(Err(e)) => return Err(NetError::Io(e.to_string())),
            }
        }
    }

    /// Drop the TCP connection without a WebSocket close frame.
    pub async fn abort(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = match self.0.get_mut() {
            MaybeTlsStream::Plain(t) => t.shutdown().await,
            MaybeTlsStream::Rustls(t) => t.get_mut().0.shutdown().await,
            _ => Ok(()),
        };
    }

    pub async fn close(mut self) {
        let _ = self.0.close(None).await;
    }
}
