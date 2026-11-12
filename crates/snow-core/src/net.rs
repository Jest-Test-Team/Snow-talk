//! Transport: HTTPS for the PoW challenge, WebSocket for everything else.
//! Every WebSocket message is one fixed-size frame.
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use snow_proto::{decode_frame, encode_frame, ClientMsg, ServerMsg};
use std::sync::{Arc, OnceLock};
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

fn tls() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // Certificate pinning is added in Phase 5 (custom verifier).
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the default versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_backend_preconfigured((*tls()).clone())
        .user_agent("snowtalk") // no version / device details
        .build()
        .expect("http client")
}

pub async fn fetch_pow(
    http: &reqwest::Client,
    base: &str,
    bucket: u8,
) -> Result<Vec<u8>, NetError> {
    let r = http
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
    pub async fn connect(url: &str, param: &str) -> Result<Self, NetError> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = url
            .into_client_request()
            .map_err(|e| NetError::Io(e.to_string()))?;
        let protocols = format!("snowtalk.v1, {param}")
            .parse()
            .map_err(|_| NetError::BadFrame)?;
        req.headers_mut()
            .insert("sec-websocket-protocol", protocols);
        let (s, _) = tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            Some(Connector::Rustls(tls())),
        )
        .await
        .map_err(|e| match e {
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
