use rand_core::{OsRng, RngCore};
use worker::*;

pub fn now_ms() -> u64 {
    Date::now().as_millis()
}

pub fn now_secs() -> u64 {
    now_ms() / 1000
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn secret(env: &Env, name: &str) -> Result<Vec<u8>> {
    Ok(env.secret(name)?.to_string().into_bytes())
}

/// Encode a server message into a padded fixed-size frame and send it.
pub fn send(ws: &WebSocket, msg: &snow_proto::ServerMsg) -> Result<()> {
    let frame =
        snow_proto::encode_frame(msg, &mut OsRng).map_err(|e| Error::RustError(e.to_string()))?;
    ws.send_with_bytes(frame)
}

pub fn decode(msg: WebSocketIncomingMessage) -> Option<snow_proto::ClientMsg> {
    match msg {
        WebSocketIncomingMessage::Binary(b) => snow_proto::decode_frame(&b).ok(),
        WebSocketIncomingMessage::String(_) => None,
    }
}

/// Lifecycle log line. Never pass identifiers, IPs or payload here.
pub fn event(name: &'static str) {
    console_log!("{name}");
}

/// 101 response that selects our subprotocol (required since the client offers one).
pub fn upgrade_response(client: WebSocket) -> Result<Response> {
    let h = Headers::new();
    h.set("sec-websocket-protocol", crate::PROTOCOL)?;
    Ok(Response::from_websocket(client)?.with_headers(h))
}
