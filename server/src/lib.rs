//! Snow-talk relay on Cloudflare Workers.
//!
//! * `GET /pow`   (header `x-snow-bucket: <b>`)     → proof-of-work challenge (57 raw bytes)
//! * `GET /match` (subprotocols `snowtalk.v1, b.<b>`) → WebSocket to the Matchmaker shard
//! * `GET /room`  (subprotocols `snowtalk.v1, t.<ticket>`) → WebSocket to the ChatRoom
//!
//! Buckets and tickets travel in headers, never in the URL. URLs end up in edge
//! analytics, and the two tickets of a room share the room ID, so a ticket in the
//! URL would let anyone with log access link the two peers' IPs.
//!
//! Logging policy: never log payloads, IPs, tickets or room IDs. Only lifecycle
//! events (`room_created`, `room_closed`, ...) are logged, and the log line's own
//! timestamp is the only time information.
pub mod ticket;

#[cfg(target_arch = "wasm32")]
mod matchmaker;
#[cfg(target_arch = "wasm32")]
mod room;
#[cfg(target_arch = "wasm32")]
mod util;

#[cfg(target_arch = "wasm32")]
pub use {matchmaker::Matchmaker, room::ChatRoom};

/// WebSocket subprotocol both sides must agree on.
pub const PROTOCOL: &str = "snowtalk.v1";

/// Bucket value meaning "random matching, no interest tag".
pub const RANDOM_BUCKET: u8 = 255;
/// Bucket the PoW challenge is bound to (stored in the last byte of `rand`) so a
/// solution can't be replayed across matchmaker shards.
pub fn bind_bucket(rand: &mut [u8; 16], bucket: u8) {
    rand[15] = bucket;
}
pub fn parse_bucket(q: Option<&str>) -> Option<u8> {
    match q {
        None | Some("") => Some(RANDOM_BUCKET),
        Some(s) => s
            .parse::<u8>()
            .ok()
            .filter(|b| *b < 64 || *b == RANDOM_BUCKET),
    }
}

#[cfg(target_arch = "wasm32")]
mod entry {
    use super::*;
    use crate::util::*;
    use worker::*;

    #[event(fetch)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        console_error_panic_hook::set_once();
        let path = req.url()?.path().to_string();
        match (req.method(), path.as_str()) {
            (Method::Get, "/pow") => {
                let b = req.headers().get("x-snow-bucket")?;
                let Some(bucket) = parse_bucket(b.as_deref()) else {
                    return Response::error("bad bucket", 400);
                };
                let mut rand = random_bytes::<16>();
                bind_bucket(&mut rand, bucket);
                let difficulty = env
                    .var("POW_DIFFICULTY")
                    .ok()
                    .and_then(|v| v.to_string().parse().ok())
                    .unwrap_or(23);
                let c = snow_pow::Challenge::issue(
                    &secret(&env, "POW_KEY")?,
                    now_secs(),
                    difficulty,
                    rand,
                );
                let headers = Headers::new();
                headers.set("content-type", "application/octet-stream")?;
                headers.set("cache-control", "no-store")?;
                Ok(Response::from_bytes(c.to_bytes().to_vec())?.with_headers(headers))
            }
            (Method::Get, "/match") => {
                require_upgrade(&req)?;
                let Some(bucket) = parse_bucket(protocol_param(&req, "b.")?.as_deref()) else {
                    return Response::error("bad bucket", 400);
                };
                let ns = env.durable_object("MATCHMAKER")?;
                let stub = ns.id_from_name(&format!("mm:tw:{bucket}"))?.get_stub()?;
                let headers = upgrade_headers()?;
                headers.set("x-snow-bucket", &bucket.to_string())?;
                let fwd = Request::new_with_init(
                    "https://mm/",
                    RequestInit::new().with_headers(headers),
                )?;
                stub.fetch_with_request(fwd).await
            }
            (Method::Get, "/room") => {
                require_upgrade(&req)?;
                let key = secret(&env, "TICKET_KEY")?;
                let raw = protocol_param(&req, "t.")?.unwrap_or_default();
                let Some(t) = ticket::Ticket::verify(&key, &raw, now_ms()) else {
                    return Response::error("bad ticket", 403);
                };
                let ns = env.durable_object("CHATROOM")?;
                let stub = ns.id_from_string(&t.room_hex())?.get_stub()?;
                let headers = upgrade_headers()?;
                headers.set("x-snow-slot", &t.slot.to_string())?;
                headers.set("x-snow-kind", &(t.kind as u8).to_string())?;
                headers.set("x-snow-gen", &t.gen.to_string())?;
                headers.set("x-snow-flags", &t.flags.to_string())?;
                let fwd = Request::new_with_init(
                    "https://room/",
                    RequestInit::new().with_headers(headers),
                )?;
                stub.fetch_with_request(fwd).await
            }
            _ => Response::error("not found", 404),
        }
    }

    /// Read `<prefix><value>` from the offered subprotocols; `snowtalk.v1` must be offered.
    fn protocol_param(req: &Request, prefix: &str) -> Result<Option<String>> {
        let offered = req
            .headers()
            .get("sec-websocket-protocol")?
            .unwrap_or_default();
        let mut parts = offered.split(',').map(str::trim);
        if !parts.clone().any(|p| p == PROTOCOL) {
            return Err(Error::RustError("missing subprotocol".into()));
        }
        Ok(parts
            .find_map(|p| p.strip_prefix(prefix))
            .map(str::to_string))
    }

    fn require_upgrade(req: &Request) -> Result<()> {
        match req.headers().get("upgrade")? {
            Some(v) if v.eq_ignore_ascii_case("websocket") => Ok(()),
            _ => Err(Error::RustError("expected websocket".into())),
        }
    }

    /// Only the upgrade header is forwarded to the DOs; client headers (and with
    /// them any IP or UA information) never reach DO code.
    fn upgrade_headers() -> Result<Headers> {
        let h = Headers::new();
        h.set("upgrade", "websocket")?;
        Ok(h)
    }
}
