//! Snow-talk relay on Cloudflare Workers.
//!
//! * `GET /pow?b=<bucket>`   → proof-of-work challenge (57 raw bytes)
//! * `GET /match?b=<bucket>` → WebSocket to the Matchmaker DO shard for that bucket
//! * `GET /room/<ticket>`    → WebSocket to the ChatRoom DO named in the ticket
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
        Some(s) => s.parse::<u8>().ok().filter(|b| *b < 64),
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
        let url = req.url()?;
        let bucket_q = url.query_pairs().find(|(k, _)| k == "b").map(|(_, v)| v.into_owned());
        let path = url.path().to_string();
        match (req.method(), path.as_str()) {
            (Method::Get, "/pow") => {
                let Some(bucket) = parse_bucket(bucket_q.as_deref()) else {
                    return Response::error("bad bucket", 400);
                };
                let mut rand = random_bytes::<16>();
                bind_bucket(&mut rand, bucket);
                let difficulty = env
                    .var("POW_DIFFICULTY")
                    .ok()
                    .and_then(|v| v.to_string().parse().ok())
                    .unwrap_or(23);
                let c = snow_pow::Challenge::issue(&secret(&env, "POW_KEY")?, now_secs(), difficulty, rand);
                let headers = Headers::new();
                headers.set("content-type", "application/octet-stream")?;
                headers.set("cache-control", "no-store")?;
                Ok(Response::from_bytes(c.to_bytes().to_vec())?.with_headers(headers))
            }
            (Method::Get, "/match") => {
                require_upgrade(&req)?;
                let Some(bucket) = parse_bucket(bucket_q.as_deref()) else {
                    return Response::error("bad bucket", 400);
                };
                let ns = env.durable_object("MATCHMAKER")?;
                let stub = ns.id_from_name(&format!("mm:tw:{bucket}"))?.get_stub()?;
                let fwd = Request::new_with_init(
                    &format!("https://mm/?b={bucket}"),
                    RequestInit::new().with_headers(upgrade_headers()?),
                )?;
                stub.fetch_with_request(fwd).await
            }
            (Method::Get, p) if p.starts_with("/room/") => {
                require_upgrade(&req)?;
                let key = secret(&env, "TICKET_KEY")?;
                let Some(t) = ticket::Ticket::verify(&key, &p[6..], now_ms()) else {
                    return Response::error("bad ticket", 403);
                };
                let ns = env.durable_object("CHATROOM")?;
                let stub = ns.id_from_string(&t.room_hex())?.get_stub()?;
                let headers = upgrade_headers()?;
                headers.set("x-snow-slot", &t.slot.to_string())?;
                headers.set("x-snow-kind", &(t.kind as u8).to_string())?;
                headers.set("x-snow-gen", &t.gen.to_string())?;
                let fwd = Request::new_with_init("https://room/", RequestInit::new().with_headers(headers))?;
                stub.fetch_with_request(fwd).await
            }
            _ => Response::error("not found", 404),
        }
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
