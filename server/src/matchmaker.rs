//! Matchmaker Durable Object: one instance per (region, interest bucket) shard.
//!
//! Waiting clients hold a hibernatable WebSocket. When a second client joins with
//! a valid proof of work, the two are paired: a fresh ChatRoom ID is minted, each
//! side gets a short-lived signed ticket plus its handshake role, and both
//! matchmaker sockets are closed.
use crate::nullifiers::redeem;
use crate::ticket::{Kind as TicketKind, Ticket, FLAG_PARANOID};
use crate::util::*;
use serde::{Deserialize, Serialize};
use snow_proto::{ClientMsg, ErrorCode, Role, ServerMsg};
use snow_tokens::Kind;
use worker::*;

const TICKET_TTL_MS: u64 = 30_000;
/// Close sockets that never send `Join` (or never get matched) after this long.
const WAIT_LIMIT_MS: u64 = 5 * 60_000;
const SWEEP_MS: i64 = 60_000;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum Status {
    AwaitingJoin,
    Waiting,
    Done,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
struct Att {
    id: [u8; 8],
    bucket: u8,
    status: Status,
    since_ms: u64,
    /// Paranoid mode granted to this waiter.
    #[serde(default)]
    paranoid: bool,
    /// In the trusted queue (spent enough good-chat tokens).
    #[serde(default)]
    trusted: bool,
}

#[durable_object]
pub struct Matchmaker {
    state: State,
    env: Env,
}

impl Matchmaker {
    fn sockets(&self) -> Vec<(WebSocket, Att)> {
        self.state
            .get_websockets()
            .into_iter()
            .filter_map(|ws| {
                ws.deserialize_attachment::<Att>()
                    .ok()
                    .flatten()
                    .map(|a| (ws, a))
            })
            .collect()
    }

    fn var<T: std::str::FromStr>(&self, name: &str, default: T) -> T {
        self.env
            .var(name)
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(default)
    }

    /// Paranoid mode costs real money (constant traffic keeps the room awake), so
    /// it is a paid perk: one VIP token. `PARANOID_GRANT=open` grants it to
    /// anyone (dev/beta).
    async fn grant_paranoid(&self, spend: &[Vec<u8>]) -> Result<bool> {
        if self.var("PARANOID_GRANT", String::new()) == "open" {
            return Ok(true);
        }
        redeem(&self.env, spend, Kind::Vip, 1).await
    }

    fn reject(ws: &WebSocket, code: ErrorCode) -> Result<()> {
        let _ = send(ws, &ServerMsg::Error(code));
        ws.close(Some(1008), Some("rejected"))
    }

    /// PoW must be valid, fresh, bound to this shard's bucket and unused.
    async fn check_pow(&self, att: &Att, pow: &snow_proto::PowSolution) -> Result<bool> {
        let key = secret(&self.env, "POW_KEY")?;
        let Ok(c) = snow_pow::Challenge::verify(&key, now_secs(), &pow.challenge, pow.nonce) else {
            return Ok(false);
        };
        if c.rand[15] != att.bucket {
            return Ok(false);
        }
        let k = format!("pow:{}", hex::encode(c.replay_id()));
        let storage = self.state.storage();
        if storage.get::<u64>(&k).await?.is_some() {
            return Ok(false);
        }
        storage
            .put(&k, (c.issued_at + snow_pow::MAX_AGE_SECS) * 1000)
            .await?;
        Ok(true)
    }

    async fn ensure_sweep_alarm(&self) -> Result<()> {
        let storage = self.state.storage();
        if storage.get_alarm().await?.is_none() {
            storage.set_alarm(SWEEP_MS).await?;
        }
        Ok(())
    }
}

impl DurableObject for Matchmaker {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let bucket = req
            .headers()
            .get("x-snow-bucket")?
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(crate::RANDOM_BUCKET);
        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        pair.server.serialize_attachment(Att {
            id: random_bytes(),
            bucket,
            status: Status::AwaitingJoin,
            since_ms: now_ms(),
            paranoid: false,
            trusted: false,
        })?;
        self.ensure_sweep_alarm().await?;
        upgrade_response(pair.client)
    }

    async fn websocket_message(&self, ws: WebSocket, msg: WebSocketIncomingMessage) -> Result<()> {
        let Some(mut att) = ws.deserialize_attachment::<Att>()? else {
            return Self::reject(&ws, ErrorCode::Internal);
        };
        let Some(ClientMsg::Join {
            pow,
            bucket,
            paranoid,
            trusted,
            spend,
        }) = decode(msg)
        else {
            return Self::reject(&ws, ErrorCode::BadFrame);
        };
        if att.status != Status::AwaitingJoin
            || bucket.unwrap_or(crate::RANDOM_BUCKET) != att.bucket
        {
            return Self::reject(&ws, ErrorCode::BadFrame);
        }
        if !self.check_pow(&att, &pow).await? {
            return Self::reject(&ws, ErrorCode::BadPow);
        }
        att.paranoid = paranoid && self.grant_paranoid(&spend).await?;
        att.trusted = trusted
            && redeem(
                &self.env,
                &spend,
                Kind::Good,
                self.var("TRUSTED_MIN", 3usize),
            )
            .await?;

        // Pair with whoever has been waiting longest, trusted with trusted. A
        // trusted waiter is reserved for trusted arrivals for a while, then may
        // be matched with anyone so nobody waits forever.
        let now = now_ms();
        let exclusive_ms = self.var("TRUSTED_EXCLUSIVE_SECS", 30u64) * 1000;
        let waiting: Vec<(WebSocket, Att)> = self
            .sockets()
            .into_iter()
            .filter(|(_, a)| a.status == Status::Waiting && a.id != att.id)
            .collect();
        let oldest = |pred: &dyn Fn(&Att) -> bool| {
            waiting
                .iter()
                .filter(|(_, a)| pred(a))
                .min_by_key(|(_, a)| a.since_ms)
                .cloned()
        };
        let partner = if att.trusted {
            oldest(&|a| a.trusted)
        } else {
            oldest(&|a| !a.trusted).or_else(|| {
                oldest(&|a| a.trusted && now.saturating_sub(a.since_ms) >= exclusive_ms)
            })
        };

        let Some((pws, mut patt)) = partner else {
            att.status = Status::Waiting;
            att.since_ms = now_ms();
            return ws.serialize_attachment(att);
        };

        let room_id = self
            .env
            .durable_object("CHATROOM")?
            .unique_id()?
            .to_string();
        let mut room = [0u8; 32];
        hex::decode_to_slice(&room_id, &mut room).map_err(|e| Error::RustError(e.to_string()))?;
        let key = secret(&self.env, "TICKET_KEY")?;
        let exp = now_ms() + TICKET_TTL_MS;
        let ticket = |slot, paranoid: bool| {
            Ticket {
                room,
                slot,
                kind: TicketKind::Join,
                flags: if paranoid { FLAG_PARANOID } else { 0 },
                gen: 0,
                exp,
            }
            .sign(&key)
        };

        let both_trusted = att.trusted && patt.trusted;
        // The partner waited longer, so it gets slot 0 / Initiator.
        for (sock, a, slot, role) in [
            (&pws, &mut patt, 0, Role::Initiator),
            (&ws, &mut att, 1, Role::Responder),
        ] {
            a.status = Status::Done;
            sock.serialize_attachment(*a)?;
            send(
                sock,
                &ServerMsg::Matched {
                    ticket: ticket(slot, a.paranoid),
                    role,
                    paranoid: a.paranoid,
                    trusted: both_trusted,
                },
            )?;
            sock.close(Some(1000), Some("matched"))?;
        }
        event("matched");
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: Error) -> Result<()> {
        Ok(())
    }

    /// Periodic sweep: drop expired PoW replay entries and stale sockets.
    async fn alarm(&self) -> Result<Response> {
        let storage = self.state.storage();
        let now = now_ms();
        let entries = storage
            .list_with_options(ListOptions::new().prefix("pow:"))
            .await?;
        let mut expired = Vec::new();
        for k in entries.keys() {
            let k = k?.as_string().unwrap_or_default();
            let v = entries.get(&k.clone().into());
            if v.as_f64().map(|e| (e as u64) < now).unwrap_or(true) {
                expired.push(k);
            }
        }
        if !expired.is_empty() {
            storage.delete_multiple(expired).await?;
        }
        let socks = self.sockets();
        for (ws, a) in &socks {
            if now.saturating_sub(a.since_ms) > WAIT_LIMIT_MS {
                let _ = ws.close(Some(1000), Some("timeout"));
            }
        }
        if !socks.is_empty()
            || storage
                .list_with_options(ListOptions::new().prefix("pow:").limit(1))
                .await?
                .size()
                > 0
        {
            storage.set_alarm(SWEEP_MS).await?;
        }
        Response::empty()
    }
}
