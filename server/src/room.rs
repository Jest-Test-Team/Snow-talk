//! ChatRoom Durable Object: a blind two-slot relay.
//!
//! Relayed bytes are never inspected, logged or stored. The only storage is
//! per-slot lifecycle metadata (generation + status) and the room's reputation
//! bookkeeping (see [`Rep`]), which is needed because the object hibernates
//! between messages.
//!
//! ## Good-chat tokens and reports
//! When one side leaves, the other gets `PeerLeft { report_secs }` and may report
//! them during that window. A leaver's token claim is held until the window
//! closes (or the peer leaves too), and is refused if they were reported. Only
//! the first report in a room counts, so a reported user can't retaliate. A
//! claim also needs a real conversation: both sides present for
//! `GOOD_AFTER_SECS` and both having sent `MIN_ACTIVE_FRAMES`. Tokens are
//! unlinkable (VOPRF), so the issuer never learns who it rewarded.
use crate::ticket::{Kind, Ticket, FLAG_PARANOID};
use crate::util::*;
use serde::{Deserialize, Serialize};
use snow_proto::{ClientMsg, ErrorCode, ServerMsg};
use std::cell::RefCell;
use std::collections::VecDeque;
use worker::*;

/// Default reconnect grace period (free tier). Overridable with the `GRACE_SECS` var.
const DEFAULT_GRACE_SECS: u32 = 180;
/// Frames held in memory for a disconnected peer. Best-effort only: this buffer
/// is never written to storage and is lost if the object hibernates or restarts.
const HOLD_FRAMES: usize = 32;

/// Per-slot relay rate caps (token bucket: burst, frames/s). The free burst fits
/// a flash photo (~40 chunks); paranoid adds headroom for 4/s cover traffic.
/// Caps bound per-room volume; they can't stop a modified client from sending
/// slow chaff to keep its own room awake (accepted, see docs/progress.md).
const FREE_RATE: Rate = Rate {
    burst: 48.0,
    per_sec: 4.0,
};
const PARANOID_RATE: Rate = Rate {
    burst: 64.0,
    per_sec: 6.0,
};

#[derive(Clone, Copy)]
struct Rate {
    burst: f64,
    per_sec: f64,
}

/// Token bucket. RAM only: after hibernation it starts full, which is fine
/// since the slot was idle.
#[derive(Clone, Copy, Default)]
struct Limiter {
    tokens: f64,
    at_ms: u64,
    init: bool,
}

impl Limiter {
    fn allow(&mut self, r: Rate, now: u64) -> bool {
        if !self.init {
            *self = Limiter {
                tokens: r.burst,
                at_ms: now,
                init: true,
            };
        }
        let dt = now.saturating_sub(self.at_ms) as f64 / 1000.0;
        self.tokens = (self.tokens + dt * r.per_sec).min(r.burst);
        self.at_ms = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

const DEFAULT_GOOD_AFTER_SECS: u64 = 300;
const DEFAULT_MIN_ACTIVE_FRAMES: u32 = 10;
const DEFAULT_REPORT_SECS: u32 = 15;
/// Good-chat tokens per side per chat.
const GOOD_PER_CHAT: usize = 1;

/// Room-level reputation bookkeeping (in storage: it must survive hibernation).
#[derive(Serialize, Deserialize, Default)]
struct Rep {
    /// When both slots were first present, ms (0 = never).
    both_since_ms: u64,
    /// Slot has sent at least `MIN_ACTIVE_FRAMES`.
    active: [bool; 2],
    reported: [bool; 2],
    /// Claim settled (tokens or refusal sent).
    settled: [bool; 2],
    /// A leaver's claim, held until the report window closes.
    claim: [Option<Vec<[u8; 32]>>; 2],
    /// End of the report window, ms (0 = none).
    window_until_ms: u64,
}

/// Resume tickets outlive the grace period; the room enforces the real deadline.
const RESUME_TICKET_TTL_MS: u64 = 24 * 3600 * 1000;
/// How long a closed room keeps its metadata before wiping it.
const CLEANUP_DELAY_MS: i64 = 60_000;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SlotStatus {
    #[default]
    Empty,
    Connected,
    Disconnected,
    Left,
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct Slot {
    pub gen: u32,
    pub status: SlotStatus,
    /// Only meaningful while `Disconnected`: ms timestamp when the hold expires.
    pub deadline_ms: u64,
    /// Perks from the join ticket (`FLAG_*`); carried into resume tickets.
    #[serde(default)]
    pub flags: u8,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
struct Att {
    slot: u8,
    gen: u32,
}

#[durable_object]
pub struct ChatRoom {
    state: State,
    env: Env,
    /// Ciphertext frames waiting for a disconnected slot (in RAM only).
    held: RefCell<[VecDeque<Vec<u8>>; 2]>,
    /// Relay rate limiter per sending slot (in RAM only).
    limit: RefCell<[Limiter; 2]>,
    /// Frames sent per slot since wake-up (RAM); persisted once as `Rep::active`.
    sent: RefCell<[u32; 2]>,
}

fn tag(slot: u8) -> &'static str {
    if slot == 0 {
        "s0"
    } else {
        "s1"
    }
}

impl ChatRoom {
    async fn slot(&self, s: u8) -> Result<Slot> {
        Ok(self
            .state
            .storage()
            .get::<Slot>(tag(s))
            .await?
            .unwrap_or_default())
    }

    async fn put_slot(&self, s: u8, v: Slot) -> Result<()> {
        self.state.storage().put(tag(s), v).await
    }

    async fn closed(&self) -> Result<bool> {
        Ok(self
            .state
            .storage()
            .get::<bool>("closed")
            .await?
            .unwrap_or(false))
    }

    /// Live sockets for `slot` whose generation is current.
    fn sockets(&self, slot: u8, gen: u32) -> Vec<WebSocket> {
        self.state
            .get_websockets_with_tag(tag(slot))
            .into_iter()
            .filter(|ws| matches!(ws.deserialize_attachment::<Att>(), Ok(Some(a)) if a.gen == gen))
            .collect()
    }

    async fn send_to(&self, slot: u8, msg: &ServerMsg) -> Result<()> {
        let s = self.slot(slot).await?;
        for ws in self.sockets(slot, s.gen) {
            let _ = send(&ws, msg);
        }
        Ok(())
    }

    /// Close the room for good: notify the peer, drop every socket, schedule a wipe.
    async fn close_room(&self, peer_msg: Option<(u8, ServerMsg)>) -> Result<()> {
        if let Some((slot, msg)) = peer_msg {
            self.send_to(slot, &msg).await?;
        }
        self.state.storage().put("closed", true).await?;
        for ws in self.state.get_websockets() {
            let _ = ws.close(Some(1000), Some("closed"));
        }
        self.state.storage().set_alarm(CLEANUP_DELAY_MS).await?;
        event("room_closed");
        Ok(())
    }

    fn header<T: std::str::FromStr>(req: &Request, name: &str) -> Result<T> {
        req.headers()
            .get(name)?
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::RustError(format!("missing {name}")))
    }

    async fn on_socket_gone(&self, ws: WebSocket) -> Result<()> {
        let Some(att) = ws.deserialize_attachment::<Att>()? else {
            return Ok(());
        };
        if self.slot(att.slot).await?.gen == att.gen && !self.closed().await? {
            self.on_disconnect(att.slot).await?;
        }
        Ok(())
    }

    fn grace_secs(&self) -> u32 {
        self.env
            .var("GRACE_SECS")
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(DEFAULT_GRACE_SECS)
    }

    /// The slot's active socket went away without `Leave`: hold the slot for the
    /// grace period and tell the peer how long it will wait.
    async fn on_disconnect(&self, slot: u8) -> Result<()> {
        let mut s = self.slot(slot).await?;
        if s.status != SlotStatus::Connected {
            return Ok(());
        }
        let grace = self.grace_secs();
        s.status = SlotStatus::Disconnected;
        s.deadline_ms = now_ms() + grace as u64 * 1000;
        self.put_slot(slot, s).await?;
        if self.slot(1 - slot).await?.status == SlotStatus::Disconnected {
            // Both sides are gone; nobody is left to wait.
            return self.close_room(None).await;
        }
        self.send_to(1 - slot, &ServerMsg::PeerDisconnected { grace_secs: grace })
            .await?;
        self.schedule_alarm().await
    }

    fn var<T: std::str::FromStr>(&self, name: &str, default: T) -> T {
        self.env
            .var(name)
            .ok()
            .and_then(|v| v.to_string().parse().ok())
            .unwrap_or(default)
    }

    async fn rep(&self) -> Result<Rep> {
        Ok(self
            .state
            .storage()
            .get::<Rep>("rep")
            .await?
            .unwrap_or_default())
    }

    async fn put_rep(&self, r: &Rep) -> Result<()> {
        self.state.storage().put("rep", r).await
    }

    /// Count a relayed frame; persist "active" the first time the threshold is hit.
    async fn note_activity(&self, slot: u8) -> Result<()> {
        let n = {
            let mut sent = self.sent.borrow_mut();
            sent[slot as usize] = sent[slot as usize].saturating_add(1);
            sent[slot as usize]
        };
        if n == self.var("MIN_ACTIVE_FRAMES", DEFAULT_MIN_ACTIVE_FRAMES) {
            let mut r = self.rep().await?;
            if !r.active[slot as usize] {
                r.active[slot as usize] = true;
                self.put_rep(&r).await?;
            }
        }
        Ok(())
    }

    fn eligible(&self, r: &Rep, slot: u8) -> bool {
        let i = slot as usize;
        let after_ms = self.var("GOOD_AFTER_SECS", DEFAULT_GOOD_AFTER_SECS) * 1000;
        !r.reported[i]
            && !r.settled[i]
            && r.active[0]
            && r.active[1]
            && r.both_since_ms > 0
            && now_ms().saturating_sub(r.both_since_ms) >= after_ms
    }

    /// Answer `slot`'s claim: tokens if eligible, otherwise a refusal.
    async fn settle(&self, r: &mut Rep, slot: u8, claim: &[[u8; 32]]) -> Result<()> {
        let i = slot as usize;
        if r.settled[i] {
            return Ok(());
        }
        let msg = if claim.len() == GOOD_PER_CHAT && self.eligible(r, slot) {
            let epoch = snow_tokens::epoch(now_secs());
            let issuer = snow_tokens::Issuer::new(
                &secret(&self.env, "TOKEN_MASTER")?,
                snow_tokens::Kind::Good,
                epoch,
            )
            .map_err(|e| Error::RustError(e.to_string()))?;
            match issuer.issue(claim, random_bytes()) {
                Ok((evaluated, proof)) => {
                    event("token_issued");
                    ServerMsg::Tokens {
                        epoch,
                        public_key: issuer.public_key(),
                        evaluated,
                        proof: [
                            proof[..32].try_into().expect("64"),
                            proof[32..].try_into().expect("64"),
                        ],
                    }
                }
                Err(_) => ServerMsg::NoTokens,
            }
        } else {
            ServerMsg::NoTokens
        };
        r.settled[i] = true;
        r.claim[i] = None;
        self.send_to(slot, &msg).await
    }

    /// `slot` leaves (optionally reporting its peer). The first leaver waits for
    /// the report window; the second one settles everything and closes the room.
    async fn on_leave(&self, slot: u8, claim: Vec<[u8; 32]>, report: bool) -> Result<()> {
        let (i, p) = (slot as usize, 1 - slot as usize);
        let mut s = self.slot(slot).await?;
        if s.status == SlotStatus::Left {
            return Ok(());
        }
        let mut r = self.rep().await?;
        // Only the first report counts; a reported user can't report back.
        if report && !r.reported[i] && !r.reported[p] {
            r.reported[p] = true;
            event("report");
        }
        s.status = SlotStatus::Left;
        self.put_slot(slot, s).await?;
        let peer = self.slot(1 - slot).await?;
        if peer.status == SlotStatus::Connected {
            // First to leave: hold the claim; the peer may still report us.
            let secs = self.var("REPORT_SECS", DEFAULT_REPORT_SECS);
            r.claim[i] = Some(claim);
            r.window_until_ms = now_ms() + secs as u64 * 1000;
            self.put_rep(&r).await?;
            self.send_to(1 - slot, &ServerMsg::PeerLeft { report_secs: secs })
                .await?;
            return self.schedule_alarm().await;
        }
        // Second to leave (or the peer is gone): settle both and close.
        self.settle(&mut r, slot, &claim).await?;
        if let Some(c) = r.claim[p].take() {
            self.settle(&mut r, 1 - slot, &c).await?;
        }
        r.window_until_ms = 0;
        self.put_rep(&r).await?;
        self.close_room(None).await
    }

    /// The report window ran out: settle the waiting leaver's claim and close.
    async fn end_window(&self) -> Result<()> {
        let mut r = self.rep().await?;
        for slot in 0..2u8 {
            if let Some(c) = r.claim[slot as usize].take() {
                self.settle(&mut r, slot, &c).await?;
            }
        }
        r.window_until_ms = 0;
        self.put_rep(&r).await?;
        self.close_room(None).await
    }

    /// Point the single alarm at the earliest grace deadline or report window.
    async fn schedule_alarm(&self) -> Result<()> {
        let w = self.rep().await?.window_until_ms;
        let mut next: Option<u64> = (w > 0).then_some(w);
        for i in 0..2 {
            let s = self.slot(i).await?;
            if s.status == SlotStatus::Disconnected {
                next = Some(next.map_or(s.deadline_ms, |n| n.min(s.deadline_ms)));
            }
        }
        if let Some(t) = next {
            let delay = t.saturating_sub(now_ms()).max(1) as i64;
            self.state.storage().set_alarm(delay).await?;
        }
        Ok(())
    }

    /// Relay to the peer, or hold a few frames in RAM while it is reconnecting.
    async fn relay(&self, to: u8, bytes: Vec<u8>) -> Result<()> {
        let s = self.slot(to).await?;
        match s.status {
            SlotStatus::Connected => self.send_to(to, &ServerMsg::Relay(bytes)).await,
            SlotStatus::Disconnected => {
                let mut held = self.held.borrow_mut();
                let q = &mut held[to as usize];
                if q.len() == HOLD_FRAMES {
                    q.pop_front();
                }
                q.push_back(bytes);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl DurableObject for ChatRoom {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            held: RefCell::new([VecDeque::new(), VecDeque::new()]),
            limit: RefCell::new([Limiter::default(); 2]),
            sent: RefCell::new([0; 2]),
        }
    }

    /// Only the Worker can reach this, after verifying the ticket's MAC and expiry.
    async fn fetch(&self, req: Request) -> Result<Response> {
        let slot: u8 = Self::header(&req, "x-snow-slot")?;
        let kind: u8 = Self::header(&req, "x-snow-kind")?;
        let gen: u32 = Self::header(&req, "x-snow-gen")?;
        let flags: u8 = Self::header(&req, "x-snow-flags")?;
        if slot > 1 || self.closed().await? {
            return Response::error("gone", 410);
        }
        let mut s = self.slot(slot).await?;
        let resumed = match kind {
            k if k == Kind::Join as u8 && s.status == SlotStatus::Empty && gen == 0 => false,
            k if k == Kind::Resume as u8
                && gen == s.gen
                && matches!(s.status, SlotStatus::Connected | SlotStatus::Disconnected) =>
            {
                true
            }
            _ => return Response::error("ticket already used", 409),
        };
        // Each successful entry bumps the generation, which revokes the old ticket
        // and marks any older socket for this slot as stale.
        let first_entry = s.status == SlotStatus::Empty;
        let was_disconnected = s.status == SlotStatus::Disconnected;
        s.gen += 1;
        s.status = SlotStatus::Connected;
        s.deadline_ms = 0;
        if first_entry {
            // Perks come from the matchmaker's join ticket; resumes keep them.
            s.flags = flags;
        }
        self.put_slot(slot, s).await?;
        for old in self.state.get_websockets_with_tag(tag(slot)) {
            let _ = old.close(Some(1000), Some("superseded"));
        }

        let pair = WebSocketPair::new()?;
        self.state
            .accept_websocket_with_tags(&pair.server, &[tag(slot)]);
        pair.server.serialize_attachment(Att { slot, gen: s.gen })?;

        let mut room = [0u8; 32];
        hex::decode_to_slice(self.state.id().to_string(), &mut room)
            .map_err(|e| Error::RustError(e.to_string()))?;
        let resume = Ticket {
            room,
            slot,
            kind: Kind::Resume,
            flags: s.flags,
            gen: s.gen,
            exp: now_ms() + RESUME_TICKET_TTL_MS,
        }
        .sign(&secret(&self.env, "TICKET_KEY")?);
        let peer = self.slot(1 - slot).await?;
        let peer_present = peer.status == SlotStatus::Connected;
        send(
            &pair.server,
            &ServerMsg::Joined {
                resume,
                peer_present,
            },
        )?;
        if resumed {
            let held: Vec<_> = self.held.borrow_mut()[slot as usize].drain(..).collect();
            for bytes in held {
                send(&pair.server, &ServerMsg::Relay(bytes))?;
            }
            // A rotation (resume while still connected) is invisible to the peer.
            if was_disconnected {
                self.send_to(1 - slot, &ServerMsg::PeerReconnected).await?;
            }
        } else {
            self.send_to(1 - slot, &ServerMsg::PeerJoined).await?;
            if first_entry && peer.status == SlotStatus::Empty {
                event("room_created");
            }
            if first_entry && peer.status != SlotStatus::Empty {
                let mut r = self.rep().await?;
                r.both_since_ms = now_ms();
                self.put_rep(&r).await?;
            }
        }
        upgrade_response(pair.client)
    }

    async fn websocket_message(&self, ws: WebSocket, msg: WebSocketIncomingMessage) -> Result<()> {
        let Some(att) = ws.deserialize_attachment::<Att>()? else {
            return Ok(());
        };
        if self.slot(att.slot).await?.gen != att.gen {
            let _ = ws.close(Some(1000), Some("superseded"));
            return Ok(());
        }
        match decode(msg) {
            // Forwarded unchanged (or briefly held in RAM if the peer is reconnecting).
            Some(ClientMsg::Relay(bytes)) => {
                let s = self.slot(att.slot).await?;
                let rate = if s.flags & FLAG_PARANOID != 0 {
                    PARANOID_RATE
                } else {
                    FREE_RATE
                };
                if !self.limit.borrow_mut()[att.slot as usize].allow(rate, now_ms()) {
                    // Dropped, not relayed. The sender's pacer should never get here.
                    return send(&ws, &ServerMsg::Error(ErrorCode::RateLimited));
                }
                self.note_activity(att.slot).await?;
                self.relay(1 - att.slot, bytes).await
            }
            Some(ClientMsg::Leave { claim }) => self.on_leave(att.slot, claim, false).await,
            Some(ClientMsg::Report { claim }) => self.on_leave(att.slot, claim, true).await,
            _ => send(&ws, &ServerMsg::Error(ErrorCode::BadFrame)),
        }
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _clean: bool,
    ) -> Result<()> {
        self.on_socket_gone(ws).await
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        self.on_socket_gone(ws).await
    }

    async fn alarm(&self) -> Result<Response> {
        if self.closed().await? {
            self.state.storage().delete_all().await?;
            return Response::empty();
        }
        let w = self.rep().await?.window_until_ms;
        if w > 0 && w <= now_ms() {
            self.end_window().await?;
            return Response::empty();
        }
        for i in 0..2u8 {
            let mut s = self.slot(i).await?;
            if s.status == SlotStatus::Disconnected && s.deadline_ms <= now_ms() {
                s.status = SlotStatus::Left;
                self.put_slot(i, s).await?;
                self.close_room(Some((1 - i, ServerMsg::PeerGone))).await?;
                return Response::empty();
            }
        }
        self.schedule_alarm().await?;
        Response::empty()
    }
}
