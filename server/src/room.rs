//! ChatRoom Durable Object: a blind two-slot relay.
//!
//! Relayed bytes are never inspected, logged or stored. The only storage is
//! per-slot lifecycle metadata (generation + status), which is needed because the
//! object hibernates between messages.
use crate::ticket::{Kind, Ticket};
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

    /// Point the single alarm at the earliest grace deadline.
    async fn schedule_alarm(&self) -> Result<()> {
        let mut next: Option<u64> = None;
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
        }
    }

    /// Only the Worker can reach this, after verifying the ticket's MAC and expiry.
    async fn fetch(&self, req: Request) -> Result<Response> {
        let slot: u8 = Self::header(&req, "x-snow-slot")?;
        let kind: u8 = Self::header(&req, "x-snow-kind")?;
        let gen: u32 = Self::header(&req, "x-snow-gen")?;
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
            Some(ClientMsg::Relay(bytes)) => self.relay(1 - att.slot, bytes).await,
            Some(ClientMsg::Leave) => {
                let mut s = self.slot(att.slot).await?;
                s.status = SlotStatus::Left;
                self.put_slot(att.slot, s).await?;
                self.close_room(Some((1 - att.slot, ServerMsg::PeerLeft)))
                    .await
            }
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
