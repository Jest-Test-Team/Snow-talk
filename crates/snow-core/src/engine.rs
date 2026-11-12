//! The per-chat async task: PoW → queue → room → handshake → chat.
use crate::api::*;
use crate::net::{self, NetError, Ws};
use crate::pacer::{Out, Pacer};
use snow_crypto::{ChatSession, CryptoError, Handshaker, Step};
use snow_proto::{ClientMsg, Handshake, Inner, PeerEnvelope, Role, ServerMsg};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

pub enum Cmd {
    Send {
        id: u64,
        body: Zeroizing<String>,
        ttl_secs: u32,
    },
    Leave,
    Wipe,
    /// Testing: kill the socket without a close frame, as a network drop would.
    DebugDrop,
    /// App moved to the foreground (`true`) or background (`false`).
    Foreground(bool),
}

#[derive(Debug, thiserror::Error)]
enum EngineError {
    #[error(transparent)]
    Net(#[from] NetError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("server rejected us: {0:?}")]
    Server(snow_proto::ErrorCode),
    #[error("protocol violation")]
    Protocol,
}

pub async fn run(
    cfg: Config,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    l: Arc<dyn ChatListener>,
    frames: Arc<AtomicU64>,
) {
    let reason = match run_inner(&cfg, &mut cmds, &*l, frames).await {
        Ok(r) => r,
        Err(e) => EndReason::Error {
            message: e.to_string(),
        },
    };
    l.on_state(ChatState::Ended { reason });
}

fn relay(env: &PeerEnvelope) -> ClientMsg {
    ClientMsg::Relay(postcard::to_allocvec(env).expect("envelope serializes"))
}

async fn run_inner(
    cfg: &Config,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    l: &dyn ChatListener,
    frames: Arc<AtomicU64>,
) -> Result<EndReason, EngineError> {
    let base = cfg.server_url.trim_end_matches('/');
    let bucket = cfg.bucket.unwrap_or(255);

    // 1. Proof of work.
    l.on_state(ChatState::SolvingPow);
    let netw = net::Net::new(base, &cfg.pins, net::Dialer::Direct).await?;
    let challenge = net::fetch_pow(&netw, bucket).await?;
    let c = snow_pow::Challenge::from_bytes(&challenge).map_err(|_| EngineError::Protocol)?;
    let nonce = tokio::task::spawn_blocking(move || c.solve())
        .await
        .map_err(|_| EngineError::Protocol)?;

    // 2. Matchmaking.
    l.on_state(ChatState::Queued);
    let mut mm = Ws::connect(&netw, "/match", &format!("b.{bucket}")).await?;
    mm.send(&ClientMsg::Join {
        pow: snow_proto::PowSolution { challenge, nonce },
        bucket: cfg.bucket,
    })
    .await?;
    let (ticket, role) = loop {
        tokio::select! {
            m = mm.recv() => match m? {
                ServerMsg::Matched { ticket, role } => break (ticket, role),
                ServerMsg::Error(c) => return Err(EngineError::Server(c)),
                _ => return Err(EngineError::Protocol),
            },
            c = cmds.recv() => match c {
                Some(Cmd::Send { .. } | Cmd::DebugDrop | Cmd::Foreground(_)) => continue,
                Some(Cmd::Wipe) => { mm.close().await; return Ok(EndReason::Wiped) }
                Some(Cmd::Leave) | None => { mm.close().await; return Ok(EndReason::Cancelled) }
            },
        }
    };
    mm.close().await;

    // 3. Room + handshake + chat.
    l.on_state(ChatState::Handshaking);
    let room_url = "/room";
    let (mut room, mut resume, peer_present) = join_room(&netw, room_url, &ticket).await?;
    let mut chat = Chat::new(role, frames);
    if peer_present {
        chat.send_commit(&mut room).await?;
    }
    let mut rotate_at = next_rotation(cfg);
    let mut outbox: Vec<Cmd> = Vec::new();
    let mut pacer = Pacer::new(cfg.chaff_ms);
    let mut foreground = true;

    loop {
        // Anything typed while we were reconnecting goes back into the queue.
        for c in std::mem::take(&mut outbox) {
            match c {
                Cmd::Send { id, body, ttl_secs } => pacer.push(id, body, ttl_secs),
                Cmd::Foreground(f) => foreground = f,
                _ => {}
            }
        }
        let cover = foreground && chat.peer_online;
        let lost = tokio::select! {
            out = pacer.next(cover), if chat.session.is_some() => match out {
                Out::Text(p) => chat.send_text(&mut room, p.id, &p.body, p.ttl_secs).await.is_err(),
                Out::Chaff => chat.send_chaff(&mut room).await.is_err(),
            },
            m = room.recv() => match m {
                Ok(m) => match chat.on_server(m, &mut room, l).await? {
                    Some(end) => return Ok(end),
                    None => false,
                },
                Err(NetError::Closed | NetError::Io(_)) => true,
                Err(e) => return Err(e.into()),
            },
            _ = tokio::time::sleep_until(rotate_at) => {
                // Session-ID rotation: enter the same slot on a fresh socket with
                // the resume ticket; the room then revokes the old socket and ticket.
                if let Ok((new, r, _)) = join_room(&netw, room_url, &resume).await {
                    let old = std::mem::replace(&mut room, new);
                    resume = r;
                    chat.drain(old, &mut room, l).await?;
                }
                rotate_at = next_rotation(cfg);
                false
            }
            c = cmds.recv() => match c {
                Some(Cmd::Send { id, body, ttl_secs }) => { pacer.push(id, body, ttl_secs); false }
                Some(Cmd::Foreground(f)) => { foreground = f; false }
                Some(Cmd::Leave) => {
                    let _ = room.send(&ClientMsg::Leave).await;
                    room.close().await;
                    return Ok(EndReason::SelfLeft);
                }
                Some(Cmd::DebugDrop) => { room.abort().await; true }
                Some(Cmd::Wipe) | None => { room.close().await; return Ok(EndReason::Wiped) }
            },
        };
        if lost {
            match reconnect(&netw, room_url, &mut resume, cmds, &mut outbox, l).await? {
                Reconnect::Joined(ws) => {
                    room = *ws;
                    l.on_state(if chat.session.is_some() {
                        ChatState::Chatting
                    } else {
                        ChatState::Handshaking
                    });
                }
                Reconnect::End(r) => return Ok(r),
            }
        }
    }
}

/// How long the UI counts down while we try to get back in. The room is the
/// authority: once it has given up, resume attempts are rejected.
const RECONNECT_SECS: u32 = 180;

fn next_rotation(cfg: &Config) -> tokio::time::Instant {
    use rand::Rng;
    let secs = cfg
        .rotation_secs
        .map(u64::from)
        .unwrap_or_else(|| rand::thread_rng().gen_range(8 * 60..15 * 60));
    tokio::time::Instant::now() + std::time::Duration::from_secs(secs)
}

async fn join_room(
    netw: &net::Net,
    url: &str,
    ticket: &str,
) -> Result<(Ws, String, bool), EngineError> {
    let mut ws = Ws::connect(netw, url, &format!("t.{ticket}")).await?;
    match ws.recv().await? {
        ServerMsg::Joined {
            resume,
            peer_present,
        } => Ok((ws, resume, peer_present)),
        ServerMsg::Error(c) => Err(EngineError::Server(c)),
        _ => Err(EngineError::Protocol),
    }
}

enum Reconnect {
    Joined(Box<Ws>),
    End(EndReason),
}

async fn reconnect(
    netw: &net::Net,
    url: &str,
    resume: &mut String,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    outbox: &mut Vec<Cmd>,
    l: &dyn ChatListener,
) -> Result<Reconnect, EngineError> {
    use std::time::Duration;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(RECONNECT_SECS as u64);
    let mut backoff = Duration::from_millis(250);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Ok(Reconnect::End(EndReason::ConnectionLost));
        }
        l.on_state(ChatState::Reconnecting {
            seconds_left: left.as_secs() as u32,
        });
        match join_room(netw, url, resume).await {
            Ok((ws, r, _)) => {
                *resume = r;
                return Ok(Reconnect::Joined(Box::new(ws)));
            }
            // The room is closed or our ticket was superseded: it's over.
            Err(EngineError::Net(NetError::Rejected(_))) => {
                return Ok(Reconnect::End(EndReason::ConnectionLost))
            }
            Err(_) => {}
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff.min(left)) => {}
            c = cmds.recv() => match c {
                Some(c @ (Cmd::Send { .. } | Cmd::Foreground(_))) => outbox.push(c),
                Some(Cmd::DebugDrop) => {}
                Some(Cmd::Leave) => return Ok(Reconnect::End(EndReason::SelfLeft)),
                Some(Cmd::Wipe) | None => return Ok(Reconnect::End(EndReason::Wiped)),
            },
        }
        backoff = (backoff * 2).min(Duration::from_secs(8));
    }
}

/// Handshake/session state for one room.
struct Chat {
    role: Role,
    /// False while the room reports the peer as disconnected (no point sending cover traffic).
    peer_online: bool,
    frames: Arc<AtomicU64>,
    commit: Option<Handshake>,
    hs: Option<Handshaker>,
    session: Option<ChatSession>,
}

impl Chat {
    fn new(role: Role, frames: Arc<AtomicU64>) -> Self {
        let (hs, commit) = Handshaker::new(role);
        Self {
            role,
            peer_online: true,
            frames,
            commit: Some(commit),
            hs: Some(hs),
            session: None,
        }
    }

    /// Sent once both peers are in the room (frames to an absent peer are dropped).
    async fn send_commit(&mut self, room: &mut Ws) -> Result<(), EngineError> {
        if let Some(c) = self.commit.take() {
            room.send(&relay(&PeerEnvelope::Handshake(c))).await?;
        }
        Ok(())
    }

    async fn send_text(
        &mut self,
        room: &mut Ws,
        id: u64,
        body: &str,
        ttl_secs: u32,
    ) -> Result<(), EngineError> {
        let inner = Inner::Text {
            id,
            body: body.to_string(),
            ttl_secs,
        };
        self.send_inner(room, &inner).await
    }

    async fn send_chaff(&mut self, room: &mut Ws) -> Result<(), EngineError> {
        self.send_inner(room, &Inner::Chaff).await
    }

    async fn send_inner(&mut self, room: &mut Ws, inner: &Inner) -> Result<(), EngineError> {
        let Some(s) = self.session.as_mut() else {
            return Ok(());
        };
        let env = s.encrypt(inner)?;
        room.send(&relay(&env)).await?;
        self.frames.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Handle one server message. `Some` ends the chat.
    async fn on_server(
        &mut self,
        m: ServerMsg,
        room: &mut Ws,
        l: &dyn ChatListener,
    ) -> Result<Option<EndReason>, EngineError> {
        match m {
            ServerMsg::PeerJoined => self.send_commit(room).await?,
            ServerMsg::Relay(bytes) => {
                let env: PeerEnvelope =
                    postcard::from_bytes(&bytes).map_err(|_| EngineError::Protocol)?;
                self.on_envelope(env, room, l).await?;
            }
            ServerMsg::PeerLeft => return Ok(Some(EndReason::PeerLeft)),
            ServerMsg::PeerGone => return Ok(Some(EndReason::PeerGone)),
            ServerMsg::PeerDisconnected { grace_secs } => {
                self.peer_online = false;
                l.on_peer(PeerEvent::Disconnected { grace_secs })
            }
            ServerMsg::PeerReconnected => {
                self.peer_online = true;
                l.on_peer(PeerEvent::Reconnected)
            }
            ServerMsg::Error(c) => return Err(EngineError::Server(c)),
            ServerMsg::Rotate { .. } | ServerMsg::Joined { .. } | ServerMsg::Matched { .. } => {}
        }
        Ok(None)
    }

    /// After a rotation, read whatever was already queued on the old socket until
    /// the room closes it, so no frame is lost in the switch-over.
    async fn drain(
        &mut self,
        mut old: Ws,
        room: &mut Ws,
        l: &dyn ChatListener,
    ) -> Result<(), EngineError> {
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while let Ok(Ok(m)) = tokio::time::timeout_at(until, old.recv()).await {
            if let ServerMsg::Relay(_) | ServerMsg::PeerJoined = m {
                self.on_server(m, room, l).await?;
            }
        }
        Ok(())
    }

    fn established(&mut self, s: ChatSession, l: &dyn ChatListener) {
        l.on_sas(s.sas().emoji().iter().map(|e| e.to_string()).collect());
        l.on_state(ChatState::Chatting);
        self.session = Some(s);
    }

    async fn on_envelope(
        &mut self,
        env: PeerEnvelope,
        room: &mut Ws,
        l: &dyn ChatListener,
    ) -> Result<(), EngineError> {
        match env {
            PeerEnvelope::Handshake(h) => {
                let hs = self.hs.as_mut().ok_or(EngineError::Protocol)?;
                match hs.on_message(h)? {
                    Step::Send(m) => room.send(&relay(&PeerEnvelope::Handshake(m))).await?,
                    Step::Established { session, first } => {
                        room.send(&relay(&first)).await?;
                        self.hs = None;
                        self.established(*session, l);
                    }
                    Step::AwaitPreKey => {}
                }
            }
            env @ PeerEnvelope::Olm { .. } => {
                let inner = match self.session.as_mut() {
                    Some(s) => match s.decrypt(&env) {
                        Ok(i) => i,
                        // A single undecryptable frame (tampering, replay) is dropped.
                        Err(_) => return Ok(()),
                    },
                    None if self.role == Role::Responder => {
                        let hs = self.hs.take().ok_or(EngineError::Protocol)?;
                        let (s, inner) = hs.accept(&env)?;
                        self.established(s, l);
                        inner
                    }
                    None => return Err(EngineError::Protocol),
                };
                handle_inner(inner, l);
            }
        }
        Ok(())
    }
}

fn handle_inner(inner: Inner, l: &dyn ChatListener) {
    match inner {
        Inner::Text { id, body, ttl_secs } => {
            let body = Zeroizing::new(body);
            l.on_message(ChatMessage {
                id,
                body: body.to_string(),
                ttl_secs,
            });
        }
        Inner::ScreenCaptured => l.on_peer(PeerEvent::ScreenCaptured),
        Inner::Chaff | Inner::Ready | Inner::Ext { .. } => {}
    }
}
