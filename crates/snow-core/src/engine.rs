//! The per-chat async task: PoW → queue → room → handshake → chat.
use crate::api::*;
use crate::net::{self, NetError, Ws};
use snow_crypto::{ChatSession, CryptoError, Handshaker, Step};
use snow_proto::{ClientMsg, Handshake, Inner, PeerEnvelope, Role, ServerMsg};
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

pub async fn run(cfg: Config, mut cmds: mpsc::UnboundedReceiver<Cmd>, l: Arc<dyn ChatListener>) {
    let reason = match run_inner(&cfg, &mut cmds, &*l).await {
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
) -> Result<EndReason, EngineError> {
    let base = cfg.server_url.trim_end_matches('/');
    let bucket = cfg.bucket.unwrap_or(255);

    // 1. Proof of work.
    l.on_state(ChatState::SolvingPow);
    let challenge = net::fetch_pow(&net::http_client(), base, bucket).await?;
    let c = snow_pow::Challenge::from_bytes(&challenge).map_err(|_| EngineError::Protocol)?;
    let nonce = tokio::task::spawn_blocking(move || c.solve())
        .await
        .map_err(|_| EngineError::Protocol)?;

    // 2. Matchmaking.
    l.on_state(ChatState::Queued);
    let mut mm = Ws::connect(&net::ws_url(base, "/match"), &format!("b.{bucket}")).await?;
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
                Some(Cmd::Send { .. }) => continue,
                Some(Cmd::Wipe) => { mm.close().await; return Ok(EndReason::Wiped) }
                Some(Cmd::Leave) | None => { mm.close().await; return Ok(EndReason::Cancelled) }
            },
        }
    };
    mm.close().await;

    // 3. Room + handshake + chat.
    l.on_state(ChatState::Handshaking);
    let mut room = Ws::connect(&net::ws_url(base, "/room"), &format!("t.{ticket}")).await?;
    let peer_present = match room.recv().await? {
        ServerMsg::Joined { peer_present, .. } => peer_present,
        ServerMsg::Error(c) => return Err(EngineError::Server(c)),
        _ => return Err(EngineError::Protocol),
    };
    let mut chat = Chat::new(role);
    if peer_present {
        chat.send_commit(&mut room).await?;
    }

    loop {
        tokio::select! {
            m = room.recv() => match m? {
                ServerMsg::PeerJoined => chat.send_commit(&mut room).await?,
                ServerMsg::Relay(bytes) => {
                    let env: PeerEnvelope = postcard::from_bytes(&bytes).map_err(|_| EngineError::Protocol)?;
                    chat.on_envelope(env, &mut room, l).await?;
                }
                ServerMsg::PeerLeft => return Ok(EndReason::PeerLeft),
                ServerMsg::PeerGone => return Ok(EndReason::PeerGone),
                ServerMsg::PeerDisconnected { grace_secs } => l.on_peer(PeerEvent::Disconnected { grace_secs }),
                ServerMsg::PeerReconnected => l.on_peer(PeerEvent::Reconnected),
                ServerMsg::Error(c) => return Err(EngineError::Server(c)),
                ServerMsg::Rotate { .. } | ServerMsg::Joined { .. } | ServerMsg::Matched { .. } => {}
            },
            c = cmds.recv() => match c {
                Some(Cmd::Send { id, body, ttl_secs }) => {
                    if let Some(s) = chat.session.as_mut() {
                        let env = s.encrypt(&Inner::Text { id, body: body.to_string(), ttl_secs })?;
                        room.send(&relay(&env)).await?;
                    }
                }
                Some(Cmd::Leave) => {
                    room.send(&ClientMsg::Leave).await?;
                    room.close().await;
                    return Ok(EndReason::SelfLeft);
                }
                Some(Cmd::Wipe) | None => { room.close().await; return Ok(EndReason::Wiped) }
            },
        }
    }
}

/// Handshake/session state for one room.
struct Chat {
    role: Role,
    commit: Option<Handshake>,
    hs: Option<Handshaker>,
    session: Option<ChatSession>,
}

impl Chat {
    fn new(role: Role) -> Self {
        let (hs, commit) = Handshaker::new(role);
        Self {
            role,
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
