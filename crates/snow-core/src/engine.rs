//! The per-chat async task: PoW → queue → room → handshake → chat.
use crate::api::*;
use crate::interests;
use crate::media::MediaStore;
use crate::net::{self, NetError, Ws};
use crate::pacer::{Item, Out, Pacer};
use crate::transcript::Transcript;
use crate::wallet::Wallet;
use snow_crypto::{ChatSession, CryptoError, Handshaker, Step};
use snow_proto::{ClientMsg, ErrorCode, Handshake, Inner, PeerEnvelope, Role, ServerMsg};
use snow_psi::Psi;
use std::collections::VecDeque;
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
    /// An encrypted control message for the peer (sent through the pacer).
    Control(Inner),
    /// A media offer followed by its chunks (bulk, in order).
    Media(Vec<Inner>),
    /// We opened a received item: tell the peer, and time our view.
    MediaOpened {
        id: u64,
        view_secs: u8,
    },
    Leave,
    /// Report the peer and leave (no content is sent to the server).
    Report,
    Wipe,
    /// Testing: kill the socket without a close frame, as a network drop would.
    DebugDrop,
    /// App moved to the foreground (`true`) or background (`false`).
    Foreground(bool),
    /// Testing: send `n` cover frames back-to-back, bypassing the pacer.
    DebugFlood(u32),
    /// VIP: ask the room to hold this chat for 24 h.
    Extend,
    /// VIP: seal the session under this key, disconnect without leaving, stop.
    Suspend(
        Zeroizing<[u8; 32]>,
        std::sync::mpsc::Sender<Result<Vec<u8>, CoreError>>,
    ),
}

/// Test/diagnostic counters.
#[derive(Default)]
pub struct Counters {
    /// Encrypted frames sent (text + chaff).
    pub sent: AtomicU64,
    /// Frames the room dropped for exceeding its rate cap.
    pub rate_limited: AtomicU64,
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
    #[error("config_key is not a 32-byte hex key")]
    BadConfigKey,
}

/// Plaintext state of one chat, reachable from the UI thread. Wiped when the
/// chat ends.
#[derive(Default)]
pub struct PerChat {
    pub transcript: std::sync::Mutex<Transcript>,
    pub media: std::sync::Mutex<MediaStore>,
}

impl PerChat {
    fn wipe(&self) {
        self.transcript.lock().unwrap().clear();
        self.media.lock().unwrap().clear();
    }
}

/// State shared by all chats of one `SnowClient`.
#[derive(Default, Clone)]
pub struct Shared {
    pub frames: Arc<Counters>,
    /// The current chat's plaintext state.
    pub chat: Arc<PerChat>,
    /// Anonymous tokens (persists across chats; the app saves it).
    pub wallet: Arc<std::sync::Mutex<Wallet>>,
    /// Last verified remote config and sponsor catalog.
    pub remote: Arc<std::sync::Mutex<crate::remote::Remote>>,
}

/// A chat that has ended for the UI but still owes the server our good-chat
/// claim (and, if the peer left first, our chance to report them).
struct Settle {
    room: Ws,
    req: snow_tokens::Request,
    claim: Vec<[u8; 32]>,
    /// `Some(secs)`: the peer left first; we may report them for `secs`, and
    /// haven't sent our claim yet. `None`: our claim is already sent.
    window: Option<u32>,
}

struct Outcome {
    reason: EndReason,
    settle: Option<Settle>,
}

impl From<EndReason> for Outcome {
    fn from(reason: EndReason) -> Self {
        Self {
            reason,
            settle: None,
        }
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Good-chat tokens needed for the trusted queue (matches the server's `TRUSTED_MIN`).
pub const TRUSTED_MIN: usize = 3;

/// Tokens to present at the matchmaker (postcard-encoded).
fn spend_tokens(cfg: &Config, shared: &Shared, l: &dyn ChatListener) -> Vec<Vec<u8>> {
    use snow_tokens::Kind;
    let epoch = snow_tokens::epoch(unix_now());
    let mut w = shared.wallet.lock().unwrap();
    let mut out = Vec::new();
    if cfg.trusted {
        out.extend(w.take(Kind::Good, TRUSTED_MIN, epoch).unwrap_or_default());
    }
    if cfg.paranoid {
        out.extend(w.take(Kind::Vip, 1, epoch).unwrap_or_default());
    }
    drop(w);
    if !out.is_empty() {
        l.on_wallet_changed();
    }
    out.iter()
        .map(|t| postcard::to_allocvec(t).expect("token serializes"))
        .collect()
}

/// Trade a purchase for VIP tokens (see `SnowClient::redeem_purchase`).
pub async fn redeem_purchase(
    cfg: Config,
    shared: Shared,
    l: Arc<dyn ChatListener>,
    store: PurchaseStore,
    proof: String,
) -> Result<u32, CoreError> {
    use sha2::{Digest, Sha256};
    use snow_proto::{VipRefusal, VipRequest, VipResponse};
    let purchase: [u8; 32] = Sha256::digest(proof.as_bytes()).into();
    let now_epoch = snow_tokens::epoch(unix_now());
    let (seed, epoch, created) = shared.wallet.lock().unwrap().pending(purchase, now_epoch);
    if created {
        // Persist the seed before anything is sent.
        l.on_wallet_changed();
    }
    let (mut req, blinded) =
        snow_tokens::request(snow_tokens::Kind::Vip, epoch, snow_tokens::MAX_BATCH, seed)
            .expect("valid batch");
    let body = postcard::to_allocvec(&VipRequest {
        store: match store {
            PurchaseStore::Apple => snow_proto::Store::Apple,
            PurchaseStore::Google => snow_proto::Store::Google,
        },
        epoch,
        proof,
        blinded,
    })
    .expect("serializes");
    let base = cfg.server_url.trim_end_matches('/');
    let dialer = dialer(&cfg, &shared, &*l)
        .await
        .map_err(|_| CoreError::Network)?;
    let netw = net::Net::new(base, &cfg.pins, dialer)
        .await
        .map_err(|_| CoreError::Network)?;
    let (status, resp) = crate::http::request(
        &netw.dialer,
        &netw.relay,
        "POST",
        "/tokens/vip",
        &[("content-type", "application/octet-stream")],
        &body,
    )
    .await
    .map_err(|_| CoreError::Network)?;
    let resp: VipResponse = match status {
        200 => postcard::from_bytes(&resp).map_err(|_| CoreError::Network)?,
        _ => return Err(CoreError::Network),
    };
    let done = |w: &mut Wallet| w.clear_pending(&purchase);
    match resp {
        VipResponse::Tokens {
            epoch: e,
            public_key,
            evaluated,
            proof,
        } => {
            let listed = shared.remote.lock().unwrap().token_key_ok(
                snow_config::TokenKind::Vip,
                e,
                &public_key,
                unix_now(),
            );
            let mut w = shared.wallet.lock().unwrap();
            if e != epoch
                || listed == Some(false)
                || w.pin(snow_tokens::Kind::Vip, e, public_key).is_err()
            {
                // A relay trying to tag this purchase. Keep the seed: nothing
                // better can come of a retry, but don't pretend it worked.
                return Err(CoreError::PurchaseInvalid);
            }
            let mut p = [0u8; 64];
            p[..32].copy_from_slice(&proof[0]);
            p[32..].copy_from_slice(&proof[1]);
            req.truncate(evaluated.len());
            let tokens = req
                .finish(&public_key, &evaluated, &p)
                .map_err(|_| CoreError::PurchaseInvalid)?;
            let n = tokens.len() as u32;
            w.add(tokens);
            done(&mut w);
            drop(w);
            l.on_wallet_changed();
            Ok(n)
        }
        VipResponse::Refused(r) => {
            done(&mut shared.wallet.lock().unwrap());
            l.on_wallet_changed();
            Err(match r {
                VipRefusal::Invalid => CoreError::PurchaseInvalid,
                VipRefusal::NotEligible => CoreError::PurchaseNotEligible,
                VipRefusal::AlreadyRedeemed => CoreError::PurchaseAlreadyRedeemed,
                VipRefusal::Unsupported => CoreError::StoreUnsupported,
            })
        }
    }
}

/// One VIP token for a room hold, if the wallet has one (else the room decides
/// by policy).
fn take_vip(shared: &Shared, l: &dyn ChatListener) -> Vec<Vec<u8>> {
    let epoch = snow_tokens::epoch(unix_now());
    let taken = shared
        .wallet
        .lock()
        .unwrap()
        .take(snow_tokens::Kind::Vip, 1, epoch)
        .unwrap_or_default();
    if !taken.is_empty() {
        l.on_wallet_changed();
    }
    taken
        .iter()
        .map(|t| postcard::to_allocvec(t).expect("token serializes"))
        .collect()
}

/// A fresh, unlinkable good-chat token request.
fn new_claim() -> (snow_tokens::Request, Vec<[u8; 32]>) {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let epoch = snow_tokens::epoch(unix_now());
    snow_tokens::request(snow_tokens::Kind::Good, epoch, 1, seed).expect("valid batch size")
}

/// After the chat: report or not (if the peer left first), then collect tokens.
async fn settle(
    mut s: Settle,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    wallet: &std::sync::Mutex<Wallet>,
    remote: &std::sync::Mutex<crate::remote::Remote>,
    l: &dyn ChatListener,
) {
    use std::time::Duration;
    if let Some(secs) = s.window {
        // Answer a little before the room's window closes.
        let until =
            tokio::time::Instant::now() + Duration::from_secs(secs.saturating_sub(1) as u64);
        let report = loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => break false,
                c = cmds.recv() => match c {
                    Some(Cmd::Report) => break true,
                    Some(Cmd::Wipe) => { s.room.abort().await; return }
                    Some(Cmd::Leave) | None => break false,
                    Some(_) => continue,
                },
            }
        };
        let claim = std::mem::take(&mut s.claim);
        let msg = if report {
            ClientMsg::Report { claim }
        } else {
            ClientMsg::Leave { claim }
        };
        if s.room.send(&msg).await.is_err() {
            return;
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let answer = loop {
        tokio::select! {
            m = tokio::time::timeout_at(deadline, s.room.recv()) => match m {
                Ok(Ok(m @ (ServerMsg::Tokens { .. } | ServerMsg::NoTokens))) => break Some(m),
                Ok(Ok(_)) => continue,
                _ => break None,
            },
            c = cmds.recv() => if matches!(c, Some(Cmd::Wipe)) { break None },
        }
    };
    if let Some(ServerMsg::Tokens {
        epoch,
        public_key,
        evaluated,
        proof,
    }) = answer
    {
        let mut p = [0u8; 64];
        p[..32].copy_from_slice(&proof[0]);
        p[32..].copy_from_slice(&proof[1]);
        // The proof binds the tokens to `public_key`. The key must be the one the
        // signed config lists for this epoch, or (without a config) the first
        // one we saw: either way the server can't tag us with a key of our own.
        let listed = remote.lock().unwrap().token_key_ok(
            snow_config::TokenKind::Good,
            epoch,
            &public_key,
            unix_now(),
        );
        let mut w = wallet.lock().unwrap();
        if listed != Some(false) && w.pin(snow_tokens::Kind::Good, epoch, public_key).is_ok() {
            if let Ok(tokens) = s.req.finish(&public_key, &evaluated, &p) {
                w.add(tokens);
                drop(w);
                l.on_wallet_changed();
            }
        }
    }
    s.room.close().await;
}

/// Direct, or Tor through the local SOCKS5 proxy (fresh circuit per chat).
async fn dialer(
    cfg: &Config,
    _shared: &Shared,
    l: &dyn ChatListener,
) -> Result<net::Dialer, EngineError> {
    let Some(proxy) = &cfg.socks_proxy else {
        return Ok(net::Dialer::Direct);
    };
    l.on_state(ChatState::ConnectingTor);
    Ok(net::Dialer::Socks(crate::socks::Socks::isolated(proxy)?))
}

/// Run one chat: a new match, or (`saved`) a VIP session resumed from disk.
pub async fn run(
    cfg: Config,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    l: Arc<dyn ChatListener>,
    shared: Shared,
    saved: Option<(crate::saved::Saved, ChatSession)>,
) {
    let per_chat = shared.chat.clone();
    let wallet = shared.wallet.clone();
    let remote = shared.remote.clone();
    let res = match saved {
        None => run_inner(&cfg, &mut cmds, &*l, shared).await,
        Some((s, session)) => run_resumed(&cfg, &mut cmds, &*l, shared, s, session).await,
    };
    let out = match res {
        Ok(o) => o,
        Err(e) => EndReason::Error {
            message: e.to_string(),
        }
        .into(),
    };
    // The chat is over: zeroize its plaintext before telling the UI.
    per_chat.wipe();
    l.on_state(ChatState::Ended { reason: out.reason });
    if let Some(s) = out.settle {
        settle(s, &mut cmds, &wallet, &remote, &*l).await;
    }
}

/// Up to three sponsor cards for our (non-adult) tags, picked locally.
fn sponsors(cfg: &Config, shared: &Shared) -> Vec<SponsorCard> {
    let r = shared.remote.lock().unwrap();
    let Some(c) = r.catalog(unix_now()) else {
        return Vec::new();
    };
    c.select(&cfg.tags, 3, rand::random())
        .into_iter()
        .map(|s| SponsorCard {
            id: s.id,
            title: s.title,
            body: s.body,
            url: s.url,
        })
        .collect()
}

fn relay(env: &PeerEnvelope) -> ClientMsg {
    ClientMsg::Relay(postcard::to_allocvec(env).expect("envelope serializes"))
}

async fn run_inner(
    cfg: &Config,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    l: &dyn ChatListener,
    shared: Shared,
) -> Result<Outcome, EngineError> {
    let base = cfg.server_url.trim_end_matches('/');
    let bucket = interests::bucket(cfg, unix_now());

    // 1. Proof of work.
    l.on_state(ChatState::SolvingPow);
    let dialer = dialer(cfg, &shared, l).await?;
    let netw = net::Net::new(base, &cfg.pins, dialer).await?;
    if let Some(k) = &cfg.config_key {
        let key = crate::remote::parse_key(k).ok_or(EngineError::BadConfigKey)?;
        crate::remote::refresh(&netw, &key, &shared.remote, unix_now()).await;
    }
    let challenge = net::fetch_pow(&netw, bucket).await?;
    let c = snow_pow::Challenge::from_bytes(&challenge).map_err(|_| EngineError::Protocol)?;
    let nonce = tokio::task::spawn_blocking(move || c.solve())
        .await
        .map_err(|_| EngineError::Protocol)?;

    // 2. Matchmaking. Tokens are taken from the wallet only now, right before
    // they're sent; once the matchmaker has them they're spent either way.
    let spend = spend_tokens(cfg, &shared, l);
    l.on_state(ChatState::Queued);
    l.on_sponsors(sponsors(cfg, &shared));
    let mut mm = Ws::connect(&netw, "/match", &format!("b.{bucket}")).await?;
    mm.send(&ClientMsg::Join {
        pow: snow_proto::PowSolution { challenge, nonce },
        bucket: (bucket != interests::RANDOM_BUCKET).then_some(bucket),
        paranoid: cfg.paranoid,
        trusted: cfg.trusted,
        spend,
    })
    .await?;
    let (ticket, role, paranoid, trusted) = loop {
        tokio::select! {
            m = mm.recv() => match m? {
                ServerMsg::Matched { ticket, role, paranoid, trusted } => break (ticket, role, paranoid, trusted),
                ServerMsg::Error(c) => return Err(EngineError::Server(c)),
                _ => return Err(EngineError::Protocol),
            },
            c = cmds.recv() => match c {
                Some(Cmd::Send { .. } | Cmd::Control(_) | Cmd::Media(_) | Cmd::MediaOpened { .. } | Cmd::DebugDrop | Cmd::DebugFlood(_) | Cmd::Foreground(_) | Cmd::Extend | Cmd::Suspend(..)) => continue,
                Some(Cmd::Wipe) => { mm.close().await; return Ok(EndReason::Wiped.into()) }
                Some(Cmd::Leave | Cmd::Report) | None => { mm.close().await; return Ok(EndReason::Cancelled.into()) }
            },
        }
    };
    mm.close().await;

    // 3. Room + handshake + chat.
    let paranoid = paranoid && cfg.paranoid;
    l.on_state(ChatState::Handshaking { paranoid, trusted });
    let room_url = "/room";
    let (mut room, resume, peer_present) = join_room(&netw, room_url, &ticket).await?;
    let mut chat = Chat::new(role, shared.clone(), cfg);
    if peer_present {
        chat.send_commit(&mut room).await?;
    }
    chat_loop(
        cfg, cmds, l, &shared, &netw, room, resume, chat, paranoid, trusted,
    )
    .await
}

/// Re-enter the room of a saved session with its resume ticket.
async fn run_resumed(
    cfg: &Config,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    l: &dyn ChatListener,
    shared: Shared,
    saved: crate::saved::Saved,
    session: ChatSession,
) -> Result<Outcome, EngineError> {
    let base = cfg.server_url.trim_end_matches('/');
    let dialer = dialer(cfg, &shared, l).await?;
    let netw = net::Net::new(base, &cfg.pins, dialer).await?;
    l.on_state(ChatState::Reconnecting {
        seconds_left: RECONNECT_SECS,
    });
    let (room, resume, _) = match join_room(&netw, "/room", &saved.resume).await {
        Ok(j) => j,
        // The hold ran out, or the peer left: the room is gone.
        Err(EngineError::Net(NetError::Rejected(_))) => return Ok(EndReason::ConnectionLost.into()),
        Err(e) => return Err(e),
    };
    let mut chat = Chat::new(saved.role, shared.clone(), cfg);
    chat.restore(session, l);
    chat_loop(
        cfg,
        cmds,
        l,
        &shared,
        &netw,
        room,
        resume,
        chat,
        saved.paranoid,
        saved.trusted,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn chat_loop(
    cfg: &Config,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    l: &dyn ChatListener,
    shared: &Shared,
    netw: &net::Net,
    mut room: Ws,
    mut resume: String,
    mut chat: Chat,
    paranoid: bool,
    trusted: bool,
) -> Result<Outcome, EngineError> {
    let room_url = "/room";
    let mut rotate_at = next_rotation(cfg);
    let mut outbox: Vec<Cmd> = Vec::new();
    // Without a paranoid grant there is no cover traffic: the room would rate-limit
    // it, and idle rooms must be able to hibernate.
    let chaff_ms = cfg
        .chaff_ms
        .or_else(|| shared.remote.lock().unwrap().chaff_ms(unix_now()));
    let mut pacer = Pacer::new(if paranoid { chaff_ms } else { Some(0) });
    let mut foreground = true;

    loop {
        // Protocol messages the chat wants to send (PSI, profile) go through the
        // pacer like everything else.
        while let Some(i) = chat.outgoing.pop_front() {
            pacer.push(Item::Control(i));
        }
        // Anything typed while we were reconnecting goes back into the queue.
        for c in std::mem::take(&mut outbox) {
            match c {
                Cmd::Send { id, body, ttl_secs } => pacer.push(Item::Text { id, body, ttl_secs }),
                Cmd::Control(i) => pacer.push(Item::Control(i)),
                Cmd::Media(items) => pacer.push_bulk(items.into_iter().map(Item::Control)),
                Cmd::MediaOpened { id, view_secs } => chat.media_opened(id, view_secs, &mut pacer),
                Cmd::Foreground(f) => foreground = f,
                _ => {}
            }
        }
        let cover = foreground && chat.peer_online;
        let next_burn = [
            shared.chat.transcript.lock().unwrap().next_burn(),
            chat.media_deadlines.iter().map(|(t, _)| *t).min(),
        ]
        .into_iter()
        .flatten()
        .min();
        let lost = tokio::select! {
            out = pacer.next(cover), if chat.session.is_some() => match out {
                Out::Send(Item::Text { id, body, ttl_secs }) => chat.send_text(&mut room, id, &body, ttl_secs).await.is_err(),
                Out::Send(Item::Control(i)) => chat.send_inner(&mut room, &i).await.is_err(),
                Out::Chaff => chat.send_chaff(&mut room).await.is_err(),
            },
            _ = tokio::time::sleep_until(next_burn.unwrap_or_else(tokio::time::Instant::now)), if next_burn.is_some() => {
                let now = tokio::time::Instant::now();
                let burned = shared.chat.transcript.lock().unwrap().burn_due(now);
                for (id, from_me) in burned {
                    l.on_burn(id, from_me);
                }
                chat.media_deadlines.retain(|(t, id)| {
                    let due = *t <= now;
                    if due {
                        l.on_media_burned(*id, false);
                    }
                    !due
                });
                false
            }
            m = room.recv() => match m {
                Ok(m) => match chat.on_server(m, &mut room, l).await? {
                    Some(EndReason::PeerLeft) => {
                        // Still connected: we may report them, and we claim our token.
                        let (req, claim) = new_claim();
                        let window = Some(chat.report_secs);
                        return Ok(Outcome {
                            reason: EndReason::PeerLeft,
                            settle: Some(Settle { room, req, claim, window }),
                        });
                    }
                    Some(end) => return Ok(end.into()),
                    None => false,
                },
                Err(NetError::Closed | NetError::Io(_)) => true,
                Err(e) => return Err(e.into()),
            },
            _ = tokio::time::sleep_until(rotate_at) => {
                // Session-ID rotation: enter the same slot on a fresh socket with
                // the resume ticket; the room then revokes the old socket and ticket.
                if let Ok((new, r, _)) = join_room(netw, room_url, &resume).await {
                    let old = std::mem::replace(&mut room, new);
                    resume = r;
                    chat.drain(old, &mut room, l).await?;
                }
                rotate_at = next_rotation(cfg);
                false
            }
            c = cmds.recv() => match c {
                Some(Cmd::Send { id, body, ttl_secs }) => { pacer.push(Item::Text { id, body, ttl_secs }); false }
                Some(Cmd::Control(i)) => { pacer.push(Item::Control(i)); false }
                Some(Cmd::Media(items)) => { pacer.push_bulk(items.into_iter().map(Item::Control)); false }
                Some(Cmd::MediaOpened { id, view_secs }) => { chat.media_opened(id, view_secs, &mut pacer); false }
                Some(Cmd::Foreground(f)) => { foreground = f; false }
                Some(c @ (Cmd::Leave | Cmd::Report)) => {
                    let report = matches!(c, Cmd::Report);
                    let (req, claim) = new_claim();
                    let msg = if report {
                        ClientMsg::Report { claim: claim.clone() }
                    } else {
                        ClientMsg::Leave { claim: claim.clone() }
                    };
                    let _ = room.send(&msg).await;
                    let reason = if report { EndReason::Reported } else { EndReason::SelfLeft };
                    return Ok(Outcome {
                        reason,
                        settle: Some(Settle { room, req, claim, window: None }),
                    });
                }
                Some(Cmd::DebugDrop) => { room.abort().await; true }
                Some(Cmd::DebugFlood(n)) => {
                    let mut lost = false;
                    for _ in 0..n {
                        lost |= chat.send_chaff(&mut room).await.is_err();
                    }
                    lost
                }
                Some(Cmd::Extend) => {
                    let spend = take_vip(shared, l);
                    room.send(&ClientMsg::Extend { spend }).await.is_err()
                }
                Some(Cmd::Suspend(key, reply)) => match chat.save(&resume, &key, paranoid, trusted) {
                    Ok(blob) => {
                        // No `Leave`: the room keeps our slot for the rest of the hold.
                        room.abort().await;
                        let _ = reply.send(Ok(blob));
                        return Ok(EndReason::Suspended.into());
                    }
                    Err(e) => { let _ = reply.send(Err(e)); false }
                },
                Some(Cmd::Wipe) | None => { room.close().await; return Ok(EndReason::Wiped.into()) }
            },
        };
        if let Some(end) = chat.ending.take() {
            let _ = room.send(&ClientMsg::Leave { claim: Vec::new() }).await;
            room.close().await;
            return Ok(end.into());
        }
        if lost {
            match reconnect(netw, room_url, &mut resume, cmds, &mut outbox, l).await? {
                Reconnect::Joined(ws) => {
                    room = *ws;
                    l.on_state(if chat.session.is_some() {
                        ChatState::Chatting
                    } else {
                        ChatState::Handshaking { paranoid, trusted }
                    });
                }
                Reconnect::End(r) => return Ok(r.into()),
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
                Some(c @ (Cmd::Send { .. } | Cmd::Control(_) | Cmd::Media(_) | Cmd::MediaOpened { .. } | Cmd::Foreground(_))) => outbox.push(c),
                // A suspend request's reply sender is dropped: "not chatting".
                Some(Cmd::DebugDrop | Cmd::DebugFlood(_) | Cmd::Extend | Cmd::Suspend(..)) => {}
                Some(Cmd::Leave | Cmd::Report) => return Ok(Reconnect::End(EndReason::SelfLeft)),
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
    shared: Shared,
    /// Normalized tags for the PSI (empty = we don't care about interests).
    tags: Vec<String>,
    require_common_tag: bool,
    profile: Option<snow_proto::Profile>,
    psi: Option<Psi>,
    /// Encrypted control messages waiting for the pacer.
    outgoing: VecDeque<Inner>,
    /// Set when the chat decides to end itself (e.g. no common tags).
    ending: Option<EndReason>,
    /// When each opened media item's view time runs out.
    media_deadlines: Vec<(tokio::time::Instant, u64)>,
    /// From `PeerLeft`: how long we may still report the peer.
    report_secs: u32,
    /// The room is held for 24 h (VIP); the session may be saved.
    extended: bool,
    commit: Option<Handshake>,
    hs: Option<Handshaker>,
    session: Option<ChatSession>,
}

impl Chat {
    fn new(role: Role, shared: Shared, cfg: &Config) -> Self {
        let (hs, commit) = Handshaker::new(role);
        Self {
            role,
            peer_online: true,
            shared,
            tags: interests::psi_tags(cfg),
            require_common_tag: cfg.require_common_tag,
            profile: cfg.profile.as_ref().map(interests::to_wire),
            psi: None,
            outgoing: VecDeque::new(),
            ending: None,
            media_deadlines: Vec::new(),
            report_secs: 0,
            extended: false,
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
        self.shared.frames.sent.fetch_add(1, Ordering::Relaxed);
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
            ServerMsg::PeerLeft { report_secs } => {
                self.report_secs = report_secs;
                return Ok(Some(EndReason::PeerLeft));
            }
            ServerMsg::PeerGone => return Ok(Some(EndReason::PeerGone)),
            ServerMsg::PeerDisconnected { grace_secs } => {
                self.peer_online = false;
                l.on_peer(PeerEvent::Disconnected { grace_secs })
            }
            ServerMsg::PeerReconnected => {
                self.peer_online = true;
                l.on_peer(PeerEvent::Reconnected)
            }
            // The room dropped a frame over its rate cap. Olm tolerates the gap;
            // our pacer stays under the cap, so this means a misconfiguration.
            ServerMsg::Error(ErrorCode::RateLimited) => {
                self.shared
                    .frames
                    .rate_limited
                    .fetch_add(1, Ordering::Relaxed);
            }
            ServerMsg::Extended { hold_secs, by_me } => {
                self.extended = true;
                l.on_peer(PeerEvent::Extended { hold_secs, by_me });
            }
            ServerMsg::Error(ErrorCode::NotAllowed) => l.on_peer(PeerEvent::ExtendRefused),
            ServerMsg::Error(c) => return Err(EngineError::Server(c)),
            ServerMsg::Rotate { .. }
            | ServerMsg::Joined { .. }
            | ServerMsg::Matched { .. }
            | ServerMsg::Tokens { .. }
            | ServerMsg::NoTokens => {}
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
        if !self.tags.is_empty() {
            self.start_psi();
        }
        if let Some(p) = self.profile.take() {
            self.outgoing.push_back(Inner::Profile(p));
        }
    }

    /// Continue a saved session: no handshake, PSI or profile this time.
    fn restore(&mut self, s: ChatSession, l: &dyn ChatListener) {
        self.hs = None;
        self.commit = None;
        self.tags.clear();
        self.profile = None;
        self.extended = true;
        l.on_sas(s.sas().emoji().iter().map(|e| e.to_string()).collect());
        l.on_state(ChatState::Chatting);
        self.session = Some(s);
    }

    fn save(
        &self,
        resume: &str,
        key: &[u8; 32],
        paranoid: bool,
        trusted: bool,
    ) -> Result<Vec<u8>, CoreError> {
        let session = self.session.as_ref().ok_or(CoreError::NotChatting)?;
        if !self.extended {
            return Err(CoreError::NotExtended);
        }
        let keys = crate::saved::Keys::derive(key);
        let saved = crate::saved::Saved {
            resume: resume.to_string(),
            role: self.role,
            paranoid,
            trusted,
            session: session.save(&keys.pickle).to_string(),
            messages: self.shared.chat.transcript.lock().unwrap().lasting(),
        };
        Ok(saved.seal(&keys))
    }

    fn media_opened(&mut self, id: u64, view_secs: u8, pacer: &mut Pacer) {
        pacer.push(Item::Control(Inner::MediaBurned { media_id: id }));
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(view_secs as u64);
        self.media_deadlines.push((until, id));
    }

    fn start_psi(&mut self) {
        if self.psi.is_none() {
            let (psi, round1) = Psi::new(&self.tags);
            self.psi = Some(psi);
            self.outgoing.push_back(Inner::PsiRound1(round1));
        }
    }

    /// A decrypted peer message.
    fn on_inner(&mut self, inner: Inner, l: &dyn ChatListener) {
        match inner {
            Inner::Text { id, body, ttl_secs } => {
                let body = Zeroizing::new(body);
                let safety = crate::screening::screen(&body);
                let msg = ChatMessage {
                    id,
                    from_me: false,
                    body: body.to_string(),
                    ttl_secs,
                    safety: safety.level,
                    safety_flags: safety.flags.clone(),
                };
                self.shared
                    .chat
                    .transcript
                    .lock()
                    .unwrap()
                    .push(id, false, body, ttl_secs, safety);
                l.on_message(msg);
            }
            Inner::ScreenCaptured => l.on_peer(PeerEvent::ScreenCaptured),
            Inner::PsiRound1(points) => {
                // Answer even if we have no tags (we then send only padding), so
                // the peer's run always completes and our tag count stays hidden.
                self.start_psi();
                let psi = self.psi.as_mut().expect("just started");
                if let Ok(round2) = psi.respond(&points) {
                    self.outgoing.push_back(Inner::PsiRound2(round2));
                }
            }
            Inner::PsiRound2(points) => {
                let Some(common) = self.psi.as_ref().and_then(|p| p.finish(&points).ok()) else {
                    return;
                };
                self.psi = None;
                let none = common.is_empty();
                l.on_common_tags(common);
                if none && self.require_common_tag && !self.tags.is_empty() {
                    self.ending = Some(EndReason::NoCommonTags);
                }
            }
            Inner::Profile(p) => l.on_profile(interests::from_wire(p)),
            Inner::MediaOffer {
                media_id,
                kind,
                len,
                chunks,
                key,
                view_secs,
            } => self
                .shared
                .chat
                .media
                .lock()
                .unwrap()
                .offer(media_id, kind, len, chunks, key, view_secs),
            Inner::MediaChunk {
                media_id,
                index,
                data,
            } => {
                let done = self
                    .shared
                    .chat
                    .media
                    .lock()
                    .unwrap()
                    .chunk(media_id, index, data);
                if let Some(info) = done {
                    l.on_media(info);
                }
            }
            Inner::MediaBurned { media_id } => l.on_media_burned(media_id, true),
            Inner::Chaff | Inner::Ready | Inner::Ext { .. } => {}
        }
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
                self.on_inner(inner, l);
            }
        }
        Ok(())
    }
}
