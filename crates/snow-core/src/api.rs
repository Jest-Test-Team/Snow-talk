use crate::engine::PerChat;
use crate::engine::{self, Cmd};
use crate::screening::Safety;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// Client configuration.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Config {
    /// e.g. `https://relay.snowtalk.app` (or `http://127.0.0.1:8787` for development).
    pub server_url: String,
    /// Interest bucket `0..64`, or `None` for random matching.
    #[uniffi(default = None)]
    pub bucket: Option<u8>,
    /// Session-ID rotation period. `None` = random 8–15 minutes.
    #[uniffi(default = None)]
    pub rotation_secs: Option<u32>,
    /// Ask for paranoid mode (VIP): constant-rate cover traffic. Spends one VIP
    /// token if the wallet has one. Only takes effect if the server grants it —
    /// see [`ChatState::Handshaking::paranoid`].
    #[uniffi(default = false)]
    pub paranoid: bool,
    /// Use the trusted queue: spends `TRUSTED_MIN` (3) good-chat tokens and is
    /// only matched with others who did the same. Ignored if the wallet has fewer.
    #[uniffi(default = false)]
    pub trusted: bool,
    /// Paranoid-mode cover-traffic period in ms. `None` = the remote config's
    /// value, else 1500 ms; `Some(0)` = off. Ignored unless paranoid is granted.
    #[uniffi(default = None)]
    pub chaff_ms: Option<u32>,
    /// Interest tags (free text, normalized; at most 16 are used). The first one
    /// picks the server-visible bucket unless `bucket` is set; all of them are
    /// compared privately with the peer after matching (PSI).
    #[uniffi(default = [])]
    pub tags: Vec<String>,
    /// Adult interest tags. Only used by builds with the `adult_tags` feature
    /// (Android / sideload); they only ever match other adult tags.
    #[uniffi(default = [])]
    pub adult_tags: Vec<String>,
    /// With tags set: leave automatically if the PSI finds nothing in common
    /// (`EndReason::NoCommonTags`), so the UI can queue again.
    #[uniffi(default = true)]
    pub require_common_tag: bool,
    /// Ephemeral persona sent to the peer (E2EE) once the chat starts.
    #[uniffi(default = None)]
    pub profile: Option<UserProfile>,
    /// Base64 SHA-256 SPKI pins for the relay's TLS chain. Empty = no pinning (dev only).
    #[uniffi(default = [])]
    pub pins: Vec<String>,
    /// Hex Ed25519 public key the remote config must be signed with (compiled
    /// into the app). `None` = don't fetch remote config (development).
    #[uniffi(default = None)]
    pub config_key: Option<String>,
    /// Tor mode: a private app directory for Arti's consensus/guard state.
    /// `None` = direct connections. Requires a build with the `tor` feature.
    #[uniffi(default = None)]
    pub tor_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum EndReason {
    /// We pressed "leave".
    SelfLeft,
    /// The peer pressed "leave".
    PeerLeft,
    /// The peer dropped and never came back.
    PeerGone,
    /// We cancelled before being matched.
    Cancelled,
    /// Our connection dropped and couldn't be restored within the grace period.
    ConnectionLost,
    /// Panic button: everything was wiped.
    Wiped,
    /// The private tag comparison found nothing in common; we left.
    NoCommonTags,
    /// We reported the peer and left.
    Reported,
    /// VIP: the session was saved with [`SnowClient::suspend`]; the room holds
    /// our slot until the hold ends. Resume with [`SnowClient::resume_saved`].
    Suspended,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ChatState {
    /// Tor mode: bootstrapping or building a circuit (can take several seconds).
    ConnectingTor,
    SolvingPow,
    Queued,
    /// Matched; setting up encryption. `paranoid` = cover traffic is active
    /// (requested and granted by the server).
    Handshaking {
        paranoid: bool,
        /// Both of us came through the trusted queue.
        trusted: bool,
    },
    Chatting,
    /// Our own connection dropped; retrying with the resume ticket.
    Reconnecting {
        seconds_left: u32,
    },
    Ended {
        reason: EndReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PeerEvent {
    Disconnected {
        grace_secs: u32,
    },
    Reconnected,
    ScreenCaptured,
    /// The room is held for `hold_secs` (VIP). `by_me = false`: the peer did
    /// it and may keep an encrypted copy of this chat on their device; the UI
    /// must say so.
    Extended {
        hold_secs: u32,
        by_me: bool,
    },
    /// Our [`SnowClient::extend_chat`] was refused (no VIP token).
    ExtendRefused,
}

/// Ephemeral, per-chat persona. Never stored; only the peer sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct UserProfile {
    #[uniffi(default = None)]
    pub nickname: Option<String>,
    /// e.g. "INFP".
    #[uniffi(default = None)]
    pub mbti: Option<String>,
    /// Today's mood.
    #[uniffi(default = None)]
    pub mood: Option<String>,
    /// Open to adult topics. Always `false` in builds without `adult_tags`.
    #[uniffi(default = false)]
    pub adult_ok: bool,
}

/// On-device screening result for a received message (never sent anywhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SafetyLevel {
    Clean,
    /// Show with a warning ("對方可能想引導你到其他平台／談錢").
    Caution,
    /// Blur until tapped: "此訊息可能含有不當內容，點擊以檢視".
    Blur,
}

/// Why a message was flagged, so the UI can explain it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SafetyFlag {
    Link,
    Shortener,
    LineId,
    Telegram,
    Phone,
    Email,
    Crypto,
    Wallet,
    Investment,
    MoneyTransfer,
    GiftCard,
    Gambling,
    Solicitation,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatMessage {
    /// Unique per side: `(id, from_me)` identifies a message.
    pub id: u64,
    pub from_me: bool,
    pub body: String,
    pub ttl_secs: u32,
    /// Always `Clean` for our own messages.
    pub safety: SafetyLevel,
    pub safety_flags: Vec<SafetyFlag>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MediaType {
    Image,
    Voice,
}

/// A flash photo / voice note that has fully arrived and can be opened once.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MediaInfo {
    pub id: u64,
    pub kind: MediaType,
    /// How long it may be shown once opened (1–10 s).
    pub view_secs: u8,
}

/// A sponsored card for the waiting screen, chosen on the device from the
/// whole catalog (the server never learns which one was shown).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SponsorCard {
    pub id: String,
    pub title: String,
    pub body: String,
    /// `https://` link with no query string. Opening it is the user's choice and
    /// tells the sponsor only what any visit would.
    pub url: String,
}

/// Where a purchase was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PurchaseStore {
    /// StoreKit 2: pass `Transaction.jwsRepresentation`.
    Apple,
    /// Play Billing: pass the purchase token (not supported by the relay yet).
    Google,
}

/// Feature switches from the signed remote config.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RemoteFeatures {
    pub version: u64,
    pub donations: bool,
    pub lightning: bool,
    pub voice: bool,
    pub photos: bool,
    /// Show purchase screens (off during the free beta).
    pub iap: bool,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("no active chat")]
    NotChatting,
    #[error("message too long")]
    TooLong,
    #[error("unsupported, corrupt or too large media")]
    BadMedia,
    #[error("media already opened or not available")]
    MediaGone,
    #[error("wallet data is corrupt")]
    BadWallet,
    #[error("the chat must be extended (VIP) before it can be saved")]
    NotExtended,
    #[error("key must be 32 bytes")]
    BadKey,
    #[error("saved session is corrupt or the key is wrong")]
    BadSavedSession,
    #[error("network error")]
    Network,
    #[error("the purchase proof is not genuine")]
    PurchaseInvalid,
    #[error("this purchase doesn't buy VIP tokens (other app or product, refunded, or sandbox)")]
    PurchaseNotEligible,
    #[error("this purchase was already exchanged for tokens")]
    PurchaseAlreadyRedeemed,
    #[error("this store isn't supported yet")]
    StoreUnsupported,
}

/// Implemented by the UI (Swift / Kotlin) to receive events. Called from a background thread.
#[uniffi::export(with_foreign)]
pub trait ChatListener: Send + Sync {
    fn on_state(&self, state: ChatState);
    /// Seven emoji both users can compare to rule out a man-in-the-middle.
    fn on_sas(&self, emoji: Vec<String>);
    fn on_message(&self, message: ChatMessage);
    fn on_peer(&self, event: PeerEvent);
    /// A burn-after-reading timer expired: remove this message from the screen.
    fn on_burn(&self, id: u64, from_me: bool);
    /// Result of the private tag comparison: the tags you share (normalized;
    /// adult ones are prefixed `18+:`). Empty = nothing in common.
    fn on_common_tags(&self, tags: Vec<String>);
    /// The peer's ephemeral profile.
    fn on_profile(&self, profile: UserProfile);
    /// A flash photo / voice note arrived; show a placeholder that opens it via
    /// [`SnowClient::open_media`].
    fn on_media(&self, media: MediaInfo);
    /// A media item is gone: `from_me = false` → our view time is up, stop
    /// showing it now; `from_me = true` → the peer opened what we sent.
    fn on_media_burned(&self, id: u64, from_me: bool);
    /// Tokens were added or spent: persist [`SnowClient::wallet_export`] now
    /// (Keychain / Keystore). This is the only state the app should keep.
    fn on_wallet_changed(&self);
    /// While queued: sponsored cards matching our tags (may be empty). Remove
    /// them once matched.
    fn on_sponsors(&self, cards: Vec<SponsorCard>);
}

/// One chat client. A new chat calls [`SnowClient::start_match`] again; every
/// chat uses fresh keys.
#[derive(uniffi::Object)]
pub struct SnowClient {
    rt: tokio::runtime::Runtime,
    cfg: Config,
    listener: Arc<dyn ChatListener>,
    cmd: Mutex<Option<mpsc::UnboundedSender<Cmd>>>,
    next_id: AtomicU64,
    shared: engine::Shared,
    /// The current chat's transcript and media; replaced on every `start_match`,
    /// so an old chat that ends late can't wipe the new one's.
    chat: Mutex<Arc<PerChat>>,
}

#[uniffi::export]
impl SnowClient {
    #[uniffi::constructor]
    pub fn new(cfg: Config, listener: Arc<dyn ChatListener>) -> Arc<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        Arc::new(Self {
            rt,
            cfg,
            listener,
            cmd: Mutex::new(None),
            next_id: AtomicU64::new(1),
            shared: engine::Shared::default(),
            chat: Mutex::default(),
        })
    }

    /// Solve the PoW, queue, and chat. A previous chat is left first (it still
    /// collects its good-chat token in the background); its plaintext is wiped.
    pub fn start_match(&self) {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Some(old) = self.cmd.lock().unwrap().replace(tx) {
            let _ = old.send(Cmd::Leave);
        }
        let chat = Arc::new(PerChat::default());
        *self.chat.lock().unwrap() = chat.clone();
        let shared = engine::Shared {
            chat,
            ..self.shared.clone()
        };
        self.rt.spawn(engine::run(
            self.cfg.clone(),
            rx,
            self.listener.clone(),
            shared,
            None,
        ));
    }

    /// VIP: ask the room to hold this chat for 24 h (spends one VIP token).
    /// Both sides get `PeerEvent::Extended`, or we get `ExtendRefused`.
    pub fn extend_chat(&self) -> Result<(), CoreError> {
        self.command(Cmd::Extend)
    }

    /// VIP, after `Extended`: seal the session under `key` (32 bytes from
    /// hardware-backed storage), disconnect without leaving, and end with
    /// `EndReason::Suspended`. Store the returned bytes; they are useless
    /// without `key`. Unsent messages still in the queue are dropped.
    pub fn suspend(&self, key: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let key: Zeroizing<[u8; 32]> =
            Zeroizing::new(key.as_slice().try_into().map_err(|_| CoreError::BadKey)?);
        let (tx, rx) = std::sync::mpsc::channel();
        self.command(Cmd::Suspend(key, tx))?;
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| CoreError::NotChatting)?
    }

    /// Re-enter a chat saved with [`Self::suspend`] (any time within the hold,
    /// also after an app restart). Restores the saved messages and continues
    /// with `Chatting`, or ends with `ConnectionLost` if the room is gone.
    pub fn resume_saved(&self, saved: Vec<u8>, key: Vec<u8>) -> Result<(), CoreError> {
        let key: Zeroizing<[u8; 32]> =
            Zeroizing::new(key.as_slice().try_into().map_err(|_| CoreError::BadKey)?);
        let keys = crate::saved::Keys::derive(&key);
        let s = crate::saved::Saved::open(&saved, &keys).ok_or(CoreError::BadSavedSession)?;
        let session = snow_crypto::ChatSession::restore(&s.session, &keys.pickle)
            .map_err(|_| CoreError::BadSavedSession)?;
        let (tx, rx) = mpsc::unbounded_channel();
        if let Some(old) = self.cmd.lock().unwrap().replace(tx) {
            let _ = old.send(Cmd::Leave);
        }
        let chat = Arc::new(PerChat::default());
        {
            let mut t = chat.transcript.lock().unwrap();
            let mut max_id = 0;
            for (id, from_me, body) in &s.messages {
                let safety = if *from_me {
                    Safety::clean()
                } else {
                    crate::screening::screen(body)
                };
                t.push(*id, *from_me, Zeroizing::new(body.clone()), 0, safety);
                max_id = max_id.max(*id);
            }
            self.next_id.fetch_max(max_id + 1, Ordering::Relaxed);
        }
        *self.chat.lock().unwrap() = chat.clone();
        let shared = engine::Shared {
            chat,
            ..self.shared.clone()
        };
        self.rt.spawn(engine::run(
            self.cfg.clone(),
            rx,
            self.listener.clone(),
            shared,
            Some((s, session)),
        ));
        Ok(())
    }

    /// Queue a text message. Returns its local id. `ttl_secs > 0` burns it on
    /// both sides that many seconds after it is sent / received.
    pub fn send_text(&self, body: String, ttl_secs: u32) -> Result<u64, CoreError> {
        let body = Zeroizing::new(body);
        if body.len() > snow_proto::MAX_TEXT_LEN {
            return Err(CoreError::TooLong);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.command(Cmd::Send {
            id,
            body: body.clone(),
            ttl_secs,
        })?;
        self.current()
            .transcript
            .lock()
            .unwrap()
            .push(id, true, body, ttl_secs, Safety::clean());
        Ok(id)
    }

    /// Send a flash photo. The image is decoded and re-encoded (no metadata),
    /// sealed with a one-time key and sent in chunks. Returns its id; we keep no
    /// copy. CPU-heavy: call off the main thread. `view_secs` 0 = default (3 s).
    pub fn send_image(&self, image: Vec<u8>, view_secs: u8) -> Result<u64, CoreError> {
        let clean =
            Zeroizing::new(snow_media::sanitize_image(&image).map_err(|_| CoreError::BadMedia)?);
        drop(Zeroizing::new(image));
        self.send_media(snow_proto::MediaKind::Image, &clean, view_secs)
    }

    /// Send a voice note (already encoded in memory by the platform, e.g. AAC/Opus).
    pub fn send_voice(&self, audio: Vec<u8>, view_secs: u8) -> Result<u64, CoreError> {
        let audio = Zeroizing::new(audio);
        self.send_media(snow_proto::MediaKind::Voice, &audio, view_secs)
    }

    /// Decrypt a received item **once**. The key and ciphertext are destroyed
    /// now; the peer is told it was opened. Show it for at most
    /// `MediaInfo::view_secs` — `on_media_burned(id, false)` fires when time is up.
    pub fn open_media(&self, id: u64) -> Result<Vec<u8>, CoreError> {
        let opened = self.current().media.lock().unwrap().open(id);
        let (plain, view_secs) = opened.ok_or(CoreError::MediaGone)?;
        let _ = self.command(Cmd::MediaOpened { id, view_secs });
        Ok(plain.to_vec())
    }

    /// The current chat's messages, oldest first. The UI should render from
    /// this and is free to drop its own copy whenever the app leaves the screen
    /// (background, low memory, decoy), then call this again to redraw.
    pub fn transcript(&self) -> Vec<ChatMessage> {
        self.current().transcript.lock().unwrap().snapshot()
    }

    /// Tell the peer we took a screenshot or started recording the screen
    /// (iOS `userDidTakeScreenshotNotification` / `UIScreen.capturedDidChange`).
    pub fn notify_screen_captured(&self) {
        let _ = self.command(Cmd::Control(snow_proto::Inner::ScreenCaptured));
    }

    /// Tell the peer we left, then end the chat.
    pub fn leave(&self) {
        let _ = self.command(Cmd::Leave);
    }

    /// Report the peer and leave. Works during the chat and for a few seconds
    /// after `Ended { PeerLeft }`. Nothing about the conversation is sent: the
    /// only effect is that the peer earns no good-chat token from this chat.
    pub fn report(&self) {
        let _ = self.command(Cmd::Report);
    }

    /// Good-chat tokens currently spendable.
    pub fn good_tokens(&self) -> u32 {
        let epoch = snow_tokens::epoch(engine::unix_now());
        self.shared
            .wallet
            .lock()
            .unwrap()
            .count(snow_tokens::Kind::Good, epoch)
    }

    /// VIP tokens currently spendable (paranoid mode, 24 h hold).
    pub fn vip_tokens(&self) -> u32 {
        let epoch = snow_tokens::epoch(engine::unix_now());
        self.shared
            .wallet
            .lock()
            .unwrap()
            .count(snow_tokens::Kind::Vip, epoch)
    }

    /// Exchange a store purchase for blind VIP tokens; returns how many were
    /// added. The relay learns that a purchase was made, but the tokens can't
    /// be linked to it when spent. Call `finish()` on the store transaction
    /// only after this succeeds (or fails with `PurchaseAlreadyRedeemed`); a
    /// retry after a crash or network error repeats the same request.
    pub async fn redeem_purchase(
        &self,
        store: PurchaseStore,
        proof: String,
    ) -> Result<u32, CoreError> {
        let fut = engine::redeem_purchase(
            self.cfg.clone(),
            self.shared.clone(),
            self.listener.clone(),
            store,
            proof,
        );
        self.rt.spawn(fut).await.map_err(|_| CoreError::Network)?
    }

    /// Serialized wallet, for the app to store in the Keychain / Keystore.
    pub fn wallet_export(&self) -> Vec<u8> {
        self.shared.wallet.lock().unwrap().export()
    }

    /// Restore a wallet saved with [`Self::wallet_export`] (call before `start_match`).
    pub fn wallet_import(&self, bytes: Vec<u8>) -> Result<(), CoreError> {
        let w = crate::wallet::Wallet::import(&bytes).ok_or(CoreError::BadWallet)?;
        *self.shared.wallet.lock().unwrap() = w;
        Ok(())
    }

    /// Feature switches from the last valid signed remote config (fetched at the
    /// start of each match), or `None` if there is none.
    pub fn remote_features(&self) -> Option<RemoteFeatures> {
        let r = self.shared.remote.lock().unwrap();
        r.config(engine::unix_now()).map(|c| RemoteFeatures {
            version: c.version,
            donations: c.features.donations,
            lightning: c.features.lightning,
            voice: c.features.voice,
            photos: c.features.photos,
            iap: c.features.iap,
        })
    }

    /// Call from the app lifecycle: cover traffic pauses in the background.
    pub fn set_foreground(&self, foreground: bool) {
        let _ = self.command(Cmd::Foreground(foreground));
    }

    /// Drop all keys and state immediately without telling the server anything.
    pub fn panic_wipe(&self) {
        let _ = self.command(Cmd::Wipe);
    }
}

impl SnowClient {
    /// Testing only (not exported over FFI): simulate a network drop.
    pub fn debug_drop_connection(&self) {
        let _ = self.command(Cmd::DebugDrop);
    }

    /// Testing only: number of encrypted frames (text + chaff) this client has sent.
    pub fn debug_frames_sent(&self) -> u64 {
        self.shared.frames.sent.load(Ordering::Relaxed)
    }

    /// Testing only: send `n` cover frames at once, ignoring the pacer.
    pub fn debug_flood(&self, n: u32) {
        let _ = self.command(Cmd::DebugFlood(n));
    }

    /// Testing only: frames the room dropped for exceeding its rate cap.
    pub fn debug_rate_limited(&self) -> u64 {
        self.shared.frames.rate_limited.load(Ordering::Relaxed)
    }

    fn current(&self) -> Arc<PerChat> {
        self.chat.lock().unwrap().clone()
    }

    fn send_media(
        &self,
        kind: snow_proto::MediaKind,
        plain: &[u8],
        view_secs: u8,
    ) -> Result<u64, CoreError> {
        use snow_proto::Inner;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (key, ct) = snow_media::seal(plain, &crate::media::aad(id, kind))
            .map_err(|_| CoreError::BadMedia)?;
        let mut items = vec![Inner::MediaOffer {
            media_id: id,
            kind,
            len: ct.len() as u32,
            chunks: snow_media::chunk_count(ct.len()),
            key: *key.as_bytes(),
            view_secs: crate::media::clamp_view(view_secs),
        }];
        items.extend(
            snow_media::chunks(&ct)
                .enumerate()
                .map(|(i, c)| Inner::MediaChunk {
                    media_id: id,
                    index: i as u16,
                    data: c.to_vec(),
                }),
        );
        self.command(Cmd::Media(items))?;
        Ok(id)
    }

    fn command(&self, c: Cmd) -> Result<(), CoreError> {
        let guard = self.cmd.lock().unwrap();
        let tx = guard.as_ref().ok_or(CoreError::NotChatting)?;
        tx.send(c).map_err(|_| CoreError::NotChatting)
    }
}
