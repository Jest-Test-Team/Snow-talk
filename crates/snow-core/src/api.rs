use crate::engine::PerChat;
use crate::engine::{self, Cmd};
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
    /// Ask for paranoid mode (VIP): constant-rate cover traffic. Only takes effect
    /// if the server grants it — see [`ChatState::Handshaking::paranoid`].
    #[uniffi(default = false)]
    pub paranoid: bool,
    /// Paranoid-mode cover-traffic period in ms. `None` = 1500 ms, `Some(0)` = off.
    /// Overridden by remote config in production. Ignored unless paranoid is granted.
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
    Disconnected { grace_secs: u32 },
    Reconnected,
    ScreenCaptured,
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

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatMessage {
    /// Unique per side: `(id, from_me)` identifies a message.
    pub id: u64,
    pub from_me: bool,
    pub body: String,
    pub ttl_secs: u32,
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

    /// Solve the PoW, queue, and chat. Any previous chat is wiped first.
    pub fn start_match(&self) {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Some(old) = self.cmd.lock().unwrap().replace(tx) {
            let _ = old.send(Cmd::Wipe);
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
        ));
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
            .push(id, true, body, ttl_secs);
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
