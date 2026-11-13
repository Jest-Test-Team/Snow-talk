use crate::engine::{self, Cmd};
use crate::transcript::Transcript;
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

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatMessage {
    /// Unique per side: `(id, from_me)` identifies a message.
    pub id: u64,
    pub from_me: bool,
    pub body: String,
    pub ttl_secs: u32,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("no active chat")]
    NotChatting,
    #[error("message too long")]
    TooLong,
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
    /// The current chat's transcript; replaced on every `start_match`, so an old
    /// chat that ends late can't wipe the new one's.
    transcript: Mutex<Arc<Mutex<Transcript>>>,
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
            transcript: Mutex::default(),
        })
    }

    /// Solve the PoW, queue, and chat. Any previous chat is wiped first.
    pub fn start_match(&self) {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Some(old) = self.cmd.lock().unwrap().replace(tx) {
            let _ = old.send(Cmd::Wipe);
        }
        let transcript = Arc::new(Mutex::new(Transcript::default()));
        *self.transcript.lock().unwrap() = transcript.clone();
        let shared = engine::Shared {
            transcript,
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
        let t = self.transcript.lock().unwrap().clone();
        t.lock().unwrap().push(id, true, body, ttl_secs);
        Ok(id)
    }

    /// The current chat's messages, oldest first. The UI should render from
    /// this and is free to drop its own copy whenever the app leaves the screen
    /// (background, low memory, decoy), then call this again to redraw.
    pub fn transcript(&self) -> Vec<ChatMessage> {
        let t = self.transcript.lock().unwrap().clone();
        let snapshot = t.lock().unwrap().snapshot();
        snapshot
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

    fn command(&self, c: Cmd) -> Result<(), CoreError> {
        let guard = self.cmd.lock().unwrap();
        let tx = guard.as_ref().ok_or(CoreError::NotChatting)?;
        tx.send(c).map_err(|_| CoreError::NotChatting)
    }
}
