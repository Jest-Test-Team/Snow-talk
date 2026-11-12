use crate::engine::{self, Cmd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Client configuration.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Config {
    /// e.g. `https://relay.snowtalk.app` (or `http://127.0.0.1:8787` for development).
    pub server_url: String,
    /// Interest bucket `0..64`, or `None` for random matching.
    pub bucket: Option<u8>,
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
    /// Panic button: everything was wiped.
    Wiped,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ChatState {
    SolvingPow,
    Queued,
    Handshaking,
    Chatting,
    Ended { reason: EndReason },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PeerEvent {
    Disconnected { grace_secs: u32 },
    Reconnected,
    ScreenCaptured,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChatMessage {
    pub id: u64,
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
        })
    }

    /// Solve the PoW, queue, and chat. Any previous chat is wiped first.
    pub fn start_match(&self) {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Some(old) = self.cmd.lock().unwrap().replace(tx) {
            let _ = old.send(Cmd::Wipe);
        }
        self.rt
            .spawn(engine::run(self.cfg.clone(), rx, self.listener.clone()));
    }

    /// Queue a text message. Returns its local id.
    pub fn send_text(&self, body: String, ttl_secs: u32) -> Result<u64, CoreError> {
        if body.len() > snow_proto::MAX_TEXT_LEN {
            return Err(CoreError::TooLong);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.command(Cmd::Send {
            id,
            body: body.into(),
            ttl_secs,
        })?;
        Ok(id)
    }

    /// Tell the peer we left, then end the chat.
    pub fn leave(&self) {
        let _ = self.command(Cmd::Leave);
    }

    /// Drop all keys and state immediately without telling the server anything.
    pub fn panic_wipe(&self) {
        let _ = self.command(Cmd::Wipe);
    }
}

impl SnowClient {
    fn command(&self, c: Cmd) -> Result<(), CoreError> {
        let guard = self.cmd.lock().unwrap();
        let tx = guard.as_ref().ok_or(CoreError::NotChatting)?;
        tx.send(c).map_err(|_| CoreError::NotChatting)
    }
}
