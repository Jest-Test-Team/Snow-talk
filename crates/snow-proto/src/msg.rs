use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// Which side of the Olm handshake a client plays. Assigned by the matchmaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Creates the outbound Olm session from the responder's one-time key.
    Initiator,
    /// Publishes a one-time key and accepts the initiator's pre-key message.
    Responder,
}

/// A solved proof-of-work challenge (see `snow-pow`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowSolution {
    pub challenge: Vec<u8>,
    pub nonce: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadFrame,
    BadPow,
    BadTicket,
    RoomFull,
    RateLimited,
    Internal,
}

/// Client → server. Sent to the matchmaker or to a chat room depending on the socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// First message on a matchmaker socket.
    Join {
        pow: PowSolution,
        /// Coarse interest bucket (k-anonymous), `None` = random matching.
        bucket: Option<u8>,
    },
    /// Opaque peer bytes. The relay forwards these unchanged and never parses them.
    Relay(Vec<u8>),
    /// Deliberate exit: the peer is told immediately and the room closes.
    Leave,
}

/// Server → client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMsg {
    /// The matchmaker has paired us. Connect to `/room/<ticket>`.
    Matched {
        ticket: String,
        role: Role,
    },
    /// Joined the room. `resume` reconnects to the same slot within the grace period.
    Joined {
        resume: String,
        peer_present: bool,
    },
    PeerJoined,
    Relay(Vec<u8>),
    /// The peer's connection dropped; their slot is held for `grace_secs`.
    PeerDisconnected {
        grace_secs: u32,
    },
    PeerReconnected,
    /// The peer pressed "leave".
    PeerLeft,
    /// The grace period expired without the peer coming back.
    PeerGone,
    /// Session-ID rotation: reconnect with this ticket; the old one is revoked.
    Rotate {
        ticket: String,
    },
    Error(ErrorCode),
}

/// Handshake messages carried in [`PeerEnvelope::Handshake`].
///
/// A commit/reveal step stops the relay from choosing its own keys after it has
/// seen ours, which keeps a MITM from grinding a matching SAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Handshake {
    /// `SHA-256(domain || identity_key || one_time_key || nonce)`.
    Commit([u8; 32]),
    Reveal {
        identity_key: [u8; 32],
        /// Only the responder publishes a one-time key.
        one_time_key: Option<[u8; 32]>,
        nonce: [u8; 32],
    },
}

/// Bytes inside [`ClientMsg::Relay`] / [`ServerMsg::Relay`]. Parsed by clients only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerEnvelope {
    Handshake(Handshake),
    /// An Olm message: `0` = pre-key, `1` = normal (vodozemac's message type).
    Olm {
        kind: u8,
        body: Vec<u8>,
    },
}
