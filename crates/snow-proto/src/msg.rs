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
    /// A perk was asked for without the token it costs.
    NotAllowed,
}

/// Client → server. Sent to the matchmaker or to a chat room depending on the socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// First message on a matchmaker socket.
    Join {
        pow: PowSolution,
        /// Coarse interest bucket (k-anonymous), `None` = random matching.
        bucket: Option<u8>,
        /// Ask for paranoid mode (constant-rate cover traffic, a VIP perk).
        /// The matchmaker decides; see [`ServerMsg::Matched::paranoid`].
        paranoid: bool,
        /// Ask for the trusted queue (only matched with other trusted users).
        trusted: bool,
        /// Tokens spent on this join (postcard-encoded `snow_tokens::Token`s):
        /// good-chat tokens for `trusted`, a VIP token for `paranoid`.
        spend: Vec<Vec<u8>>,
    },
    /// Opaque peer bytes. The relay forwards these unchanged and never parses them.
    Relay(Vec<u8>),
    /// Deliberate exit. `claim`: blinded elements for a good-chat token, issued
    /// once the peer has had a chance to report (empty = no claim).
    Leave { claim: Vec<[u8; 32]> },
    /// Report the peer (no content is sent) and leave. The peer gets no token
    /// for this chat; the reporter may still claim one.
    Report { claim: Vec<[u8; 32]> },
    /// Hold this room for 24 h (VIP: one VIP token in `spend`), so either side
    /// can come back from a saved session after the app was closed. Both sides
    /// are told ([`ServerMsg::Extended`]).
    Extend { spend: Vec<Vec<u8>> },
}

/// Server → client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMsg {
    /// The matchmaker has paired us. Connect to `/room/<ticket>`.
    Matched {
        ticket: String,
        role: Role,
        /// Paranoid mode granted: the room allows a constant cover-traffic rate
        /// for this slot. If `false`, the client must not send chaff.
        paranoid: bool,
        /// Placed in the trusted queue (tokens accepted).
        trusted: bool,
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
    /// The peer pressed "leave". We may still report them for `report_secs`.
    PeerLeft {
        report_secs: u32,
    },
    /// The grace period expired without the peer coming back.
    PeerGone,
    /// Session-ID rotation: reconnect with this ticket; the old one is revoked.
    Rotate {
        ticket: String,
    },
    /// Good-chat tokens for our claim (see `snow-tokens`). The client checks
    /// `proof` against `public_key` and pins that key for the epoch.
    Tokens {
        epoch: u32,
        public_key: [u8; 32],
        evaluated: Vec<[u8; 32]>,
        proof: [[u8; 32]; 2],
    },
    /// Our claim was refused (reported, too short, or already issued).
    NoTokens,
    Error(ErrorCode),
    /// The room is held for `hold_secs` even if both sides go offline.
    /// `by_me`: we asked for it (else the peer did, and may save the session).
    Extended {
        hold_secs: u32,
        by_me: bool,
    },
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
