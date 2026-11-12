use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// Fixed size of every Olm plaintext. Leaves room for Olm's pre-key overhead,
/// CBC padding and the outer frame header inside [`crate::FRAME_LEN`].
pub const INNER_LEN: usize = 3328;
/// Longest text message body, in UTF-8 bytes (about 1000 CJK characters).
pub const MAX_TEXT_LEN: usize = 3000;

/// Plaintext carried inside the end-to-end encrypted channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Inner {
    /// Cover traffic. Dropped on receipt.
    Chaff,
    /// The initiator's first message, which lets the responder build the inbound session.
    Ready,
    Text {
        id: u64,
        body: String,
        /// Burn-after-reading timer in seconds; `0` = keep for the session.
        ttl_secs: u32,
    },
    /// The peer took a screenshot or started a screen recording.
    ScreenCaptured,
    /// Placeholder for later protocol messages (PSI, profiles, media) so that
    /// older clients can skip them.
    Ext { kind: u16, data: Vec<u8> },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InnerError {
    #[error("message too large")]
    TooLarge,
    #[error("malformed plaintext")]
    Malformed,
}

/// Serialize and zero-pad to exactly [`INNER_LEN`] bytes: `[len: u16 BE][postcard][0..]`.
pub fn encode_inner(msg: &Inner) -> Result<Vec<u8>, InnerError> {
    if let Inner::Text { body, .. } = msg {
        if body.len() > MAX_TEXT_LEN {
            return Err(InnerError::TooLarge);
        }
    }
    let mut out = alloc::vec![0u8; INNER_LEN];
    let used = postcard::to_slice(msg, &mut out[2..])
        .map_err(|_| InnerError::TooLarge)?
        .len();
    out[..2].copy_from_slice(&(used as u16).to_be_bytes());
    Ok(out)
}

pub fn decode_inner(buf: &[u8]) -> Result<Inner, InnerError> {
    if buf.len() != INNER_LEN {
        return Err(InnerError::Malformed);
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len > INNER_LEN - 2 {
        return Err(InnerError::Malformed);
    }
    postcard::from_bytes(&buf[2..2 + len]).map_err(|_| InnerError::Malformed)
}
