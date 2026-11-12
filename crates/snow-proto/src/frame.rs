use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};

/// Size of every frame on the wire. Real messages, chaff and control frames are
/// indistinguishable by length.
pub const FRAME_LEN: usize = 4096;
/// Protocol version carried in the first byte.
pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 3;
/// Largest postcard body that fits in a frame.
pub const MAX_BODY_LEN: usize = FRAME_LEN - HEADER_LEN;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame must be exactly {FRAME_LEN} bytes, got {0}")]
    BadLength(usize),
    #[error("unsupported protocol version {0}")]
    BadVersion(u8),
    #[error("body of {0} bytes does not fit in a frame")]
    TooLarge(usize),
    #[error("malformed body")]
    Malformed,
}

/// Serialize `msg` into a padded [`FRAME_LEN`]-byte frame.
pub fn encode_frame<T: Serialize, R: RngCore + CryptoRng>(
    msg: &T,
    rng: &mut R,
) -> Result<Vec<u8>, FrameError> {
    let mut out = alloc::vec![0u8; FRAME_LEN];
    let used = postcard::to_slice(msg, &mut out[HEADER_LEN..])
        .map_err(|_| FrameError::TooLarge(MAX_BODY_LEN + 1))?
        .len();
    out[0] = VERSION;
    out[1..3].copy_from_slice(&(used as u16).to_be_bytes());
    rng.fill_bytes(&mut out[HEADER_LEN + used..]);
    Ok(out)
}

/// Parse a frame, rejecting anything that is not exactly [`FRAME_LEN`] bytes.
pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    if frame.len() != FRAME_LEN {
        return Err(FrameError::BadLength(frame.len()));
    }
    if frame[0] != VERSION {
        return Err(FrameError::BadVersion(frame[0]));
    }
    let len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    if len > MAX_BODY_LEN {
        return Err(FrameError::Malformed);
    }
    postcard::from_bytes(&frame[HEADER_LEN..HEADER_LEN + len]).map_err(|_| FrameError::Malformed)
}
