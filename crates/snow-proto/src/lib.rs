//! Snow-talk wire format.
//!
//! Two layers:
//!
//! * **Frame** — what the relay (and any network observer) sees. Every WebSocket
//!   binary message is exactly [`FRAME_LEN`] bytes: `[version][len: u16 BE][postcard body][random padding]`.
//!   The body is a [`ClientMsg`] or [`ServerMsg`]. Peer-to-peer traffic travels as
//!   opaque bytes inside `Relay`, which the server never parses.
//! * **Peer envelope** ([`PeerEnvelope`]) — only parsed by clients: handshake
//!   messages and Olm ciphertexts. The Olm plaintext is an [`Inner`] padded to
//!   [`INNER_LEN`] so that real messages and chaff have the same size.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod frame;
mod inner;
mod msg;

pub use frame::{decode_frame, encode_frame, FrameError, FRAME_LEN, MAX_BODY_LEN, VERSION};
pub use inner::{decode_inner, encode_inner, Inner, InnerError, INNER_LEN, MAX_TEXT_LEN};
pub use msg::{ClientMsg, ErrorCode, Handshake, PeerEnvelope, PowSolution, Role, ServerMsg};
