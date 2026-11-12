//! snow-core: the client state machine, and the only crate exposed to the native
//! apps (via UniFFI).
//!
//! All keys and all plaintext stay in this process's RAM. Nothing is written to
//! disk. The UI gets plaintext through [`ChatListener::on_message`] and is
//! responsible for dropping it again.

uniffi::setup_scaffolding!();

mod api;
mod engine;
mod net;
mod pacer;
mod pin;

pub use api::*;

/// Library version, exposed to the native shells as a smoke test.
#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
