//! snow-core: client state machine and the only crate exposed to the native apps (via UniFFI).

uniffi::setup_scaffolding!();

/// Library version, exposed to the native shells as a smoke test.
#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
