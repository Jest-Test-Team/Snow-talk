//! snow-core

/// Library version, exposed to the native shells as a smoke test.
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
