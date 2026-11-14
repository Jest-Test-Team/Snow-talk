//! snow-core: the client state machine, and the only crate exposed to the native
//! apps (via UniFFI).
//!
//! All keys and all plaintext stay in this process's RAM. Nothing is written to
//! disk. The UI gets plaintext through [`ChatListener::on_message`] and is
//! responsible for dropping it again.

uniffi::setup_scaffolding!();

mod api;
mod catalog;
mod dns;
mod engine;
mod http;
mod interests;
mod media;
mod net;
mod pacer;
mod pin;
mod remote;
mod saved;
mod screening;
mod socks;
mod transcript;
mod wallet;

pub use api::*;
pub use catalog::*;

/// Library version, exposed to the native shells as a smoke test.
#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Testing only (not exported over FFI): resolve `url`'s host via DoH, connect with
/// ECH if the host publishes a config, and GET it. Returns `(ech_used, body)`.
/// With `socks` (e.g. `127.0.0.1:9050`), everything goes through that Tor proxy.
pub fn debug_net_check(url: &str, socks: Option<&str>) -> Result<(bool, String), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let u = url::Url::parse(url).map_err(|e| e.to_string())?;
        let origin = format!("{}://{}", u.scheme(), u.host_str().unwrap_or_default());
        let dialer = match socks {
            None => net::Dialer::Direct,
            Some(p) => net::Dialer::Socks(socks::Socks::isolated(p).map_err(|e| e.to_string())?),
        };
        let n = net::Net::new(&origin, &[], dialer)
            .await
            .map_err(|e| e.to_string())?;
        let (_, body) = http::request(&n.dialer, &n.relay, "GET", u.path(), &[], &[])
            .await
            .map_err(|e| e.to_string())?;
        Ok((n.ech, String::from_utf8_lossy(&body).into_owned()))
    })
}
