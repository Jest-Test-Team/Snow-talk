//! Remote config and sponsor catalog, as seen by the client.
//!
//! The config is only trusted if it verifies against the key compiled into the
//! app ([`Config::config_key`]). Fetching is best effort: if the relay is down or
//! serves garbage we keep the last good config (while it is valid), and the
//! wallet's first-seen key pin still guards token keys.
use crate::net::{Net, NetError};
use snow_config::{Catalog, RemoteConfig, TokenKind};

/// Re-fetch the config at most this often.
const REFRESH_SECS: u64 = 3600;

#[derive(Default)]
pub struct Remote {
    config: Option<RemoteConfig>,
    catalog: Option<Catalog>,
    /// Highest config version accepted so far (rollback protection).
    min_version: u64,
    fetched_at: u64,
}

impl Remote {
    /// The current config, if one verified and hasn't expired.
    pub fn config(&self, now: u64) -> Option<&RemoteConfig> {
        self.config.as_ref().filter(|c| now < c.expires_at)
    }

    pub fn catalog(&self, now: u64) -> Option<&Catalog> {
        self.config(now)?;
        self.catalog.as_ref()
    }

    fn stale(&self, now: u64) -> bool {
        self.config(now).is_none() || now >= self.fetched_at + REFRESH_SECS
    }

    /// Accept a freshly downloaded config if it verifies.
    pub fn accept(&mut self, bytes: &[u8], key: &[u8; 32], now: u64) -> bool {
        match RemoteConfig::verify(bytes, key, now, self.min_version) {
            Ok(c) => {
                if self
                    .catalog
                    .as_ref()
                    .zip(c.catalog.as_ref())
                    .is_none_or(|(old, new)| old.hash != new.sha256)
                {
                    self.catalog = None;
                }
                self.min_version = c.version;
                self.config = Some(c);
                self.fetched_at = now;
                true
            }
            Err(_) => false,
        }
    }

    /// The catalog hash we still need to download, if any.
    fn wanted_catalog(&self, now: u64) -> Option<snow_config::CatalogRef> {
        let c = self.config(now)?;
        if self.catalog.is_some() {
            return None;
        }
        c.catalog.clone()
    }

    fn set_catalog(&mut self, bytes: &[u8], pin: &snow_config::CatalogRef) {
        if let Ok(c) = Catalog::verify(bytes, pin) {
            self.catalog = Some(c);
        }
    }

    /// Whether tokens issued under `public_key` for `epoch` may be accepted.
    /// `None` = the config says nothing (fall back to the wallet's own pin).
    pub fn token_key_ok(
        &self,
        kind: TokenKind,
        epoch: u32,
        public_key: &[u8; 32],
        now: u64,
    ) -> Option<bool> {
        let c = self.config(now)?;
        if !c.pins_tokens(kind) {
            return None;
        }
        Some(c.token_key(kind, epoch).as_ref() == Some(public_key))
    }

    pub fn chaff_ms(&self, now: u64) -> Option<u32> {
        self.config(now).map(|c| c.chaff_ms)
    }
}

async fn get(net: &Net, path: &str) -> Result<Vec<u8>, NetError> {
    let (status, body) =
        crate::http::request(&net.dialer, &net.relay, "GET", path, &[], &[]).await?;
    if status != 200 {
        return Err(NetError::Io(format!("{path}: HTTP {status}")));
    }
    Ok(body)
}

/// Refresh the config (and catalog) if needed. Errors are swallowed on purpose.
pub async fn refresh(net: &Net, key: &[u8; 32], remote: &std::sync::Mutex<Remote>, now: u64) {
    if !remote.lock().unwrap().stale(now) {
        return;
    }
    if let Ok(bytes) = get(net, "/config").await {
        remote.lock().unwrap().accept(&bytes, key, now);
    }
    let want = remote.lock().unwrap().wanted_catalog(now);
    if let Some(pin) = want {
        if let Ok(bytes) = get(net, "/catalog").await {
            remote.lock().unwrap().set_catalog(&bytes, &pin);
        }
    }
}

/// Parse the hex public key from [`crate::Config::config_key`].
pub fn parse_key(hex_key: &str) -> Option<[u8; 32]> {
    let mut k = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut k).ok()?;
    Some(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snow_config::*;

    fn signed(version: u64, keys: Vec<TokenKey>, catalog: Option<CatalogRef>) -> Vec<u8> {
        RemoteConfig {
            version,
            issued_at: 100,
            expires_at: 10_000,
            chaff_ms: 900,
            features: Features::default(),
            token_keys: keys,
            catalog,
        }
        .sign(&signing_key(&[7; 32]))
    }

    #[test]
    fn accept_rollback_and_token_pins() {
        let pk = public_key(&signing_key(&[7; 32]));
        let mut r = Remote::default();
        assert_eq!(r.token_key_ok(TokenKind::Good, 1, &[1; 32], 200), None);
        assert!(
            !r.accept(&signed(5, vec![], None), &[0; 32], 200),
            "wrong key"
        );
        assert!(r.accept(&signed(5, vec![], None), &pk, 200));
        assert_eq!(r.chaff_ms(200), Some(900));
        assert_eq!(
            r.token_key_ok(TokenKind::Good, 1, &[1; 32], 200),
            None,
            "no pins"
        );
        assert!(
            !r.accept(&signed(4, vec![], None), &pk, 300),
            "rollback refused"
        );
        let keys = vec![TokenKey {
            kind: TokenKind::Good,
            epoch: 1,
            key: [1; 32],
        }];
        assert!(r.accept(&signed(6, keys, None), &pk, 300));
        assert_eq!(
            r.token_key_ok(TokenKind::Good, 1, &[1; 32], 300),
            Some(true)
        );
        assert_eq!(
            r.token_key_ok(TokenKind::Good, 1, &[2; 32], 300),
            Some(false),
            "tagging key"
        );
        assert_eq!(
            r.token_key_ok(TokenKind::Good, 2, &[1; 32], 300),
            Some(false),
            "unlisted epoch"
        );
        assert_eq!(r.token_key_ok(TokenKind::Vip, 1, &[2; 32], 300), None);
        assert!(r.config(10_000).is_none(), "expired");
        assert!(r.stale(300 + REFRESH_SECS));
    }

    #[test]
    fn catalog_follows_config() {
        let pk = public_key(&signing_key(&[7; 32]));
        let raw = br#"{"version":1,"sponsors":[{"id":"a","title":"t","body":"b","url":"https://a.example/"}]}"#;
        let pin = CatalogRef {
            sha256: Catalog::sha256(raw),
        };
        let mut r = Remote::default();
        assert!(r.accept(&signed(1, vec![], Some(pin.clone())), &pk, 200));
        assert_eq!(r.wanted_catalog(200), Some(pin.clone()));
        r.set_catalog(b"tampered", &pin);
        assert!(r.catalog(200).is_none());
        r.set_catalog(raw, &pin);
        assert_eq!(r.catalog(200).unwrap().sponsors.len(), 1);
        assert_eq!(r.wanted_catalog(200), None);
        // Same catalog in a newer config: kept. New hash: dropped and re-fetched.
        assert!(r.accept(&signed(2, vec![], Some(pin.clone())), &pk, 200));
        assert!(r.catalog(200).is_some());
        let other = CatalogRef { sha256: [3; 32] };
        assert!(r.accept(&signed(3, vec![], Some(other.clone())), &pk, 200));
        assert!(r.catalog(200).is_none());
        assert_eq!(r.wanted_catalog(200), Some(other));
    }
}
