//! Signed remote config and sponsored-tag catalog.
//!
//! The config is signed **offline** with an Ed25519 key whose public half is
//! compiled into the app. The relay only serves the bytes (from R2), so a
//! compromised relay can neither forge flags nor hand out a different token
//! issuer key per user: the config lists the token keys for each epoch, and the
//! client refuses tokens issued under any other key. That turns the per-epoch
//! "first key seen" pin of the wallet into a global one.
//!
//! Wire format of `config.bin`: `MAGIC (8) ‖ signature (64) ‖ JSON body`, the
//! signature covering `DOMAIN ‖ body`. JSON so operators can read and diff it.
//!
//! The sponsored-tag catalog is plain JSON pinned by SHA-256 in the config. The
//! client downloads the whole catalog and picks ads for its own tags locally,
//! so nobody learns which tags it has. No third-party ad SDK, no click tracking.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 8] = b"SNOWCFG1";
const DOMAIN: &[u8] = b"snowtalk/config/v1\0";
/// Refuse configs bigger than this (they are a few hundred bytes).
pub const MAX_CONFIG: usize = 32 * 1024;
/// Refuse catalogs bigger than this.
pub const MAX_CATALOG: usize = 256 * 1024;
/// Signed configs may not claim a lifetime longer than this.
pub const MAX_LIFETIME_SECS: u64 = 45 * 24 * 3600;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("malformed config")]
    Malformed,
    #[error("bad signature")]
    BadSignature,
    #[error("config expired or not yet valid")]
    Expired,
    #[error("config older than one already seen (rollback)")]
    Rollback,
    #[error("catalog hash mismatch")]
    CatalogHash,
}

mod hex32 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(D::Error::custom)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    Good,
    Vip,
}

/// An issuer public key the client should accept for `(kind, epoch)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenKey {
    pub kind: TokenKind,
    pub epoch: u32,
    #[serde(with = "hex32")]
    pub key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRef {
    #[serde(with = "hex32")]
    pub sha256: [u8; 32],
}

/// Client-side feature switches. Unknown fields are ignored so older apps keep
/// working when new switches appear.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Features {
    /// Post-chat donation prompt.
    pub donations: bool,
    /// Lightning tips / gifts (Android and web builds only; iOS ignores it).
    pub lightning: bool,
    /// Voice messages.
    pub voice: bool,
    /// Flash photos.
    pub photos: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// Monotonic. Clients refuse anything older than what they have seen.
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Paranoid-mode cover-traffic period in ms (0 = off).
    pub chaff_ms: u32,
    #[serde(default)]
    pub features: Features,
    #[serde(default)]
    pub token_keys: Vec<TokenKey>,
    #[serde(default)]
    pub catalog: Option<CatalogRef>,
}

impl RemoteConfig {
    /// The pinned issuer key for `(kind, epoch)`, if the config lists one.
    pub fn token_key(&self, kind: TokenKind, epoch: u32) -> Option<[u8; 32]> {
        self.token_keys
            .iter()
            .find(|k| k.kind == kind && k.epoch == epoch)
            .map(|k| k.key)
    }

    /// Whether the config pins any key for `kind` (then unknown keys are refused).
    pub fn pins_tokens(&self, kind: TokenKind) -> bool {
        self.token_keys.iter().any(|k| k.kind == kind)
    }

    /// Sign this config (operator side, offline).
    pub fn sign(&self, key: &SigningKey) -> Vec<u8> {
        let body = serde_json::to_vec_pretty(self).expect("config serializes");
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&body);
        let sig = key.sign(&msg);
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&sig.to_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Verify `bytes` against the pinned `public_key`, at time `now` (unix
    /// seconds), refusing anything older than `min_version`.
    pub fn verify(
        bytes: &[u8],
        public_key: &[u8; 32],
        now: u64,
        min_version: u64,
    ) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG || bytes.len() < MAGIC.len() + 64 {
            return Err(ConfigError::Malformed);
        }
        let (magic, rest) = bytes.split_at(MAGIC.len());
        if magic != MAGIC {
            return Err(ConfigError::Malformed);
        }
        let (sig, body) = rest.split_at(64);
        let vk = VerifyingKey::from_bytes(public_key).map_err(|_| ConfigError::BadSignature)?;
        let sig = Signature::from_bytes(sig.try_into().expect("64 bytes"));
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(body);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| ConfigError::BadSignature)?;
        let cfg: Self = serde_json::from_slice(body).map_err(|_| ConfigError::Malformed)?;
        // Allow 5 minutes of clock skew on the start.
        if cfg.issued_at > now + 300
            || now >= cfg.expires_at
            || cfg.expires_at.saturating_sub(cfg.issued_at) > MAX_LIFETIME_SECS
        {
            return Err(ConfigError::Expired);
        }
        if cfg.version < min_version {
            return Err(ConfigError::Rollback);
        }
        Ok(cfg)
    }
}

/// Public key bytes for a signing key (for building the app's pinned key).
pub fn public_key(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

pub fn signing_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sponsor {
    pub id: String,
    /// Interest tags this sponsor is shown for (normalized on load). Empty =
    /// shown to everyone, including random matching.
    #[serde(default)]
    pub tags: Vec<String>,
    pub title: String,
    pub body: String,
    /// `https://` link without query or fragment (no per-user tracking params).
    pub url: String,
    #[serde(default = "one")]
    pub weight: u32,
}
fn one() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    pub version: u64,
    pub sponsors: Vec<Sponsor>,
}

impl Catalog {
    /// Parse a catalog and check it against the hash pinned in the config.
    /// Entries with bad links are dropped; tags are normalized.
    pub fn verify(bytes: &[u8], pinned: &CatalogRef) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CATALOG {
            return Err(ConfigError::Malformed);
        }
        let h: [u8; 32] = Sha256::digest(bytes).into();
        if h != pinned.sha256 {
            return Err(ConfigError::CatalogHash);
        }
        let mut c: Self = serde_json::from_slice(bytes).map_err(|_| ConfigError::Malformed)?;
        c.sponsors.retain(|s| valid_link(&s.url) && s.weight > 0);
        for s in &mut c.sponsors {
            s.tags = s
                .tags
                .iter()
                .filter_map(|t| snow_psi::normalize(t))
                .collect();
        }
        Ok(c)
    }

    /// Sponsors for these (user) tags, best matches first: sponsors sharing a
    /// tag, then untargeted ones. Done on the device; `pick` is a random value
    /// used to rotate among equally good candidates by weight.
    pub fn select(&self, tags: &[String], max: usize, pick: u64) -> Vec<Sponsor> {
        let mine: Vec<String> = tags.iter().filter_map(|t| snow_psi::normalize(t)).collect();
        let targeted: Vec<&Sponsor> = self
            .sponsors
            .iter()
            .filter(|s| s.tags.iter().any(|t| mine.contains(t)))
            .collect();
        let general: Vec<&Sponsor> = self.sponsors.iter().filter(|s| s.tags.is_empty()).collect();
        let mut out = weighted_rotate(targeted, pick);
        out.extend(weighted_rotate(general, pick.rotate_left(17)));
        out.truncate(max);
        out
    }

    pub fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
}

/// Start the list at a weight-proportional position chosen by `pick`.
fn weighted_rotate(v: Vec<&Sponsor>, pick: u64) -> Vec<Sponsor> {
    let total: u64 = v.iter().map(|s| s.weight as u64).sum();
    if total == 0 {
        return Vec::new();
    }
    let mut r = pick % total;
    let mut start = 0;
    for (i, s) in v.iter().enumerate() {
        if r < s.weight as u64 {
            start = i;
            break;
        }
        r -= s.weight as u64;
    }
    v[start..]
        .iter()
        .chain(&v[..start])
        .map(|s| (*s).clone())
        .collect()
}

fn valid_link(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty()
        && !url.contains(['?', '#', ' ', '@'])
        && url.len() <= 512
        && rest.split('/').next().is_some_and(|h| h.contains('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(version: u64) -> RemoteConfig {
        RemoteConfig {
            version,
            issued_at: 1_000,
            expires_at: 1_000 + 86_400,
            chaff_ms: 1500,
            features: Features {
                photos: true,
                ..Default::default()
            },
            token_keys: vec![TokenKey {
                kind: TokenKind::Good,
                epoch: 7,
                key: [9; 32],
            }],
            catalog: None,
        }
    }

    #[test]
    fn sign_verify_and_reject() {
        let sk = signing_key(&[1; 32]);
        let pk = public_key(&sk);
        let bytes = cfg(3).sign(&sk);
        let c = RemoteConfig::verify(&bytes, &pk, 2_000, 0).unwrap();
        assert_eq!(c, cfg(3));
        assert_eq!(c.token_key(TokenKind::Good, 7), Some([9; 32]));
        assert_eq!(c.token_key(TokenKind::Vip, 7), None);
        assert!(c.pins_tokens(TokenKind::Good) && !c.pins_tokens(TokenKind::Vip));

        let other = public_key(&signing_key(&[2; 32]));
        assert_eq!(
            RemoteConfig::verify(&bytes, &other, 2_000, 0),
            Err(ConfigError::BadSignature)
        );
        let mut tampered = bytes.clone();
        let n = tampered.len();
        tampered[n - 3] ^= 1;
        assert!(RemoteConfig::verify(&tampered, &pk, 2_000, 0).is_err());
        assert_eq!(
            RemoteConfig::verify(&bytes, &pk, 1_000 + 86_400, 0),
            Err(ConfigError::Expired)
        );
        assert_eq!(
            RemoteConfig::verify(&bytes, &pk, 0, 0),
            Err(ConfigError::Expired),
            "issued too far in the future"
        );
        assert_eq!(
            RemoteConfig::verify(&bytes, &pk, 2_000, 4),
            Err(ConfigError::Rollback)
        );
        assert_eq!(
            RemoteConfig::verify(b"nope", &pk, 2_000, 0),
            Err(ConfigError::Malformed)
        );
        let mut long = cfg(3);
        long.expires_at = long.issued_at + MAX_LIFETIME_SECS + 1;
        assert_eq!(
            RemoteConfig::verify(&long.sign(&sk), &pk, 2_000, 0),
            Err(ConfigError::Expired)
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let sk = signing_key(&[1; 32]);
        let body = br#"{"version":1,"issued_at":1,"expires_at":99,"chaff_ms":0,
            "features":{"voice":true,"future_flag":true},"future":42}"#;
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(body);
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&sk.sign(&msg).to_bytes());
        bytes.extend_from_slice(body);
        let c = RemoteConfig::verify(&bytes, &public_key(&sk), 50, 0).unwrap();
        assert!(c.features.voice && !c.features.photos);
        assert!(c.token_keys.is_empty() && c.catalog.is_none());
    }

    fn catalog_json() -> Vec<u8> {
        r##"{"version":1,"sponsors":[
          {"id":"cafe","tags":["Coffee","#咖啡"],"title":"A","body":"b","url":"https://cafe.example/menu"},
          {"id":"hike","tags":["hiking"],"title":"H","body":"b","url":"https://hike.example/","weight":3},
          {"id":"all","title":"G","body":"b","url":"https://general.example"},
          {"id":"track","title":"T","body":"b","url":"https://x.example/?uid=1"},
          {"id":"http","title":"T","body":"b","url":"http://x.example/"}
        ]}"##
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn catalog_hash_and_selection() {
        let raw = catalog_json();
        let pin = CatalogRef {
            sha256: Catalog::sha256(&raw),
        };
        assert_eq!(Catalog::verify(b"{}", &pin), Err(ConfigError::CatalogHash));
        let c = Catalog::verify(&raw, &pin).unwrap();
        let ids: Vec<_> = c.sponsors.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            ["cafe", "hike", "all"],
            "tracking / plain-http links dropped"
        );
        assert_eq!(c.sponsors[0].tags, ["coffee", "咖啡"]);

        let s = c.select(&["咖啡".into()], 5, 0);
        assert_eq!(
            s.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["cafe", "all"]
        );
        let s = c.select(&[], 5, 0);
        assert_eq!(s.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), ["all"]);
        let s = c.select(&["Hiking".into(), "coffee".into()], 1, 0);
        assert_eq!(s.len(), 1);
        // Weighted rotation: "hike" (weight 3) leads 3 times out of 4.
        let lead_hike = (0..400u64)
            .filter(|p| c.select(&["hiking".into(), "coffee".into()], 1, *p)[0].id == "hike")
            .count();
        assert_eq!(lead_hike, 300);
    }

    #[test]
    fn random_keys_roundtrip() {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = signing_key(&seed);
        let bytes = cfg(1).sign(&sk);
        assert!(RemoteConfig::verify(&bytes, &public_key(&sk), 5_000, 1).is_ok());
    }
}
