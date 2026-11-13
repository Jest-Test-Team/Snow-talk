//! VIP saved sessions: the one exception to "nothing leaves RAM".
//!
//! After the room has been extended to 24 h (`SnowClient::extend_chat`),
//! `SnowClient::suspend` seals the ratchet state, the resume ticket and the
//! non-burning messages under a 32-byte key the app keeps in hardware-backed
//! storage (Secure Enclave-wrapped Keychain item / StrongBox-wrapped Keystore
//! key), disconnects without leaving, and stops. `SnowClient::resume_saved` opens
//! it and re-enters the same room slot. The UI must say plainly that this keeps an
//! encrypted copy of the conversation on the device. Burn-after-reading messages
//! and media are never saved.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use snow_proto::Role;
use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 1;
const AAD: &[u8] = b"snowtalk/saved-session/v1";

#[derive(Serialize, Deserialize)]
pub struct Saved {
    pub resume: String,
    pub role: Role,
    pub paranoid: bool,
    pub trusted: bool,
    /// `snow_crypto::ChatSession::save` output (itself encrypted).
    pub session: String,
    /// `(id, from_me, body)` of messages without a burn timer.
    pub messages: Vec<(u64, bool, String)>,
}

impl Drop for Saved {
    fn drop(&mut self) {
        self.resume.zeroize();
        self.session.zeroize();
        for (_, _, b) in &mut self.messages {
            b.zeroize();
        }
    }
}

/// Subkeys: one for the session pickle, one for the outer seal.
pub struct Keys {
    pub pickle: Zeroizing<[u8; 32]>,
    seal: Zeroizing<[u8; 32]>,
}

impl Keys {
    pub fn derive(key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(AAD), key);
        let mut pickle = Zeroizing::new([0u8; 32]);
        let mut seal = Zeroizing::new([0u8; 32]);
        hk.expand(b"pickle", pickle.as_mut()).expect("32 bytes");
        hk.expand(b"seal", seal.as_mut()).expect("32 bytes");
        Self { pickle, seal }
    }
}

impl Saved {
    pub fn seal(&self, keys: &Keys) -> Vec<u8> {
        use rand::RngCore;
        let plain = Zeroizing::new(postcard::to_allocvec(self).expect("serializes"));
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = ChaCha20Poly1305::new_from_slice(keys.seal.as_ref())
            .expect("32-byte key")
            .encrypt(
                &Nonce::try_from(&nonce[..]).expect("12 bytes"),
                Payload {
                    msg: &plain,
                    aad: AAD,
                },
            )
            .expect("encrypts");
        let mut out = vec![VERSION];
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    pub fn open(bytes: &[u8], keys: &Keys) -> Option<Self> {
        if bytes.len() < 1 + 12 + 16 || bytes[0] != VERSION {
            return None;
        }
        let plain = Zeroizing::new(
            ChaCha20Poly1305::new_from_slice(keys.seal.as_ref())
                .expect("32-byte key")
                .decrypt(
                    &Nonce::try_from(&bytes[1..13]).ok()?,
                    Payload {
                        msg: &bytes[13..],
                        aad: AAD,
                    },
                )
                .ok()?,
        );
        postcard::from_bytes(&plain).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_tamper() {
        let keys = Keys::derive(&[5; 32]);
        let s = Saved {
            resume: "ticket".into(),
            role: Role::Responder,
            paranoid: false,
            trusted: true,
            session: "pickle".into(),
            messages: vec![(1, true, "SECRET-MARKER".into())],
        };
        let b = s.seal(&keys);
        assert!(!b.windows(13).any(|w| w == b"SECRET-MARKER"));
        let o = Saved::open(&b, &keys).unwrap();
        assert_eq!(o.messages[0].2, "SECRET-MARKER");
        assert!(o.trusted && o.role == Role::Responder);
        assert!(Saved::open(&b, &Keys::derive(&[6; 32])).is_none());
        let mut t = b.clone();
        t[20] ^= 1;
        assert!(Saved::open(&t, &keys).is_none());
        assert!(Saved::open(&[1, 2, 3], &keys).is_none());
    }
}
