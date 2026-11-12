//! End-to-end session for one anonymous chat.
//!
//! Every chat uses a brand-new Olm [`Account`] that lives only in RAM, so there is
//! no long-term identity and no key directory. Both peers are online when they're
//! matched, so the ref's X3DH prekey directory isn't needed: the responder's
//! one-time key is handed over through the relay instead.
//!
//! ```text
//!  Initiator                         relay                         Responder
//!  Commit(H(idA‖nA))  ───────────────────────────────────────────▶
//!                     ◀─────────────────────────────────────────── Commit(H(idB‖otkB‖nB))
//!  Reveal(idA,nA)     ───────────────────────────────────────────▶ (verify)
//!  (verify)           ◀─────────────────────────────────────────── Reveal(idB,otkB,nB)
//!  3DH + Double Ratchet session ── Olm pre-key msg(Inner::Ready) ─▶ inbound session
//! ```
//!
//! Each side commits to its keys before seeing the other side's, so a relay
//! acting as a MITM has to fix its own keys blind. That limits it to a 2⁻⁴² chance
//! of producing matching [`Sas`] emoji on both screens.
#![forbid(unsafe_code)]

mod sas;

pub use sas::{Sas, SAS_EMOJI};

use rand::RngCore;
use sha2::{Digest, Sha256};
use snow_proto::{decode_inner, encode_inner, Handshake, Inner, PeerEnvelope, Role};
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;
use zeroize::Zeroizing;

const COMMIT_DOMAIN: &[u8] = b"snowtalk-commit-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("handshake message arrived out of order")]
    UnexpectedMessage,
    #[error("peer's reveal does not match its commitment")]
    CommitMismatch,
    #[error("peer sent an invalid or low-order key")]
    BadKey,
    #[error("message could not be decrypted or authenticated")]
    Decrypt,
    #[error("plaintext is malformed or too large")]
    Plaintext,
}

fn commitment(identity: &[u8; 32], otk: Option<&[u8; 32]>, nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    h.update(identity);
    match otk {
        Some(k) => {
            h.update([1]);
            h.update(k);
        }
        None => h.update([0]),
    }
    h.update(nonce);
    h.finalize().into()
}

/// Peer keys learned from a verified reveal.
struct PeerKeys {
    identity: Curve25519PublicKey,
    otk: Option<Curve25519PublicKey>,
}

/// Result of feeding a handshake message to the [`Handshaker`].
pub enum Step {
    /// Send this to the peer and keep waiting.
    Send(Handshake),
    /// Initiator only: the session is ready. Send `first` (an encrypted
    /// [`Inner::Ready`]) so the responder can build its side.
    Established {
        session: Box<ChatSession>,
        first: PeerEnvelope,
    },
    /// Responder only: wait for the initiator's pre-key message, then call
    /// [`Handshaker::accept`].
    AwaitPreKey,
}

/// Sans-IO handshake state machine. Holds the ephemeral account until the session exists.
pub struct Handshaker {
    role: Role,
    account: Account,
    otk: Option<Curve25519PublicKey>,
    nonce: Zeroizing<[u8; 32]>,
    peer_commit: Option<[u8; 32]>,
    peer: Option<PeerKeys>,
}

impl Handshaker {
    /// Create fresh ephemeral keys and return the commitment to send first.
    pub fn new(role: Role) -> (Self, Handshake) {
        let mut account = Account::new();
        let otk = (role == Role::Responder).then(|| {
            account.generate_one_time_keys(1);
            let k = *account
                .one_time_keys()
                .values()
                .next()
                .expect("generated one key");
            account.mark_keys_as_published();
            k
        });
        let mut nonce = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(nonce.as_mut());
        let commit = commitment(
            account.curve25519_key().as_bytes(),
            otk.as_ref().map(|k| k.as_bytes()),
            &nonce,
        );
        let hs = Self {
            role,
            account,
            otk,
            nonce,
            peer_commit: None,
            peer: None,
        };
        (hs, Handshake::Commit(commit))
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Feed a handshake message from the peer.
    pub fn on_message(&mut self, msg: Handshake) -> Result<Step, CryptoError> {
        match (msg, self.peer_commit, &self.peer) {
            (Handshake::Commit(c), None, None) => {
                self.peer_commit = Some(c);
                Ok(Step::Send(Handshake::Reveal {
                    identity_key: self.account.curve25519_key().to_bytes(),
                    one_time_key: self.otk.map(|k| k.to_bytes()),
                    nonce: *self.nonce,
                }))
            }
            (
                Handshake::Reveal {
                    identity_key,
                    one_time_key,
                    nonce,
                },
                Some(c),
                None,
            ) => {
                if commitment(&identity_key, one_time_key.as_ref(), &nonce) != c {
                    return Err(CryptoError::CommitMismatch);
                }
                // The initiator needs the responder's OTK; the responder must not get one.
                if (self.role == Role::Initiator) != one_time_key.is_some() {
                    return Err(CryptoError::UnexpectedMessage);
                }
                let peer = PeerKeys {
                    identity: Curve25519PublicKey::from_bytes(identity_key),
                    otk: one_time_key.map(Curve25519PublicKey::from_bytes),
                };
                match self.role {
                    Role::Responder => {
                        self.peer = Some(peer);
                        Ok(Step::AwaitPreKey)
                    }
                    Role::Initiator => {
                        let otk = peer.otk.expect("checked above");
                        let session = self
                            .account
                            .create_outbound_session(SessionConfig::version_1(), peer.identity, otk)
                            .map_err(|_| CryptoError::BadKey)?;
                        let sas = Sas::derive(
                            self.account.curve25519_key().as_bytes(),
                            peer.identity.as_bytes(),
                            otk.as_bytes(),
                        );
                        let mut session = ChatSession { session, sas };
                        let first = session.encrypt(&Inner::Ready)?;
                        Ok(Step::Established {
                            session: Box::new(session),
                            first,
                        })
                    }
                }
            }
            _ => Err(CryptoError::UnexpectedMessage),
        }
    }

    /// Responder only: build the inbound session from the initiator's first message.
    pub fn accept(mut self, first: &PeerEnvelope) -> Result<(ChatSession, Inner), CryptoError> {
        let peer = self.peer.take().ok_or(CryptoError::UnexpectedMessage)?;
        let PeerEnvelope::Olm { kind: 0, body } = first else {
            return Err(CryptoError::UnexpectedMessage);
        };
        let OlmMessage::PreKey(pre) =
            OlmMessage::from_parts(0, body).map_err(|_| CryptoError::Decrypt)?
        else {
            return Err(CryptoError::Decrypt);
        };
        let otk = self.otk.expect("responder always has an OTK");
        if pre.one_time_key() != otk {
            return Err(CryptoError::BadKey);
        }
        let res = self
            .account
            .create_inbound_session(SessionConfig::version_1(), peer.identity, &pre)
            .map_err(|_| CryptoError::Decrypt)?;
        let plaintext = Zeroizing::new(res.plaintext);
        let inner = decode_inner(&plaintext).map_err(|_| CryptoError::Plaintext)?;
        let sas = Sas::derive(
            peer.identity.as_bytes(),
            self.account.curve25519_key().as_bytes(),
            otk.as_bytes(),
        );
        Ok((
            ChatSession {
                session: res.session,
                sas,
            },
            inner,
        ))
    }
}

/// An established Double Ratchet session. Lives only in RAM; dropping it wipes the keys.
pub struct ChatSession {
    session: Session,
    sas: Sas,
}

impl ChatSession {
    /// Encrypt a padded [`Inner`]. Every ciphertext of a given Olm message type has the same length.
    pub fn encrypt(&mut self, msg: &Inner) -> Result<PeerEnvelope, CryptoError> {
        let plaintext = Zeroizing::new(encode_inner(msg).map_err(|_| CryptoError::Plaintext)?);
        let m = self
            .session
            .encrypt(plaintext.as_slice())
            .map_err(|_| CryptoError::BadKey)?;
        let (kind, body) = m.to_parts();
        Ok(PeerEnvelope::Olm {
            kind: kind as u8,
            body,
        })
    }

    pub fn decrypt(&mut self, env: &PeerEnvelope) -> Result<Inner, CryptoError> {
        let PeerEnvelope::Olm { kind, body } = env else {
            return Err(CryptoError::UnexpectedMessage);
        };
        let m = OlmMessage::from_parts(*kind as usize, body).map_err(|_| CryptoError::Decrypt)?;
        let plaintext = Zeroizing::new(self.session.decrypt(&m).map_err(|_| CryptoError::Decrypt)?);
        decode_inner(&plaintext).map_err(|_| CryptoError::Plaintext)
    }

    /// Short authentication string the users can compare out loud.
    pub fn sas(&self) -> Sas {
        self.sas
    }
}
