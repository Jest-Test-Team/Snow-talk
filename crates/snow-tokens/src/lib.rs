//! Anonymous, unlinkable tokens: "good-chat" reputation and paid perks.
//!
//! Privacy-Pass style issuance over the RFC 9497 **VOPRF** (ristretto255-SHA512):
//!
//! ```text
//! client: nonce ← random;  B = Blind(input(kind, epoch, nonce))      ── B ──▶ issuer
//! issuer: E = B·sk, DLEQ proof that E used the published key  ◀── E, π ──
//! client: verify π against the published key, output = Finalize(…)
//! token  = (kind, epoch, nonce, output)
//! redeem: issuer recomputes Evaluate(input) == output, then burns the nullifier
//! ```
//!
//! * **Unlinkable**: the issuer only ever saw `B`, a uniformly random point, so a
//!   token presented later can't be tied to the chat or purchase that earned it.
//! * **Key consistency**: the DLEQ proof forces the issuer to use the key it
//!   published for `(kind, epoch)`. Without it, a malicious server could give
//!   every user their own key and recognize them at redemption. Clients must
//!   only accept keys that everyone sees (signed remote config / cached per epoch).
//! * **Privately verifiable**: only the issuer can check a token, which is fine
//!   because the issuer is also the only verifier (our Worker). It also means no
//!   RSA: verification and issuance are constant-time curve operations.
//! * **Double spending** is stopped by the issuer storing each spent
//!   [`Token::nullifier`] until the token's epoch expires.
//!
//! Tokens are valid in their own and the following [`epoch`] (30–60 days).
use hmac::{Hmac, Mac};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use voprf::{
    BlindedElement, EvaluationElement, Group, Proof, Ristretto255, VoprfClient, VoprfServer,
};

pub const ELEM_LEN: usize = 32;
pub const PROOF_LEN: usize = 64;
pub const NONCE_LEN: usize = 32;
/// Most tokens issued in one request.
pub const MAX_BATCH: usize = 16;
pub const EPOCH_SECS: u64 = 30 * 86_400;
const INPUT_DOMAIN: &[u8] = b"snowtalk-token-v1";
const KEY_DOMAIN: &[u8] = b"snowtalk-token-key-v1";
const NULLIFIER_DOMAIN: &[u8] = b"snowtalk-nullifier-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Kind {
    /// Earned by finishing a chat without being reported.
    Good = 1,
    /// Bought (IAP): paranoid mode, priority queue, 24 h resume.
    Vip = 2,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("malformed token message")]
    Malformed,
    #[error("issuer proof did not verify (wrong or inconsistent key)")]
    BadProof,
    #[error("batch size out of range")]
    BadBatch,
}

/// 30-day epoch number. Keys rotate per epoch.
pub fn epoch(unix_secs: u64) -> u32 {
    (unix_secs / EPOCH_SECS) as u32
}

/// Whether a token from `token_epoch` may be spent in `now_epoch`.
pub fn is_current(token_epoch: u32, now_epoch: u32) -> bool {
    token_epoch == now_epoch || token_epoch + 1 == now_epoch
}

fn input(kind: Kind, epoch: u32, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(INPUT_DOMAIN.len() + 5 + NONCE_LEN);
    v.extend_from_slice(INPUT_DOMAIN);
    v.push(kind as u8);
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(nonce);
    v
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub kind: Kind,
    pub epoch: u32,
    pub nonce: [u8; NONCE_LEN],
    /// The 64-byte VOPRF output, as two halves (serde-friendly).
    pub output: [[u8; 32]; 2],
}

impl Token {
    /// What the issuer stores to stop double spending. Reveals nothing else.
    pub fn nullifier(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(NULLIFIER_DOMAIN);
        h.update(input(self.kind, self.epoch, &self.nonce));
        h.finalize().into()
    }

    fn output_bytes(&self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(&self.output[0]);
        o[32..].copy_from_slice(&self.output[1]);
        o
    }
}

/// Client side of one issuance request.
pub struct Request {
    kind: Kind,
    epoch: u32,
    items: Vec<([u8; NONCE_LEN], VoprfClient<Ristretto255>)>,
}

/// Start a request for `n` tokens. Send the returned blinded elements.
/// `seed`: 32 fresh bytes from the OS CSPRNG (drives nonces and blinds).
pub fn request(
    kind: Kind,
    epoch: u32,
    n: usize,
    seed: [u8; 32],
) -> Result<(Request, Vec<[u8; ELEM_LEN]>), TokenError> {
    let rng = &mut ChaCha20Rng::from_seed(seed);
    if n == 0 || n > MAX_BATCH {
        return Err(TokenError::BadBatch);
    }
    let mut items = Vec::with_capacity(n);
    let mut blinded = Vec::with_capacity(n);
    for _ in 0..n {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let r = VoprfClient::<Ristretto255>::blind(&input(kind, epoch, &nonce), rng)
            .map_err(|_| TokenError::Malformed)?;
        blinded.push(to32(&r.message.serialize())?);
        items.push((nonce, r.state));
    }
    Ok((Request { kind, epoch, items }, blinded))
}

fn to32(b: &[u8]) -> Result<[u8; 32], TokenError> {
    b.try_into().map_err(|_| TokenError::Malformed)
}

impl Request {
    /// Verify the issuer's proof against `public_key` (the key published for
    /// this kind and epoch) and unblind the tokens.
    pub fn finish(
        self,
        public_key: &[u8; ELEM_LEN],
        evaluated: &[[u8; ELEM_LEN]],
        proof: &[u8; PROOF_LEN],
    ) -> Result<Vec<Token>, TokenError> {
        if evaluated.len() != self.items.len() {
            return Err(TokenError::BadBatch);
        }
        let pk = Ristretto255::deserialize_elem(public_key).map_err(|_| TokenError::Malformed)?;
        let proof = Proof::<Ristretto255>::deserialize(proof).map_err(|_| TokenError::Malformed)?;
        let messages = evaluated
            .iter()
            .map(|e| EvaluationElement::<Ristretto255>::deserialize(e))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TokenError::Malformed)?;
        let inputs: Vec<Vec<u8>> = self
            .items
            .iter()
            .map(|(n, _)| input(self.kind, self.epoch, n))
            .collect();
        let clients: Vec<VoprfClient<Ristretto255>> =
            self.items.iter().map(|(_, c)| c.clone()).collect();
        let outputs = VoprfClient::batch_finalize(&inputs, &clients, &messages, &proof, pk)
            .map_err(|_| TokenError::BadProof)?;
        self.items
            .iter()
            .zip(outputs)
            .map(|((nonce, _), out)| {
                let out = out.map_err(|_| TokenError::Malformed)?;
                Ok(Token {
                    kind: self.kind,
                    epoch: self.epoch,
                    nonce: *nonce,
                    output: [to32(&out[..32])?, to32(&out[32..])?],
                })
            })
            .collect()
    }
}

/// Issuer / verifier for one `(kind, epoch)`. The secret key is derived from a
/// master secret, so nothing per-epoch needs to be stored.
pub struct Issuer {
    kind: Kind,
    epoch: u32,
    server: VoprfServer<Ristretto255>,
}

impl Issuer {
    pub fn new(master: &[u8], kind: Kind, epoch: u32) -> Result<Self, TokenError> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(master).expect("any key length");
        m.update(KEY_DOMAIN);
        m.update(&[kind as u8]);
        m.update(&epoch.to_be_bytes());
        let seed = m.finalize().into_bytes();
        let server = VoprfServer::<Ristretto255>::new_from_seed(&seed, KEY_DOMAIN)
            .map_err(|_| TokenError::Malformed)?;
        Ok(Self {
            kind,
            epoch,
            server,
        })
    }

    pub fn public_key(&self) -> [u8; ELEM_LEN] {
        to32(&Ristretto255::serialize_elem(self.server.get_public_key())).expect("32 bytes")
    }

    /// Evaluate blinded elements and prove it was done with [`Self::public_key`].
    /// `seed`: 32 fresh random bytes (for the proof's nonce).
    pub fn issue(
        &self,
        blinded: &[[u8; ELEM_LEN]],
        seed: [u8; 32],
    ) -> Result<(Vec<[u8; ELEM_LEN]>, [u8; PROOF_LEN]), TokenError> {
        let rng = &mut ChaCha20Rng::from_seed(seed);
        if blinded.is_empty() || blinded.len() > MAX_BATCH {
            return Err(TokenError::BadBatch);
        }
        let elems = blinded
            .iter()
            .map(|b| BlindedElement::<Ristretto255>::deserialize(b))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TokenError::Malformed)?;
        let r = self
            .server
            .batch_blind_evaluate(rng, &elems)
            .map_err(|_| TokenError::Malformed)?;
        let evaluated = r
            .messages
            .iter()
            .map(|m| to32(&m.serialize()))
            .collect::<Result<Vec<_>, _>>()?;
        let proof: [u8; PROOF_LEN] = r
            .proof
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| TokenError::Malformed)?;
        Ok((evaluated, proof))
    }

    /// Is this a genuine token of our kind and epoch? (Doesn't check spending.)
    pub fn verify(&self, t: &Token) -> bool {
        if t.kind != self.kind || t.epoch != self.epoch {
            return false;
        }
        match self.server.evaluate(&input(t.kind, t.epoch, &t.nonce)) {
            Ok(out) => out.as_slice().ct_eq(&t.output_bytes()).into(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// Distinct seeds per call (tests only; real callers use the OS CSPRNG).
    fn seed() -> [u8; 32] {
        static N: AtomicU8 = AtomicU8::new(1);
        let mut s = [0u8; 32];
        s[0] = N.fetch_add(1, Ordering::Relaxed);
        s[31] = 0x5a;
        s
    }

    fn issue(n: usize) -> (Issuer, Vec<Token>) {
        let iss = Issuer::new(b"master", Kind::Good, 7).unwrap();
        let (req, blinded) = request(Kind::Good, 7, n, seed()).unwrap();
        let (ev, proof) = iss.issue(&blinded, seed()).unwrap();
        let toks = req.finish(&iss.public_key(), &ev, &proof).unwrap();
        (iss, toks)
    }

    #[test]
    fn issue_and_verify_batch() {
        let (iss, toks) = issue(5);
        assert_eq!(toks.len(), 5);
        assert!(toks.iter().all(|t| iss.verify(t)));
        let nf: std::collections::HashSet<_> = toks.iter().map(|t| t.nullifier()).collect();
        assert_eq!(nf.len(), 5, "distinct nullifiers");
    }

    #[test]
    fn forged_or_mismatched_tokens_fail() {
        let (iss, toks) = issue(1);
        let mut t = toks[0].clone();
        t.output[0][0] ^= 1;
        assert!(!iss.verify(&t));
        let mut t = toks[0].clone();
        t.nonce[0] ^= 1;
        assert!(!iss.verify(&t));
        // Same master, other kind or epoch: different key.
        assert!(!Issuer::new(b"master", Kind::Vip, 7)
            .unwrap()
            .verify(&toks[0]));
        assert!(!Issuer::new(b"master", Kind::Good, 8)
            .unwrap()
            .verify(&toks[0]));
        assert!(!Issuer::new(b"other", Kind::Good, 7)
            .unwrap()
            .verify(&toks[0]));
    }

    #[test]
    fn proof_pins_the_published_key() {
        // A server evaluating with a different (e.g. per-user tagging) key is caught.
        let honest = Issuer::new(b"master", Kind::Good, 7).unwrap();
        let tagging = Issuer::new(b"user-42-key", Kind::Good, 7).unwrap();
        let (req, blinded) = request(Kind::Good, 7, 2, seed()).unwrap();
        let (ev, proof) = tagging.issue(&blinded, seed()).unwrap();
        assert_eq!(
            req.finish(&honest.public_key(), &ev, &proof).unwrap_err(),
            TokenError::BadProof
        );
    }

    #[test]
    fn issuer_sees_only_random_points() {
        let (_, a) = request(Kind::Good, 7, 1, seed()).unwrap();
        let (_, b) = request(Kind::Good, 7, 1, seed()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn bounds_and_garbage() {
        assert_eq!(
            request(Kind::Good, 1, 0, seed()).err(),
            Some(TokenError::BadBatch)
        );
        assert_eq!(
            request(Kind::Good, 1, MAX_BATCH + 1, seed()).err(),
            Some(TokenError::BadBatch)
        );
        let iss = Issuer::new(b"m", Kind::Good, 1).unwrap();
        assert_eq!(
            iss.issue(&[[0xff; 32]], seed()).err(),
            Some(TokenError::Malformed)
        );
        assert_eq!(iss.issue(&[], seed()).err(), Some(TokenError::BadBatch));
        let (req, blinded) = request(Kind::Good, 1, 2, seed()).unwrap();
        let (ev, proof) = iss.issue(&blinded, seed()).unwrap();
        assert_eq!(
            req.finish(&iss.public_key(), &ev[..1], &proof).err(),
            Some(TokenError::BadBatch)
        );
    }

    #[test]
    fn epochs_and_wire_size() {
        assert!(is_current(5, 5) && is_current(5, 6));
        assert!(!is_current(5, 7) && !is_current(6, 5));
        assert_eq!(epoch(EPOCH_SECS * 3 + 1), 3);
        let (_, toks) = issue(1);
        let b = postcard::to_allocvec(&toks[0]).unwrap();
        assert!(b.len() <= 104, "{}", b.len());
        assert_eq!(postcard::from_bytes::<Token>(&b).unwrap(), toks[0]);
    }
}
