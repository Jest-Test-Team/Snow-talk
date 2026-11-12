//! Stateless hashcash proof-of-work.
//!
//! The server issues `challenge = ts || difficulty || rand || HMAC(key, ts || difficulty || rand)`.
//! The client finds `nonce` such that `SHA-256(DOMAIN || challenge || nonce)` has at
//! least `difficulty` leading zero bits. Verification is one HMAC + one SHA-256,
//! so it is cheap on Workers. The server must also reject replays of `rand`
//! within [`MAX_AGE_SECS`] (see [`Challenge::replay_id`]).
#![no_std]
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"snowtalk-pow-v1";
/// Encoded challenge length: ts(8) + difficulty(1) + rand(16) + mac(32).
pub const CHALLENGE_LEN: usize = 57;
/// Challenges older than this are rejected.
pub const MAX_AGE_SECS: u64 = 60;
/// Hard ceiling so a misconfigured server can't hang clients forever.
pub const MAX_DIFFICULTY: u8 = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PowError {
    #[error("malformed challenge")]
    Malformed,
    #[error("challenge was not issued by this server")]
    BadMac,
    #[error("challenge expired")]
    Expired,
    #[error("not enough work")]
    InsufficientWork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    pub issued_at: u64,
    pub difficulty: u8,
    pub rand: [u8; 16],
    mac: [u8; 32],
}

fn mac_of(key: &[u8], issued_at: u64, difficulty: u8, rand: &[u8; 16]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key");
    m.update(DOMAIN);
    m.update(&issued_at.to_be_bytes());
    m.update(&[difficulty]);
    m.update(rand);
    m.finalize().into_bytes().into()
}

impl Challenge {
    /// Server side: mint a challenge. `rand` must come from a CSPRNG.
    pub fn issue(key: &[u8], now: u64, difficulty: u8, rand: [u8; 16]) -> Self {
        let difficulty = difficulty.min(MAX_DIFFICULTY);
        Self {
            issued_at: now,
            difficulty,
            rand,
            mac: mac_of(key, now, difficulty, &rand),
        }
    }

    pub fn to_bytes(&self) -> [u8; CHALLENGE_LEN] {
        let mut out = [0u8; CHALLENGE_LEN];
        out[..8].copy_from_slice(&self.issued_at.to_be_bytes());
        out[8] = self.difficulty;
        out[9..25].copy_from_slice(&self.rand);
        out[25..].copy_from_slice(&self.mac);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, PowError> {
        if b.len() != CHALLENGE_LEN || b[8] > MAX_DIFFICULTY {
            return Err(PowError::Malformed);
        }
        Ok(Self {
            issued_at: u64::from_be_bytes(b[..8].try_into().unwrap()),
            difficulty: b[8],
            rand: b[9..25].try_into().unwrap(),
            mac: b[25..].try_into().unwrap(),
        })
    }

    /// Value the server stores (until expiry) to stop a solution being reused.
    pub fn replay_id(&self) -> [u8; 16] {
        self.rand
    }

    /// Client side: brute-force a nonce. Expected work is `2^difficulty` hashes.
    pub fn solve(&self) -> u64 {
        let bytes = self.to_bytes();
        let mut base = Sha256::new();
        base.update(DOMAIN);
        base.update(bytes);
        (0u64..)
            .find(|n| leading_zero_bits(&finish(&base, *n)) >= self.difficulty as u32)
            .expect("u64 space is never exhausted at difficulty <= 32")
    }

    /// Server side: check MAC, freshness and work. Replay protection is the caller's job.
    pub fn verify(key: &[u8], now: u64, challenge: &[u8], nonce: u64) -> Result<Self, PowError> {
        let c = Self::from_bytes(challenge)?;
        let expected = mac_of(key, c.issued_at, c.difficulty, &c.rand);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&expected[..], &c.mac[..])) {
            return Err(PowError::BadMac);
        }
        if now < c.issued_at || now - c.issued_at > MAX_AGE_SECS {
            return Err(PowError::Expired);
        }
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(challenge);
        if leading_zero_bits(&finish(&h, nonce)) < c.difficulty as u32 {
            return Err(PowError::InsufficientWork);
        }
        Ok(c)
    }
}

fn finish(base: &Sha256, nonce: u64) -> [u8; 32] {
    let mut h = base.clone();
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for b in h {
        if *b == 0 {
            bits += 8;
        } else {
            return bits + b.leading_zeros();
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &[u8] = b"test-key";

    #[test]
    fn solve_then_verify() {
        let c = Challenge::issue(KEY, 1000, 12, [9; 16]);
        let n = c.solve();
        assert_eq!(Challenge::verify(KEY, 1010, &c.to_bytes(), n), Ok(c));
    }

    #[test]
    fn rejects_forged_expired_and_lazy() {
        let c = Challenge::issue(KEY, 1000, 12, [9; 16]);
        let n = c.solve();
        let b = c.to_bytes();
        assert_eq!(
            Challenge::verify(b"other", 1000, &b, n),
            Err(PowError::BadMac)
        );
        assert_eq!(
            Challenge::verify(KEY, 1000 + MAX_AGE_SECS + 1, &b, n),
            Err(PowError::Expired)
        );
        assert_eq!(Challenge::verify(KEY, 999, &b, n), Err(PowError::Expired));
        // Lowering the difficulty breaks the MAC.
        let mut weaker = b;
        weaker[8] = 1;
        assert_eq!(
            Challenge::verify(KEY, 1000, &weaker, 0),
            Err(PowError::BadMac)
        );
        let bad_nonce = (0u64..)
            .find(|x| Challenge::verify(KEY, 1000, &b, *x).is_err())
            .unwrap();
        assert_eq!(
            Challenge::verify(KEY, 1000, &b, bad_nonce),
            Err(PowError::InsufficientWork)
        );
    }

    #[test]
    fn leading_zeros() {
        let mut h = [0u8; 32];
        h[1] = 0b0001_0000;
        assert_eq!(leading_zero_bits(&h), 11);
    }
}
