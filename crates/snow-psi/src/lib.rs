//! Interest matching without telling the server (or the peer) your interests.
//!
//! Two layers:
//!
//! 1. **Buckets** (server-visible). A tag maps to one of only [`BUCKETS`] = 64
//!    buckets, so very many tags share each bucket (k-anonymity). The matchmaker
//!    only ever sees the bucket number of your *primary* tag. The mapping is
//!    re-salted every week ([`epoch`]), so a bucket number isn't a stable label.
//!
//! 2. **PSI** (inside the E2EE session, after matching). Both phones run a
//!    ristretto255 Diffie–Hellman private set intersection over all their tags:
//!
//!    ```text
//!    A → B : shuffle{ H(t)·a }            B → A : shuffle{ H(u)·b }      (round 1)
//!    A → B : { (H(u)·b)·a } in B's order  B → A : { (H(t)·a)·b } in A's order (round 2)
//!    ```
//!    Each side then sees which of its own tags have `H(t)·ab` in the peer's set.
//!    Both sets are padded with random points to exactly [`SET_SIZE`], so neither
//!    side learns how many tags the other has — only the intersection.
//!
//! Limits (documented, inherent to PSI): a dishonest peer learns at most whether
//! your set contains any of the ≤ [`SET_SIZE`] tags it chose to probe with, per
//! chat; and it can lie about the result (it could lie in chat anyway).
//! Security is semi-honest DDH on ristretto255; the round messages ride inside
//! the Olm session, so the relay sees only ciphertext.
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// Every PSI message carries exactly this many points.
pub const SET_SIZE: usize = 16;
/// Server-visible bucket count (6 bits).
pub const BUCKETS: u8 = 64;
pub const MAX_TAG_CHARS: usize = 32;
const EPOCH_SECS: u64 = 7 * 86_400;
const BUCKET_DOMAIN: &[u8] = b"snowtalk-bucket-v1\0";
const PSI_DOMAIN: &[u8] = b"snowtalk-psi-v1\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PsiError {
    #[error("PSI message must have exactly {SET_SIZE} points")]
    BadLength,
    #[error("invalid group element")]
    BadPoint,
    #[error("PSI round received out of order")]
    OutOfOrder,
}

/// Canonical form so `#Cats`, `cats ` and full-width `ｃａｔｓ` are the same tag:
/// NFKC, lowercase, no leading `#`, single spaces, at most [`MAX_TAG_CHARS`].
pub fn normalize(tag: &str) -> Option<String> {
    let s: String = tag.nfkc().collect::<String>().to_lowercase();
    let s = s.trim().trim_start_matches(['#', '＃']).trim();
    let s: String = s
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_TAG_CHARS)
        .collect();
    (!s.is_empty()).then_some(s)
}

/// Week number since the Unix epoch; bucket salts rotate with it.
pub fn epoch(unix_secs: u64) -> u64 {
    unix_secs / EPOCH_SECS
}

/// Bucket of an already-normalized tag in `epoch`.
pub fn bucket(tag: &str, epoch: u64) -> u8 {
    let mut h = Sha256::new();
    h.update(BUCKET_DOMAIN);
    h.update(epoch.to_be_bytes());
    h.update(tag.as_bytes());
    // 64 divides 256, so this is unbiased.
    h.finalize()[0] % BUCKETS
}

fn hash_to_point(tag: &str) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(PSI_DOMAIN);
    h.update(tag.as_bytes());
    RistrettoPoint::from_uniform_bytes(&h.finalize().into())
}

fn random_point() -> RistrettoPoint {
    let mut b = [0u8; 64];
    OsRng.fill_bytes(&mut b);
    RistrettoPoint::from_uniform_bytes(&b)
}

fn random_scalar() -> Scalar {
    let mut b = [0u8; 64];
    OsRng.fill_bytes(&mut b);
    let s = Scalar::from_bytes_mod_order_wide(&b);
    b.zeroize();
    s
}

fn decode(points: &[[u8; 32]]) -> Result<Vec<RistrettoPoint>, PsiError> {
    if points.len() != SET_SIZE {
        return Err(PsiError::BadLength);
    }
    points
        .iter()
        .map(|b| {
            CompressedRistretto(*b)
                .decompress()
                .filter(|p| !p.is_identity())
                .ok_or(PsiError::BadPoint)
        })
        .collect()
}

fn encode(points: impl Iterator<Item = RistrettoPoint>) -> Vec<[u8; 32]> {
    points.map(|p| p.compress().to_bytes()).collect()
}

/// One side of a PSI run.
pub struct Psi {
    secret: Scalar,
    /// The tag behind each position of our round-1 message (`None` = padding).
    slots: Vec<Option<String>>,
    /// Peer's round-1 points, raised to our secret.
    peer_double: Option<HashSet<[u8; 32]>>,
}

impl Drop for Psi {
    fn drop(&mut self) {
        self.secret.zeroize();
        for s in self.slots.iter_mut().flatten() {
            s.zeroize();
        }
    }
}

impl Psi {
    /// Start with our tags (normalized, de-duplicated, at most [`SET_SIZE`]).
    /// Returns our round-1 message.
    pub fn new(tags: &[String]) -> (Self, Vec<[u8; 32]>) {
        let mut seen = HashSet::new();
        let mut slots: Vec<Option<String>> = tags
            .iter()
            .filter_map(|t| normalize(t))
            .filter(|t| seen.insert(t.clone()))
            .take(SET_SIZE)
            .map(Some)
            .collect();
        slots.resize(SET_SIZE, None);
        slots.shuffle(&mut OsRng);
        let secret = random_scalar();
        let round1 = encode(slots.iter().map(|s| match s {
            Some(t) => hash_to_point(t) * secret,
            None => random_point(),
        }));
        (
            Self {
                secret,
                slots,
                peer_double: None,
            },
            round1,
        )
    }

    /// Handle the peer's round 1; returns our round 2 (their points · our
    /// secret, in their order).
    pub fn respond(&mut self, peer_round1: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, PsiError> {
        if self.peer_double.is_some() {
            return Err(PsiError::OutOfOrder);
        }
        let pts = decode(peer_round1)?;
        let out = encode(pts.iter().map(|p| p * self.secret));
        self.peer_double = Some(out.iter().copied().collect());
        Ok(out)
    }

    /// Handle the peer's round 2 (our points · their secret). Returns our tags
    /// that the peer also has, in normalized form.
    pub fn finish(&self, peer_round2: &[[u8; 32]]) -> Result<Vec<String>, PsiError> {
        let theirs = self.peer_double.as_ref().ok_or(PsiError::OutOfOrder)?;
        decode(peer_round2)?;
        let mut common: Vec<String> = self
            .slots
            .iter()
            .zip(peer_round2)
            .filter_map(|(slot, p)| slot.as_ref().filter(|_| theirs.contains(p)).cloned())
            .collect();
        common.sort();
        Ok(common)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn run(a: &[&str], b: &[&str]) -> (Vec<String>, Vec<String>) {
        let (mut pa, a1) = Psi::new(&tags(a));
        let (mut pb, b1) = Psi::new(&tags(b));
        let a2 = pa.respond(&b1).unwrap();
        let b2 = pb.respond(&a1).unwrap();
        (pa.finish(&b2).unwrap(), pb.finish(&a2).unwrap())
    }

    #[test]
    fn finds_exactly_the_intersection_on_both_sides() {
        let (a, b) = run(
            &["貓", "#Hiking", "jazz"],
            &["hiking", "爵士", "ＪＡＺＺ", "chess"],
        );
        assert_eq!(a, tags(&["hiking", "jazz"]));
        assert_eq!(a, b);
    }

    #[test]
    fn disjoint_and_empty_sets() {
        assert_eq!(run(&["a", "b"], &["c"]), (vec![], vec![]));
        assert_eq!(run(&[], &["c"]), (vec![], vec![]));
        assert_eq!(run(&[], &[]), (vec![], vec![]));
    }

    #[test]
    fn messages_are_fixed_size_and_hide_the_tags() {
        let (_, one) = Psi::new(&tags(&["cats"]));
        let (_, many) = Psi::new(&tags(&["a", "b", "c", "d", "e", "f", "g", "h"]));
        assert_eq!(one.len(), SET_SIZE);
        assert_eq!(many.len(), SET_SIZE);
        // Fresh secret per run: the same tag never looks the same twice.
        let (_, again) = Psi::new(&tags(&["cats"]));
        assert!(one.iter().all(|p| !again.contains(p)));
        // And it isn't the bare hash either.
        let bare = hash_to_point("cats").compress().to_bytes();
        assert!(!one.contains(&bare));
    }

    #[test]
    fn caps_at_set_size_and_dedupes() {
        let many: Vec<String> = (0..40).map(|i| format!("t{i}")).collect();
        let (p, _) = Psi::new(&many);
        assert_eq!(p.slots.iter().flatten().count(), SET_SIZE);
        let (p, _) = Psi::new(&tags(&["Cats", "#cats", "  CATS "]));
        assert_eq!(p.slots.iter().flatten().count(), 1);
    }

    #[test]
    fn rejects_malformed_and_out_of_order() {
        let (mut p, r1) = Psi::new(&tags(&["x"]));
        assert_eq!(p.finish(&r1), Err(PsiError::OutOfOrder));
        assert_eq!(p.respond(&r1[..3]), Err(PsiError::BadLength));
        let mut bad = r1.clone();
        bad[0] = [0u8; 32]; // identity
        assert_eq!(p.respond(&bad), Err(PsiError::BadPoint));
        bad[0] = [0xff; 32]; // not a valid encoding
        assert_eq!(p.respond(&bad), Err(PsiError::BadPoint));
        p.respond(&r1).unwrap();
        assert_eq!(p.respond(&r1), Err(PsiError::OutOfOrder));
    }

    #[test]
    fn normalization_and_buckets() {
        assert_eq!(normalize("  #Hello   World "), Some("hello world".into()));
        assert_eq!(normalize("ＣＡＴ"), Some("cat".into()));
        assert_eq!(normalize("＃台北"), Some("台北".into()));
        assert_eq!(normalize(" # "), None);
        assert_eq!(normalize(&"x".repeat(50)).unwrap().len(), MAX_TAG_CHARS);
        let e = epoch(1_800_000_000);
        assert!(bucket("cats", e) < BUCKETS);
        assert_eq!(bucket("cats", e), bucket("cats", e));
        // Salt rotates weekly: across many tags, buckets must change somewhere.
        let moved = (0..50)
            .filter(|i| bucket(&format!("t{i}"), e) != bucket(&format!("t{i}"), e + 1))
            .count();
        assert!(moved > 30);
    }

    #[test]
    fn buckets_spread_evenly() {
        let mut counts = [0u32; BUCKETS as usize];
        for i in 0..64_000 {
            counts[bucket(&format!("tag{i}"), 1) as usize] += 1;
        }
        assert!(counts.iter().all(|c| (800..1200).contains(c)), "{counts:?}");
    }
}
