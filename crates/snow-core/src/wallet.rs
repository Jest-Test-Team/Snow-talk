//! Anonymous tokens held by this device (good-chat reputation, VIP perks).
//!
//! This is the one piece of state the app persists: after
//! `ChatListener::on_wallet_changed` the app stores `SnowClient::wallet_export()`
//! in the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) / an
//! Android-Keystore-wrapped file, and hands it back with `wallet_import` on start.
//! Tokens are bearer credentials but unlinkable: spending one tells the server
//! only "someone with a good-chat history", not who.
use serde::{Deserialize, Serialize};
use snow_tokens::{Kind, Token};
use std::collections::BTreeMap;

/// Keep at most this many tokens per kind (oldest dropped).
const MAX_PER_KIND: usize = 64;

#[derive(Default, Serialize, Deserialize)]
pub struct Wallet {
    /// First-seen issuer key per (kind, epoch). A different key later in the
    /// same epoch would mean the server is trying to tag us: refused.
    keys: BTreeMap<(u8, u32), [u8; 32]>,
    tokens: Vec<Token>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PinError {
    KeyChanged,
}

// `take`/`prune` are used by trusted-queue spending (next step).
#[allow(dead_code)]
impl Wallet {
    /// Accept `pk` for `(kind, epoch)` if it is new or matches what we saw before.
    pub fn pin(&mut self, kind: Kind, epoch: u32, pk: [u8; 32]) -> Result<(), PinError> {
        match self.keys.entry((kind as u8, epoch)) {
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(pk);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(o) if *o.get() == pk => Ok(()),
            _ => Err(PinError::KeyChanged),
        }
    }

    pub fn add(&mut self, tokens: Vec<Token>) {
        for t in tokens {
            if self.tokens.iter().filter(|x| x.kind == t.kind).count() >= MAX_PER_KIND {
                if let Some(i) = self.tokens.iter().position(|x| x.kind == t.kind) {
                    self.tokens.remove(i);
                }
            }
            self.tokens.push(t);
        }
    }

    /// Drop tokens and keys too old to spend in `now_epoch`.
    pub fn prune(&mut self, now_epoch: u32) {
        self.tokens
            .retain(|t| snow_tokens::is_current(t.epoch, now_epoch));
        self.keys
            .retain(|(_, e), _| snow_tokens::is_current(*e, now_epoch));
    }

    pub fn count(&self, kind: Kind, now_epoch: u32) -> u32 {
        self.tokens
            .iter()
            .filter(|t| t.kind == kind && snow_tokens::is_current(t.epoch, now_epoch))
            .count() as u32
    }

    /// Remove and return `n` spendable tokens of `kind`, oldest epoch first, or
    /// nothing if there aren't enough.
    pub fn take(&mut self, kind: Kind, n: usize, now_epoch: u32) -> Option<Vec<Token>> {
        self.prune(now_epoch);
        let mut idx: Vec<usize> = (0..self.tokens.len())
            .filter(|&i| self.tokens[i].kind == kind)
            .collect();
        if idx.len() < n {
            return None;
        }
        idx.sort_by_key(|&i| self.tokens[i].epoch);
        let mut chosen: Vec<usize> = idx.into_iter().take(n).collect();
        chosen.sort_unstable_by(|a, b| b.cmp(a));
        Some(chosen.into_iter().map(|i| self.tokens.remove(i)).collect())
    }

    pub fn export(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("wallet serializes")
    }

    pub fn import(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(kind: Kind, epoch: u32, n: u8) -> Token {
        Token {
            kind,
            epoch,
            nonce: [n; 32],
            output: [[n; 32]; 2],
        }
    }

    #[test]
    fn pins_keys_per_epoch() {
        let mut w = Wallet::default();
        assert!(w.pin(Kind::Good, 5, [1; 32]).is_ok());
        assert!(w.pin(Kind::Good, 5, [1; 32]).is_ok());
        assert_eq!(w.pin(Kind::Good, 5, [2; 32]), Err(PinError::KeyChanged));
        assert!(w.pin(Kind::Good, 6, [2; 32]).is_ok(), "new epoch, new key");
        assert!(w.pin(Kind::Vip, 5, [3; 32]).is_ok());
    }

    #[test]
    fn take_spends_oldest_and_prunes() {
        let mut w = Wallet::default();
        w.add(vec![
            tok(Kind::Good, 9, 1),
            tok(Kind::Good, 10, 2),
            tok(Kind::Good, 8, 3),
        ]);
        w.add(vec![tok(Kind::Vip, 10, 4)]);
        assert_eq!(w.count(Kind::Good, 10), 2, "epoch 8 expired");
        assert!(w.take(Kind::Good, 3, 10).is_none());
        let t = w.take(Kind::Good, 1, 10).unwrap();
        assert_eq!(t[0].epoch, 9);
        assert_eq!(w.count(Kind::Good, 10), 1);
        assert_eq!(w.count(Kind::Vip, 10), 1);
        let back = Wallet::import(&w.export()).unwrap();
        assert_eq!(back.count(Kind::Good, 10), 1);
        assert!(Wallet::import(b"\xff\xff").is_none());
    }
}
