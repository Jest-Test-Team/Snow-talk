//! Received flash media, held as ciphertext until opened once.
//!
//! The sender keeps nothing after sending. The receiver reassembles chunks into
//! ciphertext and keeps it with its key; [`MediaStore::open`] decrypts it a single
//! time and destroys both. The plaintext then lives only in the buffer handed to
//! the UI, for at most `view_secs`.
use crate::api::{MediaInfo, MediaType};
use snow_media::{Incoming, MediaKey};
use snow_proto::MediaKind;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Items being received at once; further offers are ignored.
const MAX_INFLIGHT: usize = 4;
/// Received-but-unopened items kept per chat.
const MAX_STORED: usize = 16;
pub const DEFAULT_VIEW_SECS: u8 = 3;
pub const MAX_VIEW_SECS: u8 = 10;

pub fn clamp_view(secs: u8) -> u8 {
    match secs {
        0 => DEFAULT_VIEW_SECS,
        s => s.min(MAX_VIEW_SECS),
    }
}

/// Binds ciphertext to its offer.
pub fn aad(media_id: u64, kind: MediaKind) -> [u8; 9] {
    let mut a = [0u8; 9];
    a[..8].copy_from_slice(&media_id.to_be_bytes());
    a[8] = kind as u8;
    a
}

pub fn to_api(k: MediaKind) -> MediaType {
    match k {
        MediaKind::Image => MediaType::Image,
        MediaKind::Voice => MediaType::Voice,
    }
}

struct Meta {
    kind: MediaKind,
    view_secs: u8,
    key: MediaKey,
}

#[derive(Default)]
pub struct MediaStore {
    inflight: HashMap<u64, (Meta, Incoming)>,
    ready: HashMap<u64, (Meta, Vec<u8>)>,
}

impl MediaStore {
    pub fn offer(
        &mut self,
        id: u64,
        kind: MediaKind,
        len: u32,
        chunks: u16,
        key: [u8; 32],
        view_secs: u8,
    ) {
        let key = MediaKey::from_bytes(key);
        if self.inflight.len() >= MAX_INFLIGHT
            || self.ready.len() >= MAX_STORED
            || self.inflight.contains_key(&id)
            || self.ready.contains_key(&id)
        {
            return;
        }
        if let Ok(inc) = Incoming::new(len, chunks) {
            let meta = Meta {
                kind,
                view_secs: clamp_view(view_secs),
                key,
            };
            self.inflight.insert(id, (meta, inc));
        }
    }

    /// Add a chunk; returns the item's info once it is complete.
    pub fn chunk(&mut self, id: u64, index: u16, data: Vec<u8>) -> Option<MediaInfo> {
        let (_, inc) = self.inflight.get_mut(&id)?;
        match inc.add(index, data) {
            Ok(false) => None,
            Ok(true) => {
                let (meta, inc) = self.inflight.remove(&id)?;
                let ct = inc.into_ciphertext()?;
                let info = MediaInfo {
                    id,
                    kind: to_api(meta.kind),
                    view_secs: meta.view_secs,
                };
                self.ready.insert(id, (meta, ct));
                Some(info)
            }
            // A bad chunk poisons the item.
            Err(_) => {
                self.inflight.remove(&id);
                None
            }
        }
    }

    /// Decrypt once and forget. Returns the plaintext and how long it may be shown.
    pub fn open(&mut self, id: u64) -> Option<(Zeroizing<Vec<u8>>, u8)> {
        let (meta, ct) = self.ready.remove(&id)?;
        let plain = snow_media::open(&meta.key, &ct, &aad(id, meta.kind)).ok()?;
        Some((plain, meta.view_secs))
    }

    pub fn clear(&mut self) {
        self.inflight.clear();
        self.ready.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_open_once() {
        let plain = vec![9u8; 7000];
        let (key, ct) = snow_media::seal(&plain, &aad(5, MediaKind::Image)).unwrap();
        let mut s = MediaStore::default();
        let n = snow_media::chunk_count(ct.len());
        s.offer(5, MediaKind::Image, ct.len() as u32, n, *key.as_bytes(), 0);
        let parts: Vec<_> = snow_media::chunks(&ct).map(|c| c.to_vec()).collect();
        let mut info = None;
        for (i, p) in parts.into_iter().enumerate() {
            info = s.chunk(5, i as u16, p);
        }
        let info = info.unwrap();
        assert_eq!((info.id, info.view_secs), (5, DEFAULT_VIEW_SECS));
        let (got, secs) = s.open(5).unwrap();
        assert_eq!((&*got, secs), (&plain, 3));
        assert!(s.open(5).is_none(), "one view only");
    }

    #[test]
    fn wrong_kind_or_bad_chunk_never_opens() {
        let (key, ct) = snow_media::seal(b"hi", &aad(1, MediaKind::Image)).unwrap();
        let mut s = MediaStore::default();
        // Offer claims Voice: AAD mismatch, so decryption fails.
        s.offer(1, MediaKind::Voice, ct.len() as u32, 1, *key.as_bytes(), 99);
        assert_eq!(s.chunk(1, 0, ct.clone()).unwrap().view_secs, MAX_VIEW_SECS);
        assert!(s.open(1).is_none());
        s.offer(2, MediaKind::Image, ct.len() as u32, 1, *key.as_bytes(), 1);
        assert!(s.chunk(2, 0, vec![0; 3]).is_none());
        assert!(s.chunk(2, 0, ct).is_none(), "poisoned item is gone");
    }

    #[test]
    fn bounds_inflight() {
        let mut s = MediaStore::default();
        for id in 0..10 {
            s.offer(id, MediaKind::Voice, 100, 1, [0; 32], 1);
        }
        assert_eq!(s.inflight.len(), MAX_INFLIGHT);
    }
}
