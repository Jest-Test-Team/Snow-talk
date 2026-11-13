//! Flash photos and voice notes.
//!
//! * **Metadata-free images**: [`sanitize_image`] fully decodes the picture and
//!   re-encodes the pixels as a fresh baseline JPEG. Nothing from the original
//!   file (EXIF/GPS, XMP, ICC, maker notes, thumbnails, trailing data) survives,
//!   because none of it is copied — there's no "strip list" to get wrong. The EXIF
//!   orientation is applied to the pixels first so photos aren't sideways.
//! * **Per-media key**: [`seal`] encrypts each item under a fresh random
//!   ChaCha20-Poly1305 [`MediaKey`]. The key travels in the (already E2EE) offer;
//!   the receiver keeps only ciphertext until the user actually views it, and
//!   destroying the key burns the item even if ciphertext lingers.
//! * **Chunking**: [`chunks`] splits ciphertext so each piece fits one fixed-size
//!   4 KB frame; [`Incoming`] reassembles with strict bounds.
//!
//! Voice notes are recorded and encoded natively (AAC/Opus in memory) and are
//! treated as opaque bytes here: sealed and chunked, not re-encoded.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use image::{DynamicImage, ImageDecoder, ImageReader, Limits};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::Cursor;
use zeroize::Zeroizing;

/// Longest side of a sanitized image, in pixels.
pub const MAX_DIM: u32 = 1280;
/// Upper bound on a sanitized item (before encryption). Keeps a photo to about
/// 40 frames, i.e. a few seconds even on the free rate cap.
pub const MAX_MEDIA_BYTES: usize = 120 * 1024;
/// Ciphertext bytes per chunk; with headers this fits one padded plaintext frame.
pub const CHUNK_LEN: usize = 3072;
const TAG_LEN: usize = 16;
pub const MAX_CHUNKS: u16 = ((MAX_MEDIA_BYTES + TAG_LEN).div_ceil(CHUNK_LEN)) as u16;
/// Inputs larger than this are refused before decoding.
pub const MAX_INPUT_BYTES: usize = 40 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MediaError {
    #[error("unsupported or corrupt image")]
    BadImage,
    #[error("media too large")]
    TooLarge,
    #[error("media chunk out of range or inconsistent")]
    BadChunk,
    #[error("media failed to decrypt")]
    Decrypt,
}

/// Decode `input` (JPEG, PNG, WebP, GIF) and re-encode it as a metadata-free JPEG
/// no larger than [`MAX_MEDIA_BYTES`] and [`MAX_DIM`] on its longest side.
/// HEIC isn't decodable here; iOS converts to JPEG before calling.
pub fn sanitize_image(input: &[u8]) -> Result<Vec<u8>, MediaError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(MediaError::TooLarge);
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(512 * 1024 * 1024);
    let mut reader = ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|_| MediaError::BadImage)?;
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(|_| MediaError::BadImage)?;
    let orientation = decoder.orientation().ok();
    let mut img = DynamicImage::from_decoder(decoder).map_err(|_| MediaError::BadImage)?;
    if let Some(o) = orientation {
        img.apply_orientation(o);
    }
    // Pixels only: drop alpha and any colour profile by going to plain RGB8.
    let mut rgb = DynamicImage::ImageRgb8(fit(img, MAX_DIM).to_rgb8());
    loop {
        for q in [80u8, 70, 60, 50, 40] {
            let out = encode_jpeg(&rgb, q)?;
            if out.len() <= MAX_MEDIA_BYTES {
                return Ok(out);
            }
        }
        let (w, h) = (rgb.width(), rgb.height());
        if w.max(h) <= 64 {
            return Err(MediaError::TooLarge);
        }
        rgb = rgb.resize(w * 3 / 4, h * 3 / 4, image::imageops::FilterType::Triangle);
    }
}

fn fit(img: DynamicImage, max: u32) -> DynamicImage {
    if img.width().max(img.height()) <= max {
        img
    } else {
        img.resize(max, max, image::imageops::FilterType::Triangle)
    }
}

fn encode_jpeg(img: &DynamicImage, quality: u8) -> Result<Vec<u8>, MediaError> {
    let mut out = Vec::new();
    let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
    img.write_with_encoder(enc)
        .map_err(|_| MediaError::BadImage)?;
    Ok(out)
}

/// A single-use media key. Zeroized on drop.
#[derive(Clone)]
pub struct MediaKey(Zeroizing<[u8; 32]>);

impl MediaKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn cipher(key: &MediaKey) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("32-byte key")
}

/// Encrypt under a fresh key. `aad` binds the ciphertext to its offer (media id,
/// kind), so chunks can't be spliced into another item. The key is used exactly
/// once, so a fixed nonce is safe.
pub fn seal(plain: &[u8], aad: &[u8]) -> Result<(MediaKey, Vec<u8>), MediaError> {
    if plain.len() > MAX_MEDIA_BYTES {
        return Err(MediaError::TooLarge);
    }
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    let key = MediaKey::from_bytes(k);
    k.fill(0);
    let ct = cipher(&key)
        .encrypt(&Nonce::default(), Payload { msg: plain, aad })
        .map_err(|_| MediaError::TooLarge)?;
    Ok((key, ct))
}

pub fn open(key: &MediaKey, ct: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, MediaError> {
    cipher(key)
        .decrypt(&Nonce::default(), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| MediaError::Decrypt)
}

pub fn chunks(ct: &[u8]) -> impl Iterator<Item = &[u8]> {
    ct.chunks(CHUNK_LEN)
}

/// Number of chunks for `ct_len` ciphertext bytes.
pub fn chunk_count(ct_len: usize) -> u16 {
    ct_len.div_ceil(CHUNK_LEN) as u16
}

/// Reassembles one item's ciphertext from its chunks.
pub struct Incoming {
    len: usize,
    parts: Vec<Option<Vec<u8>>>,
    missing: usize,
}

impl Incoming {
    /// From the offer: total ciphertext length and chunk count must agree.
    pub fn new(len: u32, total: u16) -> Result<Self, MediaError> {
        let len = len as usize;
        if len == 0 || len > MAX_MEDIA_BYTES + TAG_LEN || total > MAX_CHUNKS {
            return Err(MediaError::TooLarge);
        }
        if chunk_count(len) != total {
            return Err(MediaError::BadChunk);
        }
        Ok(Self {
            len,
            parts: vec![None; total as usize],
            missing: total as usize,
        })
    }

    /// Add a chunk. Returns `true` once every chunk is present.
    pub fn add(&mut self, index: u16, data: Vec<u8>) -> Result<bool, MediaError> {
        let i = index as usize;
        let last = self.parts.len() - 1;
        let want = if i == last {
            self.len - last * CHUNK_LEN
        } else {
            CHUNK_LEN
        };
        let slot = self.parts.get_mut(i).ok_or(MediaError::BadChunk)?;
        if data.len() != want {
            return Err(MediaError::BadChunk);
        }
        if slot.is_none() {
            *slot = Some(data);
            self.missing -= 1;
        }
        Ok(self.missing == 0)
    }

    pub fn into_ciphertext(self) -> Option<Vec<u8>> {
        (self.missing == 0).then(|| self.parts.into_iter().flatten().flatten().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, Rgb, RgbImage};

    fn jpeg(w: u32, h: u32) -> Vec<u8> {
        let img = RgbImage::from_fn(w, h, |x, y| Rgb([(x % 256) as u8, (y % 256) as u8, 128]));
        let mut out = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Jpeg)
            .unwrap();
        out
    }

    /// Insert an APP1/EXIF segment (with a tell-tale string) right after SOI.
    fn with_exif(mut j: Vec<u8>, secret: &[u8]) -> Vec<u8> {
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(secret);
        let len = (payload.len() + 2) as u16;
        let mut seg = vec![0xFF, 0xE1];
        seg.extend_from_slice(&len.to_be_bytes());
        seg.extend_from_slice(&payload);
        j.splice(2..2, seg);
        j.extend_from_slice(b"TRAILING-SECRET");
        j
    }

    fn contains(h: &[u8], n: &[u8]) -> bool {
        h.windows(n.len()).any(|w| w == n)
    }

    #[test]
    fn re_encoding_drops_all_metadata() {
        let dirty = with_exif(jpeg(64, 48), b"GPS 25.0330N 121.5654E SECRET");
        assert!(contains(&dirty, b"SECRET"));
        let clean = sanitize_image(&dirty).unwrap();
        assert!(!contains(&clean, b"SECRET"));
        assert!(!contains(&clean, b"Exif"));
        let back = image::load_from_memory(&clean).unwrap();
        assert_eq!((back.width(), back.height()), (64, 48));
    }

    #[test]
    fn png_with_text_chunk_is_cleaned_and_large_images_shrink() {
        let img = RgbImage::from_fn(4000, 3000, |x, y| {
            Rgb([(x * y % 251) as u8, 0, (x % 7) as u8])
        });
        let mut png = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        png.extend_from_slice(b"tEXtComment\0SECRET");
        let clean = sanitize_image(&png).unwrap();
        assert!(clean.len() <= MAX_MEDIA_BYTES);
        assert!(!contains(&clean, b"SECRET"));
        let back = image::load_from_memory(&clean).unwrap();
        assert!(back.width().max(back.height()) <= MAX_DIM);
        assert_eq!(back.width() * 3, back.height() * 4, "aspect kept");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(sanitize_image(b"not an image"), Err(MediaError::BadImage));
    }

    #[test]
    fn seal_chunk_reassemble_open() {
        let plain = vec![42u8; 50_000];
        let (key, ct) = seal(&plain, b"id1").unwrap();
        let total = chunk_count(ct.len());
        let mut inc = Incoming::new(ct.len() as u32, total).unwrap();
        let parts: Vec<_> = chunks(&ct).map(|c| c.to_vec()).collect();
        // Out of order and with a duplicate.
        for i in (0..parts.len()).rev() {
            inc.add(i as u16, parts[i].clone()).unwrap();
        }
        assert!(inc.add(0, parts[0].clone()).unwrap());
        let ct2 = inc.into_ciphertext().unwrap();
        assert_eq!(&*open(&key, &ct2, b"id1").unwrap(), &plain);
        assert_eq!(open(&key, &ct2, b"id2").unwrap_err(), MediaError::Decrypt);
        let (other, _) = seal(b"x", b"").unwrap();
        assert_eq!(open(&other, &ct2, b"id1").unwrap_err(), MediaError::Decrypt);
    }

    #[test]
    fn incoming_is_strict() {
        assert_eq!(Incoming::new(0, 0).err(), Some(MediaError::TooLarge));
        assert_eq!(Incoming::new(10_000, 2).err(), Some(MediaError::BadChunk));
        assert!(Incoming::new(u32::MAX, MAX_CHUNKS).is_err());
        let mut inc = Incoming::new(5000, 2).unwrap();
        assert_eq!(inc.add(2, vec![0; 10]), Err(MediaError::BadChunk));
        assert_eq!(inc.add(1, vec![0; 10]), Err(MediaError::BadChunk));
        assert_eq!(inc.add(0, vec![0; CHUNK_LEN]), Ok(false));
        assert!(inc.add(1, vec![0; 5000 - CHUNK_LEN]).unwrap());
        assert_eq!(
            seal(&vec![0; MAX_MEDIA_BYTES + 1], b"").err(),
            Some(MediaError::TooLarge)
        );
    }
}
