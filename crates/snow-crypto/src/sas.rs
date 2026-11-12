use hkdf::Hkdf;
use sha2::Sha256;

/// 64 emoji (6 bits each). Both apps must ship the same table.
pub const SAS_EMOJI: [&str; 64] = [
    "🐶", "🐱", "🦁", "🐎", "🦄", "🐷", "🐘", "🐰", "🐼", "🐓", "🐧", "🐢", "🐟", "🐙", "🦋", "🌷",
    "🌳", "🌵", "🍄", "🌏", "🌙", "☁️", "🔥", "🍌", "🍎", "🍓", "🌽", "🍕", "🎂", "❤️", "😀", "🤖",
    "🎩", "👓", "🔧", "🎅", "👍", "☂️", "⌛", "⏰", "🎁", "💡", "📕", "✏️", "📎", "✂️", "🔒", "🔑",
    "🔨", "☎️", "🏁", "🚂", "🚲", "✈️", "🚀", "🏆", "⚽", "🎸", "🎺", "🔔", "⚓", "🎧", "📁", "📌",
];

/// Seven emoji indices (42 bits) derived from both identity keys and the responder's OTK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sas(pub [u8; 7]);

impl Sas {
    pub(crate) fn derive(initiator_id: &[u8; 32], responder_id: &[u8; 32], otk: &[u8; 32]) -> Self {
        let mut ikm = [0u8; 96];
        ikm[..32].copy_from_slice(initiator_id);
        ikm[32..64].copy_from_slice(responder_id);
        ikm[64..].copy_from_slice(otk);
        let mut okm = [0u8; 6];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(b"snowtalk-sas-v1", &mut okm)
            .expect("6 bytes is a valid HKDF length");
        let bits = okm.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
        let mut idx = [0u8; 7];
        for (i, slot) in idx.iter_mut().enumerate() {
            *slot = ((bits >> (42 - 6 * (i + 1))) & 0x3f) as u8;
        }
        Sas(idx)
    }

    pub fn emoji(&self) -> [&'static str; 7] {
        self.0.map(|i| SAS_EMOJI[i as usize])
    }
}
