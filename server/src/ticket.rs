//! HMAC-signed room tickets. Pure logic, no Workers APIs, so it's unit-testable natively.
//!
//! `hex( room_id[32] | slot u8 | kind u8 | flags u8 | gen u32 | exp u64 | mac[16] )`
use hmac::{Hmac, Mac};
use sha2::Sha256;

const BODY_LEN: usize = 32 + 1 + 1 + 1 + 4 + 8;

/// `flags` bit: paranoid mode (VIP constant-rate cover traffic) was granted.
pub const FLAG_PARANOID: u8 = 1;
const MAC_LEN: usize = 16;
const DOMAIN: &[u8] = b"snowtalk-ticket-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// First entry into the room, issued by the matchmaker.
    Join = 1,
    /// Re-entry into the same slot (reconnect or ID rotation), issued by the room.
    Resume = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    pub room: [u8; 32],
    pub slot: u8,
    pub kind: Kind,
    /// Perks granted at match time (`FLAG_*`). Signed, so a client can't add them.
    pub flags: u8,
    /// Generation. The room only accepts the latest one, so each ticket works once.
    pub gen: u32,
    /// Expiry, ms since the epoch.
    pub exp: u64,
}

fn mac(key: &[u8], body: &[u8]) -> [u8; MAC_LEN] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    m.update(DOMAIN);
    m.update(body);
    let full = m.finalize().into_bytes();
    full[..MAC_LEN].try_into().unwrap()
}

impl Ticket {
    pub fn room_hex(&self) -> String {
        hex::encode(self.room)
    }

    pub fn sign(&self, key: &[u8]) -> String {
        let mut b = Vec::with_capacity(BODY_LEN + MAC_LEN);
        b.extend_from_slice(&self.room);
        b.push(self.slot);
        b.push(self.kind as u8);
        b.push(self.flags);
        b.extend_from_slice(&self.gen.to_be_bytes());
        b.extend_from_slice(&self.exp.to_be_bytes());
        let m = mac(key, &b);
        b.extend_from_slice(&m);
        hex::encode(b)
    }

    pub fn verify(key: &[u8], s: &str, now_ms: u64) -> Option<Self> {
        let b = hex::decode(s).ok()?;
        if b.len() != BODY_LEN + MAC_LEN {
            return None;
        }
        let (body, tag) = b.split_at(BODY_LEN);
        let expected = mac(key, body);
        // Constant-time compare.
        if expected
            .iter()
            .zip(tag)
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            != 0
        {
            return None;
        }
        let kind = match body[33] {
            1 => Kind::Join,
            2 => Kind::Resume,
            _ => return None,
        };
        let t = Ticket {
            room: body[..32].try_into().ok()?,
            slot: body[32],
            kind,
            flags: body[34],
            gen: u32::from_be_bytes(body[35..39].try_into().ok()?),
            exp: u64::from_be_bytes(body[39..47].try_into().ok()?),
        };
        (t.slot <= 1 && now_ms <= t.exp).then_some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> Ticket {
        Ticket {
            room: [7; 32],
            slot: 1,
            kind: Kind::Join,
            flags: FLAG_PARANOID,
            gen: 0,
            exp: 1000,
        }
    }

    #[test]
    fn roundtrip() {
        let s = t().sign(b"k");
        assert_eq!(Ticket::verify(b"k", &s, 999), Some(t()));
    }

    #[test]
    fn rejects_wrong_key_expired_and_tampered() {
        let s = t().sign(b"k");
        assert_eq!(Ticket::verify(b"x", &s, 0), None);
        assert_eq!(Ticket::verify(b"k", &s, 1001), None);
        let mut b = hex::decode(&s).unwrap();
        b[32] = 0; // try to take the other slot
        assert_eq!(Ticket::verify(b"k", &hex::encode(&b), 0), None);
        let mut b = hex::decode(&s).unwrap();
        b[34] = 0; // try to change the granted perks
        assert_eq!(Ticket::verify(b"k", &hex::encode(&b), 0), None);
        assert_eq!(Ticket::verify(b"k", "zz", 0), None);
    }
}
