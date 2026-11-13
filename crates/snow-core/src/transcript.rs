//! The chat transcript, held in Rust so plaintext lives in zeroizing memory.
//!
//! The UI is expected to keep as little as possible: it renders from
//! [`crate::SnowClient::transcript`], may drop its own copy at any time (app in
//! background, low memory, decoy screen) and re-fetch it later. Burn-after-reading
//! timers run here; when one expires the message is removed and zeroized, and the
//! UI is told via `ChatListener::on_burn`.
//!
//! Each side runs its own timer: the sender's starts when the message is queued,
//! the receiver's when it arrives. Swift/Kotlin strings handed to the UI can't be
//! zeroized; that is a documented best-effort limit.
use crate::api::ChatMessage;
use crate::screening::Safety;
use std::time::Duration;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// Oldest messages are dropped (and zeroized) beyond this.
pub const MAX_MESSAGES: usize = 1000;

struct Entry {
    id: u64,
    from_me: bool,
    body: Zeroizing<String>,
    ttl_secs: u32,
    burn_at: Option<Instant>,
    safety: Safety,
}

#[derive(Default)]
pub struct Transcript {
    items: Vec<Entry>,
}

impl Transcript {
    pub fn push(
        &mut self,
        id: u64,
        from_me: bool,
        body: Zeroizing<String>,
        ttl_secs: u32,
        safety: Safety,
    ) {
        let burn_at = (ttl_secs > 0).then(|| Instant::now() + Duration::from_secs(ttl_secs as u64));
        if self.items.len() == MAX_MESSAGES {
            self.items.remove(0);
        }
        self.items.push(Entry {
            id,
            from_me,
            body,
            ttl_secs,
            burn_at,
            safety,
        });
    }

    pub fn next_burn(&self) -> Option<Instant> {
        self.items.iter().filter_map(|e| e.burn_at).min()
    }

    /// Remove every expired message; returns `(id, from_me)` of each.
    pub fn burn_due(&mut self, now: Instant) -> Vec<(u64, bool)> {
        let mut burned = Vec::new();
        self.items.retain(|e| {
            let keep = e.burn_at.is_none_or(|t| t > now);
            if !keep {
                burned.push((e.id, e.from_me));
            }
            keep
        });
        burned
    }

    /// Current messages, oldest first. Already-expired ones are left out even if
    /// the timer hasn't fired yet (e.g. while reconnecting).
    pub fn snapshot(&self) -> Vec<ChatMessage> {
        let now = Instant::now();
        self.items
            .iter()
            .filter(|e| e.burn_at.is_none_or(|t| t > now))
            .map(|e| ChatMessage {
                id: e.id,
                from_me: e.from_me,
                body: e.body.to_string(),
                ttl_secs: e.ttl_secs,
                safety: e.safety.level,
                safety_flags: e.safety.flags.clone(),
            })
            .collect()
    }

    /// `(id, from_me, body)` of messages without a burn timer (for a VIP saved
    /// session; burning messages are never written anywhere).
    pub fn lasting(&self) -> Vec<(u64, bool, String)> {
        self.items
            .iter()
            .filter(|e| e.burn_at.is_none())
            .map(|e| (e.id, e.from_me, e.body.to_string()))
            .collect()
    }

    /// Drop (and zeroize) everything.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.into())
    }

    #[tokio::test(start_paused = true)]
    async fn burns_only_expired_messages() {
        let mut t = Transcript::default();
        t.push(1, true, z("keep"), 0, Safety::clean());
        t.push(2, false, z("short"), 5, Safety::clean());
        t.push(3, true, z("long"), 60, Safety::clean());
        assert_eq!(
            t.next_burn().unwrap() - Instant::now(),
            Duration::from_secs(5)
        );
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(
            t.snapshot().len(),
            2,
            "expired hidden before the timer runs"
        );
        assert_eq!(t.burn_due(Instant::now()), vec![(2, false)]);
        assert_eq!(t.len(), 2);
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(t.burn_due(Instant::now()), vec![(3, true)]);
        assert_eq!(t.snapshot()[0].body, "keep");
        assert!(t.next_burn().is_none());
    }

    #[test]
    fn caps_size_and_ids_are_per_side() {
        let mut t = Transcript::default();
        for i in 0..MAX_MESSAGES as u64 + 5 {
            t.push(i, i % 2 == 0, z("x"), 0, Safety::clean());
        }
        assert_eq!(t.len(), MAX_MESSAGES);
        assert_eq!(t.snapshot()[0].id, 5);
        t.clear();
        assert!(t.is_empty());
    }
}
