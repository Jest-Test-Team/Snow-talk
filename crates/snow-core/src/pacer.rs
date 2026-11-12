//! Traffic shaping: constant-rate cover traffic and send-time jitter.
//!
//! With chaff on, the client sends exactly one frame per tick: a queued message
//! if one is due, otherwise [`Inner::Chaff`](snow_proto::Inner::Chaff). An observer
//! (or the relay) sees a steady stream of identical 4096-byte frames, so it can't
//! tell when anyone is typing or sending. Every message also waits a random
//! 0–300 ms before it is eligible, which blurs keystroke-timing fingerprints even
//! when chaff is off.
use rand::Rng;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use zeroize::Zeroizing;

pub const DEFAULT_CHAFF_MS: u32 = 1500;
const MAX_JITTER_MS: u64 = 300;

pub struct Pending {
    due: Instant,
    pub id: u64,
    pub body: Zeroizing<String>,
    pub ttl_secs: u32,
}

pub enum Out {
    Text(Pending),
    Chaff,
}

pub struct Pacer {
    interval: Option<Interval>,
    queue: VecDeque<Pending>,
}

impl Pacer {
    /// `chaff_ms`: `None` → default rate, `Some(0)` → chaff off.
    pub fn new(chaff_ms: Option<u32>) -> Self {
        let ms = chaff_ms.unwrap_or(DEFAULT_CHAFF_MS);
        let interval = (ms > 0).then(|| {
            let mut i = tokio::time::interval(Duration::from_millis(ms as u64));
            i.set_missed_tick_behavior(MissedTickBehavior::Delay);
            i
        });
        Self {
            interval,
            queue: VecDeque::new(),
        }
    }

    pub fn push(&mut self, id: u64, body: Zeroizing<String>, ttl_secs: u32) {
        let jitter = rand::thread_rng().gen_range(0..=MAX_JITTER_MS);
        let due = Instant::now() + Duration::from_millis(jitter);
        self.queue.push_back(Pending {
            due,
            id,
            body,
            ttl_secs,
        });
    }

    fn pop_due(&mut self) -> Option<Pending> {
        if self.queue.front().is_some_and(|p| p.due <= Instant::now()) {
            self.queue.pop_front()
        } else {
            None
        }
    }

    /// Resolves when the next frame should go out. `cover` = whether chaff is
    /// wanted right now (chatting, peer online, app in the foreground).
    /// Cancel-safe: nothing is dequeued before the final await completes.
    pub async fn next(&mut self, cover: bool) -> Out {
        match self.interval.is_some() {
            true => loop {
                self.interval.as_mut().expect("checked").tick().await;
                if let Some(p) = self.pop_due() {
                    return Out::Text(p);
                }
                if cover {
                    return Out::Chaff;
                }
            },
            false => loop {
                match self.queue.front() {
                    Some(p) => tokio::time::sleep_until(p.due).await,
                    None => std::future::pending::<()>().await,
                }
                if let Some(p) = self.pop_due() {
                    return Out::Text(p);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn constant_rate_with_chaff_fills_gaps() {
        let mut p = Pacer::new(Some(100));
        p.push(1, Zeroizing::new("hi".into()), 0);
        let mut kinds = Vec::new();
        let start = Instant::now();
        for _ in 0..5 {
            kinds.push(match p.next(true).await {
                Out::Text(t) => t.id,
                Out::Chaff => 0,
            });
        }
        // The first tick fires immediately, before the jitter has elapsed.
        assert_eq!(kinds.iter().filter(|k| **k == 1).count(), 1);
        assert_eq!(kinds.len(), 5);
        assert!(start.elapsed() >= Duration::from_millis(400));
    }

    #[tokio::test(start_paused = true)]
    async fn no_cover_means_only_real_messages() {
        let mut p = Pacer::new(Some(100));
        p.push(7, Zeroizing::new("x".into()), 0);
        assert!(matches!(p.next(false).await, Out::Text(t) if t.id == 7));
        let r = tokio::time::timeout(Duration::from_secs(5), p.next(false)).await;
        assert!(r.is_err(), "no chaff while cover is off");
    }

    #[tokio::test(start_paused = true)]
    async fn chaff_off_sends_after_jitter_only() {
        let mut p = Pacer::new(Some(0));
        let t0 = Instant::now();
        p.push(3, Zeroizing::new("x".into()), 0);
        assert!(matches!(p.next(true).await, Out::Text(t) if t.id == 3));
        assert!(t0.elapsed() <= Duration::from_millis(MAX_JITTER_MS));
    }
}
