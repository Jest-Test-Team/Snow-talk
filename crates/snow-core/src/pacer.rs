//! Traffic shaping: constant-rate cover traffic and send-time jitter.
//!
//! With chaff on (paranoid mode), the client sends exactly one frame per tick:
//! a queued item if one is ready, otherwise [`Inner::Chaff`](snow_proto::Inner::Chaff).
//! An observer (or the relay) sees a steady stream of identical 4096-byte frames,
//! so it can't tell when anyone is typing or sending. Media then moves at the
//! chaff rate too: slower, on purpose, because a rate change would give it away.
//!
//! Without chaff, frames go out as soon as they're ready, through a token bucket
//! that stays under the room's free-tier cap.
//!
//! Every text/control message also waits a random 0–300 ms before it is
//! eligible, which blurs keystroke-timing fingerprints. Text and control always
//! go before bulk media chunks, so a photo never holds up a chat line.
use rand::Rng;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use zeroize::Zeroizing;

pub const DEFAULT_CHAFF_MS: u32 = 1500;
/// Fastest allowed cover rate (4/s); the room caps paranoid slots at 6 frames/s.
pub const MIN_CHAFF_MS: u32 = 250;
/// Free-mode token bucket; the room's free cap is burst 48, 4 frames/s.
const FREE_BURST: f64 = 40.0;
const FREE_PER_SEC: f64 = 3.5;
const MAX_JITTER_MS: u64 = 300;

/// Something real to send.
pub enum Item {
    Text {
        id: u64,
        body: Zeroizing<String>,
        ttl_secs: u32,
    },
    /// An encrypted control message (e.g. "screen captured", PSI, a media chunk).
    /// It goes through the pacer too, so it can't be told apart from text or
    /// chaff by timing.
    Control(snow_proto::Inner),
}

struct Pending {
    due: Instant,
    item: Item,
}

pub enum Out {
    Send(Item),
    Chaff,
}

/// Token bucket mirroring (a little below) the room's rate cap.
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn level(&self, now: Instant) -> f64 {
        (self.tokens + (now - self.at).as_secs_f64() * FREE_PER_SEC).min(FREE_BURST)
    }

    fn ready_at(&self, now: Instant) -> Instant {
        let l = self.level(now);
        if l >= 1.0 {
            now
        } else {
            now + Duration::from_secs_f64((1.0 - l) / FREE_PER_SEC)
        }
    }

    fn take(&mut self, now: Instant) {
        self.tokens = self.level(now) - 1.0;
        self.at = now;
    }
}

pub struct Pacer {
    interval: Option<Interval>,
    /// Text and control messages, each with its own jitter.
    queue: VecDeque<Pending>,
    /// Media offers and chunks, in order, after everything in `queue`.
    bulk: VecDeque<Item>,
    bucket: Bucket,
}

impl Pacer {
    /// `chaff_ms`: `None` → default rate, `Some(0)` → chaff off.
    /// Rates faster than [`MIN_CHAFF_MS`] are clamped.
    pub fn new(chaff_ms: Option<u32>) -> Self {
        let ms = chaff_ms.unwrap_or(DEFAULT_CHAFF_MS);
        let interval = (ms > 0).then(|| {
            let ms = ms.max(MIN_CHAFF_MS);
            let mut i = tokio::time::interval(Duration::from_millis(ms as u64));
            i.set_missed_tick_behavior(MissedTickBehavior::Delay);
            i
        });
        Self {
            interval,
            queue: VecDeque::new(),
            bulk: VecDeque::new(),
            bucket: Bucket {
                tokens: FREE_BURST,
                at: Instant::now(),
            },
        }
    }

    pub fn push(&mut self, item: Item) {
        let jitter = rand::thread_rng().gen_range(0..=MAX_JITTER_MS);
        let due = Instant::now() + Duration::from_millis(jitter);
        self.queue.push_back(Pending { due, item });
    }

    /// Queue bulk data (media). Kept in order, sent when nothing else is ready.
    pub fn push_bulk(&mut self, items: impl IntoIterator<Item = Item>) {
        self.bulk.extend(items);
    }

    fn pop(&mut self, now: Instant) -> Option<Item> {
        if self.queue.front().is_some_and(|p| p.due <= now) {
            return self.queue.pop_front().map(|p| p.item);
        }
        self.bulk.pop_front()
    }

    /// When something will be ready to send, ignoring rate limits.
    fn ready(&self, now: Instant) -> Option<Instant> {
        if !self.bulk.is_empty() {
            return Some(now);
        }
        self.queue.front().map(|p| p.due.max(now))
    }

    /// Resolves when the next frame should go out. `cover` = whether chaff is
    /// wanted right now (chatting, peer online, app in the foreground).
    /// Cancel-safe: nothing is dequeued before the final await completes.
    pub async fn next(&mut self, cover: bool) -> Out {
        match self.interval.is_some() {
            true => loop {
                self.interval.as_mut().expect("checked").tick().await;
                if let Some(item) = self.pop(Instant::now()) {
                    return Out::Send(item);
                }
                if cover {
                    return Out::Chaff;
                }
            },
            false => loop {
                let now = Instant::now();
                match self.ready(now) {
                    Some(at) => tokio::time::sleep_until(at.max(self.bucket.ready_at(now))).await,
                    None => std::future::pending::<()>().await,
                }
                let now = Instant::now();
                if let Some(item) = self.pop(now) {
                    self.bucket.take(now);
                    return Out::Send(item);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(id: u64) -> Item {
        Item::Text {
            id,
            body: Zeroizing::new("x".into()),
            ttl_secs: 0,
        }
    }

    fn id(o: Out) -> u64 {
        match o {
            Out::Send(Item::Text { id, .. }) => id,
            Out::Send(Item::Control(_)) => u64::MAX,
            Out::Chaff => 0,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn constant_rate_with_chaff_fills_gaps() {
        let mut p = Pacer::new(Some(250));
        p.push(text(1));
        let mut kinds = Vec::new();
        let start = Instant::now();
        for _ in 0..5 {
            kinds.push(id(p.next(true).await));
        }
        // The first tick fires immediately, before the jitter has elapsed.
        assert_eq!(kinds.iter().filter(|k| **k == 1).count(), 1);
        assert_eq!(kinds.len(), 5);
        assert!(start.elapsed() >= Duration::from_millis(1000));
    }

    #[tokio::test(start_paused = true)]
    async fn too_fast_chaff_is_clamped() {
        let mut p = Pacer::new(Some(10));
        let start = Instant::now();
        for _ in 0..5 {
            assert!(matches!(p.next(true).await, Out::Chaff));
        }
        assert!(start.elapsed() >= Duration::from_millis(4 * MIN_CHAFF_MS as u64));
    }

    #[tokio::test(start_paused = true)]
    async fn chaff_off_bursts_then_rate_limits() {
        let mut p = Pacer::new(Some(0));
        p.push_bulk((1..=60).map(text));
        let start = Instant::now();
        for i in 1..=40 {
            assert_eq!(id(p.next(false).await), i);
        }
        assert!(
            start.elapsed() < Duration::from_millis(10),
            "burst is immediate"
        );
        for i in 41..=60 {
            assert_eq!(id(p.next(false).await), i);
        }
        let rate = 20.0 / (start.elapsed().as_secs_f64());
        assert!(rate <= FREE_PER_SEC + 0.1, "rate {rate}");
    }

    #[tokio::test(start_paused = true)]
    async fn text_jumps_ahead_of_bulk() {
        let mut p = Pacer::new(Some(250));
        p.push_bulk((100..110).map(text));
        assert_eq!(id(p.next(true).await), 100);
        p.push(text(7));
        tokio::time::advance(Duration::from_millis(MAX_JITTER_MS)).await;
        assert_eq!(id(p.next(true).await), 7);
        assert_eq!(id(p.next(true).await), 101);
    }

    #[tokio::test(start_paused = true)]
    async fn no_cover_means_only_real_messages() {
        let mut p = Pacer::new(Some(100));
        p.push(text(7));
        assert_eq!(id(p.next(false).await), 7);
        let r = tokio::time::timeout(Duration::from_secs(5), p.next(false)).await;
        assert!(r.is_err(), "no chaff while cover is off");
    }

    #[tokio::test(start_paused = true)]
    async fn chaff_off_sends_after_jitter_only() {
        let mut p = Pacer::new(Some(0));
        let t0 = Instant::now();
        p.push(Item::Control(snow_proto::Inner::ScreenCaptured));
        assert_eq!(id(p.next(true).await), u64::MAX);
        assert!(t0.elapsed() <= Duration::from_millis(MAX_JITTER_MS));
    }
}
