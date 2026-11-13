//! snow-cli — terminal client and E2E test bot.
//!
//! ```text
//! snow-cli chat      [--server URL] [--bucket N]
//! snow-cli net-check --server URL [--tor DIR]   # DoH + ECH (+ Tor) diagnostics
//! snow-cli pair-test [--server URL] [--bucket N] [--messages N] [--marker TEXT]
//!                    [--scenario basic|reconnect|rotate|chaff|free|flood|burn|tags|disjoint|media|safety|goodchat|report|trusted|grace]
//!                    [--tag TEXT]... [--nick NAME]
//!                    [--paranoid] [--chaff MS] [--config-key HEX]
//! ```
//! `pair-test` runs two clients in one process, pairs them, exchanges messages in
//! both directions, checks that the SAS matches, and exits non-zero on failure.
//! Scenarios:
//! * `basic`     — chat, then A leaves and B must see `PeerLeft`
//! * `reconnect` — A's socket is killed; both must recover and keep chatting
//! * `rotate`    — session IDs rotate every 2 s while chatting; nothing may be lost
//! * `chaff`     — paranoid mode (needs `PARANOID_GRANT=open` on the relay): idle
//!   clients must emit cover frames at the configured rate, and stop in the background
//! * `free`      — no paranoid mode: no cover frames at all, bursts still delivered
//! * `flood`     — a client bypassing its pacer must be rate-limited by the room
//! * `burn`      — a 2 s burn-after-reading message vanishes on both sides, and
//!   a screenshot notice reaches the peer
//! * `tags`      — PSI finds exactly the shared tags on both sides; profiles arrive
//! * `disjoint`  — same bucket, no shared tags: both leave with `NoCommonTags`
//! * `media`     — a flash photo with GPS EXIF arrives clean, opens once, burns
//! * `safety`    — a scam pitch arrives blurred with reasons; small talk stays clean
//! * `goodchat`  — after a real chat both sides earn one unlinkable token
//! * `report`    — A leaves, B reports A in the window: only B earns a token
//!   (run the relay with short `GOOD_AFTER_SECS` / `REPORT_SECS`)
//! * `trusted`   — earn 3 tokens each, then meet in the trusted queue; a replayed
//!   (double-spent) wallet is refused and lands in the normal queue
//! * `grace`     — A vanishes; B must see `Disconnected` then `PeerGone`
//!   (run the relay with a short `GRACE_SECS`)
//! * `config`    — with `--config-key`: the signed config and sponsor catalog are
//!   fetched and verified, a sponsor matching the shared tag is picked locally,
//!   and tokens under the pinned issuer key are accepted
//! * `extend`    — A extends the room (VIP; relay with `EXTEND_GRANT=open`),
//!   saves the session and quits; the room outlives the normal grace period; a
//!   brand-new client resumes from the sealed blob and the chat continues
//! * `config-tagging` — the config pins issuer keys the relay doesn't use (as a
//!   relay tagging users with its own keys would): tokens must be refused
use snow_core::*;
use std::io::BufRead;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
enum Ev {
    State(ChatState),
    Sas(Vec<String>),
    Msg(ChatMessage),
    Peer(PeerEvent),
    Burn(u64, bool),
    Common(Vec<String>),
    Profile(UserProfile),
    Media(MediaInfo),
    MediaBurned(u64, bool),
    Wallet,
}

/// Sponsor ids each client was shown while queued (the event arrives before
/// pairing, where `wait` would discard it).
static SPONSORS: std::sync::Mutex<Vec<Vec<String>>> = std::sync::Mutex::new(Vec::new());

struct Chan(Sender<Ev>);
impl ChatListener for Chan {
    fn on_sponsors(&self, cards: Vec<SponsorCard>) {
        if !cards.is_empty() {
            SPONSORS
                .lock()
                .unwrap()
                .push(cards.into_iter().map(|c| c.id).collect());
        }
    }
    fn on_state(&self, s: ChatState) {
        let _ = self.0.send(Ev::State(s));
    }
    fn on_sas(&self, e: Vec<String>) {
        let _ = self.0.send(Ev::Sas(e));
    }
    fn on_message(&self, m: ChatMessage) {
        let _ = self.0.send(Ev::Msg(m));
    }
    fn on_peer(&self, e: PeerEvent) {
        let _ = self.0.send(Ev::Peer(e));
    }
    fn on_burn(&self, id: u64, from_me: bool) {
        let _ = self.0.send(Ev::Burn(id, from_me));
    }
    fn on_common_tags(&self, tags: Vec<String>) {
        let _ = self.0.send(Ev::Common(tags));
    }
    fn on_profile(&self, p: UserProfile) {
        let _ = self.0.send(Ev::Profile(p));
    }
    fn on_media(&self, m: MediaInfo) {
        let _ = self.0.send(Ev::Media(m));
    }
    fn on_media_burned(&self, id: u64, from_me: bool) {
        let _ = self.0.send(Ev::MediaBurned(id, from_me));
    }
    fn on_wallet_changed(&self) {
        let _ = self.0.send(Ev::Wallet);
    }
}

#[derive(Clone)]
struct Args {
    cmd: String,
    server: String,
    bucket: Option<u8>,
    messages: usize,
    marker: String,
    scenario: String,
    rotation_secs: Option<u32>,
    chaff_ms: Option<u32>,
    paranoid: bool,
    trusted: bool,
    tags: Vec<String>,
    nick: Option<String>,
    pins: Vec<String>,
    tor_dir: Option<String>,
    config_key: Option<String>,
}

fn args() -> Args {
    let mut a = Args {
        cmd: String::new(),
        server: "http://127.0.0.1:8787".into(),
        bucket: None,
        messages: 5,
        marker: "SNOW-PLAINTEXT-MARKER".into(),
        scenario: "basic".into(),
        rotation_secs: None,
        chaff_ms: None,
        paranoid: false,
        trusted: false,
        tags: Vec::new(),
        nick: None,
        pins: Vec::new(),
        tor_dir: None,
        config_key: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--server" => a.server = it.next().expect("--server URL"),
            "--bucket" => {
                a.bucket = Some(
                    it.next()
                        .and_then(|v| v.parse().ok())
                        .expect("--bucket 0..63"),
                )
            }
            "--messages" => {
                a.messages = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .expect("--messages N")
            }
            "--marker" => a.marker = it.next().expect("--marker TEXT"),
            "--scenario" => a.scenario = it.next().expect("--scenario NAME"),
            "--tor" => a.tor_dir = Some(it.next().expect("--tor DIR")),
            "--pin" => a.pins.push(it.next().expect("--pin BASE64")),
            "--paranoid" => a.paranoid = true,
            "--config-key" => a.config_key = Some(it.next().expect("--config-key HEX")),
            "--tag" => a.tags.push(it.next().expect("--tag TEXT")),
            "--nick" => a.nick = Some(it.next().expect("--nick NAME")),
            "--chaff" => {
                a.chaff_ms = Some(it.next().and_then(|v| v.parse().ok()).expect("--chaff MS"))
            }
            "-h" | "--help" => {
                println!("usage: snow-cli (chat|pair-test) [--server URL] [--bucket N] [--messages N] [--marker TEXT]");
                std::process::exit(0);
            }
            c if a.cmd.is_empty() => a.cmd = c.to_string(),
            other => panic!("unknown argument {other}"),
        }
    }
    a
}

fn client(a: &Args) -> (Arc<SnowClient>, Receiver<Ev>) {
    let (tx, rx) = channel();
    let c = SnowClient::new(
        Config {
            server_url: a.server.clone(),
            bucket: a.bucket,
            rotation_secs: a.rotation_secs,
            chaff_ms: a.chaff_ms,
            paranoid: a.paranoid,
            trusted: a.trusted,
            tags: a.tags.clone(),
            adult_tags: Vec::new(),
            require_common_tag: true,
            profile: a.nick.clone().map(|n| UserProfile {
                nickname: Some(n),
                mbti: Some("INTJ".into()),
                ..Default::default()
            }),
            pins: a.pins.clone(),
            tor_dir: a.tor_dir.clone(),
            config_key: a.config_key.clone(),
        },
        Arc::new(Chan(tx)),
    );
    (c, rx)
}

fn main() {
    let a = args();
    match a.cmd.as_str() {
        "chat" => chat(&a),
        "net-check" => match debug_net_check(&a.server, a.tor_dir.as_deref()) {
            Ok((ech, body)) => println!("ech config used: {ech}\n{body}"),
            Err(e) => {
                eprintln!("FAIL: {e}");
                std::process::exit(1)
            }
        },
        "pair-test" => std::process::exit(match pair_test(&a) {
            Ok(()) => {
                println!("PASS");
                0
            }
            Err(e) => {
                eprintln!("FAIL: {e}");
                1
            }
        }),
        _ => println!("snow-cli {} — try --help", version()),
    }
}

fn chat(a: &Args) {
    let (c, rx) = client(a);
    c.start_match();
    std::thread::spawn(move || {
        for ev in rx {
            match ev {
                Ev::State(ChatState::Ended { reason }) => {
                    println!("* ended: {reason:?}");
                    std::process::exit(0);
                }
                Ev::State(s) => println!("* {s:?}"),
                Ev::Sas(e) => println!("* verify with your peer: {}", e.join(" ")),
                Ev::Msg(m) if m.safety == SafetyLevel::Clean => println!("< {}", m.body),
                Ev::Msg(m) => println!("< [{:?} {:?}] {}", m.safety, m.safety_flags, m.body),
                Ev::Peer(p) => println!("* peer: {p:?}"),
                Ev::Burn(id, mine) => println!("* burned #{id} (mine: {mine})"),
                Ev::Common(t) if t.is_empty() => println!("* no interests in common"),
                Ev::Common(t) => println!("* you both like: {}", t.join(", ")),
                Ev::Profile(p) => println!("* peer profile: {p:?}"),
                Ev::Media(m) => {
                    println!("* peer sent {:?} #{} (view {}s)", m.kind, m.id, m.view_secs)
                }
                Ev::MediaBurned(id, mine) => println!("* media #{id} burned (mine: {mine})"),
                Ev::Wallet => println!("* earned a good-chat token"),
            }
        }
    });
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap_or_default();
        if line == "/leave" {
            c.leave();
        } else if line == "/report" {
            c.report();
        } else if let Err(e) = c.send_text(line, 0) {
            println!("! {e}");
        }
    }
    c.leave();
    std::thread::sleep(Duration::from_millis(500));
}

/// Wait for an event matching `want`, skipping others; fail on Ended unless wanted.
fn wait<T>(
    rx: &Receiver<Ev>,
    what: &str,
    mut want: impl FnMut(&Ev) -> Option<T>,
) -> Result<T, String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(ev) => {
                if let Some(t) = want(&ev) {
                    return Ok(t);
                }
                if let Ev::State(ChatState::Ended { reason }) = ev {
                    return Err(format!("ended ({reason:?}) while waiting for {what}"));
                }
            }
            Err(RecvTimeoutError::Timeout) => return Err(format!("timed out waiting for {what}")),
            Err(RecvTimeoutError::Disconnected) => return Err("listener gone".into()),
        }
    }
}

fn pair_test(a: &Args) -> Result<(), String> {
    let mut a2 = a.clone();
    if a.scenario == "rotate" {
        a2.rotation_secs = Some(2);
    }
    if a.scenario == "chaff" {
        // Fast cover traffic (the fastest the pacer allows) so the test is quick.
        a2.paranoid = true;
        a2.chaff_ms = a.chaff_ms.or(Some(250));
    }
    let mut b2 = a2.clone();
    match a.scenario.as_str() {
        "tags" => {
            // Same primary tag (→ same bucket) after normalization; one more shared.
            a2.tags = ["cats", "jazz", "hiking"].map(String::from).to_vec();
            b2.tags = ["Cats", "chess", "#Hiking"].map(String::from).to_vec();
            a2.nick = Some("雪人".into());
            b2.nick = Some("Bob".into());
        }
        "config" | "config-tagging" => {
            a2.tags = vec!["Coffee".into()];
            b2.tags = vec!["coffee".into()];
        }
        "disjoint" => {
            // Forced into one bucket, but nothing in common.
            a2.bucket = Some(9);
            b2.bucket = Some(9);
            a2.tags = vec!["cats".into()];
            b2.tags = vec!["dogs".into()];
        }
        _ => {}
    }
    let (ca, ra) = client(&a2);
    let (cb, rb) = client(&b2);
    let t0 = Instant::now();
    ca.start_match();
    cb.start_match();
    let sas = |ev: &Ev| {
        if let Ev::Sas(e) = ev {
            Some(e.clone())
        } else {
            None
        }
    };
    let granted = wait(&ra, "A handshaking", |ev| match ev {
        Ev::State(ChatState::Handshaking { paranoid, .. }) => Some(*paranoid),
        _ => None,
    })?;
    if granted != a2.paranoid {
        return Err(format!(
            "paranoid requested={} but granted={granted}",
            a2.paranoid
        ));
    }
    let sa = wait(&ra, "SAS on A", sas)?;
    wait(&ra, "A chatting", chatting)?;
    let sb = wait(&rb, "SAS on B", sas)?;
    wait(&rb, "B chatting", chatting)?;
    if sa != sb {
        return Err(format!("SAS mismatch: {sa:?} vs {sb:?}"));
    }
    println!("paired in {:?}, SAS {}", t0.elapsed(), sa.join(""));
    let pair = Pair {
        ca: &ca,
        cb: &cb,
        ra: &ra,
        rb: &rb,
        marker: &a.marker,
    };
    // `wait` discards unrelated events, so PSI/profile scenarios skip the warmup.
    if !matches!(a.scenario.as_str(), "tags" | "disjoint") {
        pair.exchange(a.messages, "warmup")?;
    }

    match a.scenario.as_str() {
        "basic" => {
            ca.leave();
            wait(&ra, "A ended", |ev| ended(ev, EndReason::SelfLeft))?;
            wait(&rb, "B sees peer left", |ev| ended(ev, EndReason::PeerLeft))?;
            println!("leave propagated");
        }
        "reconnect" => {
            ca.debug_drop_connection();
            wait(&ra, "A reconnecting", |ev| {
                matches!(ev, Ev::State(ChatState::Reconnecting { .. })).then_some(())
            })?;
            wait(&ra, "A back", chatting)?;
            // B may see Disconnected→Reconnected, or nothing if A was back before the room noticed.
            pair.exchange(a.messages, "after-reconnect")?;
            println!("recovered from a dropped connection");
        }
        "rotate" => {
            let until = Instant::now() + Duration::from_secs(7);
            let mut n = 0;
            while Instant::now() < until {
                pair.exchange(1, &format!("rot{n}"))?;
                n += 1;
                std::thread::sleep(Duration::from_millis(200));
            }
            for (rx, who) in [(&ra, "A"), (&rb, "B")] {
                if let Ok(ev) = rx.try_recv() {
                    if matches!(ev, Ev::Peer(PeerEvent::Disconnected { .. }) | Ev::State(_)) {
                        return Err(format!("{who} saw {ev:?} during rotation"));
                    }
                }
            }
            println!("{n} round trips across rotations, none lost");
        }
        "chaff" => {
            let ms = a2.chaff_ms.unwrap_or(250) as u64;
            let idle = Duration::from_secs(2);
            let before = ca.debug_frames_sent();
            std::thread::sleep(idle);
            let sent = ca.debug_frames_sent() - before;
            let expected = (idle.as_millis() as u64).checked_div(ms).unwrap_or(0);
            println!("idle {idle:?}: {sent} cover frames (expected ≈{expected})");
            if sent + 2 < expected || sent > expected + 2 {
                return Err(format!("cover rate off: {sent} vs {expected}"));
            }
            ca.set_foreground(false);
            std::thread::sleep(Duration::from_millis(3 * ms));
            let before = ca.debug_frames_sent();
            std::thread::sleep(idle);
            let bg = ca.debug_frames_sent() - before;
            println!("background: {bg} frames");
            if bg != 0 {
                return Err("cover traffic must stop in the background".into());
            }
            ca.set_foreground(true);
            pair.exchange(1, "after-bg")?;
        }
        "free" => {
            let before = ca.debug_frames_sent();
            std::thread::sleep(Duration::from_secs(2));
            let idle = ca.debug_frames_sent() - before;
            println!("idle 2s without paranoid: {idle} frames");
            if idle != 0 {
                return Err("free mode must not send cover traffic".into());
            }
            // A burst of sends is spaced by the pacer and must not trip the cap.
            let n = 12;
            for i in 0..n {
                ca.send_text(format!("{} burst #{i}", a.marker), 0)
                    .map_err(|e| e.to_string())?;
            }
            for i in 0..n {
                let want = format!("{} burst #{i}", a.marker);
                let got = wait(&rb, "burst", |ev| match ev {
                    Ev::Msg(m) => Some(m.body.clone()),
                    _ => None,
                })?;
                if got != want {
                    return Err(format!("burst: expected {want:?}, got {got:?}"));
                }
            }
            if ca.debug_rate_limited() != 0 {
                return Err("pacer exceeded the room's free rate cap".into());
            }
            println!("burst of {n} delivered in order, never rate-limited");
        }
        "flood" => {
            ca.debug_flood(100);
            std::thread::sleep(Duration::from_secs(1));
            let dropped = ca.debug_rate_limited();
            println!("flood of 100: {dropped} dropped by the room");
            if dropped < 50 {
                return Err(format!(
                    "room should cap free slots, dropped only {dropped}"
                ));
            }
            std::thread::sleep(Duration::from_secs(3));
            pair.exchange(1, "after-flood")?;
            println!("chat still works after the flood");
        }
        "burn" => {
            let body = format!("{} burn-me", a.marker);
            let id = ca.send_text(body.clone(), 2).map_err(|e| e.to_string())?;
            let (rid, ttl) = wait(&rb, "burn msg", |ev| match ev {
                Ev::Msg(m) if m.body == body => Some((m.id, m.ttl_secs)),
                _ => None,
            })?;
            if ttl != 2 || !cb.transcript().iter().any(|m| m.id == rid && !m.from_me) {
                return Err("receiver transcript is missing the message".into());
            }
            let t = Instant::now();
            wait(&ra, "A burns", |ev| {
                (matches!(ev, Ev::Burn(i, true) if *i == id)).then_some(())
            })?;
            wait(&rb, "B burns", |ev| {
                (matches!(ev, Ev::Burn(i, false) if *i == rid)).then_some(())
            })?;
            for (c, who) in [(&ca, "A"), (&cb, "B")] {
                if c.transcript().iter().any(|m| m.body == body) {
                    return Err(format!("{who} still holds a burned message"));
                }
            }
            println!("burned on both sides after {:?}", t.elapsed());
            ca.notify_screen_captured();
            wait(&rb, "screenshot notice", |ev| {
                matches!(ev, Ev::Peer(PeerEvent::ScreenCaptured)).then_some(())
            })?;
            println!("screenshot notice delivered");
        }
        "tags" => {
            let want = vec!["cats".to_string(), "hiking".to_string()];
            for (rx, who, peer_nick) in [(&ra, "A", "Bob"), (&rb, "B", "雪人")] {
                // The profile and the PSI result may arrive in either order.
                let (mut common, mut profile) = (None, None);
                while common.is_none() || profile.is_none() {
                    match wait(rx, "common tags + profile", |ev| match ev {
                        Ev::Common(_) | Ev::Profile(_) => Some(ev_clone(ev)),
                        _ => None,
                    })? {
                        Ev::Common(t) => common = Some(t),
                        Ev::Profile(p) => profile = Some(p),
                        _ => unreachable!(),
                    }
                }
                let (common, p) = (common.unwrap(), profile.unwrap());
                if common != want {
                    return Err(format!("{who}: common tags {common:?}, want {want:?}"));
                }
                if p.nickname.as_deref() != Some(peer_nick) || p.adult_ok {
                    return Err(format!("{who}: bad peer profile {p:?}"));
                }
            }
            println!("both sides found {want:?} privately; profiles exchanged");
            pair.exchange(a.messages, "after-psi")?;
        }
        "disjoint" => {
            for (rx, who) in [(&ra, "A"), (&rb, "B")] {
                wait(rx, "no common tags", |ev| match ev {
                    Ev::State(ChatState::Ended {
                        reason: EndReason::NoCommonTags,
                    }) => Some(()),
                    // The peer may leave first: that's fine too.
                    Ev::State(ChatState::Ended {
                        reason: EndReason::PeerLeft,
                    }) => Some(()),
                    _ => None,
                })
                .map_err(|e| format!("{who}: {e}"))?;
            }
            println!("no shared interests → both left to re-queue");
        }
        "media" => {
            let photo = test_photo(b"GPS 25.0330N 121.5654E");
            let t = Instant::now();
            let id = ca.send_image(photo, 2).map_err(|e| e.to_string())?;
            let info = wait(&rb, "media", |ev| match ev {
                Ev::Media(m) => Some(m.clone()),
                _ => None,
            })?;
            println!("photo arrived in {:?}: {info:?}", t.elapsed());
            if info.kind != MediaType::Image || info.view_secs != 2 {
                return Err(format!("bad media info {info:?}"));
            }
            let bytes = cb.open_media(info.id).map_err(|e| e.to_string())?;
            if bytes.windows(3).any(|w| w == b"GPS") || bytes.windows(4).any(|w| w == b"Exif") {
                return Err("metadata survived".into());
            }
            let img = image::load_from_memory(&bytes).map_err(|e| e.to_string())?;
            if (img.width(), img.height()) != (320, 240) {
                return Err(format!("unexpected size {}x{}", img.width(), img.height()));
            }
            if cb.open_media(info.id).is_ok() {
                return Err("media opened twice".into());
            }
            wait(&ra, "sender told it was opened", |ev| {
                matches!(ev, Ev::MediaBurned(i, true) if *i == id).then_some(())
            })?;
            let t = Instant::now();
            wait(&rb, "view time over", |ev| {
                matches!(ev, Ev::MediaBurned(i, false) if *i == info.id).then_some(())
            })?;
            println!("opened once, metadata-free, burned after {:?}", t.elapsed());
            pair.exchange(1, "after-media")?;
        }
        "safety" => {
            for (text, want) in [
                ("老師帶單保證獲利，加賴 abc", SafetyLevel::Blur),
                ("你好，今天好冷", SafetyLevel::Clean),
            ] {
                ca.send_text(text.into(), 0).map_err(|e| e.to_string())?;
                let m = wait(&rb, "screened message", |ev| match ev {
                    Ev::Msg(m) if m.body == text => Some(m.clone()),
                    _ => None,
                })?;
                if m.safety != want {
                    return Err(format!("{text}: {:?} {:?}", m.safety, m.safety_flags));
                }
                let stored = cb.transcript().into_iter().find(|t| t.body == text);
                if stored.map(|s| s.safety) != Some(want) {
                    return Err("transcript lost the safety verdict".into());
                }
                println!("{text:?} → {:?} {:?}", m.safety, m.safety_flags);
            }
        }
        "goodchat" | "report" => {
            // Long enough for the relay's (shortened) GOOD_AFTER_SECS.
            std::thread::sleep(Duration::from_millis(1500));
            pair.exchange(1, "before-leave")?;
            ca.leave();
            wait(&rb, "B sees peer left", |ev| ended(ev, EndReason::PeerLeft))?;
            if a.scenario == "report" {
                cb.report();
            }
            wallet_event(&rb, "B's token")?;
            let a_got = if a.scenario == "report" {
                std::thread::sleep(Duration::from_secs(2));
                ra.try_iter().any(|ev| matches!(ev, Ev::Wallet))
            } else {
                wallet_event(&ra, "A's token")?;
                true
            };
            let (ta, tb) = (ca.good_tokens(), cb.good_tokens());
            println!("tokens: A={ta} B={tb}");
            let want_a = u32::from(a.scenario != "report");
            if ta != want_a || tb != 1 || a_got != (want_a == 1) {
                return Err(format!("expected A={want_a} B=1, got A={ta} B={tb}"));
            }
            // The wallet survives an export/import round trip (app persistence).
            let saved = cb.wallet_export();
            let (fresh, _rx) = client(&a2);
            fresh.wallet_import(saved).map_err(|e| e.to_string())?;
            if fresh.good_tokens() != 1 {
                return Err("wallet import lost tokens".into());
            }
        }
        "config" | "config-tagging" => {
            if a.config_key.is_none() {
                return Err("needs --config-key".into());
            }
            let f = ca.remote_features().ok_or("no valid remote config")?;
            println!("remote config v{} {f:?}", f.version);
            let shown = SPONSORS.lock().unwrap().clone();
            if shown.len() != 2
                || !shown
                    .iter()
                    .all(|ids| ids.first().map(String::as_str) == Some("cafe"))
            {
                return Err(format!(
                    "expected the coffee sponsor first on both sides, got {shown:?}"
                ));
            }
            println!("sponsors picked on-device: {shown:?}");
            std::thread::sleep(Duration::from_millis(1500));
            pair.exchange(1, "before-leave")?;
            ca.leave();
            wait(&rb, "B sees peer left", |ev| ended(ev, EndReason::PeerLeft))?;
            let tagging = a.scenario == "config-tagging";
            if tagging {
                // Give the settle phase time to receive (and refuse) the tokens.
                std::thread::sleep(Duration::from_secs(3));
            } else {
                wallet_event(&ra, "A's token")?;
                wallet_event(&rb, "B's token")?;
            }
            let (ta, tb) = (ca.good_tokens(), cb.good_tokens());
            println!("tokens: A={ta} B={tb}");
            let want = u32::from(!tagging);
            if (ta, tb) != (want, want) {
                return Err(format!("expected {want} token each, got A={ta} B={tb}"));
            }
        }
        "extend" => {
            ca.extend_chat().map_err(|e| e.to_string())?;
            let ext = |mine: bool| {
                move |ev: &Ev| match ev {
                    Ev::Peer(PeerEvent::Extended { hold_secs, by_me }) if *by_me == mine => {
                        Some(*hold_secs)
                    }
                    _ => None,
                }
            };
            let hold = wait(&ra, "A extended", |ev| match ev {
                Ev::Peer(PeerEvent::ExtendRefused) => Some(None),
                ev => ext(true)(ev).map(Some),
            })?
            .ok_or("extend refused: no VIP token (relay policy)")?;
            wait(&rb, "B told about the hold", ext(false))?;
            let keep = format!("{} keep-me", a.marker);
            let burn = format!("{} burn-me", a.marker);
            ca.send_text(keep.clone(), 0).map_err(|e| e.to_string())?;
            ca.send_text(burn.clone(), 60).map_err(|e| e.to_string())?;
            for want in [&keep, &burn] {
                wait(&rb, "B gets A's message", |ev| {
                    matches!(ev, Ev::Msg(m) if &m.body == want).then_some(())
                })?;
            }
            let key = vec![0x5au8; 32];
            let blob = ca.suspend(key.clone()).map_err(|e| e.to_string())?;
            wait(&ra, "A suspended", |ev| ended(ev, EndReason::Suspended))?;
            if blob
                .windows(a.marker.len())
                .any(|w| w == a.marker.as_bytes())
            {
                return Err("saved session contains plaintext".into());
            }
            drop(ca);
            let grace = wait(&rb, "B sees A away", |ev| match ev {
                Ev::Peer(PeerEvent::Disconnected { grace_secs }) => Some(*grace_secs),
                _ => None,
            })?;
            if grace < 3600 {
                return Err(format!("room only holds A for {grace}s"));
            }
            // Longer than the relay's (shortened) normal grace period.
            let away = format!("{} while-away", a.marker);
            cb.send_text(away.clone(), 0).map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_secs(6));
            if let Some(ev) = rb
                .try_iter()
                .find(|ev| matches!(ev, Ev::State(ChatState::Ended { .. })))
            {
                return Err(format!("B's chat ended while A was saved: {ev:?}"));
            }
            let (ca2, ra2) = client(&a2);
            if ca2.resume_saved(blob.clone(), vec![1; 32]).is_ok() {
                return Err("resumed with the wrong key".into());
            }
            ca2.resume_saved(blob, key).map_err(|e| e.to_string())?;
            wait(&ra2, "A resumed", chatting)?;
            wait(&rb, "B sees A back", |ev| {
                matches!(ev, Ev::Peer(PeerEvent::Reconnected)).then_some(())
            })?;
            let t = ca2.transcript();
            if !t.iter().any(|m| m.body == keep && m.from_me) || t.iter().any(|m| m.body == burn) {
                return Err(format!("restored transcript wrong: {t:?}"));
            }
            wait(&ra2, "message sent while A was away", |ev| {
                matches!(ev, Ev::Msg(m) if m.body == away).then_some(())
            })?;
            let p2 = Pair {
                ca: &ca2,
                cb: &cb,
                ra: &ra2,
                rb: &rb,
                marker: &a.marker,
            };
            p2.exchange(2, "after-resume")?;
            println!("held {hold}s; saved, quit, resumed after 6s; burn-after-reading not saved");
            ca2.leave();
            wait(&rb, "B sees peer left", |ev| ended(ev, EndReason::PeerLeft))?;
            return Ok(());
        }
        "trusted" => {
            // Earn three good-chat tokens each (this chat and two more).
            for round in 0..3 {
                if round > 0 {
                    ca.start_match();
                    cb.start_match();
                    wait(&ra, "A chatting", chatting)?;
                    wait(&rb, "B chatting", chatting)?;
                }
                std::thread::sleep(Duration::from_millis(1500));
                pair.exchange(1, &format!("earn{round}"))?;
                ca.leave();
                wait(&rb, "B sees peer left", |ev| ended(ev, EndReason::PeerLeft))?;
                wallet_event(&rb, "B's token")?;
                wallet_event(&ra, "A's token")?;
            }
            if (ca.good_tokens(), cb.good_tokens()) != (3, 3) {
                return Err(format!(
                    "earned {} / {}",
                    ca.good_tokens(),
                    cb.good_tokens()
                ));
            }
            let replay = ca.wallet_export();
            let mut ta = a2.clone();
            ta.trusted = true;
            let (xa, rxa) = client(&ta);
            let (xb, rxb) = client(&ta);
            xa.wallet_import(ca.wallet_export())
                .map_err(|e| e.to_string())?;
            xb.wallet_import(cb.wallet_export())
                .map_err(|e| e.to_string())?;
            xa.start_match();
            xb.start_match();
            for (rx, who) in [(&rxa, "A"), (&rxb, "B")] {
                let t = wait(rx, "trusted handshake", |ev| match ev {
                    Ev::State(ChatState::Handshaking { trusted, .. }) => Some(*trusted),
                    _ => None,
                })?;
                if !t {
                    return Err(format!("{who} was not placed in the trusted queue"));
                }
            }
            if (xa.good_tokens(), xb.good_tokens()) != (0, 0) {
                return Err("tokens were not spent".into());
            }
            println!("3 tokens each → matched in the trusted queue");
            xa.leave();
            xb.leave();
            // Replaying A's old wallet: the nullifiers are already spent.
            let (xc, rxc) = client(&ta);
            xc.wallet_import(replay).map_err(|e| e.to_string())?;
            let (xd, rxd) = client(&a2);
            xc.start_match();
            std::thread::sleep(Duration::from_millis(500));
            xd.start_match();
            let t = wait(&rxc, "replay handshake", |ev| match ev {
                Ev::State(ChatState::Handshaking { trusted, .. }) => Some(*trusted),
                _ => None,
            })?;
            wait(&rxd, "partner handshake", |ev| {
                matches!(ev, Ev::State(ChatState::Handshaking { .. })).then_some(())
            })?;
            if t {
                return Err("double-spent tokens were accepted".into());
            }
            println!("replayed tokens refused; matched normally instead");
        }
        "grace" => {
            ca.panic_wipe();
            let g = wait(&rb, "B sees disconnect", |ev| match ev {
                Ev::Peer(PeerEvent::Disconnected { grace_secs }) => Some(*grace_secs),
                _ => None,
            })?;
            let t = Instant::now();
            wait(&rb, "B sees peer gone", |ev| ended(ev, EndReason::PeerGone))?;
            println!("grace {g}s expired after {:?}", t.elapsed());
        }
        other => return Err(format!("unknown scenario {other}")),
    }
    Ok(())
}

/// Tokens arrive after the chat has ended for the UI, so skip `Ended` events.
fn wallet_event(rx: &Receiver<Ev>, what: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ev::Wallet) => return Ok(()),
            Ok(_) => continue,
            Err(_) => return Err(format!("timed out waiting for {what}")),
        }
    }
}

/// A 320×240 JPEG with an EXIF segment carrying `exif`.
fn test_photo(exif: &[u8]) -> Vec<u8> {
    let img = image::RgbImage::from_fn(320, 240, |x, y| image::Rgb([x as u8, y as u8, 99]));
    let mut j = Vec::new();
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut std::io::Cursor::new(&mut j), image::ImageFormat::Jpeg)
        .expect("encode");
    let mut seg = vec![0xFF, 0xE1];
    seg.extend_from_slice(&((exif.len() + 8) as u16).to_be_bytes());
    seg.extend_from_slice(b"Exif\0\0");
    seg.extend_from_slice(exif);
    j.splice(2..2, seg);
    j
}

fn ev_clone(ev: &Ev) -> Ev {
    match ev {
        Ev::Common(t) => Ev::Common(t.clone()),
        Ev::Profile(p) => Ev::Profile(p.clone()),
        _ => unreachable!("only used for PSI events"),
    }
}

fn chatting(ev: &Ev) -> Option<()> {
    matches!(ev, Ev::State(ChatState::Chatting)).then_some(())
}

fn ended(ev: &Ev, want: EndReason) -> Option<()> {
    matches!(ev, Ev::State(ChatState::Ended { reason }) if *reason == want).then_some(())
}

struct Pair<'a> {
    ca: &'a SnowClient,
    cb: &'a SnowClient,
    ra: &'a Receiver<Ev>,
    rb: &'a Receiver<Ev>,
    marker: &'a str,
}

impl Pair<'_> {
    /// Send `n` messages each way and check every one arrives intact.
    fn exchange(&self, n: usize, tag: &str) -> Result<(), String> {
        for i in 0..n {
            for (from, to_rx, name) in [(self.ca, self.rb, "A→B"), (self.cb, self.ra, "B→A")] {
                let body = format!("{} {tag} {name} #{i} 你好", self.marker);
                from.send_text(body.clone(), 0).map_err(|e| e.to_string())?;
                let got = wait(to_rx, name, |ev| {
                    if let Ev::Msg(m) = ev {
                        Some(m.body.clone())
                    } else {
                        None
                    }
                })?;
                if got != body {
                    return Err(format!("{name}: expected {body:?}, got {got:?}"));
                }
            }
        }
        Ok(())
    }
}
