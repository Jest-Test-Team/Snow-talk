//! snow-cli — terminal client and E2E test bot.
//!
//! ```text
//! snow-cli chat      [--server URL] [--bucket N]
//! snow-cli net-check --server URL [--tor DIR]   # DoH + ECH (+ Tor) diagnostics
//! snow-cli pair-test [--server URL] [--bucket N] [--messages N] [--marker TEXT]
//!                    [--scenario basic|reconnect|rotate|chaff|free|flood|burn|grace]
//!                    [--paranoid] [--chaff MS]
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
//! * `grace`     — A vanishes; B must see `Disconnected` then `PeerGone`
//!   (run the relay with a short `GRACE_SECS`)
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
}

struct Chan(Sender<Ev>);
impl ChatListener for Chan {
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
    pins: Vec<String>,
    tor_dir: Option<String>,
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
        pins: Vec::new(),
        tor_dir: None,
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
            pins: a.pins.clone(),
            tor_dir: a.tor_dir.clone(),
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
                Ev::Msg(m) => println!("< {}", m.body),
                Ev::Peer(p) => println!("* peer: {p:?}"),
                Ev::Burn(id, mine) => println!("* burned #{id} (mine: {mine})"),
            }
        }
    });
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap_or_default();
        if line == "/leave" {
            c.leave();
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
    let (ca, ra) = client(&a2);
    let (cb, rb) = client(&a2);
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
        Ev::State(ChatState::Handshaking { paranoid }) => Some(*paranoid),
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
    pair.exchange(a.messages, "warmup")?;

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
