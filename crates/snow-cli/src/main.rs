//! snow-cli — terminal client and E2E test bot.
//!
//! ```text
//! snow-cli chat      [--server URL] [--bucket N]
//! snow-cli pair-test [--server URL] [--bucket N] [--messages N] [--marker TEXT]
//! ```
//! `pair-test` runs two clients in one process, pairs them, exchanges messages in
//! both directions, checks that the SAS matches, leaves, and exits non-zero on failure.
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
}

struct Args {
    cmd: String,
    server: String,
    bucket: Option<u8>,
    messages: usize,
    marker: String,
}

fn args() -> Args {
    let mut a = Args {
        cmd: String::new(),
        server: "http://127.0.0.1:8787".into(),
        bucket: None,
        messages: 5,
        marker: "SNOW-PLAINTEXT-MARKER".into(),
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
        },
        Arc::new(Chan(tx)),
    );
    (c, rx)
}

fn main() {
    let a = args();
    match a.cmd.as_str() {
        "chat" => chat(&a),
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
    let (ca, ra) = client(a);
    let (cb, rb) = client(a);
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
    let chatting = |ev: &Ev| matches!(ev, Ev::State(ChatState::Chatting)).then_some(());
    let sa = wait(&ra, "SAS on A", sas)?;
    wait(&ra, "A chatting", chatting)?;
    let sb = wait(&rb, "SAS on B", sas)?;
    wait(&rb, "B chatting", chatting)?;
    if sa != sb {
        return Err(format!("SAS mismatch: {sa:?} vs {sb:?}"));
    }
    println!("paired in {:?}, SAS {}", t0.elapsed(), sa.join(""));

    for i in 0..a.messages {
        for (from, to_rx, name) in [(&ca, &rb, "A→B"), (&cb, &ra, "B→A")] {
            let body = format!("{} {name} #{i} 你好", a.marker);
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
    println!("exchanged {} messages each way", a.messages);

    ca.leave();
    wait(&ra, "A ended", |ev| match ev {
        Ev::State(ChatState::Ended {
            reason: EndReason::SelfLeft,
        }) => Some(()),
        _ => None,
    })?;
    wait(&rb, "B sees peer left", |ev| match ev {
        Ev::State(ChatState::Ended {
            reason: EndReason::PeerLeft,
        }) => Some(()),
        _ => None,
    })?;
    println!("leave propagated");
    Ok(())
}
