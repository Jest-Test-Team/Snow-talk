# Progress & plan-alignment log

The plan these entries are checked against is summarized in `docs/threat-model.md`
and the phase list below.

## Phase 0 — Scaffolding (2026-11-12)

| Plan item | Status |
|---|---|
| Cargo workspace (`crates/*`, `server/` excluded, wasm-built separately) | ✅ |
| CI: fmt, clippy `-D warnings`, test, wasm build, cargo-deny | ✅ `.github/workflows/ci.yml`, `deny.toml` (no copyleft; libsignal banned) |
| UniFFI binding generation script | ✅ `scripts/gen-bindings.sh` — verified locally, produces Swift + Kotlin |
| iOS xcframework / Android cargo-ndk scripts | ✅ written, ⚠️ **unverified**: this machine has no Xcode or Android SDK/NDK |
| Empty iOS/Android shells calling `snow_core::version()` | ⏭️ **Deferred to start of Phase 3**: can't be built or verified without Xcode / Android Studio |
| Licenses (Apache-2.0 root; proprietary `server/LICENSE`) | ✅ |

**Deviation:** the native shell apps move from Phase 0 to Phase 3. Nothing else in
Phase 1–2 depends on them, so the order of the remaining work doesn't change.

**Action for the user:** install Xcode (then run `sudo xcode-select -s /Applications/Xcode.app`)
and Android Studio with the SDK, NDK, and cmdline-tools before Phase 3.

## Phase 1 — Protocol & crypto core (2026-11-12)

| Plan item | Status |
|---|---|
| Fixed 4096-byte frames; chaff and data indistinguishable on the wire | ✅ `snow-proto` — `[ver][len][postcard][random pad]`. Chaff and text are both `Relay` frames carrying Olm ciphertexts of identical length (test `chaff_and_text_ciphertexts_have_equal_length`) |
| Ephemeral Olm account per chat, keys handed over through the relay (no prekey directory) | ✅ `snow-crypto::Handshaker` |
| SAS, 7 emoji | ✅ — plus a **commit/reveal** step the plan didn't spell out. Without it, the relay could grind keys until both screens show the same SAS (about 2²¹ work) |
| Zeroize secrets; `ChatSession::destroy()` | ✅ vodozemac zeroizes its key types on drop; plaintext buffers are wrapped in `Zeroizing`. ⚠️ The decoded `Inner::Text.body` is a plain `String` — `snow-core` (Phase 3) must keep it in zeroizing storage |
| PoW: HMAC-signed stateless challenge, 60 s validity | ✅ `snow-pow`; replay protection (`replay_id`) is the server's job (Phase 2) |
| Tests: out of order, replay, constant length, wasm/native | ✅ 3 proto + 3 pow + 8 crypto tests; `snow-proto`/`snow-pow` build for `wasm32-unknown-unknown` |

**Deviations / notes**
- Olm v1 uses AES-256-CBC + HMAC-SHA-256 (MAC truncated to 8 bytes), not the AES-GCM / ChaCha20 named in the ref. That's the audited vodozemac default; v2 (full MAC) is still behind an experimental feature flag.
- PoW calibration: on this Mac, solving at difficulty 16 takes about 23 ms. The default difficulty will start at 23 (about 2–3 s on a mid-range phone, to be confirmed on real devices) and is configurable on the server. SHA-256 hashcash is cheap for GPU-equipped bots, which is why the plan also adds token-based trust in Phase 9.

## Phase 2 — Cloudflare relay (2026-11-12)

| Plan item | Status |
|---|---|
| Worker router: `/pow`, `/match`, `/room` | ✅ `server/src/lib.rs` |
| Matchmaker DO sharded by `region × bucket` | ✅ `mm:tw:{bucket}`. PoW is bound to the bucket (`rand[15]`) so one solution can't be replayed across shards; replay IDs live in DO storage and are swept by an alarm |
| `priority` / `trusted` / `normal` queues | ⏭️ Only `normal` for now. The other two need tokens (Phase 9: trust, Phase 10: Fast Pass) and will be added then |
| Matched → `newUniqueId` ChatRoom + HMAC tickets (30 s TTL) | ✅ `server/src/ticket.rs` (native unit tests) |
| ChatRoom DO: hibernation API, 2 slots, only checks frames are 4096 bytes, forwards untouched, no payload storage | ✅ Re-frames `Relay` bytes without parsing them. Storage holds only per-slot generation/status |
| Logging policy | ✅ `invocation_logs = false`; code only logs `matched` / `room_created` / `room_closed` |
| E2E with `wrangler dev` + `snow-cli` bots | ✅ `scripts/e2e.sh`: pairs two bots, checks SAS and 5 messages each way plus leave propagation, then greps the logs and DO state for the plaintext marker (not found) |

**Deviations / notes**
- **New: tickets and buckets travel in headers (WebSocket subprotocol / `x-snow-bucket`), not URLs.** The plan put tickets in `/room/:ticket`. Testing showed that both peers' tickets share the room-ID prefix, so URL logs at the edge could link the two IPs.
- The client-side engine and `snow-cli` (planned for Phase 3) were pulled forward because Phase 2 can't be verified end to end without them. Phase 3 is left with the UniFFI surface hardening and the native apps.
- Pinned `wrangler@4.161.0` in `server/package.json`. The globally installed 4.33 can't parse the `import source` syntax that worker-build 0.9 emits.
- A room currently ends as soon as either socket drops (`PeerGone`). The grace period comes in Phase 4.
- Pairing latency on local dev is 25–60 ms.

## Phase 4 — Connection resilience (2026-11-12)

| Plan item | Status |
|---|---|
| Deliberate leave → peer sees "對方已離開" immediately | ✅ `ClientMsg::Leave` → `PeerLeft` (scenario `basic`) |
| Unexpected drop → slot held 3 min by DO `alarm()`, peer gets the countdown | ✅ `GRACE_SECS` var (default 180) → `PeerDisconnected { grace_secs }` → `PeerGone` on expiry (scenario `grace`, run with 4 s) |
| Resume credential kept only in RAM; ratchet survives in RAM | ✅ The resume ticket lives in the engine task. A reconnect keeps the same `ChatSession` (scenario `reconnect`) |
| iOS `beginBackgroundTask` | ⏭️ Native shell work, moved to Phase 3 |
| Session-ID rotation every N (random) minutes with overlap, no lost messages | ✅ Client-driven: re-enter with the resume ticket, the room bumps the generation and revokes the old socket and ticket, and the client drains the old socket. 8–15 min by default (scenario `rotate`: 6 rotations in 7 s, 33 round trips, no loss) |
| No cookies / JWT; short-lived single-use tickets | ✅ Every entry bumps the generation, so each resume ticket works exactly once |

**Deviations / notes**
- The plan had an *encrypted* `Control::Leave`. The server has to know about a leave anyway to close the room, so a plaintext `ClientMsg::Leave` doesn't reveal anything new.
- Added (not in the plan): while a peer is reconnecting, the room holds up to 32 ciphertext frames **in RAM only**. They're lost if the DO is evicted, which is acceptable: Olm handles gaps.
- `ServerMsg::Rotate` (server-initiated rotation) exists in the protocol but isn't used. Client-driven rotation turned out simpler.
- A rotation is invisible to the peer: `PeerReconnected` is only sent if the slot really was `Disconnected`.

## Phase 5 — Traffic obfuscation & network anonymity (2026-11-12)

| Plan item | Status |
|---|---|
| Padding (fixed 4 KB; media chunks use the same size) | ✅ since Phase 1 |
| Chaffing: constant rate in both directions, real messages take a slot, pause in background, remotely tunable | ✅ `pacer.rs`: default 1500 ms, `Config.chaff_ms`, `set_foreground(false)` pauses, peer-disconnected pauses (scenario `chaff`: 20 frames per 2 s at 100 ms; 0 in background). Remote tuning lands with remote config in Phase 10 |
| Keystroke-timing jitter (0–300 ms, then aligned to the next slot) | ✅ No typing indicator at all (decided: it would leak timing) |
| ODoH | 🔄 **Replaced (user-approved) by DoH + ECH.** ODoH can't hide the plaintext SNI. Now: RFC 8484 DoH to 1.1.1.1 by fixed IP → A/AAAA/HTTPS records → TLS 1.3 with ECH. `snow-cli net-check` against crypto.cloudflare.com reports `sni=encrypted` |
| Certificate pinning | ✅ `pin.rs`: SPKI SHA-256 pins on top of WebPKI. Wrong pin → TLS fails (checked against a live host) |
| Tor mode (Arti), off by default | ✅ `tor` cargo feature + `Config.tor_dir`. Bootstraps once, isolated circuit per chat. Every request (DoH, PoW, WS) goes through one `Dialer`. Checked: the exit IP differs from the direct IP and ECH still applies. First bootstrap 49 s, warm 10 s |
| OHTTP for `/pow`, `/tokens/*` | ⏭️ Not done. With ECH (and Tor when wanted), its remaining value is small. Revisit in Phase 10 for `/tokens/issue`, where unlinkability from IP matters most |

**Deviations / notes**
- rustls's crypto backend moved from ring to **aws-lc-rs** (needed for HPKE/ECH). Mobile builds now need `cmake` (Phase 3 prerequisite).
- reqwest was removed. A minimal HTTP/1.1 client (`http.rs`) means nothing can bypass the dialer.
- Upgraded hickory-proto 0.25 → 0.26 because of DNS parsing advisories.
- ⚠️ **Known issue:** the `tor` feature pulls in a bundled SQLite with an open CVE (RUSTSEC-2026-0459), pinned by arti 0.48. It's ignored in `deny.toml` with a justification. **Re-check on every arti upgrade.**
- Not yet verified: pairing end to end *over Tor*. That needs a deployed relay (localhost isn't reachable from an exit), plus the Cloudflare WAF rule that lets Tor exits through without a challenge.

### ⚠️ Cost finding: chaff disables Durable Object hibernation
A DO hibernates only after about 10 s without events. Chaff every 1.5 s keeps every active room awake, so **duration** billing applies for the whole chat. Back-of-envelope, using Cloudflare's published rates as I know them (128 MB × 3600 s = 460.8 GB-s per room-hour; the incoming-message charge is negligible): roughly **US$0.006 per room-hour**, which is about **US$4,000/month for 1,000 rooms open around the clock**. Re-check these numbers against the current price list before launch.
Options: (a) accept it as the cost of strong cover traffic; (b) chaff period > 10 s (weak cover, but the DO hibernates); (c) a time budget, e.g. chaff only for the first N minutes or only when the user turns on "paranoid mode"; (d) make chaff a paid/VIP feature. **This needs a product decision** — `chaff_ms` is already remotely tunable, so all four options are possible without an app update.
