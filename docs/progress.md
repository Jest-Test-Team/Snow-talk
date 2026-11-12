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
