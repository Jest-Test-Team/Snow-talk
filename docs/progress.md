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
- ~~⚠️ Known issue: bundled SQLite CVE (RUSTSEC-2026-0459) pinned by arti 0.48.~~ **Resolved (2026-11-13):** `vendor/libsqlite3-sys` = upstream 0.38.2 + the SQLite 3.54.1 amalgamation from 0.39.1, wired via `[patch.crates-io]`. The `deny.toml` ignore is removed; CI runs `scripts/check-vendor.sh` (SQLite ≥ 3.54.0 and the patch is actually used). Verified: Tor bootstrap with a fresh `dir.sqlite3` works, ECH still on. Drop the vendor copy once arti uses rusqlite ≥ 0.41.
- Not yet verified: pairing end to end *over Tor*. That needs a deployed relay (localhost isn't reachable from an exit), plus the Cloudflare WAF rule that lets Tor exits through without a challenge.

### ⚠️ Cost finding: chaff disables Durable Object hibernation
A DO hibernates only after about 10 s without events. Chaff every 1.5 s keeps every active room awake, so **duration** billing applies for the whole chat. Back-of-envelope, using Cloudflare's published rates as I know them (128 MB × 3600 s = 460.8 GB-s per room-hour; the incoming-message charge is negligible): roughly **US$0.006 per room-hour**, which is about **US$4,000/month for 1,000 rooms open around the clock**. Re-check these numbers against the current price list before launch.
Options: (a) accept it as the cost of strong cover traffic; (b) chaff period > 10 s (weak cover, but the DO hibernates); (c) a time budget, e.g. chaff only for the first N minutes or only when the user turns on "paranoid mode"; (d) make chaff a paid/VIP feature. **This needs a product decision** — `chaff_ms` is already remotely tunable, so all four options are possible without an app update.

**Decision (2026-11-13): (c)+(d) — chaff is the VIP "paranoid mode".** Implemented:
- `Join { paranoid }` request → the matchmaker grants it (`PARANOID_GRANT=open` in dev/beta; production `token` = denied until Phase 10 VIP tokens) → the grant is a signed `flags` bit in the room ticket and carried into resume/rotation tickets → `Matched { paranoid }` / `ChatState::Handshaking { paranoid }` tell the client.
- The client sends chaff only when granted (`chaff_ms` clamped to ≥ 250 ms). Without it there's no cover traffic, so idle rooms hibernate. Padding (4096 B) and the 0–300 ms send jitter still apply to everyone; free mode also spaces bursts ≥ 500 ms apart.
- **Server-side enforcement**, since the client is open source: per-slot token-bucket cap in the ChatRoom (free: burst 20, 2/s; paranoid: burst 40, 5/s — *raised in Phase 8 to free 48/4 s⁻¹, paranoid 64/6 s⁻¹ so a flash photo fits in one burst*). Over-cap frames are dropped with `Error(RateLimited)` (non-fatal; Olm tolerates gaps). A modified free client can still run slow (≤ 2/s) chaff and keep its room awake — the cost is bounded per room, so this is accepted.
- E2E: the `chaff` (granted), `free` (0 idle frames, 12-message burst never limited) and `flood` (83/100 dropped, chat survives) scenarios pass; production policy denies the request.
- Privacy note: the matchmaker learns one bit ("this user asked for/holds the perk"). In Phase 10 it will come from an unlinkable blind token.

## Phase 6 — Device protection (Rust part done 2026-11-13; native part blocked on Xcode / Android SDK)

**Plan vs. done**
- ✅ **Burn after reading**: every message carries a TTL; each side runs its own timer (sender from when it's queued, receiver from arrival). On expiry the message is removed from the Rust store, zeroized, and the UI gets `on_burn(id, from_me)`. E2E `burn`: a 2 s message disappears on both sides after 2.00 s.
- ✅ **RAM hygiene (Rust side)**: plaintext lives in a per-chat `Transcript` of `Zeroizing<String>`s, wiped when the chat ends. Each `start_match` gets a new transcript, so an old chat that ends late can't clear the new one.
- ✅ **Screenshot notice**: `notify_screen_captured()` → encrypted `Inner::ScreenCaptured`, sent through the pacer so its timing looks like any other frame → the peer gets `on_peer(ScreenCaptured)`. Verified in E2E.
- ⏳ **Native, blocked on tooling**: Android `FLAG_SECURE` + `onTrimMemory`; iOS secure-layer rendering, `userDidTakeScreenshotNotification` / `capturedDidChange` → `notify_screen_captured()`, blurred app-switcher snapshot; decoy calculator UI.

**Deviations**
- The plan had `snow_core::wipe_ui_cache()`. Instead, Rust is the source of truth: the UI renders from `transcript()` and drops its own list on background, low memory or the decoy screen, then fetches it again. A `wipe_ui_cache()` in Rust couldn't reach Swift/Kotlin memory anyway. Swift/Kotlin strings still can't be zeroized (best-effort, as the plan says).
- While reconnecting, burn timers fire late, but `transcript()` already hides expired messages.

## Phase 7 — Interest matching & ephemeral profiles (2026-11-13)

**Plan vs. done**
- ✅ **Tag buckets**: `snow_psi::bucket = SHA-256(domain ‖ week ‖ normalize(tag))[0] mod 64`, salted weekly (epoch = week number). The matchmaker only sees the bucket of the *primary* (first) tag. Normalization: NFKC, lowercase, strip `#`/`＃`, collapse spaces, ≤ 32 chars (so `ＣＡＴＳ`, `#cats` and `cats` are the same tag).
- ✅ **In-session PSI**: ristretto255 DH-PSI (`snow-psi`) with two rounds of exactly 16 points. Both sets are padded with random points, so each side learns only the intersection, not the peer's tag count. The rounds travel as `Inner::PsiRound1/2` inside Olm and through the pacer. A peer with no tags still answers with padding, so the run always completes. Tests: intersection, disjoint/empty sets, fixed size, fresh secrets per run, malformed or out-of-order input, bucket uniformity.
- ✅ **Auto re-queue**: with tags and `require_common_tag` (default true), an empty intersection ends the chat with `EndReason::NoCommonTags` and sends `Leave`. E2E `disjoint` passes.
- ✅ **Ephemeral profile**: nickname / MBTI / mood / `adult_ok`, sent once per chat over E2EE (`Inner::Profile`), ≤ 64 bytes per field (checked on both encode and decode), never stored.
- ✅ **Adult gate**: the `adult_tags` cargo feature (Android/sideload only). Without it, adult tags are never put in the PSI and `adult_ok` is forced false on send *and* receive. Adult tags use their own namespace (`18+:`), so they only match each other. CI tests both builds.
- ✅ E2E `tags`: A = {cats, jazz, hiking}, B = {Cats, chess, #Hiking} → both privately get [cats, hiking]; profiles arrive; chat continues.

**Deviations / limits to keep in mind**
- Matching uses only the primary tag's bucket, so people who share only a secondary tag won't meet. A fix would be multi-bucket queueing (join several matchmaker shards at once); deferred until there's real queue data.
- PSI limits (written in the crate docs): a dishonest peer can probe up to 16 chosen tags per chat, and can lie about the result.
- Age self-declaration UI for adult tags belongs to the native app (Phase 3/6).
- Users near a week boundary may hash to different buckets for a moment (negligible).

## Phase 8 — Flash photos & voice notes (Rust part done 2026-11-13)

**Plan vs. done**
- ✅ **Metadata stripping by re-encoding** (`snow-media`): the image is fully decoded (JPEG/PNG/WebP/GIF, with decode-size limits), EXIF orientation is applied to the pixels, it's scaled to ≤ 1280 px and written as a fresh JPEG ≤ 120 KB (lower quality, then smaller size, until it fits). Tests put GPS EXIF, a PNG `tEXt` chunk and trailing data in; none of it comes out.
- ✅ **One `MediaKey` per item** (ChaCha20-Poly1305, single-use key, AAD = media id ‖ kind, so chunks can't be spliced between items). The key travels in an Olm-encrypted `MediaOffer`, and the ciphertext goes as 3 KB `MediaChunk`s, each in one fixed 4 KB frame.
- ✅ **Sharing the send path**: chunks go into the pacer's *bulk* queue behind text and control messages. Free mode sends them as one token-bucket burst (a 320×240 photo arrived in 27 ms in E2E). In paranoid mode they replace chaff ticks, so they're slow on purpose, as the plan says.
- ✅ **Flash burn**: the receiver keeps only ciphertext. `open_media` decrypts **once**, destroys the key and ciphertext, sends `MediaBurned` (the sender gets `on_media_burned(id, true)`) and starts the view timer (`view_secs` 1–10, default 3). When it expires → `on_media_burned(id, false)`. Opening a second time → `MediaGone`.
- ✅ **RAM only**: nothing is written to disk anywhere in the Rust path. Limits: 4 items in flight and 16 unopened per chat; a bad chunk poisons its item.
- ✅ E2E `media`: a photo with GPS EXIF arrives clean (320×240), opens once, the sender is notified, and it burns after 2 s.
- ⏳ **Native**: hold-to-view UI; iOS converts HEIC to JPEG before `send_image` (the Rust decoder has no HEIC); audio recording and encoding in memory (AVAudioRecorder → AAC / MediaRecorder → Opus).

**Deviations**
- No `opus` crate: it needs C libopus. Voice is platform-encoded and treated as opaque sealed bytes. Recorded audio has no EXIF-like location metadata, but the native layer must not write container tags.
- The free-mode pacer changed from a fixed 500 ms gap to a token bucket (burst 40, 3.5/s), kept just under the room's raised caps.

## Phase 9 — Trust & safety (core done 2026-11-13; ML stage pending a model decision)

**Plan vs. done**
- ✅ **PoW**: done in Phases 1–2 (difficulty is a server var and can be raised under load).
- ✅ **Local rule screening** (`snow-safety`, received text only, on device): links / shorteners, LINE / Telegram / phone / e-mail, crypto and wallet addresses, investment pitches, payments, **game-card / gift-card requests**, gambling, paid-sex solicitation. Text is normalized against obfuscation (full-width, zero-width, Chinese numerals `零九一二…`, spaced-out `l i n e`, `點` → `.`). Contact + money is always blurred. `ChatMessage.safety` (Clean / Caution / Blur) plus `safety_flags` drive "此訊息可能含有不當內容，點擊以檢視". Unit tests include a set of ordinary-chat false-positive checks; E2E `safety` passes.
- ✅ **Reports**: `report()` during the chat, or within `report_secs` after the peer leaves. The room only records "slot X reported" — no content. Only the first report in a room counts, so a reported user can't retaliate.
- ✅ **Anonymous reputation tokens** (`snow-tokens`): **RFC 9497 VOPRF (ristretto255)**, issued per room at the end of a chat when both sides were present ≥ `GOOD_AFTER_SECS` (300 s) and active ≥ `MIN_ACTIVE_FRAMES` (10), and the claimant wasn't reported. Keys are derived per (kind, 30-day epoch) from `TOKEN_MASTER`; the client checks the DLEQ proof and pins the key per epoch. The wallet is the app's only persisted state (`wallet_export` → Keychain/Keystore, `on_wallet_changed`).
- ✅ **Trusted queue**: Join spends 3 good-chat tokens. They're verified, and their nullifiers are burned in a sharded `Nullifiers` DO shared by all matchmaker shards. Trusted users are paired with each other; after `TRUSTED_EXCLUSIVE_SECS` (30 s) a trusted waiter may be matched with anyone. A **VIP token** spent on Join grants paranoid mode (same machinery; VIP issuance arrives with IAP in Phase 10).
- ✅ E2E: `goodchat` (A=1, B=1), `report` (reported leaver A=0, reporter B=1), `trusted` (3+3 tokens → trusted match; a replayed wallet is refused and matched normally).
- ⏳ **ML toxicity stage (tract + model from R2 + pinned SHA-256)**: not built yet. It needs a concrete model choice: a multilingual model small enough to download (the plan's 20–60 MB int8), a tokenizer we can run in pure Rust, and a zh-Hant evaluation set for precision/recall. `Verdict.score` is already the hook for combining rules + model.
- ⏳ **Report with a user-chosen excerpt**: deferred. It would send plaintext to the operator, so it needs a moderation-storage design and its own disclosure.

**Deviations**
- **Blind RSA (RFC 9474) → VOPRF (RFC 9497).** The issuer is also the only verifier, so public verifiability buys nothing. VOPRF is smaller, constant-time and wasm-friendly, and its DLEQ proof gives the key-consistency guarantee we need (no per-user tagging keys). It also keeps RSA private-key operations off the server.
- **Library**: `voprf 0.6.0-pre.2`, pinned exactly. 0.5 pulls `crypto-bigint 0.5` (RUSTSEC-2026-0387, timing); 0.6 uses crypto-bigint 0.7.11 and the same curve25519-dalek 5 as `snow-psi`. Move to 0.6.0 when it is released.
- **Token earning is per chat, at the end** (the "nobody reported me" rule), rather than for any chat that simply wasn't reported. Self-dealing (one person running both sides for 5 min) can still farm tokens; the cost is PoW + 5 min per token, and the trusted queue's value depends on it staying expensive. Revisit with real data (e.g. raise `GOOD_AFTER_SECS` or `TRUSTED_MIN`).
- **Key consistency** is only first-seen pinning per epoch. Stronger: ship the epoch keys inside the Phase 10 signed remote config, so every client sees the same keys.
- The matchmaker learns one bit per join ("spent N good tokens" / "spent a VIP token"), never which ones.

## Phase 10 — Monetization (server / Rust part done 2026-11-13; Google Play and native UI pending)

**Plan vs. done**
- ✅ **Signed remote config** (`snow-config`): Ed25519 over a JSON body (`SNOWCFG1 ‖ sig ‖ json`), with expiry, a 45-day lifetime cap and rollback protection (highest version seen). It carries `chaff_ms`, feature switches (donations / lightning / voice / photos), **the token issuer keys per epoch**, and the sponsor catalog's SHA-256. It is signed **offline** (`snow-config` tool, `--features tool`); the relay only serves `config.bin` from R2 and can't forge it. The client fetches it at match start when `Config::config_key` is set and keeps the last valid copy if a fetch fails. This closes the Phase 9 follow-up: a relay that hands someone its own issuer key is refused (E2E `config-tagging`: A=0, B=0).
- ✅ **Sponsored tags**: `catalog.json` in R2, pinned by hash in the config. The client downloads the whole catalog and picks up to 3 cards for its own tags (weighted rotation), so the relay never learns which tags you have. Links must be `https://` with no query or fragment (no per-user tracking parameters); no ad SDK. `ChatListener::on_sponsors` fires while queued. E2E `config`: both sides were shown the coffee sponsor first.
- ✅ **24 h hold (VIP)**: `extend_chat()` spends a VIP token (`EXTEND_GRANT=open` in dev). The room then holds both slots for `EXTEND_SECS` (24 h), even if both sides go offline, and **tells both sides** (`PeerEvent::Extended { by_me }`), so the UI can warn that the peer may keep a saved copy.
  - `suspend(key)` seals the vodozemac pickle, the resume ticket and the non-burning messages under an HKDF-split app key (ChaCha20-Poly1305), then disconnects without leaving.
  - `resume_saved(blob, key)` works from a brand-new client.
  - Burn-after-reading messages and media are never saved.
  - E2E `extend`: the session outlives the 4 s grace, the wrong key is refused, the message sent while away arrives, and the chat continues.
- ✅ **IAP → blind VIP tokens, App Store**: `POST /tokens/vip` verifies the StoreKit 2 `jwsRepresentation` offline.
  - The `x5c` chain must end in the pinned **Apple Root CA - G3** (fingerprint `63343abf…9179`, checked in a test), carry Apple's leaf and intermediate OIDs, and chain-verify at `signedDate`. The payload is then ES256-verified.
  - Policy (`APPLE_BUNDLE_ID`, `APPLE_PRODUCTS = id:count`, `APPLE_SANDBOX`) refuses other apps, refunds and, by default, sandbox purchases.
  - The `Redemptions` DO stores `hash(transaction id) → hash(blinded)`: a lost response can be retried with the identical request, which the wallet keeps a seed for, but a second request for the same purchase is refused.
  - E2E `vip` (test CA, accepted only in `--features e2e-test-root` builds): a purchase buys 5 tokens; a replay, a foreign product and a forgery are refused.
  - Native tests cover a wrong root, a spliced chain, a leaf without the marker OID, and a payload swapped after signing.
- ⏳ **Google Play**: needs a service account for the Play Developer API. `Store::Google` is answered with `Unsupported`.
- ⏳ **Donations / cosmetics / Lightning (Android, Breez SDK)**: these are client-side and native. The remote-config switches exist; the UI waits for Xcode and Android Studio.

**Deviations**
- **Fast Pass (`priority` queue) dropped.** I built it and the E2E test showed it can't work: the matchmaker pairs the first two compatible people immediately, so there is never a line of compatible waiters to jump. A VIP arriving while someone waits is matched at once, which happens for free anyway. Selling it would mean charging for nothing. Revisit only if matching ever becomes selective (e.g. filters), and then it must be shown to shorten waits.
- **"進階篩選" (match only with trusted users)** is already the Phase 9 trusted queue (paid with good-chat tokens, not money). It stays reputation-based, so trust can't simply be bought.
- **Saved sessions include non-burning messages**, not only the ratchet. Without them a resumed chat would come back blank. The blob is useless without the hardware-backed key, and the UI must state that an encrypted copy stays on the device.
- **Remote config is fail-open.** If the relay withholds it, the client keeps the last valid copy and falls back to first-seen key pinning. Withholding can only remove features; it can't forge them.
- **Dependency hygiene**: p256/p384 0.13 pull crypto-bigint 0.5 (RUSTSEC-2026-0387), so the IAP code uses p256/p384 0.14 and x509-cert 0.3. CI now also runs the server's unit tests and its advisory check.
- The relay sees one transaction per purchase (which Apple can tie to an Apple ID). Tokens are blinded, so spending can't be linked to the purchase. But redeeming right before the first spend narrows timing. The app should redeem in the background on purchase, not just in time.
