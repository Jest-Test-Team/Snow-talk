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
