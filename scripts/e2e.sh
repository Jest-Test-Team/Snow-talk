#!/usr/bin/env bash
# Start the relay locally, pair two bots, and check the relay never saw plaintext.
set -euo pipefail
cd "$(dirname "$0")/.."
MARKER="E2E-MARKER-$RANDOM$RANDOM"
LOG=$(mktemp)
[[ -f server/.dev.vars ]] || cp server/.dev.vars.example server/.dev.vars
(cd server && npm install --silent && npx wrangler dev --port 8787 --var GRACE_SECS:4 --var PARANOID_GRANT:open --var GOOD_AFTER_SECS:1 --var MIN_ACTIVE_FRAMES:2 --var REPORT_SECS:3 --var TRUSTED_EXCLUSIVE_SECS:1 >"$LOG" 2>&1) &
WRANGLER=$!
trap 'kill $WRANGLER 2>/dev/null; pkill -f "wrangler dev --port 8787" 2>/dev/null || true' EXIT
for _ in $(seq 1 90); do grep -q "Ready on" "$LOG" && break; sleep 2; done
cargo build -q -p snow-cli
cargo build -q -p snow-config --features tool

# Signed remote config + sponsor catalog in the local R2 bucket. $1 = version,
# $2 = token master whose issuer keys the config pins.
CFG=$(mktemp -d)
PUBKEY=$(./target/debug/snow-config keygen "$CFG/seed")
cat >"$CFG/catalog.json" <<'JSON'
{"version":1,"sponsors":[
  {"id":"cafe","tags":["coffee","咖啡"],"title":"Local roastery","body":"10% off","url":"https://cafe.example/"},
  {"id":"house","title":"Snow-talk","body":"Be kind.","url":"https://snowtalk.example/"}
]}
JSON
publish_config() {
  echo "{\"version\":$1,\"chaff_ms\":1500,\"features\":{\"photos\":true,\"voice\":true}}" >"$CFG/tpl.json"
  TOKEN_MASTER="$2" ./target/debug/snow-config sign "$CFG/seed" "$CFG/tpl.json" "$CFG/config.bin" --catalog "$CFG/catalog.json" >/dev/null
  for f in config.bin catalog.json; do
    (cd server && npx wrangler r2 object put "snow-talk-public/$f" --file "$CFG/$f" --local >/dev/null 2>&1)
  done
}
MASTER=$(sed -n 's/^TOKEN_MASTER="\(.*\)"$/\1/p' server/.dev.vars)
for s in basic reconnect rotate chaff free flood burn tags disjoint media safety goodchat report trusted grace; do
  echo "== scenario: $s"
  ./target/debug/snow-cli pair-test --messages "${MESSAGES:-3}" --marker "$MARKER" --scenario "$s"
done
echo "== scenario: config"
publish_config 1 "$MASTER"
./target/debug/snow-cli pair-test --messages 1 --marker "$MARKER" --scenario config --config-key "$PUBKEY"
echo "== scenario: config-tagging"
publish_config 2 "not-the-relays-master"
./target/debug/snow-cli pair-test --messages 1 --marker "$MARKER" --scenario config-tagging --config-key "$PUBKEY"
rm -rf "$CFG"
if grep -q "$MARKER" "$LOG" || grep -rq "$MARKER" server/.wrangler/state 2>/dev/null; then
  echo "FAIL: plaintext marker reached the relay's logs or storage"; exit 1
fi
if grep -q "GET /room/" "$LOG"; then echo "FAIL: ticket appeared in a URL"; exit 1; fi
echo "blind-relay checks passed"
