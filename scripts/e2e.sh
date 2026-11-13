#!/usr/bin/env bash
# Start the relay locally, pair two bots, and check the relay never saw plaintext.
set -euo pipefail
cd "$(dirname "$0")/.."
MARKER="E2E-MARKER-$RANDOM$RANDOM"
LOG=$(mktemp)
[[ -f server/.dev.vars ]] || cp server/.dev.vars.example server/.dev.vars
(cd server && npm install --silent && npx wrangler dev --port 8787 --var GRACE_SECS:4 --var PARANOID_GRANT:open >"$LOG" 2>&1) &
WRANGLER=$!
trap 'kill $WRANGLER 2>/dev/null; pkill -f "wrangler dev --port 8787" 2>/dev/null || true' EXIT
for _ in $(seq 1 90); do grep -q "Ready on" "$LOG" && break; sleep 2; done
cargo build -q -p snow-cli
for s in basic reconnect rotate chaff free flood burn grace; do
  echo "== scenario: $s"
  ./target/debug/snow-cli pair-test --messages "${MESSAGES:-3}" --marker "$MARKER" --scenario "$s"
done
if grep -q "$MARKER" "$LOG" || grep -rq "$MARKER" server/.wrangler/state 2>/dev/null; then
  echo "FAIL: plaintext marker reached the relay's logs or storage"; exit 1
fi
if grep -q "GET /room/" "$LOG"; then echo "FAIL: ticket appeared in a URL"; exit 1; fi
echo "blind-relay checks passed"
