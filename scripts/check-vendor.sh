#!/usr/bin/env bash
# Fail if the vendored SQLite is older than the CVE-2026-119375 fix (3.54.0).
set -euo pipefail
cd "$(dirname "$0")/.."
n=$(sed -n 's/^#define SQLITE_VERSION_NUMBER \([0-9]*\).*/\1/p' vendor/libsqlite3-sys/sqlite3/sqlite3.h)
if [ "$n" -lt 3054000 ]; then echo "vendored SQLite $n < 3054000"; exit 1; fi
cargo tree -p snow-core --features tor -i libsqlite3-sys | grep -q "vendor/libsqlite3-sys" \
  || { echo "libsqlite3-sys is not the vendored copy"; exit 1; }
echo "vendored SQLite $n OK"
