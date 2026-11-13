# Vendored crates

## libsqlite3-sys (0.38.3 = 0.38.2 + SQLite 3.54.1)

Arti 0.48 (`tor-dirmgr`) pins `rusqlite` 0.40, which needs `libsqlite3-sys` 0.38.
The bundled SQLite in 0.38.2 (3.53.2) is affected by CVE-2026-119375 /
RUSTSEC-2026-0459 (uninitialized page-cache memory via a crafted `-wal` file).

This copy is the upstream 0.38.2 crate, unchanged, except:

* `sqlite3/sqlite3.c`, `sqlite3.h`, `sqlite3ext.h` — SQLite **3.54.1**, taken
  verbatim from `libsqlite3-sys` 0.39.1 (the upstream fix release).
* `sqlite3/bindgen_bundled_version{,_ext}.rs` — the matching pre-generated
  bindings from 0.39.1 (API is a superset of 3.53).
* version bumped to `0.38.3` so it is visibly not the registry release.

It is wired in with `[patch.crates-io]` in the workspace `Cargo.toml`.
`scripts/check-vendor.sh` asserts the bundled SQLite version is >= 3.54.0.

**Remove** this directory and the patch once arti depends on `rusqlite >= 0.41`
(`cargo tree -i rusqlite --features snow-core/tor`).
