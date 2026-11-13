//! Operator tool: offline signing of the remote config. Run on an offline
//! machine; the signing seed never touches the relay.
//!
//! ```text
//! snow-config keygen <seed-file>
//!     New Ed25519 seed (hex, mode 0600). Prints the public key to compile
//!     into the app (`Config::config_key`).
//! snow-config sign <seed-file> <template.json> <out> [--catalog FILE] [--days N]
//!     Fill issued_at / expires_at (default 30 days), the catalog hash, and —
//!     if TOKEN_MASTER is set in the environment — the token issuer keys for the
//!     current and next epoch, then sign. The template holds version, chaff_ms
//!     and features.
//! snow-config show <config.bin> <public-key-hex>
//!     Verify and print.
//! ```
use snow_config::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1)
}

fn read_seed(path: &str) -> [u8; 32] {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| die(e));
    let mut seed = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut seed).unwrap_or_else(|e| die(e));
    seed
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut out).unwrap_or_else(|e| die(e));
    out
}

#[derive(serde::Deserialize)]
struct Template {
    version: u64,
    chaff_ms: u32,
    #[serde(default)]
    features: Features,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 2 => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap_or_else(|e| die(e));
            let path = &args[1];
            if std::path::Path::new(path).exists() {
                die(format!("{path} exists; refusing to overwrite"));
            }
            write_private(path, hex::encode(seed).as_bytes());
            println!("{}", hex::encode(public_key(&signing_key(&seed))));
        }
        Some("sign") if args.len() >= 4 => {
            let key = signing_key(&read_seed(&args[1]));
            let t: Template =
                serde_json::from_slice(&std::fs::read(&args[2]).unwrap_or_else(|e| die(e)))
                    .unwrap_or_else(|e| die(e));
            let mut catalog = None;
            let mut days = 30u64;
            let mut it = args[4..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--catalog" => {
                        let raw = std::fs::read(it.next().unwrap_or_else(|| die("--catalog FILE")))
                            .unwrap_or_else(|e| die(e));
                        catalog = Some(CatalogRef {
                            sha256: Catalog::sha256(&raw),
                        });
                        let c = catalog.as_ref().expect("set");
                        Catalog::verify(&raw, c).unwrap_or_else(|e| die(format!("catalog: {e}")));
                    }
                    "--days" => {
                        days = it
                            .next()
                            .and_then(|d| d.parse().ok())
                            .unwrap_or_else(|| die("--days N"))
                    }
                    o => die(format!("unknown argument {o}")),
                }
            }
            let issued_at = now();
            let expires_at = issued_at + days * 86_400;
            if expires_at - issued_at > MAX_LIFETIME_SECS {
                die("lifetime too long");
            }
            let token_keys = match std::env::var("TOKEN_MASTER") {
                Ok(m) => token_keys(m.as_bytes(), issued_at, expires_at),
                Err(_) => {
                    eprintln!("note: TOKEN_MASTER not set; token keys not pinned");
                    Vec::new()
                }
            };
            let cfg = RemoteConfig {
                version: t.version,
                issued_at,
                expires_at,
                chaff_ms: t.chaff_ms,
                features: t.features,
                token_keys,
                catalog,
            };
            std::fs::write(&args[3], cfg.sign(&key)).unwrap_or_else(|e| die(e));
            println!("public key {}", hex::encode(public_key(&key)));
        }
        Some("show") if args.len() == 3 => {
            let bytes = std::fs::read(&args[1]).unwrap_or_else(|e| die(e));
            let cfg = RemoteConfig::verify(&bytes, &hex32(&args[2]), now(), 0)
                .unwrap_or_else(|e| die(e));
            println!("{}", serde_json::to_string_pretty(&cfg).expect("json"));
        }
        _ => die("usage: snow-config keygen SEED | sign SEED TEMPLATE OUT [--catalog F] [--days N] | show CONFIG PUBKEY"),
    }
}

/// Issuer keys for every token epoch the config's lifetime touches.
fn token_keys(master: &[u8], from: u64, to: u64) -> Vec<TokenKey> {
    use snow_tokens::{epoch, Issuer, Kind};
    let mut out = Vec::new();
    for e in epoch(from)..=epoch(to) {
        for (kind, k) in [(Kind::Good, TokenKind::Good), (Kind::Vip, TokenKind::Vip)] {
            let issuer = Issuer::new(master, kind, e).unwrap_or_else(|e| die(e));
            out.push(TokenKey {
                kind: k,
                epoch: e,
                key: issuer.public_key(),
            });
        }
    }
    out
}

fn write_private(path: &str, data: &[u8]) {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
        .and_then(|mut f| f.write_all(data))
        .unwrap_or_else(|e| die(e));
}
