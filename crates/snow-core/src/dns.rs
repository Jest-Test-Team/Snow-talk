//! DNS over HTTPS (RFC 8484, wire format), reached by fixed IP so the OS
//! resolver and the ISP never see the relay's hostname. Also fetches the HTTPS
//! record so TLS can use Encrypted Client Hello.
//!
//! Some networks block one resolver or another (a phone failed with Cloudflare
//! alone), so providers are tried in turn, each with a time limit, and the real
//! errors are reported.
use crate::net::{Dialer, Endpoint, NetError};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::IpAddr;

struct Provider {
    host: &'static str,
    addrs: [&'static str; 3],
}

const PROVIDERS: [Provider; 3] = [
    Provider {
        host: "cloudflare-dns.com",
        addrs: ["1.1.1.1:443", "1.0.0.1:443", "[2606:4700:4700::1111]:443"],
    },
    Provider {
        host: "dns.google",
        addrs: ["8.8.8.8:443", "8.8.4.4:443", "[2001:4860:4860::8888]:443"],
    },
    // Unfiltered AdGuard. (Quad9 answers HTTP/1.1 with 505, and our client is
    // HTTP/1.1 only.)
    Provider {
        host: "unfiltered.adguard-dns.com",
        addrs: [
            "94.140.14.140:443",
            "94.140.14.141:443",
            "[2a10:50c0::1:ff]:443",
        ],
    },
];

/// Per provider, all three queries together.
const PROVIDER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

#[derive(Debug, Default, Clone)]
pub struct Resolved {
    pub addrs: Vec<IpAddr>,
    /// Raw `ECHConfigList` from the HTTPS record's `ech` parameter.
    pub ech: Option<Vec<u8>>,
}

fn doh_endpoint(dialer: &Dialer, p: &Provider) -> Result<Endpoint, NetError> {
    // Direct: dial the resolver by fixed IP. Tor: let the exit resolve its name.
    let addrs = if dialer.is_proxied() {
        Vec::new()
    } else {
        p.addrs
            .iter()
            .map(|a| a.parse().expect("static addr"))
            .collect()
    };
    let tls = crate::net::tls_config(&[], None)?;
    Ok(Endpoint {
        host: p.host.into(),
        port: 443,
        addrs,
        tls: Some(std::sync::Arc::new(tls)),
    })
}

/// Resolve via the first DoH provider that answers.
pub async fn resolve(dialer: &Dialer, host: &str) -> Result<Resolved, NetError> {
    let mut errors = Vec::new();
    for p in &PROVIDERS {
        match tokio::time::timeout(PROVIDER_TIMEOUT, resolve_with(dialer, p, host)).await {
            Ok(Ok(r)) => return Ok(r),
            Ok(Err(e)) => errors.push(format!("{}: {e}", p.host)),
            Err(_) => errors.push(format!("{}: timed out", p.host)),
        }
    }
    Err(NetError::Io(format!("DoH failed ({})", errors.join("; "))))
}

async fn resolve_with(dialer: &Dialer, p: &Provider, host: &str) -> Result<Resolved, NetError> {
    let ep = doh_endpoint(dialer, p)?;
    let (a, aaaa, https) = tokio::join!(
        query(dialer, &ep, host, RecordType::A),
        query(dialer, &ep, host, RecordType::AAAA),
        query(dialer, &ep, host, RecordType::HTTPS),
    );
    let mut out = Resolved::default();
    let mut first_err = None;
    for m in [a, aaaa] {
        match m {
            Ok(m) => out
                .addrs
                .extend(m.answers.iter().filter_map(|r| r.data.ip_addr())),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    if let Ok(m) = https {
        out.ech = m.answers.iter().find_map(|r| match &r.data {
            RData::HTTPS(h) => h.0.svc_params.iter().find_map(|(_, v)| match v {
                SvcParamValue::EchConfigList(e) => Some(e.0.clone()),
                _ => None,
            }),
            _ => None,
        });
    }
    if out.addrs.is_empty() {
        return Err(first_err.unwrap_or_else(|| NetError::Io(format!("no address for {host}"))));
    }
    Ok(out)
}

async fn query(
    dialer: &Dialer,
    ep: &Endpoint,
    host: &str,
    rt: RecordType,
) -> Result<Message, NetError> {
    let io = |e: &dyn std::fmt::Display| NetError::Io(format!("DoH: {e}"));
    // RFC 8484 §4.1: id 0 for cache friendliness.
    let mut m = Message::new(0, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_ascii(host).map_err(|e| io(&e))?,
        rt,
    ));
    let body = m.to_vec().map_err(|e| io(&e))?;
    let hdrs = [
        ("content-type", "application/dns-message"),
        ("accept", "application/dns-message"),
    ];
    let (status, bytes) =
        crate::http::request(dialer, ep, "POST", "/dns-query", &hdrs, &body).await?;
    if status != 200 {
        return Err(NetError::Io(format!("DoH: HTTP {status}")));
    }
    Message::from_vec(&bytes).map_err(|e| io(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs the internet: `cargo test -p snow-core every_provider -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn every_provider_resolves_the_relay() {
        for p in &PROVIDERS {
            let r = resolve_with(&Dialer::Direct, p, "snow-talk.pcleegood.workers.dev")
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", p.host));
            assert!(!r.addrs.is_empty(), "{}", p.host);
            assert!(r.ech.is_some(), "{}: no ECH config", p.host);
        }
    }
}
