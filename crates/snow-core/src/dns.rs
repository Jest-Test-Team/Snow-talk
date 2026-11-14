//! DNS over HTTPS (RFC 8484, wire format) to Cloudflare's resolver, reached by
//! fixed IP so the OS resolver and the ISP never see the relay's hostname.
//! Also fetches the HTTPS record so TLS can use Encrypted Client Hello.
use crate::net::{Dialer, Endpoint, NetError};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::IpAddr;

const DOH_HOST: &str = "cloudflare-dns.com";
const DOH_ADDRS: [&str; 3] = ["1.1.1.1:443", "1.0.0.1:443", "[2606:4700:4700::1111]:443"];

#[derive(Debug, Default, Clone)]
pub struct Resolved {
    pub addrs: Vec<IpAddr>,
    /// Raw `ECHConfigList` from the HTTPS record's `ech` parameter.
    pub ech: Option<Vec<u8>>,
}

fn doh_endpoint(dialer: &Dialer) -> Result<Endpoint, NetError> {
    // Direct: dial the resolver by fixed IP. Tor: let the exit resolve its name.
    let addrs = if dialer.is_proxied() {
        Vec::new()
    } else {
        DOH_ADDRS
            .iter()
            .map(|a| a.parse().expect("static addr"))
            .collect()
    };
    let tls = crate::net::tls_config(&[], None)?;
    Ok(Endpoint {
        host: DOH_HOST.into(),
        port: 443,
        addrs,
        tls: Some(std::sync::Arc::new(tls)),
    })
}

pub async fn resolve(dialer: &Dialer, host: &str) -> Result<Resolved, NetError> {
    let ep = doh_endpoint(dialer)?;
    let (a, aaaa, https) = tokio::join!(
        query(dialer, &ep, host, RecordType::A),
        query(dialer, &ep, host, RecordType::AAAA),
        query(dialer, &ep, host, RecordType::HTTPS),
    );
    let mut out = Resolved::default();
    for m in [a, aaaa].into_iter().flatten() {
        out.addrs
            .extend(m.answers.iter().filter_map(|r| r.data.ip_addr()));
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
        return Err(NetError::Io(format!("DoH: no address for {host}")));
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
