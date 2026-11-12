//! DNS over HTTPS (RFC 8484, wire format) to Cloudflare's resolver, reached by
//! fixed IP so the OS resolver and the ISP never see the relay's hostname.
//! Also fetches the HTTPS record so TLS can use Encrypted Client Hello.
use crate::net::NetError;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{IpAddr, SocketAddr};

const DOH_HOST: &str = "cloudflare-dns.com";
const DOH_ADDRS: [&str; 3] = ["1.1.1.1:443", "1.0.0.1:443", "[2606:4700:4700::1111]:443"];

#[derive(Debug, Default, Clone)]
pub struct Resolved {
    pub addrs: Vec<IpAddr>,
    /// Raw `ECHConfigList` from the HTTPS record's `ech` parameter.
    pub ech: Option<Vec<u8>>,
}

pub fn doh_client(tls: rustls::ClientConfig) -> reqwest::Client {
    let addrs: Vec<SocketAddr> = DOH_ADDRS
        .iter()
        .map(|a| a.parse().expect("static addr"))
        .collect();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .resolve_to_addrs(DOH_HOST, &addrs)
        .user_agent("snowtalk")
        .build()
        .expect("doh client")
}

pub async fn resolve(doh: &reqwest::Client, host: &str) -> Result<Resolved, NetError> {
    let (a, aaaa, https) = tokio::join!(
        query(doh, host, RecordType::A),
        query(doh, host, RecordType::AAAA),
        query(doh, host, RecordType::HTTPS),
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

async fn query(doh: &reqwest::Client, host: &str, rt: RecordType) -> Result<Message, NetError> {
    let io = |e: &dyn std::fmt::Display| NetError::Io(format!("DoH: {e}"));
    // RFC 8484 §4.1: id 0 for cache friendliness.
    let mut m = Message::new(0, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_ascii(host).map_err(|e| io(&e))?,
        rt,
    ));
    let body = m.to_vec().map_err(|e| io(&e))?;
    let resp = doh
        .post(format!("https://{DOH_HOST}/dns-query"))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(body)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| io(&e))?;
    let bytes = resp.bytes().await.map_err(|e| io(&e))?;
    Message::from_vec(&bytes).map_err(|e| io(&e))
}
