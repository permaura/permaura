//! Connector layer for the gateway.
//!
//! This is now a thin re-export of the [`permaura_connectors`] crate, which is the
//! single source of truth for the `HttpClient` seam, the built-in connectors, the
//! `ConnectorRegistry`, and the request-shaping + redaction that turns an authorized
//! `(capability, params, secret)` into a redacted upstream result. The gateway used to
//! carry its own copy so it could compile and run offline; that copy has been collapsed
//! into the crate (whose `MockHttpClient` provides the same deterministic offline
//! behaviour), so `crate::connectors::*` paths continue to resolve unchanged.

pub use permaura_connectors::*;

/// The host a request to `base_url` reaches, written the way a browser's `new URL(base_url).host`
/// writes it (lowercase, punycode, a non-default port kept), so the phone, the console and the gateway
/// name one host the same way. `None` for a template or anything else that is not an absolute URL.
pub fn shown_host(base_url: &str) -> Option<String> {
    if base_url.contains('{') {
        return None;
    }
    let url = reqwest::Url::parse(base_url.trim()).ok()?;
    let host = url.host_str().filter(|h| !h.is_empty())?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// Where a connection of the `connector` family sends its credential: the one base URL every pinned
/// capability shares (`None` when nothing is pinned or they differ), and every distinct host they pin,
/// sorted. A capability whose URL the agent supplies, an SSH one and a command one pin nothing.
pub fn connection_pins(connector: &str, caps: &[Capability]) -> (Option<String>, Vec<String>) {
    let mut bases: Vec<String> = caps
        .iter()
        .filter_map(|cap| connector::pinned_base_url(connector, cap))
        .map(|base| base.trim_end_matches('/').to_string())
        .collect();
    bases.sort();
    bases.dedup();
    let mut hosts: Vec<String> = bases.iter().filter_map(|base| shown_host(base)).collect();
    hosts.sort();
    hosts.dedup();
    let base = match bases.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    };
    (base, hosts)
}
