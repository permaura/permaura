//! Outbound-egress guard for the connector HTTP layer.
//!
//! Every HTTP call a connector makes funnels through [`crate::http::ReqwestClient`], and
//! that is the one place an agent-supplied URL (the generic-HTTP proxy) can reach an
//! attacker-chosen host. SSH dials apply the same address rules through [`screen_resolved`]
//! only on a hosted worker (a self-run gateway dials whatever the pinned host resolves to), and
//! a command capability's CLI makes its own network calls, which this guard never sees.
//! Without a guard, a hosted Mode C worker (Cloud Run) would happily
//! fetch `http://169.254.169.254/…` and hand the GCP metadata server's service-account
//! token back to the agent (defeating the whole KMS-custody model) or be used as an
//! open egress proxy on Permaura's bill.
//!
//! This module is that guard. It is deliberately split into small pure functions
//! ([`screen_url`], [`is_blocked_ip`], [`is_blocked_host`], [`host_allowed`]) so the
//! classification logic is unit-testable with no network, plus a [`GuardedResolver`] that
//! re-checks every resolved address at connection time, closing the DNS-rebinding window
//! that a pre-flight string check alone would leave open.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Why an outbound request was refused before it ever left the worker.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EgressError {
    /// The URL used a scheme other than `http`/`https` (e.g. `file:`, `gopher:`, `ftp:`).
    #[error("egress blocked: scheme '{0}' is not allowed (only http/https)")]
    BadScheme(String),
    /// The URL could not be parsed into a scheme + host.
    #[error("egress blocked: '{0}' is not a valid absolute http(s) URL")]
    Unparseable(String),
    /// The host name is one we never route to (loopback alias, `*.internal`, metadata).
    #[error("egress blocked: host '{0}' is not permitted")]
    BlockedHost(String),
    /// The host is a literal IP in a disallowed range (private, loopback, link-local, …).
    #[error("egress blocked: address {0} is in a disallowed range")]
    BlockedAddress(IpAddr),
    /// A request carrying an injected credential was redirected off its own host, or from https to http.
    #[error("egress blocked: a request carrying a credential may not follow a redirect from {from} to {to}")]
    RedirectOffHost {
        /// The scheme and host the request was sent to.
        from: String,
        /// Where the redirect pointed.
        to: String,
    },
    /// The authority holds a backslash, control character or whitespace, which parsers disagree on.
    #[error("egress blocked: '{0}' has a backslash, control character or whitespace in its host part")]
    AmbiguousAuthority(String),
    /// A request carrying an injected credential named a plain `http` URL; a credential travels over TLS only.
    #[error("egress blocked: a request carrying a credential is sent over https only")]
    CredentialOverPlainHttp,
    /// A target that should be a bare host name or IP address (an SSH host) is something else.
    #[error("egress blocked: '{0}' is not a bare host name or IP address")]
    NotAHost(String),
    /// Every address the host resolved to is in a disallowed range.
    #[error("egress blocked: '{0}' resolves only to disallowed addresses")]
    NoPermittedAddress(String),
}

/// The scheme + host (+ optional port) extracted from a URL. The host has any IPv6 brackets,
/// userinfo, and port stripped, so it is ready for [`is_blocked_host`] / IP parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    /// Lower-cased scheme (`http` or `https`).
    pub scheme: String,
    /// Lower-cased host (a hostname or a bare IP literal, no brackets).
    pub host: String,
    /// The port, if the URL carried one other than its scheme's default.
    pub port: Option<u16>,
}

/// Parse `url` into scheme + host + port, rejecting anything that is not an absolute `http`/`https`
/// URL. See [`parse_checked`], which this wraps.
pub fn parse_url(url: &str) -> Result<UrlParts, EgressError> {
    parse_checked(url).map(|(_, parts)| parts)
}

/// The host a request to `url` actually reaches, or `None` when [`parse_url`] refuses it.
pub fn url_host(url: &str) -> Option<String> {
    parse_url(url).ok().map(|parts| parts.host)
}

/// Parse `url` with the same parser `reqwest` dispatches with (the `url` crate, re-exported as
/// [`reqwest::Url`]), so the host every allowlist and screen judges is the host the request connects to.
///
/// A hand-rolled split once read `https://attacker.example\@api.allowed.com/` as `api.allowed.com`
/// while `reqwest` connected to `attacker.example`, because WHATWG parsing ends the authority at a
/// backslash. The authority as RFC 3986 reads it (everything up to the first `/`, `?` or `#`) is also
/// refused outright when it holds a backslash, a control character or whitespace, so no two parsers can
/// disagree about which host such a URL names.
pub fn parse_checked(url: &str) -> Result<(reqwest::Url, UrlParts), EgressError> {
    let unparseable = || EgressError::Unparseable(without_secrets(url));
    let (scheme, rest) = url.split_once("://").ok_or_else(unparseable)?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return Err(unparseable());
    }
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(EgressError::BadScheme(scheme));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.chars().any(|c| c == '\\' || c.is_control() || c.is_whitespace()) {
        return Err(EgressError::AmbiguousAuthority(without_secrets(url)));
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| unparseable())?;
    if parsed.scheme() != scheme {
        return Err(unparseable());
    }
    // `host_str` brackets an IPv6 literal; every caller wants the bare address.
    let host = parsed
        .host_str()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .ok_or_else(unparseable)?;
    let port = parsed.port();
    Ok((parsed, UrlParts { scheme, host, port }))
}

/// Whether a request carrying an injected credential, first sent to `first`, may follow a redirect to
/// `next`: only within its own origin, the same host on the same port, and never from https down to
/// http. A credential in a header other than `Authorization` travels on any hop reqwest follows, so a
/// hop to another port on the same host would hand it to whatever listens there. The one scheme change
/// followed is the upgrade from http to https, both on their default ports.
pub fn check_pinned_hop(first: &str, next: &str) -> Result<(), EgressError> {
    let from = parse_url(first)?;
    let refused = |to: String| EgressError::RedirectOffHost { from: origin_of(&from), to };
    let to = parse_url(next).map_err(|_| refused(without_secrets(next)))?;
    let same_host = to.host.trim_end_matches('.') == from.host.trim_end_matches('.');
    let same_origin = to.scheme == from.scheme && to.port == from.port;
    let upgrade = from.scheme == "http" && to.scheme == "https" && from.port.is_none() && to.port.is_none();
    if !same_host || !(same_origin || upgrade) {
        return Err(refused(origin_of(&to)));
    }
    Ok(())
}

/// `scheme://host[:port]` of parsed parts, the port shown only when it is not the scheme's default.
fn origin_of(parts: &UrlParts) -> String {
    match parts.port {
        Some(port) => format!("{}://{}:{port}", parts.scheme, parts.host),
        None => format!("{}://{}", parts.scheme, parts.host),
    }
}

/// `text` with every URL-looking word passed through [`scrub_url`], for an error or a log line.
///
/// A connector URL can carry its credential in the query (`AuthScheme::ApiKeyQuery`) and a generic
/// HTTP URL is agent-supplied, so no text that might name one reaches an agent, a REST body or a log
/// without this.
pub fn scrub_urls(text: &str) -> String {
    text.split_whitespace().map(scrub_url).collect::<Vec<_>>().join(" ")
}

/// Drop the query, fragment and userinfo of a word that looks like a URL or a path, with or without a
/// scheme. Plain words pass through, so "what?" survives.
pub fn scrub_url(word: &str) -> std::borrow::Cow<'_, str> {
    if !word.contains("://") && !word.contains('/') {
        return std::borrow::Cow::Borrowed(word);
    }
    std::borrow::Cow::Owned(without_secrets(word))
}

/// `url` with its query, fragment and userinfo removed, whatever it looks like. For the URL an
/// [`EgressError`] names, which is a URL even when it is too malformed for [`scrub_url`] to see one.
fn without_secrets(url: &str) -> String {
    // Built from the parts that stay, so the query and the userinfo, where a credential sits, are never copied.
    let cut = url.find(['?', '#']);
    let kept = &url[..cut.unwrap_or(url.len())];
    let start = kept.find("://").map_or(0, |i| i + 3);
    let authority_end = kept[start..].find('/').map_or(kept.len(), |i| start + i);
    let host = kept[start..authority_end].rfind('@').map_or(start, |at| start + at + 1);
    let mut out = String::with_capacity(start + (kept.len() - host) + "?…".len());
    out.push_str(&kept[..start]);
    out.push_str(&kept[host..]);
    if cut.is_some() {
        out.push_str("?…");
    }
    out
}

/// Screen an agent-supplied (or connector-built) URL before it is dispatched: reject
/// non-http(s) schemes, never-route host names, and IP-literal hosts in disallowed ranges.
///
/// This catches IP-literal SSRF (`http://169.254.169.254/…`) which the [`GuardedResolver`]
/// cannot: reqwest connects straight to a literal IP without ever consulting a DNS resolver.
/// Hostname targets are additionally re-screened by the resolver after DNS resolution.
pub fn screen_url(url: &str) -> Result<(), EgressError> {
    screened_url(url).map(|_| ())
}

/// [`screen_url`], returning the parsed URL it judged so the caller can dispatch exactly that URL
/// rather than handing the string to a second parse.
pub fn screened_url(url: &str) -> Result<reqwest::Url, EgressError> {
    let (parsed, parts) = parse_checked(url)?;
    if is_blocked_host(&parts.host) {
        return Err(EgressError::BlockedHost(parts.host));
    }
    if let Ok(ip) = parts.host.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(EgressError::BlockedAddress(ip));
        }
    }
    Ok(parsed)
}

/// Screen a bare host, an SSH target's name or IP literal with no scheme, port or path, by the rules
/// [`screened_url`] applies to a URL's host: the never-route names, and an address in a disallowed range
/// however it is spelled (`2130706433` and `0x7f.1` are loopback to the system resolver as well).
///
/// A name passes on its spelling alone; [`screen_resolved`] judges what it resolves to at connect time.
pub fn screen_host(host: &str) -> Result<(), EgressError> {
    let not_a_host = || EgressError::NotAHost(host.to_string());
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .filter(|h| h.parse::<Ipv6Addr>().is_ok())
        .unwrap_or(host);
    let authority = match bare.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => format!("[{v6}]"),
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Err(_) if !bare.is_empty() && bare.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) => {
            bare.to_string()
        }
        Err(_) => return Err(not_a_host()),
    };
    match screened_url(&format!("https://{authority}/")) {
        Ok(_) => Ok(()),
        Err(EgressError::Unparseable(_)) => Err(not_a_host()),
        Err(e) => Err(e),
    }
}

/// The addresses `host` resolved to that a worker may connect to, or [`EgressError::NoPermittedAddress`]
/// when none is left. The one rule the HTTP [`GuardedResolver`] and an SSH dial both apply, and the
/// connection then goes to exactly these addresses, so nothing re-resolves between the check and the connect.
pub fn screen_resolved(host: &str, resolved: impl IntoIterator<Item = SocketAddr>) -> Result<Vec<SocketAddr>, EgressError> {
    let safe: Vec<SocketAddr> = resolved.into_iter().filter(|addr| !is_blocked_ip(addr.ip())).collect();
    if safe.is_empty() {
        return Err(EgressError::NoPermittedAddress(host.to_string()));
    }
    Ok(safe)
}

/// Host names we refuse outright, regardless of what they resolve to: the loopback alias and
/// the internal/metadata names cloud platforms expose. The numeric metadata address
/// (169.254.169.254) is caught by [`is_blocked_ip`]; this blocks the friendlier aliases too.
pub fn is_blocked_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "metadata"
        || host == "metadata.google.internal"
        || host.ends_with(".internal")
}

/// True if `ip` is in a range a worker must never reach. IPv4: loopback, RFC-1918 private
/// space, link-local (169.254/16, the cloud metadata range), CGNAT, multicast, broadcast,
/// documentation, benchmarking, reserved, 192.0.0.0/24 and 0.0.0.0/8. IPv6: loopback,
/// unspecified, multicast, unique-local and link-local, with IPv4-mapped, IPv4-compatible and
/// NAT64 (`64:ff9b::/96`) addresses unwrapped and the embedded IPv4 re-checked so
/// `::ffff:169.254.169.254` cannot slip through. Other IPv6 ranges are not blocked, including
/// 6to4 (`2002::/16`), Teredo (`2001::/32`), the local-use NAT64 prefix (`64:ff9b:1::/48`),
/// documentation (`2001:db8::/32`) and the deprecated site-local `fec0::/10`.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _c, _d] = ip.octets();
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254.0.0/16: the cloud metadata range
        || ip.is_unspecified()  // 0.0.0.0
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_documentation()
        || ip.is_multicast()    // 224.0.0.0/4
        || (a == 0)             // "this network" 0.0.0.0/8
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 CGNAT shared
        || (a == 192 && b == 0 && _c == 0)       // 192.0.0.0/24 IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19))    // 198.18.0.0/15 benchmarking
        || (a >= 240) // 240.0.0.0/4 reserved (and 255.* broadcast)
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(v4);
    }
    // NAT64's well-known prefix (64:ff9b::/96, RFC 6052) reaches the IPv4 address in its last 32 bits.
    let seg = ip.segments();
    if seg[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        let o = ip.octets();
        if is_blocked_ipv4(Ipv4Addr::new(o[12], o[13], o[14], o[15])) {
            return true;
        }
    }
    // `to_ipv4` also maps the deprecated IPv4-compatible form (::a.b.c.d); re-check that too,
    // but never treat genuine global v6 (whose high bits make to_ipv4 None) as v4.
    if let Some(v4) = ip.to_ipv4() {
        if is_blocked_ipv4(v4) {
            return true;
        }
    }
    let seg0 = ip.segments()[0];
    ip.is_loopback()                  // ::1
        || ip.is_unspecified()        // ::
        || ip.is_multicast()          // ff00::/8
        || (seg0 & 0xfe00) == 0xfc00  // fc00::/7 unique-local
        || (seg0 & 0xffc0) == 0xfe80  // fe80::/10 link-local
}

/// True if `host` matches the operator's allowlist. Matching is case-insensitive and supports
/// a leading `*.`/`.` wildcard for subdomains (e.g. `*.example.com` matches `api.example.com`
/// but not the bare `example.com`).
pub fn host_allowed(host: &str, allowlist: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allowlist.iter().any(|entry| {
        let entry = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(suffix) = entry.strip_prefix("*.").or_else(|| entry.strip_prefix('.')) {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == entry
        }
    })
}

/// Remove any agent-supplied `Metadata-Flavor` header (case-insensitive). Cloud metadata
/// servers require this header on requests; stripping it is belt-and-braces alongside the
/// IP/host blocks, so an agent cannot pre-set it hoping a future code path forwards it.
pub fn strip_metadata_headers(headers: &mut std::collections::BTreeMap<String, String>) {
    headers.retain(|name, _| !name.eq_ignore_ascii_case("metadata-flavor"));
}

/// A [`reqwest`] DNS resolver that rejects disallowed host names and filters every resolved
/// address through [`is_blocked_ip`], returning only public-unicast addresses. Because the
/// connection then uses exactly the addresses this resolver returned, a DNS-rebinding attacker
/// cannot swap in a private address between a pre-flight check and the actual connect: there
/// is only one resolution, and it is the validated one.
#[derive(Debug, Clone, Default)]
pub struct GuardedResolver;

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            if is_blocked_host(&host) {
                return Err(format!("egress blocked: host '{host}' is not permitted").into());
            }
            let resolved = tokio::net::lookup_host((host.as_str(), 0u16)).await?;
            let safe = screen_resolved(&host, resolved)?;
            Ok(Box::new(safe.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAT64 (64:ff9b::/96) carries an IPv4 address in its last 32 bits, and a network that routes the
    /// prefix reaches that address: the metadata server among them.
    #[test]
    fn a_nat64_address_is_judged_by_the_ipv4_address_it_carries() {
        assert!(is_blocked_ip("64:ff9b::a9fe:a9fe".parse().unwrap()), "169.254.169.254 through NAT64");
        assert!(is_blocked_ip("64:ff9b::a00:5".parse().unwrap()), "10.0.0.5 through NAT64");
        assert!(screen_url("http://[64:ff9b::a9fe:a9fe]/latest/meta-data/").is_err());
        assert!(!is_blocked_ip("64:ff9b::808:808".parse().unwrap()), "8.8.8.8 through NAT64 is public");
    }

    /// A refusal names the URL it refused, and a connector URL can carry its key in the query.
    #[test]
    fn a_refused_url_is_named_without_its_query_or_userinfo() {
        for url in [
            "https://api.example\\@other.example/x?api_key=sk_canary",
            "notaurl?api_key=sk_canary",
            "https://user:sk_canary@api.example\\x/?q=1",
        ] {
            let text = parse_url(url).unwrap_err().to_string();
            assert!(!text.contains("sk_canary"), "{url}: {text}");
        }
        let hop = check_pinned_hop("https://api.example/x", "ftp://elsewhere/y?api_key=sk_canary").unwrap_err();
        assert!(!hop.to_string().contains("sk_canary"), "{hop}");
        let scrubbed = scrub_urls("error sending request for url (https://u:sk_canary@api.example/v1?api_key=sk_canary#f)");
        assert!(!scrubbed.contains("sk_canary"), "{scrubbed}");
        assert!(scrubbed.contains("https://api.example/v1?"), "{scrubbed}");
    }

    /// An SSH host is screened by the rules a URL host is, however it is spelled, and
    /// anything that is not a bare name or address is refused rather than read.
    #[test]
    fn a_bare_host_is_screened_by_the_url_host_rules() {
        for host in [
            "169.254.169.254", "metadata.google.internal", "metadata", "127.0.0.1", "2130706433", "0x7f.1", "127.1",
            "[::1]", "::1", "::ffff:169.254.169.254", "localhost", "LOCALHOST.", "10.0.0.1", "192.168.1.20", "fd00::1",
        ] {
            assert!(matches!(screen_host(host), Err(EgressError::BlockedHost(_) | EgressError::BlockedAddress(_))), "{host}");
        }
        for host in [
            "", "a b", "user@ssh.example.com", "ssh.example.com/x", "ssh.example.com:22", "ssh.example.com\\@10.0.0.1",
            "b\u{fc}cher.example", "[ssh.example.com]",
        ] {
            assert!(matches!(screen_host(host), Err(EgressError::NotAHost(_))), "{host:?}");
        }
        for host in ["ssh.example.com", "140.82.112.3", "2606:4700:4700::1111", "[2606:4700:4700::1111]", "box_1.example.com"] {
            assert_eq!(screen_host(host), Ok(()), "{host}");
        }
    }

    #[test]
    fn a_resolution_keeps_its_public_addresses_only() {
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(
            screen_resolved("mixed.example", [addr("10.0.0.1:22"), addr("140.82.112.3:22")]),
            Ok(vec![addr("140.82.112.3:22")])
        );
        assert_eq!(
            screen_resolved("rebind.example", [addr("169.254.169.254:22"), addr("[::1]:22")]),
            Err(EgressError::NoPermittedAddress("rebind.example".into()))
        );
    }

    #[test]
    fn blocks_the_gcp_metadata_address() {
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        // The IPv4-mapped form must not slip through.
        assert!(is_blocked_ip("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn blocks_private_loopback_and_friends() {
        for ip in [
            "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "0.0.0.0",
            "100.64.0.1", "198.18.0.1", "169.254.0.1", "::1", "fc00::1", "fe80::1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
    }

    #[test]
    fn allows_ordinary_public_addresses() {
        for ip in ["8.8.8.8", "1.1.1.1", "140.82.112.3", "2606:4700:4700::1111"] {
            assert!(!is_blocked_ip(ip.parse().unwrap()), "{ip} should be allowed");
        }
    }

    #[test]
    fn screen_url_rejects_non_http_schemes() {
        assert_eq!(
            screen_url("file:///etc/passwd"),
            Err(EgressError::BadScheme("file".into()))
        );
        assert!(matches!(screen_url("gopher://x/"), Err(EgressError::BadScheme(_))));
        assert!(matches!(screen_url("notaurl"), Err(EgressError::Unparseable(_))));
    }

    #[test]
    fn screen_url_rejects_metadata_and_private_literals() {
        assert!(matches!(
            screen_url("http://169.254.169.254/computeMetadata/v1/"),
            Err(EgressError::BlockedAddress(_))
        ));
        assert!(matches!(
            screen_url("http://10.0.0.5:8080/admin"),
            Err(EgressError::BlockedAddress(_))
        ));
        assert!(matches!(
            screen_url("http://[::1]:9000/"),
            Err(EgressError::BlockedAddress(_))
        ));
        assert!(matches!(
            screen_url("http://metadata.google.internal/"),
            Err(EgressError::BlockedHost(_))
        ));
        // userinfo trick: the real host is the metadata IP.
        assert!(matches!(
            screen_url("http://trusted.example.com@169.254.169.254/"),
            Err(EgressError::BlockedAddress(_))
        ));
    }

    #[test]
    fn screen_url_allows_public_hosts() {
        assert_eq!(screen_url("https://api.github.com/repos/x/y"), Ok(()));
        assert_eq!(screen_url("https://example.com:8443/path?q=1"), Ok(()));
    }

    /// WHATWG parsing (the `url` crate `reqwest` uses) ends the authority at `\\`, so this URL
    /// connects to `attacker.example`. It must never read as the allowlisted host.
    #[test]
    fn backslash_authority_is_refused_rather_than_misread() {
        let url = "https://attacker.example\\@api.allowed.com/v1/data";
        assert_eq!(
            reqwest::Url::parse(url).unwrap().host_str(),
            Some("attacker.example"),
            "the parser reqwest dispatches with reads the attacker host"
        );
        assert!(matches!(parse_url(url), Err(EgressError::AmbiguousAuthority(_))));
        assert!(matches!(screen_url(url), Err(EgressError::AmbiguousAuthority(_))));
        for url in [
            "https://api.allowed.com\\@attacker.example/",
            "https://attacker.example\\@x.allowed.com/",
            "https://api.allowed.com\\path",
            "https://api.allowed.com\t.attacker.example/",
            "https://api.allowed.com .attacker.example/",
            "https://attacker.example\n@api.allowed.com/",
            " https://api.allowed.com/",
        ] {
            assert!(parse_url(url).is_err(), "{url:?} must be refused");
        }
    }

    /// Whatever host this module reports is the host `reqwest` would connect to, for every input it
    /// accepts. A differential check against the dispatching parser, over the shapes that have split
    /// hand-rolled parsers before.
    #[test]
    fn reported_host_is_the_host_reqwest_connects_to() {
        for url in [
            "https://api.allowed.com/v1",
            "https://user:pass@api.allowed.com:8443/p?q=1#f",
            "https://attacker.example/@api.allowed.com/",
            "https://attacker.example?@api.allowed.com/",
            "https://attacker.example#@api.allowed.com/",
            "https://a@b@api.allowed.com/",
            "https://api.allowed.com%2eattacker.example/",
            "https://API.Allowed.COM./",
            "http://[::ffff:a9fe:a9fe]/",
            "http://2130706433/",
            "http://0x7f.1/",
        ] {
            let ours = parse_url(url).map(|p| p.host);
            let theirs = reqwest::Url::parse(url).ok().and_then(|u| {
                u.host_str().map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
            });
            match ours {
                Ok(h) => assert_eq!(Some(h), theirs, "{url:?}"),
                Err(e) => assert!(theirs.is_none() || matches!(e, EgressError::AmbiguousAuthority(_)), "{url:?}: {e}"),
            }
        }
    }

    /// The old split read `2130706433` as a host name, so the IP screen never saw the loopback address
    /// `reqwest` then connected to directly, with no resolver in the way.
    #[test]
    fn numeric_ipv4_spellings_are_screened_as_the_address_they_name() {
        for url in ["http://2130706433/", "http://0x7f.1/", "http://127.1/", "http://0251.0376.0251.0376/"] {
            assert!(matches!(screen_url(url), Err(EgressError::BlockedAddress(_))), "{url}");
        }
    }

    /// A credentialed request follows a redirect only within its own origin (host and port), never down to http; the one scheme change it follows is the upgrade from http to https on the default ports.
    #[test]
    fn a_credentialed_redirect_stays_on_its_host() {
        let first = "https://api.allowed.com/v1/x";
        assert_eq!(check_pinned_hop(first, "https://api.allowed.com/v2/x"), Ok(()));
        assert_eq!(check_pinned_hop(first, "https://API.allowed.com:443/y"), Ok(()));
        assert_eq!(check_pinned_hop("https://api.allowed.com:8443/", "https://api.allowed.com:8443/y"), Ok(()));
        assert_eq!(check_pinned_hop("http://api.allowed.com/", "https://api.allowed.com/"), Ok(()));
        for (first, next) in [
            (first, "https://attacker.example/"),
            (first, "https://cdn.allowed.com/"),
            (first, "http://api.allowed.com/v1/x"),
            (first, "http://api.allowed.com:443/v1/x"),
            (first, "https://api.allowed.com.attacker.example/"),
            (first, "https://attacker.example\\@api.allowed.com/"),
            (first, "https://api.allowed.com:8443/y"),
            ("https://api.allowed.com:8443/", "https://api.allowed.com/y"),
            ("http://api.allowed.com/", "http://api.allowed.com:8080/"),
            ("http://api.allowed.com:8080/", "https://api.allowed.com/"),
        ] {
            assert!(
                matches!(check_pinned_hop(first, next), Err(EgressError::RedirectOffHost { .. })),
                "{next} must be refused"
            );
        }
    }

    #[test]
    fn host_allowlist_exact_and_wildcard() {
        let allow = vec!["api.example.com".to_string(), "*.trusted.dev".to_string()];
        assert!(host_allowed("api.example.com", &allow));
        assert!(host_allowed("API.EXAMPLE.COM", &allow));
        assert!(host_allowed("a.trusted.dev", &allow));
        assert!(!host_allowed("trusted.dev", &allow)); // bare apex not matched by *.
        assert!(!host_allowed("evil.com", &allow));
        assert!(!host_allowed("api.example.com.evil.com", &allow));
    }

    #[test]
    fn strips_metadata_flavor_header_case_insensitively() {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("Metadata-Flavor".to_string(), "Google".to_string());
        headers.insert("metadata-flavor".to_string(), "Google".to_string());
        headers.insert("Authorization".to_string(), "Bearer x".to_string());
        strip_metadata_headers(&mut headers);
        assert!(!headers.keys().any(|k| k.eq_ignore_ascii_case("metadata-flavor")));
        assert!(headers.contains_key("Authorization"));
    }
}
