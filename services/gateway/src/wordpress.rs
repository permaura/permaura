//! WordPress sites as a connection source: find a site's REST index, derive capabilities from it, and
//! read the Abilities API as a second source once a credential is sealed.
//!
//! WordPress describes its own API at the REST index (`/wp-json/`): every route, its methods and each
//! argument, plugin routes included. That makes a WordPress importer the same shape as the OpenAPI
//! one with a different document. Everything here is derived once, shown to the operator and stored;
//! nothing re-reads the index at call time, and a later read is a re-sync that returns a diff.
//!
//! Two rules hold everywhere in this module. Only the host the operator entered is ever probed, and a
//! canonical REST root naming another host is refused (a bare `www.` difference aside). And risk only
//! escalates: [`crate::openapi::classify`] runs unchanged, then a raise-only pass here may make a
//! capability riskier and never safer. That pass reads the site's own words (route names, an
//! ability's name and annotations), which the site being governed writes, so none of them can lower
//! what the method gives: an ability annotated `readonly` is sent as the `GET` WordPress demands for
//! it, with the posture it would have unannotated.

use std::collections::{BTreeMap, BTreeSet};

use permaura_core::{Action, RiskTier};
use reqwest::Url;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::connectors::{
    compile_path_pattern, AuthScheme, Capability, CapabilityKind, HttpClient, HttpMethod, HttpRequest, HttpSpec, PathPattern,
    QueryStyle,
};
use crate::error::GatewayError;
use crate::openapi::classify;

/// Response fields redacted on every call through a WordPress connection, on top of the gateway's
/// defaults. `wp/v2/users?context=edit` returns email addresses, and bbPress replies carry the
/// author's IP and user agent.
pub const DEFAULT_REDACT_FIELDS: [&str; 7] =
    ["email", "user_email", "author_email", "author_ip", "author_user_agent", "ip", "ip_address"];

/// The Abilities API listing, relative to the REST root.
const ABILITIES_ROUTE: &str = "/wp-abilities/v1/abilities";

/// The page size the Abilities listing is read with; a shorter page is the last one.
pub const ABILITIES_PAGE_SIZE: usize = 100;

/// A backstop on the Abilities pagination, so a site that never returns a short page cannot keep the
/// gateway reading forever.
pub const ABILITIES_MAX_PAGES: u32 = 50;

/// The most routes one index route may split into. A route with several enum groups multiplies.
const MAX_SPLIT: usize = 64;

/// Words that make a mutating REST call Critical plus approval wherever they appear in its path.
const RISKY_WORDS: &[&str] =
    &["trash", "delete", "spam", "merge", "split", "destroy", "purge", "remove", "ban", "block"];

/// Money and destruction words from the MCP annotation table, which an
/// ability's name is also checked against.
const ABILITY_RISKY_WORDS: &[&str] = &["refund", "charge", "capture", "payout", "transfer", "drop"];

/// Path segments under which any write is Critical plus approval: they change who can do what.
const SENSITIVE_SEGMENTS: &[&str] =
    &["users", "plugins", "themes", "settings", "roles", "application-passwords"];

// ── Where a site's REST API is pinned ───────────────────────────────────────────

/// How a site's REST routes are addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routing {
    /// Pretty permalinks: the route is appended to the REST root (`/wp-json/bbpress/v1/topics`).
    Pretty,
    /// Plain permalinks: the route travels as `?rest_route=` on the site home.
    Query,
}

impl Routing {
    /// The wire name, `pretty` or `query`.
    pub fn as_str(self) -> &'static str {
        match self {
            Routing::Pretty => "pretty",
            Routing::Query => "query",
        }
    }
}

/// Where a site's REST API is pinned, derived from the index's own canonical links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestPin {
    /// How routes are addressed.
    pub routing: Routing,
    /// Pretty: the REST root without its trailing slash. Query: the site home without its trailing slash.
    root: String,
}

impl RestPin {
    /// The REST root as recorded on a connection and shown to the operator.
    pub fn rest_root(&self) -> String {
        match self.routing {
            Routing::Pretty => self.root.clone(),
            Routing::Query => format!("{}/?rest_route=/", self.root),
        }
    }

    /// The `base_url` pinned into each capability, for a path that is a full route.
    pub fn base_url(&self) -> String {
        match self.routing {
            Routing::Pretty => self.root.clone(),
            Routing::Query => format!("{}/", self.root),
        }
    }

    /// The query parameter the route travels as, when it does not travel in the path.
    pub fn route_param(&self) -> Option<String> {
        match self.routing {
            Routing::Pretty => None,
            Routing::Query => Some("rest_route".to_string()),
        }
    }

    /// The inverse of [`Self::rest_root`], for a connection's stored source.
    pub fn from_rest_root(rest_root: &str) -> Option<Self> {
        if rest_root.is_empty() {
            return None;
        }
        Some(match rest_root.strip_suffix("/?rest_route=/") {
            Some(home) => RestPin { routing: Routing::Query, root: home.to_string() },
            None => RestPin { routing: Routing::Pretty, root: rest_root.trim_end_matches('/').to_string() },
        })
    }

    /// How a preset whose paths are relative to `namespace` is pinned: `(base_url, route_param,
    /// path_prefix)`. Pretty routing folds the namespace into the base URL; query routing cannot, so
    /// the namespace moves onto the front of every path.
    pub fn preset_pin(&self, namespace: &str) -> (String, Option<String>, Option<String>) {
        let namespace = namespace.trim_matches('/');
        match self.routing {
            Routing::Pretty => (format!("{}/{namespace}", self.root), None, None),
            Routing::Query => (self.base_url(), self.route_param(), Some(format!("/{namespace}"))),
        }
    }
}

// ── Discovery ────────────────────────────────────────────────────────────────

/// A WordPress site whose REST index was found and whose canonical root passed the host rule.
#[derive(Debug, Clone)]
pub struct Site {
    /// The URL the operator entered, normalized (no trailing slash).
    pub site_url: String,
    /// Where the REST API is pinned.
    pub pin: RestPin,
    /// The site title from the index.
    pub name: String,
    /// The site tagline from the index.
    pub description: String,
    /// The REST index as fetched.
    pub index: Value,
}

/// The outcome of probing a URL for a WordPress REST index.
#[derive(Debug)]
pub enum Discovery {
    /// A REST index was found.
    Found(Box<Site>),
    /// Nothing answered like a WordPress REST index.
    NotFound {
        /// Every URL requested, in order.
        tried: Vec<String>,
        /// Requests that failed before any response came back, as `(url, error)`.
        errors: Vec<(String, String)>,
    },
}

/// Normalize and validate an operator-entered site URL: absolute https, a host, no userinfo, no query
/// and no fragment. The result carries no trailing slash.
pub fn parse_site_url(raw: &str) -> Result<Url, String> {
    let raw = raw.trim();
    let url = Url::parse(raw).map_err(|e| format!("url '{raw}' is not a valid absolute URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("url '{raw}' must be an https:// URL"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(format!("url '{raw}' has no host"));
    }
    if crate::connectors::url_host(raw).is_none() {
        return Err(format!("url '{raw}' has a backslash or a control character where its host is read"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("url '{raw}' must not contain userinfo (user:pass@host)"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("url '{raw}' must not contain a query string or fragment"));
    }
    Ok(url)
}

fn trimmed(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_string()
}

/// Two hosts are the same site when they are equal or differ only by a leading `www.`.
fn same_site_host(a: &str, b: &str) -> bool {
    let bare = |h: &str| {
        let h = h.to_ascii_lowercase();
        h.strip_prefix("www.").map(str::to_string).unwrap_or(h)
    };
    bare(a) == bare(b)
}

/// Whether `candidate` may be pinned for a site the operator entered as `site`: https, no userinfo,
/// no fragment, the same host (a bare `www.` difference allowed) and the same port.
fn check_bound(candidate: &Url, site: &Url, what: &str) -> Result<(), String> {
    let shown = candidate.as_str();
    if candidate.scheme() != "https" {
        return Err(format!("the site's {what} is {shown}, which is not https: refused"));
    }
    if !candidate.username().is_empty() || candidate.password().is_some() || candidate.fragment().is_some() {
        return Err(format!("the site's {what} {shown} carries userinfo or a fragment: refused"));
    }
    let host = candidate.host_str().unwrap_or_default();
    let site_host = site.host_str().unwrap_or_default();
    if !same_site_host(host, site_host) || candidate.port_or_known_default() != site.port_or_known_default() {
        return Err(format!(
            "the site's {what} is on {host}, not on {site_host} where discovery was pointed: refused"
        ));
    }
    Ok(())
}

/// A body that looks like a WordPress REST index: a `namespaces` array and a `routes` object.
fn is_index(body: &Value) -> bool {
    body.get("namespaces").is_some_and(Value::is_array) && body.get("routes").is_some_and(Value::is_object)
}

/// GET `url` and return the body if it is a REST index. `Err` is a transport failure.
async fn probe(http: &dyn HttpClient, url: &str) -> Result<Option<Value>, String> {
    let request = HttpRequest::get(url).header("Accept", "application/json");
    let response = http.send(request).await.map_err(|e| crate::connectors::transport_error_text(&e))?;
    Ok((response.is_success() && is_index(&response.body)).then_some(response.body))
}

/// The target of a `Link: <…>; rel="https://api.w.org/"` header, if one was kept.
fn api_link(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("link"))
        .flat_map(|(_, value)| value.split(','))
        .find(|part| {
            part.split(';').skip(1).any(|param| {
                let param = param.trim();
                param
                    .strip_prefix("rel=")
                    .map(|v| v.trim_matches('"') == "https://api.w.org/")
                    .unwrap_or(false)
            })
        })
        .and_then(|part| {
            let start = part.find('<')?;
            let end = part[start..].find('>')? + start;
            Some(part[start + 1..end].trim().to_string())
        })
}

/// Probe `raw_url` for a WordPress REST index, in a fixed order: `{site}/wp-json/`, then
/// `{site}/?rest_route=/`, then the `Link` header of `{site}/`, accepted only on the entered origin.
///
/// Probing comes first because a Link header read after a redirect names whatever site the redirect
/// landed on: the forum at `/support` 302s to a login wall on the main install, whose Link header
/// points at the wrong WordPress. `Err` is a 400-class refusal (a bad URL, or a canonical root the
/// host rule refuses); a site that simply is not WordPress is [`Discovery::NotFound`].
pub async fn discover(http: &dyn HttpClient, raw_url: &str) -> Result<Discovery, String> {
    let site = parse_site_url(raw_url)?;
    let base = trimmed(&site);
    let mut tried = Vec::new();
    let mut errors = Vec::new();

    for url in [format!("{base}/wp-json/"), format!("{base}/?rest_route=/")] {
        tried.push(url.clone());
        match probe(http, &url).await {
            Ok(Some(index)) => return found(&site, index).map(|s| Discovery::Found(Box::new(s))),
            Ok(None) => {}
            Err(e) => errors.push((url, e)),
        }
    }

    let home = format!("{base}/");
    tried.push(home.clone());
    match http.send(HttpRequest::get(&home)).await {
        Ok(response) => {
            if let Some(target) = api_link(&response.headers) {
                let bound = Url::parse(&target)
                    .map_err(|e| e.to_string())
                    .and_then(|target_url| check_bound(&target_url, &site, "API link"));
                match bound {
                    Ok(()) => {
                        tried.push(target.clone());
                        match probe(http, &target).await {
                            Ok(Some(index)) => {
                                return found(&site, index).map(|s| Discovery::Found(Box::new(s)))
                            }
                            Ok(None) => {}
                            Err(e) => errors.push((target, e)),
                        }
                    }
                    Err(e) => errors.push((target, format!("not followed: {e}"))),
                }
            }
        }
        Err(e) => errors.push((home, crate::connectors::transport_error_text(&e))),
    }
    Ok(Discovery::NotFound { tried, errors })
}

fn found(site: &Url, index: Value) -> Result<Site, String> {
    let pin = canonical_pin(&index, site)?;
    let text = |key: &str| index.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    Ok(Site { site_url: trimmed(site), pin, name: text("name"), description: text("description"), index })
}

/// Derive the canonical REST root from the first namespace route carrying `_links.self`, and apply the
/// host rule to it: the index names its own server, and it is untrusted input.
fn canonical_pin(index: &Value, site: &Url) -> Result<RestPin, String> {
    let routes = index.get("routes").and_then(Value::as_object);
    let namespaces = index.get("namespaces").and_then(Value::as_array).cloned().unwrap_or_default();
    for ns in namespaces.iter().filter_map(Value::as_str) {
        let Some(href) = routes
            .and_then(|r| r.get(&format!("/{ns}")))
            .and_then(|r| r.pointer("/_links/self/0/href"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        return pin_from_href(href, ns, site);
    }
    Err("the site's REST index names no canonical root: no namespace route carries _links.self".into())
}

fn pin_from_href(href: &str, namespace: &str, site: &Url) -> Result<RestPin, String> {
    let url = Url::parse(href).map_err(|e| format!("the site's REST root '{href}' is not a URL: {e}"))?;
    check_bound(&url, site, "REST root")?;
    let route = url.query_pairs().find(|(k, _)| k == "rest_route").map(|(_, v)| v.into_owned());
    match route {
        Some(route) => {
            if route.trim_end_matches('/') != format!("/{namespace}") {
                return Err(format!("the site's REST root '{href}' does not name the {namespace} namespace"));
            }
            let mut home = url.clone();
            home.set_query(None);
            let path = home.path();
            let path = if path.ends_with("/index.php") { path.trim_end_matches("index.php") } else { path };
            let path = path.trim_end_matches('/').to_string();
            home.set_path(&path);
            Ok(RestPin { routing: Routing::Query, root: trimmed(&home) })
        }
        None => {
            if url.query().is_some() {
                return Err(format!("the site's REST root '{href}' carries a query string: refused"));
            }
            let full = trimmed(&url);
            let root = full
                .strip_suffix(&format!("/{namespace}"))
                .ok_or_else(|| format!("the site's REST root '{href}' does not end in its namespace {namespace}"))?;
            Ok(RestPin { routing: Routing::Pretty, root: root.to_string() })
        }
    }
}

/// The index's namespaces, in its own order.
pub fn namespaces(index: &Value) -> Vec<String> {
    index
        .get("namespaces")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// Whether the site serves the Abilities API (listing it still needs a credential).
pub fn abilities_available(index: &Value) -> bool {
    index.pointer("/routes").and_then(Value::as_object).is_some_and(|r| r.contains_key(ABILITIES_ROUTE))
}

/// The routes object, empty when absent.
fn routes(index: &Value) -> Vec<(&String, &Value)> {
    let mut out: Vec<(&String, &Value)> =
        index.get("routes").and_then(Value::as_object).map(|r| r.iter().collect()).unwrap_or_default();
    out.sort_by(|a, b| a.0.cmp(b.0));
    out
}

fn route_namespace(route: &Value) -> &str {
    route.get("namespace").and_then(Value::as_str).unwrap_or_default()
}

/// The sha256 of every route's key with each endpoint's methods and argument names, sorted, over the
/// given namespaces (every route when `None`). Covers exactly what derivation reads, so an unrelated
/// index change (the site title, a plugin in a namespace nobody imported) does not invalidate a review.
pub fn digest(index: &Value, namespaces: Option<&[String]>) -> String {
    let mut lines = Vec::new();
    for (key, route) in routes(index) {
        if let Some(selected) = namespaces {
            if !selected.iter().any(|ns| ns == route_namespace(route)) {
                continue;
            }
        }
        for endpoint in route.get("endpoints").and_then(Value::as_array).into_iter().flatten() {
            let mut methods: Vec<&str> =
                endpoint.get("methods").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
            methods.sort_unstable();
            let args = arg_names(endpoint);
            lines.push(format!("{key}\t{}\t{}", methods.join(","), args.join(",")));
        }
    }
    lines.sort();
    let mut hasher = Sha256::new();
    hasher.update(lines.join("\n").as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn arg_names(endpoint: &Value) -> Vec<String> {
    let mut names: Vec<String> =
        endpoint.get("args").and_then(Value::as_object).map(|a| a.keys().cloned().collect()).unwrap_or_default();
    names.sort();
    names
}

/// The `discover` response body for a found site.
pub fn discover_json(site: &Site) -> Value {
    let summaries: Vec<Value> = namespaces(&site.index)
        .iter()
        .map(|ns| {
            let route_count = routes(&site.index).iter().filter(|(_, r)| route_namespace(r) == ns).count();
            let derived = derive(&site.index, std::slice::from_ref(ns), "wordpress", "", &site.pin);
            json!({ "namespace": ns, "routes": route_count, "capabilities": derived.capabilities.len() })
        })
        .collect();
    json!({
        "kind": "wordpress",
        "site_url": site.site_url,
        "rest_root": site.pin.rest_root(),
        "routing": site.pin.routing.as_str(),
        "name": site.name,
        "description": site.description,
        "namespaces": summaries,
        "abilities_available": abilities_available(&site.index),
        "digest": digest(&site.index, None),
    })
}

// ── Derivation ───────────────────────────────────────────────────────────────

/// A route the importer did not turn into capabilities, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The index route (or ability name).
    pub route: String,
    /// Why it was skipped.
    pub reason: String,
}

/// Capabilities derived from one source.
#[derive(Debug, Default)]
pub struct Derived {
    /// The capabilities, ids namespaced by the connection id.
    pub capabilities: Vec<Capability>,
    /// The ids that start switched off: everything at High or above, the preset loader's rule.
    pub disabled: Vec<String>,
    /// What was not imported.
    pub skipped: Vec<Skipped>,
}

impl Derived {
    fn push(&mut self, cap: Capability) {
        if starts_disabled(cap.risk) {
            self.disabled.push(cap.id.clone());
        }
        self.capabilities.push(cap);
    }

    fn skip(&mut self, route: &str, reason: impl Into<String>) {
        self.skipped.push(Skipped { route: route.to_string(), reason: reason.into() });
    }
}

/// Whether a capability of this risk starts disabled on import: the preset loader's `risk >= High`.
pub fn starts_disabled(risk: RiskTier) -> bool {
    risk >= RiskTier::High
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Lit(String),
    /// A named group that becomes a path parameter, with the group's own pattern.
    Param(String, String),
    Enum(String, Vec<String>),
}

/// Parse an index route into literal text, `{name}` parameters and literal-alternation groups. A named
/// group may hold any pattern (it becomes a parameter); outside one, only plain path characters are
/// accepted, and anything else is a regex construct the importer cannot pin.
fn parse_route(route: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = route.chars().collect();
    let mut tokens = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i..].starts_with(&['(', '?', 'P', '<']) {
            if !lit.is_empty() {
                tokens.push(Token::Lit(std::mem::take(&mut lit)));
            }
            let name_start = i + 4;
            let name_end = chars[name_start..]
                .iter()
                .position(|c| *c == '>')
                .map(|p| p + name_start)
                .ok_or("unterminated parameter name")?;
            let name: String = chars[name_start..name_end].iter().collect();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("parameter name '{name}' cannot be pinned"));
            }
            let (mut depth, mut k, mut in_class) = (1usize, name_end + 1, false);
            while k < chars.len() && depth > 0 {
                match chars[k] {
                    '\\' => {
                        k += 2;
                        continue;
                    }
                    ']' if in_class => in_class = false,
                    _ if in_class => {}
                    '[' => in_class = true,
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                k += 1;
            }
            if depth != 0 {
                return Err(format!("parameter '{name}' has an unbalanced pattern"));
            }
            let pattern: String = chars[name_end + 1..k - 1].iter().collect();
            tokens.push(match literal_alternation(&pattern) {
                Some(alts) => Token::Enum(name, alts),
                None => Token::Param(name, pattern),
            });
            i = k;
        } else {
            let c = chars[i];
            if c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~') {
                lit.push(c);
                i += 1;
            } else {
                return Err(format!("regex syntax '{c}' outside a named parameter"));
            }
        }
    }
    if !lit.is_empty() {
        tokens.push(Token::Lit(lit));
    }
    Ok(tokens)
}

/// `close|open|stick` → the literals, when every alternative is a plain word.
fn literal_alternation(pattern: &str) -> Option<Vec<String>> {
    let alts: Vec<String> = pattern.split('|').map(str::to_string).collect();
    let plain = |a: &String| !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    alts.iter().all(plain).then_some(alts)
}

/// One concrete route after literal alternations are split.
#[derive(Debug, Clone)]
struct Variant {
    path: String,
    path_params: Vec<String>,
    path_patterns: BTreeMap<String, PathPattern>,
    split_names: Vec<String>,
    ends_in_split: bool,
}

fn expand(tokens: &[Token]) -> Result<Vec<Variant>, String> {
    let mut variants = vec![Variant { path: String::new(), path_params: Vec::new(), path_patterns: BTreeMap::new(), split_names: Vec::new(), ends_in_split: false }];
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (i, token) in tokens.iter().enumerate() {
        let is_last = i + 1 == tokens.len();
        match token {
            Token::Lit(text) => variants.iter_mut().for_each(|v| v.path.push_str(text)),
            Token::Param(name, _) | Token::Enum(name, _) if !seen.insert(name.as_str()) => {
                return Err(format!("parameter '{name}' appears twice"));
            }
            Token::Param(name, pattern) => {
                // WordPress matches a route case-insensitively; a group Rust cannot read keeps the strict one-segment rule.
                let own = format!("(?i){pattern}");
                let own = compile_path_pattern(&own).is_some().then_some(PathPattern { pattern: own, encode_slash: false });
                variants.iter_mut().for_each(|v| {
                    v.path.push_str(&format!("{{{name}}}"));
                    v.path_params.push(name.clone());
                    if let Some(own) = &own {
                        v.path_patterns.insert(name.clone(), own.clone());
                    }
                })
            }
            Token::Enum(name, alts) => {
                if variants.len() * alts.len() > MAX_SPLIT {
                    return Err(format!("splitting its literal alternations makes more than {MAX_SPLIT} routes"));
                }
                let whole_segment = i > 0 && matches!(&tokens[i - 1], Token::Lit(t) if t.ends_with('/'));
                variants = variants
                    .into_iter()
                    .flat_map(|v| {
                        alts.iter().map(move |alt| {
                            let mut v = v.clone();
                            v.path.push_str(alt);
                            v.split_names.push(name.clone());
                            v.ends_in_split = is_last && whole_segment;
                            v
                        })
                    })
                    .collect();
            }
        }
    }
    Ok(variants)
}

/// A capability-id segment: lowercase ASCII words joined by `_`.
fn sanitize(s: &str) -> String {
    let mut out = String::new();
    let mut gap = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            if gap && !out.is_empty() {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            gap = false;
        } else {
            gap = true;
        }
    }
    out
}

/// The id prefix for a namespace: its first part (`bbpress/v1` → `bbpress`, `wp/v2` → `wp`). `abilities`
/// is reserved for the Abilities source, so a REST namespace of that name is kept apart from it.
fn namespace_id(namespace: &str) -> String {
    let id = sanitize(namespace.split('/').next().unwrap_or(namespace));
    match id.as_str() {
        "" => "ns".to_string(),
        "abilities" => "abilities_rest".to_string(),
        _ => id,
    }
}

/// Claim `id`, appending `_2`, `_3`, … when it is already taken.
fn claim(used: &mut BTreeSet<String>, id: String) -> String {
    if used.insert(id.clone()) {
        return id;
    }
    (2..).map(|n| format!("{id}_{n}")).find(|c| used.insert(c.clone())).expect("an unused suffix")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read,
    Create,
    Action,
    Update(HttpMethod),
    Delete,
}

/// The capabilities one endpoint's method set yields. WordPress registers an edit as one endpoint with
/// `POST, PUT, PATCH`; that becomes a single update sent as POST, since shared hosts often block PUT
/// and PATCH and WordPress treats the three alike.
fn kinds(methods: &[String], ends_in_split: bool) -> Vec<Kind> {
    let has = |m: &str| methods.iter().any(|x| x.eq_ignore_ascii_case(m));
    let mut out = Vec::new();
    if has("GET") {
        out.push(Kind::Read);
    }
    match (has("POST"), has("PUT"), has("PATCH")) {
        (true, false, false) => out.push(if ends_in_split { Kind::Action } else { Kind::Create }),
        (true, _, _) => out.push(Kind::Update(HttpMethod::Post)),
        (false, true, _) => out.push(Kind::Update(HttpMethod::Put)),
        (false, false, true) => out.push(Kind::Update(HttpMethod::Patch)),
        _ => {}
    }
    if has("DELETE") {
        out.push(Kind::Delete);
    }
    out
}

/// The raise-only WordPress pass after `classify`: a write whose path names something destructive, or
/// that sits under a segment controlling who can do what, becomes Critical plus approval, and so does
/// any call, a read included, whose route below its namespace names an operation as a whole word
/// ([`crate::openapi::OPERATION_WORDS`]). The nouns among [`RISKY_WORDS`] (`blocks`, a ban list) stay
/// ordinary reads.
fn escalates(method: HttpMethod, literal_path: &str, segments: &[&str]) -> bool {
    let lower = literal_path.to_ascii_lowercase();
    if crate::openapi::names_an_operation(&segments.join("/")) {
        return true;
    }
    method != HttpMethod::Get
        && (RISKY_WORDS.iter().any(|w| lower.contains(w))
            || segments.iter().any(|s| {
                let s = s.to_ascii_lowercase();
                SENSITIVE_SEGMENTS.contains(&s.as_str()) || s.ends_with("-role")
            }))
}

/// Derive capabilities from `index` for the selected `namespaces`. Deterministic: namespaces and routes
/// are walked in sorted order, so a re-import or re-sync produces the same ids.
pub fn derive(
    index: &Value,
    namespaces: &[String],
    connection_id: &str,
    secret_id: &str,
    pin: &RestPin,
) -> Derived {
    let mut out = Derived::default();
    let mut used = BTreeSet::new();
    let mut selected: Vec<&String> = namespaces.iter().collect();
    selected.sort();
    selected.dedup();
    let all_routes = routes(index);
    for ns in selected {
        let ns = ns.trim_matches('/');
        let prefix = format!("/{ns}");
        for (key, route) in all_routes.iter().filter(|(_, r)| route_namespace(r) == ns) {
            if **key == prefix {
                continue;
            }
            if !key.starts_with(&format!("{prefix}/")) {
                out.skip(key, format!("route is outside its declared namespace {ns}"));
                continue;
            }
            let variants = match parse_route(key).and_then(|t| expand(&t)) {
                Ok(v) => v,
                Err(reason) => {
                    out.skip(key, reason);
                    continue;
                }
            };
            let Some(endpoints) = route.get("endpoints").and_then(Value::as_array) else {
                out.skip(key, "route lists no endpoints");
                continue;
            };
            for variant in variants {
                if variant.path.split('/').any(|s| s == "." || s == "..") {
                    out.skip(key, "route has a dot path segment");
                    break;
                }
                derive_variant(&mut out, &mut used, ns, (key, &variant), endpoints, &all_routes, connection_id, secret_id, pin);
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn derive_variant(
    out: &mut Derived,
    used: &mut BTreeSet<String>,
    ns: &str,
    (route_key, variant): (&str, &Variant),
    endpoints: &[Value],
    all_routes: &[(&String, &Value)],
    connection_id: &str,
    secret_id: &str,
    pin: &RestPin,
) {
    let relative = variant.path.strip_prefix(&format!("/{ns}")).unwrap_or(&variant.path);
    let raw_segments: Vec<&str> = relative.split('/').filter(|s| !s.is_empty() && !s.contains('{')).collect();
    let literal_path: String = {
        let mut text = String::new();
        let mut in_param = false;
        for c in variant.path.chars() {
            match c {
                '{' => in_param = true,
                '}' => in_param = false,
                _ if !in_param => text.push(c),
                _ => {}
            }
        }
        text
    };
    let mut stem = vec![namespace_id(ns)];
    stem.extend(raw_segments.iter().map(|s| sanitize(s)).filter(|s| !s.is_empty()));

    for endpoint in endpoints {
        let methods: Vec<String> = endpoint
            .get("methods")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        // A `_method` argument would let the call run as another method than the one the capability shows.
        let args: Vec<String> = arg_names(endpoint)
            .into_iter()
            .filter(|a| !variant.split_names.contains(a) && !variant.path_params.contains(a) && !crate::connectors::is_method_override_param(a))
            .collect();
        for kind in kinds(&methods, variant.ends_in_split) {
            let (method, semantic, verb) = match kind {
                Kind::Read => {
                    let list = args.iter().any(|a| a == "page" || a == "per_page");
                    (HttpMethod::Get, "get", Some(if list { "list" } else { "get" }))
                }
                Kind::Create => (HttpMethod::Post, "post", Some("create")),
                Kind::Action => (HttpMethod::Post, "post", None),
                Kind::Update(m) => (m, "put", Some("update")),
                Kind::Delete => (HttpMethod::Delete, "delete", Some("delete")),
            };
            let mut parts = stem.clone();
            parts.extend(verb.map(str::to_string));
            let action_id = claim(used, parts.join("."));
            let (mut action, mut risk, mut requires_approval) = classify(semantic, &variant.path, &action_id);
            if escalates(method, &literal_path, &raw_segments) || crate::openapi::names_an_operation(relative) {
                risk = risk.max(RiskTier::Critical);
                requires_approval = true;
                // A `GET` escalates only on an operation word, so it is not a read whatever its method says.
                if method == HttpMethod::Get {
                    action = Action::Execute;
                }
            }
            let (query_params, body_params) = match method {
                HttpMethod::Get | HttpMethod::Delete => (args.clone(), Vec::new()),
                _ => (Vec::new(), args.clone()),
            };
            // A capability whose siblings cannot all be carried keeps the strict one-segment rule. One whose own pattern could not be read still carries its siblings, which only ever refuse a value.
            let (path_patterns, sibling_routes) = match variant.path_params.is_empty() {
                true => (BTreeMap::new(), Vec::new()),
                false => match sibling_routes(all_routes, route_key, method.as_str()) {
                    Some(siblings) => (variant.path_patterns.clone(), siblings),
                    None => (BTreeMap::new(), Vec::new()),
                },
            };
            out.push(Capability {
                id: format!("{connection_id}.{action_id}"),
                description: format!("{} {}", method.as_str(), variant.path),
                risk,
                action,
                requires_approval,
                resource: connection_id.to_string(),
                secret_id: secret_id.to_string(),
                kind: CapabilityKind::Http,
                command: None,
                http: Some(HttpSpec {
                    method,
                    base_url: pin.base_url(),
                    path: variant.path.clone(),
                    path_params: variant.path_params.clone(),
                    path_patterns,
                    sibling_routes,
                    route_patterns_read: !variant.path_params.is_empty(),
                    query_params,
                    body_params,
                    auth: AuthScheme::Basic { key_as_username: false },
                    route_param: pin.route_param(),
                    ..Default::default()
                }),
                ssh: None,
            });
        }
    }
}

/// The most sibling routes one capability carries; past this it keeps the strict one-segment rule.
const MAX_SIBLING_ROUTES: usize = 64;

/// A route's text up to its first regex syntax, lowercased: another route can only also match a path of this one when one of the two literal starts begins the other.
fn literal_start(route: &str) -> String {
    route.chars().take_while(|c| !"([\\.*+?{|^$".contains(*c)).collect::<String>().to_lowercase()
}

/// The routes other than `own` that take `method` and whose literal start overlaps `own`'s, or `None`
/// when there are more than [`MAX_SIBLING_ROUTES`] of them or one is too long to carry.
fn sibling_routes(all: &[(&String, &Value)], own: &str, method: &str) -> Option<Vec<String>> {
    let mine = literal_start(own);
    let mut out = Vec::new();
    for (key, route) in all {
        let theirs = literal_start(key);
        if key.as_str() == own || !(mine.starts_with(&theirs) || theirs.starts_with(&mine)) {
            continue;
        }
        let takes = route
            .get("endpoints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|e| e.get("methods").and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_str)
            .any(|m| m.eq_ignore_ascii_case(method));
        if takes {
            if key.len() + 4 > crate::connectors::connector::MAX_PATH_PATTERN_LEN {
                return None;
            }
            out.push(key.to_string());
        }
    }
    (out.len() <= MAX_SIBLING_ROUTES).then_some(out)
}

// ── The Abilities API ────────────────────────────────────────────────────────

/// The capability that reads one page of the Abilities listing with the connection's credential. It
/// is never stored or granted: the gateway sends it on the operator's behalf during a re-sync.
pub fn abilities_list_capability(connection_id: &str, secret_id: &str, pin: &RestPin) -> Capability {
    Capability {
        id: format!("{connection_id}.abilities.discover"),
        description: format!("GET {ABILITIES_ROUTE}"),
        risk: RiskTier::Medium,
        action: Action::Search,
        requires_approval: false,
        resource: connection_id.to_string(),
        secret_id: secret_id.to_string(),
        kind: CapabilityKind::Http,
        command: None,
        http: Some(HttpSpec {
            method: HttpMethod::Get,
            base_url: pin.base_url(),
            path: ABILITIES_ROUTE.to_string(),
            query_params: vec!["per_page".into(), "page".into()],
            auth: AuthScheme::Basic { key_as_username: false },
            route_param: pin.route_param(),
            ..Default::default()
        }),
        ssh: None,
    }
}

/// Whether the ids this connection holds under `abilities.` came from the Abilities source.
pub fn is_ability_capability(connection_id: &str, capability_id: &str) -> bool {
    capability_id.starts_with(&format!("{connection_id}.abilities."))
}

fn valid_ability_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

fn annotation(ability: &Value, key: &str) -> bool {
    ability.pointer(&format!("/meta/annotations/{key}")).and_then(Value::as_bool).unwrap_or(false)
}

/// The method WordPress runs an ability with, from its annotations.
fn ability_method(readonly: bool, destructive: bool, idempotent: bool) -> HttpMethod {
    if readonly {
        HttpMethod::Get
    } else if destructive && idempotent {
        HttpMethod::Delete
    } else {
        HttpMethod::Post
    }
}

/// One ability Permaura has reviewed: the annotations its plugin registers it with and the posture it
/// lands with when a site registers it exactly so. Compiled in from `presets/abilities.yaml`, so it is
/// vouched the way the bundled catalog is.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KnownAbility {
    /// The ability's registered name, e.g. `events-manager/list-events`.
    pub name: String,
    /// The `readonly` annotation it is registered with.
    pub readonly: bool,
    /// The `destructive` annotation it is registered with.
    pub destructive: bool,
    /// The `idempotent` annotation it is registered with.
    pub idempotent: bool,
    /// The reviewed action.
    pub action: Action,
    /// The reviewed risk.
    pub risk: RiskTier,
    /// Whether every call asks for approval.
    pub requires_approval: bool,
    /// The top-level input fields it was reviewed with.
    pub input: Vec<String>,
}

impl KnownAbility {
    /// The method WordPress runs it with when registered as reviewed.
    pub fn method(&self) -> HttpMethod {
        ability_method(self.readonly, self.destructive, self.idempotent)
    }

    fn posture(&self) -> (Action, RiskTier, bool) {
        (self.action, self.risk, self.requires_approval)
    }

    /// Whether `ability`, as a site lists it, is still the ability that was reviewed: the same annotations, and an input schema that takes no top-level field the review did not see.
    fn reviewed_as(&self, ability: &Value) -> bool {
        let annotations = (annotation(ability, "readonly"), annotation(ability, "destructive"), annotation(ability, "idempotent"));
        if annotations != (self.readonly, self.destructive, self.idempotent) {
            return false;
        }
        let Some(schema) = ability.get("input_schema").and_then(Value::as_object) else { return false };
        // PHP encodes an empty `properties` array as `[]`.
        match schema.get("properties") {
            None | Some(Value::Null) => true,
            Some(Value::Array(none)) => none.is_empty(),
            Some(Value::Object(fields)) => fields.keys().all(|field| self.input.iter().any(|known| known == field)),
            Some(_) => false,
        }
    }
}

/// Every reviewed ability, loaded on first use.
pub fn known_abilities() -> &'static [KnownAbility] {
    static KNOWN: std::sync::OnceLock<Vec<KnownAbility>> = std::sync::OnceLock::new();
    KNOWN.get_or_init(|| serde_yaml::from_str(include_str!("../presets/abilities.yaml")).expect("bundled presets/abilities.yaml is valid"))
}

/// The reviewed entry for `name`, if any.
pub fn known_ability(name: &str) -> Option<&'static KnownAbility> {
    known_abilities().iter().find(|k| k.name == name)
}

/// Derive one capability per ability. The run path is literal (the name contains a slash, so it cannot
/// be a path parameter); the method is what the annotations make WordPress demand, and the annotations
/// may raise risk but never lower it, because the site being governed writes them: an ability annotated
/// `readonly` is sent as a `GET` and keeps the action and risk of an unannotated one (Execute, High),
/// while `destructive` or a risky word in its name makes it Critical plus approval. A [`known_ability`]
/// registered as it was reviewed ([`KnownAbility::reviewed_as`]) lands with the reviewed posture instead.
pub fn derive_abilities(abilities: &[Value], connection_id: &str, secret_id: &str, pin: &RestPin) -> Derived {
    let mut out = Derived::default();
    let mut used = BTreeSet::new();
    let mut sorted: Vec<&Value> = abilities.iter().collect();
    sorted.sort_by_key(|a| a.get("name").and_then(Value::as_str).unwrap_or_default().to_string());
    for ability in sorted {
        let Some(name) = ability.get("name").and_then(Value::as_str) else {
            out.skip("(unnamed)", "ability has no name");
            continue;
        };
        if ability.pointer("/meta/show_in_rest").and_then(Value::as_bool) == Some(false) {
            out.skip(name, "ability is not shown in REST");
            continue;
        }
        if !valid_ability_name(name) {
            out.skip(name, "ability name has characters that cannot be pinned in a path");
            continue;
        }
        let readonly = annotation(ability, "readonly");
        let destructive = annotation(ability, "destructive");
        let idempotent = annotation(ability, "idempotent");
        let method = ability_method(readonly, destructive, idempotent);
        let path = format!("{ABILITIES_ROUTE}/{name}/run");
        let action_id = claim(&mut used, format!("abilities.{}", sanitize(name)));
        let (action, risk, requires_approval) = match known_ability(name).filter(|k| k.reviewed_as(ability)) {
            Some(known) => known.posture(),
            None => ability_posture(name, &path, &action_id, method, destructive),
        };
        let (query_params, body_params, query_style) = match method {
            HttpMethod::Post => (Vec::new(), vec!["input".to_string()], QueryStyle::Flat),
            _ => (vec!["input".to_string()], Vec::new(), QueryStyle::Brackets),
        };
        let text = |key: &str| ability.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
        let description = match (text("label"), text("description")) {
            (Some(label), Some(desc)) => format!("{label}: {desc}"),
            (Some(one), None) | (None, Some(one)) => one.to_string(),
            (None, None) => format!("{} {path}", method.as_str()),
        };
        out.push(Capability {
            id: format!("{connection_id}.{action_id}"),
            description,
            risk,
            action,
            requires_approval,
            resource: connection_id.to_string(),
            secret_id: secret_id.to_string(),
            kind: CapabilityKind::Http,
            command: None,
            http: Some(HttpSpec {
                method,
                base_url: pin.base_url(),
                path,
                query_params,
                body_params,
                auth: AuthScheme::Basic { key_as_username: false },
                route_param: pin.route_param(),
                query_style,
                ..Default::default()
            }),
            ssh: None,
        });
    }
    out
}

/// An ability's posture from what the gateway sends and its name. The floor is the method an
/// unannotated ability is sent with (`POST`, or `DELETE` for one destructive and idempotent), so a
/// `readonly` annotation, which makes WordPress demand `GET`, cannot lower it: every ability is at least
/// High, and `destructive` or a risky word in its name makes it Critical plus approval.
fn ability_posture(name: &str, path: &str, action_id: &str, method: HttpMethod, destructive: bool) -> (Action, RiskTier, bool) {
    let floor_method = if method == HttpMethod::Delete { HttpMethod::Delete } else { HttpMethod::Post };
    let (base_action, base_risk, base_approval) = classify(&floor_method.as_str().to_ascii_lowercase(), path, action_id);
    let lower = name.to_ascii_lowercase();
    let risky = RISKY_WORDS.iter().chain(ABILITY_RISKY_WORDS).any(|w| lower.contains(w)) || crate::openapi::names_an_operation(name);
    let action = match base_action {
        Action::Create if method == HttpMethod::Get && action_id.contains("export") => Action::Export,
        Action::Create => Action::Execute,
        other => other,
    };
    if destructive || risky {
        return (action, RiskTier::Critical, true);
    }
    (action, base_risk.max(RiskTier::High), base_approval)
}

/// The floor today's derivation gives a stored WordPress capability, read from its pinned shape alone:
/// an ability is held as [`ability_posture`] holds one sent with that method, and a `GET` route whose
/// route below its namespace names an operation is Execute, Critical and approval. `None` when neither
/// applies. Lets a start-up pass raise rows a re-sync from an earlier gateway stored.
pub fn stored_floor(connection_id: &str, cap: &Capability, namespaces: &[String]) -> Option<(Action, RiskTier, bool)> {
    let http = cap.http.as_ref()?;
    let action_id = cap.id.strip_prefix(&format!("{connection_id}.")).unwrap_or(&cap.id);
    if is_ability_capability(connection_id, &cap.id) {
        let name = http.path.strip_prefix(&format!("{ABILITIES_ROUTE}/"))?.strip_suffix("/run")?;
        // The annotations are not stored, so a reviewed ability is matched on the method they gave it; a floor only ever raises, so a row derived from other annotations sent the same way keeps anything it holds above this.
        if let Some(known) = known_ability(name).filter(|k| k.method() == http.method) {
            return Some(known.posture());
        }
        return Some(ability_posture(name, &http.path, action_id, http.method, false));
    }
    if http.method != HttpMethod::Get {
        return None;
    }
    crate::openapi::names_an_operation(below_namespace(&http.path, namespaces)).then_some((Action::Execute, RiskTier::Critical, true))
}

/// A route's path below the first of `namespaces` it sits under, or the whole path when it sits under none.
pub fn below_namespace<'a>(path: &'a str, namespaces: &[String]) -> &'a str {
    namespaces.iter().find_map(|ns| path.strip_prefix(&format!("/{}/", ns.trim_matches('/')))).unwrap_or(path)
}

/// Read every page of the Abilities listing with the connection's sealed credential, through
/// [`crate::service::EnforcementService::send_with_credential`], until a short page. Returns the
/// abilities and the number of pages read.
pub async fn fetch_abilities(
    service: &crate::service::EnforcementService,
    connection_id: &str,
    secret_id: &str,
    pin: &RestPin,
) -> Result<(Vec<Value>, u32), GatewayError> {
    let cap = abilities_list_capability(connection_id, secret_id, pin);
    let mut abilities = Vec::new();
    for page in 1..=ABILITIES_MAX_PAGES {
        let params = json!({ "per_page": ABILITIES_PAGE_SIZE, "page": page });
        let response = service.send_with_credential(&cap, &params).await?;
        // WordPress answers a page past the end with 400 rest_*_invalid_page_number when the previous page was exactly full.
        if page > 1 && response.status == 400 {
            return Ok((abilities, page - 1));
        }
        if matches!(response.status, 401 | 403) {
            return Err(GatewayError::BadRequest(format!(
                "the site refused the connection's credential when listing abilities (HTTP {}): check the \
                 application password sealed on '{connection_id}'",
                response.status
            )));
        }
        if !response.is_success() {
            return Err(GatewayError::BadRequest(format!(
                "the site answered HTTP {} when listing abilities",
                response.status
            )));
        }
        let Some(items) = response.body.as_array() else {
            return Err(GatewayError::BadRequest("the Abilities listing did not return a JSON array".into()));
        };
        let short = items.len() < ABILITIES_PAGE_SIZE;
        abilities.extend(items.iter().cloned());
        if short {
            return Ok((abilities, page));
        }
    }
    Err(GatewayError::BadRequest(format!(
        "the Abilities listing ran past {ABILITIES_MAX_PAGES} pages of {ABILITIES_PAGE_SIZE}: refused"
    )))
}

// ── Review shapes ────────────────────────────────────────────────────────────

/// One capability as the operator reviews it.
pub fn preview(cap: &Capability, disabled: bool) -> Value {
    let (method, path) =
        cap.http.as_ref().map(|h| (h.method.as_str(), h.path.as_str())).unwrap_or(("", ""));
    json!({
        "id": cap.id,
        "description": cap.description,
        "method": method,
        "path": path,
        "action": cap.action,
        "risk": cap.risk,
        "requires_approval": cap.requires_approval,
        "disabled": disabled,
    })
}

/// The skipped list as JSON.
pub fn skipped_json(skipped: &[Skipped]) -> Value {
    json!(skipped.iter().map(|s| json!({ "route": s.route, "reason": s.reason })).collect::<Vec<_>>())
}

/// Whether two derivations of the same capability id differ in anything a review would show.
pub fn same_capability(a: &Capability, b: &Capability) -> bool {
    a.description == b.description
        && a.risk == b.risk
        && a.action == b.action
        && a.requires_approval == b.requires_approval
        && a.kind == b.kind
        && a.secret_id == b.secret_id
        && a.http == b.http
}

/// Whether `fresh` differs from `old` only in what a re-sync records without a review, so it
/// rewrites the capability in place and keeps the operator's switch: the path patterns a capability
/// stored before they were recorded lacks (it already reached this route, and now reaches it with the
/// values the route itself admits) with the mark that they were read, and the sibling routes, which
/// only ever refuse a value. A pattern that changed once recorded is a change to review.
pub fn only_refreshes_route_context(old: &Capability, fresh: &Capability) -> bool {
    let (Some(was), Some(now)) = (&old.http, &fresh.http) else { return false };
    // Once the importer has read the route, a pattern it left out on purpose (an unreadable group) is as much a decision as one it recorded.
    if (was.route_patterns_read || !was.path_patterns.is_empty()) && was.path_patterns != now.path_patterns {
        return false;
    }
    let mut refreshed = old.clone();
    if let Some(http) = refreshed.http.as_mut() {
        http.path_patterns = now.path_patterns.clone();
        http.sibling_routes = now.sibling_routes.clone();
        http.route_patterns_read = now.route_patterns_read;
    }
    same_capability(&refreshed, fresh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::{build_request, HttpResponse, MockHttpClient};

    const FORUM: &str = include_str!("../tests/fixtures/wordpress/forum-index.json");
    const ABILITIES: &str = include_str!("../tests/fixtures/wordpress/abilities.json");
    const SITE: &str = "https://eventsmanagerpro.com/support";

    fn forum() -> Value {
        serde_json::from_str(FORUM).unwrap()
    }

    /// The forum index rewritten as a plain-permalink site would describe itself.
    fn forum_query_style() -> Value {
        let text = FORUM.replace(
            "https://eventsmanagerpro.com/support/wp-json/",
            "https://eventsmanagerpro.com/support/index.php?rest_route=/",
        );
        serde_json::from_str(&text).unwrap()
    }

    fn pretty() -> RestPin {
        RestPin { routing: Routing::Pretty, root: format!("{SITE}/wp-json") }
    }

    fn not_found() -> HttpResponse {
        HttpResponse { status: 404, text: Some("<html>not found</html>".into()), ..HttpResponse::default() }
    }

    fn derived_forum(namespaces: &[&str]) -> Derived {
        let ns: Vec<String> = namespaces.iter().map(|s| s.to_string()).collect();
        derive(&forum(), &ns, "wp_forum", "sec_wp_forum", &pretty())
    }

    fn cap<'a>(d: &'a Derived, action_id: &str) -> &'a Capability {
        d.capabilities
            .iter()
            .find(|c| c.id == format!("wp_forum.{action_id}"))
            .unwrap_or_else(|| panic!("no capability {action_id}: {:?}", d.capabilities.iter().map(|c| &c.id).collect::<Vec<_>>()))
    }

    fn disabled(d: &Derived, action_id: &str) -> bool {
        d.disabled.contains(&format!("wp_forum.{action_id}"))
    }

    async fn run_discover(mock: &MockHttpClient, url: &str) -> Result<Discovery, String> {
        discover(mock, url).await
    }

    #[tokio::test]
    async fn a_pretty_permalink_site_is_found_at_wp_json_and_pinned_to_its_canonical_root() {
        let mock = MockHttpClient::with_response(HttpResponse::json(200, forum()));
        let Discovery::Found(site) = run_discover(&mock, "https://eventsmanagerpro.com/support/").await.unwrap() else {
            panic!("the forum is a WordPress site");
        };
        assert_eq!(mock.requests()[0].url, "https://eventsmanagerpro.com/support/wp-json/");
        assert_eq!(mock.requests().len(), 1, "the first probe answered, so nothing else was asked");
        assert_eq!(site.site_url, SITE);
        assert_eq!(site.pin.routing, Routing::Pretty);
        assert_eq!(site.pin.rest_root(), "https://eventsmanagerpro.com/support/wp-json");
        assert_eq!(site.name, "Events Manager Pro Support");
        let body = discover_json(&site);
        assert_eq!(body["kind"], "wordpress");
        assert_eq!(body["routing"], "pretty");
        assert_eq!(body["abilities_available"], true);
        let bbpress = body["namespaces"].as_array().unwrap().iter().find(|n| n["namespace"] == "bbpress/v1").unwrap();
        assert_eq!(bbpress["routes"], 43);
        assert!(bbpress["capabilities"].as_u64().unwrap() > 43, "enum routes split: {bbpress}");
    }

    #[tokio::test]
    async fn a_plain_permalink_site_is_found_through_rest_route() {
        let mock = MockHttpClient::new();
        mock.push_response(not_found());
        mock.push_response(HttpResponse::json(200, forum_query_style()));
        let Discovery::Found(site) = run_discover(&mock, SITE).await.unwrap() else { panic!("found") };
        assert_eq!(mock.requests()[1].url, "https://eventsmanagerpro.com/support/?rest_route=/");
        assert_eq!(site.pin.routing, Routing::Query);
        assert_eq!(site.pin.rest_root(), "https://eventsmanagerpro.com/support/?rest_route=/");
        assert_eq!(site.pin.base_url(), "https://eventsmanagerpro.com/support/");
        assert_eq!(site.pin.route_param().as_deref(), Some("rest_route"));
        assert_eq!(RestPin::from_rest_root(&site.pin.rest_root()), Some(site.pin.clone()));
    }

    #[tokio::test]
    async fn a_canonical_root_on_another_host_is_refused() {
        let text = FORUM.replace("https://eventsmanagerpro.com/support/wp-json/", "https://attacker.example/wp-json/");
        let mock = MockHttpClient::with_response(HttpResponse::json(200, serde_json::from_str(&text).unwrap()));
        let err = run_discover(&mock, SITE).await.expect_err("another host must not be pinned");
        assert!(err.contains("attacker.example") && err.contains("refused"), "{err}");
    }

    #[tokio::test]
    async fn a_bare_www_difference_is_the_same_site() {
        let mock = MockHttpClient::with_response(HttpResponse::json(200, forum()));
        let Discovery::Found(site) = run_discover(&mock, "https://www.eventsmanagerpro.com/support").await.unwrap() else {
            panic!("found")
        };
        assert_eq!(site.pin.rest_root(), "https://eventsmanagerpro.com/support/wp-json", "the canonical host is pinned");
        assert!(same_site_host("example.com", "WWW.example.com"));
        assert!(!same_site_host("example.com", "wwwexample.com"));
        assert!(!same_site_host("example.com", "api.example.com"));
    }

    #[tokio::test]
    async fn a_site_that_is_not_wordpress_is_none_with_every_url_tried() {
        let mock = MockHttpClient::new();
        mock.push_response(not_found());
        mock.push_response(HttpResponse::json(200, json!({ "hello": "world" })));
        mock.push_response(HttpResponse { status: 200, ..HttpResponse::default() });
        let Discovery::NotFound { tried, errors } = run_discover(&mock, "https://shop.example.com").await.unwrap() else {
            panic!("nothing here is WordPress")
        };
        assert_eq!(
            tried,
            ["https://shop.example.com/wp-json/", "https://shop.example.com/?rest_route=/", "https://shop.example.com/"]
        );
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn the_link_header_is_followed_only_on_the_entered_origin() {
        let link = |target: &str| HttpResponse {
            status: 200,
            headers: vec![("link".into(), format!("<{target}>; rel=\"https://api.w.org/\""))],
            ..HttpResponse::default()
        };
        let mock = MockHttpClient::new();
        mock.push_response(not_found());
        mock.push_response(not_found());
        mock.push_response(link("https://eventsmanagerpro.com/support/wp-json/"));
        mock.push_response(HttpResponse::json(200, forum()));
        let Discovery::Found(_) = run_discover(&mock, SITE).await.unwrap() else { panic!("found via Link") };
        assert_eq!(mock.requests()[3].url, "https://eventsmanagerpro.com/support/wp-json/");

        let mock = MockHttpClient::new();
        mock.push_response(not_found());
        mock.push_response(not_found());
        mock.push_response(link("https://other.example/wp-json/"));
        let Discovery::NotFound { tried, .. } = run_discover(&mock, SITE).await.unwrap() else {
            panic!("a Link to another origin is not followed")
        };
        assert_eq!(tried.len(), 3);
        assert_eq!(mock.requests().len(), 3, "the other origin was never requested");
    }

    #[test]
    fn an_entered_url_must_be_clean_https() {
        for bad in [
            "http://example.com",
            "example.com",
            "https://user:pw@example.com",
            "https://example.com/?x=1",
            "https://example.com/#frag",
            "",
        ] {
            assert!(parse_site_url(bad).is_err(), "{bad} must be refused");
        }
        assert_eq!(trimmed(&parse_site_url(" https://Example.com/blog/ ").unwrap()), "https://example.com/blog");
    }

    #[test]
    fn enum_routes_split_into_one_capability_per_literal_with_the_right_posture() {
        let d = derived_forum(&["bbpress/v1"]);
        let trash = cap(&d, "bbpress.topics.actions.trash");
        assert_eq!(trash.risk, RiskTier::Critical);
        assert!(trash.requires_approval);
        assert!(disabled(&d, "bbpress.topics.actions.trash"));
        let http = trash.http.as_ref().unwrap();
        assert_eq!(http.method, HttpMethod::Post);
        assert_eq!(http.path, "/bbpress/v1/topics/{id}/actions/trash");
        assert_eq!(http.path_params, ["id"]);
        assert!(!http.body_params.contains(&"action".to_string()), "the split name leaves the params");
        assert!(http.body_params.contains(&"destination_forum_id".to_string()));

        let close = cap(&d, "bbpress.topics.actions.close");
        assert_eq!(close.risk, RiskTier::High);
        assert!(!close.requires_approval);
        assert!(disabled(&d, "bbpress.topics.actions.close"));

        for spammy in ["bbpress.replies.actions.spam", "bbpress.replies.actions.unspam", "bbpress.topics.actions.merge"] {
            assert_eq!(cap(&d, spammy).risk, RiskTier::Critical, "{spammy}");
        }
        assert_eq!(d.capabilities.iter().filter(|c| c.id.starts_with("wp_forum.bbpress.forums.actions.")).count(), 7);

        let attachments = cap(&d, "bbpress.replies.attachments.get");
        let http = attachments.http.as_ref().unwrap();
        assert_eq!(http.path, "/bbpress/v1/replies/{id}/attachments");
        assert_eq!(http.path_params, ["id"]);
        assert!(!http.query_params.contains(&"parent_type".to_string()));
        cap(&d, "bbpress.topics.attachments.get");
    }

    #[test]
    fn reads_are_enabled_and_an_editable_endpoint_is_one_post_update() {
        let d = derived_forum(&["bbpress/v1"]);
        let list = cap(&d, "bbpress.topics.list");
        assert_eq!(list.risk, RiskTier::Medium);
        assert!(!disabled(&d, "bbpress.topics.list"));
        assert!(list.http.as_ref().unwrap().query_params.contains(&"per_page".to_string()));
        assert!(!disabled(&d, "bbpress.topics.get"));
        assert!(!disabled(&d, "bbpress.users.me.get"));

        let update = cap(&d, "bbpress.topics.update");
        let http = update.http.as_ref().unwrap();
        assert_eq!(http.method, HttpMethod::Post);
        assert_eq!(update.action, Action::Update);
        assert!(http.body_params.contains(&"content".to_string()));
        assert!(!http.body_params.contains(&"id".to_string()), "a path param is not also a body param");
        assert!(disabled(&d, "bbpress.topics.update"));
        assert!(!d.capabilities.iter().any(|c| c.http.as_ref().unwrap().method == HttpMethod::Put));

        let delete = cap(&d, "bbpress.topics.delete");
        assert_eq!(delete.http.as_ref().unwrap().query_params, ["force"]);
        assert_eq!(delete.risk, RiskTier::Critical);
        assert_eq!(cap(&d, "bbpress.topics.create").action, Action::Create);
        for c in &d.capabilities {
            assert!(matches!(c.http.as_ref().unwrap().auth, AuthScheme::Basic { key_as_username: false }));
            assert_eq!(c.http.as_ref().unwrap().base_url, "https://eventsmanagerpro.com/support/wp-json");
        }
    }

    #[test]
    fn writes_that_change_who_can_do_what_are_critical() {
        let d = derived_forum(&["wp/v2"]);
        for id in ["wp.users.create", "wp.users.update", "wp.users.me.update", "wp.plugins.update", "wp.plugins.create", "wp.settings.update", "wp.users.application_passwords.create"] {
            let c = cap(&d, id);
            assert_eq!(c.risk, RiskTier::Critical, "{id}");
            assert!(c.requires_approval, "{id}");
        }
        assert_eq!(cap(&d, "wp.users.list").risk, RiskTier::Medium);
        assert!(!disabled(&d, "wp.users.list"));
        let role = cap(&derived_forum(&["bbpress/v1"]), "bbpress.users.forum_role.update").clone();
        assert_eq!(role.risk, RiskTier::Critical);
    }

    #[test]
    fn unsupported_routes_are_skipped_and_reported() {
        let index = json!({
            "namespaces": ["demo/v1"],
            "routes": {
                "/demo/v1": { "namespace": "demo/v1", "endpoints": [{ "methods": ["GET"] }] },
                "/demo/v1/things(?:/(?P<id>\\d+))?": { "namespace": "demo/v1", "endpoints": [{ "methods": ["GET"], "args": [] }] },
                "/elsewhere/things": { "namespace": "demo/v1", "endpoints": [{ "methods": ["GET"], "args": [] }] },
                "/demo/v1/../admin": { "namespace": "demo/v1", "endpoints": [{ "methods": ["GET"], "args": [] }] },
                "/demo/v1/things": { "namespace": "demo/v1", "endpoints": [{ "methods": ["GET"], "args": {} }, { "methods": ["GET"], "args": {} }] }
            }
        });
        let d = derive(&index, &["demo/v1".into()], "c", "s", &pretty());
        let skipped: Vec<&str> = d.skipped.iter().map(|s| s.route.as_str()).collect();
        assert_eq!(skipped.len(), 3, "{:?}", d.skipped);
        assert!(skipped.contains(&"/demo/v1/things(?:/(?P<id>\\d+))?"));
        assert!(skipped.contains(&"/elsewhere/things"));
        assert!(skipped.contains(&"/demo/v1/../admin"));
        let ids: Vec<&str> = d.capabilities.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["c.demo.things.get", "c.demo.things.get_2"], "collisions get a numeric suffix");
    }

    #[test]
    fn query_routing_sends_the_full_route_as_rest_route() {
        let pin = RestPin { routing: Routing::Query, root: SITE.to_string() };
        let d = derive(&forum_query_style(), &["bbpress/v1".into()], "wp_forum", "s", &pin);
        let list = cap(&d, "bbpress.topics.list");
        let http = list.http.as_ref().unwrap();
        assert_eq!(http.base_url, "https://eventsmanagerpro.com/support/");
        assert_eq!(http.route_param.as_deref(), Some("rest_route"));
        assert_eq!(http.path, "/bbpress/v1/topics");
        let req = build_request(list, &json!({ "per_page": 5 }), b"sam:app pass").unwrap();
        assert_eq!(req.url, "https://eventsmanagerpro.com/support/?rest_route=/bbpress/v1/topics&per_page=5");
        assert!(req.headers["Authorization"].starts_with("Basic "));
    }

    #[test]
    fn a_preset_pin_folds_the_namespace_where_the_routing_allows() {
        assert_eq!(pretty().preset_pin("bbpress/v1"), (format!("{SITE}/wp-json/bbpress/v1"), None, None));
        let query = RestPin { routing: Routing::Query, root: SITE.to_string() };
        assert_eq!(
            query.preset_pin("bbpress/v1"),
            (format!("{SITE}/"), Some("rest_route".to_string()), Some("/bbpress/v1".to_string()))
        );
    }

    #[test]
    fn the_digest_covers_the_selected_namespaces_and_nothing_else() {
        let ns = vec!["bbpress/v1".to_string()];
        let base = digest(&forum(), Some(&ns));
        assert_eq!(base, digest(&forum(), Some(&ns)), "stable");

        let mut renamed = forum();
        renamed["name"] = json!("Another title");
        assert_eq!(digest(&renamed, Some(&ns)), base, "the site title is not the API");

        let mut other_ns = forum();
        other_ns["routes"]["/wp/v2/users"]["endpoints"][0]["methods"] = json!(["GET", "HEAD"]);
        assert_eq!(digest(&other_ns, Some(&ns)), base, "an unselected namespace is not reviewed");
        assert_ne!(digest(&other_ns, None), digest(&forum(), None));

        let mut changed = forum();
        changed["routes"]["/bbpress/v1/topics"]["endpoints"][0]["args"]["new_arg"] = json!({ "type": "string" });
        assert_ne!(digest(&changed, Some(&ns)), base, "a new argument is a change to review");
    }

    fn abilities() -> Vec<Value> {
        serde_json::from_str(ABILITIES).unwrap()
    }

    #[test]
    fn abilities_take_their_method_and_posture_from_annotations_and_never_lower_it() {
        let d = derive_abilities(&abilities(), "wp_forum", "sec", &pretty());
        let get = cap(&d, "abilities.bbpress_get_topic");
        let http = get.http.as_ref().unwrap();
        assert_eq!(http.method, HttpMethod::Get);
        assert_eq!(http.path, "/wp-abilities/v1/abilities/bbpress/get-topic/run");
        assert_eq!(http.query_params, ["input"]);
        assert_eq!(http.query_style, QueryStyle::Brackets);
        assert_eq!((get.action, get.risk, get.requires_approval), (Action::Execute, RiskTier::High, false), "readonly sets the method, not a safer posture");
        assert!(disabled(&d, "abilities.bbpress_get_topic"));
        let req = build_request(get, &json!({ "input": { "topic_id": 5 } }), b"u:p").unwrap();
        assert_eq!(req.url, "https://eventsmanagerpro.com/support/wp-json/wp-abilities/v1/abilities/bbpress/get-topic/run?input[topic_id]=5");

        let trash = cap(&d, "abilities.bbpress_trash_reply");
        assert_eq!(trash.http.as_ref().unwrap().method, HttpMethod::Delete);
        assert_eq!(trash.http.as_ref().unwrap().query_style, QueryStyle::Brackets);
        assert_eq!((trash.risk, trash.requires_approval), (RiskTier::Critical, true));

        let post = cap(&d, "abilities.bbpress_post_reply");
        let http = post.http.as_ref().unwrap();
        assert_eq!(http.method, HttpMethod::Post);
        assert_eq!(http.body_params, ["input"]);
        assert!(http.query_params.is_empty());
        assert_eq!((post.action, post.risk, post.requires_approval), (Action::Execute, RiskTier::High, false));
        assert!(disabled(&d, "abilities.bbpress_post_reply"));

        let merge = cap(&d, "abilities.bbpress_merge_topics");
        assert_eq!(merge.http.as_ref().unwrap().method, HttpMethod::Post, "destructive but not idempotent posts");
        assert_eq!(merge.risk, RiskTier::Critical);

        let purge = cap(&d, "abilities.bbpress_purge_spam_queue");
        assert_eq!(purge.http.as_ref().unwrap().method, HttpMethod::Get, "a readonly ability still reads");
        assert_eq!((purge.risk, purge.requires_approval), (RiskTier::Critical, true), "its name escalates it");
        assert!(disabled(&d, "abilities.bbpress_purge_spam_queue"));

        let skipped: Vec<&str> = d.skipped.iter().map(|s| s.route.as_str()).collect();
        assert_eq!(skipped, ["bbpress/hidden-tool", "bbpress/odd name"]);
        assert!(is_ability_capability("wp_forum", &get.id));
        assert!(!is_ability_capability("wp_forum", "wp_forum.bbpress.topics.list"));
    }

    /// The site writes an ability's annotations, so `readonly` decides the method WordPress demands and nothing safer: the ability keeps the posture it would have unannotated.
    #[test]
    fn a_readonly_annotation_cannot_make_an_ability_safer() {
        let ability = |annotations: Value| json!({ "name": "acme/rebuild-site-content", "label": "Rebuild content", "meta": { "annotations": annotations } });
        let annotated = derive_abilities(&[ability(json!({ "readonly": true }))], "wp_forum", "sec", &pretty());
        let plain = derive_abilities(&[ability(json!({}))], "wp_forum", "sec", &pretty());
        let (read, unread) = (cap(&annotated, "abilities.acme_rebuild_site_content"), cap(&plain, "abilities.acme_rebuild_site_content"));
        assert_eq!(read.http.as_ref().unwrap().method, HttpMethod::Get, "WordPress runs a readonly ability on GET");
        assert_eq!(unread.http.as_ref().unwrap().method, HttpMethod::Post);
        assert_eq!((read.action, read.risk, read.requires_approval), (unread.action, unread.risk, unread.requires_approval));
        assert_eq!((read.action, read.risk), (Action::Execute, RiskTier::High));
        assert!(annotated.disabled.contains(&read.id), "it is not reported as starting enabled either");
    }

    /// A read whose route names a destructive operation is held like a write that does: a cache plugin's `GET purge` changes something.
    #[test]
    fn a_read_whose_route_names_a_destructive_operation_is_critical() {
        let route = json!({ "namespace": "cachex/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] });
        let index = json!({ "namespaces": ["cachex/v1"], "routes": {
            "/cachex/v1": route, "/cachex/v1/purge": route, "/cachex/v1/blocks": route, "/cachex/v1/stats": route,
            "/cachex/v1/clear-cache": route, "/cachex/v1/sessions/logout": route, "/cachex/v1/presets": route,
            "/cachex/v1/swiper": route, "/cachex/v1/deleted": route } });
        let d = derive(&index, &["cachex/v1".into()], "wp_forum", "sec_c", &pretty());
        for operation in ["cachex.purge.get", "cachex.clear_cache.get", "cachex.sessions.logout.get", "cachex.deleted.get"] {
            let c = cap(&d, operation);
            assert_eq!((c.action, c.risk, c.requires_approval), (Action::Execute, RiskTier::Critical, true), "{operation} is no read, so no client is told it is read-only");
            assert!(disabled(&d, operation), "{operation}");
        }
        for read in ["cachex.blocks.get", "cachex.stats.get", "cachex.presets.get", "cachex.swiper.get"] {
            assert_eq!(cap(&d, read).risk, RiskTier::Medium, "{read} has no operation prefix or suffix");
            assert!(!disabled(&d, read), "{read}");
        }
    }

    /// The words are read below the namespace: a plugin whose namespace happens to name an operation does not escalate every read it serves.
    #[test]
    fn an_operation_word_in_the_namespace_escalates_nothing() {
        let route = json!({ "namespace": "password-reset/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] });
        let index = json!({ "namespaces": ["password-reset/v1"], "routes": { "/password-reset/v1": route, "/password-reset/v1/status": route } });
        let d = derive(&index, &["password-reset/v1".into()], "wp_forum", "sec_c", &pretty());
        assert_eq!(cap(&d, "password_reset.status.get").risk, RiskTier::Medium);
    }

    /// A route whose plugin declares a `_method` argument never forwards it: WordPress would run the call as the method it names.
    #[test]
    fn a_method_argument_is_never_imported() {
        let index = json!({ "namespaces": ["acme/v1"], "routes": {
            "/acme/v1": { "namespace": "acme/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] },
            "/acme/v1/posts": { "namespace": "acme/v1", "endpoints": [{ "methods": ["GET"], "args": { "_method": {}, "page": {} } }] } } });
        let d = derive(&index, &["acme/v1".into()], "wp_forum", "sec_c", &pretty());
        let list = cap(&d, "acme.posts.list");
        assert_eq!(list.http.as_ref().unwrap().query_params, ["page"]);
    }

    /// A stored ability or route keeps the posture it was derived with until something looks again, so the start-up pass reads today's floor from its shape alone.
    #[test]
    fn the_stored_floor_matches_what_derive_gives_today() {
        let readonly = derive_abilities(&[json!({ "name": "acme/list-topics", "meta": { "annotations": { "readonly": true } } })], "wp_forum", "sec", &pretty());
        let today = cap(&readonly, "abilities.acme_list_topics");
        assert_eq!(stored_floor("wp_forum", today, &[]), Some((today.action, today.risk, today.requires_approval)));
        let route = json!({ "namespace": "cachex/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] });
        let d = derive(&json!({ "namespaces": ["cachex/v1"], "routes": { "/cachex/v1": route, "/cachex/v1/purge": route, "/cachex/v1/stats": route } }), &["cachex/v1".into()], "wp_forum", "sec", &pretty());
        let ns = ["cachex/v1".to_string()];
        let purge = cap(&d, "cachex.purge.get");
        assert_eq!(stored_floor("wp_forum", purge, &ns), Some((purge.action, purge.risk, purge.requires_approval)));
        assert_eq!(stored_floor("wp_forum", cap(&d, "cachex.stats.get"), &ns), None);
    }

    #[test]
    fn a_slash_free_value_cannot_reach_a_literal_sibling_route() {
        let index = json!({ "namespaces": ["acme/v1"], "routes": {
            "/acme/v1": { "namespace": "acme/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] },
            "/acme/v1/export": { "namespace": "acme/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] },
            "/acme/v1/(?P<report>[\\w-]+)": { "namespace": "acme/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] } } });
        let pin = RestPin { routing: Routing::Pretty, root: "https://site.example/wp-json".into() };
        let d = derive(&index, &["acme/v1".into()], "c", "sec_c", &pin);
        assert!(d.disabled.contains(&"c.acme.export.get".to_string()));
        let generic = d.capabilities.iter().find(|c| c.id == "c.acme.get").unwrap();
        assert_eq!(build_request(generic, &json!({ "report": "export" }), b"u:p").unwrap_err().code, "path_identifier");
        assert_eq!(build_request(generic, &json!({ "report": "EXPORT" }), b"u:p").unwrap_err().code, "path_identifier", "WordPress matches routes case-insensitively");
        assert!(build_request(generic, &json!({ "report": "monthly" }), b"u:p").is_ok());
    }

    /// A route whose own pattern this gateway cannot compile still carries its siblings, which only ever refuse a value.
    #[test]
    fn a_route_read_without_its_pattern_still_refuses_a_sibling() {
        let index = json!({ "namespaces": ["acme/v1"], "routes": {
            "/acme/v1": { "namespace": "acme/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] },
            "/acme/v1/admin": { "namespace": "acme/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] },
            "/acme/v1/(?P<item>(?!x)[\\w-]+)": { "namespace": "acme/v1", "endpoints": [{ "methods": ["GET"], "args": {} }] } } });
        let d = derive(&index, &["acme/v1".into()], "wp_forum", "sec_c", &pretty());
        let generic = cap(&d, "acme.get");
        let http = generic.http.as_ref().unwrap();
        assert!(http.path_patterns.is_empty(), "the lookahead cannot be compiled here, so the strict rule holds");
        assert!(http.sibling_routes.contains(&"/acme/v1/admin".to_string()), "{:?}", http.sibling_routes);
        assert_eq!(build_request(generic, &json!({ "item": "admin" }), b"u:p").unwrap_err().code, "path_identifier");
        assert!(build_request(generic, &json!({ "item": "widgets" }), b"u:p").is_ok());
    }

    /// A capability the importer read and left without a pattern on purpose is not widened in place when a later index makes the pattern readable.
    #[test]
    fn a_pattern_read_and_left_strict_is_a_change_to_review() {
        let with = |patterns: bool, read: bool| {
            let mut c = abilities_list_capability("c", "sec", &pretty());
            let http = c.http.as_mut().unwrap();
            http.path = "/x/v1/items/{id}".into();
            http.path_params = vec!["id".into()];
            http.route_patterns_read = read;
            if patterns {
                http.path_patterns = BTreeMap::from([("id".to_string(), PathPattern { pattern: "(?i).+".into(), encode_slash: false })]);
            }
            c
        };
        assert!(!only_refreshes_route_context(&with(false, true), &with(true, true)), "read and refused before, so the new pattern is reviewed");
        assert!(only_refreshes_route_context(&with(false, false), &with(true, true)), "stored before patterns were read, so recording one is a refresh");
        assert!(only_refreshes_route_context(&with(true, true), &with(true, true)));
    }

    #[test]
    fn a_rest_namespace_called_abilities_cannot_collide_with_the_abilities_source() {
        assert_eq!(namespace_id("abilities/v1"), "abilities_rest");
        assert_eq!(namespace_id("events-manager/v1"), "events_manager");
    }

    /// A plugin in a directory is addressed the way the plugins route's own pattern names it, and a numeric route still refuses a value that would reach a sibling.
    #[test]
    fn a_path_parameter_is_held_to_its_routes_own_pattern() {
        let send = |c: &Capability, params: Value| build_request(c, &params, b"u:p");
        for (d, root) in [
            (derived_forum(&["wp/v2"]), format!("{SITE}/wp-json/wp/v2")),
            (
                derive(&forum(), &["wp/v2".to_string()], "wp_forum", "sec_wp_forum", &RestPin { routing: Routing::Query, root: SITE.into() }),
                format!("{SITE}/?rest_route=/wp/v2"),
            ),
        ] {
            let on = |path: &str| -> Vec<Capability> {
                d.capabilities.iter().filter(|c| c.http.as_ref().is_some_and(|h| h.path == path)).cloned().collect()
            };
            let plugin = on("/wp/v2/plugins/{plugin}");
            let methods: BTreeSet<&str> = plugin.iter().map(|c| c.http.as_ref().unwrap().method.as_str()).collect();
            assert_eq!(methods, BTreeSet::from(["GET", "POST", "DELETE"]), "read, update and delete");
            for c in &plugin {
                let req = send(c, json!({ "plugin": "akismet/akismet" })).unwrap();
                assert!(req.url.starts_with(&format!("{root}/plugins/akismet/akismet")), "{}: {}", c.id, req.url);
                for escape in ["akismet/akismet/x", "akismet%2Fakismet", "akismet%252Fakismet", "../users", "a\\b"] {
                    let refusal = send(c, json!({ "plugin": escape })).unwrap_err();
                    assert_eq!(refusal.code, "path_identifier", "{} {escape}", c.id);
                }
            }
            let user = on("/wp/v2/users/{id}");
            assert!(!user.is_empty());
            for c in &user {
                let req = send(c, json!({ "id": 42 })).unwrap();
                assert!(req.url.starts_with(&format!("{root}/users/42")), "{}", req.url);
                for escape in ["42/application-passwords", "42%2Fapplication-passwords", "42%252Fapplication-passwords", "me"] {
                    let refusal = send(c, json!({ "id": escape })).unwrap_err();
                    assert_eq!(refusal.code, "path_identifier", "{} {escape}", c.id);
                }
            }
        }
        let d = derived_forum(&["wp/v2"]);
        let plugins = d.capabilities.iter().find_map(|c| c.http.clone().filter(|h| h.path == "/wp/v2/plugins/{plugin}")).unwrap();
        assert_eq!(plugins.path_patterns["plugin"].pattern, "(?i)[^.\\/]+(?:\\/[^.\\/]+)?");
        assert!(!plugins.path_patterns["plugin"].encode_slash);
        assert!(plugins.route_patterns_read, "a re-sync can tell a route read without a pattern from one never read");
    }

    /// Each patterned capability carries the routes that take its method and could also match its path, so a '/' cannot carry the call to a sibling WordPress would serve first.
    #[test]
    fn a_patterned_capability_carries_its_sibling_routes() {
        let route = |methods: &[&str]| json!({ "namespace": "wp/v2", "endpoints": methods.iter().map(|m| json!({ "methods": [m], "args": {} })).collect::<Vec<_>>() });
        let variations = r"/wp/v2/global-styles/themes/(?P<stylesheet>[\/\s%\w\.\(\)\[\]\@_\-]+)/variations";
        let theme = r#"/wp/v2/global-styles/themes/(?P<stylesheet>[^\/:<>\*\?"\|]+(?:\/[^\/:<>\*\?"\|]+)?)"#;
        let index = json!({ "routes": {
            "/wp/v2": route(&["GET"]),
            variations: route(&["GET"]),
            theme: route(&["GET"]),
            "/wp/v2/global-styles/(?P<id>[\\/\\w-]+)": route(&["GET", "POST"]),
            "/wp/v2/posts/(?P<id>[\\d]+)": route(&["GET"]),
        }});
        let d = derive(&index, &["wp/v2".to_string()], "wp", "sec_wp", &RestPin { routing: Routing::Query, root: SITE.into() });
        let on = |method: &str| {
            d.capabilities
                .iter()
                .find(|c| c.http.as_ref().is_some_and(|h| h.path == "/wp/v2/global-styles/{id}" && h.method.as_str() == method))
                .unwrap_or_else(|| panic!("{method} global-styles: {:?}", d.capabilities.iter().map(|c| &c.id).collect::<Vec<_>>()))
        };
        let get = on("GET");
        let siblings = &get.http.as_ref().unwrap().sibling_routes;
        assert!(siblings.contains(&variations.to_string()) && siblings.contains(&theme.to_string()), "{siblings:?}");
        assert!(!siblings.iter().any(|r| r.starts_with("/wp/v2/posts")), "a route whose literal start differs is not a sibling: {siblings:?}");
        let refusal = build_request(get, &json!({ "id": "themes/twentytwentyfour/variations" }), b"u:p").unwrap_err();
        assert_eq!(refusal.code, "path_identifier");
        assert!(build_request(get, &json!({ "id": "17" }), b"u:p").is_ok());

        let update = on("POST");
        assert!(update.http.as_ref().unwrap().sibling_routes.is_empty(), "no other route takes POST here");
        assert!(build_request(update, &json!({ "id": "themes/twentytwentyfour/variations" }), b"u:p").is_ok());
    }

    #[test]
    fn route_parsing_keeps_named_group_patterns_whole() {
        let tokens = parse_route("/wp/v2/users/(?P<user_id>(?:[\\d]+|me))/application-passwords").unwrap();
        assert_eq!(tokens[1], Token::Param("user_id".into(), "(?:[\\d]+|me)".into()), "not a pure literal alternation");
        let tokens = parse_route("/wp/v2/plugins/(?P<plugin>[^.\\/]+(?:\\/[^.\\/]+)?)").unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(parse_route("/x/v1/(?P<a>[)]+)/y").is_ok(), "a bracket inside a class is not a group");
        assert!(parse_route("/x/v1/(?P<a>\\d+)/(?P<a>\\d+)").and_then(|t| expand(&t)).is_err());
    }

    #[test]
    fn the_link_header_parser_finds_the_api_relation() {
        let headers = vec![(
            "link".to_string(),
            "<https://example.com/?p=1>; rel=shortlink, <https://example.com/wp-json/>; rel=\"https://api.w.org/\"".to_string(),
        )];
        assert_eq!(api_link(&headers).as_deref(), Some("https://example.com/wp-json/"));
        assert_eq!(api_link(&[("link".into(), "<https://x/>; rel=next".into())]), None);
    }

    /// An ability as a site lists it, taking the input fields it was reviewed with when it has an entry.
    fn em(name: &str, readonly: bool, destructive: bool, idempotent: bool) -> Value {
        let fields: serde_json::Map<String, Value> =
            known_ability(name).map(|k| k.input.iter().map(|f| (f.clone(), json!({ "type": "string" }))).collect()).unwrap_or_default();
        json!({
            "name": name, "label": "L",
            "input_schema": { "type": "object", "properties": fields },
            "meta": { "annotations": { "readonly": readonly, "destructive": destructive, "idempotent": idempotent }, "show_in_rest": true }
        })
    }

    fn posture_of(ability: Value) -> (Action, RiskTier, bool) {
        let d = derive_abilities(&[ability], "wp_forum", "sec", &pretty());
        let c = &d.capabilities[0];
        (c.action, c.risk, c.requires_approval)
    }

    /// A reviewed ability that takes an input field the review did not see, or lists no input schema, has changed since it was reviewed, so it asks for approval again until it is.
    #[test]
    fn a_reviewed_ability_with_a_new_input_field_or_no_schema_gets_the_floor() {
        let reviewed = (Action::List, RiskTier::Medium, false);
        assert_eq!(posture_of(em("events-manager/list-events", true, false, true)), reviewed);

        let mut widened = em("events-manager/list-events", true, false, true);
        widened["input_schema"]["properties"]["delete_after"] = json!({ "type": "boolean" });
        let floor = posture_of(widened);
        assert_ne!(floor, reviewed);
        assert!(floor.1 >= RiskTier::High);

        let mut unschemed = em("events-manager/list-events", true, false, true);
        unschemed.as_object_mut().unwrap().remove("input_schema");
        assert_eq!(posture_of(unschemed), floor);

        let mut narrowed = em("events-manager/list-events", true, false, true);
        narrowed["input_schema"]["properties"].as_object_mut().unwrap().remove("search");
        assert_eq!(posture_of(narrowed), reviewed, "taking fewer fields is not a change to review");

        // PHP encodes an empty properties array as [].
        let mut empty = em("events-manager-pro/list-booking-forms", true, false, true);
        empty["input_schema"]["properties"] = json!([]);
        assert_eq!(posture_of(empty), reviewed);
    }

    #[test]
    fn every_reviewed_ability_parses_once_with_a_pinnable_name_and_a_reviewed_verb() {
        let known = known_abilities();
        assert!(known.len() > 50);
        let mut names = BTreeSet::new();
        for k in known {
            assert!(names.insert(k.name.as_str()), "{} listed twice", k.name);
            assert!(valid_ability_name(&k.name), "{}", k.name);
            assert_eq!(k.readonly, is_read(k.action), "{}: a read is registered readonly and nothing else is", k.name);
            assert!(!k.readonly || (k.risk == RiskTier::Medium && !k.requires_approval), "{}", k.name);
            assert!(k.action != Action::Delete || (k.risk == RiskTier::Critical && k.requires_approval), "{}", k.name);
            assert!(k.readonly || k.risk >= RiskTier::High, "{}: every write starts switched off", k.name);
        }
    }

    fn is_read(action: Action) -> bool {
        matches!(action, Action::Read | Action::List | Action::Search)
    }

    /// Events Manager registers its abilities with these annotations; each lands with the posture its REST route gets, and bookings ask first.
    #[test]
    fn a_reviewed_ability_registered_as_reviewed_lands_with_its_reviewed_posture() {
        let abilities = [
            em("events-manager/list-events", true, false, true),
            em("events-manager/update-event", false, true, false),
            em("events-manager/delete-booking", false, true, false),
            em("events-manager/set-booking-status", false, true, true),
        ];
        let d = derive_abilities(&abilities, "wp_forum", "sec", &pretty());
        let list = cap(&d, "abilities.events_manager_list_events");
        assert_eq!((list.action, list.risk, list.requires_approval), (Action::List, RiskTier::Medium, false));
        assert_eq!(list.http.as_ref().unwrap().method, HttpMethod::Get);
        assert!(!d.disabled.contains(&list.id), "a reviewed read is on when connected");
        let update = cap(&d, "abilities.events_manager_update_event");
        assert_eq!((update.action, update.risk, update.requires_approval), (Action::Update, RiskTier::High, false));
        assert!(d.disabled.contains(&update.id));
        let delete = cap(&d, "abilities.events_manager_delete_booking");
        assert_eq!((delete.action, delete.risk, delete.requires_approval), (Action::Delete, RiskTier::Critical, true));
        let status = cap(&d, "abilities.events_manager_set_booking_status");
        assert_eq!(status.http.as_ref().unwrap().method, HttpMethod::Delete);
        assert_eq!((status.action, status.risk, status.requires_approval), (Action::Update, RiskTier::High, true));
    }

    /// The site writes the annotations, so a reviewed name registered any other way is held to the floor every unreviewed ability gets.
    #[test]
    fn a_reviewed_name_registered_with_other_annotations_gets_the_floor() {
        let as_write = derive_abilities(&[em("events-manager/list-events", false, false, true)], "wp_forum", "sec", &pretty());
        let unreviewed = derive_abilities(&[em("acme/list-events", false, false, true)], "wp_forum", "sec", &pretty());
        let (a, b) = (cap(&as_write, "abilities.events_manager_list_events"), cap(&unreviewed, "abilities.acme_list_events"));
        assert_eq!((a.action, a.risk, a.requires_approval), (b.action, b.risk, b.requires_approval));
        assert!(a.risk >= RiskTier::High);

        let not_destructive = derive_abilities(&[em("events-manager/delete-event", false, false, false)], "wp_forum", "sec", &pretty());
        let delete = cap(&not_destructive, "abilities.events_manager_delete_event");
        assert_eq!((delete.risk, delete.requires_approval), (RiskTier::Critical, true), "the name's own operation word still holds");
    }

    /// The start-up pass reads the same reviewed posture back from a stored row, so it never raises what derive gave.
    #[test]
    fn the_stored_floor_of_a_reviewed_ability_is_its_reviewed_posture() {
        for k in known_abilities() {
            let d = derive_abilities(&[em(&k.name, k.readonly, k.destructive, k.idempotent)], "wp_forum", "sec", &pretty());
            let stored = &d.capabilities[0];
            assert_eq!(stored_floor("wp_forum", stored, &[]), Some((stored.action, stored.risk, stored.requires_approval)), "{}", k.name);
            assert_eq!(stored.http.as_ref().unwrap().method, k.method(), "{}", k.name);
        }
    }
}
