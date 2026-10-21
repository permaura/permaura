//! OpenAPI 3.x → Permaura capabilities importer: the no-code connector authoring path.
//!
//! An operator hands Permaura an OpenAPI document (pasted, or fetched from the host they bind) and the
//! importer turns each operation into a guarded [`Capability`] the gateway already understands, with
//! no hand-written Rust connector. For each operation it derives:
//! - a capability **id** (`{connection}.{operationId}`),
//! - a normalized [`Action`] and a default [`RiskTier`] from the shared [`classify`] rules, and
//!   whether it starts disabled ([`disabled_on_import`], the preset loader's rule),
//! - a pinned [`HttpSpec`]: method, base URL, path and the allow-listed path, query, header and body
//!   params, so the agent only fills documented params and can never redirect the call,
//! - the auth scheme, from `components.securitySchemes` unless the operator names one.
//!
//! [`derive`] is all of that and is pure: document bytes plus [`DeriveOptions`] in, a [`Derivation`]
//! out, so a re-sync can run it again against a newer document and diff the two. Fetching is separate
//! ([`fetch_document`]) and only ever requests the host the operator bound.
//!
//! A document is untrusted input that names its own server, so every `servers[].url` is resolved,
//! re-validated (https, no userinfo, query or fragment) and, for a fetched document, held to the bound
//! host before it can become a `base_url`. A `$ref` is followed only inside the document; an external
//! reference is reported and never fetched.
//!
//! The credential is referenced by **id** only: the secret value is never written into the imported
//! definitions, so a connector spec is safe to store and inspect.

use std::collections::{BTreeMap, BTreeSet};

use permaura_core::{Action, RiskTier};
use reqwest::Url;
use serde_json::{Map, Value};

use crate::connectors::connector::is_agent_settable_header;
use crate::connectors::{
    compile_path_pattern, AuthScheme, BodyStyle, Capability, CapabilityKind, HttpClient, HttpMethod, HttpRequest, HttpSpec,
    PathPattern,
};

/// Where [`probe`] looks for a document on the bound host, in order.
pub const PROBE_PATHS: &[&str] =
    &["/openapi.json", "/openapi.yaml", "/swagger.json", "/v3/api-docs", "/.well-known/openapi.json"];

/// How many `$ref` hops one lookup follows. Real documents chain two or three.
const MAX_REF_HOPS: usize = 16;

/// How deep `allOf` compositions are flattened into a request body's properties.
const MAX_ALLOF_DEPTH: usize = 8;

/// The operations a capability can pin, in the order they are emitted for a path.
const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

/// What a document fetch asks for: the two encodings an OpenAPI document comes in.
const ACCEPT_DOCUMENT: &str = "application/json, application/yaml;q=0.9, text/yaml;q=0.9, */*;q=0.1";

const SWAGGER_2: &str =
    "this is a Swagger 2.0 document, which the importer does not read: convert it to OpenAPI 3 and paste it";

/// What the importer needs besides the document. Nothing here comes from the document, so a re-sync
/// passes the values the connection was created with and gets a comparable [`Derivation`].
#[derive(Debug, Clone, Default)]
pub struct DeriveOptions {
    /// The connection id, which prefixes every capability id and becomes the policy scope.
    pub connection_id: String,
    /// The vault secret id the capabilities reference (a reference, never the value).
    pub secret_id: String,
    /// The URL the document was read from. A relative `servers[].url` resolves against it; `None` for
    /// a pasted document, whose relative servers therefore need `base_url`.
    pub spec_url: Option<String>,
    /// The host the operator bound. When set, every server and `base_url` must be on it, give or take
    /// a bare `www.`.
    pub bound_host: Option<String>,
    /// The operator's choice among the document's servers, or an explicit base for a document whose
    /// servers can't be pinned as written.
    pub base_url: Option<String>,
    /// The operator's auth scheme, replacing whatever `securitySchemes` implies.
    pub auth: Option<AuthScheme>,
}

/// Everything [`derive`] read from a document.
#[derive(Debug, Clone)]
pub struct Derivation {
    /// The pinned base URL, or `None` when the document offers several servers and none was chosen.
    pub base_url: Option<String>,
    /// Every server the document names that could be pinned, resolved and validated, in document order.
    pub servers: Vec<String>,
    /// How the credential is presented upstream.
    pub auth: AuthScheme,
    /// One capability per operation. Each carries the pinned base URL, which is empty while
    /// `base_url` is `None`, so such a set is only ever a preview.
    pub capabilities: Vec<Capability>,
    /// The capability ids that start switched off.
    pub disabled_capabilities: Vec<String>,
    /// What was dropped, guessed or refused, in words an operator can act on.
    pub warnings: Vec<String>,
}

/// Derive a connection's capabilities from an OpenAPI 3 document (JSON or YAML).
///
/// Errors are for a document that yields no connection at all: not OpenAPI 3, no operations, no server
/// that can be pinned (with none chosen), or an unusable `base_url` or `auth` override. Anything
/// smaller is dropped and reported in [`Derivation::warnings`].
pub fn derive(doc: &[u8], opts: &DeriveOptions) -> Result<Derivation, String> {
    let spec = parse_document(doc)?;
    match document_kind(&spec) {
        DocumentKind::OpenApi3 => {}
        DocumentKind::Swagger2 => return Err(SWAGGER_2.into()),
        DocumentKind::Other => return Err("not an OpenAPI 3 document: it has no `openapi: 3.x` version".into()),
    }
    let refs = Refs { root: &spec };
    let mut warnings = Vec::new();
    let (servers, base_url) = choose_server(&spec, opts, &mut warnings)?;
    let auth = match &opts.auth {
        Some(auth) => {
            check_auth(auth)?;
            auth.clone()
        }
        None => auth_from_document(doc, &spec, refs, &mut warnings),
    };

    let paths = spec.get("paths").and_then(Value::as_object).ok_or("OpenAPI document has no paths")?;
    let mut deriver = Deriver {
        refs,
        opts,
        auth: &auth,
        base_url: base_url.as_deref().unwrap_or(""),
        used_ids: BTreeSet::new(),
        warnings,
    };
    let mut capabilities = Vec::new();
    let mut disabled_capabilities = Vec::new();
    // Deterministic order so a re-import produces the same ids/order (tests + stable diffs).
    let mut path_keys: Vec<&String> = paths.keys().collect();
    path_keys.sort();
    for path in path_keys {
        let item = match refs.resolve(&paths[path]) {
            Ok(Value::Object(item)) => item,
            Ok(_) => continue,
            Err(why) => {
                deriver.warnings.push(format!("{path} dropped: {why}"));
                continue;
            }
        };
        if path.contains(['?', '#']) {
            deriver.warnings.push(format!("{path} skipped: a path template cannot carry a query or a fragment"));
            continue;
        }
        if item.contains_key("servers") {
            deriver.warnings.push(format!(
                "{path} names its own servers, which are ignored: its operations are pinned to the connection's base_url"
            ));
        }
        for method in ["head", "options", "trace"] {
            if item.contains_key(method) {
                let m = method.to_uppercase();
                deriver.warnings.push(format!("{m} {path} skipped: the gateway cannot pin a {m} call"));
            }
        }
        for method in METHODS {
            let Some(op) = item.get(method).and_then(Value::as_object) else { continue };
            let cap = deriver.capability(method, path, item, op);
            if disabled_on_import(cap.risk) {
                disabled_capabilities.push(cap.id.clone());
            }
            capabilities.push(cap);
        }
    }

    if capabilities.is_empty() {
        return Err("OpenAPI document defined no operations to import".into());
    }
    let warnings = deriver.warnings;
    Ok(Derivation { base_url, servers, auth, capabilities, disabled_capabilities, warnings })
}

/// Whether a derived capability starts switched off: High and above, the preset loader's default
/// (`PresetCap::starts_disabled`), so an imported connection lands with its writes off exactly as a
/// marketplace one does.
pub fn disabled_on_import(risk: RiskTier) -> bool {
    risk >= RiskTier::High
}

/// The digest a connection's `source` records: sha256 of the document bytes, hex.
pub fn digest(doc: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(doc).iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a document as JSON first, then YAML (an OpenAPI file is commonly either).
fn parse_document(doc: &[u8]) -> Result<Value, String> {
    if let Ok(v) = serde_json::from_slice::<Value>(doc) {
        return Ok(v);
    }
    serde_yaml::from_slice::<Value>(doc).map_err(|e| format!("not valid JSON or YAML: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentKind {
    OpenApi3,
    Swagger2,
    Other,
}

fn document_kind(spec: &Value) -> DocumentKind {
    if spec.get("openapi").and_then(Value::as_str).is_some_and(|v| v.starts_with("3.")) {
        DocumentKind::OpenApi3
    } else if spec.get("swagger").is_some() {
        DocumentKind::Swagger2
    } else {
        DocumentKind::Other
    }
}

fn sniff(doc: &[u8]) -> DocumentKind {
    parse_document(doc).map(|v| document_kind(&v)).unwrap_or(DocumentKind::Other)
}

/// Local `$ref` resolution over one document.
#[derive(Clone, Copy)]
struct Refs<'a> {
    root: &'a Value,
}

impl<'a> Refs<'a> {
    /// Follow `value`'s `$ref` chain to what it names. Only references into this document are
    /// followed, never a file or URL, and a chain that loops or runs past [`MAX_REF_HOPS`] is refused.
    fn resolve(&self, mut value: &'a Value) -> Result<&'a Value, String> {
        let mut seen: Vec<&'a str> = Vec::new();
        while let Some(target) = value.get("$ref").and_then(Value::as_str) {
            if seen.contains(&target) {
                return Err(format!("$ref {target} refers back to itself"));
            }
            if seen.len() == MAX_REF_HOPS {
                return Err(format!("$ref chain through {target} is longer than {MAX_REF_HOPS} hops"));
            }
            seen.push(target);
            let Some(fragment) = target.strip_prefix('#') else {
                return Err(format!(
                    "$ref {target} points outside this document, and external references are never fetched"
                ));
            };
            value = self
                .root
                .pointer(&percent_decode(fragment))
                .ok_or_else(|| format!("$ref {target} names nothing in this document"))?;
        }
        Ok(value)
    }
}

/// Undo the percent-encoding a JSON pointer may carry inside a URI fragment (`#/paths/~1pets%7Bid%7D`).
fn percent_decode(s: &str) -> String {
    let hex = |b: Option<&u8>| b.and_then(|b| (*b as char).to_digit(16)).map(|d| d as u8);
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(hi), Some(lo)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Servers ──────────────────────────────────────────────────────────────────────

/// Resolve and validate the document's servers, then pick the one to pin: the operator's `base_url`,
/// else the only usable server, else none (several candidates and no choice).
fn choose_server(
    spec: &Value,
    opts: &DeriveOptions,
    warnings: &mut Vec<String>,
) -> Result<(Vec<String>, Option<String>), String> {
    let bound = opts.bound_host.as_deref();
    let declared = spec.get("servers").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let mut servers: Vec<String> = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    for server in declared {
        let Some(raw) = server.get("url").and_then(Value::as_str) else { continue };
        let pinned = substitute_variables(raw, server.get("variables"))
            .and_then(|url| resolve_against(&url, opts.spec_url.as_deref()))
            .and_then(|url| check_pin(&url, bound));
        match pinned {
            Ok(url) if !servers.contains(&url) => servers.push(url),
            Ok(_) => {}
            Err(why) => refused.push(format!("server {raw} {why}")),
        }
    }
    // OpenAPI's default when no server is named is `/`: the root of wherever the document was served.
    if declared.is_empty() {
        if let Some(spec_url) = opts.spec_url.as_deref() {
            match resolve_against("/", Some(spec_url)).and_then(|url| check_pin(&url, bound)) {
                Ok(url) => servers.push(url),
                Err(why) => refused.push(format!("the default server {why}")),
            }
        }
    }
    warnings.extend(refused.iter().cloned());

    if let Some(raw) = opts.base_url.as_deref() {
        let chosen = check_pin(raw, bound).map_err(|why| format!("base_url {why}"))?;
        if !servers.contains(&chosen) {
            warnings.push(format!("base_url {chosen} is not one of the document's servers; it is pinned because you chose it"));
        }
        return Ok((servers, Some(chosen)));
    }
    let chosen = match servers.len() {
        1 => Some(servers[0].clone()),
        0 if refused.is_empty() => return Err("the document names no server; supply base_url".into()),
        0 => {
            return Err(format!("the document names no usable server ({}); supply base_url", refused.join("; ")))
        }
        _ => None,
    };
    Ok((servers, chosen))
}

/// Replace each `{name}` in a server URL with that variable's `default`.
fn substitute_variables(raw: &str, variables: Option<&Value>) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after.find('}').ok_or("has an unclosed {")?;
        let name = &after[..close];
        let default = variables
            .and_then(|v| v.get(name))
            .and_then(|v| v.get("default"))
            .and_then(|d| d.as_str().map(str::to_string).or_else(|| d.as_u64().map(|n| n.to_string())))
            .ok_or_else(|| format!("uses variable {{{name}}} with no default"))?;
        out.push_str(&default);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Resolve a server URL against the document's own URL (RFC 3986), which is how OpenAPI reads a
/// relative server. A pasted document has no URL, so its relative servers can't be resolved.
fn resolve_against(url: &str, spec_url: Option<&str>) -> Result<String, String> {
    if Url::parse(url).is_ok() {
        return Ok(url.to_string());
    }
    let Some(base) = spec_url else {
        return Err("is relative and the document was pasted, so there is nothing to resolve it against".into());
    };
    let base = Url::parse(base).map_err(|e| format!("could not be resolved: {e}"))?;
    let url = if url.is_empty() { "/" } else { url };
    base.join(url).map(String::from).map_err(|e| format!("could not be resolved: {e}"))
}

/// Check a URL that is about to become a connection's pinned `base_url`, returning it normalized with
/// no trailing slash. The rules of `rest::validate_override_base_url` (https, a host, no userinfo,
/// query or fragment), plus: no unfilled `{variable}`, not an address the egress guard blocks, and on
/// the bound host when there is one.
fn check_pin(raw: &str, bound_host: Option<&str>) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("must not be empty".into());
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("must not contain whitespace or control characters".into());
    }
    // https only: a downgrade to http would send the injected credential in the clear.
    if !raw.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")) {
        return Err("must be an absolute https:// URL".into());
    }
    let parsed = Url::parse(raw).map_err(|e| format!("is not a valid URL: {e}"))?;
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err("must include a host".into());
    }
    // The raw authority is checked too, so an empty `@` the parser drops is still refused.
    if !parsed.username().is_empty() || parsed.password().is_some() || raw[8..].split(['/', '?', '#']).next().is_some_and(|a| a.contains('@')) {
        return Err("must not contain userinfo (user:pass@host)".into());
    }
    if raw.contains(['?', '#']) {
        return Err("must not contain a query string or fragment".into());
    }
    if raw.contains(['{', '}']) {
        return Err("has an unfilled {variable}".into());
    }
    if crate::connectors::url_host(raw).is_none() {
        return Err("is not a URL the gateway can send to (a backslash in the host is refused)".into());
    }
    let url = Url::parse(raw).map_err(|e| format!("is not a valid URL: {e}"))?;
    let host = url.host_str().ok_or("must include a host")?;
    crate::connectors::screen_url(url.as_str()).map_err(|e| format!("is refused: {e}"))?;
    if let Some(bound) = bound_host {
        if !same_host(host, bound) {
            return Err(format!("is on {host}, not the bound host {bound}"));
        }
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// Whether two hosts are the same site, allowing only a bare `www.` difference.
fn same_host(a: &str, b: &str) -> bool {
    let norm = |h: &str| {
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        h.strip_prefix("www.").map(str::to_string).unwrap_or(h)
    };
    norm(a) == norm(b)
}

// ── Auth ────────────────────────────────────────────────────────────────────────

/// The auth scheme the document asks for: the one its top-level `security` requirement names, else
/// the first it declares. Anything the gateway cannot present falls back to Bearer with a warning.
fn auth_from_document(doc: &[u8], spec: &Value, refs: Refs<'_>, warnings: &mut Vec<String>) -> AuthScheme {
    let schemes = spec.pointer("/components/securitySchemes").and_then(Value::as_object).filter(|s| !s.is_empty());
    let Some(schemes) = schemes else {
        warnings.push(
            "the document declares no securitySchemes, so the credential is sent as a Bearer token (pass auth to change it)"
                .into(),
        );
        return AuthScheme::Bearer;
    };
    let name = required_scheme(spec, schemes, warnings).or_else(|| {
        if schemes.len() == 1 {
            return schemes.keys().next().cloned();
        }
        let first = scheme_order(doc)
            .into_iter()
            .find(|n| schemes.contains_key(n))
            .or_else(|| schemes.keys().next().cloned())?;
        warnings.push(format!(
            "the document declares {} security schemes and no top-level security requirement; '{first}' is used (pass auth to choose another)",
            schemes.len()
        ));
        Some(first)
    });
    let Some(name) = name else { return AuthScheme::Bearer };
    match refs.resolve(&schemes[&name]) {
        Ok(scheme) => map_scheme(&name, scheme, warnings),
        Err(why) => {
            warnings.push(format!(
                "security scheme '{name}' could not be read ({why}), so the credential is sent as a Bearer token"
            ));
            AuthScheme::Bearer
        }
    }
}

/// The scheme the document's top-level `security` names. Alternatives are tried in order; the
/// schemes within one requirement are all required together, and the gateway injects one credential.
fn required_scheme(spec: &Value, schemes: &Map<String, Value>, warnings: &mut Vec<String>) -> Option<String> {
    for requirement in spec.get("security")?.as_array()? {
        let Some(requirement) = requirement.as_object() else { continue };
        let named: Vec<&String> = requirement.keys().filter(|k| schemes.contains_key(*k)).collect();
        let Some(first) = named.first() else { continue };
        if named.len() > 1 {
            let all: Vec<String> = named.iter().map(|n| format!("'{n}'")).collect();
            warnings.push(format!(
                "the document requires {} together; only '{first}' is sent (pass auth if that is the wrong one)",
                all.join(" and ")
            ));
        }
        return Some((*first).clone());
    }
    None
}

/// `securitySchemes` names in the order the author wrote them. The JSON value the importer works on
/// keeps keys sorted, and "the first scheme" should not mean the alphabetically first.
fn scheme_order(doc: &[u8]) -> Vec<String> {
    let Ok(doc) = serde_yaml::from_slice::<serde_yaml::Value>(doc) else { return Vec::new() };
    doc.get("components")
        .and_then(|c| c.get("securitySchemes"))
        .and_then(serde_yaml::Value::as_mapping)
        .map(|m| m.keys().filter_map(|k| k.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Map one OpenAPI security scheme onto the [`AuthScheme`] the gateway presents.
fn map_scheme(name: &str, scheme: &Value, warnings: &mut Vec<String>) -> AuthScheme {
    let field = |key: &str| scheme.get(key).and_then(Value::as_str).unwrap_or("");
    let mut fallback = |why: String| {
        warnings.push(format!("security scheme '{name}' {why}, so the credential is sent as a Bearer token"));
        AuthScheme::Bearer
    };
    match field("type").to_ascii_lowercase().as_str() {
        "http" => match field("scheme").to_ascii_lowercase().as_str() {
            "bearer" => AuthScheme::Bearer,
            "basic" => AuthScheme::Basic { key_as_username: false },
            other => fallback(format!("is HTTP '{other}', which the gateway cannot present")),
        },
        "apikey" => match (field("in"), field("name")) {
            ("header", header) if credential_header_ok(header) => AuthScheme::ApiKeyHeader { header: header.into() },
            ("query", param) if !param.trim().is_empty() => AuthScheme::ApiKeyQuery { param: param.into() },
            ("cookie", _) => fallback("sends its key in a cookie, which the gateway does not support".into()),
            (location, key) => fallback(format!("has an unusable apiKey location ('{location}', '{key}')")),
        },
        "oauth2" | "openidconnect" => {
            warnings.push(format!(
                "security scheme '{name}' is OAuth: seal an access token, which is sent as a Bearer token and not refreshed"
            ));
            AuthScheme::Bearer
        }
        other => fallback(format!("has type '{other}', which the gateway does not support")),
    }
}

/// Whether a header can carry the credential: a real header token, and not one that frames or routes
/// the request.
fn credential_header_ok(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        && !matches!(
            n.as_str(),
            "host" | "content-length" | "content-type" | "transfer-encoding" | "connection" | "te" | "upgrade"
                | "cookie" | "proxy-authorization" | "metadata-flavor"
        )
}

/// Refuse an operator-supplied scheme that could not be sent.
fn check_auth(auth: &AuthScheme) -> Result<(), String> {
    match auth {
        AuthScheme::ApiKeyHeader { header } | AuthScheme::Raw { header, .. } if !credential_header_ok(header) => {
            Err(format!("auth header '{header}' cannot carry a credential"))
        }
        AuthScheme::Raw { prefix, .. } if prefix.contains(['\r', '\n']) => {
            Err("auth prefix must not contain CR or LF".into())
        }
        AuthScheme::ApiKeyQuery { param } if param.trim().is_empty() => Err("auth param must not be empty".into()),
        _ => Ok(()),
    }
}

/// The header the credential travels in, if any, so a parameter of the same name is not also offered
/// to the agent.
fn credential_header(auth: &AuthScheme) -> Option<&str> {
    match auth {
        AuthScheme::Bearer | AuthScheme::Basic { .. } => Some("Authorization"),
        AuthScheme::ApiKeyHeader { header } | AuthScheme::Raw { header, .. } => Some(header),
        AuthScheme::ApiKeyQuery { .. } => None,
    }
}

// ── Operations ──────────────────────────────────────────────────────────────────

/// The per-document state one derivation threads through its operations.
struct Deriver<'a> {
    refs: Refs<'a>,
    opts: &'a DeriveOptions,
    auth: &'a AuthScheme,
    base_url: &'a str,
    used_ids: BTreeSet<String>,
    warnings: Vec<String>,
}

#[derive(Default)]
struct OpParams {
    path: Vec<String>,
    path_patterns: BTreeMap<String, PathPattern>,
    query: Vec<String>,
    header: Vec<String>,
}

impl<'a> Deriver<'a> {
    fn capability(
        &mut self,
        method: &str,
        path: &str,
        item: &'a Map<String, Value>,
        op: &'a Map<String, Value>,
    ) -> Capability {
        let ctx = format!("{} {path}", method.to_uppercase());
        let operation_id = op
            .get("operationId")
            .and_then(|v| v.as_str())
            .map(sanitize_id_segment)
            .unwrap_or_else(|| format!("{method}_{}", sanitize_id_segment(path)));
        let id = self.unique_id(&operation_id, &ctx);

        let description = op
            .get("summary")
            .or_else(|| op.get("description"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{} {path}", method.to_uppercase()));

        let (action, risk, requires_approval) = shape_floor(method, path, &operation_id);
        if op.contains_key("servers") {
            self.warnings.push(format!(
                "{ctx} names its own servers, which are ignored: it is pinned to the connection's base_url"
            ));
        }
        let params = self.params(item.get("parameters"), op.get("parameters"), path, &ctx);
        let (body_params, body_style) = self.body_params(op, &ctx);

        Capability {
            id,
            description,
            risk,
            action,
            requires_approval,
            resource: self.opts.connection_id.clone(),
            secret_id: self.opts.secret_id.clone(),
            kind: CapabilityKind::Http,
            command: None,
            http: Some(HttpSpec {
                method: parse_method(method),
                base_url: self.base_url.to_string(),
                // A path key without its leading slash would be joined onto the base's host.
                path: if path.starts_with('/') { path.to_string() } else { format!("/{path}") },
                path_params: params.path,
                path_patterns: params.path_patterns,
                query_params: params.query,
                body_params,
                body_style,
                auth: self.auth.clone(),
                header_params: params.header,
                ..Default::default()
            }),
            ssh: None,
        }
    }

    /// `{connection}.{operationId}`, suffixed when two operations share an operationId, so one never
    /// overwrites the other in the store.
    fn unique_id(&mut self, operation_id: &str, ctx: &str) -> String {
        let base = format!("{}.{operation_id}", self.opts.connection_id);
        let mut id = base.clone();
        let mut n = 2;
        while self.used_ids.contains(&id) {
            id = format!("{base}_{n}");
            n += 1;
        }
        if id != base {
            self.warnings.push(format!("{ctx}: operationId '{operation_id}' is already taken, so this capability is '{id}'"));
        }
        self.used_ids.insert(id.clone());
        id
    }

    /// The operation's parameters by location: the path item's shared list merged with the
    /// operation's own, where the operation's wins on the same name and location.
    fn params(&mut self, shared: Option<&'a Value>, own: Option<&'a Value>, path: &str, ctx: &str) -> OpParams {
        let mut merged: Vec<(String, String, Option<String>)> = Vec::new();
        for list in [shared, own].into_iter().flatten().filter_map(Value::as_array) {
            for p in list {
                let p = match self.refs.resolve(p) {
                    Ok(p) => p,
                    Err(why) => {
                        self.warnings.push(format!("{ctx}: a parameter was dropped: {why}"));
                        continue;
                    }
                };
                let name = p.get("name").and_then(Value::as_str);
                let location = p.get("in").and_then(Value::as_str);
                let (Some(name), Some(location)) = (name, location) else {
                    self.warnings.push(format!("{ctx}: a parameter with no name or location was dropped"));
                    continue;
                };
                // Only name, location and pattern are kept, so the operation's own definition replacing a
                // shared one of the same name and location leaves nothing to merge.
                if !merged.iter().any(|(n, l, _)| n == name && l == location) {
                    merged.push((name.to_string(), location.to_string(), self.anchored_pattern(p)));
                }
            }
        }

        let credential_header = credential_header(self.auth);
        let mut out = OpParams::default();
        for (name, location, pattern) in merged {
            match location.as_str() {
                "path" => {
                    if let Some(pattern) = pattern {
                        out.path_patterns.insert(name.clone(), PathPattern { pattern, encode_slash: true });
                    }
                    out.path.push(name)
                }
                "query" => match self.auth {
                    AuthScheme::ApiKeyQuery { param } if *param == name => self.warnings.push(format!(
                        "{ctx}: query parameter '{name}' is the credential, which the gateway adds itself"
                    )),
                    _ if crate::connectors::is_method_override_param(&name) => self.warnings.push(format!(
                        "{ctx}: query parameter '{name}' dropped: it asks the upstream to run the call as another method"
                    )),
                    _ => out.query.push(name),
                },
                "header" => {
                    // OpenAPI itself says these three are ignored as parameters.
                    if matches!(name.to_ascii_lowercase().as_str(), "accept" | "content-type" | "authorization") {
                        continue;
                    }
                    if credential_header.is_some_and(|h| h.eq_ignore_ascii_case(&name)) {
                        self.warnings.push(format!(
                            "{ctx}: header '{name}' is the credential, which the gateway sets itself"
                        ));
                    } else if !is_agent_settable_header(&name) {
                        self.warnings.push(format!(
                            "{ctx}: header '{name}' dropped: it looks like a credential or transport header, which an agent may not set"
                        ));
                    } else {
                        out.header.push(name);
                    }
                }
                "cookie" => self
                    .warnings
                    .push(format!("{ctx}: cookie parameter '{name}' dropped: the gateway does not send cookies")),
                other => self.warnings.push(format!("{ctx}: parameter '{name}' in '{other}' dropped: unknown location")),
            }
        }
        // A template segment no parameter declares could never be filled, which leaves the literal
        // `{name}` in every request; accept it as a path parameter instead.
        for var in template_vars(path) {
            if !out.path.contains(&var) {
                self.warnings.push(format!(
                    "{ctx}: path segment {{{var}}} has no declared parameter; it is accepted as a path parameter"
                ));
                out.path.push(var);
            }
        }
        out
    }

    /// A parameter's schema `pattern` (OpenAPI 3) or own `pattern` (Swagger 2), kept only when it is
    /// anchored at both ends, where whole-value matching is what the document already says.
    fn anchored_pattern(&self, param: &Value) -> Option<String> {
        let schema = param.get("schema").and_then(|s| self.refs.resolve(s).ok());
        let pattern = schema.and_then(|s| s.get("pattern")).or_else(|| param.get("pattern")).and_then(Value::as_str)?;
        let anchored = pattern.starts_with('^') && pattern.ends_with('$') && !pattern.ends_with("\\$");
        (anchored && compile_path_pattern(pattern).is_some()).then(|| pattern.to_string())
    }

    /// The request body's top-level property names, each allowed as a body param, and how they are
    /// encoded: JSON when the operation offers it, otherwise a form body when it offers that.
    fn body_params(&mut self, op: &'a Map<String, Value>, ctx: &str) -> (Vec<String>, BodyStyle) {
        let none = (Vec::new(), BodyStyle::Json);
        let Some(body) = op.get("requestBody") else { return none };
        let body = match self.refs.resolve(body) {
            Ok(body) => body,
            Err(why) => {
                self.warnings.push(format!("{ctx}: request body dropped: {why}"));
                return none;
            }
        };
        let Some(content) = body.get("content").and_then(Value::as_object) else { return none };
        let json = content.iter().find(|(t, _)| is_json_media_type(t)).map(|(_, m)| (m, BodyStyle::Json));
        let form = || content.iter().find(|(t, _)| is_form_media_type(t)).map(|(_, m)| (m, BodyStyle::Form));
        let Some((media, style)) = json.or_else(form) else {
            let types: Vec<&str> = content.keys().map(String::as_str).collect();
            self.warnings.push(format!(
                "{ctx}: request body is {}, neither JSON nor a urlencoded form, so it has no body parameters",
                types.join(", ")
            ));
            return none;
        };
        let Some(schema) = media.get("schema") else { return (Vec::new(), style) };
        let mut names = Vec::new();
        let taken = self.properties(schema, 0, &mut names);
        if names.iter().any(|n| crate::connectors::is_method_override_param(n)) {
            self.warnings.push(format!("{ctx}: body property '_method' dropped: it asks the upstream to run the call as another method"));
            names.retain(|n| !crate::connectors::is_method_override_param(n));
        }
        match taken {
            Ok(()) if names.is_empty() => {
                self.warnings.push(format!("{ctx}: request body declares no properties, so it has no body parameters"));
            }
            Ok(()) => {}
            Err(why) => {
                self.warnings.push(format!("{ctx}: no body parameters taken: {why}"));
                names.clear();
            }
        }
        (names, style)
    }

    /// Collect an object schema's property names, shallow-merging `allOf`. A `oneOf` or `anyOf` has
    /// no single set of properties to allow, so it is an error rather than a guess.
    fn properties(&self, schema: &'a Value, depth: usize, out: &mut Vec<String>) -> Result<(), String> {
        if depth > MAX_ALLOF_DEPTH {
            return Err(format!("allOf nests more than {MAX_ALLOF_DEPTH} deep, which is taken as a cycle"));
        }
        let schema = self.refs.resolve(schema)?;
        if schema.get("oneOf").is_some() || schema.get("anyOf").is_some() {
            return Err("the body schema is a oneOf/anyOf, which has no single set of properties".into());
        }
        if let Some(parts) = schema.get("allOf").and_then(Value::as_array) {
            for part in parts {
                self.properties(part, depth + 1, out)?;
            }
        }
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            for name in props.keys() {
                if !out.contains(name) {
                    out.push(name.clone());
                }
            }
        } else if let Some(kind) = schema.get("type").and_then(Value::as_str).filter(|k| *k != "object") {
            return Err(format!("the body is a {kind}, not an object"));
        }
        Ok(())
    }
}

fn is_json_media_type(media_type: &str) -> bool {
    let t = media_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    t == "application/json" || t.ends_with("+json")
}

fn is_form_media_type(media_type: &str) -> bool {
    media_type.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/x-www-form-urlencoded")
}

/// The `{name}` segments of a path template.
fn template_vars(path: &str) -> Vec<String> {
    path.split('{')
        .skip(1)
        .filter_map(|s| s.split_once('}').map(|(name, _)| name.to_string()))
        .filter(|n| !n.is_empty())
        .collect()
}

/// Map an HTTP method + path + operationId to a normalized [`Action`], a default [`RiskTier`], and
/// whether the capability always escalates to human approval. Payment-sensitive verbs (refund,
/// charge) and destructive verbs (delete) default to Critical + approval; the operator confirms.
/// Shared with the preset loader ([`crate::presets`]) so a curated preset capability and an
/// OpenAPI-imported one get the same risk posture from the same rules.
pub(crate) fn classify(method: &str, path: &str, operation_id: &str) -> (Action, RiskTier, bool) {
    let method = method.to_ascii_lowercase();
    let hay = format!("{} {}", path.to_lowercase(), operation_id.to_lowercase());
    // Money-movement keywords escalate to Critical only for *mutating* methods: a GET whose name
    // merely contains "charges"/"transfers" (listing or reading them) is a safe read, not a payment.
    let mutating = matches!(method.as_str(), "post" | "put" | "patch" | "delete");
    if mutating && hay.contains("refund") {
        return (Action::Refund, RiskTier::Critical, true);
    }
    if mutating
        && (hay.contains("charge") || hay.contains("capture") || hay.contains("payout") || hay.contains("transfer"))
    {
        return (Action::Charge, RiskTier::Critical, true);
    }
    match method.as_str() {
        "delete" => (Action::Delete, RiskTier::Critical, true),
        "post" => (Action::Create, RiskTier::High, false),
        "put" | "patch" => (Action::Update, RiskTier::High, false),
        "get" => {
            if operation_id.to_lowercase().contains("export") {
                (Action::Export, RiskTier::High, false)
            } else if path.contains('{') {
                (Action::Read, RiskTier::Medium, false)
            } else {
                (Action::Search, RiskTier::Medium, false)
            }
        }
        _ => (Action::Execute, RiskTier::Medium, false),
    }
}

/// Words naming an operation rather than a thing. A call whose literal path has one as a whole word
/// changes something whatever method it is sent with (a plugin's `GET /purge`, `GET /clear-cache`), so a
/// `GET` naming one is no read. Match a word prefix or suffix, including compounds such as
/// `purgeall` and `flushcache`, while leaving interior matches such as `presets` and `swiper` alone.
pub(crate) const OPERATION_WORDS: &[&str] = &[
    "trash", "delete", "destroy", "purge", "remove", "flush", "reset", "wipe", "clear", "empty", "revoke",
    "deactivate", "disable", "uninstall", "cancel", "invalidate", "logout", "disconnect", "unsubscribe", "regenerate", "trigger",
];

/// The lowercased words of a path's literal text: percent-decoded, `{placeholders}` dropped, and split
/// on `/`, `-`, `_`, `.` and a lower-to-upper case change (`clearCache` is two words).
pub(crate) fn path_words(path: &str) -> Vec<String> {
    let decoded = percent_decoded(path);
    let mut literal = String::with_capacity(decoded.len());
    let mut depth = 0usize;
    for c in decoded.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => literal.push(c),
            _ => {}
        }
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut prev_lower = false;
    for c in literal.chars() {
        let split = matches!(c, '/' | '-' | '_' | '.' | '?' | '&' | '=' | ' ') || (c.is_uppercase() && prev_lower);
        if split && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        if c.is_alphanumeric() {
            word.extend(c.to_lowercase());
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

fn percent_decoded(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a literal path word starts or ends with one of the [`OPERATION_WORDS`].
pub(crate) fn names_an_operation(path: &str) -> bool {
    path_words(path).iter().any(|w| OPERATION_WORDS.iter().any(|op| w.starts_with(op) || w.ends_with(op)))
}

/// The posture a document someone outside Permaura wrote gets from a line's method and path alone,
/// before anything it says about itself: [`classify`], with the path read as well as the operation id,
/// since an unsigned author chooses the id. A `GET` whose path names an operation is
/// Execute, Critical and approval on every call; one whose path says `export` is an Export.
pub(crate) fn shape_floor(method: &str, path: &str, operation_id: &str) -> (Action, RiskTier, bool) {
    let floor = classify(method, path, operation_id);
    if !method.eq_ignore_ascii_case("get") {
        return floor;
    }
    if names_an_operation(path) {
        return (Action::Execute, RiskTier::Critical, true);
    }
    if floor.0 != Action::Export && path_words(path).iter().any(|w| w == "export") {
        return (Action::Export, RiskTier::High, floor.2);
    }
    floor
}

fn parse_method(method: &str) -> HttpMethod {
    match method {
        "post" => HttpMethod::Post,
        "put" => HttpMethod::Put,
        "patch" => HttpMethod::Patch,
        "delete" => HttpMethod::Delete,
        _ => HttpMethod::Get,
    }
}

/// Keep an id segment to a safe charset (the capability id is `connector.action`-validated, and a
/// connector id flows into URLs and policy keys). Non-alphanumerics collapse to nothing or `_`.
fn sanitize_id_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if matches!(c, '_' | '-') {
            out.push('_');
        }
        // drop slashes, braces, dots, spaces: they'd break the `connector.action` id form
    }
    if out.is_empty() {
        "op".to_string()
    } else {
        out
    }
}

// ── Fetching ────────────────────────────────────────────────────────────────────

/// A document, the URL it was read from, and the host the operator bound.
#[derive(Debug, Clone)]
pub struct FetchedDocument {
    /// Where the document was read from; recorded as the connection's `source.url`.
    pub url: String,
    /// The host every server must be on.
    pub bound_host: String,
    /// The document as served (read as UTF-8), which is what the digest covers.
    pub bytes: Vec<u8>,
}

/// Read the document an operator pointed at, through the gateway's egress-guarded client: `spec_url`
/// when given (it must be on the bound host), otherwise [`probe`] the bound `url`. The bound host is
/// `url`'s, or `spec_url`'s when it stands alone.
pub async fn fetch_document(
    http: &dyn HttpClient,
    url: Option<&str>,
    spec_url: Option<&str>,
) -> Result<FetchedDocument, String> {
    let bound = url.map(|raw| parse_bound_url(raw).map_err(|why| format!("url {why}"))).transpose()?;
    let spec = spec_url.map(|raw| parse_bound_url(raw).map_err(|why| format!("spec_url {why}"))).transpose()?;
    match (bound, spec) {
        (Some(bound), Some(spec)) => {
            let (bound_host, spec_host) = (host_of(&bound), host_of(&spec));
            if !same_host(&spec_host, &bound_host) {
                return Err(format!("spec_url is on {spec_host}, not the bound host {bound_host}"));
            }
            fetch_spec(http, &spec, bound_host).await
        }
        (None, Some(spec)) => {
            let bound_host = host_of(&spec);
            fetch_spec(http, &spec, bound_host).await
        }
        (Some(bound), None) => probe(http, &bound).await,
        (None, None) => Err("url or spec_url is required".into()),
    }
}

/// Check a URL the operator entered before anything is requested from it: https, a host, no userinfo
/// or fragment, and not an address the egress guard blocks. A query is allowed (some specs are served
/// as `?format=json`); probing ignores it.
fn parse_bound_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw.trim()).map_err(|_| "must be an absolute https:// URL".to_string())?;
    if url.scheme() != "https" {
        return Err("must be an absolute https:// URL".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain userinfo (user:pass@host)".into());
    }
    if url.fragment().is_some() {
        return Err("must not contain a fragment".into());
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("must include a host".into());
    }
    if crate::connectors::url_host(raw.trim()).is_none() {
        return Err("has a backslash or a control character where its host is read".into());
    }
    crate::connectors::screen_url(url.as_str()).map_err(|e| format!("is refused: {e}"))?;
    Ok(url)
}

fn host_of(url: &Url) -> String {
    url.host_str().unwrap_or_default().to_string()
}

/// The URLs [`probe`] tries for `bound`, in order: `bound` itself when it already names a `.json`,
/// `.yaml` or `.yml` file; then each of [`PROBE_PATHS`] under the bound URL's path, when it has one
/// (a file's directory, for a file); then each under the origin root. All are on the bound origin.
pub fn probe_urls(bound: &Url) -> Vec<String> {
    let origin = bound.origin().ascii_serialization();
    let path = bound.path();
    let lower = path.to_ascii_lowercase();
    let is_document = [".json", ".yaml", ".yml"].iter().any(|ext| lower.ends_with(ext));
    let mut out = Vec::new();
    let dir = if is_document {
        push_unique(&mut out, bound.to_string());
        path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("")
    } else {
        path.trim_end_matches('/')
    };
    if !dir.is_empty() {
        for probe in PROBE_PATHS {
            push_unique(&mut out, format!("{origin}{dir}{probe}"));
        }
    }
    for probe in PROBE_PATHS {
        push_unique(&mut out, format!("{origin}{probe}"));
    }
    out
}

fn push_unique(out: &mut Vec<String>, url: String) {
    if !out.contains(&url) {
        out.push(url);
    }
}

/// Look for an OpenAPI 3 document at each of [`probe_urls`] and return the first. Every request goes
/// to the bound origin, and a transport failure ends the search, since the next path on the same host
/// would fail the same way (and a host that swallows packets would otherwise cost a timeout per path).
async fn probe(http: &dyn HttpClient, bound: &Url) -> Result<FetchedDocument, String> {
    let host = host_of(bound);
    let mut tried = Vec::new();
    let mut swagger = None;
    for url in probe_urls(bound) {
        let resp = http
            .fetch_text(HttpRequest::get(url.as_str()).header("Accept", ACCEPT_DOCUMENT))
            .await
            .map_err(|e| format!("could not reach {host}: {}", crate::connectors::transport_error_text(&e)))?;
        if !resp.is_success() {
            tried.push(format!("{url} ({})", resp.status));
            continue;
        }
        let bytes = resp.text.unwrap_or_default().into_bytes();
        match sniff(&bytes) {
            DocumentKind::OpenApi3 => return Ok(FetchedDocument { url, bound_host: host, bytes }),
            DocumentKind::Swagger2 => {
                tried.push(format!("{url} (Swagger 2.0)"));
                swagger.get_or_insert(url);
            }
            DocumentKind::Other => tried.push(format!("{url} (not an OpenAPI document)")),
        }
    }
    let mut message = format!("no OpenAPI 3 document found on {host}; tried {}", tried.join(", "));
    if let Some(url) = swagger {
        message.push_str(&format!(". {url} is Swagger 2.0, which the importer does not read: convert it to OpenAPI 3 and paste it"));
    }
    Err(message)
}

async fn fetch_spec(http: &dyn HttpClient, url: &Url, bound_host: String) -> Result<FetchedDocument, String> {
    let resp = http
        .fetch_text(HttpRequest::get(url.as_str()).header("Accept", ACCEPT_DOCUMENT))
        .await
        .map_err(|e| format!("spec_url could not be fetched: {}", crate::connectors::transport_error_text(&e)))?;
    if !resp.is_success() {
        return Err(format!("spec_url answered {}", resp.status));
    }
    let bytes = resp.text.unwrap_or_default().into_bytes();
    match sniff(&bytes) {
        DocumentKind::OpenApi3 => Ok(FetchedDocument { url: url.to_string(), bound_host, bytes }),
        DocumentKind::Swagger2 => Err(SWAGGER_2.into()),
        DocumentKind::Other => Err("spec_url did not return an OpenAPI 3 document".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn opts() -> DeriveOptions {
        DeriveOptions { connection_id: "acme".into(), secret_id: "sec_acme".into(), ..Default::default() }
    }

    fn bytes(doc: &Value) -> Vec<u8> {
        serde_json::to_vec(doc).unwrap()
    }

    /// A one-operation document with `extra` merged over its top level.
    fn doc_with(extra: Value) -> Vec<u8> {
        let mut doc = json!({
            "openapi": "3.0.3",
            "info": { "title": "Acme", "version": "1" },
            "servers": [{ "url": "https://api.example.com/v1" }],
            "paths": { "/pets": { "get": { "operationId": "listPets" } } },
        });
        for (k, v) in extra.as_object().unwrap() {
            doc[k] = v.clone();
        }
        bytes(&doc)
    }

    fn derive_ok(doc: &[u8], opts: &DeriveOptions) -> Derivation {
        derive(doc, opts).unwrap_or_else(|e| panic!("derive failed: {e}"))
    }

    fn find<'a>(d: &'a Derivation, op: &str) -> &'a HttpSpec {
        d.capabilities
            .iter()
            .find(|c| c.id == format!("acme.{op}"))
            .and_then(|c| c.http.as_ref())
            .unwrap_or_else(|| panic!("no capability for {op}"))
    }

    fn warned(d: &Derivation, needle: &str) -> bool {
        d.warnings.iter().any(|w| w.contains(needle))
    }

    fn derive_petstore() -> Derivation {
        let doc = include_bytes!("../../../examples/openapi-import/petstore-payments.openapi.yaml");
        derive(
            doc,
            &DeriveOptions {
                connection_id: "payments".into(),
                secret_id: "sec_payments".into(),
                ..Default::default()
            },
        )
        .expect("petstore imports")
    }

    fn cap<'a>(derived: &'a Derivation, op: &str) -> &'a Capability {
        derived
            .capabilities
            .iter()
            .find(|c| c.id == format!("payments.{op}"))
            .unwrap_or_else(|| panic!("no capability for {op}"))
    }

    #[test]
    fn imports_all_six_operations_with_correct_actions_and_risks() {
        let derived = derive_petstore();
        assert_eq!(derived.capabilities.len(), 6);
        assert_eq!(derived.base_url.as_deref(), Some("https://api.example-payments.com/v1"));
        assert_eq!(derived.auth, AuthScheme::Bearer);

        let search = cap(&derived, "searchTransactions");
        assert_eq!(search.action, Action::Search);
        assert_eq!(search.risk, RiskTier::Medium);

        let read = cap(&derived, "readTransaction");
        assert_eq!(read.action, Action::Read);
        assert_eq!(read.risk, RiskTier::Medium);

        let export = cap(&derived, "exportCustomers");
        assert_eq!(export.action, Action::Export);
        assert_eq!(export.risk, RiskTier::High);

        let update = cap(&derived, "updateCustomer");
        assert_eq!(update.action, Action::Update);
        assert_eq!(update.risk, RiskTier::High);

        // Refund + delete are critical and always require approval.
        let refund = cap(&derived, "refundTransaction");
        assert_eq!(refund.action, Action::Refund);
        assert_eq!(refund.risk, RiskTier::Critical);
        assert!(refund.requires_approval);

        let delete = cap(&derived, "deleteCustomer");
        assert_eq!(delete.action, Action::Delete);
        assert_eq!(delete.risk, RiskTier::Critical);
        assert!(delete.requires_approval);
    }

    /// Replaces the old behavior on purpose: an import used to land with every write enabled, unlike a
    /// marketplace connection. Now anything High or above starts in `disabled_capabilities`.
    #[test]
    fn writes_start_disabled_like_the_preset_loader() {
        let derived = derive_petstore();
        for id in ["exportCustomers", "updateCustomer", "refundTransaction", "deleteCustomer"] {
            assert!(derived.disabled_capabilities.contains(&format!("payments.{id}")), "{id} must start disabled");
        }
        for id in ["searchTransactions", "readTransaction"] {
            assert!(!derived.disabled_capabilities.contains(&format!("payments.{id}")), "{id} is a read");
        }
        for c in &derived.capabilities {
            assert_eq!(derived.disabled_capabilities.contains(&c.id), c.risk >= RiskTier::High, "{}", c.id);
        }
    }

    #[test]
    fn refund_capability_pins_method_path_and_input_schema() {
        let derived = derive_petstore();
        let refund = cap(&derived, "refundTransaction");
        let http = refund.http.as_ref().expect("imported caps carry an http spec");
        assert_eq!(http.method, HttpMethod::Post);
        assert_eq!(http.base_url, "https://api.example-payments.com/v1");
        assert_eq!(http.path, "/transactions/{id}/refund");
        assert_eq!(http.path_params, vec!["id".to_string()]);
        assert!(http.body_params.contains(&"amount".to_string()));
        assert!(http.body_params.contains(&"currency".to_string()));
    }

    #[test]
    fn imported_request_is_built_from_the_pinned_spec_not_agent_params() {
        // An imported capability's request shape comes from its HttpSpec; the agent only fills
        // documented params and cannot redirect the host.
        let derived = derive_petstore();
        let refund = cap(&derived, "refundTransaction").clone();
        let params = json!({
            "id": "txn_123",
            "amount": 9.99,
            "currency": "USD",
            "url": "https://evil.example/steal" // an agent-supplied host must be ignored
        });
        let req = crate::connectors::build_request(&refund, &params, b"super-secret").unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.url, "https://api.example-payments.com/v1/transactions/txn_123/refund");
        assert_eq!(
            req.headers.get("Authorization").map(String::as_str),
            Some("Bearer super-secret")
        );
        let body = req.json().expect("refund has a JSON body");
        assert_eq!(body.get("amount").and_then(|v| v.as_f64()), Some(9.99));
        assert_eq!(body.get("currency").and_then(|v| v.as_str()), Some("USD"));
        // The agent's stray `url` never reaches the request.
        assert!(!req.url.contains("evil"));
    }

    // ── Auth ────────────────────────────────────────────────────────────────────

    #[test]
    fn each_security_scheme_maps_to_an_auth_scheme() {
        let cases = [
            (json!({ "type": "http", "scheme": "bearer" }), AuthScheme::Bearer, false),
            (json!({ "type": "http", "scheme": "Basic" }), AuthScheme::Basic { key_as_username: false }, false),
            (
                json!({ "type": "apiKey", "in": "header", "name": "X-API-Key" }),
                AuthScheme::ApiKeyHeader { header: "X-API-Key".into() },
                false,
            ),
            (
                json!({ "type": "apiKey", "in": "query", "name": "api_key" }),
                AuthScheme::ApiKeyQuery { param: "api_key".into() },
                false,
            ),
            (json!({ "type": "oauth2", "flows": {} }), AuthScheme::Bearer, true),
            (json!({ "type": "openIdConnect", "openIdConnectUrl": "https://id.example.com" }), AuthScheme::Bearer, true),
            (json!({ "type": "apiKey", "in": "cookie", "name": "session" }), AuthScheme::Bearer, true),
            (json!({ "type": "apiKey", "in": "header", "name": "Host" }), AuthScheme::Bearer, true),
            (json!({ "type": "http", "scheme": "digest" }), AuthScheme::Bearer, true),
            (json!({ "type": "mutualTLS" }), AuthScheme::Bearer, true),
        ];
        for (scheme, expected, warns) in cases {
            let doc = doc_with(json!({
                "components": { "securitySchemes": { "only": scheme } },
                "security": [{ "only": [] }],
            }));
            let d = derive_ok(&doc, &opts());
            assert_eq!(d.auth, expected, "{scheme}");
            assert_eq!(find(&d, "listPets").auth, expected, "the scheme is pinned on every capability");
            assert_eq!(warned(&d, "security scheme 'only'"), warns, "{scheme}: {:?}", d.warnings);
        }
        let cookie = doc_with(json!({
            "components": { "securitySchemes": { "only": { "type": "apiKey", "in": "cookie", "name": "sid" } } },
        }));
        assert!(warned(&derive_ok(&cookie, &opts()), "cookie"));
    }

    #[test]
    fn the_top_level_security_requirement_picks_the_scheme() {
        let doc = doc_with(json!({
            "components": { "securitySchemes": {
                "a_basic": { "type": "http", "scheme": "basic" },
                "b_key": { "type": "apiKey", "in": "header", "name": "X-Key" },
            } },
            "security": [{ "missing": [] }, { "b_key": [] }],
        }));
        let d = derive_ok(&doc, &opts());
        assert_eq!(d.auth, AuthScheme::ApiKeyHeader { header: "X-Key".into() });

        let together = doc_with(json!({
            "components": { "securitySchemes": {
                "a_basic": { "type": "http", "scheme": "basic" },
                "b_key": { "type": "apiKey", "in": "header", "name": "X-Key" },
            } },
            "security": [{ "a_basic": [], "b_key": [] }],
        }));
        let d = derive_ok(&together, &opts());
        assert_eq!(d.auth, AuthScheme::Basic { key_as_username: false });
        assert!(warned(&d, "together"), "{:?}", d.warnings);
    }

    #[test]
    fn without_a_requirement_the_first_scheme_in_document_order_is_used() {
        let yaml = b"openapi: 3.0.3
info: { title: Acme, version: '1' }
servers: [{ url: 'https://api.example.com' }]
paths:
  /pets:
    get:
      operationId: listPets
components:
  securitySchemes:
    zeta: { type: http, scheme: basic }
    alpha: { type: http, scheme: bearer }
";
        let d = derive_ok(yaml, &opts());
        assert_eq!(d.auth, AuthScheme::Basic { key_as_username: false }, "zeta was written first, not alpha");
        assert!(warned(&d, "'zeta' is used"), "{:?}", d.warnings);
    }

    #[test]
    fn no_security_schemes_means_bearer_and_a_warning() {
        let d = derive_ok(&doc_with(json!({})), &opts());
        assert_eq!(d.auth, AuthScheme::Bearer);
        assert!(warned(&d, "no securitySchemes"));
    }

    #[test]
    fn an_auth_override_replaces_the_document_and_is_checked() {
        let doc = doc_with(json!({
            "components": { "securitySchemes": { "b": { "type": "http", "scheme": "bearer" } } },
        }));
        let custom = DeriveOptions { auth: Some(AuthScheme::ApiKeyQuery { param: "key".into() }), ..opts() };
        let d = derive_ok(&doc, &custom);
        assert_eq!(d.auth, AuthScheme::ApiKeyQuery { param: "key".into() });
        assert_eq!(find(&d, "listPets").auth, AuthScheme::ApiKeyQuery { param: "key".into() });

        let bad = DeriveOptions { auth: Some(AuthScheme::ApiKeyHeader { header: "Host".into() }), ..opts() };
        assert!(derive(&doc, &bad).unwrap_err().contains("cannot carry a credential"));
    }

    #[test]
    fn the_credential_is_never_offered_to_the_agent_as_a_parameter() {
        let header = doc_with(json!({
            "components": { "securitySchemes": { "k": { "type": "apiKey", "in": "header", "name": "X-Acme-Key" } } },
            "paths": { "/pets": { "get": { "operationId": "listPets", "parameters": [
                { "name": "x-acme-key", "in": "header" },
                { "name": "X-Request-Tag", "in": "header" },
            ] } } },
        }));
        let d = derive_ok(&header, &opts());
        assert_eq!(find(&d, "listPets").header_params, vec!["X-Request-Tag".to_string()]);
        assert!(warned(&d, "'x-acme-key' is the credential"), "{:?}", d.warnings);

        let query = doc_with(json!({
            "components": { "securitySchemes": { "k": { "type": "apiKey", "in": "query", "name": "key" } } },
            "paths": { "/pets": { "get": { "operationId": "listPets", "parameters": [
                { "name": "key", "in": "query" },
                { "name": "limit", "in": "query" },
            ] } } },
        }));
        let d = derive_ok(&query, &opts());
        assert_eq!(find(&d, "listPets").query_params, vec!["limit".to_string()]);
        assert!(warned(&d, "'key' is the credential"));
    }

    // ── Servers ─────────────────────────────────────────────────────────────────

    #[test]
    fn several_servers_leave_the_choice_to_the_operator() {
        let doc = doc_with(json!({ "servers": [
            { "url": "https://sandbox.example.com/v1" },
            { "url": "https://api.example.com/v1/" },
        ] }));
        let d = derive_ok(&doc, &opts());
        assert_eq!(d.base_url, None);
        assert_eq!(d.servers, vec!["https://sandbox.example.com/v1", "https://api.example.com/v1"]);
        assert_eq!(find(&d, "listPets").base_url, "", "an unchosen preview pins nothing");

        let chosen = DeriveOptions { base_url: Some("https://api.example.com/v1".into()), ..opts() };
        let d = derive_ok(&doc, &chosen);
        assert_eq!(d.base_url.as_deref(), Some("https://api.example.com/v1"));
        assert_eq!(find(&d, "listPets").base_url, "https://api.example.com/v1");
        assert!(d.warnings.iter().all(|w| !w.contains("not one of")), "{:?}", d.warnings);

        let elsewhere = DeriveOptions { base_url: Some("https://eu.example.com/v1".into()), ..opts() };
        let d = derive_ok(&doc, &elsewhere);
        assert_eq!(d.base_url.as_deref(), Some("https://eu.example.com/v1"));
        assert!(warned(&d, "not one of the document's servers"));
    }

    #[test]
    fn a_relative_server_resolves_against_the_spec_url() {
        let doc = doc_with(json!({ "servers": [{ "url": "/v2" }, { "url": "v3" }] }));
        let fetched = DeriveOptions {
            spec_url: Some("https://api.example.com/docs/openapi.json".into()),
            bound_host: Some("api.example.com".into()),
            ..opts()
        };
        let d = derive_ok(&doc, &fetched);
        assert_eq!(d.servers, vec!["https://api.example.com/v2", "https://api.example.com/docs/v3"]);
    }

    #[test]
    fn a_pasted_document_with_a_relative_server_needs_base_url() {
        let doc = doc_with(json!({ "servers": [{ "url": "/v2" }] }));
        let err = derive(&doc, &opts()).unwrap_err();
        assert!(err.contains("relative") && err.contains("base_url"), "{err}");
        let d = derive_ok(&doc, &DeriveOptions { base_url: Some("https://api.example.com/v2".into()), ..opts() });
        assert_eq!(d.base_url.as_deref(), Some("https://api.example.com/v2"));
    }

    #[test]
    fn no_servers_means_the_root_the_document_was_served_from() {
        let doc = r#"{"openapi":"3.1.0","paths":{"/pets":{"get":{"operationId":"listPets"}}}}"#;
        let fetched = DeriveOptions {
            spec_url: Some("https://api.example.com/docs/openapi.json".into()),
            bound_host: Some("api.example.com".into()),
            ..opts()
        };
        assert_eq!(derive_ok(doc.as_bytes(), &fetched).base_url.as_deref(), Some("https://api.example.com"));
        assert!(derive(doc.as_bytes(), &opts()).unwrap_err().contains("no server"));
    }

    #[test]
    fn server_variables_take_their_defaults() {
        let doc = doc_with(json!({ "servers": [{
            "url": "https://{env}.example.com/{version}",
            "variables": { "env": { "default": "sandbox", "enum": ["sandbox", "live"] }, "version": { "default": "v1" } },
        }] }));
        assert_eq!(derive_ok(&doc, &opts()).base_url.as_deref(), Some("https://sandbox.example.com/v1"));

        let undefaulted = doc_with(json!({ "servers": [{ "url": "https://{env}.example.com" }] }));
        assert!(derive(&undefaulted, &opts()).unwrap_err().contains("no default"));
    }

    #[test]
    fn an_http_server_is_refused() {
        let only_http = doc_with(json!({ "servers": [{ "url": "http://api.example.com/v1" }] }));
        let err = derive(&only_http, &opts()).unwrap_err();
        assert!(err.contains("https://"), "{err}");

        let mixed = doc_with(json!({ "servers": [{ "url": "http://api.example.com/v1" }, { "url": "https://api.example.com/v1" }] }));
        let d = derive_ok(&mixed, &opts());
        assert_eq!(d.base_url.as_deref(), Some("https://api.example.com/v1"));
        assert!(warned(&d, "server http://api.example.com/v1 must be an absolute https:// URL"), "{:?}", d.warnings);

        for bad in ["https://user:pw@api.example.com", "https://api.example.com/v1?x=1", "https://127.0.0.1/v1"] {
            let doc = doc_with(json!({ "servers": [{ "url": bad }] }));
            assert!(derive(&doc, &opts()).is_err(), "{bad} must not become a pin");
        }
        let http_override = DeriveOptions { base_url: Some("http://api.example.com".into()), ..opts() };
        assert!(derive(&mixed, &http_override).unwrap_err().starts_with("base_url"));
    }

    #[test]
    fn a_fetched_documents_servers_must_be_on_the_bound_host() {
        let doc = doc_with(json!({ "servers": [
            { "url": "https://api.other.net/v1" },
            { "url": "https://www.example.com/api" },
        ] }));
        let fetched = DeriveOptions {
            spec_url: Some("https://example.com/openapi.json".into()),
            bound_host: Some("example.com".into()),
            ..opts()
        };
        let d = derive_ok(&doc, &fetched);
        assert_eq!(d.base_url.as_deref(), Some("https://www.example.com/api"), "a bare www. difference is allowed");
        assert!(warned(&d, "is on api.other.net, not the bound host example.com"), "{:?}", d.warnings);

        let off_host = DeriveOptions { base_url: Some("https://api.other.net/v1".into()), ..fetched.clone() };
        assert!(derive(&doc, &off_host).unwrap_err().contains("not the bound host"));

        let sub = DeriveOptions { bound_host: Some("api.example.com".into()), ..fetched };
        let only_sub = doc_with(json!({ "servers": [{ "url": "https://example.com/api" }] }));
        assert!(derive(&only_sub, &sub).is_err(), "only www. is forgiven, not any other subdomain");
    }

    // ── Parameters and bodies ───────────────────────────────────────────────────

    #[test]
    fn a_ref_parameter_is_resolved() {
        let doc = doc_with(json!({
            "components": { "parameters": {
                "Limit": { "name": "limit", "in": "query" },
                "PetId": { "$ref": "#/components/parameters/RealPetId" },
                "RealPetId": { "name": "petId", "in": "path", "required": true },
            } },
            "paths": { "/pets/{petId}": { "get": { "operationId": "getPet", "parameters": [
                { "$ref": "#/components/parameters/Limit" },
                { "$ref": "#/components/parameters/PetId" },
            ] } } },
        }));
        let d = derive_ok(&doc, &opts());
        let http = find(&d, "getPet");
        assert_eq!(http.query_params, vec!["limit".to_string()], "a $ref'd parameter used to be dropped in silence");
        assert_eq!(http.path_params, vec!["petId".to_string()]);
        assert!(!warned(&d, "has no declared parameter"), "{:?}", d.warnings);
    }

    /// An anchored pattern decides whether a value may hold a slash, which is sent encoded in its one segment; a parameter with no pattern, or an unanchored one, sends a slash encoded as the gateway always did, since GitLab's project id declares none.
    #[test]
    fn an_anchored_path_pattern_decides_whether_a_value_may_hold_a_slash() {
        let doc = doc_with(json!({
            "servers": [{ "url": "https://git.example/api/v4" }],
            "components": { "schemas": { "ProjectPath": { "type": "string", "pattern": "^[\\w.-]+(/[\\w.-]+)*$" } } },
            "paths": {
                "/projects/{id}": { "get": { "operationId": "getProject", "parameters": [
                    { "name": "id", "in": "path", "required": true, "schema": { "$ref": "#/components/schemas/ProjectPath" } },
                ] } },
                "/issues/{iid}": { "get": { "operationId": "getIssue", "parameters": [
                    { "name": "iid", "in": "path", "required": true, "schema": { "type": "string", "pattern": "[0-9]+" } },
                ] } },
                "/v2/jobs/{job}": { "get": { "operationId": "getJob", "parameters": [
                    { "name": "job", "in": "path", "required": true, "type": "string", "pattern": "^[a-z]+$" },
                ] } },
            },
        }));
        let d = derive_ok(&doc, &opts());
        let cap = |op: &str| d.capabilities.iter().find(|c| c.id == format!("acme.{op}")).unwrap();
        let send = |op: &str, params: Value| crate::connectors::build_request_for("openapi", cap(op), &params, b"t");

        assert!(find(&d, "getProject").path_patterns["id"].encode_slash);
        let req = send("getProject", json!({ "id": "group/project" })).unwrap();
        assert_eq!(req.url, "https://git.example/api/v4/projects/group%2Fproject");
        for id in ["group%2Fproject", "group%252Fproject", "group/..", "group\\project", "group/project?x"] {
            assert_eq!(send("getProject", json!({ "id": id })).unwrap_err().code, "path_identifier", "{id}");
        }

        assert!(find(&d, "getIssue").path_patterns.is_empty(), "an unanchored pattern is not whole-value matching");
        assert_eq!(send("getIssue", json!({ "iid": "42/notes" })).unwrap().url, "https://git.example/api/v4/issues/42%2Fnotes");
        assert_eq!(send("getIssue", json!({ "iid": "../users" })).unwrap_err().code, "path_identifier");
        assert_eq!(send("getIssue", json!({ "iid": "42" })).unwrap().url, "https://git.example/api/v4/issues/42");

        assert_eq!(find(&d, "getJob").path_patterns["job"].pattern, "^[a-z]+$", "a Swagger 2 parameter carries its own pattern");
        assert_eq!(send("getJob", json!({ "job": "build" })).unwrap().url, "https://git.example/api/v4/v2/jobs/build");
        assert_eq!(send("getJob", json!({ "job": "build/7" })).unwrap_err().code, "path_identifier");
        assert_eq!(send("getJob", json!({ "job": "Build" })).unwrap_err().code, "path_identifier");
    }

    #[test]
    fn path_level_parameters_merge_with_the_operations() {
        let doc = doc_with(json!({ "paths": { "/pets/{id}": {
            "parameters": [{ "name": "id", "in": "path", "required": true }, { "name": "verbose", "in": "query" }],
            "get": { "operationId": "getPet", "parameters": [
                { "name": "verbose", "in": "query", "required": true },
                { "name": "fields", "in": "query" },
            ] },
            "delete": { "operationId": "deletePet" },
        } } }));
        let d = derive_ok(&doc, &opts());
        let get = find(&d, "getPet");
        assert_eq!(get.path_params, vec!["id".to_string()]);
        assert_eq!(get.query_params, vec!["verbose".to_string(), "fields".to_string()]);
        let delete = find(&d, "deletePet");
        assert_eq!(delete.path_params, vec!["id".to_string()], "the shared list reaches every operation");
        assert_eq!(delete.query_params, vec!["verbose".to_string()]);
    }

    #[test]
    fn a_header_parameter_lands_in_header_params() {
        let doc = doc_with(json!({ "paths": { "/pets": { "get": { "operationId": "listPets", "parameters": [
            { "name": "X-Request-Id", "in": "header" },
            { "name": "X-Auth-Token", "in": "header" },
            { "name": "Accept", "in": "header" },
        ] } } } }));
        let d = derive_ok(&doc, &opts());
        let http = find(&d, "listPets");
        assert_eq!(http.header_params, vec!["X-Request-Id".to_string()]);
        assert!(warned(&d, "'X-Auth-Token' dropped"), "{:?}", d.warnings);
        assert!(!warned(&d, "'Accept'"), "OpenAPI says Accept is ignored as a parameter: {:?}", d.warnings);

        let cap = d.capabilities.iter().find(|c| c.id == "acme.listPets").unwrap();
        let req = crate::connectors::build_request(cap, &json!({ "X-Request-Id": "r-1" }), b"s").unwrap();
        assert_eq!(req.headers.get("X-Request-Id").map(String::as_str), Some("r-1"));
    }

    #[test]
    fn a_cookie_parameter_is_dropped_with_a_warning() {
        let doc = doc_with(json!({ "paths": { "/pets": { "get": { "operationId": "listPets", "parameters": [
            { "name": "session", "in": "cookie" },
        ] } } } }));
        let d = derive_ok(&doc, &opts());
        assert!(warned(&d, "cookie parameter 'session' dropped"), "{:?}", d.warnings);
        let http = find(&d, "listPets");
        assert!(http.query_params.is_empty() && http.header_params.is_empty());
    }

    #[test]
    fn a_ref_cycle_terminates() {
        let doc = doc_with(json!({
            "components": {
                "parameters": { "A": { "$ref": "#/components/parameters/B" }, "B": { "$ref": "#/components/parameters/A" } },
                "schemas": { "Loop": { "allOf": [{ "$ref": "#/components/schemas/Loop" }] } },
            },
            "paths": {
                "/pets": { "post": {
                    "operationId": "createPet",
                    "parameters": [{ "$ref": "#/components/parameters/A" }],
                    "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Loop" } } } },
                } },
                "/self": { "$ref": "#/paths/~1self" },
            },
        }));
        let d = derive_ok(&doc, &opts());
        assert!(warned(&d, "refers back to itself"), "{:?}", d.warnings);
        assert!(warned(&d, "allOf nests more than"), "{:?}", d.warnings);
        assert!(find(&d, "createPet").body_params.is_empty());
    }

    #[test]
    fn request_bodies_resolve_refs_and_merge_all_of() {
        let doc = doc_with(json!({
            "components": {
                "requestBodies": { "NewPet": { "content": { "application/vnd.acme+json; charset=utf-8": {
                    "schema": { "$ref": "#/components/schemas/NewPet" },
                } } } },
                "schemas": {
                    "Base": { "type": "object", "properties": { "name": {}, "owner": {} } },
                    "NewPet": { "allOf": [{ "$ref": "#/components/schemas/Base" }, { "properties": { "tag": {} } }] },
                },
            },
            "paths": { "/pets": { "post": { "operationId": "createPet", "requestBody": { "$ref": "#/components/requestBodies/NewPet" } } } },
        }));
        let d = derive_ok(&doc, &opts());
        let mut body = find(&d, "createPet").body_params.clone();
        body.sort();
        assert_eq!(body, vec!["name", "owner", "tag"]);
    }

    #[test]
    fn a_one_of_body_takes_no_params_and_says_so() {
        let doc = doc_with(json!({ "paths": { "/pets": { "post": { "operationId": "createPet", "requestBody": {
            "content": { "application/json": { "schema": { "oneOf": [
                { "properties": { "cat": {} } }, { "properties": { "dog": {} } },
            ] } } },
        } } } } }));
        let d = derive_ok(&doc, &opts());
        assert!(find(&d, "createPet").body_params.is_empty());
        assert!(warned(&d, "oneOf/anyOf"), "{:?}", d.warnings);

        let multipart = doc_with(json!({ "paths": { "/pets": { "post": { "operationId": "createPet", "requestBody": {
            "content": { "multipart/form-data": { "schema": { "properties": { "a": {} } } } },
        } } } } }));
        let d = derive_ok(&multipart, &opts());
        assert!(find(&d, "createPet").body_params.is_empty());
        assert!(warned(&d, "neither JSON nor a urlencoded form"), "{:?}", d.warnings);
    }

    /// Stripe's own OpenAPI document offers only a urlencoded body on every v1 write, and Stripe reads
    /// nothing else, so such an operation imports as a form body rather than as one with no params.
    #[test]
    fn a_form_only_body_imports_as_a_form_and_json_still_wins_when_offered() {
        let doc = doc_with(json!({ "paths": {
            "/refunds": { "post": { "operationId": "PostRefunds", "requestBody": {
                "content": { "application/x-www-form-urlencoded; charset=utf-8": { "schema": {
                    "type": "object", "properties": { "charge": {}, "amount": {}, "metadata": {} },
                } } },
            } } },
            "/pets": { "post": { "operationId": "createPet", "requestBody": { "content": {
                "application/x-www-form-urlencoded": { "schema": { "properties": { "a": {} } } },
                "application/json": { "schema": { "properties": { "name": {} } } },
            } } } },
        } }));
        let d = derive_ok(&doc, &opts());
        let refund = find(&d, "PostRefunds");
        assert_eq!(refund.body_style, BodyStyle::Form);
        let mut names = refund.body_params.clone();
        names.sort();
        assert_eq!(names, ["amount", "charge", "metadata"]);
        assert!(!warned(&d, "no body parameters"), "{:?}", d.warnings);
        let pet = find(&d, "createPet");
        assert_eq!(pet.body_style, BodyStyle::Json);
        assert_eq!(pet.body_params, ["name"]);

        let cap = d.capabilities.iter().find(|c| c.id == "acme.PostRefunds").unwrap();
        let params = json!({ "charge": "ch_1", "amount": 500, "metadata": { "order": "1042" } });
        let req = crate::connectors::build_request(cap, &params, b"sk_test").unwrap();
        assert!(req.json().is_none(), "no JSON body alongside the form");
        let mut fields: Vec<&str> = req.form_encoded.as_deref().expect("a form body").split('&').collect();
        fields.sort();
        assert_eq!(fields, ["amount=500", "charge=ch_1", "metadata[order]=1042"]);
        assert_eq!(req.headers.get("Content-Type").unwrap(), "application/x-www-form-urlencoded");
    }

    #[test]
    fn an_external_ref_is_reported_and_never_followed() {
        let doc = doc_with(json!({ "paths": { "/pets": { "get": { "operationId": "listPets", "parameters": [
            { "$ref": "https://evil.example/params.json#/Limit" },
        ] } } } }));
        let d = derive_ok(&doc, &opts());
        assert!(warned(&d, "external references are never fetched"), "{:?}", d.warnings);
    }

    #[test]
    fn an_undeclared_template_segment_becomes_a_path_param() {
        let doc = doc_with(json!({ "paths": { "/pets/{petId}": { "get": { "operationId": "getPet" } } } }));
        let d = derive_ok(&doc, &opts());
        assert_eq!(find(&d, "getPet").path_params, vec!["petId".to_string()]);
        assert!(warned(&d, "{petId} has no declared parameter"));
    }

    #[test]
    fn duplicate_operation_ids_do_not_overwrite_each_other() {
        let doc = doc_with(json!({ "paths": {
            "/a": { "get": { "operationId": "list" } },
            "/b": { "get": { "operationId": "list" } },
        } }));
        let d = derive_ok(&doc, &opts());
        let ids: Vec<&str> = d.capabilities.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["acme.list", "acme.list_2"]);
        assert!(warned(&d, "already taken"));
    }

    #[test]
    fn a_swagger_2_document_is_refused_by_name() {
        let doc = br#"{"swagger":"2.0","paths":{"/pets":{"get":{}}}}"#;
        assert!(derive(doc, &opts()).unwrap_err().contains("Swagger 2.0"));
    }

    #[test]
    fn yaml_with_unquoted_response_codes_parses() {
        let yaml = b"openapi: 3.0.3
info:
  title: Acme
  version: 1.0
servers:
  - url: https://api.example.com
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        200:
          description: ok
        default:
          description: error
";
        let d = derive_ok(yaml, &opts());
        assert_eq!(d.capabilities.len(), 1);
    }

    #[test]
    fn probing_stays_on_the_bound_origin() {
        let root = Url::parse("https://api.example.com").unwrap();
        let expected: Vec<String> = PROBE_PATHS.iter().map(|p| format!("https://api.example.com{p}")).collect();
        assert_eq!(probe_urls(&root), expected);

        let pathed = Url::parse("https://api.example.com/v1/").unwrap();
        let urls = probe_urls(&pathed);
        assert_eq!(urls.first().map(String::as_str), Some("https://api.example.com/v1/openapi.json"));
        assert_eq!(urls.len(), PROBE_PATHS.len() * 2);

        let document = Url::parse("https://api.example.com:8443/docs/spec.yaml?v=2").unwrap();
        let urls = probe_urls(&document);
        assert_eq!(urls[0], "https://api.example.com:8443/docs/spec.yaml?v=2", "a document URL is tried as given");
        assert_eq!(urls[1], "https://api.example.com:8443/docs/openapi.json");
        assert!(urls.iter().all(|u| u.starts_with("https://api.example.com:8443/")), "{urls:?}");
    }

    #[tokio::test]
    async fn a_spec_url_on_another_host_is_refused_before_any_request() {
        let mock = crate::connectors::MockHttpClient::new();
        let err = fetch_document(&mock, Some("https://api.example.com"), Some("https://evil.example.net/openapi.json"))
            .await
            .unwrap_err();
        assert!(err.contains("not the bound host"), "{err}");
        assert!(mock.requests().is_empty(), "nothing may be requested from an unbound host");

        let err = fetch_document(&mock, Some("http://api.example.com"), None).await.unwrap_err();
        assert!(err.starts_with("url must be an absolute https:// URL"), "{err}");
        let err = fetch_document(&mock, None, Some("https://10.0.0.5/openapi.json")).await.unwrap_err();
        assert!(err.contains("refused"), "{err}");
        assert!(mock.requests().is_empty());
    }
}
