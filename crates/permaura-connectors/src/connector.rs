//! The connector layer: capability definitions plus the request-shaping that turns an
//! authorized `(capability, params, secret)` into an upstream [`HttpRequest`].
//!
//! A connector is identified by the segment before the first dot of a capability id
//! (`github`, `braintree`, `http`). Each connector declares its capabilities (id, risk,
//! requires_approval) and knows how to build the upstream request. The secret is
//! injected *here*, from the gateway's opened copy, and the gateway's execution path keeps
//! it out of what the agent receives by key-name redaction plus a scrub of the injected
//! value (`permaura_core::json_stream::agent_view`).
//!
//! This mirrors the TypeScript SDK's `defineConnector` shape
//! (`{ id, capabilities: [{ id, risk, requiresApproval?, execute }] }`) in idiomatic
//! Rust.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use permaura_core::{effective_redact_keys, redact, Action, CapabilitySpec, RiskTier};
use serde::{Deserialize, Serialize};

use crate::command::CommandInvocation;
use crate::error::ConnectorError;
use crate::http::{HttpClient, HttpMethod, HttpRequest};
use crate::json_budget;

/// How a capability reaches its upstream: an HTTP call (the default) or a locked-down
/// CLI invocation. The serde default is [`CapabilityKind::Http`] so every existing
/// HTTP-shaped capability deserializes unchanged when the field is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// Shape and send an [`HttpRequest`] (the GitHub / Braintree / Vercel / generic path).
    #[default]
    Http,
    /// Run a fixed, allow-listed CLI with a scoped token injected as an env var.
    Command,
    /// Run an allow-listed remote command or SFTP file operation over SSH, authenticating with a
    /// key/password resolved from the vault. See [`crate::ssh`].
    Ssh,
}

/// The fixed shape of a command capability: which program to run, the argv template (with
/// `{placeholder}` tokens), which env var carries the injected secret, and which
/// placeholders an agent is even allowed to fill. Everything an agent cannot influence is
/// pinned here, server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    /// The program to exec (e.g. `vercel`). Never agent-supplied.
    pub program: String,
    /// The argument template. Literal args pass through; `{name}` tokens are substituted
    /// from `params` *only* when `name` is in `allowed_placeholders`.
    pub args_template: Vec<String>,
    /// The environment variable the opened secret is injected into (e.g. `VERCEL_TOKEN`).
    pub secret_env: String,
    /// The set of placeholder names an agent may fill. A `{token}` not in this list is a
    /// hard error: an agent cannot smuggle a new substitution point past the allow-list.
    pub allowed_placeholders: Vec<String>,
}

/// How the injected secret is presented to the upstream. Carried on an imported [`HttpSpec`] so a
/// preset or OpenAPI import can declare the auth scheme as **data**, closing the old assumption that
/// every imported capability used `Authorization: Bearer`. The secret plaintext is still injected
/// server-side and never handed to the agent, whichever scheme is used.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case")]
pub enum AuthScheme {
    /// `Authorization: Bearer <secret>`, the default and most common.
    #[default]
    Bearer,
    /// HTTP basic. When `key_as_username` is set the secret is the username with an empty password
    /// (`base64("<secret>:")`), Stripe / Recurly / Chargebee / Zendesk style; otherwise the secret
    /// is already a `user:pass` pair and is base64'd as-is (Twilio `SID:token`, Braintree `pub:priv`).
    Basic {
        /// Treat the secret as the username and append a trailing colon before base64.
        #[serde(default)]
        key_as_username: bool,
    },
    /// Inject the secret into a named request header verbatim (`X-API-Key`, `x-api-key`, `x-api-token`).
    ApiKeyHeader {
        /// The header name to set to the secret.
        header: String,
    },
    /// Inject the secret as a query-string parameter (rare; some legacy APIs).
    ApiKeyQuery {
        /// The query parameter name to set to the secret.
        param: String,
    },
    /// A raw header with a literal prefix before the secret. Covers schemes Bearer/Basic can't express:
    /// Linear (`Authorization: <key>`, empty prefix), PagerDuty (`Authorization: Token token=<key>`),
    /// Discord (`Authorization: Bot <token>`).
    Raw {
        /// The header name (usually `Authorization`).
        header: String,
        /// The literal text placed before the secret (may be empty).
        #[serde(default)]
        prefix: String,
    },
}

impl AuthScheme {
    /// The names a response could carry the credential back under: the header or query parameter it is
    /// sent in, lowercased, in its hyphen and underscore spellings. Bearer and Basic travel in
    /// `Authorization`, which is a default redaction already, so they add nothing.
    pub fn credential_field_names(&self) -> Vec<String> {
        match self {
            AuthScheme::Bearer | AuthScheme::Basic { .. } => Vec::new(),
            AuthScheme::ApiKeyHeader { header } | AuthScheme::Raw { header, .. } => field_spellings(header),
            AuthScheme::ApiKeyQuery { param } => field_spellings(param),
        }
    }
}

/// `name` lowercased, then with every `-` written as `_` and every `_` written as `-`: an upstream that
/// takes `xi-api-key` as a header answers with `xi_api_key` in JSON.
fn field_spellings(name: &str) -> Vec<String> {
    let name = name.trim().to_ascii_lowercase();
    let mut spellings = Vec::new();
    for spelling in [name.clone(), name.replace('-', "_"), name.replace('_', "-")] {
        if !spelling.is_empty() && !spellings.contains(&spelling) {
            spellings.push(spelling);
        }
    }
    spellings
}

/// The fixed shape of an **imported** HTTP capability (e.g. one derived from an OpenAPI document).
/// Everything an agent cannot influence (method, upstream base URL, path template) is pinned here
/// at import time; the agent only fills allow-listed params. The base URL is the SSRF guard: it is
/// operator-supplied at import and never agent-supplied, so a tool call can only ever reach the host
/// the operator pinned.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HttpSpec {
    /// The HTTP method, pinned at import.
    pub method: HttpMethod,
    /// The upstream base URL (scheme+host[+base path]), pinned at import. Never agent-supplied.
    pub base_url: String,
    /// The path template, e.g. `/v1/transactions/{id}/refund`. `{name}` segments are filled from
    /// `path_params`; everything else is fixed.
    pub path: String,
    /// Param names allowed to fill `{name}` segments of `path`.
    pub path_params: Vec<String>,
    /// Param names sent as the query string (GET/DELETE): only these are allowed.
    pub query_params: Vec<String>,
    /// Param names assembled into the request body (POST/PUT/PATCH): only these are allowed. Encoded
    /// per [`HttpSpec::body_style`].
    pub body_params: Vec<String>,
    /// How the injected secret is presented upstream. Defaults to [`AuthScheme::Bearer`] so capability
    /// blobs persisted before auth-scheme support deserialize unchanged.
    #[serde(default)]
    pub auth: AuthScheme,
    /// Headers pinned at import that the upstream always requires (e.g. `Stripe-Version`,
    /// `Notion-Version`, `anthropic-version`). Never agent-supplied.
    #[serde(default)]
    pub static_headers: BTreeMap<String, String>,
    /// When set, the path travels as this query parameter instead of being appended to `base_url`,
    /// which is then the site root: a WordPress site without pretty permalinks is only reachable as
    /// `/?rest_route=/wp/v2/posts`. `base_url` stays free of a query string either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_param: Option<String>,
    /// How a structured (object or array) query value is encoded.
    #[serde(default, skip_serializing_if = "QueryStyle::is_flat")]
    pub query_style: QueryStyle,
    /// How the body params are encoded. Defaults to JSON, so a spec stored before this field existed
    /// sends exactly what it always did.
    #[serde(default, skip_serializing_if = "BodyStyle::is_json")]
    pub body_style: BodyStyle,
    /// Param names forwarded as request headers (an OpenAPI `in: header` parameter). Never overrides
    /// a pinned header or the credential, and credential-bearing names are refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_params: Vec<String>,
    /// For a GraphQL endpoint, what the agent's document in `query` may ask for. A spec without one
    /// that forwards `query` is still held to its capability's action; see [`GraphqlCheck`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphqlSpec>,
    /// What each path parameter's own route admits, by name, as the importer read it. A parameter with
    /// no entry is one path segment and may not hold a separator in any encoding, except on an OpenAPI
    /// connection's path-style URL, where a literal `/` is sent as `%2F` inside that segment.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub path_patterns: BTreeMap<String, PathPattern>,
    /// The site's other routes that take this method and could also match this path once a parameter
    /// holds a `/` its pattern admits, as WordPress route regexes (matched whole, case-insensitively).
    /// WordPress serves the first registered route that matches and its index does not say which that
    /// is, so a value with a `/` is refused when any of these matches the filled path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sibling_routes: Vec<String>,
    /// Whether the WordPress importer read this route's path patterns. One stored before it did carries
    /// none whatever its route admits, and a re-sync records them; one read and left without a pattern
    /// stays that way, so only the first is told a re-sync could help.
    #[serde(default, skip_serializing_if = "is_false")]
    pub route_patterns_read: bool,
    /// The posture the owner set on this capability through the gateway's held posture route, with the
    /// posture it replaced. A re-sync keeps it while the source still derives the replaced posture for
    /// the same method and path, and a vault import never carries it in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_posture: Option<OwnerPosture>,
}

/// What the owner set a capability's posture to, and what it was derived as when they did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerPosture {
    /// The risk tier the owner set.
    pub risk: RiskTier,
    /// Whether the owner kept an approval on every call.
    pub requires_approval: bool,
    /// The action the capability carried when the owner set it.
    pub from_action: Action,
    /// The risk tier it replaced.
    pub from_risk: RiskTier,
    /// Whether the posture it replaced asked for an approval on every call.
    pub from_requires_approval: bool,
}

/// A path parameter's own pattern, carried from its route (a WordPress route regex, or an OpenAPI
/// parameter's anchored schema `pattern`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PathPattern {
    /// A regular expression the whole value must match.
    pub pattern: String,
    /// Whether a `/` the pattern admits travels as `%2F` inside one segment rather than as a separator.
    #[serde(default, skip_serializing_if = "is_false")]
    pub encode_slash: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The longest pattern an importer carries; a route regex is a few dozen characters.
pub const MAX_PATH_PATTERN_LEN: usize = 1024;

/// Compile a [`PathPattern::pattern`] anchored at both ends, or `None` when it is too long or is not a
/// pattern this gateway can read (the importer then carries none, and the strict one-segment rule holds).
pub fn compile_path_pattern(pattern: &str) -> Option<regex::Regex> {
    if pattern.len() > MAX_PATH_PATTERN_LEN {
        return None;
    }
    regex::RegexBuilder::new(&format!("^(?:{pattern})$")).size_limit(1 << 20).build().ok()
}

/// What a GraphQL capability's document may ask its endpoint to do. The endpoint serves reads and writes
/// on one URL, so this, not the URL, is what makes a capability's name true.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GraphqlSpec {
    /// The one operation type the document may carry.
    pub operation: GraphqlOperation,
    /// The root fields the operation may select, by schema name. Empty allows any root field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_fields: Vec<String>,
}

/// The operation type a [`GraphqlSpec`] allows. Subscriptions are never forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphqlOperation {
    /// A read.
    #[default]
    Query,
    /// A write.
    Mutation,
}

/// Why a request was refused before it was shaped: the agent's input would have sent something other
/// than what the capability names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRefusal {
    /// A stable label for the audit chain: `graphql_operation`, `path_identifier`, `unknown_action`,
    /// `agent_header`, `method_for_action`, `dot_segment`, `userinfo` or `pinned_host`.
    pub code: &'static str,
    /// Human-readable, safe to return to the agent and to record.
    pub reason: String,
}

impl RequestRefusal {
    fn new(code: &'static str, reason: impl Into<String>) -> Self {
        RequestRefusal { code, reason: reason.into() }
    }
}

impl std::fmt::Display for RequestRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// How [`build_request`] encodes an object or array query value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStyle {
    /// `name=value` for scalars; a structured value is sent empty.
    #[default]
    Flat,
    /// PHP bracket syntax, `name[key]=value` recursively, which is the only way WordPress reads a
    /// structured value (an Abilities API `input`) from a query string.
    Brackets,
}

impl QueryStyle {
    /// True for the default, so a spec that never set a style serializes exactly as it used to.
    pub fn is_flat(&self) -> bool {
        matches!(self, QueryStyle::Flat)
    }
}

/// How [`build_request`] encodes the body params of a POST/PUT/PATCH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyStyle {
    /// An `application/json` object of the supplied body params.
    #[default]
    Json,
    /// `application/x-www-form-urlencoded`, in declared param order, with an object or array value in
    /// PHP bracket syntax (`metadata[order]=1042`, `expand[0]=customer`) and nulls left out. Stripe's v1
    /// API reads only this, and an OpenAPI operation that offers only a form body imports as it.
    Form,
}

impl BodyStyle {
    /// True for the default, so a spec that never set a style serializes exactly as it used to.
    pub fn is_json(&self) -> bool {
        matches!(self, BodyStyle::Json)
    }
}

/// A single capability exposed by a connector, with everything the broker needs to
/// classify it for policy and to shape its upstream request.
#[derive(Debug, Clone)]
pub struct Capability {
    /// Full capability id, e.g. `braintree.transactions.search`.
    pub id: String,
    /// Human description surfaced to agents via `permaura.list_capabilities`.
    pub description: String,
    /// Risk tier driving default policy behavior.
    pub risk: RiskTier,
    /// The normalized risk-bearing verb behind the capability.
    pub action: Action,
    /// Whether the capability itself always escalates to human approval.
    pub requires_approval: bool,
    /// The integration / resource short name this capability acts on (e.g. `braintree_production`). Used as the policy resource and to resolve the sealed secret.
    pub resource: String,
    /// The secret id (in the vault) whose plaintext is injected when invoking.
    pub secret_id: String,
    /// Whether this capability reaches its upstream over HTTP (the default) or by running
    /// a locked-down CLI. Drives which execution path the gateway takes.
    pub kind: CapabilityKind,
    /// For [`CapabilityKind::Command`] capabilities, the fixed command shape (program,
    /// argv template, secret env var, allowed placeholders). `None` for HTTP capabilities.
    pub command: Option<CommandSpec>,
    /// For **imported** HTTP capabilities (e.g. from an OpenAPI spec), the pinned request shape.
    /// `None` for the hand-written connectors (GitHub/Braintree/Vercel/fal/generic), which build
    /// their request from `connector_id()`. When `Some`, it takes precedence in [`build_request`].
    pub http: Option<HttpSpec>,
    /// For [`CapabilityKind::Ssh`] capabilities, the pinned SSH target + operation. `None` otherwise.
    pub ssh: Option<crate::ssh::SshSpec>,
}

impl Capability {
    /// Render this capability as a core [`CapabilitySpec`] (for serde / list output).
    pub fn to_spec(&self) -> CapabilitySpec {
        let mut spec = CapabilitySpec::new(self.id.clone(), self.description.clone(), self.risk)
            .expect("seeded capability ids are valid");
        spec.requires_approval = self.requires_approval;
        spec
    }

    /// The connector id: the segment before the first dot of the capability id.
    pub fn connector_id(&self) -> &str {
        self.id.split('.').next().unwrap_or("")
    }

    /// The names this capability's credential is injected under, for the redaction set: the pinned
    /// [`AuthScheme`]'s header or query parameter, and a command's secret env var. The built-in
    /// families and the generic proxy send `Authorization`, which every set already carries.
    pub fn credential_field_names(&self) -> Vec<String> {
        let mut names = self.http.as_ref().map(|http| http.auth.credential_field_names()).unwrap_or_default();
        if let Some(command) = &self.command {
            names.extend(field_spellings(&command.secret_env));
        }
        names
    }
}

/// Shape an upstream [`HttpRequest`] for a capability, injecting the secret plaintext.
///
/// `secret` is the opened secret bytes (the gateway's `OpenedSecret`, copied out of the vault
/// closure); it is placed where the capability's auth scheme says (a header, the query or a
/// Basic pair), and the returned request carries it until it is sent. `params`
/// is the agent-supplied input. Input that would send something other than what the capability names
/// is a [`RequestRefusal`], and no request exists to send.
pub fn build_request(
    cap: &Capability,
    params: &serde_json::Value,
    secret: &[u8],
) -> Result<HttpRequest, RequestRefusal> {
    build_request_for(cap.connector_id(), cap, params, secret)
}

/// [`build_request`] for a capability on a connection of the `connector` family (the connection's
/// `connector` field). A capability created through a connection is namespaced by the connection id
/// (`github-work.repos.read`), so its own id no longer names the family that shapes its request.
pub fn build_request_for(
    connector: &str,
    cap: &Capability,
    params: &serde_json::Value,
    secret: &[u8],
) -> Result<HttpRequest, RequestRefusal> {
    let token = CredentialText::of(secret);
    let token: &str = &token;
    let request = match request_shape(connector, cap) {
        RequestShape::Imported(spec) => {
            refuse_a_family_elsewhere(connector, spec)?;
            if let Some(why) = method_override_refusal(spec) {
                return Err(RequestRefusal::new("method_override", format!("This capability is refused before the credential is attached: {why}.")));
            }
            if let Some(check) = graphql_check(spec) {
                check_graphql(cap, &check, params)?;
            }
            build_imported_http(connector, spec, params, token)?
        }
        RequestShape::GitHub => build_github(cap, params, token)?,
        RequestShape::Braintree => build_braintree(cap, params, token)?,
        RequestShape::Vercel => build_vercel(cap, params, token)?,
        RequestShape::Fal => build_fal(cap, params, token)?,
        RequestShape::AgentUrl => build_generic_http(cap, params, token)?,
    };
    Ok(request.credentialed())
}

/// The opened credential as text, for a header, a query value or an environment variable.
///
/// Valid UTF-8, which every credential that fits in a header is, is borrowed from the opened bytes. Anything else is decoded into a wiped buffer sized for the worst case up front, so decoding never moves a partial copy to a block it frees.
enum CredentialText<'a> {
    Borrowed(&'a str),
    Decoded(permaura_core::SecretString),
}

impl<'a> CredentialText<'a> {
    fn of(secret: &'a [u8]) -> Self {
        match std::str::from_utf8(secret) {
            Ok(text) => CredentialText::Borrowed(text),
            Err(_) => CredentialText::Decoded(permaura_core::SecretString::from_utf8_lossy(secret)),
        }
    }
}

impl std::ops::Deref for CredentialText<'_> {
    type Target = str;
    fn deref(&self) -> &str {
        match self {
            CredentialText::Borrowed(text) => text,
            CredentialText::Decoded(text) => text.expose(),
        }
    }
}

/// `prefix` then the credential, in a string of exactly that length: built without growing, so no partial copy of the credential is left in a block it outgrew. It goes into an [`HttpRequest`], which wipes it on drop.
fn credential_value(prefix: &str, token: &str) -> String {
    let mut value = String::with_capacity(prefix.len() + token.len());
    value.push_str(prefix);
    value.push_str(token);
    value
}

/// `Basic ` then base64 of `raw` (or of `raw` and a trailing colon), written straight into one string of exactly that length, so neither the raw pair nor its encoding exists anywhere else.
fn basic_value(raw: &str, colon: bool) -> String {
    let input_len = raw.len() + usize::from(colon);
    let encoded = base64::encoded_len(input_len, true).unwrap_or(0);
    let mut value = String::with_capacity("Basic ".len() + encoded);
    value.push_str("Basic ");
    if colon {
        let mut pair = zeroize::Zeroizing::new(Vec::with_capacity(input_len));
        pair.extend_from_slice(raw.as_bytes());
        pair.push(b':');
        B64.encode_string(&*pair, &mut value);
    } else {
        B64.encode_string(raw.as_bytes(), &mut value);
    }
    value
}

/// Why [`build_request_for`] would refuse this input, without a credential. The gateway asks before
/// policy so the refusal is a recorded denial rather than a failed execution, and shares the builder's
/// own checks so the two can never disagree.
pub fn request_refusal(
    connector: &str,
    cap: &Capability,
    params: &serde_json::Value,
) -> Option<RequestRefusal> {
    if !matches!(cap.kind, CapabilityKind::Http) {
        return None;
    }
    build_request_for(connector, cap, params, &[]).err()
}

/// Narrow an upstream response to what the capability promises before redaction sees it. Today that is
/// Vercel: an environment variable record keeps its metadata and loses every value field, whichever
/// endpoint returned it, because a `plain` variable's value arrives in clear without any `decrypt`; and
/// a project's standing credentials (its deploy hooks, Protection Bypass secrets) are redacted.
pub fn project_response(connector: &str, cap: &Capability, body: serde_json::Value) -> serde_json::Value {
    if !matches!(cap.kind, CapabilityKind::Http) {
        return body;
    }
    match vercel_endpoint(connector, cap) {
        Some(VercelEndpoint::EnvListing) => project_env_listing(body),
        Some(VercelEndpoint::Other) => strip_vercel_secrets(body),
        None => body,
    }
}

/// Whether [`project_response`] changes `cap`'s responses, so a caller that otherwise never builds a tree of an upstream body knows when it must.
pub fn response_needs_projection(connector: &str, cap: &Capability) -> bool {
    matches!(cap.kind, CapabilityKind::Http) && vercel_endpoint(connector, cap).is_some()
}

/// True when [`build_request_for`] would send `cap` to a URL the agent supplies in `params.url`, so
/// the gateway must hold it to the connection's host allowlist. Shares [`request_shape`] with the
/// builder, so the gate and the request can never disagree about where the credential goes.
pub fn takes_agent_url(connector: &str, cap: &Capability) -> bool {
    matches!(cap.kind, CapabilityKind::Http)
        && matches!(request_shape(connector, cap), RequestShape::AgentUrl)
}

enum RequestShape<'a> {
    Imported(&'a HttpSpec),
    GitHub,
    Braintree,
    Vercel,
    Fal,
    AgentUrl,
}

fn request_shape<'a>(connector: &str, cap: &'a Capability) -> RequestShape<'a> {
    // An imported (OpenAPI-derived) capability carries its pinned request shape; it takes precedence
    // over the connector dispatch so an operator can add a typed connector with no hand-written code.
    if let Some(spec) = &cap.http {
        return RequestShape::Imported(spec);
    }
    let family = |id: &str| match id {
        "github" => Some(RequestShape::GitHub),
        "braintree" => Some(RequestShape::Braintree),
        "vercel" => Some(RequestShape::Vercel),
        "fal" => Some(RequestShape::Fal),
        _ => None,
    };
    // The generic HTTP proxy (`permaura.http_request` / capability `http.request`), and anything else
    // with no pinned shape, takes its URL from the agent.
    family(connector).or_else(|| family(cap.connector_id())).unwrap_or(RequestShape::AgentUrl)
}

/// Refuse an imported spec on a connection of a family the gateway pins to fixed hosts
/// ([`family_hosts`]) when it would send that family's credential anywhere else. Every write path
/// that names a family checks the same thing first; this is the one place every definition passes,
/// whoever wrote it.
fn refuse_a_family_elsewhere(connector: &str, spec: &HttpSpec) -> Result<(), RequestRefusal> {
    if family_hosts(connector).is_empty() || on_family_host(connector, &spec.base_url) {
        return Ok(());
    }
    Err(RequestRefusal::new(
        "pinned_host",
        format!(
            "This connection is a '{connector}' connection, whose credential the gateway sends to {} only, and this capability would send it to {} instead, so it is refused before the credential is attached. A connection to another host is added as an OpenAPI import or a connector manifest under an id of its own.",
            family_hosts(connector).join(", "),
            crate::egress::url_host(&spec.base_url).unwrap_or_else(|| "a host it does not name".into())
        ),
    ))
}

/// Every host a connector family the gateway pins sends its credential to: its builder's own origin's,
/// and the vendor's other hosts for the same credential (a sandbox, a queue, a GraphQL endpoint). Empty
/// for any other id.
pub fn family_hosts(family: &str) -> &'static [&'static str] {
    match family {
        "github" => &["api.github.com"],
        "braintree" => &[
            "api.braintreegateway.com",
            "api.sandbox.braintreegateway.com",
            "payments.braintree-api.com",
            "payments.sandbox.braintree-api.com",
        ],
        "vercel" => &["api.vercel.com"],
        "fal" => &["fal.run", "queue.fal.run"],
        _ => &[],
    }
}

/// Whether `base_url` is an https URL with no userinfo and no port of its own, on one of `family`'s
/// [`family_hosts`], parsed the way the request is sent.
pub fn on_family_host(family: &str, base_url: &str) -> bool {
    match crate::egress::parse_checked(base_url) {
        Ok((parsed, parts)) => {
            parts.scheme == "https"
                && parts.port.is_none()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && family_hosts(family).contains(&parts.host.as_str())
        }
        Err(_) => false,
    }
}

/// Header names that ask an upstream to run a request as another method than the one it was sent with.
const METHOD_OVERRIDE_HEADERS: &[&str] = &["x-http-method-override", "x-http-method", "x-method-override"];

/// Whether `name` is a header that asks an upstream to treat a request as another method.
pub fn is_method_override_header(name: &str) -> bool {
    METHOD_OVERRIDE_HEADERS.iter().any(|h| name.trim().eq_ignore_ascii_case(h))
}

/// Whether `name` is a parameter an upstream reads as the method to run instead (WordPress reads `_method` from the query, other frameworks from a form body too).
pub fn is_method_override_param(name: &str) -> bool {
    name.trim().eq_ignore_ascii_case("_method")
}

/// Why `spec` could send a request that runs as another method than its pinned one, or as a path other
/// than its template: a method-override header among its static, parameter or credential headers, a
/// `_method` parameter, or a `?` or `#` in its path template (which a value or a literal query could
/// use to add one). `None` when it can do neither. Checked at dispatch for every source, and at every
/// route that stores a spec, so a preview never shows a `GET` that runs as a `DELETE`.
pub fn method_override_refusal(spec: &HttpSpec) -> Option<String> {
    if spec.path.contains(['?', '#']) {
        return Some(format!("its path template '{}' carries a query or a fragment, which the gateway does not send as part of a path", excerpt(&spec.path)));
    }
    let credential_header = match &spec.auth {
        AuthScheme::ApiKeyHeader { header } | AuthScheme::Raw { header, .. } => Some(header.as_str()),
        _ => None,
    };
    let mut headers = spec.static_headers.keys().chain(&spec.header_params).map(String::as_str).chain(credential_header);
    if let Some(name) = headers.find(|n| is_method_override_header(n)) {
        return Some(format!("it sends the header '{name}', which asks the upstream to run the request as another method than its pinned {}", spec.method.as_str()));
    }
    let credential_param = match &spec.auth {
        AuthScheme::ApiKeyQuery { param } => Some(param.as_str()),
        _ => None,
    };
    let mut named =
        spec.query_params.iter().chain(&spec.body_params).chain(&spec.path_params).map(String::as_str).chain(spec.route_param.as_deref()).chain(credential_param);
    if let Some(name) = named.find(|n| is_method_override_param(n)) {
        return Some(format!("it sends the parameter '{name}', which asks the upstream to run the request as another method than its pinned {}", spec.method.as_str()));
    }
    None
}

/// The origin a connector family the gateway builds by hand sends every request to, by family id.
pub fn family_base_url(family: &str) -> Option<&'static str> {
    match family {
        "github" => Some("https://api.github.com"),
        "braintree" => Some("https://api.braintreegateway.com"),
        "vercel" => Some("https://api.vercel.com"),
        "fal" => Some("https://fal.run"),
        _ => None,
    }
}

/// Where `cap`, on a connection of the `connector` family, sends its credential: an imported spec's
/// pinned base URL, or the built-in family's origin. `None` when the agent supplies the URL or the
/// capability is not an HTTP one. Shares [`request_shape`] with the builder, so it names the host the
/// request is actually sent to.
pub fn pinned_base_url(connector: &str, cap: &Capability) -> Option<String> {
    if !matches!(cap.kind, CapabilityKind::Http) {
        return None;
    }
    let family = match request_shape(connector, cap) {
        RequestShape::Imported(spec) => return Some(spec.base_url.clone()),
        RequestShape::AgentUrl => return None,
        RequestShape::GitHub => "github",
        RequestShape::Braintree => "braintree",
        RequestShape::Vercel => "vercel",
        RequestShape::Fal => "fal",
    };
    family_base_url(family).map(str::to_string)
}

/// The action part of a capability id: everything after the connector or connection prefix.
fn action_of(cap: &Capability) -> &str {
    cap.id.split_once('.').map(|(_, action)| action).unwrap_or(&cap.id)
}

/// Build the upstream request for an imported capability from its pinned [`HttpSpec`].
///
/// The base URL is pinned at import (never agent-supplied), so a tool call can only reach the host
/// the operator chose. `{name}` path segments are filled from allow-listed `path_params`; only
/// allow-listed `query_params`/`body_params` are forwarded; the secret is injected as the spec's
/// [`AuthScheme`] says (Bearer by default). Substituted path/query values are percent-encoded so an agent value can't break out of
/// its slot (add a path segment, inject a query separator, etc.).
fn build_imported_http(
    connector: &str,
    spec: &HttpSpec,
    params: &serde_json::Value,
    token: &str,
) -> Result<HttpRequest, RequestRefusal> {
    let mut path = spec.path.clone();
    let mut routed: BTreeMap<&str, String> = BTreeMap::new();
    let mut filled_names: Vec<&str> = Vec::new();
    for name in &spec.path_params {
        let placeholder = format!("{{{name}}}");
        if !path.contains(&placeholder) {
            continue;
        }
        let raw = params.get(name).map(json_value_to_string).unwrap_or_default();
        // Percent-encoding keeps a value inside its segment, but URL parsers resolve `.` and `..` as
        // dot segments even when encoded, and an empty value collapses two segments into one.
        if raw.is_empty() || raw == "." || raw == ".." {
            return Err(RequestRefusal::new(
                "path_identifier",
                format!("Path parameter '{name}' must be a non-empty value other than '.' or '..'."),
            ));
        }
        if percent_encoded_len(&raw) > MAX_ENCODED_PARAMS_BYTES {
            return Err(encoded_too_large());
        }
        let filled = match spec.path_patterns.get(name) {
            Some(own) => fill_by_pattern(name, &raw, own)?,
            // No PHP decodes an OpenAPI path before routing it, so a '/' stays data inside its one segment as %2F, which is how an API like GitLab addresses group/project.
            None if connector == "openapi" && spec.route_param.is_none() => fill_one_segment(name, &raw)?,
            // A `rest_route` value is decoded by PHP before WordPress routes it, so an encoded separator becomes a real one there.
            None if crosses_a_segment(&raw) => {
                let reason = if connector == "wordpress" && !spec.route_patterns_read && spec.path_patterns.is_empty() {
                    format!("Path parameter '{name}' must be a single path segment: it cannot contain '/' or '\\', encoded or not, or be '.' or '..' once decoded. This capability was stored before the gateway read its route's pattern: if the route does admit '/' here, the operator can re-sync the connection so the gateway records it.")
                } else {
                    format!("Path parameter '{name}' cannot contain '/' on this route: it must be a single path segment, with no '/' or '\\', encoded or not, and not '.' or '..' once decoded.")
                };
                return Err(RequestRefusal::new("path_identifier", reason));
            }
            None => percent_encode(&raw),
        };
        filled_names.push(name);
        // The value is percent-encoded on the wire and decoded once by WordPress, so the route it sees holds the raw value.
        routed.insert(name, raw);
        path = path.replace(&placeholder, &filled);
    }
    // Any filled value, a slash-free one included, can make the path one a sibling route also matches (a literal `export` beside a generic `{report}`).
    if !filled_names.is_empty() && !spec.sibling_routes.is_empty() {
        refuse_a_sibling_route(spec, &fill_template(&spec.path, &routed), &filled_names)?;
    }
    let base = spec.base_url.trim_end_matches('/');
    let mut left = MAX_ENCODED_PARAMS_BYTES;
    take_encoded(&mut left, path.len())?;
    let mut query = String::new();
    let mut url = match &spec.route_param {
        // The substituted path values are already percent-encoded, so `%` passes through and only the
        // template's own reserved characters are escaped: an agent value still cannot add a parameter.
        Some(param) => {
            push_pair(&mut query, &mut left, &percent_encode(param), &encode_route(&path))?;
            format!("{base}/")
        }
        None => format!("{base}{path}"),
    };
    pinned_to_base(&url, base)?;

    for name in &spec.query_params {
        if let Some(v) = params.get(name) {
            match spec.query_style {
                QueryStyle::Flat => push_raw_pair(&mut query, &mut left, &percent_encode(name), &json_value_to_string(v), true)?,
                QueryStyle::Brackets => push_bracketed(&mut query, &mut left, &mut percent_encode(name), v, true)?,
            }
        }
    }
    // A query-string credential is appended last so it cannot be shadowed by an agent param of the
    // same name (the allow-list above only forwards declared params, but defence in depth).
    if let AuthScheme::ApiKeyQuery { param } = &spec.auth {
        let name = percent_encode(param);
        // Room first, so appending the credential never leaves part of it in a block the string outgrew.
        query.reserve(1 + name.len() + 1 + percent_encoded_len(token));
        let mut unbounded = usize::MAX;
        push_raw_pair(&mut query, &mut unbounded, &name, token, true)?;
    }
    if !query.is_empty() {
        let mut full = String::with_capacity(url.len() + 1 + query.len());
        full.push_str(&url);
        full.push('?');
        full.push_str(&query);
        url = full;
    }
    {
        use zeroize::Zeroize as _;
        query.zeroize();
    }
    drop(query);
    url.shrink_to_fit();

    let (body, form_encoded) = match spec.body_style {
        BodyStyle::Json => {
            let fields: BTreeMap<&str, &serde_json::Value> =
                spec.body_params.iter().filter_map(|name| params.get(name).map(|v| (name.as_str(), v))).collect();
            ((!fields.is_empty()).then(|| json_text(&fields)), None)
        }
        BodyStyle::Form => {
            let mut fields = String::new();
            let mut written = BTreeSet::new();
            for name in &spec.body_params {
                if let Some(v) = params.get(name) {
                    let again = !written.insert(name.as_str());
                    push_bracketed(&mut fields, &mut left, &mut percent_encode(name), v, again)?;
                }
            }
            fields.shrink_to_fit();
            (None, (!fields.is_empty()).then_some(fields))
        }
    };

    // Pinned headers first (e.g. API version), then the credential per the declared scheme.
    let mut headers: BTreeMap<String, String> = spec.static_headers.clone();
    match &spec.auth {
        AuthScheme::Bearer => {
            headers.insert("Authorization".to_string(), credential_value("Bearer ", token));
        }
        AuthScheme::Basic { key_as_username } => {
            headers.insert("Authorization".to_string(), basic_value(token, *key_as_username));
        }
        AuthScheme::ApiKeyHeader { header } => {
            headers.insert(header.clone(), credential_value("", token));
        }
        AuthScheme::ApiKeyQuery { .. } => {} // injected into the query string above
        AuthScheme::Raw { header, prefix } => {
            headers.insert(header.clone(), credential_value(prefix, token));
        }
    }
    if body.is_some() {
        headers.entry("Content-Type".to_string()).or_insert_with(|| "application/json".to_string());
    }
    if form_encoded.is_some() {
        headers
            .entry("Content-Type".to_string())
            .or_insert_with(|| "application/x-www-form-urlencoded".to_string());
    }
    // Last, and only into a name nothing above has claimed: header names are case-insensitive but the
    // map is not, so a plain insert of `authorization` would sit beside the credential's `Authorization`.
    let given = spec.header_params.iter().filter(|name| params.get(name.as_str()).is_some()).count();
    if given > MAX_AGENT_HEADERS {
        return Err(too_many_agent_headers(given));
    }
    let mut seen: HashSet<String> = headers.keys().map(|name| name.to_ascii_lowercase()).collect();
    for name in &spec.header_params {
        let Some(value) = params.get(name).map(json_value_to_string) else { continue };
        if value.contains(['\r', '\n']) || !is_agent_settable_header(name) {
            continue;
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            continue;
        }
        take_encoded(&mut left, name.len() + value.len())?;
        headers.insert(name.clone(), value);
    }

    Ok(HttpRequest {
        method: spec.method,
        url,
        headers,
        body: None,
        form: None,
        form_encoded,
        json_encoded: body,
        credentialed: true,
    })
}

/// How a capability that forwards a `query` field is held to GraphQL. Without a declared rule only a
/// read-only action is narrowed: a write action already allows a query or a mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphqlCheck {
    /// The spec declares a rule ([`HttpSpec::graphql`]): the document must parse and keep to it.
    Declared(GraphqlSpec),
    /// No rule, but the request is shaped like GraphQL: its pinned endpoint names GraphQL, or it
    /// forwards `operationName` or `variables` beside `query`. A read capability must send exactly one
    /// query, in a document this reader can parse.
    Shaped,
    /// No rule and nothing GraphQL-shaped but a `query` field, which may as well be a search term. A
    /// read capability's value is held to one query when it parses as GraphQL, whatever the URL, and
    /// left alone when it does not.
    Content,
}

/// The [`GraphqlCheck`] for a spec, from what it declares and what it forwards, never from what the agent
/// sends, so an agent cannot drop a field to weaken the check.
pub fn graphql_check(spec: &HttpSpec) -> Option<GraphqlCheck> {
    if let Some(rule) = &spec.graphql {
        return Some(GraphqlCheck::Declared(rule.clone()));
    }
    let forwards = |name: &str| spec.body_params.iter().chain(&spec.query_params).any(|p| p == name);
    let names_graphql = [spec.base_url.as_str(), spec.path.as_str()].iter().any(|part| {
        part.split(['/', '?']).any(|segment| {
            let segment = segment.to_ascii_lowercase();
            segment == "graphql" || segment.starts_with("graphql.")
        })
    });
    if !forwards("query") {
        // A GraphQL endpoint that forwards a stored operation's name and no document is held too, so a read cannot run one; elsewhere those names are ordinary REST fields.
        let names_stored = forwards("extensions") || STORED_OPERATION_MARKERS.iter().any(|name| forwards(name));
        return (names_graphql && names_stored).then_some(GraphqlCheck::Shaped);
    }
    Some(if names_graphql || forwards("operationName") || forwards("variables") || forwards("extensions") {
        GraphqlCheck::Shaped
    } else {
        GraphqlCheck::Content
    })
}

/// Top-level request fields some GraphQL servers read as the name of a stored operation to run in place of the `query` text (Relay's `doc_id`, the GraphQL-over-HTTP persisted documents' `documentId`, others' `queryId`). `id` and graphql-ruby Pro's `operationId` do the same on some servers, but are too common as REST fields to mark a request as GraphQL; they are refused only beside a document the check holds strictly.
const STORED_OPERATION_MARKERS: &[&str] = &["documentId", "doc_id", "queryId"];

/// The field in `fields` naming a stored operation, if any: a [`STORED_OPERATION_MARKERS`] member, `id` or `operationId` when `strict`, or Apollo's `extensions.persistedQuery`. `extensions` sent as a JSON string, the only form a flat query parameter or a form body carries, is read the same way, and under a strict check one that is not a JSON object is refused, since what it names cannot be told. A null counts as absent.
fn stored_operation_field(fields: &serde_json::Value, strict: bool) -> Option<String> {
    let obj = fields.as_object()?;
    let present = |v: Option<&serde_json::Value>| v.is_some_and(|v| !v.is_null());
    let top = STORED_OPERATION_MARKERS.iter().copied().chain(if strict { &["id", "operationId"][..] } else { &[][..] }.iter().copied());
    if let Some(name) = top.into_iter().find(|name| present(obj.get(*name))) {
        return Some(name.to_string());
    }
    let parsed;
    let ext = match obj.get("extensions") {
        Some(serde_json::Value::Object(ext)) => ext,
        Some(serde_json::Value::String(text)) => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(serde_json::Value::Object(ext)) => {
                parsed = ext;
                &parsed
            }
            _ if strict => return Some("extensions".to_string()),
            _ => return None,
        },
        _ => return None,
    };
    ["persistedQuery", "persisted_query"].into_iter().find(|key| present(ext.get(*key))).map(|key| format!("extensions.{key}"))
}

/// The [`GraphqlCheck`] for a body a built-in connector forwards as the agent wrote it. Here the agent's
/// own fields are all there is to go on.
fn forwarded_body_check(body: &serde_json::Value) -> Option<GraphqlCheck> {
    let obj = body.as_object()?;
    let names_stored = stored_operation_field(body, false).is_some();
    if !obj.contains_key("query") && !names_stored {
        return None;
    }
    Some(if names_stored || obj.contains_key("operationName") || obj.contains_key("variables") || obj.contains_key("extensions") {
        GraphqlCheck::Shaped
    } else {
        GraphqlCheck::Content
    })
}

fn check_forwarded_body(cap: &Capability, body: &serde_json::Value) -> Result<(), RequestRefusal> {
    match forwarded_body_check(body) {
        Some(check) => check_graphql(cap, &check, body),
        None => Ok(()),
    }
}

fn is_read_only(action: Action) -> bool {
    matches!(action, Action::Read | Action::Search | Action::List | Action::Export)
}

/// Hold the document in `fields.query` to `check` and to the capability's own action: a read-only action
/// may only ever send a query, whatever a rule says, because that action is what policy evaluated.
fn check_graphql(cap: &Capability, check: &GraphqlCheck, fields: &serde_json::Value) -> Result<(), RequestRefusal> {
    use crate::graphql::{OperationType, RootSelection};
    let refuse = |reason: String| Err(RequestRefusal::new("graphql_operation", reason));
    let read_only = is_read_only(cap.action);
    let (strict, rule) = match check {
        GraphqlCheck::Declared(rule) => (true, Some(rule)),
        // Without a rule nothing says which operation a write capability needs, so its action already
        // covers whatever it sends.
        _ if !read_only => return Ok(()),
        GraphqlCheck::Shaped => (true, None),
        GraphqlCheck::Content => (false, None),
    };
    // A server that runs a stored operation by name runs whatever was stored, so the document below would judge nothing. A lone `query` that is not GraphQL is a search term, and its body's other fields are the REST API's own.
    let held_document = strict
        || fields.get("query").and_then(|v| v.as_str()).is_some_and(|d| crate::graphql::read(d, |_, _, _| {}).is_ok());
    if let Some(field) = stored_operation_field(fields, strict).filter(|_| held_document) {
        return refuse(format!(
            "Capability '{}' may not name a stored GraphQL operation ('{field}'): only a document sent in 'query' can be checked against what the capability allows.",
            cap.id
        ));
    }
    let Some(document) = fields.get("query").and_then(|v| v.as_str()) else {
        if strict {
            return refuse(format!("Capability '{}' needs its GraphQL document in 'query' as a string.", cap.id));
        }
        return Ok(());
    };
    let named = rule.map(|r| r.root_fields.as_slice()).filter(|fields| !fields.is_empty());
    // Only the first operation is judged, and only when it is the one there is, so its type and its first root selection the rule refuses are all that is kept.
    let mut first: Option<(OperationType, Option<RootSelection>)> = None;
    let read = crate::graphql::read(document, |index, kind, selection| {
        if index != 0 {
            return;
        }
        let (_, refused) = first.get_or_insert((kind, None));
        let allowed = match selection {
            RootSelection::Field(name) => named.is_none_or(|fields| name == "__typename" || fields.iter().any(|f| f == name)),
            RootSelection::Fragment => named.is_none(),
        };
        if refused.is_none() && !allowed {
            *refused = Some(selection);
        }
    });
    let count = match read {
        Ok(count) => count,
        Err(e) if strict => {
            return refuse(format!("Capability '{}' could not read the GraphQL document: {e}.", cap.id))
        }
        Err(_) => return Ok(()),
    };
    let (kind, refused) = match (count, first) {
        (1, Some(first)) => first,
        _ => {
            return refuse(format!(
                "Capability '{}' sends exactly one GraphQL operation; this document has {count}.",
                cap.id
            ))
        }
    };
    let allowed = match rule.map(|r| r.operation) {
        Some(GraphqlOperation::Mutation) if !read_only => OperationType::Mutation,
        _ => OperationType::Query,
    };
    if kind != allowed {
        return refuse(format!(
            "Capability '{}' is a {} capability and may only send a GraphQL {}; this document is a {}.",
            cap.id,
            cap.action.as_str(),
            allowed.as_str(),
            kind.as_str()
        ));
    }
    match (refused, named) {
        (Some(RootSelection::Field(name)), Some(fields)) => refuse(format!(
            "Capability '{}' may only call {}; this document calls '{}'.",
            cap.id,
            fields.join(", "),
            excerpt(name)
        )),
        (Some(RootSelection::Fragment), Some(_)) => refuse(format!(
            "Capability '{}' needs its root fields named directly, not through a fragment.",
            cap.id
        )),
        _ => Ok(()),
    }
}

/// At most 64 characters of agent-supplied text, for a refusal reason that is returned and recorded.
fn excerpt(s: &str) -> String {
    match s.char_indices().nth(64) {
        Some((at, _)) => format!("{}...", &s[..at]),
        None => s.to_string(),
    }
}

/// Render a JSON scalar as a string for URL substitution (objects/arrays/null → empty).
fn json_value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

/// Fill a path parameter whose route carries its own pattern. The raw value must match that pattern whole;
/// a literal `/` is then accepted only where the pattern admits it, and each piece between them is held to
/// the one-segment rule, so an encoded separator, a backslash or a dot segment is still refused.
fn fill_by_pattern(name: &str, raw: &str, own: &PathPattern) -> Result<String, RequestRefusal> {
    let refuse = |why: &str| Err(RequestRefusal::new("path_identifier", format!("Path parameter '{name}' {why}.")));
    let Some(re) = compile_path_pattern(&own.pattern) else {
        return refuse("has a route pattern this gateway cannot read, so no value is sent");
    };
    if !re.is_match(raw) {
        return refuse(&format!("'{}' does not match its route's pattern", excerpt(raw)));
    }
    if raw.split('/').any(crosses_a_segment) {
        return refuse("may hold '/' only where its route allows it: it cannot contain '\\' or an encoded separator, or hold a '.' or '..' segment");
    }
    Ok(if own.encode_slash {
        percent_encode(raw)
    } else {
        raw.split('/').map(percent_encode).collect::<Vec<_>>().join("/")
    })
}

/// Fill an OpenAPI path parameter that declares no pattern: the whole value is percent-encoded into its one segment, so a `/` travels as `%2F`. A dot segment, a backslash or an already encoded separator is still refused, since an upstream that decodes the segment would read it as another path.
fn fill_one_segment(name: &str, raw: &str) -> Result<String, RequestRefusal> {
    if raw.split('/').any(crosses_a_segment) {
        return Err(RequestRefusal::new(
            "path_identifier",
            format!("Path parameter '{name}' may hold '/' only as data inside its one segment: it cannot contain '\\' or an encoded separator, or hold a '.' or '..' segment."),
        ));
    }
    Ok(percent_encode(raw))
}

/// Refuse a filled path, holding a `/` a parameter's pattern admits, that another route on the site also matches: WordPress would serve whichever of the two was registered first.
fn refuse_a_sibling_route(spec: &HttpSpec, routed: &str, filled: &[&str]) -> Result<(), RequestRefusal> {
    // WordPress strips trailing '/' and '\\' from the route, then matches with PCRE, whose '$' (no D modifier) also matches before a final newline; Rust's '$' does not, so that newline is dropped here. A route this gateway cannot read might be the one WordPress serves, so it counts as a match.
    let untrailed = routed.trim_end_matches(['/', '\\']);
    let unbroken = untrailed.strip_suffix("\r\n").or_else(|| untrailed.strip_suffix(['\n', '\r'])).unwrap_or(untrailed);
    let mut unreadable = false;
    let reached = spec.sibling_routes.iter().any(|route| {
        match compile_path_pattern(&format!("(?i){route}")).or_else(|| {
            unreadable = true;
            compile_path_pattern(&format!("(?i){}", readable_superset(route)))
        }) {
            Some(re) => [routed, untrailed, unbroken].iter().any(|path| re.is_match(path)),
            None => {
                unreadable = true;
                true
            }
        }
    });
    if reached {
        let why = if unreadable {
            "which another route on this site, one whose pattern this gateway cannot read, might also match"
        } else {
            "which another route on this site also matches"
        };
        return Err(RequestRefusal::new(
            "path_identifier",
            format!(
                "Path parameter '{}' fills the path as '{}', {why}, so the call could reach that route instead; it is not sent.",
                filled.join("', '"),
                excerpt(routed)
            ),
        ));
    }
    Ok(())
}

/// A route regex this gateway can compile that matches at least every path the PCRE `route` matches:
/// lookaround groups and atomic markers only narrow a match, so they are dropped, possessive quantifiers
/// lose their `+`, and a `-` beside a class escape inside a character class (PCRE reads `[\w-.]`'s `-` as
/// a literal) is escaped. A sibling read this way can only refuse more values, never fewer, with one exception:
/// WordPress matches bytes rather than characters, so `\W`, `\D`, `\S` or a counted `.` over non-ASCII text can
/// still match there and not here.
fn readable_superset(route: &str) -> String {
    let chars: Vec<char> = route.chars().collect();
    let mut out = String::with_capacity(route.len());
    let mut i = 0;
    let mut after_quantifier = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            out.push(c);
            if let Some(&next) = chars.get(i + 1) {
                out.push(next);
            }
            i += 2;
            after_quantifier = false;
            continue;
        }
        if c == '[' {
            i = copy_class(&chars, i, &mut out);
            after_quantifier = false;
            continue;
        }
        if c == '(' && chars.get(i + 1) == Some(&'?') {
            let rest: String = chars[i + 2..chars.len().min(i + 5)].iter().collect();
            if rest.starts_with('=') || rest.starts_with('!') || rest.starts_with("<=") || rest.starts_with("<!") {
                i = skip_group(&chars, i);
                continue;
            }
            if rest.starts_with('>') {
                out.push_str("(?:");
                i += 3;
                after_quantifier = false;
                continue;
            }
        }
        if c == '+' && after_quantifier {
            i += 1;
            after_quantifier = false;
            continue;
        }
        after_quantifier = matches!(c, '*' | '+' | '?' | '}');
        out.push(c);
        i += 1;
    }
    out
}

/// Copy the character class opening at `start` into `out`, escaping a `-` beside a class escape, and return the index after it.
fn copy_class(chars: &[char], start: usize, out: &mut String) -> usize {
    let mut i = start + 1;
    out.push('[');
    if chars.get(i) == Some(&'^') {
        out.push('^');
        i += 1;
    }
    if chars.get(i) == Some(&']') {
        out.push_str("\\]");
        i += 1;
    }
    let mut last_was_class_escape = false;
    while i < chars.len() {
        let c = chars[i];
        if c == ']' {
            out.push(']');
            return i + 1;
        }
        if c == '\\' {
            let next = chars.get(i + 1).copied().unwrap_or('\\');
            out.push(c);
            out.push(next);
            last_was_class_escape = matches!(next, 'w' | 'W' | 'd' | 'D' | 's' | 'S' | 'h' | 'H' | 'v' | 'V');
            i += 2;
            continue;
        }
        if c == '-' {
            let next_is_class_escape =
                chars.get(i + 1) == Some(&'\\') && chars.get(i + 2).is_some_and(|n| matches!(n, 'w' | 'W' | 'd' | 'D' | 's' | 'S'));
            if last_was_class_escape || next_is_class_escape {
                out.push_str("\\-");
                i += 1;
                last_was_class_escape = false;
                continue;
            }
        }
        out.push(c);
        last_was_class_escape = false;
        i += 1;
    }
    i
}

/// The index after the group opening at `start`, counting nested groups and skipping escapes and classes.
fn skip_group(chars: &[char], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '[' => {
                let mut scratch = String::new();
                i = copy_class(chars, i, &mut scratch);
            }
            '(' => {
                depth += 1;
                i += 1;
            }
            ')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    i
}

/// A path template with each `{name}` in `values` replaced in one pass, so a value holding braces is never read as another placeholder.
fn fill_template(template: &str, values: &BTreeMap<&str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}').and_then(|close| values.get(&after[..close]).map(|v| (close, v))) {
            Some((close, value)) => {
                out.push_str(value);
                rest = &after[close + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether a path value, read raw or after any number of percent-decodings, holds a separator or is a dot segment. A value that is still decoding after eight rounds counts as one.
fn crosses_a_segment(raw: &str) -> bool {
    let mut value = raw.as_bytes().to_vec();
    for _ in 0..8 {
        if value.iter().any(|b| matches!(b, b'/' | b'\\')) || value == b"." || value == b".." {
            return true;
        }
        let decoded = percent_decode_once(&value);
        if decoded == value {
            return false;
        }
        value = decoded;
    }
    true
}

/// One pass of percent-decoding; a `%` not followed by two hex digits is kept as it is.
fn percent_decode_once(input: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(hi), Some(lo)) = (hex(input[i + 1]), hex(input[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

/// Encode a filled path template as a query value: `/` stays readable and `%` passes through because
/// every agent-supplied segment was percent-encoded when it was substituted.
fn encode_route(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/' | b'%') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// The most text a request may take from an agent's params outside a JSON body (2 MiB): its URL and the headers it sets from them, which the client copies again to send, and the keys a form body writes beside its values, together.
/// The agent's own text is no longer held by the time a request is built, and this fits in its place. Bracket syntax repeats every key above a value beside each value it writes, so without it a small, deep body could write gigabytes.
/// A form body's values are not counted the first time it writes them: each takes the place it would take in a JSON body, which the params' charge already has room for, so a long field is written whole however long its encoding; a value written a second time is counted.
pub const MAX_ENCODED_PARAMS_BYTES: usize = 2 * 1024 * 1024;

fn encoded_too_large() -> RequestRefusal {
    RequestRefusal::new(
        "encoded_too_large",
        format!("The request's URL, headers and form keys written from these params would take more than {MAX_ENCODED_PARAMS_BYTES} bytes; send less."),
    )
}

fn take_encoded(left: &mut usize, len: usize) -> Result<(), RequestRefusal> {
    *left = left.checked_sub(len).ok_or_else(encoded_too_large)?;
    Ok(())
}

/// Append `name=value` to a query string or form body, `&`-separated, within what is `left`.
fn push_pair(out: &mut String, left: &mut usize, name: &str, value: &str) -> Result<(), RequestRefusal> {
    let separator = usize::from(!out.is_empty());
    take_encoded(left, separator + name.len() + 1 + value.len())?;
    if separator == 1 {
        out.push('&');
    }
    out.push_str(name);
    out.push('=');
    out.push_str(value);
    Ok(())
}

/// [`push_pair`] with `raw` percent-encoded as it is appended, checked before anything is written: its encoded length counts against what is `left` when `counted`, and its name always does.
fn push_raw_pair(out: &mut String, left: &mut usize, name: &str, raw: &str, counted: bool) -> Result<(), RequestRefusal> {
    let separator = usize::from(!out.is_empty());
    let value = if counted { percent_encoded_len(raw) } else { 0 };
    take_encoded(left, separator + name.len() + 1 + value)?;
    if separator == 1 {
        out.push('&');
    }
    out.push_str(name);
    out.push('=');
    push_percent_encoded(out, raw);
    Ok(())
}

/// Append `value` under `name` in PHP bracket syntax, as `name=value` pairs for a query string or a
/// form body. `name` is already encoded; object keys are encoded here, nulls are omitted, and an empty
/// object or array contributes nothing. `name` is extended in place for each member and restored after it.
/// Every name written counts against what is `left`, and the values too when `counted` ([`push_raw_pair`]).
fn push_bracketed(out: &mut String, left: &mut usize, name: &mut String, value: &serde_json::Value, counted: bool) -> Result<(), RequestRefusal> {
    let len = name.len();
    match value {
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                name.push('[');
                name.push_str(&percent_encode(key));
                name.push(']');
                push_bracketed(out, left, name, v, counted)?;
                name.truncate(len);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                use std::fmt::Write as _;
                let _ = write!(name, "[{i}]");
                push_bracketed(out, left, name, v, counted)?;
                name.truncate(len);
            }
        }
        serde_json::Value::Null => {}
        scalar => push_raw_pair(out, left, name, &json_value_to_string(scalar), counted)?,
    }
    Ok(())
}

/// `value` written as compact JSON in a buffer of exactly its length: the body of a request built from an agent's params, written from the tree the caller still holds rather than from a copy of it.
pub fn json_text<T: Serialize + ?Sized>(value: &T) -> String {
    struct Counted(usize);
    impl std::io::Write for Counted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counted = Counted(0);
    if serde_json::to_writer(&mut counted, value).is_err() {
        return "null".to_string();
    }
    let mut out = Vec::with_capacity(counted.0);
    if serde_json::to_writer(&mut out, value).is_err() {
        return "null".to_string();
    }
    // serde_json writes UTF-8 only.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// The most headers an agent may give in one request, to the generic proxy or through an imported capability's `header_params`.
pub const MAX_AGENT_HEADERS: usize = 256;

fn too_many_agent_headers(given: usize) -> RequestRefusal {
    RequestRefusal::new("agent_header", format!("the request gives {given} headers, more than the {MAX_AGENT_HEADERS} the gateway forwards"))
}

/// Whether an agent may set a header of this name through `header_params`. Transport and credential
/// headers are the gateway's alone; a spec that declares one as a parameter is not trusted to. Public
/// so an importer can drop such a parameter, with a warning, instead of storing one that never sends.
pub fn is_agent_settable_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let valid = !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    let reserved = matches!(
        n.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "host" | "content-length" | "content-type"
            | "transfer-encoding" | "connection" | "te" | "upgrade" | "metadata-flavor"
    ) || is_method_override_header(&n);
    let credential = ["secret", "token", "password", "passwd", "apikey", "api-key", "api_key", "credential", "bearer"]
        .iter()
        .any(|needle| n.contains(needle));
    valid && !reserved && !credential
}

/// Minimal RFC 3986 percent-encoding for a single path/query value: keep the unreserved set,
/// encode everything else. Avoids a new dependency for the importer's one need.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(percent_encoded_len(s));
    push_percent_encoded(&mut out, s);
    out
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// How long [`percent_encode`] writes `s`, counted without writing it.
fn percent_encoded_len(s: &str) -> usize {
    s.bytes().map(|b| if is_unreserved(b) { 1 } else { 3 }).sum()
}

fn push_percent_encoded(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    for b in s.bytes() {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

/// Characters we refuse to see in a substituted argv value. There is no shell in the
/// command path (the argv is exec'd directly), so these can never be *interpreted*, but
/// rejecting them is cheap defence in depth and keeps an agent from sneaking flag-like or
/// metacharacter-laden values into a slot a human reading the audit log would not expect.
/// Whitespace is included: a substituted value is a single argv slot and must not try to
/// smuggle extra words.
pub(crate) const FORBIDDEN_ARG_CHARS: &[char] = &[
    ';', '&', '|', '<', '>', '$', '`', '\\', '"', '\'', '(', ')', '{', '}', '[', ']', '*',
    '?', '~', '!', '\n', '\r', '\t', ' ', '\0',
];

/// Build a [`CommandInvocation`] from a [`CommandSpec`], the agent's `params`, and the
/// opened `secret`.
///
/// Substitution is allow-list-driven: a `{name}` token in the template is replaced by
/// `params[name]` *only* when `name` appears in [`CommandSpec::allowed_placeholders`].
/// Any other `{token}` (one the spec never sanctioned) is a hard error, so an agent
/// cannot introduce a new substitution point. Every substituted value is rejected if it
/// is empty or contains a [`FORBIDDEN_ARG_CHARS`] character. The opened secret is set as
/// `envs[secret_env]` and is the only place the plaintext appears.
pub fn build_command(
    spec: &CommandSpec,
    params: &serde_json::Value,
    secret: &[u8],
) -> Result<CommandInvocation, ConnectorError> {
    let mut args = Vec::with_capacity(spec.args_template.len());
    for templ in &spec.args_template {
        args.push(substitute_arg(templ, &spec.allowed_placeholders, params)?);
    }

    let mut envs = BTreeMap::new();
    // The secret is a token string; inject it as-is, lossily decoded so non-UTF-8 bytes never panic.
    envs.insert(spec.secret_env.clone(), credential_value("", &CredentialText::of(secret)));

    Ok(CommandInvocation {
        program: spec.program.clone(),
        args,
        envs,
    })
}

/// Substitute one argv-template element. A template element is either a literal (passed
/// through verbatim, e.g. `whoami`, `--prod`) or a single `{name}` placeholder. We only
/// support a whole-element placeholder (not embedded `pre-{x}-post`) so the substituted
/// value can never alter the surrounding argv slot's shape.
///
/// Shared with the SSH exec path ([`crate::ssh::build_ssh`]) so the same allow-list and
/// forbidden-character rules guard a remote command as guard a local one.
pub(crate) fn substitute_arg(
    templ: &str,
    allowed_placeholders: &[String],
    params: &serde_json::Value,
) -> Result<String, ConnectorError> {
    let Some(name) = templ
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        // A literal template element. It must itself be free of a stray `{` / `}` that
        // would signal a malformed placeholder.
        if templ.contains('{') || templ.contains('}') {
            return Err(ConnectorError::BadInput(format!(
                "malformed argv template element '{templ}'"
            )));
        }
        return Ok(templ.to_string());
    };

    if !allowed_placeholders.iter().any(|p| p == name) {
        return Err(ConnectorError::BadInput(format!(
            "placeholder '{{{name}}}' is not in the allow-list"
        )));
    }

    let value = params
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConnectorError::BadInput(format!("missing string param '{name}'")))?;

    if value.is_empty() {
        return Err(ConnectorError::BadInput(format!("param '{name}' is empty")));
    }
    if let Some(bad) = value.chars().find(|c| FORBIDDEN_ARG_CHARS.contains(c)) {
        return Err(ConnectorError::BadInput(format!(
            "param '{name}' contains a forbidden character {bad:?}"
        )));
    }
    // A value beginning with '-' is delivered to the target program as an option/flag even though
    // it can never affect a shell: the argument-injection vector (`--version`, GNU tar's
    // `--checkpoint-action=…`, curl's `-o`, etc.). Whole-element quoting stops shell interpretation
    // but not the program's own option parsing, so an allow-listed slot is a value, never a flag:
    // refuse a leading '-'. (Callers that legitimately need a leading-dash argument must pin it in
    // the fixed template, not accept it from an agent.)
    if value.starts_with('-') {
        return Err(ConnectorError::BadInput(format!(
            "param '{name}' must not start with '-' (an agent value cannot be a flag)"
        )));
    }

    Ok(value.to_string())
}

/// An identifier an agent supplies for a built-in path segment, checked against the provider's own
/// grammar and then percent-encoded. No grammar admits `/`, `?`, `#`, `%` or whitespace, and none can
/// spell `.` or `..`, so the value can only ever name a resource at the pinned endpoint.
struct IdGrammar {
    what: &'static str,
    max: usize,
    /// Punctuation allowed beside ASCII letters and digits.
    punct: &'static [u8],
    /// Whether the first character may be punctuation too.
    punct_first: bool,
}

/// Vercel project ids (`prj_...`) and names.
const VERCEL_PROJECT: IdGrammar = IdGrammar { what: "project", max: 100, punct: b"._-", punct_first: false };
/// Vercel deployment ids (`dpl_...`) or deployment hostnames.
const VERCEL_DEPLOYMENT: IdGrammar = IdGrammar { what: "deployment", max: 253, punct: b"._-", punct_first: false };
/// GitHub user and organization logins.
const GITHUB_OWNER: IdGrammar = IdGrammar { what: "repository owner", max: 39, punct: b"-", punct_first: false };
/// GitHub repository names, which may start with a dot (`.github`).
const GITHUB_REPO: IdGrammar = IdGrammar { what: "repository name", max: 100, punct: b"._-", punct_first: true };
/// Braintree transaction and customer ids.
const BRAINTREE_ID: IdGrammar = IdGrammar { what: "Braintree id", max: 64, punct: b"_-", punct_first: true };

impl IdGrammar {
    fn check(&self, param: &str, value: &serde_json::Value) -> Result<String, RequestRefusal> {
        let allowed = |c: u8| c.is_ascii_alphanumeric() || self.punct.contains(&c);
        let valid = value.as_str().is_some_and(|s| {
            let b = s.as_bytes();
            !b.is_empty()
                && b.len() <= self.max
                && (self.punct_first || b[0].is_ascii_alphanumeric())
                && b.iter().all(|&c| allowed(c))
                && !b.iter().all(|&c| c == b'.')
        });
        match value.as_str() {
            Some(s) if valid => Ok(percent_encode(s)),
            _ => Err(RequestRefusal::new(
                "path_identifier",
                format!(
                    "'{param}' must be a {} identifier ({} characters at most, no URL syntax).",
                    self.what, self.max
                ),
            )),
        }
    }
}

/// The first of `names` present in `params`, held to `grammar`. A missing identifier is refused rather
/// than defaulted: a credentialed call to a placeholder resource is never what the agent asked for.
fn identifier(params: &serde_json::Value, names: &[&str], grammar: &IdGrammar) -> Result<String, RequestRefusal> {
    for name in names {
        if let Some(value) = params.get(*name) {
            return grammar.check(name, value);
        }
    }
    Err(RequestRefusal::new(
        "path_identifier",
        format!("A {} identifier is required in '{}'.", grammar.what, names.join("' or '")),
    ))
}

fn unknown_action(family: &str, cap: &Capability) -> RequestRefusal {
    RequestRefusal::new(
        "unknown_action",
        format!("The built-in {family} connector has no capability '{}'.", action_of(cap)),
    )
}

/// `owner/name` in `repo`, or `owner` and `repo` given separately (and agreeing, if both name an owner).
fn github_repository(params: &serde_json::Value) -> Result<String, RequestRefusal> {
    let repo = params.get("repo").ok_or_else(|| {
        RequestRefusal::new("path_identifier", "A repository is required in 'repo' as owner/name.")
    })?;
    let (owner, name) = match repo.as_str().and_then(|r| r.split_once('/')) {
        Some((owner, name)) => {
            if params.get("owner").is_some_and(|o| o.as_str() != Some(owner)) {
                return Err(RequestRefusal::new("path_identifier", "'owner' and the owner in 'repo' disagree."));
            }
            (GITHUB_OWNER.check("repo", &owner.into())?, GITHUB_REPO.check("repo", &name.into())?)
        }
        None => {
            let owner = params.get("owner").ok_or_else(|| {
                RequestRefusal::new("path_identifier", "A repository is required in 'repo' as owner/name.")
            })?;
            (GITHUB_OWNER.check("owner", owner)?, GITHUB_REPO.check("repo", repo)?)
        }
    };
    Ok(format!("{owner}/{name}"))
}

fn build_github(cap: &Capability, params: &serde_json::Value, token: &str) -> Result<HttpRequest, RequestRefusal> {
    let action = action_of(cap);
    let (method, suffix, body) = match action {
        "pull_requests.create" => (HttpMethod::Post, "/pulls", Some(params)),
        "pull_requests.list" => (HttpMethod::Get, "/pulls", None),
        "issues.create" => (HttpMethod::Post, "/issues", Some(params)),
        "repos.read" => (HttpMethod::Get, "", None),
        _ => return Err(unknown_action("GitHub", cap)),
    };
    let repo = github_repository(params)?;
    if let Some(b) = body {
        check_forwarded_body(cap, b)?;
    }
    let mut req = HttpRequest::new(method, format!("https://api.github.com/repos/{repo}{suffix}"))
        .header("Authorization", credential_value("Bearer ", token))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(b) = body {
        req.json_encoded = Some(json_text(b));
    }
    Ok(req)
}

fn build_braintree(cap: &Capability, params: &serde_json::Value, token: &str) -> Result<HttpRequest, RequestRefusal> {
    let action = action_of(cap);
    let transaction = || identifier(params, &["transaction_id"], &BRAINTREE_ID);
    let (method, path, body) = match action {
        "transactions.search" => (
            HttpMethod::Post,
            "/transactions/advanced_search".to_string(),
            Some(params),
        ),
        "transactions.read" => (HttpMethod::Get, format!("/transactions/{}", transaction()?), None),
        "transactions.refund" => (
            HttpMethod::Post,
            format!("/transactions/{}/refund", transaction()?),
            Some(params),
        ),
        "customers.read" => (
            HttpMethod::Get,
            format!("/customers/{}", identifier(params, &["customer_id"], &BRAINTREE_ID)?),
            None,
        ),
        _ => return Err(unknown_action("Braintree", cap)),
    };
    if let Some(b) = body {
        check_forwarded_body(cap, b)?;
    }
    let mut req = HttpRequest::new(method, format!("https://api.braintreegateway.com{path}"))
        // Braintree uses HTTP basic with the private key; we inject it server-side.
        .header("Authorization", credential_value("Basic ", token))
        .header("Accept", "application/json");
    if let Some(b) = body {
        req.json_encoded = Some(json_text(b));
    }
    Ok(req)
}

/// Vercel: read projects, deployments, env-var *keys*, and domains, plus the high-risk
/// `deployments.create`. Bearer-token auth against `api.vercel.com`. The env-read arm
/// deliberately lists keys/targets only (no `decrypt=true`), and [`project_response`] drops every
/// value field from what comes back, so plaintext env values never leave the gateway.
fn build_vercel(cap: &Capability, params: &serde_json::Value, token: &str) -> Result<HttpRequest, RequestRefusal> {
    let action = action_of(cap);
    let project = || identifier(params, &["project_id", "id", "name"], &VERCEL_PROJECT);
    let (method, path, body) = match action {
        "projects.list" => (HttpMethod::Get, "/v9/projects".to_string(), None),
        "projects.read" => (HttpMethod::Get, format!("/v9/projects/{}", project()?), None),
        "deployments.list" => (HttpMethod::Get, "/v6/deployments".to_string(), None),
        "deployments.read" => (
            HttpMethod::Get,
            format!("/v13/deployments/{}", identifier(params, &["deployment_id", "id"], &VERCEL_DEPLOYMENT)?),
            None,
        ),
        "deployments.create" => (
            HttpMethod::Post,
            "/v13/deployments".to_string(),
            Some(params),
        ),
        "env.read" => (HttpMethod::Get, format!("/v9/projects/{}/env", project()?), None),
        "domains.list" => (HttpMethod::Get, "/v5/domains".to_string(), None),
        _ => return Err(unknown_action("Vercel", cap)),
    };
    if let Some(b) = body {
        check_forwarded_body(cap, b)?;
    }
    let mut req = HttpRequest::new(method, format!("https://api.vercel.com{path}"))
        .header("Authorization", credential_value("Bearer ", token))
        .header("Accept", "application/json");
    if let Some(b) = body {
        req.json_encoded = Some(json_text(b));
    }
    Ok(req)
}

enum VercelEndpoint {
    EnvListing,
    Other,
}

/// The most distinct aliases of redaction-key fields [`response_redact_keys`] adds for one call. Past it the whole response is redacted instead, which keeps what the aliases hold from growing with the document; a query written to be read names far fewer.
pub const MAX_RESPONSE_ALIASES: u64 = 1024;

/// The most room the aliases of one call's response take without asking the memory pool, as the pool counts no call's fixed working memory: so a query that aliases a few redacted fields does not depend on the pool having room, and is not redacted whole for want of it, unless its call is redacted under some 200 keys or more ([`response_alias_room`] counts the keys' sets too).
pub const UNCHARGED_ALIAS_ROOM: u64 = 64 * 1024;

/// What a response is redacted under ([`response_redact_keys`]).
#[derive(Debug)]
pub enum ResponseRedaction {
    /// Redact the members these keys name.
    Keys {
        /// The call's keys, then each alias added to them.
        keys: Vec<String>,
        /// What the aliases take in the memory pool, given back when it is dropped, so it is kept beside the keys.
        room: json_budget::MemoryCharge,
    },
    /// Redact the whole response: its documents name more than [`MAX_RESPONSE_ALIASES`] aliases of redaction-key fields, or the pool had no room at once for the ones they name.
    Whole,
}

/// The redaction set for `cap`'s response with the agent's GraphQL aliases resolved. An alias renames a response key, so a key-name redaction would otherwise be the agent's to switch off on any capability that forwards its document: every alias whose field is a target, or a segment of a dotted one, becomes a target itself. That can only redact more, and a key the agent did not alias is matched exactly as before.
/// Each alias is added once, after the keys, in no particular order. Before any is kept, the room they can hold ([`response_alias_room`]) is taken from `pool` when it is more than [`UNCHARGED_ALIAS_ROOM`], and only if it is there at once: the call already holds its params' room, so taking this room never waits. With no room, or past [`MAX_RESPONSE_ALIASES`] aliases, the answer is [`ResponseRedaction::Whole`]. A call whose documents alias no key takes nothing.
pub fn response_redact_keys(
    connector: &str,
    cap: &Capability,
    params: &serde_json::Value,
    keys: &[String],
    pool: &json_budget::MemoryPool,
) -> ResponseRedaction {
    let unchanged = || ResponseRedaction::Keys { keys: keys.to_vec(), room: json_budget::MemoryCharge::none() };
    if !matches!(cap.kind, CapabilityKind::Http) {
        return unchanged();
    }
    let segments = key_segments(keys);
    let mut field = KeySegment::new(&segments);
    let scan = alias_scan(connector, cap, params, keys, &mut field);
    if scan.room == 0 {
        return unchanged();
    }
    let room = if scan.room <= UNCHARGED_ALIAS_ROOM {
        json_budget::MemoryCharge::none()
    } else {
        match pool.try_reserve(scan.room) {
            Some(room) => room,
            None => return ResponseRedaction::Whole,
        }
    };
    let longest = scan.longest;
    let mut alias_lower = String::with_capacity(longest);
    let mut added: HashSet<String> = HashSet::new();
    let mut over = false;
    graphql_documents(connector, cap, params, &mut |document| {
        crate::graphql::aliases(document, |alias, name| {
            if over || !field.is_named(name) {
                return;
            }
            alias_lower.clear();
            alias_lower.push_str(alias);
            alias_lower.make_ascii_lowercase();
            if added.contains(&alias_lower) {
                return;
            }
            if added.len() as u64 == MAX_RESPONSE_ALIASES {
                over = true;
                return;
            }
            added.insert(alias_lower.clone());
        })
    });
    if over {
        return ResponseRedaction::Whole;
    }
    added.retain(|alias| !keys.contains(alias));
    let mut out = Vec::with_capacity(keys.len() + added.len());
    out.extend_from_slice(keys);
    out.extend(added);
    ResponseRedaction::Keys { keys: out, room }
}

/// What the aliases in `params`' documents that [`response_redact_keys`] adds to `keys` can hold, which it takes from the memory pool before it keeps any when it is more than [`UNCHARGED_ALIAS_ROOM`]: zero when none of them aliases a field `keys` name. It reads the documents and keeps nothing of them.
pub fn response_alias_room(connector: &str, cap: &Capability, params: &serde_json::Value, keys: &[String]) -> u64 {
    if !matches!(cap.kind, CapabilityKind::Http) {
        return 0;
    }
    let segments = key_segments(keys);
    alias_scan(connector, cap, params, keys, &mut KeySegment::new(&segments)).room
}

/// Every segment of every redaction key, lowercased, as an alias's field is compared with them.
fn key_segments(keys: &[String]) -> HashSet<String> {
    keys.iter().flat_map(|k| k.split('.')).map(|s| s.trim().to_ascii_lowercase()).collect()
}

/// What a pass over the alias pairs whose field a key names finds, without keeping any of them.
struct AliasScan {
    /// [`alias_room`] for them, or zero when there are none.
    room: u64,
    /// The longest alias among them.
    longest: usize,
}

fn alias_scan(connector: &str, cap: &Capability, params: &serde_json::Value, keys: &[String], field: &mut KeySegment<'_>) -> AliasScan {
    let (mut pairs, mut text, mut longest) = (0u64, 0u64, 0usize);
    graphql_documents(connector, cap, params, &mut |document| {
        crate::graphql::aliases(document, |alias, name| {
            if field.is_named(name) {
                pairs += 1;
                text = text.saturating_add(json_budget::chunk_bytes(alias.len() as u64));
                longest = longest.max(alias.len());
            }
        })
    });
    if pairs == 0 {
        return AliasScan { room: 0, longest };
    }
    // No more names than pairs or than the most kept, and none longer than the longest.
    let distinct = pairs.min(MAX_RESPONSE_ALIASES);
    let text = text.min(distinct.saturating_mul(json_budget::chunk_bytes(longest as u64)));
    AliasScan { room: alias_room(keys, distinct, text, longest), longest }
}

/// Whether a field name, lowercased into a buffer kept for it, is one of the redaction keys' segments.
struct KeySegment<'a> {
    segments: &'a HashSet<String>,
    lower: String,
}

impl<'a> KeySegment<'a> {
    fn new(segments: &'a HashSet<String>) -> Self {
        let longest = segments.iter().map(String::len).max().unwrap_or(0);
        KeySegment { segments, lower: String::with_capacity(longest) }
    }

    fn is_named(&mut self, field: &str) -> bool {
        if field.len() > self.lower.capacity() {
            return false;
        }
        self.lower.clear();
        self.lower.push_str(field);
        self.lower.make_ascii_lowercase();
        self.segments.contains(&self.lower)
    }
}

/// What [`response_redact_keys`] and the redaction view built from its answer can hold once a document aliases a key, for `keys` and at most `distinct` aliases whose lowercased names take `text` bytes, the longest `longest`, in glibc chunks as [`json_budget`] counts them.
/// All of it, the part the keys alone would take included: a few aliases can take a set of the keys past a capacity step, where it holds a table twice as large beside the old one while it moves, so what they add grows with the keys and not only with the aliases. So each set is counted at the table its whole count needs, beside the one before it: the keys' segments, the aliases gathered, and the view's set of every key and alias. Then the list returned, the copies of the keys in it and in the view, each alias name in both, the view's dotted keys split into segments, and the buffers a name is lowercased in.
fn alias_room(keys: &[String], distinct: u64, text: u64, longest: usize) -> u64 {
    let chunk = json_budget::chunk_bytes;
    let count = keys.len() as u64;
    let (mut segments, mut segment_text, mut widest, mut key_text, mut dotted, mut paths) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for key in keys {
        key_text = key_text.saturating_add(chunk(key.len() as u64));
        let parts = key.split('.').count() as u64;
        let part_text = key.split('.').map(|s| chunk(s.len() as u64)).fold(0u64, u64::saturating_add);
        segments += parts;
        segment_text = segment_text.saturating_add(part_text);
        widest = widest.max(key.split('.').map(str::len).max().unwrap_or(0) as u64);
        if parts > 1 {
            dotted += 1;
            paths = paths.saturating_add(vec_peak(parts, 24)).saturating_add(part_text);
        }
    }
    let sets = set_peak(segments).saturating_add(set_peak(distinct)).saturating_add(set_peak(count.saturating_add(distinct)));
    let list = chunk(24 * count.saturating_add(distinct));
    let buffers = chunk(widest).saturating_add(chunk(longest as u64));
    [sets, list, segment_text, key_text.saturating_mul(2), text.saturating_mul(2), paths, vec_peak(dotted, 24), buffers].into_iter().fold(0u64, u64::saturating_add)
}

/// The most a `HashSet<String>` filled one entry at a time to `len` entries holds at once: the table it ends in, which hashbrown sizes to the next power of two past eight sevenths of its entries (four or eight buckets below eight), of a 24-byte slot and a control byte a bucket and 16 more, beside the table half its size it moves out of.
fn set_peak(len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let buckets = match len {
        0..=3 => 4,
        4..=7 => 8,
        n => (n.saturating_mul(8) / 7).next_power_of_two(),
    };
    let table = |b: u64| json_budget::chunk_bytes((24 * b).next_multiple_of(16) + b + 16);
    table(buckets).saturating_add(table(buckets / 2))
}

/// The most a `Vec` of `size`-byte elements pushed one at a time to `len` holds at once: the buffer it ends in, which starts at four and doubles, beside the one half its size it moves out of.
fn vec_peak(len: u64, size: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let cap = len.max(4).next_power_of_two();
    json_budget::chunk_bytes(cap * size).saturating_add(json_budget::chunk_bytes(cap / 2 * size))
}

/// Each GraphQL document [`response_redact_keys`] reads in `params`. A `query` field that may be a search term is a document only when it reads as one, the same rule the request check applies.
fn graphql_documents(connector: &str, cap: &Capability, params: &serde_json::Value, visit: &mut dyn FnMut(&str)) {
    forwarded_documents(connector, cap, params, &mut |check, document| {
        if *check == GraphqlCheck::Content && crate::graphql::read(document, |_, _, _| {}).is_err() {
            return;
        }
        visit(document);
    });
}

/// Every GraphQL document [`response_redact_keys`] may read in `params`, with the check that says whether it is read as one: the body the request forwards, each operation of a batched one, and on the generic proxy each `query` parameter of the URL.
fn forwarded_documents(connector: &str, cap: &Capability, params: &serde_json::Value, visit: &mut dyn FnMut(&GraphqlCheck, &str)) {
    fn take(check: Option<GraphqlCheck>, fields: &serde_json::Value, visit: &mut dyn FnMut(&GraphqlCheck, &str)) {
        if let (Some(check), Some(document)) = (check, fields.get("query").and_then(|v| v.as_str())) {
            visit(&check, document);
        }
    }
    match request_shape(connector, cap) {
        RequestShape::Imported(spec) => take(graphql_check(spec), params, visit),
        // The generic proxy forwards the agent's body as written, so a batched array is one document per element, and a GET carries its document in the URL's `query` parameter.
        RequestShape::AgentUrl => {
            match params.get("body") {
                Some(serde_json::Value::Array(batch)) => {
                    for op in batch {
                        take(forwarded_body_check(op), op, visit);
                    }
                }
                Some(body) => take(forwarded_body_check(body), body, visit),
                None => {}
            }
            if let Some(url) = params.get("url").and_then(|v| v.as_str()) {
                url_graphql_documents(url, visit);
            }
        }
        _ => take(forwarded_body_check(params), params, visit),
    }
}

/// Each `query` parameter of `url` as a GraphQL document over GET, with the check its other parameters call for, as [`forwarded_body_check`] judges a body's fields. Every one, since which an upstream reads is its own choice. The parameters are decoded one at a time as they are read.
fn url_graphql_documents(url: &str, visit: &mut dyn FnMut(&GraphqlCheck, &str)) {
    let Ok((parsed, _)) = crate::egress::parse_checked(url) else { return };
    let check = if parsed.query_pairs().any(|(k, _)| k == "operationName" || k == "variables") {
        GraphqlCheck::Shaped
    } else {
        GraphqlCheck::Content
    };
    for (k, document) in parsed.query_pairs() {
        if k == "query" {
            visit(&check, &document);
        }
    }
}

/// Which Vercel endpoint `cap` calls, through the built-in connector or a spec pinned to
/// `api.vercel.com` (the marketplace preset, or an import of Vercel's OpenAPI document).
fn vercel_endpoint(connector: &str, cap: &Capability) -> Option<VercelEndpoint> {
    match request_shape(connector, cap) {
        RequestShape::Vercel => Some(if action_of(cap) == "env.read" {
            VercelEndpoint::EnvListing
        } else {
            VercelEndpoint::Other
        }),
        RequestShape::Imported(spec) => {
            let host = crate::egress::parse_url(&spec.base_url).ok()?.host;
            if !host.eq_ignore_ascii_case("api.vercel.com") {
                return None;
            }
            // The version may sit in the pinned base URL rather than the path template.
            let base_path = spec.base_url.split_once("://").and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]));
            let full = format!("{}{}", base_path.unwrap_or(""), spec.path);
            let segments: Vec<&str> = full.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
            let listing = spec.method == HttpMethod::Get
                && matches!(segments.as_slice(), [version, "projects", id, "env"]
                    if version.len() > 1 && version.starts_with('v') && version[1..].bytes().all(|b| b.is_ascii_digit())
                        && id.starts_with('{') && id.ends_with('}'));
            Some(if listing { VercelEndpoint::EnvListing } else { VercelEndpoint::Other })
        }
        _ => None,
    }
}

/// The fields of a Vercel environment variable record that are metadata. Everything else, `value`,
/// `vsmValue`, `decrypted` and any field Vercel adds later, is dropped.
const ENV_METADATA: &[&str] =
    &["id", "key", "type", "target", "gitBranch", "customEnvironmentIds", "createdAt", "updatedAt"];

fn project_env_record(record: &serde_json::Value) -> Option<serde_json::Value> {
    let obj = record.as_object()?;
    let scalar = |v: &serde_json::Value| !v.is_object() && !v.is_array();
    let kept: serde_json::Map<String, serde_json::Value> = ENV_METADATA
        .iter()
        .filter_map(|name| {
            let v = obj.get(*name)?;
            let ok = scalar(v) || v.as_array().is_some_and(|items| items.iter().all(|i| i.is_string()));
            ok.then(|| (name.to_string(), v.clone()))
        })
        .collect();
    Some(serde_json::Value::Object(kept))
}

fn project_env_records(records: &[serde_json::Value]) -> serde_json::Value {
    serde_json::Value::Array(records.iter().filter_map(project_env_record).collect())
}

/// The env listing endpoint answers with `{ envs, pagination }`, a bare array, or one record; each
/// comes back in its own shape holding metadata only, and anything else comes back as nothing.
fn project_env_listing(body: serde_json::Value) -> serde_json::Value {
    match &body {
        serde_json::Value::Array(records) => project_env_records(records),
        serde_json::Value::Object(obj) => match obj.get("envs").and_then(|e| e.as_array()) {
            Some(records) => {
                let mut out = serde_json::Map::new();
                out.insert("envs".into(), project_env_records(records));
                if let Some(page) = obj.get("pagination").and_then(|p| p.as_object()) {
                    let page: serde_json::Map<String, serde_json::Value> = ["count", "next", "prev"]
                        .iter()
                        .filter_map(|k| {
                            let v = page.get(*k).filter(|v| v.is_number() || v.is_null())?;
                            Some((k.to_string(), v.clone()))
                        })
                        .collect();
                    out.insert("pagination".into(), serde_json::Value::Object(page));
                }
                serde_json::Value::Object(out)
            }
            None => project_env_record(&body).unwrap_or(serde_json::Value::Null),
        },
        _ => serde_json::Value::Null,
    }
}

/// The `type` values Vercel gives an environment variable.
const ENV_TYPES: &[&str] = &["system", "secret", "encrypted", "plain", "sensitive"];

/// Recognized by shape rather than by where it sits: a string `key` beside a `target` or an env `type`.
fn is_env_record(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("key").is_some_and(|k| k.is_string())
        && (obj.contains_key("target")
            || obj.get("type").and_then(|t| t.as_str()).is_some_and(|t| ENV_TYPES.contains(&t)))
}

/// Every other Vercel response keeps its shape, but an environment variable record anywhere in it (a
/// project carries its variables, a single-variable read returns one) is projected to metadata, as is
/// every element of an `env` or `envs` array.
///
/// A project also carries two credentials that work outside Permaura: its deploy hooks
/// (`link.deployHooks`), each an unauthenticated trigger for a deployment, and the keys of
/// `protectionBypass`, each of which is a Protection Bypass for Automation or shareable-link secret. The
/// whole hook list is replaced by the redaction marker, because a hook's URL is
/// `https://api.vercel.com/v1/integrations/deploy/<projectId>/<hookId>` and the project id and hook id
/// beside it rebuild it; a bypass keeps its metadata (scope, creator, dates) under a
/// redacted key. A deployment a hook created names that hook in `meta.deployHookId`, beside
/// `deployHookName` and `deployHookRef`, wherever a deployment appears (a deployment list or read, a
/// project's `latestDeployments`), so every `deployHook*` field other than the list itself is dropped.
/// Matched by field name anywhere, so a project list and an imported endpoint that returns either
/// field get the same treatment. A project's `passwordProtection` holds
/// no password in what the API returns, and a `password` field anywhere is in the default redaction set.
fn strip_vercel_secrets(body: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match body {
        Value::Object(obj) if is_env_record(&obj) => project_env_record(&Value::Object(obj)).unwrap_or(Value::Null),
        Value::Object(obj) => Value::Object(
            obj.into_iter()
                .filter(|(k, _)| k == "deployHooks" || !k.starts_with("deployHook"))
                .map(|(k, v)| match (k.as_str(), v) {
                    ("env" | "envs", Value::Array(records)) => {
                        let projected = project_env_records(&records);
                        (k, projected)
                    }
                    ("deployHooks", _) => (k, Value::String(permaura_core::REDACTED.to_string())),
                    ("protectionBypass", Value::Object(bypasses)) => {
                        let count = bypasses.len();
                        let redacted = bypasses
                            .into_iter()
                            .enumerate()
                            .map(|(i, (_, meta))| {
                                let key = if count == 1 {
                                    permaura_core::REDACTED.to_string()
                                } else {
                                    format!("{} {}", permaura_core::REDACTED, i + 1)
                                };
                                (key, strip_vercel_secrets(meta))
                            })
                            .collect();
                        (k, Value::Object(redacted))
                    }
                    (_, v) => (k, strip_vercel_secrets(v)),
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(strip_vercel_secrets).collect()),
        other => other,
    }
}

/// fal.ai generative media. The agent supplies a `prompt` (plus optional model params);
/// the fal key is injected as `Authorization: Key <key>` (fal's scheme, not Bearer) and the
/// call goes to fal's synchronous `fal.run` endpoint for the model behind the capability,
/// which returns image URLs. The key never reaches the agent.
fn build_fal(cap: &Capability, params: &serde_json::Value, token: &str) -> Result<HttpRequest, RequestRefusal> {
    check_forwarded_body(cap, params)?;
    let action = action_of(cap);
    let model = match action {
        // Fast, inexpensive text-to-image: a good default for the broker demo.
        "image.generate" => "fal-ai/flux/schnell",
        _ => "fal-ai/flux/schnell",
    };
    let mut req = HttpRequest::new(HttpMethod::Post, format!("https://fal.run/{model}"))
        .header("Authorization", credential_value("Key ", token))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");
    req.json_encoded = Some(json_text(params));
    Ok(req)
}

/// The generic HTTP proxy, and any other capability with no pinned request shape. The agent supplies
/// `method`, `url`, optional `headers` and `body`; the gateway supplies the credential, always, as a
/// bearer token the agent never sees. A header the gateway owns (the credential, the host the allowlist
/// judged, transport framing) is refused rather than dropped, so the request that leaves is the one the
/// agent and the approver saw. A read-only action sends GET and nothing else, so the method on the wire
/// stays inside the action policy judged.
fn build_generic_http(cap: &Capability, params: &serde_json::Value, token: &str) -> Result<HttpRequest, RequestRefusal> {
    if let Some(body) = params.get("body") {
        check_forwarded_body(cap, body)?;
    }
    let method = params
        .get("method")
        .and_then(|v| v.as_str())
        .map(HttpMethod::parse)
        .unwrap_or(HttpMethod::Get);
    if is_read_only(cap.action) && method != HttpMethod::Get {
        return Err(RequestRefusal::new(
            "method_for_action",
            format!(
                "capability '{}' is a {} and sends only GET; {} refused",
                cap.id,
                cap.action.as_str(),
                method.as_str()
            ),
        ));
    }
    let mut left = MAX_ENCODED_PARAMS_BYTES;
    let url = params.get("url").and_then(|v| v.as_str()).unwrap_or("https://example.com/");
    // Parsing percent-encodes what needs it, three bytes for one, so the agent's text is held to a third of the bound before it is parsed.
    if url.len().saturating_mul(3) > MAX_ENCODED_PARAMS_BYTES {
        return Err(encoded_too_large());
    }
    let url = agent_url(url)?;
    take_encoded(&mut left, url.len())?;

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    if let Some(obj) = params.get("headers").and_then(|v| v.as_object()) {
        // Counted before the loop: the gateway runs this before policy, so its cost is any agent's to choose.
        if obj.len() > MAX_AGENT_HEADERS {
            return Err(too_many_agent_headers(obj.len()));
        }
        let mut seen = HashSet::with_capacity(obj.len());
        for (name, value) in obj {
            let Some(value) = value.as_str() else { continue };
            // Content-Type is the agent's here, unlike under a pinned spec: the body is the agent's too.
            if !is_agent_settable_header(name) && !name.eq_ignore_ascii_case("content-type") {
                return Err(RequestRefusal::new(
                    "agent_header",
                    format!("header '{name}' is set by the gateway and may not be supplied by the agent"),
                ));
            }
            if value.contains(['\r', '\n']) {
                return Err(RequestRefusal::new("agent_header", format!("header '{name}' may not contain a line break")));
            }
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err(RequestRefusal::new("agent_header", format!("header '{name}' is given more than once")));
            }
            take_encoded(&mut left, name.len() + value.len())?;
            headers.insert(name.clone(), value.to_string());
        }
    }
    headers.insert("Authorization".to_string(), credential_value("Bearer ", token));

    Ok(HttpRequest {
        method,
        url,
        headers,
        body: None,
        form: None,
        form_encoded: None,
        json_encoded: params.get("body").map(json_text),
        credentialed: true,
    })
}

/// Refuse a built URL whose scheme, host, port or userinfo is not its pinned base's. The path template is joined to the base as text, so one without a leading slash would run on into the host, and a value substituted there would choose where the credential goes.
fn pinned_to_base(url: &str, base: &str) -> Result<(), RequestRefusal> {
    let origin = |u: &str| {
        crate::egress::parse_checked(u)
            .ok()
            .map(|(parsed, parts)| (parts, parsed.username().to_string(), parsed.password().map(str::to_string)))
    };
    match (origin(base), origin(url)) {
        (Some(pinned), Some(built)) if pinned == built => Ok(()),
        _ => Err(RequestRefusal::new(
            "pinned_host",
            "The request would not go to the scheme, host and port pinned for this connection, so it is refused before the credential is attached.",
        )),
    }
}

/// The agent's URL in the form the HTTP client sends it: the WHATWG serialization the dispatch parser produces, which lowercases the host, drops a default port and percent-encodes what it must. A path dot segment is refused rather than resolved, because the parser resolves percent-encoded ones too and the agent's chosen path would never be on screen. Userinfo is refused because the client sends it as an `Authorization: Basic` ahead of the connection's credential.
fn agent_url(url: &str) -> Result<String, RequestRefusal> {
    if has_dot_segment(url) {
        return Err(RequestRefusal::new(
            "dot_segment",
            "The request URL's path has a '.' or '..' dot segment (literal or percent-encoded), which would send the call to a different path than the one shown; give the path without it.",
        ));
    }
    // An unparseable URL is left as given: the egress gate refuses it with the parser's own reason, before policy and again at dispatch.
    let Ok((parsed, _)) = crate::egress::parse_checked(url) else { return Ok(url.to_string()) };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RequestRefusal::new(
            "userinfo",
            "The request URL has a user name or password before its host, which would travel as a second Authorization header beside the connection's credential; give the URL without it.",
        ));
    }
    Ok(parsed.to_string())
}

/// Whether the path of `url` holds a segment the WHATWG parser resolves as `.` or `..`. Mirrors the parser's own reading: leading and trailing controls and spaces are trimmed, tab and newline are dropped anywhere, a backslash separates segments in an http(s) path, and `%2e` in either case is a dot.
fn has_dot_segment(url: &str) -> bool {
    let cleaned: String = url
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let rest = cleaned.split_once("://").map_or(cleaned.as_str(), |(_, rest)| rest);
    let Some(start) = rest.find(['/', '\\', '?', '#']) else { return false };
    let path = rest[start..].split(['?', '#']).next().unwrap_or_default();
    path.split(['/', '\\']).any(|segment| {
        let segment = segment.to_ascii_lowercase().replace("%2e", ".");
        segment == "." || segment == ".."
    })
}

/// `params` with its `url` replaced by the form [`build_request_for`] sends, when `cap` takes its URL from the agent and that form differs; `None` otherwise. The gateway holds this, so the URL an approver is shown and signs is the URL that executes.
pub fn canonical_agent_params(connector: &str, cap: &Capability, params: &serde_json::Value) -> Option<serde_json::Value> {
    if !takes_agent_url(connector, cap) {
        return None;
    }
    let given = params.get("url")?.as_str()?;
    let sent = agent_url(given).ok()?;
    if sent == given {
        return None;
    }
    let mut canonical = params.clone();
    canonical["url"] = serde_json::Value::String(sent);
    Some(canonical)
}

/// [`canonical_agent_params`] applied to `params` itself, answering whether its `url` changed, for a caller that owns the params and need not hold a second copy of them.
pub fn canonicalize_agent_params(connector: &str, cap: &Capability, params: &mut serde_json::Value) -> bool {
    if !takes_agent_url(connector, cap) {
        return false;
    }
    let Some(given) = params.get("url").and_then(|v| v.as_str()) else { return false };
    let Ok(sent) = agent_url(given) else { return false };
    if sent == given {
        return false;
    }
    params["url"] = serde_json::Value::String(sent);
    true
}

// ---- Connector framework ------------------------------------------------------

/// A connector groups the capabilities for one upstream system (GitHub, Braintree, a
/// generic HTTP host) and is configured with the resource short-name and the vault
/// secret id its capabilities act on. The built-ins implement this; external connectors
/// can too.
pub trait Connector: Send + Sync {
    /// The connector id: the segment before the first dot of its capability ids.
    fn id(&self) -> &str;
    /// The configured capabilities this connector exposes.
    fn capabilities(&self) -> Vec<Capability>;
}

/// GitHub: read repos, list/create pull requests, create issues. Destructive verbs
/// (merge, force-push, delete) are deliberately *not* exposed: an agent cannot invoke
/// what no capability defines.
pub struct GitHubConnector {
    /// The integration short-name used as the policy resource.
    pub resource: String,
    /// The vault secret id holding the GitHub token.
    pub secret_id: String,
}

impl GitHubConnector {
    /// Configure the GitHub connector for a given resource + secret.
    pub fn new(resource: impl Into<String>, secret_id: impl Into<String>) -> Self {
        GitHubConnector { resource: resource.into(), secret_id: secret_id.into() }
    }
}

impl Connector for GitHubConnector {
    fn id(&self) -> &str {
        "github"
    }
    fn capabilities(&self) -> Vec<Capability> {
        let mk = |id: &str, desc: &str, risk: RiskTier, action: Action, approval: bool| Capability {
            id: id.to_string(),
            description: desc.to_string(),
            risk,
            action,
            requires_approval: approval,
            resource: self.resource.clone(),
            secret_id: self.secret_id.clone(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        };
        vec![
            mk("github.repos.read", "Read repository metadata", RiskTier::Low, Action::Read, false),
            mk("github.pull_requests.list", "List pull requests", RiskTier::Low, Action::List, false),
            mk("github.pull_requests.create", "Open a pull request", RiskTier::High, Action::Create, false),
            mk("github.issues.create", "Open an issue", RiskTier::Medium, Action::Create, false),
        ]
    }
}

/// Braintree: search/read transactions and customers (read tier), plus the
/// approval-gated `transactions.refund` (critical), the canonical prompt-injection
/// demo target.
pub struct BraintreeConnector {
    /// The integration short-name used as the policy resource.
    pub resource: String,
    /// The vault secret id holding the Braintree private key.
    pub secret_id: String,
}

impl BraintreeConnector {
    /// Configure the Braintree connector for a given resource + secret.
    pub fn new(resource: impl Into<String>, secret_id: impl Into<String>) -> Self {
        BraintreeConnector { resource: resource.into(), secret_id: secret_id.into() }
    }
}

impl Connector for BraintreeConnector {
    fn id(&self) -> &str {
        "braintree"
    }
    fn capabilities(&self) -> Vec<Capability> {
        let mk = |id: &str, desc: &str, risk: RiskTier, action: Action, approval: bool| Capability {
            id: id.to_string(),
            description: desc.to_string(),
            risk,
            action,
            requires_approval: approval,
            resource: self.resource.clone(),
            secret_id: self.secret_id.clone(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        };
        vec![
            mk("braintree.transactions.search", "Search transactions", RiskTier::Medium, Action::Search, false),
            mk("braintree.transactions.read", "Read a transaction", RiskTier::Low, Action::Read, false),
            mk("braintree.customers.read", "Read a customer", RiskTier::Low, Action::Read, false),
            mk("braintree.transactions.refund", "Refund a transaction", RiskTier::Critical, Action::Refund, true),
        ]
    }
}

/// Vercel: read-tier access to projects, deployments, env-var keys, and domains, plus
/// the High-risk `deployments.create`, which the policy engine auto-escalates to human
/// approval. `env.read` lists env-var keys/targets only and never returns plaintext
/// values (the connector never asks Vercel to decrypt them).
pub struct VercelConnector {
    /// The integration short-name used as the policy resource.
    pub resource: String,
    /// The vault secret id holding the Vercel API token.
    pub secret_id: String,
}

impl VercelConnector {
    /// Configure the Vercel connector for a given resource + secret.
    pub fn new(resource: impl Into<String>, secret_id: impl Into<String>) -> Self {
        VercelConnector { resource: resource.into(), secret_id: secret_id.into() }
    }
}

impl Connector for VercelConnector {
    fn id(&self) -> &str {
        "vercel"
    }
    fn capabilities(&self) -> Vec<Capability> {
        let mk = |id: &str, desc: &str, risk: RiskTier, action: Action, approval: bool| Capability {
            id: id.to_string(),
            description: desc.to_string(),
            risk,
            action,
            requires_approval: approval,
            resource: self.resource.clone(),
            secret_id: self.secret_id.clone(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        };
        vec![
            mk("vercel.projects.list", "List Vercel projects", RiskTier::Low, Action::List, false),
            mk("vercel.projects.read", "Read a Vercel project", RiskTier::Low, Action::Read, false),
            mk("vercel.deployments.list", "List Vercel deployments", RiskTier::Low, Action::List, false),
            mk("vercel.deployments.read", "Read a Vercel deployment", RiskTier::Low, Action::Read, false),
            mk("vercel.deployments.create", "Create a Vercel deployment", RiskTier::High, Action::Deploy, false),
            mk("vercel.env.read", "List a project's env var keys/targets (never values)", RiskTier::Medium, Action::Read, false),
            mk("vercel.domains.list", "List Vercel domains", RiskTier::Low, Action::List, false),
        ]
    }
}

/// True if `connector` names the generic-HTTP proxy family (the escape hatch whose target
/// host is agent-supplied). These are the connections that MUST carry an operator host
/// allowlist: the request URL is not pinned at config time the way a typed connector's is.
pub fn is_generic_http_connector(connector: &str) -> bool {
    matches!(connector, "generic-http" | "generic_http" | "http")
}

/// The generic HTTP proxy connector, backing `permaura.http_request`. One high-risk
/// capability (`http.request`) that issues an arbitrary upstream call with the injected
/// credential, the escape hatch for systems without a native connector.
pub struct GenericHttpConnector {
    /// The integration short-name used as the policy resource.
    pub resource: String,
    /// The vault secret id holding the credential to inject.
    pub secret_id: String,
}

impl GenericHttpConnector {
    /// Configure the generic HTTP connector for a given resource + secret.
    pub fn new(resource: impl Into<String>, secret_id: impl Into<String>) -> Self {
        GenericHttpConnector { resource: resource.into(), secret_id: secret_id.into() }
    }
}

impl Connector for GenericHttpConnector {
    fn id(&self) -> &str {
        "http"
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: "http.request".to_string(),
            description: "Issue an arbitrary HTTP request with an injected credential".to_string(),
            risk: RiskTier::High,
            action: Action::Execute,
            requires_approval: false,
            resource: self.resource.clone(),
            secret_id: self.secret_id.clone(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        }]
    }
}

/// **fal.ai**: generative media. One capability for now: `fal.image.generate`
/// (text-to-image via fal's synchronous `fal.run` endpoint). The user adds their fal key as
/// the secret; an agent passes a prompt and gets back image URLs, while the key is injected
/// server-side as `Authorization: Key …` and is never exposed. Medium risk (it spends the
/// user's fal credits), so a policy can require approval or cap calls.
pub struct FalConnector {
    /// The integration short-name used as the policy resource (e.g. `fal`).
    pub resource: String,
    /// The vault secret id holding the fal.ai key.
    pub secret_id: String,
}

impl FalConnector {
    /// Configure the fal.ai connector for a given resource + secret.
    pub fn new(resource: impl Into<String>, secret_id: impl Into<String>) -> Self {
        FalConnector { resource: resource.into(), secret_id: secret_id.into() }
    }
}

impl Connector for FalConnector {
    fn id(&self) -> &str {
        "fal"
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: "fal.image.generate".to_string(),
            description: "Generate an image from a text prompt via fal.ai (flux/schnell)".to_string(),
            risk: RiskTier::Medium,
            action: Action::Create,
            requires_approval: false,
            resource: self.resource.clone(),
            secret_id: self.secret_id.clone(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        }]
    }
}

/// The **command connector** for the Vercel CLI: drive a locked-down `vercel` binary with
/// a Permaura-controlled scoped token injected as `VERCEL_TOKEN`, instead of handing the
/// agent the ambient `vercel login` session.
///
/// Its capabilities are [`CapabilityKind::Command`]: each pins a fixed argv (`vercel
/// whoami`, `vercel ls`, `vercel deploy --prod --yes`). `whoami` / `deployments.list` are
/// Low-risk reads; `deploy` is High risk so the policy engine auto-escalates it to human
/// approval, the same posture as the HTTP `vercel.deployments.create`. The agent can fill
/// only the whitelisted `dir` placeholder on `deploy`, and even that is metacharacter- and
/// whitespace-rejected.
pub struct VercelCliConnector {
    /// The integration short-name used as the policy resource (e.g. `vercel_cli`).
    pub resource: String,
    /// The vault secret id holding the scoped Vercel CLI token injected into `VERCEL_TOKEN`.
    pub secret_id: String,
}

impl VercelCliConnector {
    /// Configure the Vercel CLI connector for a given resource + secret.
    pub fn new(resource: impl Into<String>, secret_id: impl Into<String>) -> Self {
        VercelCliConnector {
            resource: resource.into(),
            secret_id: secret_id.into(),
        }
    }
}

impl Connector for VercelCliConnector {
    fn id(&self) -> &str {
        "vercel-cli"
    }
    fn capabilities(&self) -> Vec<Capability> {
        let mk = |id: &str,
                  desc: &str,
                  risk: RiskTier,
                  action: Action,
                  approval: bool,
                  args: &[&str],
                  allowed: &[&str]| Capability {
            id: id.to_string(),
            description: desc.to_string(),
            risk,
            action,
            requires_approval: approval,
            resource: self.resource.clone(),
            secret_id: self.secret_id.clone(),
            kind: CapabilityKind::Command,
            command: Some(CommandSpec {
                program: "vercel".to_string(),
                args_template: args.iter().map(|s| s.to_string()).collect(),
                secret_env: "VERCEL_TOKEN".to_string(),
                allowed_placeholders: allowed.iter().map(|s| s.to_string()).collect(),
            }),
            http: None,
            ssh: None,
        };
        vec![
            mk(
                "vercel-cli.whoami",
                "Print the Vercel account the scoped token belongs to",
                RiskTier::Low,
                Action::Read,
                false,
                &["whoami"],
                &[],
            ),
            mk(
                "vercel-cli.deployments.list",
                "List recent Vercel deployments via the CLI",
                RiskTier::Low,
                Action::List,
                false,
                &["ls"],
                &[],
            ),
            mk(
                "vercel-cli.deploy",
                "Deploy the current project to production via the CLI",
                RiskTier::High,
                Action::Deploy,
                false,
                // The argv is fixed to a production, non-interactive deploy. `dir` is
                // allow-listed so a deployment can optionally target a specific project
                // directory, but it is not in the base template: a parameterless deploy
                // runs in the gateway's working directory.
                &["deploy", "--prod", "--yes"],
                &["dir"],
            ),
        ]
    }
}

/// A catalog of configured capabilities and the execution path that runs one.
///
/// The registry flattens connectors into a `capability id -> Capability` map. Resolving
/// is a lookup; executing shapes the request, sends it through the injected
/// [`HttpClient`], rejects non-2xx, and redacts the response by key name (the default set
/// plus the credential's own header and query names) before returning it. It does not scrub
/// the secret by value, and the gateway's execution path does not use it.
#[derive(Default)]
pub struct ConnectorRegistry {
    caps: HashMap<String, Capability>,
}

impl ConnectorRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        ConnectorRegistry::default()
    }

    /// Register every capability of `connector`.
    pub fn register_connector(&mut self, connector: &dyn Connector) -> &mut Self {
        for cap in connector.capabilities() {
            self.caps.insert(cap.id.clone(), cap);
        }
        self
    }

    /// Register a single pre-built capability.
    pub fn register_capability(&mut self, cap: Capability) -> &mut Self {
        self.caps.insert(cap.id.clone(), cap);
        self
    }

    /// Look up a capability by its full id.
    pub fn resolve(&self, capability_id: &str) -> Option<&Capability> {
        self.caps.get(capability_id)
    }

    /// All capabilities, sorted by id for stable output.
    pub fn list(&self) -> Vec<Capability> {
        let mut v: Vec<Capability> = self.caps.values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// All capabilities rendered as core [`CapabilitySpec`]s (the `permaura.list_capabilities` shape).
    pub fn specs(&self) -> Vec<CapabilitySpec> {
        self.list().iter().map(|c| c.to_spec()).collect()
    }

    /// Execute a capability: shape the request (injecting `secret`), send it through
    /// `client`, reject a non-2xx upstream, then redact the body by key name and return it.
    /// An upstream that echoes the secret inside a string or under an unlisted name returns it.
    pub async fn execute(
        &self,
        client: &dyn HttpClient,
        capability_id: &str,
        params: &serde_json::Value,
        secret: &[u8],
    ) -> Result<serde_json::Value, ConnectorError> {
        let cap = self
            .resolve(capability_id)
            .ok_or_else(|| ConnectorError::UnknownCapability(capability_id.to_string()))?;
        let request = build_request(cap, params, secret).map_err(|r| ConnectorError::BadInput(r.reason))?;
        let response = client.send(request).await.map_err(ConnectorError::from)?;
        if !response.is_success() {
            return Err(ConnectorError::Upstream { status: response.status });
        }
        let body = project_response(cap.connector_id(), cap, response.body);
        Ok(redact(body, &effective_redact_keys(cap.credential_field_names())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CommandOutput, CommandRunner, MockCommandRunner};
    use crate::http::{HttpResponse, MockHttpClient};
    use permaura_core::REDACTED;

    fn cap(id: &str, resource: &str, action: Action) -> Capability {
        Capability {
            id: id.into(),
            description: "test".into(),
            risk: RiskTier::Medium,
            action,
            requires_approval: false,
            resource: resource.into(),
            secret_id: "sec".into(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        }
    }

    #[test]
    fn github_pr_create_targets_pulls_with_bearer() {
        let c = cap("github.pull_requests.create", "github_acme", Action::Create);
        let req = build_request(&c, &serde_json::json!({ "repo": "acme/app" }), b"ghp_x").unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.url, "https://api.github.com/repos/acme/app/pulls");
        assert_eq!(req.headers.get("Authorization").unwrap(), "Bearer ghp_x");
    }

    /// The origin each built-in family is said to send to is the one its requests actually go to.
    #[test]
    fn a_built_in_family_is_pinned_where_its_requests_go() {
        let cases = [
            ("github", "github.pull_requests.list", serde_json::json!({ "repo": "acme/app" })),
            ("braintree", "braintree.transactions.search", serde_json::json!({ "status": "failed" })),
            ("vercel", "vercel.projects.list", serde_json::json!({})),
            ("fal", "fal.image.generate", serde_json::json!({ "prompt": "a lighthouse" })),
        ];
        for (family, id, params) in cases {
            let mut c = cap(id, "conn", Action::List);
            c.id = format!("conn.{}", id.split_once('.').unwrap().1);
            let req = build_request_for(family, &c, &params, b"k").unwrap();
            let base = pinned_base_url(family, &c).unwrap();
            assert_eq!(Some(base.as_str()), family_base_url(family), "{family}");
            assert!(req.url.starts_with(&format!("{base}/")), "{family}: {} is not under {base}", req.url);
        }
        let mut imported = cap("conn.items.list", "conn", Action::List);
        imported.http = Some(HttpSpec { base_url: "https://api.example.com/v2".into(), path: "/items".into(), ..Default::default() });
        assert_eq!(pinned_base_url("github", &imported).as_deref(), Some("https://api.example.com/v2"));
        assert_eq!(pinned_base_url("generic-http", &cap("http.request", "conn", Action::Execute)), None);
    }

    #[test]
    fn braintree_search_injects_basic_auth() {
        let c = cap("braintree.transactions.search", "braintree_production", Action::Search);
        let req = build_request(&c, &serde_json::json!({ "status": "failed" }), b"bt_key").unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.url.ends_with("/transactions/advanced_search"));
        assert_eq!(req.headers.get("Authorization").unwrap(), "Basic bt_key");
    }

    #[test]
    fn vercel_projects_list_is_get_v9_with_bearer() {
        let c = cap("vercel.projects.list", "vercel_acme", Action::List);
        let req = build_request(&c, &serde_json::json!({}), b"vc_tok").unwrap();
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.url, "https://api.vercel.com/v9/projects");
        assert_eq!(req.headers.get("Authorization").unwrap(), "Bearer vc_tok");
    }

    #[test]
    fn vercel_deployments_create_posts_v13_deployments() {
        let c = cap("vercel.deployments.create", "vercel_acme", Action::Deploy);
        let req = build_request(
            &c,
            &serde_json::json!({ "name": "acme-web", "target": "production" }),
            b"vc_tok",
        ).unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.url, "https://api.vercel.com/v13/deployments");
        assert_eq!(req.headers.get("Authorization").unwrap(), "Bearer vc_tok");
        // The agent-supplied body is forwarded verbatim.
        assert_eq!(req.json().unwrap()["name"], "acme-web");
    }

    #[test]
    fn vercel_env_read_lists_keys_without_decrypt() {
        let c = cap("vercel.env.read", "vercel_acme", Action::Read);
        let req = build_request(&c, &serde_json::json!({ "project_id": "prj_123" }), b"vc_tok").unwrap();
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.url, "https://api.vercel.com/v9/projects/prj_123/env");
        // Critically: we never ask Vercel to decrypt env values.
        assert!(!req.url.contains("decrypt"));
        assert!(req.json().is_none());
    }

    /// A built-in capability created through a connection is namespaced by the connection id. Its
    /// request must still go to the family's pinned upstream, never to a URL the agent supplies.
    #[test]
    fn namespaced_builtin_capability_ignores_an_agent_url() {
        let mut c = cap("github.repos.read", "github", Action::Read);
        c.id = "github-work.repos.read".into();
        let params = serde_json::json!({ "repo": "a/b", "url": "https://attacker.example/" });
        let req = build_request_for("github", &c, &params, b"ghp_x").unwrap();
        assert_eq!(req.host().as_deref(), Some("api.github.com"));
        assert!(req.url.ends_with("/repos/a/b"), "{}", req.url);
        assert!(!takes_agent_url("github", &c));
        let mut pr = cap("github.pull_requests.list", "github", Action::List);
        pr.id = "github-work.pull_requests.list".into();
        assert!(build_request_for("github", &pr, &params, b"ghp_x").unwrap().url.ends_with("/repos/a/b/pulls"));
    }

    /// Anything with no pinned shape takes its URL from the agent, and says so, so the gateway holds it
    /// to the connection's allowlist.
    #[test]
    fn unpinned_capability_reports_an_agent_url() {
        let c = cap("http.request", "generic_http", Action::Execute);
        assert!(takes_agent_url("generic-http", &c));
        assert!(takes_agent_url("acme", &cap("acme.widgets.read", "acme", Action::Read)));
        let mut ssh = cap("ssh.uptime", "ssh_prod", Action::Read);
        ssh.kind = CapabilityKind::Ssh;
        assert!(!takes_agent_url("ssh", &ssh), "only an HTTP capability is built from a URL");
    }

    #[test]
    fn generic_http_defaults_bearer_when_absent() {
        let c = cap("http.request", "generic_http", Action::Execute);
        let req = build_request(
            &c,
            &serde_json::json!({ "method": "GET", "url": "https://api.x.com/v1/ping" }),
            b"tok",
        ).unwrap();
        assert_eq!(req.host().as_deref(), Some("api.x.com"));
        assert_eq!(req.headers.get("Authorization").unwrap(), "Bearer tok");
    }

    /// An imported capability's request goes to its pinned base's scheme, host and port whatever its path template or parameters say. A path without a leading slash would otherwise run on into the host.
    #[test]
    fn an_imported_request_never_leaves_its_pinned_host() {
        let spec = |path: &str| HttpSpec {
            method: HttpMethod::Get,
            base_url: "https://api.example.com".into(),
            path: path.into(),
            path_params: vec!["account".into()],
            ..Default::default()
        };
        let mut c = cap("acme.items.list", "acme", Action::Read);
        for (path, account) in [
            ("{account}/items", ".evil.example"),
            ("{account}/items", "acme"),
            ("{account}/items", ":8443"),
            ("@evil.example/{account}", "acme"),
        ] {
            c.http = Some(spec(path));
            let params = serde_json::json!({ "account": account });
            let refusal = build_request(&c, &params, b"tok").expect_err(&format!("{path} {account}"));
            assert_eq!(refusal.code, "pinned_host", "{path} {account}: {}", refusal.reason);
        }
        c.http = Some(spec("/{account}/items"));
        let req = build_request(&c, &serde_json::json!({ "account": ".evil.example" }), b"tok").unwrap();
        assert_eq!(req.url, "https://api.example.com/.evil.example/items");
    }

    /// The parser the client dispatches with resolves dot segments, percent-encoded ones included, so a path the approver read is not the path that leaves. The builder refuses them instead.
    #[test]
    fn generic_http_refuses_the_dot_segments_the_dispatch_parser_resolves() {
        let c = cap("http.request", "generic_http", Action::Create);
        for (shown, resolved) in [
            ("https://api.example.test/orders/123/note/../../orders/999/cancel", "/orders/orders/999/cancel"),
            ("https://api.example.test/orders/123/note/%2e%2e/%2e%2e/orders/999/cancel", "/orders/orders/999/cancel"),
            ("https://api.example.test/a/.%2E/b", "/b"),
        ] {
            let sent = crate::egress::screened_url(shown).expect("parses");
            assert_eq!(sent.path(), resolved, "{shown}");
            let params = serde_json::json!({ "method": "POST", "url": shown });
            let refusal = build_request_for("generic-http", &c, &params, b"tok").expect_err(shown);
            assert_eq!(refusal.code, "dot_segment", "{shown}: {}", refusal.reason);
        }
    }

    /// The request carries the URL in the form the client sends it, so the string a hold stores and an approver signs is the one on the wire.
    #[test]
    fn generic_http_sends_the_parsed_url() {
        let c = cap("http.request", "generic_http", Action::Create);
        let params = serde_json::json!({ "method": "POST", "url": "https://API.X.com:443/v1/a b?q=x y" });
        let req = build_request_for("generic-http", &c, &params, b"tok").unwrap();
        assert_eq!(req.url, "https://api.x.com/v1/a%20b?q=x%20y");
        assert_eq!(
            canonical_agent_params("generic-http", &c, &params).expect("rewritten")["url"],
            "https://api.x.com/v1/a%20b?q=x%20y"
        );
        let canonical = serde_json::json!({ "method": "POST", "url": "https://api.x.com/v1/a%20b?q=x%20y" });
        assert!(canonical_agent_params("generic-http", &c, &canonical).is_none(), "already in sent form");
    }

    /// A header the gateway owns (the credential, the host, transport framing) is refused rather
    /// than dropped, so the agent learns why and the approver never sees a request the wire will not carry.
    #[test]
    fn generic_http_refuses_headers_the_gateway_owns() {
        let c = cap("http.request", "generic_http", Action::Execute);
        for name in [
            "Host", "host", "Cookie", "Proxy-Authorization", "Metadata-Flavor", "Content-Length",
            "Transfer-Encoding", "Connection", "X-Api-Key", "X-Secret-Token",
        ] {
            let params = serde_json::json!({ "url": "https://api.x.com/v1/ping", "headers": { name: "x" } });
            let refusal = build_request_for("generic-http", &c, &params, b"tok")
                .expect_err(&format!("header '{name}' must be refused"));
            assert_eq!(refusal.code, "agent_header", "{name}: {}", refusal.reason);
            assert!(refusal.reason.contains(name), "{name}: {}", refusal.reason);
        }
    }

    /// The vault credential is the only credential on the request, under one spelling. Before, an
    /// agent's `Authorization` suppressed the injection and an `authorization` travelled beside it.
    #[test]
    fn generic_http_carries_the_vault_credential_once_and_no_other() {
        let c = cap("http.request", "generic_http", Action::Execute);
        for spelling in ["Authorization", "authorization", "AUTHORIZATION"] {
            let params = serde_json::json!({
                "url": "https://api.x.com/v1/ping", "headers": { spelling: "Bearer attacker" }
            });
            let refusal = build_request_for("generic-http", &c, &params, b"tok").expect_err(spelling);
            assert_eq!(refusal.code, "agent_header", "{}", refusal.reason);
        }
        let params =
            serde_json::json!({ "url": "https://api.x.com/v1/ping", "headers": { "Accept": "application/json" } });
        let req = build_request_for("generic-http", &c, &params, b"tok").unwrap();
        let credentials: Vec<(&String, &String)> =
            req.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("authorization")).collect();
        assert_eq!(credentials, vec![(&"Authorization".to_string(), &"Bearer tok".to_string())]);
    }

    #[test]
    fn generic_http_refuses_a_header_value_with_a_line_break_or_a_name_given_twice() {
        let c = cap("http.request", "generic_http", Action::Execute);
        let crlf = serde_json::json!({ "url": "https://api.x.com/", "headers": { "Accept": "text/plain\r\nHost: evil" } });
        assert_eq!(build_request_for("generic-http", &c, &crlf, b"tok").unwrap_err().code, "agent_header");
        let twice = serde_json::json!({ "url": "https://api.x.com/", "headers": { "Accept": "a", "accept": "b" } });
        assert_eq!(build_request_for("generic-http", &c, &twice, b"tok").unwrap_err().code, "agent_header");
    }

    /// Ordinary headers, and the content type of a body the agent wrote, still pass.
    #[test]
    fn generic_http_keeps_ordinary_headers() {
        let c = cap("http.request", "generic_http", Action::Execute);
        let params = serde_json::json!({
            "url": "https://api.x.com/v1/items", "method": "POST", "body": { "a": 1 },
            "headers": { "Accept": "application/json", "X-Request-Id": "r-1", "Content-Type": "application/json" }
        });
        let req = build_request_for("generic-http", &c, &params, b"tok").unwrap();
        assert_eq!(req.headers.get("Accept").unwrap(), "application/json");
        assert_eq!(req.headers.get("X-Request-Id").unwrap(), "r-1");
        assert_eq!(req.headers.get("Content-Type").unwrap(), "application/json");
        assert_eq!(req.headers.get("Authorization").unwrap(), "Bearer tok");
    }

    /// A capability with no pinned shape and a read-only action sends GET and nothing else, so the
    /// method on the wire cannot outrun the action policy judged.
    #[test]
    fn a_shapeless_read_capability_sends_only_get() {
        for action in [Action::Read, Action::List, Action::Search, Action::Export] {
            let c = cap("acme.widgets.read", "acme", action);
            for method in ["POST", "PUT", "PATCH", "DELETE", "delete"] {
                let params = serde_json::json!({ "url": "https://api.acme.test/widgets/1", "method": method });
                let refusal = build_request_for("acme", &c, &params, b"tok")
                    .expect_err(&format!("{} with {method}", action.as_str()));
                assert_eq!(refusal.code, "method_for_action", "{}", refusal.reason);
                assert!(refusal.reason.contains(&method.to_ascii_uppercase()), "{}", refusal.reason);
            }
            let get = serde_json::json!({ "url": "https://api.acme.test/widgets/1", "method": "GET" });
            assert_eq!(build_request_for("acme", &c, &get, b"tok").unwrap().method, HttpMethod::Get);
            let unspecified = serde_json::json!({ "url": "https://api.acme.test/widgets/1" });
            assert_eq!(build_request_for("acme", &c, &unspecified, b"tok").unwrap().method, HttpMethod::Get);
        }
        let exec = cap("http.request", "generic_http", Action::Execute);
        let delete = serde_json::json!({ "url": "https://api.x.com/v1/items/1", "method": "DELETE" });
        assert_eq!(build_request_for("generic-http", &exec, &delete, b"tok").unwrap().method, HttpMethod::Delete);
        let create = cap("acme.widgets.create", "acme", Action::Create);
        let post = serde_json::json!({ "url": "https://api.acme.test/widgets", "method": "POST", "body": {} });
        assert_eq!(build_request_for("acme", &create, &post, b"tok").unwrap().method, HttpMethod::Post);
    }

    #[test]
    fn generic_http_refuses_more_headers_than_it_forwards_without_reading_them() {
        let c = cap("http.request", "generic_http", Action::Execute);
        let with_headers = |n: usize| {
            let headers: serde_json::Map<String, serde_json::Value> =
                (0..n).map(|i| (format!("x{i:06}"), serde_json::Value::from("v"))).collect();
            serde_json::json!({ "url": "https://api.x.com/", "headers": serde_json::Value::Object(headers) })
        };
        let at_cap = build_request_for("generic-http", &c, &with_headers(MAX_AGENT_HEADERS), b"tok").unwrap();
        assert_eq!(at_cap.headers.len(), MAX_AGENT_HEADERS + 1, "every header kept, plus the credential");
        let past = request_refusal("generic-http", &c, &with_headers(MAX_AGENT_HEADERS + 1)).expect("one past the cap");
        assert_eq!(past.code, "agent_header", "{}", past.reason);

        let flood = with_headers(150_000);
        let started = std::time::Instant::now();
        let refusal = request_refusal("generic-http", &c, &flood).expect("150,000 headers are refused");
        let took = started.elapsed();
        assert_eq!(refusal.code, "agent_header", "{}", refusal.reason);
        assert!(refusal.reason.contains("150000"), "{}", refusal.reason);
        assert!(took < std::time::Duration::from_secs(1), "refused in {took:?}");
    }

    /// Both refusals reach the gateway's pre-policy gate, so each is a recorded denial.
    #[test]
    fn the_generic_refusals_are_reported_before_policy() {
        let exec = cap("http.request", "generic_http", Action::Execute);
        let spoof = serde_json::json!({ "url": "https://api.x.com/", "headers": { "Host": "internal.x.com" } });
        assert_eq!(request_refusal("generic-http", &exec, &spoof).unwrap().code, "agent_header");
        let read = cap("acme.widgets.read", "acme", Action::Read);
        let delete = serde_json::json!({ "url": "https://api.acme.test/widgets/1", "method": "DELETE" });
        assert_eq!(request_refusal("acme", &read, &delete).unwrap().code, "method_for_action");
        let fine = serde_json::json!({ "url": "https://api.x.com/", "headers": { "Accept": "*/*" } });
        assert!(request_refusal("generic-http", &exec, &fine).is_none());
    }

    #[test]
    fn builtin_connectors_populate_registry() {
        let mut reg = ConnectorRegistry::new();
        reg.register_connector(&GitHubConnector::new("github_acme", "sec_gh"))
            .register_connector(&BraintreeConnector::new("braintree_production", "sec_bt"))
            .register_connector(&VercelConnector::new("vercel_acme", "sec_vercel"))
            .register_connector(&VercelCliConnector::new("vercel_cli", "sec_vercel_cli"))
            .register_connector(&GenericHttpConnector::new("generic_http", "sec_http"));
        // 4 github + 4 braintree + 7 vercel + 3 vercel-cli + 1 http = 19 capabilities.
        assert_eq!(reg.list().len(), 19);
        let refund = reg.resolve("braintree.transactions.refund").unwrap();
        assert_eq!(refund.risk, RiskTier::Critical);
        assert!(refund.requires_approval);
        assert!(reg.resolve("braintree.transactions.delete").is_none());
        // Vercel deployments.create is High risk (the policy engine escalates it to approval).
        let deploy = reg.resolve("vercel.deployments.create").unwrap();
        assert_eq!(deploy.risk, RiskTier::High);
        // The Vercel CLI command capabilities carry a CommandSpec, not an HTTP shape.
        let whoami = reg.resolve("vercel-cli.whoami").unwrap();
        assert_eq!(whoami.kind, CapabilityKind::Command);
        assert_eq!(whoami.risk, RiskTier::Low);
        let cli_deploy = reg.resolve("vercel-cli.deploy").unwrap();
        assert_eq!(cli_deploy.kind, CapabilityKind::Command);
        // High risk so the policy engine auto-escalates the CLI deploy to human approval.
        assert_eq!(cli_deploy.risk, RiskTier::High);
    }

    #[tokio::test]
    async fn execute_redacts_sensitive_response_fields() {
        let mut reg = ConnectorRegistry::new();
        reg.register_connector(&BraintreeConnector::new("braintree_production", "sec_bt"));
        let client = MockHttpClient::new();
        client.push_response(HttpResponse::json(
            200,
            serde_json::json!({
                "id": "txn_1",
                "amount": 4900,
                "status": "settled",
                "card_number": "4111111111111111",
                "cvv": "123"
            }),
        ));
        let out = reg
            .execute(
                &client,
                "braintree.transactions.read",
                &serde_json::json!({ "transaction_id": "txn_1" }),
                b"bt_key",
            )
            .await
            .unwrap();
        // Non-sensitive fields pass through; PAN + CVV are redacted before the agent sees them.
        assert_eq!(out["status"], "settled");
        assert_eq!(out["amount"], 4900);
        assert_eq!(out["card_number"], REDACTED);
        assert_eq!(out["cvv"], REDACTED);
        // The request was shaped against the real Braintree endpoint with injected basic auth.
        let sent = client.last_request().unwrap();
        assert_eq!(sent.headers.get("Authorization").unwrap(), "Basic bt_key");
        assert!(sent.url.ends_with("/transactions/txn_1"));
    }

    #[tokio::test]
    async fn execute_unknown_capability_errors() {
        let reg = ConnectorRegistry::new();
        let client = MockHttpClient::new();
        let err = reg
            .execute(&client, "nope.do_thing", &serde_json::json!({}), b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::UnknownCapability(_)));
    }

    #[tokio::test]
    async fn execute_rejects_non_success_upstream() {
        let mut reg = ConnectorRegistry::new();
        reg.register_connector(&GitHubConnector::new("github_acme", "sec_gh"));
        let client = MockHttpClient::new();
        client.push_response(HttpResponse::json(403, serde_json::json!({ "message": "Forbidden" })));
        let err = reg
            .execute(&client, "github.repos.read", &serde_json::json!({ "repo": "x/y" }), b"ghp")
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::Upstream { status: 403 }));
    }

    // ── Command connector (Vercel CLI) ──────────────────────────────────────────

    fn vercel_cli_cap(id: &str) -> Capability {
        VercelCliConnector::new("vercel_cli", "sec_vercel_cli")
            .capabilities()
            .into_iter()
            .find(|c| c.id == id)
            .expect("capability exists")
    }

    #[test]
    fn build_command_whoami_shapes_argv_and_injects_token() {
        let cap = vercel_cli_cap("vercel-cli.whoami");
        let spec = cap.command.as_ref().unwrap();
        let inv = build_command(spec, &serde_json::json!({}), b"vc_scoped_token").unwrap();
        assert_eq!(inv.program, "vercel");
        assert_eq!(inv.args, vec!["whoami".to_string()]);
        // The scoped token is injected as VERCEL_TOKEN, never on the argv.
        assert_eq!(inv.envs.get("VERCEL_TOKEN").unwrap(), "vc_scoped_token");
        assert!(inv.args.iter().all(|a| !a.contains("vc_scoped_token")));
    }

    #[test]
    fn build_command_deploy_shapes_prod_yes_argv() {
        let cap = vercel_cli_cap("vercel-cli.deploy");
        let spec = cap.command.as_ref().unwrap();
        let inv = build_command(spec, &serde_json::json!({}), b"vc_tok").unwrap();
        assert_eq!(inv.program, "vercel");
        assert_eq!(
            inv.args,
            vec!["deploy".to_string(), "--prod".to_string(), "--yes".to_string()]
        );
        assert_eq!(inv.envs.get("VERCEL_TOKEN").unwrap(), "vc_tok");
    }

    #[test]
    fn build_command_substitutes_whitelisted_placeholder() {
        // A spec whose template carries an allow-listed {dir} placeholder.
        let spec = CommandSpec {
            program: "vercel".into(),
            args_template: vec!["deploy".into(), "--prod".into(), "--yes".into(), "{dir}".into()],
            secret_env: "VERCEL_TOKEN".into(),
            allowed_placeholders: vec!["dir".into()],
        };
        let inv = build_command(&spec, &serde_json::json!({ "dir": "apps/web" }), b"vc_tok").unwrap();
        assert_eq!(
            inv.args,
            vec![
                "deploy".to_string(),
                "--prod".to_string(),
                "--yes".to_string(),
                "apps/web".to_string()
            ]
        );
    }

    #[test]
    fn build_command_rejects_shell_metacharacters() {
        let spec = CommandSpec {
            program: "vercel".into(),
            args_template: vec!["deploy".into(), "{dir}".into()],
            secret_env: "VERCEL_TOKEN".into(),
            allowed_placeholders: vec!["dir".into()],
        };
        // A classic injection attempt: try to chain a second command.
        let err = build_command(
            &spec,
            &serde_json::json!({ "dir": "app; rm -rf /" }),
            b"vc_tok",
        )
        .unwrap_err();
        assert!(matches!(err, ConnectorError::BadInput(_)));
    }

    #[test]
    fn build_command_rejects_non_whitelisted_placeholder() {
        // The template references {evil} but the allow-list only sanctions {dir}.
        let spec = CommandSpec {
            program: "vercel".into(),
            args_template: vec!["deploy".into(), "{evil}".into()],
            secret_env: "VERCEL_TOKEN".into(),
            allowed_placeholders: vec!["dir".into()],
        };
        let err = build_command(&spec, &serde_json::json!({ "evil": "x" }), b"vc_tok").unwrap_err();
        assert!(matches!(err, ConnectorError::BadInput(_)));
    }

    #[tokio::test]
    async fn mock_runner_records_invocation_for_whoami() {
        // End-to-end of the command seam without a real CLI: build_command → MockCommandRunner.
        let cap = vercel_cli_cap("vercel-cli.whoami");
        let spec = cap.command.as_ref().unwrap();
        let inv = build_command(spec, &serde_json::json!({}), b"vc_tok").unwrap();

        let runner = MockCommandRunner::with_output(CommandOutput {
            code: 0,
            stdout: "permaura-bot\n".into(),
            stderr: String::new(),
        });
        let out = runner.run(inv).await.unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout, "permaura-bot\n");

        let captured = runner.last_invocation().unwrap();
        assert_eq!(captured.args, vec!["whoami".to_string()]);
        assert_eq!(captured.envs.get("VERCEL_TOKEN").unwrap(), "vc_tok");
    }

    fn imported(spec: HttpSpec) -> Capability {
        Capability { http: Some(spec), ..cap("wp.posts.get", "wp", Action::Read) }
    }

    /// However the definition arrived, a capability on a connection of a family the gateway pins to a fixed host sends that family's credential nowhere else.
    #[test]
    fn a_fixed_host_family_never_sends_its_credential_to_an_imported_host() {
        let elsewhere = imported(HttpSpec { base_url: "https://collector.example".into(), path: "/user/repos".into(), ..Default::default() });
        for family in ["github", "braintree", "vercel", "fal"] {
            let refusal = build_request_for(family, &elsewhere, &serde_json::json!({}), b"ghp_token").unwrap_err();
            assert_eq!(refusal.code, "pinned_host", "{family}");
            assert!(request_refusal(family, &elsewhere, &serde_json::json!({})).is_some(), "{family}");
        }
        let home = imported(HttpSpec { base_url: "https://api.github.com".into(), path: "/user/repos".into(), ..Default::default() });
        assert_eq!(build_request_for("github", &home, &serde_json::json!({}), b"t").unwrap().url, "https://api.github.com/user/repos");
        assert!(build_request_for("acme", &elsewhere, &serde_json::json!({}), b"t").is_ok(), "an unpinned family keeps its imported host");
        let reason = build_request_for("github", &elsewhere, &serde_json::json!({}), b"t").unwrap_err().reason;
        assert!(reason.contains("OpenAPI import") && reason.contains("id of its own"), "the refusal names the way back: {reason}");
    }

    /// A family's credential may go to each of the vendor's own hosts for it, and to nothing else: fal's queue, Braintree's sandbox and GraphQL hosts.
    #[test]
    fn a_family_pins_every_host_its_vendor_serves_the_credential_on() {
        let at = |base: &str| imported(HttpSpec { base_url: base.into(), path: "/x".into(), ..Default::default() });
        for (family, base) in [
            ("fal", "https://queue.fal.run"),
            ("fal", "https://fal.run"),
            ("braintree", "https://payments.braintree-api.com/graphql"),
            ("braintree", "https://payments.sandbox.braintree-api.com"),
            ("braintree", "https://api.sandbox.braintreegateway.com"),
            ("github", "https://API.GITHUB.COM:443"),
        ] {
            assert!(build_request_for(family, &at(base), &serde_json::json!({}), b"t").is_ok(), "{family} {base}");
        }
        for (family, base) in [
            ("github", "https://ghe.corp.example/api/v3"),
            ("github", "https://uploads.github.com"),
            ("github", "http://api.github.com"),
            ("github", "https://api.github.com:8443"),
            ("github", "https://user@api.github.com"),
            ("fal", "https://rest.alpha.fal.ai"),
            ("braintree", "https://braintree-api.com.attacker.example"),
        ] {
            assert_eq!(build_request_for(family, &at(base), &serde_json::json!({}), b"t").unwrap_err().code, "pinned_host", "{family} {base}");
        }
    }

    /// WordPress, and other frameworks, run a request as the method a `_method` parameter or a method-override header names, so no spec may carry one, whoever wrote it: a static header, a declared header, query or body parameter, the credential's own name, or a query written into the path template.
    #[test]
    fn a_method_override_is_refused_for_every_source() {
        let get = |spec: HttpSpec| imported(HttpSpec { base_url: "https://site.example/wp-json".into(), ..spec });
        let carriers = [
            HttpSpec { path: "/wp/v2/posts/{id}".into(), path_params: vec!["id".into()], static_headers: BTreeMap::from([("X-HTTP-Method-Override".into(), "DELETE".into())]), ..Default::default() },
            HttpSpec { path: "/wp/v2/posts/{id}".into(), path_params: vec!["id".into()], static_headers: BTreeMap::from([("x-http-method".into(), "DELETE".into())]), ..Default::default() },
            HttpSpec { path: "/wp/v2/posts/{id}".into(), path_params: vec!["id".into()], static_headers: BTreeMap::from([("X-Method-Override".into(), "DELETE".into())]), ..Default::default() },
            HttpSpec { path: "/wp/v2/posts/{id}?_method=DELETE&force=true".into(), path_params: vec!["id".into()], ..Default::default() },
            HttpSpec { path: "/wp/v2/posts/{id}#frag".into(), path_params: vec!["id".into()], ..Default::default() },
            HttpSpec { path: "/wp/v2/posts/{id}".into(), path_params: vec!["id".into()], query_params: vec!["_method".into(), "force".into()], ..Default::default() },
            HttpSpec { path: "/wp/v2/posts/{id}".into(), path_params: vec!["id".into()], query_params: vec!["_METHOD".into()], ..Default::default() },
            HttpSpec { method: HttpMethod::Post, path: "/wp/v2/posts".into(), body_params: vec!["_method".into()], ..Default::default() },
            HttpSpec { path: "/wp/v2/posts".into(), header_params: vec!["X-HTTP-Method-Override".into()], ..Default::default() },
            HttpSpec { path: "/wp/v2/posts".into(), auth: AuthScheme::ApiKeyQuery { param: "_method".into() }, ..Default::default() },
            HttpSpec { path: "/wp/v2/posts".into(), auth: AuthScheme::ApiKeyHeader { header: "X-HTTP-Method-Override".into() }, ..Default::default() },
        ];
        for spec in carriers {
            let cap = get(spec.clone());
            let refusal = build_request_for("wordpress", &cap, &serde_json::json!({ "id": 42, "_method": "DELETE", "force": true }), b"u:p").unwrap_err();
            assert_eq!(refusal.code, "method_override", "{spec:?}");
            assert!(request_refusal("wordpress", &cap, &serde_json::json!({ "id": 42 })).is_some());
            assert!(method_override_refusal(&spec).is_some());
        }
        let plain = get(HttpSpec { path: "/wp/v2/posts/{id}".into(), path_params: vec!["id".into()], query_params: vec!["context".into()], ..Default::default() });
        assert!(build_request_for("wordpress", &plain, &serde_json::json!({ "id": 42, "context": "view" }), b"u:p").is_ok());
        assert!(!is_agent_settable_header("X-HTTP-Method-Override"), "an agent cannot set one either");
    }

    #[test]
    fn a_route_param_carries_the_path_in_the_query_and_keeps_params_after_it() {
        let c = imported(HttpSpec {
            base_url: "https://example.com/".into(),
            path: "/wp/v2/posts/{id}".into(),
            path_params: vec!["id".into()],
            query_params: vec!["context".into()],
            route_param: Some("rest_route".into()),
            auth: AuthScheme::Basic { key_as_username: false },
            ..Default::default()
        });
        let req = build_request(&c, &serde_json::json!({ "id": 7, "context": "view" }), b"u:p").unwrap();
        assert_eq!(req.url, "https://example.com/?rest_route=/wp/v2/posts/7&context=view");
    }

    #[test]
    fn an_agent_value_cannot_add_a_query_parameter_through_the_route() {
        let c = imported(HttpSpec {
            base_url: "https://example.com".into(),
            path: "/wp/v2/posts/{id}".into(),
            path_params: vec!["id".into()],
            route_param: Some("rest_route".into()),
            ..Default::default()
        });
        let req = build_request(&c, &serde_json::json!({ "id": "7&status=trash#x" }), b"t").unwrap();
        assert_eq!(req.url, "https://example.com/?rest_route=/wp/v2/posts/7%26status%3Dtrash%23x");
        assert_eq!(req.url.matches('&').count(), 0, "the agent value stayed inside the route value");
    }

    const SEGMENT_CROSSINGS: [&str; 12] = [
        "42/refunds",
        "42\\refunds",
        "42%2frefunds",
        "42%2Frefunds",
        "42%5crefunds",
        "42%5Crefunds",
        "42%252Frefunds",
        "42%25252frefunds",
        "%2e%2e",
        "%252E%252E",
        "/",
        "%2F",
    ];

    /// PHP decodes the `rest_route` value before WordPress routes it, so a separator in a path value, encoded or not, would reach a sibling route the grant never named.
    #[test]
    fn a_path_value_cannot_reach_a_sibling_route_through_the_route_param() {
        let c = imported(HttpSpec {
            base_url: "https://shop.example".into(),
            path: "/wc/v3/orders/{id}".into(),
            path_params: vec!["id".into()],
            route_param: Some("rest_route".into()),
            ..Default::default()
        });
        for id in SEGMENT_CROSSINGS {
            let refusal = build_request(&c, &serde_json::json!({ "id": id }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{id}");
        }
        let req = build_request(&c, &serde_json::json!({ "id": 42 }), b"t").unwrap();
        assert_eq!(req.url, "https://shop.example/?rest_route=/wc/v3/orders/42");
        let req = build_request(&c, &serde_json::json!({ "id": "50%" }), b"t").unwrap();
        assert_eq!(req.url, "https://shop.example/?rest_route=/wc/v3/orders/50%25");
    }

    /// In the ordinary path form the same values are refused, so no upstream that decodes a path segment sees a separator either.
    #[test]
    fn a_path_value_cannot_cross_a_segment_in_a_plain_path() {
        let c = imported(HttpSpec {
            base_url: "https://shop.example/wp-json".into(),
            path: "/wc/v3/orders/{id}".into(),
            path_params: vec!["id".into()],
            ..Default::default()
        });
        for id in SEGMENT_CROSSINGS {
            let refusal = build_request(&c, &serde_json::json!({ "id": id }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{id}");
        }
        let req = build_request(&c, &serde_json::json!({ "id": "order-42" }), b"t").unwrap();
        assert_eq!(req.url, "https://shop.example/wp-json/wc/v3/orders/order-42");
    }

    fn patterned(base_url: &str, path: &str, name: &str, pattern: &str, encode_slash: bool, route_param: bool) -> Capability {
        imported(HttpSpec {
            base_url: base_url.into(),
            path: path.into(),
            path_params: vec![name.into()],
            route_param: route_param.then(|| "rest_route".into()),
            path_patterns: BTreeMap::from([(name.into(), PathPattern { pattern: pattern.into(), encode_slash })]),
            ..Default::default()
        })
    }

    const WP_PLUGIN: &str = r"(?i)[^.\/]+(?:\/[^.\/]+)?";
    const WP_TEMPLATE: &str = r#"(?i)([^\/:<>\*\?"\|]+(?:\/[^\/:<>\*\?"\|]+)?)[\/\w%-]+"#;

    /// A WordPress plugin id is `<dir>/<file>`, which the plugins route's own pattern admits, so it is sent as WordPress names it.
    #[test]
    fn a_slash_the_routes_own_pattern_admits_is_sent_as_a_separator() {
        let c = patterned("https://site.example", "/wp/v2/plugins/{plugin}", "plugin", WP_PLUGIN, false, true);
        let req = build_request(&c, &serde_json::json!({ "plugin": "akismet/akismet" }), b"t").unwrap();
        assert_eq!(req.url, "https://site.example/?rest_route=/wp/v2/plugins/akismet/akismet");
        let req = build_request(&c, &serde_json::json!({ "plugin": "hello" }), b"t").unwrap();
        assert_eq!(req.url, "https://site.example/?rest_route=/wp/v2/plugins/hello");

        let pretty = patterned("https://site.example/wp-json", "/wp/v2/plugins/{plugin}", "plugin", WP_PLUGIN, false, false);
        let req = build_request(&pretty, &serde_json::json!({ "plugin": "woocommerce/woocommerce" }), b"t").unwrap();
        assert_eq!(req.url, "https://site.example/wp-json/wp/v2/plugins/woocommerce/woocommerce");

        let template = patterned("https://site.example", "/wp/v2/templates/{id}", "id", WP_TEMPLATE, false, true);
        let req = build_request(&template, &serde_json::json!({ "id": "twentytwentyfour//home" }), b"t").unwrap();
        assert_eq!(req.url, "https://site.example/?rest_route=/wp/v2/templates/twentytwentyfour//home");
    }

    /// Admitting a '/' where the route pattern allows one keeps the separator rule: the pattern decides where a literal '/' may stand, and nothing else crosses a segment.
    #[test]
    fn a_patterned_value_still_cannot_leave_its_route() {
        let c = patterned("https://site.example", "/wp/v2/plugins/{plugin}", "plugin", WP_PLUGIN, false, true);
        for plugin in [
            "akismet/akismet/extra",
            "akismet%2Fakismet",
            "akismet%252Fakismet",
            "akismet/akismet%2F..",
            "akismet\\akismet",
            "../users",
            "akismet/..",
            "%2e%2e/x",
            "a/%252E%252E",
            "/akismet",
        ] {
            let refusal = build_request(&c, &serde_json::json!({ "plugin": plugin }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{plugin}");
        }

        let orders = patterned("https://shop.example", "/wc/v3/orders/{id}", "id", r"(?i)[\d]+", false, true);
        for id in SEGMENT_CROSSINGS.iter().copied().chain(["abc", "42 ", "42?x=1"]) {
            let refusal = build_request(&orders, &serde_json::json!({ "id": id }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{id}");
        }
        let req = build_request(&orders, &serde_json::json!({ "id": 42 }), b"t").unwrap();
        assert_eq!(req.url, "https://shop.example/?rest_route=/wc/v3/orders/42");

        let unreadable = patterned("https://shop.example", "/wc/v3/orders/{id}", "id", r"(?<=x)\d+", false, true);
        assert_eq!(build_request(&unreadable, &serde_json::json!({ "id": 42 }), b"t").unwrap_err().code, "path_identifier");
    }

    /// WordPress serves the first registered route that matches, so a '/' the global-styles id admits must not fill a path the theme variations route also matches.
    #[test]
    fn a_slash_that_reaches_a_sibling_route_is_refused() {
        let mut c = patterned("https://site.example", "/wp/v2/global-styles/{id}", "id", r"(?i)[\/\w-]+", false, true);
        c.http.as_mut().unwrap().sibling_routes = vec![
            r"/wp/v2/global-styles/themes/(?P<stylesheet>[\/\s%\w\.\(\)\[\]\@_\-]+)/variations".into(),
            r#"/wp/v2/global-styles/themes/(?P<stylesheet>[^\/:<>\*\?"\|]+(?:\/[^\/:<>\*\?"\|]+)?)"#.into(),
        ];
        for id in ["themes/twentytwentyfour/variations", "THEMES/twentytwentyfour/Variations", "themes/twentytwentyfour"] {
            let refusal = build_request(&c, &serde_json::json!({ "id": id }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{id}");
            assert!(refusal.reason.contains("another route"), "{}", refusal.reason);
        }
        for id in ["themes/twentytwentyfour/variations/", "themes/twentytwentyfour/variations//"] {
            let refusal = build_request(&c, &serde_json::json!({ "id": id }), b"t").unwrap_err();
            assert!(refusal.reason.contains("another route"), "WordPress strips the trailing '/' of {id}: {}", refusal.reason);
        }
        let req = build_request(&c, &serde_json::json!({ "id": "42" }), b"t").unwrap();
        assert_eq!(req.url, "https://site.example/?rest_route=/wp/v2/global-styles/42");
        let req = build_request(&c, &serde_json::json!({ "id": "custom/style" }), b"t").unwrap();
        assert_eq!(req.url, "https://site.example/?rest_route=/wp/v2/global-styles/custom/style");

        // PCRE's '$' also matches before a final newline, and the theme id's negated class admits one, so WordPress would route this to the variations route.
        for route_param in [true, false] {
            let mut theme = patterned("https://site.example", "/wp/v2/global-styles/themes/{stylesheet}", "stylesheet", r#"(?i)[^\/:<>\*\?"\|]+(?:\/[^\/:<>\*\?"\|]+)?"#, false, route_param);
            theme.http.as_mut().unwrap().sibling_routes = vec![r"/wp/v2/global-styles/themes/(?P<stylesheet>[\/\s%\w\.\(\)\[\]\@_\-]+)/variations".into()];
            for stylesheet in ["twentytwentyfour/variations", "twentytwentyfour/variations\n", "twentytwentyfour/Variations\n"] {
                let refusal = build_request(&theme, &serde_json::json!({ "stylesheet": stylesheet }), b"t").unwrap_err();
                assert!(refusal.reason.contains("another route"), "{stylesheet:?}: {}", refusal.reason);
            }
            assert!(build_request(&theme, &serde_json::json!({ "stylesheet": "twentytwentyfour/style" }), b"t").is_ok());
        }

        // A backreference has no reading this gateway can compile, even as a superset of itself.
        c.http.as_mut().unwrap().sibling_routes = vec![r"/wp/v2/global-styles/(?P<a>x)(?P=a)".into()];
        assert_eq!(build_request(&c, &serde_json::json!({ "id": "a/b" }), b"t").unwrap_err().code, "path_identifier", "an unreadable sibling counts as a match");
        let refusal = build_request(&c, &serde_json::json!({ "id": "ab" }), b"t").unwrap_err();
        assert!(refusal.reason.contains("cannot read"), "a value with no '/' can match a sibling too: {}", refusal.reason);
    }

    /// A sibling route this gateway cannot compile as written is read as a superset of itself (its lookarounds dropped, a `-` beside a class escape taken literally), so it refuses every value it could match, and may refuse some it could not.
    #[test]
    fn an_unreadable_sibling_is_read_as_a_superset_of_itself() {
        for generic in [r"/acme/v1/(?P<page>(?!admin)[\w-]+)", r"/acme/v1/(?P<page>[\w-.]+)", r"/acme/v1/(?P<page>(?>[\w-]+))"] {
            let mut items = patterned("https://site.example", "/acme/v1/items/{id}", "id", r"(?i)[\d]+", false, false);
            items.http.as_mut().unwrap().sibling_routes = vec![generic.into(), "/acme/v1/items/export".into()];
            assert!(build_request(&items, &serde_json::json!({ "id": "42" }), b"t").is_ok(), "{generic}: an ordinary id is sent");
            let mut reports = patterned("https://site.example", "/acme/v1/{page}", "page", r"(?i)[\w]+", false, false);
            reports.http.as_mut().unwrap().sibling_routes = vec![generic.into(), "/acme/v1/export".into()];
            assert_eq!(build_request(&reports, &serde_json::json!({ "page": "export" }), b"t").unwrap_err().code, "path_identifier", "{generic}: the literal sibling still refuses");
            assert_eq!(build_request(&reports, &serde_json::json!({ "page": "monthly" }), b"t").unwrap_err().code, "path_identifier", "{generic}: the generic sibling matches this value, as WordPress could serve it");
            let refusal = build_request(&reports, &serde_json::json!({ "page": "monthly" }), b"t").unwrap_err();
            assert!(refusal.reason.contains("might also match"), "a widened pattern proves only a possibility: {}", refusal.reason);
        }
        assert_eq!(readable_superset(r"(?!admin)[\w-.]+(?<=x)"), r"[\w\-.]+");
    }

    /// A one-segment refusal offers a re-sync only to a WordPress capability stored before its route's pattern was read; a preset, an OpenAPI route or a WordPress route read and left without a pattern is told plainly that '/' cannot go there.
    #[test]
    fn a_one_segment_refusal_offers_a_resync_only_where_one_would_record_a_pattern() {
        let spec = |read: bool, route_param: bool| {
            imported(HttpSpec {
                base_url: "https://site.example".into(),
                path: "/wp/v2/things/{id}".into(),
                path_params: vec!["id".into()],
                route_param: route_param.then(|| "rest_route".into()),
                route_patterns_read: read,
                ..Default::default()
            })
        };
        let refuse = |connector: &str, c: &Capability| build_request_for(connector, c, &serde_json::json!({ "id": "a/b" }), b"t").unwrap_err();

        let stored_before = refuse("wordpress", &spec(false, true));
        assert_eq!(stored_before.code, "path_identifier");
        assert!(stored_before.reason.contains("re-sync"), "{}", stored_before.reason);

        for (connector, c) in [
            ("wordpress", spec(true, true)),
            ("wordpress", spec(true, false)),
            ("stripe", spec(false, false)),
            ("openapi", spec(false, true)),
            ("acme-from-preset", spec(false, true)),
        ] {
            let refusal = refuse(connector, &c);
            assert_eq!(refusal.code, "path_identifier", "{connector}");
            assert!(!refusal.reason.contains("re-sync"), "{connector}: {}", refusal.reason);
            assert!(refusal.reason.contains("cannot contain '/' on this route"), "{connector}: {}", refusal.reason);
        }
    }

    #[test]
    fn a_template_is_filled_in_one_pass() {
        let values = BTreeMap::from([("a", "{b}".to_string()), ("b", "x".to_string())]);
        assert_eq!(fill_template("/r/{a}/{b}/{c}", &values), "/r/{b}/x/{c}");
    }

    /// An OpenAPI path parameter is one segment, so a '/' its pattern admits travels as %2F, the way a project path is addressed.
    #[test]
    fn an_openapi_pattern_that_admits_a_slash_sends_it_encoded_in_one_segment() {
        let c = patterned("https://git.example/api/v4", "/projects/{id}", "id", r"^[\w.-]+(/[\w.-]+)+$", true, false);
        let req = build_request(&c, &serde_json::json!({ "id": "group/sub/project" }), b"t").unwrap();
        assert_eq!(req.url, "https://git.example/api/v4/projects/group%2Fsub%2Fproject");
        for id in ["group%2Fproject", "group%252Fproject", "group/..", "group/./x", "group\\project", "group"] {
            let refusal = build_request(&c, &serde_json::json!({ "id": id }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{id}");
        }
    }

    /// An OpenAPI path parameter with no pattern sends a '/' as %2F inside its segment, so GitLab's project id reaches its project; WordPress keeps the one-segment rule.
    #[test]
    fn a_patternless_openapi_value_sends_a_slash_encoded_in_one_segment() {
        let gitlab = imported(HttpSpec {
            base_url: "https://gitlab.example/api/v4".into(),
            path: "/projects/{id}/issues".into(),
            path_params: vec!["id".into()],
            ..Default::default()
        });
        let req = build_request_for("openapi", &gitlab, &serde_json::json!({ "id": "group/project" }), b"t").unwrap();
        assert_eq!(req.url, "https://gitlab.example/api/v4/projects/group%2Fproject/issues");
        let req = build_request_for("openapi", &gitlab, &serde_json::json!({ "id": 42 }), b"t").unwrap();
        assert_eq!(req.url, "https://gitlab.example/api/v4/projects/42/issues");
        for id in ["../x", "x/..", "group/./project", "a\\b", "a%2Fb", "a%2fb", "a%5Cb", "a%252Fb", "%2e%2e", "..", "."] {
            let refusal = build_request_for("openapi", &gitlab, &serde_json::json!({ "id": id }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{id}");
        }
        assert_eq!(
            build_request_for("gitlab-work", &gitlab, &serde_json::json!({ "id": "group/project" }), b"t").unwrap_err().code,
            "path_identifier",
            "only an OpenAPI connection sends the slash"
        );

        let orders = |route_param: bool| {
            imported(HttpSpec {
                base_url: "https://shop.example".into(),
                path: "/wc/v3/orders/{id}".into(),
                path_params: vec!["id".into()],
                route_param: route_param.then(|| "rest_route".into()),
                ..Default::default()
            })
        };
        for (connector, route_param) in [("wordpress", true), ("wordpress", false), ("openapi", true)] {
            let refusal = build_request_for(connector, &orders(route_param), &serde_json::json!({ "id": "42/refunds" }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{connector} route_param={route_param}");
        }
        let plugins = patterned("https://site.example", "/wp/v2/plugins/{plugin}", "plugin", WP_PLUGIN, false, true);
        let req = build_request_for("wordpress", &plugins, &serde_json::json!({ "plugin": "akismet/akismet" }), b"t").unwrap();
        assert_eq!(req.url, "https://site.example/?rest_route=/wp/v2/plugins/akismet/akismet");
    }

    #[test]
    fn brackets_expand_structured_input_the_way_php_reads_it() {
        let c = imported(HttpSpec {
            method: HttpMethod::Get,
            base_url: "https://example.com/wp-json".into(),
            path: "/wp-abilities/v1/abilities/site/get-post/run".into(),
            query_params: vec!["input".into()],
            query_style: QueryStyle::Brackets,
            ..Default::default()
        });
        let input = serde_json::json!({ "input": { "id": 5, "tags": ["a b", "c"], "draft": false, "skip": null } });
        let req = build_request(&c, &input, b"t").unwrap();
        let query = req.url.split_once('?').unwrap().1;
        let mut parts: Vec<&str> = query.split('&').collect();
        parts.sort();
        assert_eq!(parts, vec!["input[draft]=false", "input[id]=5", "input[tags][0]=a%20b", "input[tags][1]=c"]);
    }

    #[test]
    fn flat_style_is_unchanged_for_a_structured_value() {
        let c = imported(HttpSpec {
            base_url: "https://api.example.com".into(),
            path: "/items".into(),
            query_params: vec!["filter".into()],
            ..Default::default()
        });
        let req = build_request(&c, &serde_json::json!({ "filter": { "a": 1 } }), b"t").unwrap();
        assert_eq!(req.url, "https://api.example.com/items?filter=");
    }

    #[test]
    fn header_params_never_shadow_the_credential_or_a_pinned_header() {
        let c = imported(HttpSpec {
            base_url: "https://api.example.com".into(),
            path: "/items".into(),
            header_params: vec!["authorization".into(), "x-api-version".into(), "X-Trace".into(), "X-Api-Key".into(), "X-Note".into()],
            static_headers: BTreeMap::from([("X-Api-Version".to_string(), "2024-01".to_string())]),
            ..Default::default()
        });
        let params = serde_json::json!({
            "authorization": "Bearer stolen",
            "x-api-version": "1999",
            "X-Trace": "abc",
            "X-Api-Key": "k",
            "X-Note": "line\r\nInjected: yes",
        });
        let req = build_request(&c, &params, b"real").unwrap();
        assert_eq!(req.headers.get("Authorization").unwrap(), "Bearer real");
        assert!(!req.headers.contains_key("authorization"));
        assert_eq!(req.headers.get("X-Api-Version").unwrap(), "2024-01");
        assert!(!req.headers.contains_key("x-api-version"));
        assert!(!req.headers.contains_key("X-Api-Key"), "a credential-shaped name is refused");
        assert!(!req.headers.contains_key("X-Note"), "a CR/LF value is refused");
        assert_eq!(req.headers.get("X-Trace").unwrap(), "abc");
    }

    #[test]
    fn imported_header_params_are_capped_and_deduplicated_without_rescanning() {
        let spec = |n: usize| HttpSpec {
            base_url: "https://api.example.com".into(),
            path: "/items".into(),
            header_params: (0..n).map(|i| format!("x-h{i:06}")).collect(),
            ..Default::default()
        };
        let values = |n: usize| {
            let given: serde_json::Map<String, serde_json::Value> =
                (0..n).map(|i| (format!("x-h{i:06}"), serde_json::Value::from("v"))).collect();
            serde_json::Value::Object(given)
        };
        let at_cap = build_request(&imported(spec(MAX_AGENT_HEADERS)), &values(MAX_AGENT_HEADERS), b"tok").unwrap();
        assert_eq!(at_cap.headers.len(), MAX_AGENT_HEADERS + 1, "every header kept, plus the credential");
        let past = request_refusal("openapi", &imported(spec(MAX_AGENT_HEADERS + 1)), &values(MAX_AGENT_HEADERS + 1)).expect("one past the cap");
        assert_eq!(past.code, "agent_header", "{}", past.reason);
        let declared_not_given = build_request(&imported(spec(MAX_AGENT_HEADERS * 4)), &values(3), b"tok").unwrap();
        assert_eq!(declared_not_given.headers.len(), 4, "only the headers given count");

        let (flood_spec, flood) = (imported(spec(150_000)), values(150_000));
        let started = std::time::Instant::now();
        let refusal = request_refusal("openapi", &flood_spec, &flood).expect("150,000 headers are refused");
        let took = started.elapsed();
        assert_eq!(refusal.code, "agent_header", "{}", refusal.reason);
        assert!(took < std::time::Duration::from_secs(1), "refused in {took:?}");
    }

    #[test]
    fn a_spec_without_the_new_fields_round_trips_byte_for_byte() {
        let old = r#"{"method":"GET","base_url":"https://a.example","path":"/x","path_params":[],"query_params":[],"body_params":[],"auth":{"scheme":"bearer"},"static_headers":{}}"#;
        let spec: HttpSpec = serde_json::from_str(old).unwrap();
        assert_eq!(spec.route_param, None);
        assert_eq!(spec.query_style, QueryStyle::Flat);
        assert!(spec.header_params.is_empty());
        assert_eq!(spec.body_style, BodyStyle::Json);
        assert_eq!(serde_json::to_string(&spec).unwrap(), old);
    }

    #[test]
    fn a_stored_write_spec_without_a_body_style_still_sends_json() {
        let old = r#"{"method":"POST","base_url":"https://api.example.com","path":"/refunds","path_params":[],"query_params":[],"body_params":["charge","metadata"],"auth":{"scheme":"bearer"},"static_headers":{}}"#;
        let spec: HttpSpec = serde_json::from_str(old).unwrap();
        assert_eq!(serde_json::to_string(&spec).unwrap(), old);
        let req = build_request(
            &imported(spec),
            &serde_json::json!({ "charge": "ch_1", "metadata": { "order": "1042" } }),
            b"t",
        ).unwrap();
        assert_eq!(req.json(), Some(serde_json::json!({ "charge": "ch_1", "metadata": { "order": "1042" } })));
        assert_eq!(req.form_encoded, None);
        assert_eq!(req.headers.get("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn a_form_body_keeps_declared_order_brackets_nesting_and_drops_nulls() {
        let c = imported(HttpSpec {
            method: HttpMethod::Post,
            base_url: "https://api.stripe.com/v1".into(),
            path: "/checkout/sessions".into(),
            body_params: vec!["mode".into(), "line_items".into(), "expand".into(), "customer".into(), "metadata".into()],
            body_style: BodyStyle::Form,
            ..Default::default()
        });
        let items: Vec<serde_json::Value> =
            (0..11).map(|i| serde_json::json!({ "price": format!("price_{i}"), "quantity": 1 })).collect();
        let params = serde_json::json!({
            "metadata": { "a key": "x=y&z", "gone": null },
            "customer": null,
            "expand": ["customer"],
            "line_items": items,
            "mode": "payment",
        });
        let req = build_request(&c, &params, b"t").unwrap();
        assert!(req.json().is_none());
        assert_eq!(req.headers.get("Content-Type").unwrap(), "application/x-www-form-urlencoded");
        let form = req.form_encoded.clone().expect("a form body");
        let fields: Vec<&str> = form.split('&').collect();
        assert_eq!(fields[0], "mode=payment");
        assert_eq!(&fields[1..3], ["line_items[0][price]=price_0", "line_items[0][quantity]=1"]);
        assert_eq!(fields[21], "line_items[10][price]=price_10", "array items stay in order past ten");
        assert_eq!(&fields[23..], ["expand[0]=customer", "metadata[a%20key]=x%3Dy%26z"]);
        assert!(!form.contains("customer=") && !form.contains("gone"), "nulls are left out: {form}");
    }

    /// What an imported capability writes from params outside a JSON body is held to a bound as it is written. Bracket syntax writes every key above a value beside each value, so a 64 KiB key over 100,000 zeros, about 300 KiB of params, would be 6.4 GB of form text or query.
    #[test]
    fn a_form_or_query_written_from_params_is_bounded_as_it_is_written() {
        let key = "k".repeat(64 * 1024);
        let params = serde_json::json!({ "metadata": { key.clone(): vec![0; 100_000] } });
        for (body_style, query_style, query_params, body_params) in [
            (BodyStyle::Form, QueryStyle::Flat, vec![], vec!["metadata".to_string()]),
            (BodyStyle::Json, QueryStyle::Brackets, vec!["metadata".to_string()], vec![]),
        ] {
            let c = imported(HttpSpec {
                method: HttpMethod::Post,
                base_url: "https://api.stripe.com/v1".into(),
                path: "/checkout/sessions".into(),
                query_params,
                query_style,
                body_params,
                body_style,
                ..Default::default()
            });
            let started = std::time::Instant::now();
            let refusal = build_request(&c, &params, b"t").unwrap_err();
            assert_eq!(refusal.code, "encoded_too_large", "{body_style:?}");
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "stopped at the bound, not after writing it all");
            // The same shape within the bound is written whole.
            let small = serde_json::json!({ "metadata": { key.clone(): vec![0; 20] } });
            let req = build_request(&c, &small, b"t").unwrap();
            let written = req.form_encoded.clone().unwrap_or_else(|| req.url.clone());
            assert_eq!(written.matches(&key).count(), 20, "{body_style:?}");
        }
    }

    /// A form body writes a value whole however long its encoding, as a JSON body would, and only the keys beside each value count against the bound: 1.8 MiB of HTML and 1.9 MiB of CJK text encode to 2.9 and 5.7 MiB. A value the form writes a second time, and a value in the URL, which the client copies again to send it, still count in full.
    #[test]
    fn a_form_body_writes_a_long_value_whole_and_bounds_only_what_repeats() {
        const MIB: usize = 1024 * 1024;
        let line = "<li class=\"item\"><a href=\"/items/42?ref=list&amp;page=2\">Widget 42</a> renders off by one pixel</li>\n";
        let html = line.repeat((18 * MIB / 10).div_ceil(line.len()));
        let sentence = "日本語のテキストを送信します。";
        let cjk = sentence.repeat((19 * MIB / 10).div_ceil(sentence.len()));
        let form = |body_params: Vec<String>, query_params: Vec<String>| {
            imported(HttpSpec {
                method: HttpMethod::Post,
                base_url: "https://api.example.com/v1".into(),
                path: "/notes".into(),
                query_params,
                body_params,
                body_style: BodyStyle::Form,
                ..Default::default()
            })
        };
        let c = form(vec!["content".to_string()], vec![]);
        for text in [&html, &cjk] {
            let req = build_request(&c, &serde_json::json!({ "content": text }), b"t").unwrap_or_else(|r| panic!("{} bytes: {}", text.len(), r.reason));
            let body = req.form_encoded.clone().expect("a form body");
            assert!(body.len() > MAX_ENCODED_PARAMS_BYTES, "{} bytes encode to {}", text.len(), body.len());
            assert_eq!(body, format!("content={}", percent_encode(text)));
        }
        let twice = form(vec!["content".to_string(), "content".to_string()], vec![]);
        assert_eq!(build_request(&twice, &serde_json::json!({ "content": cjk }), b"t").unwrap_err().code, "encoded_too_large");
        let in_url = form(vec![], vec!["content".to_string()]);
        assert_eq!(build_request(&in_url, &serde_json::json!({ "content": cjk }), b"t").unwrap_err().code, "encoded_too_large");
    }

    /// The generic proxy holds the URL and headers it takes from params to the same bound, the URL before it is parsed, since parsing percent-encodes it.
    #[test]
    fn the_generic_proxy_holds_its_url_and_headers_to_the_bound() {
        let c = cap("http.request", "generic_http", Action::Execute);
        let long_url = format!("https://api.example.com/{}", "a".repeat(MAX_ENCODED_PARAMS_BYTES / 3));
        let refusal = build_request_for("generic-http", &c, &serde_json::json!({ "url": long_url }), b"t").unwrap_err();
        assert_eq!(refusal.code, "encoded_too_large");
        let header = serde_json::json!({ "url": "https://api.example.com/x", "headers": { "X-Large": "v".repeat(MAX_ENCODED_PARAMS_BYTES) } });
        assert_eq!(build_request_for("generic-http", &c, &header, b"t").unwrap_err().code, "encoded_too_large");
        let fine = serde_json::json!({ "url": "https://api.example.com/x?q=1", "headers": { "X-Request-Id": "r-1" }, "body": { "a": 1 } });
        let req = build_request_for("generic-http", &c, &fine, b"t").unwrap();
        assert_eq!(req.headers.get("X-Request-Id").map(String::as_str), Some("r-1"));
        assert_eq!(req.json(), Some(serde_json::json!({ "a": 1 })));
    }

    /// A JSON body is written from the params the builder borrows, at exactly its length, and reads back as the params it came from.
    #[test]
    fn a_json_body_is_written_from_the_params_it_borrows() {
        let params = serde_json::json!({ "repo": "o/r", "title": "t", "rows": [{ "x": 1, "y": 2 }, { "x": 1e15, "y": "\u{1}" }] });
        let text = json_text(&params);
        assert_eq!(text, serde_json::to_string(&params).unwrap());
        assert_eq!(text.capacity(), text.len(), "written once, at its length");
        let req = build_request(&cap("github.issues.create", "github", Action::Create), &params, b"t").unwrap();
        assert_eq!(req.body, None, "no second tree of the params");
        assert_eq!(req.json_encoded.as_deref(), Some(text.as_str()));
    }

    #[test]
    fn a_form_style_write_with_nothing_to_send_has_no_body_and_no_content_type() {
        let c = imported(HttpSpec {
            method: HttpMethod::Post,
            base_url: "https://api.stripe.com/v1".into(),
            path: "/payment_intents/{id}/capture".into(),
            path_params: vec!["id".into()],
            body_params: vec!["amount_to_capture".into()],
            body_style: BodyStyle::Form,
            ..Default::default()
        });
        let req = build_request(&c, &serde_json::json!({ "id": "pi_1", "amount_to_capture": null }), b"t").unwrap();
        assert_eq!(req.form_encoded, None);
        assert_eq!(req.json(), None);
        assert!(!req.headers.contains_key("Content-Type"));
    }

    #[test]
    fn a_path_parameter_cannot_be_a_dot_segment_or_empty() {
        let c = imported(HttpSpec {
            base_url: "https://api.vercel.com".into(),
            path: "/v9/projects/{id}/env".into(),
            path_params: vec!["id".into()],
            ..Default::default()
        });
        for id in [serde_json::json!(".."), serde_json::json!("."), serde_json::json!(""), serde_json::json!(null), serde_json::json!({})] {
            let refusal = build_request(&c, &serde_json::json!({ "id": id }), b"t").unwrap_err();
            assert_eq!(refusal.code, "path_identifier", "{id}");
        }
        assert!(build_request(&c, &serde_json::json!({}), b"t").is_err());
        // Anything else stays inside its segment, URL syntax included.
        let req = build_request(&c, &serde_json::json!({ "id": "a..b?decrypt=true#" }), b"t").unwrap();
        assert_eq!(req.url, "https://api.vercel.com/v9/projects/a..b%3Fdecrypt%3Dtrue%23/env");
        let req = build_request(&c, &serde_json::json!({ "id": "..." }), b"t").unwrap();
        assert_eq!(req.url, "https://api.vercel.com/v9/projects/.../env");
    }

    fn graphql_cap(base_url: &str, path: &str, action: Action, rule: Option<GraphqlSpec>) -> Capability {
        Capability {
            http: Some(HttpSpec {
                method: HttpMethod::Post,
                base_url: base_url.into(),
                path: path.into(),
                body_params: vec!["query".into(), "variables".into()],
                graphql: rule,
                ..Default::default()
            }),
            ..cap("lin.issues.list", "lin", action)
        }
    }

    fn rest_cap(base_url: &str, path: &str, action: Action, body_params: &[&str]) -> Capability {
        Capability {
            http: Some(HttpSpec {
                method: HttpMethod::Post,
                base_url: base_url.into(),
                path: path.into(),
                body_params: body_params.iter().map(|p| p.to_string()).collect(),
                ..Default::default()
            }),
            ..cap("acme.items.list", "acme", action)
        }
    }

    const MUTATION: &str = "mutation { issueArchive(id: \"x\") { success } }";

    #[test]
    fn a_rule_less_spec_is_checked_by_its_shape_not_its_url() {
        let spec = |c: &Capability| graphql_check(c.http.as_ref().unwrap());
        let linear = graphql_cap("https://api.linear.app/graphql", "/", Action::List, None);
        assert_eq!(spec(&linear), Some(GraphqlCheck::Shaped));
        let shop = rest_cap("https://shop.myshopify.com/admin/api/2024-01", "/graphql.json", Action::Read, &["query"]);
        assert_eq!(spec(&shop), Some(GraphqlCheck::Shaped));
        let monday = rest_cap("https://api.monday.com", "/v2", Action::List, &["query", "variables"]);
        assert_eq!(spec(&monday), Some(GraphqlCheck::Shaped));
        let named = rest_cap("https://hasura.example.com", "/v1/run", Action::Read, &["query", "operationName"]);
        assert_eq!(spec(&named), Some(GraphqlCheck::Shaped));
        let search = rest_cap("https://api.hubapi.com", "/crm/v3/objects/contacts/search", Action::Search, &["filterGroups", "query", "limit"]);
        assert_eq!(spec(&search), Some(GraphqlCheck::Content));
        assert_eq!(spec(&rest_cap("https://api.example.com", "/v2", Action::List, &["name"])), None);
        let declared = graphql_cap("https://api.example.com", "/v2", Action::List, Some(GraphqlSpec::default()));
        assert_eq!(spec(&declared), Some(GraphqlCheck::Declared(GraphqlSpec::default())));
    }

    #[test]
    fn a_shaped_read_sends_one_parseable_query_and_a_shaped_write_is_not_narrowed() {
        let read = rest_cap("https://api.monday.com", "/v2", Action::List, &["query", "variables"]);
        let ok = |c: &Capability, v: serde_json::Value| build_request(c, &v, b"t");
        assert!(ok(&read, serde_json::json!({ "query": "query ($n: Int) { boards(limit: $n) { id } }", "variables": { "n": 1 } })).is_ok());
        assert!(ok(&read, serde_json::json!({ "query": "{ boards { id } }" })).is_ok());
        for refused in [
            serde_json::json!({ "query": MUTATION }),
            serde_json::json!({ "query": "subscription { a }" }),
            serde_json::json!({ "query": "{ a } { b }" }),
            serde_json::json!({ "query": "not a document" }),
            serde_json::json!({ "query": ["{ a }"] }),
            serde_json::json!({ "variables": {} }),
        ] {
            assert_eq!(ok(&read, refused.clone()).unwrap_err().code, "graphql_operation", "{refused}");
        }
        let write = rest_cap("https://api.monday.com", "/v2", Action::Create, &["query", "variables"]);
        for passed in [MUTATION, "{ a }", "subscription { a }", "not a document"] {
            assert!(ok(&write, serde_json::json!({ "query": passed })).is_ok(), "{passed}");
        }
        assert!(ok(&write, serde_json::json!({})).is_ok());
    }

    #[test]
    fn a_lone_query_field_is_held_only_when_it_is_graphql() {
        let search = rest_cap("https://api.hubapi.com", "/crm/v3/objects/contacts/search", Action::Search, &["filterGroups", "query", "limit"]);
        for term in ["jane", "jane doe", "mutation testing", "query", "{", "", "\"quoted\""] {
            let req = build_request(&search, &serde_json::json!({ "query": term, "limit": 5 }), b"t").unwrap();
            assert_eq!(req.json().unwrap()["query"], term, "a search term is forwarded untouched");
        }
        assert!(build_request(&search, &serde_json::json!({ "query": 42 }), b"t").is_ok());
        assert!(build_request(&search, &serde_json::json!({ "query": "{ contacts { id } }" }), b"t").is_ok());
        let refusal = build_request(&search, &serde_json::json!({ "query": MUTATION }), b"t").unwrap_err();
        assert!(refusal.reason.contains("may only send a GraphQL query"), "{}", refusal.reason);
        // A write capability's lone `query` is left to its action.
        let write = rest_cap("https://api.example.com", "/v2", Action::Create, &["query"]);
        assert!(build_request(&write, &serde_json::json!({ "query": MUTATION }), b"t").is_ok());
    }

    #[test]
    fn a_body_a_builtin_forwards_whole_is_checked_by_its_own_fields() {
        let search = cap("braintree.transactions.search", "braintree", Action::Search);
        assert!(build_request(&search, &serde_json::json!({ "query": "settled" }), b"t").is_ok());
        assert!(build_request(&search, &serde_json::json!({ "query": MUTATION }), b"t").is_err());
        let shaped = serde_json::json!({ "query": "not a document", "variables": {} });
        assert!(build_request(&search, &shaped, b"t").is_err());
        let mut proxy = cap("acme.widgets.read", "acme", Action::Read);
        proxy.id = "acme.widgets.read".into();
        let body = serde_json::json!({ "url": "https://api.acme.test/v2", "method": "POST", "body": { "query": MUTATION } });
        assert!(build_request_for("acme", &proxy, &body, b"t").is_err());
        let exec = cap("http.request", "generic_http", Action::Execute);
        assert!(build_request_for("generic-http", &exec, &body, b"t").is_ok(), "an execute capability is not a read");
    }

    /// Some GraphQL servers run a stored operation named by `extensions.persistedQuery`, `documentId`, `doc_id`, `queryId` or `id` in place of the `query` text, and the gateway can only judge the text it is sent, so a capability whose operation is held to a query or a rule may not name one.
    #[test]
    fn a_held_capability_may_not_name_a_stored_graphql_operation() {
        let apq = serde_json::json!({ "persistedQuery": { "version": 1, "sha256Hash": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38" } });
        let read = rest_cap("https://api.monday.com", "/v2", Action::List, &["query", "variables", "extensions", "documentId", "doc_id", "queryId", "id", "operationId"]);
        let ok = |c: &Capability, v: serde_json::Value| build_request(c, &v, b"t");
        assert!(ok(&read, serde_json::json!({ "query": "{ boards { id } }", "extensions": {} })).is_ok());
        for refused in [
            serde_json::json!({ "query": "{ boards { id } }", "extensions": apq }),
            serde_json::json!({ "query": "{ boards { id } }", "documentId": "stored-mutation" }),
            serde_json::json!({ "query": "{ boards { id } }", "doc_id": "1234" }),
            serde_json::json!({ "query": "{ boards { id } }", "queryId": "q1" }),
            serde_json::json!({ "query": "{ boards { id } }", "id": "stored" }),
            serde_json::json!({ "query": "{ boards { id } }", "operationId": "app/stored-mutation" }),
            serde_json::json!({ "query": "{ boards { id } }", "extensions": apq.to_string() }),
            serde_json::json!({ "query": "{ boards { id } }", "extensions": "not json" }),
        ] {
            assert_eq!(ok(&read, refused.clone()).unwrap_err().code, "graphql_operation", "{refused}");
        }

        // A spec that forwards only a stored operation's name is GraphQL to the check too, and a read sends no document to judge.
        let persisted_only = rest_cap("https://api.example.com", "/graphql", Action::Read, &["documentId", "variables"]);
        assert_eq!(graphql_check(persisted_only.http.as_ref().unwrap()), Some(GraphqlCheck::Shaped));
        assert_eq!(ok(&persisted_only, serde_json::json!({ "documentId": "x", "variables": {} })).unwrap_err().code, "graphql_operation");

        // A declared rule pins the operation and its root fields, which a stored operation would bypass on a write as well.
        let rule = GraphqlSpec { operation: GraphqlOperation::Mutation, root_fields: vec!["issueCreate".into()] };
        let mut write = graphql_cap("https://api.linear.app/graphql", "/", Action::Create, Some(rule));
        write.http.as_mut().unwrap().body_params.push("extensions".into());
        let create = "mutation { issueCreate(input: {}) { success } }";
        assert!(ok(&write, serde_json::json!({ "query": create })).is_ok());
        assert_eq!(ok(&write, serde_json::json!({ "query": create, "extensions": apq })).unwrap_err().code, "graphql_operation");

        // A lone `query` that is a search term leaves a REST body's other fields alone; one that is GraphQL does not.
        let search = rest_cap("https://api.hubapi.com", "/crm/v3/objects/contacts/search", Action::Search, &["query", "queryId", "id"]);
        assert!(ok(&search, serde_json::json!({ "query": "jane", "queryId": "saved-1", "id": "c1" })).is_ok());
        assert!(ok(&search, serde_json::json!({ "query": "{ contacts { id } }", "id": "c1" })).is_ok(), "an id beside a search is not a stored operation");
        assert!(ok(&read, serde_json::json!({ "query": "{ boards { id } }", "extensions": "{}" })).is_ok(), "an extensions string with nothing stored in it is fine");
        assert!(ok(&search, serde_json::json!({ "query": "{ contacts { id } }", "documentId": "x" })).is_err());

        // A body a built-in forwards whole, and the generic proxy's, are held the same way.
        let bt = cap("braintree.transactions.search", "braintree", Action::Search);
        assert!(build_request(&bt, &serde_json::json!({ "id": { "is": "abc" } }), b"t").is_ok(), "a search filter named id is not GraphQL");
        assert!(build_request(&bt, &serde_json::json!({ "query": "{ a }", "extensions": apq }), b"t").is_err());
        assert!(build_request(&bt, &serde_json::json!({ "documentId": "x" }), b"t").is_err());
        let mut proxy = cap("acme.widgets.read", "acme", Action::Read);
        proxy.id = "acme.widgets.read".into();
        let body = serde_json::json!({ "url": "https://api.acme.test/graphql", "method": "GET", "body": { "doc_id": "123", "variables": {} } });
        assert!(build_request_for("acme", &proxy, &body, b"t").is_err());
    }

    #[test]
    fn a_read_action_sends_only_a_query_whatever_its_rule_says() {
        let rule = GraphqlSpec { operation: GraphqlOperation::Mutation, root_fields: vec![] };
        let c = graphql_cap("https://api.linear.app/graphql", "/", Action::Read, Some(rule));
        let refusal = build_request(&c, &serde_json::json!({ "query": "mutation { a }" }), b"t").unwrap_err();
        assert!(refusal.reason.contains("may only send a GraphQL query"), "{}", refusal.reason);
        assert!(build_request(&c, &serde_json::json!({ "query": "{ a }" }), b"t").is_ok());
    }

    #[test]
    fn a_declared_write_rule_pins_the_operation_and_its_root_fields() {
        let rule = GraphqlSpec { operation: GraphqlOperation::Mutation, root_fields: vec!["issueCreate".into()] };
        let c = graphql_cap("https://api.linear.app/graphql", "/", Action::Create, Some(rule));
        let ok = |q: &str| build_request(&c, &serde_json::json!({ "query": q }), b"t");
        assert!(ok("mutation { issueCreate(input: {}) { success } __typename }").is_ok());
        assert!(ok("mutation { a: issueCreate(input: {}) { success } b: issueCreate(input: {}) { success } }").is_ok());
        assert!(ok("{ viewer { id } }").is_err(), "a declared mutation rule is not a read");
        assert!(ok("mutation { issueDelete(id: \"x\") { success } }").is_err());
        assert!(ok("mutation { issueCreate: issueDelete(id: \"x\") { success } }").is_err(), "an alias is not the field");
        assert!(ok("mutation { ... on Mutation { issueDelete(id: \"x\") { success } } }").is_err());
        let long = format!("mutation {{ {} }}", "x".repeat(5000));
        assert!(ok(&long).unwrap_err().reason.len() < 300, "an agent's text is cut in a refusal");
    }

    #[test]
    fn a_builtin_capability_the_family_does_not_define_is_refused() {
        for (family, id) in [("github", "github.repos.delete"), ("braintree", "braintree.customers.delete"), ("vercel", "vercel.projects.delete")] {
            let refusal = build_request_for(family, &cap(id, family, Action::Delete), &serde_json::json!({}), b"t").unwrap_err();
            assert_eq!(refusal.code, "unknown_action", "{id}");
        }
    }

    #[test]
    fn request_refusal_answers_for_http_capabilities_only() {
        let c = cap("vercel.env.read", "vercel", Action::Read);
        let bad = serde_json::json!({ "project_id": "x/env?decrypt=true" });
        assert_eq!(request_refusal("vercel", &c, &bad).unwrap().code, "path_identifier");
        assert!(request_refusal("vercel", &c, &serde_json::json!({ "project_id": "x" })).is_none());
        let mut command = c.clone();
        command.kind = CapabilityKind::Command;
        assert!(request_refusal("vercel", &command, &bad).is_none());
    }

    #[test]
    fn a_vercel_env_listing_keeps_metadata_in_every_shape_it_arrives_in() {
        let env = cap("vercel.env.read", "vercel", Action::Read);
        let record = serde_json::json!({ "id": "e", "key": "K", "type": "plain", "target": ["production"], "value": "v",
            "vsmValue": "w", "decrypted": true, "contentHint": { "type": "x" }, "comment": "c", "createdAt": 1 });
        let kept = serde_json::json!({ "id": "e", "key": "K", "type": "plain", "target": ["production"], "createdAt": 1 });
        assert_eq!(project_response("vercel", &env, serde_json::json!([record.clone()])), serde_json::json!([kept.clone()]));
        assert_eq!(project_response("vercel", &env, record.clone()), kept.clone());
        assert_eq!(
            project_response("vercel", &env, serde_json::json!({ "envs": [record.clone(), "junk"], "pagination": { "count": 1, "next": "x" }, "other": 1 })),
            serde_json::json!({ "envs": [kept.clone()], "pagination": { "count": 1 } })
        );
        assert_eq!(project_response("vercel", &env, serde_json::json!("text")), serde_json::Value::Null);

        let projects = cap("vercel.projects.list", "vercel", Action::List);
        let body = serde_json::json!({ "projects": [{ "name": "p", "env": [record.clone()] }] });
        assert_eq!(
            project_response("vercel", &projects, body),
            serde_json::json!({ "projects": [{ "name": "p", "env": [kept.clone()] }] })
        );
        // A single variable read, or one nested anywhere else, is recognized by its shape.
        let single = cap("vercel.env.get", "vercel", Action::Read);
        let spec_single = Capability {
            http: Some(HttpSpec {
                base_url: "https://api.vercel.com/v1".into(),
                path: "/projects/{id}/env/{env}".into(),
                ..Default::default()
            }),
            ..single
        };
        assert_eq!(project_response("vercel", &spec_single, record.clone()), kept.clone());
        assert_eq!(
            project_response("vercel", &spec_single, serde_json::json!({ "created": record.clone(), "failed": [] })),
            serde_json::json!({ "created": kept.clone(), "failed": [] })
        );
        // An edge config item is a key and a value, not an env variable.
        let item = serde_json::json!({ "key": "flag", "value": true });
        assert_eq!(project_response("vercel", &spec_single, item.clone()), item);
        // A pinned base URL can carry the version; the listing is still recognized.
        let listing = Capability {
            http: Some(HttpSpec { base_url: "https://api.vercel.com/v9".into(), path: "/projects/{id}/env".into(), ..Default::default() }),
            ..cap("vercel.env.read", "vercel", Action::Read)
        };
        assert_eq!(project_response("vercel", &listing, serde_json::json!([record.clone()])), serde_json::json!([kept.clone()]));
        // Another family's `value` is not Vercel's to touch.
        let gh = cap("github.repos.read", "github", Action::Read);
        let body = serde_json::json!({ "env": [record.clone()], "value": "v" });
        assert_eq!(project_response("github", &gh, body.clone()), body);
    }

    #[tokio::test]
    async fn execute_refuses_input_the_capability_does_not_name() {
        let mut reg = ConnectorRegistry::new();
        reg.register_connector(&VercelConnector::new("vercel_acme", "sec_vercel"));
        let http = MockHttpClient::new();
        let err = reg
            .execute(&http, "vercel.env.read", &serde_json::json!({ "project_id": "p/env?decrypt=true#" }), b"t")
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::BadInput(_)), "{err:?}");
        assert!(http.requests().is_empty());
        http.push_response(HttpResponse::json(200, serde_json::json!({ "envs": [{ "key": "K", "value": "v" }] })));
        let out = reg.execute(&http, "vercel.env.read", &serde_json::json!({ "project_id": "p" }), b"t").await.unwrap();
        assert_eq!(out, serde_json::json!({ "envs": [{ "key": "K" }] }));
    }

    #[test]
    fn the_field_a_credential_is_injected_under_names_it_in_both_spellings() {
        let names = |auth: AuthScheme| auth.credential_field_names();
        assert_eq!(names(AuthScheme::ApiKeyHeader { header: "XI-API-Key".into() }), vec!["xi-api-key", "xi_api_key"]);
        assert_eq!(names(AuthScheme::ApiKeyQuery { param: "api_key".into() }), vec!["api_key", "api-key"]);
        assert_eq!(names(AuthScheme::ApiKeyQuery { param: "appid".into() }), vec!["appid"]);
        assert_eq!(names(AuthScheme::Raw { header: "X-Auth_Token".into(), prefix: "Token ".into() }).len(), 3);
        assert!(names(AuthScheme::Bearer).is_empty() && names(AuthScheme::Basic { key_as_username: true }).is_empty());

        let mut imported = cap("voices.getUser", "voices", Action::Read);
        imported.http = Some(HttpSpec { auth: AuthScheme::ApiKeyHeader { header: "xi-api-key".into() }, ..HttpSpec::default() });
        assert_eq!(imported.credential_field_names(), vec!["xi-api-key", "xi_api_key"]);
        let mut command = cap("vercel-cli.whoami", "vercel", Action::Read);
        command.command = Some(CommandSpec {
            program: "vercel".into(),
            args_template: vec!["whoami".into()],
            secret_env: "VERCEL_TOKEN".into(),
            allowed_placeholders: vec![],
        });
        assert_eq!(command.credential_field_names(), vec!["vercel_token", "vercel-token"]);
        assert!(cap("github.repos.read", "github", Action::Read).credential_field_names().is_empty());
    }

    /// On the generic proxy, a document sent as a GET's `query` parameter, and every operation in a batched array body, has its aliases mapped to the fields they rename, exactly as a single forwarded body's are.
    #[test]
    fn the_generic_proxy_maps_aliases_in_a_get_query_and_a_batched_body() {
        let c = cap("probe.request", "probe", Action::Read);
        let keys = vec!["secret".to_string(), "creator.email".to_string()];
        let pool = json_budget::MemoryPool::new(1 << 30);
        let mapped = |params: serde_json::Value| match response_redact_keys("generic-http", &c, &params, &keys, &pool) {
            ResponseRedaction::Keys { keys, .. } => keys,
            ResponseRedaction::Whole => panic!("redacted whole: {params}"),
        };
        let get = mapped(serde_json::json!({
            "url": "https://api.probe.test/graphql?query=query%20%7B%20w%3A%20webhooks%20%7B%20nodes%20%7B%20s%3A%20secret%20%7D%20%7D%20%7D"
        }));
        assert!(get.contains(&"s".to_string()), "{get:?}");
        let shaped = mapped(serde_json::json!({
            "url": "https://api.probe.test/graphql?operationName=Q&query=query%20Q%20%7B%20i%3A%20issues%20%7B%20c%3A%20creator%20%7B%20e%3A%20email%20%7D%20%7D%20%7D"
        }));
        assert!(shaped.contains(&"c".to_string()) && shaped.contains(&"e".to_string()), "{shaped:?}");
        let twice = mapped(serde_json::json!({ "url": "https://api.probe.test/graphql?query=%7B%20id%20%7D&query=%7B%20x%3A%20secret%20%7D" }));
        assert!(twice.contains(&"x".to_string()), "every query parameter: {twice:?}");

        let batch = mapped(serde_json::json!({
            "method": "POST",
            "url": "https://api.probe.test/graphql",
            "body": [
                { "query": "query { viewer { id } }" },
                { "query": "query { w: webhooks { nodes { s: secret } } }", "variables": {} },
                { "query": "{ i: issues { nodes { c: creator { e: email } } } }" },
                "not an operation"
            ]
        }));
        for alias in ["s", "c", "e"] {
            assert!(batch.contains(&alias.to_string()), "{alias}: {batch:?}");
        }

        let plain = mapped(serde_json::json!({ "url": "https://api.probe.test/search?query=w%3A%20secret%20things" }));
        assert_eq!(plain, keys, "a search term that does not read as GraphQL is left alone: {plain:?}");
        assert_eq!(mapped(serde_json::json!({ "url": "https://api.probe.test/graphql?query=%7B%20id%20%7D" })), keys);
    }
}
