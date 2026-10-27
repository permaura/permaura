//! Data-driven preset connectors: the marketplace catalog.
//!
//! A preset is *pre-verified import arguments*: a declarative manifest (one entry in
//! `presets/presets.yaml`) that the loader turns into exactly the [`Capability`] + [`HttpSpec`]
//! shape the OpenAPI importer ([`crate::openapi`]) already produces, so "Add from marketplace" and
//! "Import an OpenAPI doc" land on the same enforcement path. No hand-written Rust per connector.
//!
//! The manifest carries only what an agent must never influence: the pinned `base_url` (the SSRF
//! guard), the auth scheme, mandatory version headers, plus the curated capability set. Risk,
//! action, and the approval/disabled posture default from the shared [`crate::openapi::classify`]
//! rules (so a `refund`/`delete`/`POST` lands High/Critical + gated automatically). A line of a
//! manifest Permaura vouches for (the bundled catalog, or one it signed) can override any of them; a
//! line of any other manifest is written by the party being governed, so its overrides apply only
//! where they raise the risk, add an approval or switch the capability off. The secret value is never
//! part of a preset; it is referenced by id and sealed separately, exactly like an imported connector.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use permaura_core::{Action, RiskTier};
use serde::{Deserialize, Serialize};

use crate::connectors::{AuthScheme, BodyStyle, Capability, CapabilityKind, GraphqlSpec, HttpMethod, HttpSpec};
use crate::openapi::{classify, shape_floor};

/// OAuth metadata for a connector that supports the OAuth paths. Its presence
/// means the connector can be connected via OAuth (PKCE / BYO app / Managed) **in addition** to an
/// API key. Whether the *Managed* (hosted) layer is offered is a separate, web-side availability flag
/// (`managed_oauth_provider`): a connector can advertise OAuth while we're still standing up its
/// hosted app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthPreset {
    /// The provider's authorization endpoint.
    pub authorize_url: String,
    /// The provider's token endpoint (code exchange + refresh).
    pub token_url: String,
    /// The default scopes to request.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// True if the provider supports PKCE public clients (enables the zero-knowledge "Permaura app" layer).
    #[serde(default)]
    pub pkce: bool,
    /// How the token endpoint takes the client id and secret: form fields (the default, what Google,
    /// GitHub, Slack and Dropbox accept) or an HTTP Basic header (Reddit refuses the form).
    #[serde(default, skip_serializing_if = "is_body_token_auth")]
    pub token_auth: crate::oauth_credential::TokenAuth,
    /// Provider-specific parameters added to every authorization URL, such as Reddit's
    /// `duration=permanent`, without which it issues no refresh token.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub authorize_params: BTreeMap<String, String>,
    /// Which grant keeps the access token alive: a refresh token (the default), or, for Meta, which
    /// issues none, exchanging the still-valid token for a new sixty-day one.
    #[serde(default, skip_serializing_if = "is_refresh_token_grant")]
    pub refresh_grant: crate::oauth_credential::RefreshGrant,
}

fn is_refresh_token_grant(g: &crate::oauth_credential::RefreshGrant) -> bool {
    *g == crate::oauth_credential::RefreshGrant::RefreshToken
}

/// A header every connection to this connector sends with a value only the operator has: an API
/// developer token, a manager account id. Asked for when the connection is made and stored as the
/// connection's own static header, in the clear, so it must never be the credential itself: the header
/// the sealed secret travels in is the auth scheme's, and the sealed secret authorizes the account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionHeader {
    /// The header name as the upstream reads it, e.g. `developer-token`.
    pub name: String,
    /// What to call it in a form.
    #[serde(default)]
    pub label: String,
    /// Where the operator finds the value and what it does.
    #[serde(default)]
    pub description: String,
    /// Whether a connection without it cannot work, so `from-preset` refuses one.
    #[serde(default)]
    pub required: bool,
}

fn is_body_token_auth(t: &crate::oauth_credential::TokenAuth) -> bool {
    *t == crate::oauth_credential::TokenAuth::Body
}

/// Marks a preset as a curated slice of a WordPress site's REST API. The manifest cannot know the
/// operator's site, so `from-preset` discovers it from a site URL and pins the namespace there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordPressPreset {
    /// The REST namespace the capability paths are relative to, e.g. `bbpress/v1`.
    pub namespace: String,
}

/// One marketplace preset: the connection-level config plus its curated capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preset {
    /// Stable preset id and connector family name, e.g. `stripe`.
    pub id: String,
    /// Display name, e.g. `Stripe`.
    pub name: String,
    /// Honest label; defaults to `name`.
    #[serde(default)]
    pub label: Option<String>,
    /// Vertical for the marketplace category filter (`payments`, `devtools`, `comms`, `crm`, `data`).
    pub vertical: String,
    /// One-line description for the marketplace card.
    #[serde(default)]
    pub description: String,
    /// The pinned upstream base URL: the SSRF guard. Never agent-supplied.
    pub base_url: String,
    /// How the sealed secret is presented upstream (defaults to Bearer).
    #[serde(default)]
    pub auth: AuthScheme,
    /// Mandatory non-auth headers the upstream requires (e.g. an API version).
    #[serde(default)]
    pub static_headers: BTreeMap<String, String>,
    /// Headers every connection sends with a value only the operator has (a developer token, an account
    /// id), asked for when the connection is made.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connection_headers: Vec<ConnectionHeader>,
    /// How every capability's body params are encoded, unless a capability line says otherwise.
    /// Defaults to JSON; `form` for an upstream that only reads form bodies (Stripe's v1 API).
    #[serde(default, skip_serializing_if = "BodyStyle::is_json")]
    pub body_style: BodyStyle,
    /// Response field names to redact (merged with the gateway's default redaction set).
    #[serde(default)]
    pub redact_fields: Vec<String>,
    /// A brand-logo reference for the marketplace tile: a Simple Icons slug (e.g. `stripe`, `github`).
    #[serde(default)]
    pub logo: Option<String>,
    /// The brand's hex colour (e.g. `#635BFF`), for the logo tint / tile accent.
    #[serde(default)]
    pub brand_color: Option<String>,
    /// OAuth metadata, when the connector can be connected via OAuth as well as an API key.
    #[serde(default)]
    pub oauth: Option<OAuthPreset>,
    /// Present when this preset is a curated slice of a WordPress REST namespace. Its `base_url` is
    /// then only a template: every connection pins the operator's own site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wordpress: Option<WordPressPreset>,
    /// The curated capability set.
    pub capabilities: Vec<PresetCap>,
    /// Whether Permaura vouches for this manifest's posture lines, so they apply as written. Never read from or written to the manifest itself: the bundled catalog and a Permaura-signed install set it, and everything else (an unsigned install, a manifest read back from the store without its provenance) is held to the floor.
    #[serde(skip)]
    pub vouched: bool,
}

/// One capability in a preset. Only the HTTP shape is required; risk/approval/disabled default from
/// [`classify`] and may be overridden per line, as far as [`Preset::vouched`] allows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetCap {
    /// The action id: the capability id minus the connector prefix, e.g. `charges.list`.
    pub id: String,
    /// Human description; defaults to `METHOD path`.
    #[serde(default)]
    pub description: String,
    /// The pinned HTTP method.
    pub method: HttpMethod,
    /// The path template, e.g. `/charges/{id}/refund`.
    pub path: String,
    /// Param names that fill `{name}` path segments.
    #[serde(default)]
    pub path_params: Vec<String>,
    /// Param names forwarded as the query string.
    #[serde(default)]
    pub query_params: Vec<String>,
    /// Param names assembled into the request body.
    #[serde(default)]
    pub body_params: Vec<String>,
    /// Override the preset's body encoding for this capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_style: Option<BodyStyle>,
    /// Override the classified action verb (e.g. a GraphQL `query` is a read even though it POSTs).
    #[serde(default)]
    pub action: Option<Action>,
    /// Override the classified risk tier.
    #[serde(default)]
    pub risk: Option<RiskTier>,
    /// Override whether this capability always escalates to human approval.
    #[serde(default)]
    pub requires_approval: Option<bool>,
    /// Override whether this capability starts switched off on the connection. Defaults to "off for
    /// High/Critical": risky verbs are imported but disabled until the operator opts them in.
    #[serde(default)]
    pub disabled: Option<bool>,
    /// For a GraphQL endpoint, the operation type and root fields this capability's document may use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphqlSpec>,
}

/// The resolved capability set for a preset instance: the [`Capability`] objects to persist plus the
/// ids that should start in the connection's `disabled_capabilities` (the risky verbs).
pub struct Instantiated {
    /// Capabilities to store, with ids namespaced by the connection id.
    pub capabilities: Vec<Capability>,
    /// Capability ids that begin switched off (the capability master switch).
    pub disabled_capabilities: Vec<String>,
}

/// The posture one capability line lands with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Posture {
    action: Action,
    risk: RiskTier,
    requires_approval: bool,
    disabled: bool,
}

fn is_read(action: Action) -> bool {
    matches!(action, Action::Read | Action::Search | Action::List)
}

/// A declared posture held to `floor`: a read action never replaces a write the floor names, the risk
/// is never below the floor's or below what the action itself carries ([`Action::baseline_risk`]), and
/// an approval the floor asks for is never dropped. A part left undeclared takes the floor's.
fn raised_to(floor: (Action, RiskTier, bool), declared: (Option<Action>, Option<RiskTier>, Option<bool>)) -> (Action, RiskTier, bool) {
    let (faction, frisk, fapproval) = floor;
    let action = match declared.0 {
        Some(said) if is_read(said) && !is_read(faction) => faction,
        Some(said) => said,
        None => faction,
    };
    let risk_floor = frisk.max(action.baseline_risk());
    let risk = declared.1.map_or(risk_floor, |said| said.max(risk_floor));
    (action, risk, fapproval || declared.2.unwrap_or(false))
}

/// The posture a capability with this pinned HTTP shape keeps when whoever declared `declared` is not
/// vouched for: [`shape_floor`] on the method and path is the floor, and the declaration may only raise
/// it. The same rule an unsigned manifest line is held to.
pub fn held_to_shape(method: HttpMethod, path: &str, action_id: &str, declared: (Action, RiskTier, bool)) -> (Action, RiskTier, bool) {
    raised_to(shape_floor(method.as_str(), path, action_id), (Some(declared.0), Some(declared.1), Some(declared.2)))
}

/// `declared` held to a vouched `floor` (a built-in connector's own definition, or a Permaura-signed
/// manifest's line for the same shape): the same raise-only rule, with the floor's risk as written.
pub fn held_to_vouched(floor: (Action, RiskTier, bool), declared: (Action, RiskTier, bool)) -> (Action, RiskTier, bool) {
    let (faction, frisk, fapproval) = floor;
    let action = if is_read(declared.0) && !is_read(faction) { faction } else { declared.0 };
    (action, declared.1.max(frisk), fapproval || declared.2)
}

impl PresetCap {
    /// The line's posture. A `vouched` manifest's line defaults from [`classify`] and its overrides apply
    /// as written. Any other manifest's floor is [`shape_floor`] on the method and path (which also reads
    /// the path's operation words and `export`), and its overrides apply only where they raise it: a read
    /// action never replaces a classified write, the risk is never below what the method and the action
    /// give, an approval is never removed, and a line the floor switches off stays off. A capability
    /// starts disabled at High or above unless its line says otherwise, and an unvouched line cannot switch on one the
    /// floor itself puts at High.
    fn posture(&self, vouched: bool) -> Posture {
        if vouched {
            let (daction, drisk, dapproval) = classify(self.method.as_str(), &self.path, &self.id);
            let risk = self.risk.unwrap_or(drisk);
            return Posture {
                action: self.action.unwrap_or(daction),
                risk,
                requires_approval: self.requires_approval.unwrap_or(dapproval),
                disabled: self.disabled.unwrap_or(risk >= RiskTier::High),
            };
        }
        let (daction, drisk, dapproval) = shape_floor(self.method.as_str(), &self.path, &self.id);
        let (action, risk, requires_approval) =
            raised_to((daction, drisk, dapproval), (self.action, self.risk, self.requires_approval));
        let floor = drisk.max(action.baseline_risk());
        Posture { action, risk, requires_approval, disabled: floor >= RiskTier::High || self.disabled.unwrap_or(risk >= RiskTier::High) }
    }

    fn shown_description(&self) -> String {
        if self.description.is_empty() {
            format!("{} {}", self.method.as_str(), self.path)
        } else {
            self.description.clone()
        }
    }
}

/// Per-connection overrides for the parts of a preset a shared catalog manifest cannot know.
///
/// Some APIs put the account in the host (Mailchimp's data centre, DocuSign's account base URI) or
/// name the tenant in a header (Xero's `Xero-tenant-id`); others simply have a sandbox on a different
/// host. A manifest pins one value for everybody, so without this those connectors are either
/// uninstallable as published or fail every call. The operator supplies the missing piece once, at
/// connection time, exactly as they supply the credential.
///
/// This does not weaken the SSRF guard. `base_url` was never agent-supplied and still isn't: it moves
/// from "pinned by the manifest author" to "pinned by the operator", the same trust level as
/// `import-openapi`, and it is fixed into every capability's [`HttpSpec`] at creation. Validation of
/// both fields lives at the REST edge (`rest::validate_preset_overrides`), so anything reaching here
/// has already been checked.
#[derive(Debug, Clone, Default)]
pub struct PresetOverrides {
    /// Replaces the manifest's pinned `base_url` for every capability. `None` keeps the manifest's.
    pub base_url: Option<String>,
    /// Merged over the manifest's `static_headers`, matching existing names case-insensitively so a
    /// caller cannot end up sending both `Accept` and `accept`.
    pub static_headers: BTreeMap<String, String>,
    /// Sends every path as this query parameter instead of appending it: a WordPress site without
    /// pretty permalinks (`rest_route`). Set by discovery, never by the caller.
    pub route_param: Option<String>,
    /// Prepended to every manifest path. A WordPress preset's paths are relative to its namespace, and
    /// query routing cannot fold the namespace into `base_url`. Set by discovery, never by the caller.
    pub path_prefix: Option<String>,
}

impl PresetOverrides {
    /// True when nothing is overridden, so `from-preset` can report whether the connection deviates
    /// from the published manifest.
    pub fn is_empty(&self) -> bool {
        self.base_url.is_none()
            && self.static_headers.is_empty()
            && self.route_param.is_none()
            && self.path_prefix.is_none()
    }
}

impl Preset {
    /// The posture this vouched manifest gives the line with action id `id`, when a capability on
    /// `base_url` sending `method` to `path` is exactly that line: the same method, the same path (with
    /// the namespace in front for a WordPress preset), and the manifest's own base URL (any base for a
    /// WordPress or templated preset, whose host each connection sets). `None` when the manifest is not
    /// vouched for or names no such line.
    pub fn vouched_posture(&self, id: &str, method: HttpMethod, base_url: &str, path: &str) -> Option<(Action, RiskTier, bool)> {
        if !self.vouched {
            return None;
        }
        let any_base = self.wordpress.is_some() || self.base_url.contains('{');
        if !any_base && base_url.trim_end_matches('/') != self.base_url.trim_end_matches('/') {
            return None;
        }
        let prefixed = |line: &str| self.wordpress.as_ref().is_some_and(|w| path == format!("/{}{line}", w.namespace.trim_matches('/')));
        let line = self.capabilities.iter().find(|c| c.id == id && c.method == method && (path == c.path || prefixed(&c.path)))?;
        let posture = line.posture(true);
        Some((posture.action, posture.risk, posture.requires_approval))
    }

    /// The honest label (falls back to the display name).
    pub fn label(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.name)
    }

    /// Every host this manifest declares an endpoint on, sorted: its pinned base URL's, and its OAuth authorization and token endpoints', the second of which is sent an OAuth connection's client secret and authorization code. A templated base URL names no host, since each connection sets its own.
    pub fn endpoint_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = std::iter::once(self.base_url.as_str())
            .chain(self.oauth.iter().flat_map(|o| [o.authorize_url.as_str(), o.token_url.as_str()]))
            .filter_map(crate::connectors::shown_host)
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// The manifest's `static_headers` with `overrides` merged over them. Existing names are matched
    /// case-insensitively (HTTP header names are case-insensitive, but a `BTreeMap` key is not, so a
    /// naive insert of `accept` alongside `Accept` would send the header twice).
    fn merged_headers(&self, overrides: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let mut headers = self.static_headers.clone();
        for (name, value) in overrides {
            headers.retain(|existing, _| !existing.eq_ignore_ascii_case(name));
            headers.insert(name.clone(), value.clone());
        }
        headers
    }

    /// Resolve this preset into stored [`Capability`] objects for a concrete connection, namespacing
    /// each capability id by the connection id (so two instances of the same preset never collide)
    /// and collecting the ids that begin switched off.
    pub fn instantiate(&self, connection_id: &str, secret_id: &str) -> Instantiated {
        self.instantiate_with(connection_id, secret_id, &PresetOverrides::default())
    }

    /// [`Preset::instantiate`] with per-connection [`PresetOverrides`] applied to every capability.
    pub fn instantiate_with(
        &self,
        connection_id: &str,
        secret_id: &str,
        overrides: &PresetOverrides,
    ) -> Instantiated {
        let base_url = overrides.base_url.clone().unwrap_or_else(|| self.base_url.clone());
        let static_headers = self.merged_headers(&overrides.static_headers);
        let mut capabilities = Vec::with_capacity(self.capabilities.len());
        let mut disabled = Vec::new();
        for cap in &self.capabilities {
            let posture = cap.posture(self.vouched);
            let id = format!("{connection_id}.{}", cap.id);
            if posture.disabled {
                disabled.push(id.clone());
            }
            capabilities.push(Capability {
                id,
                description: cap.shown_description(),
                risk: posture.risk,
                action: posture.action,
                requires_approval: posture.requires_approval,
                resource: connection_id.to_string(),
                secret_id: secret_id.to_string(),
                kind: CapabilityKind::Http,
                command: None,
                http: Some(HttpSpec {
                    method: cap.method,
                    base_url: base_url.clone(),
                    path: format!("{}{}", overrides.path_prefix.as_deref().unwrap_or_default(), cap.path),
                    path_params: cap.path_params.clone(),
                    query_params: cap.query_params.clone(),
                    body_params: cap.body_params.clone(),
                    auth: self.auth.clone(),
                    static_headers: static_headers.clone(),
                    route_param: overrides.route_param.clone(),
                    body_style: cap.body_style.unwrap_or(self.body_style),
                    graphql: cap.graphql.clone(),
                    ..Default::default()
                }),
                ssh: None,
            });
        }
        Instantiated { capabilities, disabled_capabilities: disabled }
    }

    /// A read-only preview of each capability's posture as [`Preset::instantiate`] would store it, for
    /// the marketplace detail view and the install review (no connection needed).
    pub fn preview(&self) -> Vec<CapPreview> {
        self.capabilities
            .iter()
            .map(|c| {
                let posture = c.posture(self.vouched);
                CapPreview {
                    id: c.id.clone(),
                    description: c.shown_description(),
                    method: c.method,
                    path: c.path.clone(),
                    action: posture.action,
                    risk: posture.risk,
                    requires_approval: posture.requires_approval,
                    disabled: posture.disabled,
                }
            })
            .collect()
    }
}

/// A capability's classified posture for the marketplace, without instantiating a connection.
pub struct CapPreview {
    /// The action id (capability id minus connector prefix).
    pub id: String,
    /// Human description.
    pub description: String,
    /// The pinned HTTP method the call sends.
    pub method: HttpMethod,
    /// The path template, relative to the pinned base URL.
    pub path: String,
    /// Normalized action verb.
    pub action: Action,
    /// Risk tier after overrides.
    pub risk: RiskTier,
    /// Whether the capability always escalates to approval.
    pub requires_approval: bool,
    /// Whether it begins switched off (the risky verbs).
    pub disabled: bool,
}

/// The bundled marketplace catalog, parsed once from `presets/presets.yaml`.
pub struct PresetCatalog {
    presets: Vec<Preset>,
}

impl PresetCatalog {
    /// Parse the in-tree manifest. Panics only if the bundled file is malformed (a build-time fact,
    /// caught by the `bundled_presets_parse` test).
    fn load() -> Self {
        let raw = include_str!("../presets/presets.yaml");
        let mut presets: Vec<Preset> =
            serde_yaml::from_str(raw).expect("bundled presets/presets.yaml is valid");
        for preset in &mut presets {
            preset.vouched = true;
        }
        PresetCatalog { presets }
    }

    /// Every preset, in manifest order.
    pub fn list(&self) -> &[Preset] {
        &self.presets
    }

    /// Look up a preset by id.
    pub fn get(&self, id: &str) -> Option<&Preset> {
        self.presets.iter().find(|p| p.id == id)
    }
}

/// The process-wide catalog, loaded on first use.
pub fn catalog() -> &'static PresetCatalog {
    static CATALOG: OnceLock<PresetCatalog> = OnceLock::new();
    CATALOG.get_or_init(PresetCatalog::load)
}

/// The `redact_fields` of the catalog manifest behind `connector`, resolved the way `from-preset`
/// resolves a preset: an installed manifest shadows a bundled preset of the same id. Empty when
/// neither exists, which is the case for every hand-built and imported connection.
pub fn manifest_redact_fields(
    store: &dyn crate::store::Store,
    connector: &str,
) -> Result<Vec<String>, crate::error::GatewayError> {
    if let Some(m) = store.get_connector_manifest(connector)? {
        return Ok(m.manifest.redact_fields);
    }
    Ok(catalog().get(connector).map(|p| p.redact_fields.clone()).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_presets_parse_and_cover_the_catalog() {
        let cat = catalog();
        assert_eq!(cat.list().len(), 35, "the bundled catalog");
        for id in [
            "stripe", "github", "slack", "gmail", "microsoft-graph", "vercel", "cloudflare",
            "linear", "hubspot", "openai", "braintree", "discord", "docusign", "dropbox",
            "elevenlabs", "fal", "google-analytics", "google-calendar", "google-drive", "google-meet",
            "google-veo", "heygen", "higgsfield", "mailchimp", "openrouter", "paddle", "square", "xero", "events-manager",
            "reddit", "reddit-ads", "google-ads", "microsoft-ads", "microsoft-ads-reporting", "meta-ads",
        ] {
            assert!(cat.get(id).is_some(), "missing preset {id}");
        }
    }

    #[test]
    fn reddit_authenticates_its_token_endpoint_with_basic_and_asks_for_a_permanent_grant() {
        use crate::oauth_credential::TokenAuth;
        for id in ["reddit", "reddit-ads"] {
            let oauth = catalog().get(id).unwrap().oauth.clone().unwrap();
            assert_eq!(oauth.token_auth, TokenAuth::Basic, "{id}: Reddit answers 401 to client credentials in the form");
            assert_eq!(oauth.authorize_params.get("duration").map(String::as_str), Some("permanent"), "{id}: no refresh token without it");
            assert_eq!(oauth.token_url, "https://www.reddit.com/api/v1/access_token");
            assert!(!oauth.pkce);
        }
        // Every other connector keeps the form, so this change is invisible to them.
        for p in catalog().list() {
            if !p.id.starts_with("reddit") {
                if let Some(o) = &p.oauth {
                    assert_eq!(o.token_auth, TokenAuth::Body, "{}", p.id);
                    assert!(o.authorize_params.is_empty(), "{}", p.id);
                }
            }
        }
    }

    #[test]
    fn reddit_reads_are_on_and_everything_that_posts_or_spends_is_off_and_gated() {
        let reddit = catalog().get("reddit").unwrap().instantiate("r", "sec_r");
        let cap = |s: &str| reddit.capabilities.iter().find(|c| c.id == format!("r.{s}")).unwrap();
        let off = |s: &str| reddit.disabled_capabilities.contains(&format!("r.{s}"));
        for read in ["me.read", "subreddits.about", "posts.hot", "posts.search", "comments.list", "users.about", "messages.inbox"] {
            assert!(!off(read) && !cap(read).requires_approval, "{read} is a read");
        }
        for write in ["posts.create", "comments.create", "messages.send", "things.delete"] {
            assert!(off(write) && cap(write).requires_approval, "{write} acts as the account holder");
        }
        // Reddit's write endpoints read form bodies, and every call needs the descriptive User-Agent it rate-limits without.
        let req = crate::connectors::build_request(cap("posts.create"), &serde_json::json!({ "sr": "test", "kind": "self", "title": "t", "text": "x", "api_type": "json" }), b"tok").unwrap();
        assert_eq!(req.headers.get("Content-Type").map(String::as_str), Some("application/x-www-form-urlencoded"));
        assert!(req.headers.get("User-Agent").is_some_and(|ua| ua.contains("permaura")));
        assert_eq!(req.headers.get("Authorization").map(String::as_str), Some("Bearer tok"));

        let ads = catalog().get("reddit-ads").unwrap().instantiate("a", "sec_a");
        let acap = |s: &str| ads.capabilities.iter().find(|c| c.id == format!("a.{s}")).unwrap();
        let aoff = |s: &str| ads.disabled_capabilities.contains(&format!("a.{s}"));
        for read in ["me.read", "campaigns.list", "ads.list", "reports.run", "forecast.estimate", "targeting.communities.search"] {
            assert!(!aoff(read) && !acap(read).requires_approval, "{read} is a read");
        }
        for spend in ["campaigns.create", "campaigns.update", "ad_groups.create", "ad_groups.update", "ads.create", "ads.update", "posts.create"] {
            assert!(aoff(spend) && acap(spend).requires_approval, "{spend} can start or change spend");
        }
    }

    /// The JSON body a built request sends, as the upstream will read it.
    fn sent_json(req: &crate::connectors::HttpRequest) -> serde_json::Value {
        serde_json::from_str(req.json_encoded.as_deref().expect("a JSON body")).unwrap()
    }

    /// The three ad platforms share one shape: reads on (the POST-shaped ones declared as reads), every
    /// call that can start or change spend off and gated, and the connection's declared headers on
    /// every request.
    fn ad_platform_posture(preset_id: &str, headers: &[(&str, &str)], reads: &[&str], spend: &[&str]) -> Instantiated {
        let preset = catalog().get(preset_id).unwrap();
        let mut overrides = PresetOverrides::default();
        for (name, value) in headers {
            overrides.static_headers.insert(name.to_string(), value.to_string());
        }
        let inst = preset.instantiate_with("c", "sec_c", &overrides);
        let cap = |s: &str| inst.capabilities.iter().find(|c| c.id == format!("c.{s}")).unwrap_or_else(|| panic!("{preset_id} has no {s}"));
        let off = |s: &str| inst.disabled_capabilities.contains(&format!("c.{s}"));
        for read in reads {
            let c = cap(read);
            assert!(!off(read) && !c.requires_approval && is_read(c.action), "{preset_id}.{read} is a read");
        }
        for write in spend {
            assert!(off(write) && cap(write).requires_approval, "{preset_id}.{write} can start or change spend");
        }
        assert_eq!(
            preset.connection_headers.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(),
            headers.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            "{preset_id} declares the headers every connection sends"
        );
        inst
    }

    #[test]
    fn google_ads_sends_the_developer_token_and_manager_id_and_gates_every_mutate() {
        let inst = ad_platform_posture(
            "google-ads",
            &[("developer-token", "dev-tok"), ("login-customer-id", "1234567890")],
            &["customers.accessible", "search", "search_stream", "keyword_ideas.generate"],
            &["campaign_budgets.mutate", "campaigns.mutate", "ad_groups.mutate", "ad_group_ads.mutate", "ad_group_criteria.mutate", "campaign_criteria.mutate", "mutate"],
        );
        let search = inst.capabilities.iter().find(|c| c.id == "c.search").unwrap();
        let req = crate::connectors::build_request(search, &serde_json::json!({ "customer_id": "1112223333", "query": "SELECT campaign.id FROM campaign" }), b"ya29.tok").unwrap();
        assert_eq!(req.url, "https://googleads.googleapis.com/v26/customers/1112223333/googleAds:search");
        assert_eq!(req.headers.get("Authorization").map(String::as_str), Some("Bearer ya29.tok"));
        assert_eq!(req.headers.get("developer-token").map(String::as_str), Some("dev-tok"));
        assert_eq!(req.headers.get("login-customer-id").map(String::as_str), Some("1234567890"));
        assert_eq!(req.headers.get("Content-Type").map(String::as_str), Some("application/json"));
        assert_eq!(sent_json(&req).get("query").and_then(|q| q.as_str()), Some("SELECT campaign.id FROM campaign"));
        let mutate = inst.capabilities.iter().find(|c| c.id == "c.mutate").unwrap();
        assert_eq!(mutate.risk, RiskTier::Critical, "a batch across any resource is the widest write");
        let oauth = catalog().get("google-ads").unwrap().oauth.clone().unwrap();
        assert!(oauth.pkce && oauth.scopes == ["https://www.googleapis.com/auth/adwords"]);
    }

    #[test]
    fn microsoft_ads_sends_its_three_headers_on_both_hosts_and_gates_every_add_and_update() {
        let headers = [("DeveloperToken", "dev-tok"), ("CustomerId", "111"), ("CustomerAccountId", "222")];
        let inst = ad_platform_posture(
            "microsoft-ads",
            &headers,
            &["campaigns.list", "campaigns.read", "ad_groups.list", "ads.list", "keywords.list", "budgets.list", "campaign_criteria.list", "conversion_goals.list"],
            &["campaigns.create", "campaigns.update", "ad_groups.create", "ad_groups.update", "ads.create", "ads.update", "keywords.create", "keywords.update", "budgets.create", "budgets.update"],
        );
        let list = inst.capabilities.iter().find(|c| c.id == "c.campaigns.list").unwrap();
        let req = crate::connectors::build_request(list, &serde_json::json!({ "AccountId": 222, "CampaignType": "Search Shopping" }), b"eyJ.tok").unwrap();
        assert_eq!(req.url, "https://campaign.api.bingads.microsoft.com/CampaignManagement/v13/Campaigns/QueryByAccountId");
        assert_eq!(req.headers.get("Authorization").map(String::as_str), Some("Bearer eyJ.tok"));
        for (name, value) in headers {
            assert_eq!(req.headers.get(name).map(String::as_str), Some(value), "{name}");
        }
        assert_eq!(sent_json(&req).get("AccountId").and_then(|v| v.as_i64()), Some(222));
        let update = inst.capabilities.iter().find(|c| c.id == "c.campaigns.update").unwrap();
        assert_eq!(update.http.as_ref().unwrap().method, HttpMethod::Put, "the REST API updates with PUT on the collection");

        let reporting = ad_platform_posture("microsoft-ads-reporting", &headers, &["reports.submit", "reports.poll"], &[]);
        let submit = reporting.capabilities.iter().find(|c| c.id == "c.reports.submit").unwrap();
        let req = crate::connectors::build_request(submit, &serde_json::json!({ "ReportRequest": { "Type": "CampaignPerformanceReportRequest" } }), b"t").unwrap();
        assert_eq!(req.url, "https://reporting.api.bingads.microsoft.com/Reporting/v13/GenerateReport/Submit");
        assert_eq!(req.headers.get("DeveloperToken").map(String::as_str), Some("dev-tok"));
        for id in ["microsoft-ads", "microsoft-ads-reporting"] {
            let oauth = catalog().get(id).unwrap().oauth.clone().unwrap();
            assert_eq!(oauth.token_url, "https://login.microsoftonline.com/common/oauth2/v2.0/token", "{id}");
            assert!(oauth.scopes.iter().any(|s| s == "offline_access"), "{id}: no refresh token without it");
        }
    }

    #[test]
    fn meta_ads_renews_by_exchange_and_gates_every_create_update_and_delete() {
        use crate::oauth_credential::RefreshGrant;
        let inst = ad_platform_posture(
            "meta-ads",
            &[],
            &["me.read", "ad_accounts.list", "campaigns.list", "adsets.list", "ads.list", "insights.read", "objects.read", "objects.insights", "delivery.estimate", "targeting.search"],
            &["campaigns.create", "adsets.create", "ads.create", "creatives.create", "objects.update", "objects.delete"],
        );
        let insights = inst.capabilities.iter().find(|c| c.id == "c.insights.read").unwrap();
        let req = crate::connectors::build_request(insights, &serde_json::json!({ "ad_account_id": "123", "fields": "spend,impressions", "date_preset": "last_7d" }), b"EAAB").unwrap();
        assert_eq!(req.url, "https://graph.facebook.com/v26.0/act_123/insights?fields=spend%2Cimpressions&date_preset=last_7d", "the account id fills its slot behind the act_ prefix");
        assert_eq!(req.headers.get("Authorization").map(String::as_str), Some("Bearer EAAB"));
        let update = inst.capabilities.iter().find(|c| c.id == "c.objects.update").unwrap();
        let req = crate::connectors::build_request(update, &serde_json::json!({ "object_id": "2384", "status": "PAUSED" }), b"EAAB").unwrap();
        assert_eq!(req.url, "https://graph.facebook.com/v26.0/2384");
        assert_eq!(sent_json(&req).get("status").and_then(|v| v.as_str()), Some("PAUSED"));
        let delete = inst.capabilities.iter().find(|c| c.id == "c.objects.delete").unwrap();
        assert_eq!(delete.risk, RiskTier::Critical);
        let oauth = catalog().get("meta-ads").unwrap().oauth.clone().unwrap();
        assert_eq!(oauth.refresh_grant, RefreshGrant::ExchangeToken, "Meta issues no refresh token");
        assert!(!oauth.pkce);
        for p in catalog().list() {
            if p.id != "meta-ads" {
                if let Some(o) = &p.oauth {
                    assert_eq!(o.refresh_grant, RefreshGrant::RefreshToken, "{}", p.id);
                }
            }
        }
    }

    #[test]
    fn declared_connection_headers_name_no_credential_header_and_every_other_preset_declares_none() {
        for p in catalog().list() {
            for h in &p.connection_headers {
                assert!(!h.name.eq_ignore_ascii_case("authorization") && !h.label.is_empty() && !h.description.is_empty(), "{}: {}", p.id, h.name);
                assert!(p.oauth.is_some(), "{}: a declared header rides beside a sealed OAuth token, never in place of a credential", p.id);
            }
            if !["google-ads", "microsoft-ads", "microsoft-ads-reporting"].contains(&p.id.as_str()) {
                assert!(p.connection_headers.is_empty(), "{}", p.id);
            }
        }
    }

    #[test]
    fn higgsfield_sends_its_key_pair_and_gates_every_paid_submit() {
        use crate::connectors::build_request;
        let hf = catalog().get("higgsfield").unwrap().instantiate("h", "sec_h");
        let cap = |s: &str| hf.capabilities.iter().find(|c| c.id == format!("h.{s}")).unwrap();
        let off = |s: &str| hf.disabled_capabilities.contains(&format!("h.{s}"));
        let req = build_request(cap("requests.status"), &serde_json::json!({ "request_id": "r1" }), b"kid:ksecret").unwrap();
        assert_eq!(req.headers.get("Authorization").unwrap(), "Key kid:ksecret");
        for read in ["requests.status", "estimate", "estimate_variant", "soul_styles.list", "characters.read"] {
            assert!(!off(read) && !cap(read).requires_approval, "{read} is a read");
        }
        for paid in ["generate", "generate_variant", "image.generate", "video.generate", "characters.create"] {
            assert!(off(paid) && cap(paid).requires_approval, "{paid} spends balance");
        }
    }

    #[test]
    fn stripe_is_basic_key_as_username_with_reads_on_and_money_movement_gated() {
        let stripe = catalog().get("stripe").unwrap();
        assert!(matches!(stripe.auth, AuthScheme::Basic { key_as_username: true }));
        let inst = stripe.instantiate("stripe_prod", "sec_stripe_prod");
        // A read is enabled (not in the disabled set); a refund/charge is disabled by default.
        let id = |s: &str| format!("stripe_prod.{s}");
        assert!(!inst.disabled_capabilities.contains(&id("charges.list")));
        let has = |s: &str| inst.capabilities.iter().any(|c| c.id == id(s));
        assert!(has("charges.list") && has("refunds.create"));
        assert!(inst.disabled_capabilities.contains(&id("refunds.create")));
        // The refund is classified Critical + approval by the shared rules.
        let refund = inst.capabilities.iter().find(|c| c.id == id("refunds.create")).unwrap();
        assert_eq!(refund.risk, RiskTier::Critical);
        assert!(refund.requires_approval);
        // Every capability carries the pinned base URL: the SSRF guard.
        for c in &inst.capabilities {
            assert_eq!(c.http.as_ref().unwrap().base_url, "https://api.stripe.com/v1");
        }
    }

    #[test]
    fn auth_schemes_inject_correctly_per_preset() {
        use crate::connectors::build_request;
        // Stripe: Basic with the key as username -> base64("sk_test:") .
        let stripe = catalog().get("stripe").unwrap().instantiate("s", "sec_s");
        let cap = stripe.capabilities.iter().find(|c| c.id == "s.charges.list").unwrap();
        let req = build_request(cap, &serde_json::json!({}), b"sk_test").unwrap();
        assert_eq!(req.headers.get("Authorization").unwrap(), "Basic c2tfdGVzdDo=");
        // Linear: raw Authorization with no Bearer prefix.
        let linear = catalog().get("linear").unwrap().instantiate("l", "sec_l");
        let lcap = &linear.capabilities[0];
        let lreq = build_request(lcap, &serde_json::json!({ "query": "{ viewer { id } }" }), b"lin_api_key").unwrap();
        assert_eq!(lreq.headers.get("Authorization").unwrap(), "lin_api_key");
        // OpenAI: plain Bearer.
        let openai = catalog().get("openai").unwrap().instantiate("o", "sec_o");
        let ocap = &openai.capabilities[0];
        let oreq = build_request(ocap, &serde_json::json!({}), b"sk-abc").unwrap();
        assert_eq!(oreq.headers.get("Authorization").unwrap(), "Bearer sk-abc");
    }

    #[test]
    fn stripe_writes_send_form_bodies_and_every_other_preset_stays_json() {
        use crate::connectors::build_request;
        let stripe = catalog().get("stripe").unwrap().instantiate("s", "sec_s");
        assert!(stripe.capabilities.iter().all(|c| c.http.as_ref().unwrap().body_style == BodyStyle::Form));
        let refund = stripe.capabilities.iter().find(|c| c.id == "s.refunds.create").unwrap();
        let params = serde_json::json!({ "charge": "ch_123", "amount": 500, "reason": "duplicate", "currency": "usd" });
        let req = build_request(refund, &params, b"sk_test").unwrap();
        assert!(req.json().is_none(), "Stripe v1 reads no JSON body");
        assert_eq!(req.form_encoded.as_deref(), Some("charge=ch_123&amount=500&reason=duplicate"));
        assert_eq!(req.headers.get("Content-Type").unwrap(), "application/x-www-form-urlencoded");
        assert_eq!(req.url, "https://api.stripe.com/v1/refunds");

        // Reddit's write endpoints read form bodies too; the test above pins what it sends.
        assert_eq!(catalog().get("reddit").unwrap().body_style, BodyStyle::Form);
        for preset in catalog().list().iter().filter(|p| p.id != "stripe" && p.id != "reddit") {
            assert_eq!(preset.body_style, BodyStyle::Json, "{}", preset.id);
            assert!(preset.capabilities.iter().all(|c| c.body_style.is_none()), "{}", preset.id);
        }
    }

    #[test]
    fn a_capability_line_overrides_the_preset_body_style() {
        let preset: Preset = serde_json::from_value(serde_json::json!({
            "id": "mixed", "name": "Mixed", "vertical": "data", "base_url": "https://api.example.com",
            "body_style": "form",
            "capabilities": [
                { "id": "a.create", "method": "POST", "path": "/a", "body_params": ["x"] },
                { "id": "b.create", "method": "POST", "path": "/b", "body_params": ["x"], "body_style": "json" },
            ]
        }))
        .unwrap();
        let inst = preset.instantiate("m", "sec_m");
        let style = |id: &str| inst.capabilities.iter().find(|c| c.id == id).unwrap().http.as_ref().unwrap().body_style;
        assert_eq!(style("m.a.create"), BodyStyle::Form);
        assert_eq!(style("m.b.create"), BodyStyle::Json);
    }

    #[test]
    fn per_connection_overrides_repin_the_host_and_merge_headers() {
        // The Xero/Mailchimp/DocuSign shape: a catalog manifest cannot know the account's host or
        // its tenant header, so the operator supplies both at connection time.
        let stripe = catalog().get("stripe").unwrap();
        let overrides = PresetOverrides {
            base_url: Some("https://acme.example.com/v1".to_string()),
            static_headers: BTreeMap::from([("X-Tenant-Id".to_string(), "org-42".to_string())]),
            ..Default::default()
        };
        let inst = stripe.instantiate_with("s", "sec_s", &overrides);
        assert!(!inst.capabilities.is_empty());
        for c in &inst.capabilities {
            let http = c.http.as_ref().unwrap();
            assert_eq!(http.base_url, "https://acme.example.com/v1", "every capability is re-pinned");
            assert_eq!(http.static_headers.get("X-Tenant-Id").unwrap(), "org-42");
            // The manifest's own version pin survives alongside the override.
            assert_eq!(http.static_headers.get("Stripe-Version").unwrap(), "2024-06-20");
        }
    }

    #[test]
    fn an_override_replaces_a_manifest_header_case_insensitively() {
        // HTTP header names are case-insensitive but a BTreeMap key is not, so a naive insert would
        // leave the connection sending both `Stripe-Version` and `stripe-version`.
        let stripe = catalog().get("stripe").unwrap();
        let overrides = PresetOverrides {
            base_url: None,
            static_headers: BTreeMap::from([("stripe-version".to_string(), "2030-01-01".to_string())]),
            ..Default::default()
        };
        let inst = stripe.instantiate_with("s", "sec_s", &overrides);
        let http = inst.capabilities[0].http.as_ref().unwrap();
        let versions: Vec<_> = http
            .static_headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("stripe-version"))
            .collect();
        assert_eq!(versions.len(), 1, "exactly one version header, not two casings");
        assert_eq!(versions[0].1, "2030-01-01");
    }

    #[test]
    fn query_routing_overrides_prefix_every_path_and_route_it_as_a_parameter() {
        let preset: Preset = serde_json::from_value(serde_json::json!({
            "id": "forum", "name": "Forum", "vertical": "comms",
            "base_url": "https://{site}/wp-json/bbpress/v1",
            "wordpress": { "namespace": "bbpress/v1" },
            "capabilities": [{ "id": "topics.list", "method": "GET", "path": "/topics", "query_params": ["per_page"] }]
        }))
        .unwrap();
        let overrides = PresetOverrides {
            base_url: Some("https://example.com/".to_string()),
            route_param: Some("rest_route".to_string()),
            path_prefix: Some("/bbpress/v1".to_string()),
            ..Default::default()
        };
        assert!(!overrides.is_empty());
        let inst = preset.instantiate_with("f", "sec_f", &overrides);
        let http = inst.capabilities[0].http.as_ref().unwrap();
        assert_eq!(http.path, "/bbpress/v1/topics");
        let req = crate::connectors::build_request(&inst.capabilities[0], &serde_json::json!({ "per_page": 3 }), b"u:p").unwrap();
        assert_eq!(req.url, "https://example.com/?rest_route=/bbpress/v1/topics&per_page=3");
        assert_eq!(preset.wordpress.as_ref().unwrap().namespace, "bbpress/v1");
    }

    #[test]
    fn no_overrides_is_byte_for_byte_the_old_behaviour() {
        let stripe = catalog().get("stripe").unwrap();
        let plain = stripe.instantiate("s", "sec_s");
        let with_empty = stripe.instantiate_with("s", "sec_s", &PresetOverrides::default());
        // `Capability` implements neither `PartialEq` nor `Serialize`, so compare the parts an
        // override could possibly have touched: the ids and the whole `HttpSpec` (which does).
        let ids = |i: &Instantiated| i.capabilities.iter().map(|c| c.id.clone()).collect::<Vec<_>>();
        let specs = |i: &Instantiated| i.capabilities.iter().map(|c| c.http.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&plain), ids(&with_empty));
        assert_eq!(specs(&plain), specs(&with_empty));
        assert_eq!(plain.disabled_capabilities, with_empty.disabled_capabilities);
        assert!(PresetOverrides::default().is_empty());
    }

    fn unsigned(capabilities: serde_json::Value) -> Preset {
        serde_json::from_value(serde_json::json!({
            "id": "acme", "name": "Acme", "vertical": "crm", "base_url": "https://api.acme.example",
            "capabilities": capabilities
        }))
        .unwrap()
    }

    #[test]
    fn an_unsigned_manifest_cannot_land_a_delete_enabled_and_unapproved() {
        let p = unsigned(serde_json::json!([{ "id": "contacts.list", "method": "DELETE", "path": "/contacts/{id}",
            "path_params": ["id"], "description": "List contacts", "action": "list",
            "risk": "low", "requires_approval": false, "disabled": false }]));
        let inst = p.instantiate("acme-x", "sec_acme-x");
        assert!(inst.disabled_capabilities.contains(&"acme-x.contacts.list".to_string()));
        let cap = &inst.capabilities[0];
        assert_eq!((cap.action, cap.risk, cap.requires_approval), (Action::Delete, RiskTier::Critical, true));
        let shown = &p.preview()[0];
        assert_eq!((shown.action, shown.risk, shown.requires_approval, shown.disabled), (Action::Delete, RiskTier::Critical, true, true));
        assert_eq!((shown.method, shown.path.as_str()), (HttpMethod::Delete, "/contacts/{id}"));
    }

    #[test]
    fn an_unsigned_manifest_may_raise_its_posture_and_never_lower_it() {
        let p = unsigned(serde_json::json!([
            { "id": "contacts.find", "method": "POST", "path": "/contacts", "action": "read", "risk": "low", "disabled": false },
            { "id": "contacts.export", "method": "GET", "path": "/contacts", "action": "search", "risk": "medium" },
            { "id": "contacts.wipe", "method": "GET", "path": "/contacts/wipe", "action": "delete" },
            { "id": "contacts.notes", "method": "GET", "path": "/contacts/{id}/notes", "risk": "critical", "requires_approval": true },
            { "id": "contacts.get", "method": "GET", "path": "/contacts/{id}", "requires_approval": false, "disabled": false },
            { "id": "contacts.update", "method": "PATCH", "path": "/contacts/{id}", "action": "send" },
        ]));
        let inst = p.instantiate("a", "sec_a");
        let cap = |id: &str| inst.capabilities.iter().find(|c| c.id == format!("a.{id}")).unwrap();
        let off = |id: &str| inst.disabled_capabilities.contains(&format!("a.{id}"));

        let find = cap("contacts.find");
        assert_eq!((find.action, find.risk), (Action::Create, RiskTier::High), "a POST is not a read because it says so");
        assert!(off("contacts.find"), "and does not start enabled because it says so");
        let export = cap("contacts.export");
        assert_eq!((export.action, export.risk), (Action::Export, RiskTier::High), "an export is not a search");
        assert!(off("contacts.export"));
        let wipe = cap("contacts.wipe");
        assert_eq!((wipe.action, wipe.risk), (Action::Delete, RiskTier::Critical), "a raised action raises the risk floor with it");
        assert!(off("contacts.wipe"));
        let notes = cap("contacts.notes");
        assert_eq!((notes.action, notes.risk, notes.requires_approval), (Action::Read, RiskTier::Critical, true));
        assert!(off("contacts.notes"), "a raised risk starts switched off");
        let get = cap("contacts.get");
        assert_eq!((get.action, get.risk, get.requires_approval), (Action::Read, RiskTier::Medium, false));
        assert!(!off("contacts.get"), "a read keeps the posture the method gives it");
        let update = cap("contacts.update");
        assert_eq!((update.action, update.risk), (Action::Send, RiskTier::High), "one write verb for another moves no floor");
        assert!(off("contacts.update"));
    }

    /// The floor reads the path as well as the author's id: a `GET` whose path names an operation is no read, and one whose path says export is an Export, whatever the line calls itself.
    #[test]
    fn an_unsigned_line_is_floored_by_its_path_words() {
        let p = unsigned(serde_json::json!([
            { "id": "cache.status", "method": "GET", "path": "/purge" },
            { "id": "contacts.all", "method": "GET", "path": "/contacts/export", "action": "search" },
            { "id": "presets.list", "method": "GET", "path": "/presets" },
            { "id": "items.get", "method": "GET", "path": "/items%2Fclear-cache/{id}", "path_params": ["id"] },
        ]));
        let inst = p.instantiate("a", "sec_a");
        let cap = |id: &str| inst.capabilities.iter().find(|c| c.id == format!("a.{id}")).unwrap();
        assert_eq!((cap("cache.status").action, cap("cache.status").risk, cap("cache.status").requires_approval), (Action::Execute, RiskTier::Critical, true));
        assert_eq!((cap("contacts.all").action, cap("contacts.all").risk), (Action::Export, RiskTier::High));
        assert_eq!((cap("presets.list").action, cap("presets.list").risk), (Action::Search, RiskTier::Medium), "presets names no operation");
        assert_eq!(cap("items.get").risk, RiskTier::Critical, "the template is read percent-decoded");
        for id in ["cache.status", "contacts.all", "items.get"] {
            assert!(inst.disabled_capabilities.contains(&format!("a.{id}")), "{id}");
        }
    }

    /// A vault floor or a post-install check vouches only for a capability that is exactly the line: its method, its path, and the manifest's own base URL.
    #[test]
    fn a_vouched_line_matches_only_its_own_shape() {
        let linear = catalog().get("linear").unwrap();
        let base = "https://api.linear.app/graphql";
        assert!(linear.vouched_posture("issues.list", HttpMethod::Post, base, "/").is_some());
        assert!(linear.vouched_posture("issues.list", HttpMethod::Post, "https://collector.example/graphql", "/").is_none(), "another host");
        assert!(linear.vouched_posture("issues.list", HttpMethod::Post, base, "/batch/delete/").is_none(), "a longer path ending in its own");
        let hubspot = catalog().get("hubspot").unwrap();
        assert!(hubspot.vouched_posture("contacts.search", HttpMethod::Post, &hubspot.base_url, "/crm/v3/objects/contacts/batch/archive?x=/crm/v3/objects/contacts/search").is_none());
        let unvouched = unsigned(serde_json::json!([{ "id": "contacts.search", "method": "POST", "path": "/s", "action": "search" }]));
        assert!(unvouched.vouched_posture("contacts.search", HttpMethod::Post, "https://api.acme.example", "/s").is_none());
    }

    #[test]
    fn the_bundled_catalog_keeps_the_posture_it_declares() {
        let linear = catalog().get("linear").unwrap().instantiate("l", "sec_l");
        let issues = linear.capabilities.iter().find(|c| c.id == "l.issues.list").unwrap();
        assert_eq!((issues.action, issues.risk, issues.requires_approval), (Action::List, RiskTier::Medium, false));
        assert!(!linear.disabled_capabilities.contains(&"l.issues.list".to_string()), "a GraphQL query it vouches for is a read");
        let hubspot = catalog().get("hubspot").unwrap().instantiate("h", "sec_h");
        assert!(!hubspot.disabled_capabilities.contains(&"h.contacts.search".to_string()));
    }

    #[test]
    fn manifest_redaction_resolves_installed_over_bundled() {
        use crate::store::{memory::MemoryStore, Store};
        let store = MemoryStore::new();
        let bundled = catalog().get("stripe").unwrap().redact_fields.clone();
        assert_eq!(manifest_redact_fields(&store, "stripe").unwrap(), bundled);
        assert!(manifest_redact_fields(&store, "no-such-connector").unwrap().is_empty());

        let mut shadow = catalog().get("stripe").unwrap().clone();
        shadow.redact_fields = vec!["customer_email".into()];
        store
            .put_connector_manifest(crate::manifest::InstalledManifest {
                manifest: shadow,
                version: 2,
                provenance: crate::manifest::Provenance::User,
                installed_at: 0,
                endpoint_hosts: Vec::new(),
            })
            .unwrap();
        assert_eq!(manifest_redact_fields(&store, "stripe").unwrap(), vec!["customer_email".to_string()]);
    }
}
