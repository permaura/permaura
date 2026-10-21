//! The rendering of a held call's parameters that every approval surface shows before a human
//! decides.
//!
//! `request_hash` has always bound a device signature to the exact parameters, but no surface showed
//! them, so an agent could say "cancel at the end of the billing period" and hold a call that cancels
//! immediately, and the approver signed for parameters they never saw. This module turns the held
//! row's `params` into [`DisplayRow`]s in two forms:
//!
//!  - **compact** (`params_display`, every approval read): capped at [`MAX_ROWS`] rows, [`MAX_DEPTH`]
//!    levels and [`MAX_VALUE_CHARS`] characters, with `complete` saying whether anything was cut;
//!  - **full** (`params_display_full`, `GET /v1/approvals/:id`): no row, depth or length cap, only the
//!    [`FULL_CEILING_BYTES`] ceiling, above which it is not served at all.
//!
//! A v3 approve binds the full rendering's digest, and `verify_signed_approval` refuses one over a
//! call too large to render whole, so padding can push a parameter off a card but never out of what
//! an approve is a decision about.
//!
//! What is load-bearing:
//!  - **No secret reaches a surface.** Values under a secret-bearing name (the call's own redaction
//!    set plus the rules in [`name_rule`]), the value beside a secret-bearing name in name/value pairs,
//!    whole values shaped like credentials, and credentials inside strings (URL passwords and secret
//!    query values, webhook URLs, `<scheme> <token>` authorizations, known token prefixes anywhere,
//!    `name=value` assignments) are replaced. So is every non-identifier field of a mutation whose
//!    kind carries sealed material. The bank account a payment goes to is the exception the approver
//!    needs: under its own key it shows its last four (an IBAN its country and check digits too).
//!  - **Only what is sent.** For a capability with a pinned request shape, only the parameters it
//!    forwards are rendered, so padding with undeclared keys shows nothing.
//!  - **Deterministic, bounded and unambiguous.** The same row renders the same text at hold time and
//!    at verification time; keys are walked in sorted order; strings are quoted with invisible,
//!    direction-changing, combining and look-alike-space characters spelled out, and Cyrillic or Greek
//!    letters mixed into a Latin word spelled out too; rendering stops at the caps or the ceiling.

use std::collections::{BTreeSet, HashSet};

use permaura_relay::{
    approval_display_digest, approval_display_full_digest, ApprovalDisplay, ApprovalDisplayFull,
    DisplayContext, DisplayRow, DisplayState, APPROVAL_DISPLAY_VERSION,
};
use serde_json::{Map, Value};

use crate::store::{PendingApproval, Store};

/// Compact rows listed before the rest are counted in `omitted`.
pub const MAX_ROWS: usize = 32;
/// Compact path segments shown before a container collapses to a count.
pub const MAX_DEPTH: usize = 4;
/// Compact characters of a string shown before it is cut.
pub const MAX_VALUE_CHARS: usize = 120;
/// Compact characters of an object key shown in a path before it is cut.
pub const MAX_KEY_CHARS: usize = 64;
/// Characters of the agent's stated intent served before it is cut.
pub const MAX_INTENT_CHARS: usize = 280;
/// Bytes of rendered text (paths plus values) the full rendering may reach. The gateway's default
/// request body ceiling, so every call an ordinary route accepts can be shown whole; only the
/// execution route's larger bodies (base64 file uploads up to 2 MiB) pass it, and those no one reads
/// on a phone, so they are deny-only unless a policy rung lets them through.
pub const FULL_CEILING_BYTES: usize = 256 * 1024;

const MASK: &str = "[redacted]";

/// The caps one rendering is made under: [`COMPACT`] or [`FULL`].
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    max_rows: Option<usize>,
    max_depth: Option<usize>,
    max_value_chars: Option<usize>,
    max_key_chars: Option<usize>,
    ceiling: Option<usize>,
}

/// Card and list rendering: row, depth and length caps, no ceiling.
pub const COMPACT: Limits = Limits {
    max_rows: Some(MAX_ROWS),
    max_depth: Some(MAX_DEPTH),
    max_value_chars: Some(MAX_VALUE_CHARS),
    max_key_chars: Some(MAX_KEY_CHARS),
    ceiling: None,
};

/// The rendering an approve binds: no caps, only the ceiling.
pub const FULL: Limits = Limits {
    max_rows: None,
    max_depth: None,
    max_value_chars: None,
    max_key_chars: None,
    ceiling: Some(FULL_CEILING_BYTES),
};

/// One rendering of a call's parameters.
#[derive(Debug, Clone, Default)]
pub struct Rendered {
    /// The rows, in a fixed order.
    pub rows: Vec<DisplayRow>,
    /// Values past the row cap, counted not listed.
    pub omitted: u32,
    /// The ceiling was passed: `rows` is empty and nothing may be approved on it.
    pub too_large: bool,
    /// Bytes of rendered text, or where rendering stopped.
    pub size: usize,
}

impl Rendered {
    /// Nothing omitted, truncated or collapsed, and under the ceiling: the rows are the whole call.
    pub fn complete(&self) -> bool {
        self.omitted == 0 && !self.too_large && !self.rows.iter().any(|r| r.state.is_partial())
    }
}

/// What decides a rendering besides the held row: the call's redaction set, and for a capability with
/// a pinned request shape, the parameters it forwards. Built by [`RenderInputs::for_approval`] at
/// serve time and again at verification time.
#[derive(Debug, Clone, Default)]
pub struct RenderInputs {
    names: HashSet<String>,
    paths: Vec<Vec<String>>,
    forwarded: Option<BTreeSet<String>>,
}

impl RenderInputs {
    /// A redaction set (bare names and dotted paths, case-insensitive) and an optional forwarding filter.
    pub fn new<I: IntoIterator<Item = String>>(redact_keys: I, forwarded: Option<BTreeSet<String>>) -> Self {
        let mut names = HashSet::new();
        let mut paths = Vec::new();
        for key in redact_keys {
            let key = key.trim().to_lowercase();
            if key.is_empty() {
                continue;
            }
            if key.contains('.') {
                let segments: Vec<String> = key.split('.').map(str::to_string).collect();
                if segments.iter().all(|s| !s.is_empty()) {
                    paths.push(segments);
                }
            }
            names.insert(key);
        }
        RenderInputs { names, paths, forwarded }
    }

    /// The gateway's default redaction set and no forwarding filter.
    pub fn defaults() -> Self {
        Self::new(permaura_core::default_redact_keys(), None)
    }

    /// The set the held call's result is redacted with (defaults, the connection's own list, its
    /// manifest's, and the holding policy's), and the forwarded parameters of its pinned request
    /// shape. A lookup that fails leaves the defaults and no filter, which shows more rather than less.
    pub fn for_approval(store: &dyn Store, a: &PendingApproval) -> Self {
        let mut extra: Vec<String> = Vec::new();
        if let Ok(Some(connection)) = store.get_connection(&a.resource) {
            extra.extend(connection.redact_fields.iter().cloned());
            if let Ok(manifest) = crate::presets::manifest_redact_fields(store, &connection.connector) {
                extra.extend(manifest);
            }
        }
        if let Some(policy_id) = &a.policy_id {
            if let Ok(Some(policy)) = store.get_policy(policy_id) {
                extra.extend(policy.redact_fields.iter().cloned());
            }
        }
        let forwarded = store
            .get_capability(&a.capability)
            .ok()
            .flatten()
            .and_then(|cap| cap.http.as_ref().map(forwarded_params));
        Self::new(permaura_core::effective_redact_keys(extra), forwarded)
    }
}

/// The agent parameters an imported capability actually sends: path parameters its template uses,
/// and its declared query, body and header parameters. `build_imported_http` drops every other key.
fn forwarded_params(spec: &crate::connectors::HttpSpec) -> BTreeSet<String> {
    spec.path_params
        .iter()
        .filter(|name| spec.path.contains(&format!("{{{name}}}")))
        .chain(&spec.query_params)
        .chain(&spec.body_params)
        .chain(&spec.header_params)
        .cloned()
        .collect()
}

/// The parameters a capability with a pinned shape reads, and those of them it cannot run without.
pub struct PinnedParams {
    /// Every parameter it reads.
    pub accepted: BTreeSet<String>,
    /// Those it requires, each once, in the order its shape names them.
    pub required: Vec<String>,
}

/// What a capability with a pinned shape reads: an imported HTTP spec's forwarded parameters (the path ones its template uses required), or an SSH operation's placeholders (those its template fills, all required) or its path and content. `None` for a capability whose connector takes its params as they come.
pub fn pinned_params(cap: &crate::connectors::Capability) -> Option<PinnedParams> {
    use crate::connectors::SshOp;
    let unique = |names: Vec<String>| names.into_iter().fold(Vec::new(), |mut out: Vec<String>, n| {
        if !out.contains(&n) {
            out.push(n);
        }
        out
    });
    if let Some(spec) = &cap.http {
        let required = unique(spec.path_params.iter().filter(|name| spec.path.contains(&format!("{{{name}}}"))).cloned().collect());
        return Some(PinnedParams { accepted: forwarded_params(spec), required });
    }
    let spec = cap.ssh.as_ref()?;
    let named = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
    let (accepted, required) = match &spec.op {
        SshOp::Exec { args_template, allowed_placeholders, .. } => {
            let filled = unique(
                args_template
                    .iter()
                    .filter_map(|t| t.strip_prefix('{').and_then(|r| r.strip_suffix('}')))
                    .filter(|name| allowed_placeholders.iter().any(|p| p == name))
                    .map(str::to_string)
                    .collect(),
            );
            (filled.clone(), filled)
        }
        SshOp::SftpGet { .. } => (named(&["path"]), named(&["path"])),
        SshOp::SftpPut { .. } => (named(&["path", "content"]), named(&["path", "content"])),
        SshOp::SftpList { .. } => (named(&["path"]), Vec::new()),
    };
    Some(PinnedParams { accepted: accepted.into_iter().collect(), required })
}

/// Refuse a parameter a capability with a pinned shape does not read, naming it: its connector would drop it and the call would answer as though it had been sent. A capability without a pinned shape takes its params as they come.
pub fn refuse_unpinned_params(cap: &crate::connectors::Capability, params: &serde_json::Value) -> Result<(), crate::error::GatewayError> {
    let Some(pinned) = pinned_params(cap) else { return Ok(()) };
    match params {
        serde_json::Value::Null => Ok(()),
        serde_json::Value::Object(given) => match given.keys().find(|k| !pinned.accepted.contains(k.as_str())) {
            Some(unread) => Err(crate::error::GatewayError::BadRequest(format!(
                "'{unread}' is not a parameter of {}, so it would not be sent; send only the parameters the capability takes",
                cap.id
            ))),
            None => Ok(()),
        },
        _ => Err(crate::error::GatewayError::BadRequest(format!("the parameters of {} are an object", cap.id))),
    }
}

/// The approval's text fields as every surface prints them and the digest binds them: escaped like
/// values, the intent also masked and cut at [`MAX_INTENT_CHARS`].
#[derive(Debug, Clone)]
pub struct ServedText {
    /// The capability id.
    pub capability: String,
    /// The resource it acts on.
    pub resource: String,
    /// The captured risk label.
    pub risk: String,
    /// The gateway's sentence for what runs.
    pub action_description: Option<String>,
    /// The gateway's message for the hold.
    pub message: String,
    /// The agent's stated intent.
    pub intent: Option<String>,
}

impl ServedText {
    /// The served text of `a`.
    pub fn of(a: &PendingApproval) -> Self {
        ServedText {
            capability: escape(&a.capability, false),
            resource: escape(&a.resource, false),
            risk: escape(&a.risk_label(), false),
            action_description: a.action_description.as_deref().map(|d| escape(d, false)),
            message: escape(&a.message, false),
            intent: a.intent.as_deref().filter(|i| !i.trim().is_empty()).map(served_intent),
        }
    }

    fn context(&self) -> DisplayContext<'_> {
        DisplayContext {
            capability: &self.capability,
            resource: &self.resource,
            risk: &self.risk,
            action_description: self.action_description.as_deref(),
            message: &self.message,
            intent: self.intent.as_deref(),
        }
    }
}

/// Bytes of the agent's stated reason a hold or an audit event keeps. Far beyond anything a person
/// writes as a reason, and small enough that masking and escaping it on every read costs nothing.
pub const MAX_STORED_INTENT_BYTES: usize = 4096;

/// The agent's reason as the gateway records it, on the hold and in every audit event: cut to
/// [`MAX_STORED_INTENT_BYTES`] (saying so, with the length it had) and with credentials masked, because
/// every member who can read the audit log reads it.
pub fn stored_intent(reason: &str) -> String {
    let cut = cut_at(reason, MAX_STORED_INTENT_BYTES);
    let kept = if cut.len() < reason.len() {
        format!("{cut}… (cut from {} characters)", reason.chars().count())
    } else {
        reason.to_string()
    };
    match mask(&kept, &RenderInputs::defaults()) {
        Masking::Whole => MASK.to_string(),
        Masking::Parts(text) => text,
        Masking::Clean => kept,
    }
}

fn cut_at(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn served_intent(intent: &str) -> String {
    let masked = stored_intent(intent);
    let len = masked.chars().count();
    if len > MAX_INTENT_CHARS {
        let head: String = masked.chars().take(MAX_INTENT_CHARS).collect();
        format!("{}… ({len} characters)", escape(&head, false))
    } else {
        escape(&masked, false)
    }
}

/// The compact rendering served as `params_display`.
pub fn compact(a: &PendingApproval, inputs: &RenderInputs) -> ApprovalDisplay {
    compact_with(a, inputs, &ServedText::of(a))
}

/// [`compact`] over served text the caller already built for this approval.
pub fn compact_with(a: &PendingApproval, inputs: &RenderInputs, text: &ServedText) -> ApprovalDisplay {
    let Some(params) = params_tree(a) else {
        return unrendered_with(text);
    };
    let rendered = render(&a.capability, &params, inputs, COMPACT);
    let digest = approval_display_digest(&text.context(), &rendered.rows, rendered.omitted);
    let complete = rendered.complete();
    ApprovalDisplay { version: APPROVAL_DISPLAY_VERSION, rows: rendered.rows, omitted: rendered.omitted, complete, digest }
}

/// `params_display` with no rows and the params counted as one omitted value: what a call too large to show renders as, and what a settled approval is served with when it is answered without its rendering.
pub fn unrendered_with(text: &ServedText) -> ApprovalDisplay {
    let digest = approval_display_digest(&text.context(), &[], 1);
    ApprovalDisplay { version: APPROVAL_DISPLAY_VERSION, rows: Vec::new(), omitted: 1, complete: false, digest }
}

/// The full rendering served as `params_display_full`.
pub fn full(a: &PendingApproval, inputs: &RenderInputs) -> ApprovalDisplayFull {
    full_with(a, inputs, &ServedText::of(a))
}

/// [`full`] over served text the caller already built for this approval.
pub fn full_with(a: &PendingApproval, inputs: &RenderInputs, text: &ServedText) -> ApprovalDisplayFull {
    let Some(params) = params_tree(a) else {
        return ApprovalDisplayFull {
            version: APPROVAL_DISPLAY_VERSION,
            rows: None,
            digest: None,
            too_large: true,
            size: a.params.len() as u64,
        };
    };
    let rendered = render(&a.capability, &params, inputs, FULL);
    if rendered.too_large {
        return ApprovalDisplayFull {
            version: APPROVAL_DISPLAY_VERSION,
            rows: None,
            digest: None,
            too_large: true,
            size: rendered.size as u64,
        };
    }
    let digest = approval_display_full_digest(&text.context(), &rendered.rows);
    ApprovalDisplayFull {
        version: APPROVAL_DISPLAY_VERSION,
        rows: Some(rendered.rows),
        digest: Some(digest),
        too_large: false,
        size: rendered.size as u64,
    }
}

/// What the tree a rendering of `a` walks is estimated to cost, or `None` when it would cost more than a rendering may build ([`crate::limits::render_limit_bytes`]) and `a` renders as too large to show without one.
pub fn tree_bytes(a: &PendingApproval) -> Option<u64> {
    Some(crate::connectors::json_budget::estimate(a.params.get().as_bytes())).filter(|&estimate| estimate <= crate::limits::render_limit_bytes())
}

/// A held call's params as the tree a rendering walks, or `None` when they would cost more than a rendering may build or do not parse. The gateway's callers hold room for it in the JSON pool ([`crate::service::EnforcementService::display_room`]).
/// Every agent hold this build makes fits. A control-plane change gets no tree check, so its row may not: a lone connector install past about 6 MiB of minimal capability lines at hosted defaults, or a dense manifest (short static_headers keys) near the 8 MiB bulk body with others waiting. Nor may a row held before the hold budget existed. Either renders as too large to show, which no device can sign an approve for, as its full rendering already was on 1.3.51.
fn params_tree(a: &PendingApproval) -> Option<Value> {
    let estimate = tree_bytes(a)?;
    crate::connectors::json_budget::value_from_slice(a.params.get().as_bytes(), estimate).ok()
}

/// The digest a v3 approve of `a` must carry, or `None` when the call is too large to show whole.
pub fn full_digest(a: &PendingApproval, inputs: &RenderInputs) -> Option<String> {
    full(a, inputs).digest
}

/// Render `params` for `capability` under `limits`.
pub fn render(capability: &str, params: &Value, inputs: &RenderInputs, limits: Limits) -> Rendered {
    let control_plane = capability.starts_with("permaura.");
    let mut w = Walker { inputs, limits, control_plane, out: Rendered::default(), chain: Vec::new(), card_keys: Vec::new(), cards: 0 };
    match params {
        Value::Null => {}
        Value::Object(map) => w.object("", map, 0, true),
        Value::Array(items) => w.array("", items, 0),
        scalar => w.value("(params)".to_string(), scalar, 1),
    }
    w.out
}

/// [`render`] with the default redaction set and no forwarding filter, for callers with no store.
pub fn render_params(capability: &str, params: &Value) -> (Vec<DisplayRow>, u32) {
    let r = render(capability, params, &RenderInputs::defaults(), COMPACT);
    (r.rows, r.omitted)
}

struct Walker<'a> {
    inputs: &'a RenderInputs,
    limits: Limits,
    /// A gateway-made hold (`permaura.*`), whose params are a stored control-plane mutation.
    control_plane: bool,
    out: Rendered,
    /// Lowercased object keys from the root to the value being walked, arrays left out, for the
    /// dotted entries of a redaction set.
    chain: Vec<String>,
    /// Index-aligned with `chain`: whether each key, read in its own case so `creditCard` splits, names a card.
    card_keys: Vec<bool>,
    /// How many card objects enclose the value being walked, through arrays and nested objects.
    cards: usize,
}

const NAME_FIELDS: &[&str] =
    &["name", "key", "header", "header_name", "field", "variable", "var", "param", "parameter", "k"];
const VALUE_FIELDS: &[&str] = &["value", "values", "val", "header_value", "content", "data", "v"];
/// Keys whose presence makes an object an OAuth token exchange, where a bare `code` is the grant.
const OAUTH_EXCHANGE: &[&str] = &["grant_type", "redirect_uri", "code_verifier"];

impl Walker<'_> {
    fn rows_full(&self) -> bool {
        self.limits.max_rows.is_some_and(|max| self.out.rows.len() >= max)
    }

    fn push(&mut self, path: String, state: DisplayState, value: String) {
        if self.out.too_large {
            return;
        }
        if self.rows_full() {
            self.out.omitted = self.out.omitted.saturating_add(1);
            return;
        }
        self.out.size += path.len() + value.len();
        if self.limits.ceiling.is_some_and(|c| self.out.size > c) {
            self.out.too_large = true;
            self.out.rows = Vec::new();
            return;
        }
        self.out.rows.push(DisplayRow { path, state, value });
    }

    fn stop(&self) -> bool {
        self.out.too_large
    }

    /// Whether the value under `key` (the last entry of `chain`) is a secret's.
    fn secret_name(&self, key: &str, value: &Value) -> bool {
        self.inputs.paths.iter().any(|p| self.chain.ends_with(p)) || self.secret_label(key, value)
    }

    /// Whether `name` labels a secret, whether it is a key or the `name` half of a name/value pair.
    fn secret_label(&self, name: &str, value: &Value) -> bool {
        if self.inputs.names.contains(&name.to_lowercase()) {
            return true;
        }
        match name_rule(name) {
            NameRule::Secret | NameRule::PayeeAccount => true,
            NameRule::SecretUnlessNumber => !value.is_number(),
            NameRule::Plain => false,
        }
    }

    /// Whether the call's own redaction set names the value under `key`, which no rule here relaxes.
    fn call_redacts(&self, key: &str) -> bool {
        self.inputs.paths.iter().any(|p| self.chain.ends_with(p)) || self.inputs.names.contains(&key.to_lowercase())
    }

    fn object(&mut self, path: &str, map: &Map<String, Value>, depth: usize, top: bool) {
        let sealed = if top && self.control_plane {
            map.get("kind").and_then(Value::as_str).and_then(sealed_mutation_fields)
        } else {
            None
        };
        let paired_secret = map.iter().any(|(k, v)| {
            NAME_FIELDS.contains(&k.to_lowercase().as_str())
                && v.as_str().is_some_and(|name| self.secret_label(name, &Value::Null))
        });
        let card = self.cards > 0
            || self.card_keys.last() == Some(&true)
            || map.get("object").and_then(Value::as_str) == Some("card")
            || map.get("type").and_then(Value::as_str).is_some_and(|t| t == "card" || t == "scheme");
        if card {
            self.cards += 1;
        }
        let oauth_exchange = map.keys().any(|k| OAUTH_EXCHANGE.contains(&k.to_lowercase().as_str()));
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort();
        for key in keys {
            if self.stop() {
                break;
            }
            if top && self.inputs.forwarded.as_ref().is_some_and(|f| !f.contains(key.as_str())) {
                continue;
            }
            let child = &map[key];
            if self.rows_full() {
                self.out.omitted = self.out.omitted.saturating_add(count_units(child, depth + 1, self.limits.max_depth));
                continue;
            }
            let (child_path, cut) = join_key(path, key, self.limits.max_key_chars);
            self.chain.push(key.to_lowercase());
            let words = key_words(key);
            let names_card = words.iter().any(|w| w == "card" || w == "cards");
            self.card_keys.push(names_card);
            let forced = match sealed {
                Some(visible) => {
                    key != "kind" && !visible.contains(&key.as_str()) && !(is_identifier(key) && is_scalar(child))
                }
                None => false,
            } || (paired_secret && VALUE_FIELDS.contains(&key.to_lowercase().as_str()))
                || (card && matches!(key.to_lowercase().as_str(), "number" | "pan" | "cvc" | "cvv"))
                || ((card || names_card || names_card_number(&words)) && card_number_shaped(child))
                || (oauth_exchange && key.eq_ignore_ascii_case("code"));
            let hidden = forced || self.secret_name(key, child);
            let payee = (!forced && !cut && !self.call_redacts(key) && name_rule(key) == NameRule::PayeeAccount)
                .then(|| payee_account_text(key, child))
                .flatten();
            if hidden && !is_inert(child) {
                if self.rows_full() {
                    self.out.omitted = self.out.omitted.saturating_add(1);
                } else if let Some(text) = payee {
                    self.push(child_path, DisplayState::Masked, quote(&text));
                } else {
                    let state = if cut { DisplayState::Truncated } else { DisplayState::Redacted };
                    self.push(child_path, state, redacted_text(child));
                }
            } else if cut {
                if self.rows_full() {
                    self.out.omitted = self.out.omitted.saturating_add(1);
                } else {
                    self.push(child_path, DisplayState::Truncated, summary(child));
                }
            } else {
                self.value(child_path, child, depth + 1);
            }
            self.chain.pop();
            self.card_keys.pop();
        }
        if card {
            self.cards -= 1;
        }
    }

    fn array(&mut self, path: &str, items: &[Value], depth: usize) {
        let pair = items.len() == 2
            && items[0].as_str().is_some_and(|name| self.secret_label(name, &items[1]))
            && !is_inert(&items[1]);
        for (i, item) in items.iter().enumerate() {
            if self.stop() {
                return;
            }
            if self.rows_full() {
                let rest = items[i..].iter().fold(0u32, |n, v| n.saturating_add(count_units(v, depth + 1, self.limits.max_depth)));
                self.out.omitted = self.out.omitted.saturating_add(rest);
                return;
            }
            let item_path = format!("{path}[{i}]");
            if pair && i == 1 {
                if self.rows_full() {
                    self.out.omitted = self.out.omitted.saturating_add(1);
                } else {
                    self.push(item_path, DisplayState::Redacted, redacted_text(item));
                }
            } else {
                self.value(item_path, item, depth + 1);
            }
        }
    }

    fn value(&mut self, path: String, value: &Value, depth: usize) {
        if self.stop() {
            return;
        }
        if self.rows_full() {
            self.out.omitted = self.out.omitted.saturating_add(count_units(value, depth, self.limits.max_depth));
            return;
        }
        let collapse = self.limits.max_depth.is_some_and(|max| depth >= max);
        match value {
            Value::Object(map) if map.is_empty() => self.push(path, DisplayState::Shown, "{}".into()),
            Value::Array(items) if items.is_empty() => self.push(path, DisplayState::Shown, "[]".into()),
            Value::Object(map) if collapse => self.push(path, DisplayState::Collapsed, count(map.len(), "field", "fields", '{', '}')),
            Value::Array(items) if collapse => self.push(path, DisplayState::Collapsed, count(items.len(), "item", "items", '[', ']')),
            Value::Object(map) => self.object(&path, map, depth, false),
            Value::Array(items) => self.array(&path, items, depth),
            Value::String(s) => self.string(path, s),
            scalar => self.push(path, DisplayState::Shown, scalar.to_string()),
        }
    }

    fn string(&mut self, path: String, s: &str) {
        if let Some(ceiling) = self.limits.ceiling {
            if self.out.size + path.len() + s.len() > ceiling.saturating_mul(2) {
                self.out.too_large = true;
                self.out.size = self.out.size.saturating_add(path.len() + s.len());
                self.out.rows = Vec::new();
                return;
            }
        }
        let (state, text) = match mask(s, self.inputs) {
            Masking::Whole => return self.push(path, DisplayState::Redacted, format!("set, {}", characters(s.chars().count()))),
            Masking::Parts(text) => (DisplayState::Masked, text),
            Masking::Clean => (DisplayState::Shown, s.to_string()),
        };
        let len = text.chars().count();
        match self.limits.max_value_chars {
            Some(max) if len > max => {
                let head: String = text.chars().take(max).collect();
                let quoted = quote(&head);
                let open = &quoted[..quoted.len() - 1];
                self.push(path, DisplayState::Truncated, format!("{open}…\" ({})", characters(len)));
            }
            _ => self.push(path, state, quote(&text)),
        }
    }
}

fn count_units(value: &Value, depth: usize, max_depth: Option<usize>) -> u32 {
    let collapse = max_depth.is_some_and(|max| depth >= max);
    match value {
        Value::Object(map) if !map.is_empty() && !collapse => {
            map.values().fold(0u32, |n, v| n.saturating_add(count_units(v, depth + 1, max_depth)))
        }
        Value::Array(items) if !items.is_empty() && !collapse => {
            items.iter().fold(0u32, |n, v| n.saturating_add(count_units(v, depth + 1, max_depth)))
        }
        _ => 1,
    }
}

fn redacted_text(value: &Value) -> String {
    let len = match value {
        Value::String(s) => s.chars().count(),
        other => other.to_string().chars().count(),
    };
    format!("set, {}", characters(len))
}

fn summary(value: &Value) -> String {
    match value {
        Value::Object(map) => count(map.len(), "field", "fields", '{', '}'),
        Value::Array(items) => count(items.len(), "item", "items", '[', ']'),
        Value::String(s) => format!("({})", characters(s.chars().count())),
        scalar => scalar.to_string(),
    }
}

fn is_identifier(key: &str) -> bool {
    key_words(key).last().is_some_and(|w| w == "id")
}

fn is_scalar(value: &Value) -> bool {
    matches!(value, Value::String(_) | Value::Number(_))
}

/// Null and booleans carry no secret whatever they are called: `password_auth: true` is a mode switch
/// an approver needs to read, and a one-bit value cannot be sealed material.
fn is_inert(value: &Value) -> bool {
    matches!(value, Value::Null | Value::Bool(_))
}

fn characters(n: usize) -> String {
    if n == 1 { "1 character".into() } else { format!("{n} characters") }
}

fn count(n: usize, one: &str, many: &str, open: char, close: char) -> String {
    format!("{open}{n} {}{close}", if n == 1 { one } else { many })
}

/// The path to `key` under `parent`, and whether the key had to be cut to fit.
fn join_key(parent: &str, key: &str, max_key_chars: Option<usize>) -> (String, bool) {
    let len = key.chars().count();
    let cut = max_key_chars.is_some_and(|max| len > max);
    let plain = !key.is_empty()
        && !cut
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '$');
    if plain {
        let path = if parent.is_empty() { key.to_string() } else { format!("{parent}.{key}") };
        return (path, false);
    }
    let shown: String = match max_key_chars {
        Some(max) if cut => key.chars().take(max).collect(),
        _ => key.to_string(),
    };
    let quoted = quote(&shown);
    let quoted = if cut { format!("{}…\"", &quoted[..quoted.len() - 1]) } else { quoted };
    (format!("{parent}[{quoted}]"), cut)
}

/// A JSON-style string literal of `s` with every character that does not print as itself spelled out.
fn quote(s: &str) -> String {
    format!("\"{}\"", escape(s, true))
}

/// `s` with control characters, invisible and direction-changing characters, combining marks and
/// look-alike spaces spelled out as `\u{…}`, and with the Cyrillic or Greek letters of a word that
/// mixes them with Latin spelled out too (`p\u{0430}ypal.com`). `\` is always escaped so a spelled-out
/// character cannot be forged, and `"` too when the text sits inside quotes.
pub fn escape(s: &str, in_quotes: bool) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut spell = vec![false; chars.len()];
    let word_char = |c: char| c.is_alphanumeric() || matches!(c, '.' | '-' | '_');
    let mut i = 0;
    while i < chars.len() {
        if !word_char(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && word_char(chars[i]) {
            i += 1;
        }
        let word = &chars[start..i];
        let latin = word.iter().any(|&c| is_latin_letter(c));
        let foreign = word.iter().any(|&c| is_cyrillic(c) || is_greek(c) || is_armenian(c));
        if latin && foreign {
            for (k, &c) in word.iter().enumerate() {
                if is_cyrillic(c) || is_greek(c) || is_armenian(c) {
                    spell[start + k] = true;
                }
            }
        }
    }
    let mut out = String::with_capacity(s.len() + 2);
    for (k, &c) in chars.iter().enumerate() {
        match c {
            '"' if in_quotes => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if spell[k] || c.is_control() || is_invisible(c) || is_math_alphanumeric(c) => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn is_latin_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || matches!(c as u32, 0x00C0..=0x024F | 0x1E00..=0x1EFF) && c.is_alphabetic()
}

fn is_cyrillic(c: char) -> bool {
    matches!(c as u32, 0x0400..=0x052F | 0x1C80..=0x1C8F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F)
}

fn is_greek(c: char) -> bool {
    matches!(c as u32, 0x0370..=0x03FF | 0x1F00..=0x1FFF)
}

fn is_armenian(c: char) -> bool {
    matches!(c as u32, 0x0530..=0x058F | 0xFB13..=0xFB17)
}

/// Mathematical Alphanumeric Symbols: letters and digits that read as plain Latin and are not.
fn is_math_alphanumeric(c: char) -> bool {
    matches!(c as u32, 0x1D400..=0x1D7FF)
}

fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00A0 | 0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x1680 | 0x17B4 | 0x17B5 | 0x180B..=0x180F
        | 0x0300..=0x036F | 0x0483..=0x0489 | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF
        | 0x2000..=0x200F | 0x2028..=0x202F | 0x205F..=0x206F | 0x2800 | 0x3000 | 0x3164 | 0xFE00..=0xFE0F
        | 0xFE20..=0xFE2F | 0xFEFF | 0xFFA0 | 0xFFF0..=0xFFFC | 0x13430..=0x1345F | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0000..=0xE0FFF)
}

/// The words of a key: split on anything that is not a letter or digit and at lower-to-upper case
/// changes, lowercased, with fullwidth Latin folded to ASCII. `X-Api-Key`, `apiKey`, `api_key` and
/// `ａｐｉ＿ｋｅｙ` all read as `api key`.
fn key_words(key: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in key.chars() {
        let c = match c as u32 {
            0xFF01..=0xFF5E => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            _ => c,
        };
        if !c.is_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        current.extend(c.to_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// A name that is a card number's on its own, without the word `card` (`cc`, `pan`, `ccnumber`, `cardnum`).
fn names_card_number(words: &[String]) -> bool {
    words.iter().any(|w| w == "cc" || w == "pan") || words.concat().contains("ccnum") || words.concat().contains("cardnum")
}

/// A value shaped like a payment card number: 13 to 19 digits, spaces and hyphens allowed, that pass the Luhn
/// check. Only consulted under a card's name or inside a card, since other identifiers (an IMEI) pass it too.
fn card_number_shaped(value: &Value) -> bool {
    let text = match value {
        Value::String(s) => s.as_str(),
        Value::Number(n) if n.is_u64() => return luhn_card(&n.to_string()),
        _ => return false,
    };
    luhn_card(text)
}

fn luhn_card(text: &str) -> bool {
    let digits: Vec<u32> = text.chars().filter(|c| !matches!(c, ' ' | '-')).map(|c| c.to_digit(10)).collect::<Option<_>>().unwrap_or_default();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| if i % 2 == 1 { if d * 2 > 9 { d * 2 - 9 } else { d * 2 } } else { d })
        .sum();
    sum % 10 == 0
}

/// What a key's name says about its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRule {
    /// Shown.
    Plain,
    /// Redacted.
    Secret,
    /// A seed is wallet material as a string and an RNG input as a number.
    SecretUnlessNumber,
    /// The bank account a payment goes to: not a credential, and the thing a human approving a payout has to check, so under its own key it shows its last four (see [`payee_account_text`]) and is redacted everywhere else.
    PayeeAccount,
}

/// Whether a value under `key` is redacted whatever its contents.
///
/// Names that point AT a secret without being one stay visible, because the approver needs them:
/// identifiers (`secret_id`), fingerprints and public halves (`host_key_sha256`, `public_key`), and
/// counts (`max_tokens`). A bare `key` or `auth` is too often a storage key or a mode (`key: "prod/db"`,
/// `auth_mode: "none"`) to hide, so those need a qualifier (`api_key`, `basic_auth`); the value-shape
/// rules are the backstop for what slips past.
pub fn name_rule(key: &str) -> NameRule {
    use NameRule::{PayeeAccount, Plain, Secret, SecretUnlessNumber};
    let words = key_words(key);
    let Some(last) = words.last() else { return Plain };
    let joined: String = words.concat();
    // Session identifiers are bearer credentials, so they are checked before `*_id` names are let through.
    if matches!(joined.as_str(), "sessionid" | "jsessionid" | "phpsessid" | "aspsessionid" | "sessid")
        || (words.iter().any(|w| w == "session") && matches!(last.as_str(), "id" | "key" | "cookie"))
    {
        return Secret;
    }
    const NAMES_A_SECRET: &[&str] = &[
        "id", "ids", "fp", "fingerprint", "sha256", "type", "kind", "name", "label", "count", "length",
        "len", "amount", "mode",
    ];
    if NAMES_A_SECRET.contains(&last.as_str()) {
        return Plain;
    }
    if words.iter().any(|w| w == "public" || w == "pubkey") || joined.contains("publickey") {
        return Plain;
    }
    if matches!(words[0].as_str(), "max" | "min" | "num" | "total") {
        return Plain;
    }
    const CONTAINS: &[&str] = &[
        "secret", "password", "passwd", "passphrase", "passcode", "credential", "apikey", "privatekey",
        "privkey", "accesskey", "secretkey", "signingkey", "clientkey", "masterkey", "encryptionkey",
        "authorization", "cookie", "bearer", "mnemonic", "seedphrase", "recoverycode", "recoverykey",
        "backupcode", "totpseed", "otpsecret", "cardnumber", "securitycode", "xprv",
        "passwort", "kennwort", "contrasena", "contraseña", "senha", "motdepasse", "wachtwoord",
        "losenord", "lösenord", "salasana", "haslo", "hasło", "sifre", "şifre", "пароль", "密码", "密碼",
        "パスワード", "비밀번호", "connectionstring", "databaseurl", "recoveryphrase", "backupphrase",
        "walletwords", "seedwords", "sshprivate", "privatessh", "codeverifier", "pkceverifier", "cardcode",
    ];
    if CONTAINS.iter().any(|s| joined.contains(s)) {
        return Secret;
    }
    // The assets a swap trades are public ids an approver has to see, not credentials.
    if words.len() == 2 && last == "token" && matches!(words[0].as_str(), "sell" | "buy" | "from" | "to") {
        return Plain;
    }
    // A token-suffixed name hides a number too (an OTP or MFA token is often one); only a plural count stays visible.
    if last.ends_with("token") {
        return Secret;
    }
    if last.ends_with("tokens") {
        return SecretUnlessNumber;
    }
    const WORDS: &[&str] = &[
        "pass", "pw", "pwd", "pin", "otp", "totp", "cvv", "cvv2", "cvc", "cvc2", "ssn", "jwt", "pan",
        "wif", "sig", "dsn", "parola", "heslo", "clave", "mdp", "jelszo", "jelszó", "pword", "psw",
        "pincode", "creds",
    ];
    if words.iter().any(|w| WORDS.contains(&w.as_str())) {
        return Secret;
    }
    const CODE_QUALIFIERS: &[&str] = &[
        "mfa", "otp", "totp", "oauth", "auth", "authorization", "verification", "factor", "twofactor", "2fa",
        "sms", "login", "recovery", "backup", "security", "confirmation", "access", "activation",
    ];
    if matches!(last.as_str(), "code" | "codes")
        && words.len() > 1
        && CODE_QUALIFIERS.contains(&words[words.len() - 2].as_str())
    {
        return Secret;
    }
    const KEY_QUALIFIERS: &[&str] = &[
        "api", "private", "access", "secret", "signing", "client", "encryption", "master", "license",
        "licence", "session", "ssh", "gpg", "pgp", "deploy", "service", "account", "app", "webhook",
        "shared", "hmac", "auth", "consumer", "storage", "subscription",
    ];
    const AUTH_QUALIFIERS: &[&str] = &["basic", "http", "proxy", "client", "api", "digest"];
    for (i, w) in words.iter().enumerate() {
        let before = i.checked_sub(1).map(|j| words[j].as_str());
        if matches!(w.as_str(), "key" | "keys") && before.is_some_and(|b| KEY_QUALIFIERS.contains(&b)) {
            return Secret;
        }
        if w == "auth" && before.is_some_and(|b| AUTH_QUALIFIERS.contains(&b)) {
            return Secret;
        }
        if w == "auth" && words.get(i + 1).is_some_and(|n| matches!(n.as_str(), "header" | "value" | "string")) {
            return Secret;
        }
    }
    if words.iter().any(|w| w == "seed" || w == "seeds") {
        return SecretUnlessNumber;
    }
    if words.iter().any(|w| w == "iban") || joined.contains("accountnumber") {
        return PayeeAccount;
    }
    Plain
}

/// What a [`NameRule::PayeeAccount`] value shows: an IBAN's country and check digits and its last four, any other account number's last four, spaces and hyphens dropped. `None` for a value not shaped like one (an IBAN is two letters, two digits and 11 to 30 letters or digits; an account number 5 to 34 digits), which stays redacted, so a credential put under the name reveals nothing.
fn payee_account_text(key: &str, value: &Value) -> Option<String> {
    let raw = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    let compact: String = raw.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
    let b = compact.as_bytes();
    if key_words(key).iter().any(|w| w == "iban") {
        let shaped = (15..=34).contains(&b.len())
            && b[..2].iter().all(u8::is_ascii_alphabetic)
            && b[2..4].iter().all(u8::is_ascii_digit)
            && b[4..].iter().all(u8::is_ascii_alphanumeric);
        return shaped.then(|| format!("{}{MASK}{}", &compact[..4], &compact[b.len() - 4..]));
    }
    let shaped = (5..=34).contains(&b.len()) && b.iter().all(u8::is_ascii_digit);
    shaped.then(|| format!("{MASK}{}", &compact[b.len() - 4..]))
}

/// For a mutation whose kind carries or points at sealed material, the fields an approver may see
/// beside its `kind` and its scalar identifiers; every other field is redacted. `None` for anything
/// else, which the ordinary rules cover.
///
/// Default-deny on purpose: a kind added later whose name says it carries a credential shows only its
/// `kind` and identifiers until someone lists what else is safe. Only for gateway-made holds: an agent
/// choosing a `kind` must not be able to blank its own parameters out of the approver's view.
fn sealed_mutation_fields(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "credential_promote" => Some(&["connection_id", "secret_id", "staging_secret_id"]),
        "secret_delete" => None,
        _ => {
            const SEALED: &[&str] = &[
                "credential", "credentials", "secret", "secrets", "vault", "password", "passphrase", "token",
                "tokens", "seal", "sealed", "import", "key", "keys",
            ];
            let words = key_words(kind);
            let public_key_trust = words.iter().any(|w| w == "approver");
            (!public_key_trust && words.iter().any(|w| SEALED.contains(&w.as_str()))).then_some(&[])
        }
    }
}

// ── secrets inside strings ───────────────────────────────────────────────────────────────────────

enum Masking {
    /// The whole value is a credential.
    Whole,
    /// The value with each credential in it replaced by [`MASK`].
    Parts(String),
    Clean,
}

fn mask(s: &str, inputs: &RenderInputs) -> Masking {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let exchange = assigns_oauth_exchange(s);
    pem_spans(s, &mut spans);
    url_spans(s, inputs, exchange, &mut spans);
    token_spans(s, &mut spans);
    scheme_spans(s, &mut spans);
    assignment_spans(s, inputs, exchange, &mut spans);
    if spans.is_empty() {
        return Masking::Clean;
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (a, b) in spans {
        match merged.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    let trimmed_start = s.len() - s.trim_start().len();
    let trimmed_end = s.trim_end().len();
    if merged.len() == 1 && merged[0].0 <= trimmed_start && merged[0].1 >= trimmed_end {
        return Masking::Whole;
    }
    let mut out = String::with_capacity(s.len());
    let mut at = 0;
    for (a, b) in merged {
        out.push_str(&s[at..a]);
        out.push_str(MASK);
        at = b;
    }
    out.push_str(&s[at..]);
    Masking::Parts(out)
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '+' | '=')
}

fn is_jwt_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '=')
}

fn is_b64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '+' | '=')
}

fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// Byte offsets where a word may begin: the start, or after a character that is not alphanumeric.
fn boundaries(s: &str) -> impl Iterator<Item = usize> + '_ {
    let mut prev: Option<char> = None;
    s.char_indices().filter_map(move |(i, c)| {
        let at = prev.is_none_or(|p| !p.is_alphanumeric());
        prev = Some(c);
        at.then_some(i)
    })
}

fn run_end(s: &str, from: usize, allowed: impl Fn(char) -> bool) -> usize {
    s[from..].char_indices().find(|&(_, c)| !allowed(c)).map_or(s.len(), |(i, _)| from + i)
}

/// [`run_end`] that remembers the last run it measured, so every start inside one run costs nothing
/// and the scan over a string stays linear however many word starts it holds (`a.a.a.`, `sk-sk-`).
struct Runs<F: Fn(char) -> bool> {
    allowed: F,
    start: usize,
    end: usize,
}

impl<F: Fn(char) -> bool> Runs<F> {
    fn new(allowed: F) -> Self {
        Runs { allowed, start: 0, end: 0 }
    }

    fn end_from(&mut self, s: &str, from: usize) -> usize {
        if from >= self.start && from < self.end {
            return self.end;
        }
        let end = run_end(s, from, &self.allowed);
        self.start = from;
        self.end = end;
        end
    }
}

fn pem_spans(s: &str, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(i) = s[from..].find("-----BEGIN") {
        let start = from + i;
        let Some(j) = s[start..].find("-----END") else {
            spans.push((start, s.len()));
            return;
        };
        let after = start + j + "-----END".len();
        let end = s[after..].find("-----").map_or(s.len(), |k| after + k + 5);
        spans.push((start, end));
        from = end;
    }
}

const TOKEN_PREFIXES: &[(&str, usize)] = &[
    ("sk_live_", 8), ("sk_test_", 8), ("rk_live_", 8), ("rk_test_", 8), ("whsec_", 8), ("ghp_", 16),
    ("gho_", 16), ("ghu_", 16), ("ghs_", 16), ("ghr_", 16), ("github_pat_", 16), ("glpat-", 12),
    ("xoxa-", 8), ("xoxb-", 8), ("xoxp-", 8), ("xoxr-", 8), ("xoxe-", 8), ("xapp-", 8), ("sk-ant-", 8),
    ("sk-proj-", 8), ("sk-", 20), ("pdl_live_apikey_", 8), ("pdl_sdbx_apikey_", 8), ("npm_", 16),
    ("shpat_", 16), ("shpss_", 16), ("shpca_", 16), ("lin_api_", 16), ("AIza", 30), ("ya29.", 8),
    ("hf_", 16), ("SG.", 16), ("dop_v1_", 16), ("AGE-SECRET-KEY-1", 8), ("glsa_", 16), ("pat-na1-", 16),
    // An OpenSSH private key body: base64 of "openssh-key-v1".
    ("b3BlbnNzaC1rZXktdjE", 0),
];

fn token_spans(s: &str, spans: &mut Vec<(usize, usize)>) {
    let bytes = s.as_bytes();
    let mut tokens = Runs::new(is_token_char);
    let mut jwts = Runs::new(is_jwt_char);
    let mut dots: Option<Vec<u32>> = None;
    let mut b64_until = 0;
    for i in boundaries(s) {
        let first = bytes[i];
        if matches!(first, b's' | b'r' | b'w' | b'g' | b'x' | b'p' | b'n' | b'l' | b'A' | b'y' | b'h' | b'S' | b'd' | b'b') {
            let rest = &s[i..];
            for &(prefix, min_tail) in TOKEN_PREFIXES {
                if rest.starts_with(prefix) {
                    let from = i + prefix.len();
                    let end = tokens.end_from(s, from);
                    if end - from >= min_tail {
                        spans.push((i, end));
                    }
                }
            }
            if rest.starts_with("AKIA") || rest.starts_with("ASIA") {
                let id = bytes.get(i + 4..i + 20);
                let after = bytes.get(i + 20).copied();
                if id.is_some_and(|b| b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()))
                    && !after.is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                {
                    spans.push((i, i + 20));
                }
            }
        }
        if first == b'e' && s[i..].starts_with("eyJ") {
            let end = jwts.end_from(s, i);
            let counts = dots.get_or_insert_with(|| {
                let mut v = Vec::with_capacity(bytes.len() + 1);
                v.push(0u32);
                for b in bytes {
                    v.push(v[v.len() - 1] + u32::from(*b == b'.'));
                }
                v
            });
            let n = counts[end] - counts[i];
            if (n == 2 || n == 4) && end - i >= 20 {
                spans.push((i, end));
            }
        }
        if i >= b64_until && (i == 0 || !s[..i].chars().next_back().is_some_and(is_b64_char)) {
            let end = run_end(s, i, is_b64_char);
            b64_until = end;
            let run = &s[i..end];
            let core = run.trim_end_matches('=');
            let aws_secret = core.len() == 40
                && core.bytes().any(|c| c.is_ascii_uppercase())
                && core.bytes().any(|c| c.is_ascii_lowercase())
                && core.bytes().any(|c| c.is_ascii_digit())
                && !core.bytes().all(|c| c.is_ascii_hexdigit());
            if aws_secret || (run.starts_with("MII") && run.len() >= 48) {
                spans.push((i, end));
            }
        }
    }
}

fn scheme_spans(s: &str, spans: &mut Vec<(usize, usize)>) {
    const BARE: &[&str] = &["bearer", "basic", "token", "negotiate", "ntlm", "ssws", "apikey", "sharedkey"];
    const PARAM: &[&str] = &["digest", "aws4-hmac-sha256", "hmac", "signature"];
    let lower = s.to_ascii_lowercase();
    let mut covered = 0;
    for i in boundaries(s) {
        if i < covered || !matches!(lower.as_bytes()[i], b'b' | b't' | b'n' | b's' | b'a' | b'd' | b'h') || s[..i].ends_with('-') {
            continue;
        }
        for (schemes, param) in [(BARE, false), (PARAM, true)] {
            for scheme in schemes {
                if !lower[i..].starts_with(scheme) || !s[i + scheme.len()..].starts_with(' ') {
                    continue;
                }
                let after = i + scheme.len();
                let cred = run_end(s, after, |c| c == ' ');
                let end = if param {
                    let first = run_end(s, cred, |c| !c.is_whitespace() && c != ',');
                    if !s[cred..first].contains('=') {
                        continue;
                    }
                    run_end(s, cred, |c| !matches!(c, '\n' | '\r' | '\''))
                } else {
                    let end = run_end(s, cred, |c| !c.is_whitespace() && !matches!(c, '"' | '\'' | ',' | ';'));
                    let cred_text = &s[cred..end];
                    let looks = cred_text.len() >= 8
                        && (cred_text.len() >= 20
                            || cred_text.chars().any(|c| c.is_ascii_digit() || matches!(c, '+' | '/' | '=' | '_' | '-' | '.')));
                    if !looks {
                        continue;
                    }
                    end
                };
                spans.push((i, end));
                covered = covered.max(end);
            }
        }
    }
}

/// Whether `s` assigns one of the parameters that make an OAuth token exchange (`grant_type=`,
/// `"redirect_uri": …`, `code_verifier=`), so a bare `code` assigned in it is the grant. Naming one in
/// prose is not assigning it.
fn assigns_oauth_exchange(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    OAUTH_EXCHANGE.iter().any(|name| {
        lower.match_indices(name).any(|(at, _)| {
            let starts = lower[..at].chars().next_back().is_none_or(|c| !is_name_char(c));
            let rest = lower[at + name.len()..].trim_start_matches(['"', '\'']).trim_start_matches([' ', '\t']);
            starts && (rest.starts_with('=') || rest.starts_with(':'))
        })
    })
}

/// Longer than any credential's name: a run past it is not looked up, which is what keeps a string of
/// dotted words from costing a name lookup per word.
const MAX_ASSIGNED_NAME: usize = 64;

/// `name=value`, `name: value`, `"name":"value"`, SQL's `PASSWORD 'value'` and the command-line
/// `--password value`, masked when the name is a secret's, or is `code` in a string that assigns an
/// OAuth exchange's parameters.
fn assignment_spans(s: &str, inputs: &RenderInputs, exchange: bool, spans: &mut Vec<(usize, usize)>) {
    let mut names = Runs::new(is_name_char);
    let mut covered = 0;
    for i in boundaries(s) {
        if i < covered || !s[i..].chars().next().is_some_and(is_name_char) {
            continue;
        }
        let mut name_end = names.end_from(s, i);
        // A bracketed form name (`card[cvc]`, `user[password]`) is judged whole, as a URL query's is; bounded by the
        // name length so a long run of subscripts costs no more than one name.
        while s[name_end..].starts_with('[') && name_end - i <= MAX_ASSIGNED_NAME {
            let inner_end = run_end(s, name_end + 1, is_name_char);
            if inner_end > name_end + 1 && s[inner_end..].starts_with(']') {
                name_end = inner_end + 1;
            } else {
                break;
            }
        }
        if name_end - i > MAX_ASSIGNED_NAME {
            continue;
        }
        let name = &s[i..name_end];
        let lower = name.to_lowercase();
        let rule = name_rule(name);
        // The grant is a bare `code`, so not the end of `country_code` or `status_code`.
        let grant = exchange && lower == "code" && s[..i].chars().next_back().is_none_or(|c| !is_name_char(c));
        if !inputs.names.contains(&lower) && rule == NameRule::Plain && !grant {
            continue;
        }
        let flag = s[..i].ends_with("--");
        let mut at = name_end;
        if s[at..].starts_with('"') || s[at..].starts_with('\'') {
            at += 1;
        }
        let gap_end = run_end(s, at, |c| c == ' ' || c == '\t');
        let (sep_end, quoted_only) = match s[gap_end..].chars().next() {
            Some('=') | Some(':') => (gap_end + 1, false),
            Some('\'') | Some('"') if gap_end > at => (gap_end, true),
            Some(c) if flag && gap_end > at && c != '-' => (gap_end, false),
            _ => continue,
        };
        if s[sep_end..].starts_with("//") {
            continue;
        }
        let value_start = run_end(s, sep_end, |c| c == ' ' || c == '\t');
        let header_like = lower.contains("authorization") || lower.contains("cookie");
        let (start, end) = match s[value_start..].chars().next() {
            Some(q @ ('"' | '\'')) => {
                let body = value_start + 1;
                (body, s[body..].find(q).map_or(s.len(), |k| body + k))
            }
            Some(_) if quoted_only => continue,
            Some(_) if header_like => (value_start, run_end(s, value_start, |c| !matches!(c, '\n' | '\r' | '"' | '\''))),
            Some(_) => (value_start, run_end(s, value_start, |c| !c.is_whitespace() && !matches!(c, ';' | '&' | ',' | '}' | ')' | '"' | '\'' | '<' | '#'))),
            None => continue,
        };
        let value = &s[start..end];
        if value.is_empty() || matches!(value, "null" | "true" | "false") {
            continue;
        }
        if rule == NameRule::SecretUnlessNumber && value.parse::<f64>().is_ok() {
            continue;
        }
        spans.push((start, end));
        covered = covered.max(end);
    }
}

const URL_SECRET_PARAMS: &[&str] = &[
    "key", "sig", "signature", "x-amz-signature", "x-amz-credential", "x-amz-security-token",
    "x-goog-signature", "x-goog-credential",
];

fn url_spans(s: &str, inputs: &RenderInputs, exchange: bool, spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(k) = s[from..].find("://") {
        let sep = from + k;
        let scheme_start = s[..sep]
            .char_indices()
            .rev()
            .take_while(|&(_, c)| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
            .last()
            .map_or(sep, |(i, _)| i);
        let authority_start = sep + 3;
        let end = run_end(s, authority_start, |c| !c.is_whitespace() && !matches!(c, '"' | '\'' | '<' | '>' | '`'));
        from = end.max(authority_start);
        if scheme_start == sep {
            continue;
        }
        let authority_end = s[authority_start..end].find(['/', '?', '#']).map_or(end, |j| authority_start + j);
        let authority = &s[authority_start..authority_end];
        let host_start = match authority.rfind('@') {
            Some(at) => {
                let userinfo = &authority[..at];
                if let Some(colon) = userinfo.find(':') {
                    spans.push((authority_start + colon + 1, authority_start + at));
                }
                authority_start + at + 1
            }
            None => authority_start,
        };
        let host = s[host_start..authority_end].split(':').next().unwrap_or("").to_ascii_lowercase();
        let path = &s[authority_end..end];
        if is_webhook(&host, path) && authority_end < end {
            spans.push((authority_end + usize::from(path.starts_with('/')), end));
            continue;
        }
        if let Some(q) = path.find(['?', '#']) {
            let mut at = authority_end + q + 1;
            for part in s[at..end].split(['&', '#', '?', ';']) {
                if let Some(eq) = part.find('=') {
                    // Judged in its own case, so `sellToken` reads as two words as it does as a key.
                    let spelled = part[..eq].replace("%5f", "_").replace("%5F", "_").replace("%2d", "-").replace("%2D", "-");
                    let name = spelled.to_ascii_lowercase();
                    if !part[eq + 1..].is_empty()
                        && (URL_SECRET_PARAMS.contains(&name.as_str())
                            || inputs.names.contains(&name)
                            || name_rule(&spelled) != NameRule::Plain
                            || (exchange && name == "code"))
                    {
                        spans.push((at + eq + 1, at + part.len()));
                    }
                }
                at += part.len() + 1;
            }
        }
        if s[authority_end..end].starts_with("/bot") && host == "api.telegram.org" {
            spans.push((authority_end + 4, end));
        }
    }
}

fn is_webhook(host: &str, path: &str) -> bool {
    match host {
        "hooks.slack.com" | "hooks.zapier.com" => true,
        "discord.com" | "discordapp.com" | "ptb.discord.com" | "canary.discord.com" => path.starts_with("/api/webhooks"),
        "outlook.office.com" | "outlook.office365.com" => path.starts_with("/webhook"),
        "maker.ifttt.com" => path.starts_with("/trigger"),
        h => h.ends_with(".webhook.office.com"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rows_with(inputs: &RenderInputs, params: Value) -> Vec<(String, &'static str, String)> {
        render("permaura.policy.write", &params, inputs, COMPACT).rows.into_iter().map(|r| (r.path, r.state.as_str(), r.value)).collect()
    }

    fn rows(params: Value) -> Vec<(String, &'static str, String)> {
        rows_with(&RenderInputs::defaults(), params)
    }

    fn full_rows(params: Value) -> Rendered {
        render("permaura.policy.write", &params, &RenderInputs::defaults(), FULL)
    }

    fn row(path: &str, state: &'static str, value: &str) -> (String, &'static str, String) {
        (path.to_string(), state, value.to_string())
    }

    fn state_of(params: Value, path: &str) -> &'static str {
        rows(params).into_iter().find(|r| r.0 == path).map(|r| r.1).unwrap_or("absent")
    }

    fn value_of(params: Value, path: &str) -> String {
        rows(params).into_iter().find(|r| r.0 == path).map(|r| r.2).unwrap_or_default()
    }

    /// The agent's reason says one thing and the parameters another, and
    /// the parameter the approver must see is shown exactly.
    #[test]
    fn a_paddle_cancellation_shows_when_it_takes_effect() {
        assert_eq!(
            rows(json!({ "subscription_id": "sub_01h8", "effective_from": "immediately" })),
            vec![row("effective_from", "shown", "\"immediately\""), row("subscription_id", "shown", "\"sub_01h8\"")]
        );
    }

    /// A payout's destination is what the human approving it has to check, so a bank account it pays shows enough to recognise (an IBAN's country and check digits and its last four, an account number's last four) and the payee's name in full, while a secret in the same call stays hidden.
    #[test]
    fn a_payout_shows_where_the_money_goes_and_still_hides_secrets() {
        let params = json!({
            "amount": 250000,
            "currency": "eur",
            "destination": { "account_holder_name": "Acme Supplies Ltd", "iban": "DE89 3704 0044 0532 0130 00", "bic": "COBADEFFXXX" },
            "bank_account": { "account_number": "000123456789", "routing_number": "110000000", "sort_code": "40-47-84" },
            "client_secret": "pi_fixture_secret_value",
            "card": { "number": "4242424242424242", "cvc": "123" },
        });
        let shown: Vec<_> = render("acme_pay.payouts.create", &params, &RenderInputs::defaults(), FULL)
            .rows
            .into_iter()
            .map(|r| (r.path, r.state.as_str(), r.value))
            .collect();
        for expected in [
            row("destination.iban", "masked", "\"DE89[redacted]3000\""),
            row("bank_account.account_number", "masked", "\"[redacted]6789\""),
            row("destination.account_holder_name", "shown", "\"Acme Supplies Ltd\""),
            row("destination.bic", "shown", "\"COBADEFFXXX\""),
            row("bank_account.routing_number", "shown", "\"110000000\""),
            row("bank_account.sort_code", "shown", "\"40-47-84\""),
            row("client_secret", "redacted", "set, 23 characters"),
            row("card.number", "redacted", "set, 16 characters"),
            row("card.cvc", "redacted", "set, 3 characters"),
        ] {
            assert!(shown.contains(&expected), "{expected:?} not in {shown:?}");
        }
        assert_eq!(state_of(json!({ "accountNumber": 12345678 }), "accountNumber"), "masked", "a number is an account number too");
        assert_eq!(value_of(json!({ "accountNumber": 12345678 }), "accountNumber"), "\"[redacted]5678\"");
    }

    /// Only a value shaped like an account identifier is shown in part; anything else under the name stays redacted, as does a name the call itself redacts, a name/value pair and a mention inside a string.
    #[test]
    fn a_payee_account_name_reveals_nothing_of_a_value_that_is_not_an_account() {
        for odd in ["sk_live_fixture_value_0000", "1234", "GB29 NWBK 6016 1331 9268 1\u{200b}9", "DE89-3704-0044-0532-0130-00-but-longer-than-any-iban"] {
            assert_eq!(state_of(json!({ "iban": odd, "account_number": odd }), "iban"), "redacted", "{odd}");
            assert_eq!(state_of(json!({ "iban": odd, "account_number": odd }), "account_number"), "redacted", "{odd}");
        }
        let inputs = RenderInputs::new(["iban".to_string()], None);
        assert_eq!(rows_with(&inputs, json!({ "iban": "DE89370400440532013000" }))[0].1, "redacted", "the call's own redaction wins");
        assert_eq!(
            state_of(json!({ "fields": [{ "name": "iban", "value": "DE89370400440532013000" }] }), "fields[0].value"),
            "redacted"
        );
        assert!(!value_of(json!({ "note": "iban=DE89370400440532013000" }), "note").contains("DE89370400440532013000"));
        assert_eq!(state_of(json!({ "card": { "pan": "4242424242424242" } }), "card.pan"), "redacted");
    }

    #[test]
    fn scalars_and_nesting_render_with_their_paths() {
        assert_eq!(
            rows(json!({ "amount": 4000, "live": true, "note": null, "items": [{ "price_id": "pri_1", "qty": 2 }], "meta": {}, "tags": [] })),
            vec![
                row("amount", "shown", "4000"),
                row("items[0].price_id", "shown", "\"pri_1\""),
                row("items[0].qty", "shown", "2"),
                row("live", "shown", "true"),
                row("meta", "shown", "{}"),
                row("note", "shown", "null"),
                row("tags", "shown", "[]"),
            ]
        );
    }

    /// A control-plane hold stores the mutation verbatim, so a credential mutation that carries the
    /// new value must render with that value nowhere in it. The secret has no recognisable prefix, so
    /// only the sealed-kind rule stands between it and the screen.
    #[test]
    fn a_credential_mutation_never_renders_its_secret() {
        const SECRET: &str = "Zq8mWv3pLt6nRx1kYc4h";
        let held = json!({
            "kind": "credential_set",
            "connection_id": "conn_paddle",
            "value": SECRET,
            "material": { "seed": SECRET },
            "material_id": { "raw": SECRET },
            "note": SECRET,
        });
        for limits in [COMPACT, FULL] {
            let text = serde_json::to_string(&render("permaura.policy.write", &held, &RenderInputs::defaults(), limits).rows).unwrap();
            assert!(!text.contains(SECRET) && !text.contains("Zq8mWv3p"), "{text}");
        }
        assert_eq!(
            rows(held),
            vec![
                row("connection_id", "shown", "\"conn_paddle\""),
                row("kind", "shown", "\"credential_set\""),
                row("material", "redacted", &format!("set, {} characters", json!({ "seed": SECRET }).to_string().len())),
                row("material_id", "redacted", &format!("set, {} characters", json!({ "raw": SECRET }).to_string().len())),
                row("note", "redacted", "set, 20 characters"),
                row("value", "redacted", "set, 20 characters"),
            ]
        );
        assert_eq!(
            rows(json!({ "kind": "credential_promote", "connection_id": "conn_paddle", "secret_id": "sec_conn_paddle", "staging_secret_id": "sec_staging_ab12", "value": SECRET })),
            vec![
                row("connection_id", "shown", "\"conn_paddle\""),
                row("kind", "shown", "\"credential_promote\""),
                row("secret_id", "shown", "\"sec_conn_paddle\""),
                row("staging_secret_id", "shown", "\"sec_staging_ab12\""),
                row("value", "redacted", "set, 20 characters"),
            ]
        );
        let agent = render("vault.write", &json!({ "kind": "credential_set", "amount": 5 }), &RenderInputs::defaults(), COMPACT);
        assert!(agent.rows.iter().any(|r| r.path == "amount" && r.value == "5"), "an agent's own kind blanks nothing");
    }

    #[test]
    fn every_real_mutation_kind_renders_without_losing_what_the_approver_must_check() {
        use crate::policy_guard::{ConnPatch, Mutation, SshPatch};
        let trust = serde_json::to_value(Mutation::ApproverKeyTrust {
            approver_id: "device:watch".into(),
            approver_pubkey: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=".into(),
            person: None,
            replaces: None,
        })
        .unwrap();
        assert!(rows(trust).contains(&row("approver_pubkey", "shown", "\"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=\"")));
        let bound = serde_json::to_value(Mutation::ApproverKeyTrust {
            approver_id: "device:watch".into(),
            approver_pubkey: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=".into(),
            person: Some("user_sam".into()),
            replaces: None,
        })
        .unwrap();
        assert!(rows(bound).contains(&row("person", "shown", "\"user_sam\"")), "the co-signer signs over whose device it becomes");
        let repoint = serde_json::to_value(Mutation::ConnectionPatch {
            connection_id: "conn_box".into(),
            patch: ConnPatch {
                ssh: Some(SshPatch {
                    host: Some("10.0.0.9".into()),
                    host_key_sha256: Some("SHA256:abc".into()),
                    password_auth: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            },
        })
        .unwrap();
        let shown = rows(repoint);
        assert!(shown.contains(&row("patch.ssh.host_key_sha256", "shown", "\"SHA256:abc\"")), "{shown:?}");
        assert!(shown.contains(&row("patch.ssh.password_auth", "shown", "true")), "{shown:?}");
        assert!(shown.contains(&row("patch.ssh.host", "shown", "\"10.0.0.9\"")), "{shown:?}");
        let delete = serde_json::to_value(Mutation::SecretDelete { secret_id: "sec_github".into() }).unwrap();
        assert!(rows(delete).contains(&row("secret_id", "shown", "\"sec_github\"")));
        for kind in ["policy_upsert", "grant_upsert", "agent_upsert", "connection_patch", "approval_floor_set", "approver_key_revoke"] {
            assert_eq!(state_of(json!({ "kind": kind, "x_value": "visible" }), "x_value"), "shown", "{kind}");
        }
    }

    #[test]
    fn secret_bearing_names_are_redacted_and_the_names_of_secrets_are_not() {
        for key in [
            "password", "api_key", "apiKey", "X-Api-Key", "Authorization", "client_secret", "access_token",
            "refreshToken", "private_key", "privkey", "credentials", "pin", "otp", "otp_code", "session_cookie",
            "webhook_secret", "basic_auth", "card_number", "cvv2", "security_code", "iban", "account_number",
            "pan", "pass", "pw", "passcode", "passwort", "kennwort", "contraseña", "mot_de_passe", "пароль",
            "密码", "ｐａｓｓｗｏｒｄ", "mnemonic", "totp_seed", "recovery_codes", "backup_code", "database_url",
            "connection_string", "dsn",
        ] {
            assert_ne!(name_rule(key), NameRule::Plain, "{key} names a secret");
        }
        for key in [
            "secret_id", "key_id", "token_type", "max_tokens", "approver_pubkey", "public_key", "host_key_sha256",
            "fingerprint", "author", "oauth_scope", "keyword", "monkey", "effective_from", "amount",
            "secret_name", "key", "keys", "auth", "auth_mode", "token_amount", "routing_number", "passenger",
        ] {
            assert_eq!(name_rule(key), NameRule::Plain, "{key} does not hold a secret");
        }
        assert_eq!(name_rule("seed"), NameRule::SecretUnlessNumber);
        assert_eq!(state_of(json!({ "seed": 42 }), "seed"), "shown", "an image model's seed");
        assert_eq!(state_of(json!({ "seed": "abandon abandon about" }), "seed"), "redacted", "a wallet seed");
        assert_eq!(
            rows(json!({ "headers": { "Authorization": "x", "Accept": "application/json" }, "password": 12345, "remember": true, "key": "prod/database", "auth_mode": "none", "token_amount": 1000000 })),
            vec![
                row("auth_mode", "shown", "\"none\""),
                row("headers.Accept", "shown", "\"application/json\""),
                row("headers.Authorization", "redacted", "set, 1 character"),
                row("key", "shown", "\"prod/database\""),
                row("password", "redacted", "set, 5 characters"),
                row("remember", "shown", "true"),
                row("token_amount", "shown", "1000000"),
            ]
        );
    }

    #[test]
    fn the_calls_own_redaction_set_applies_including_dotted_paths() {
        let inputs = RenderInputs::new(permaura_core::effective_redact_keys(["email", "card.number"]), None);
        let r = rows_with(&inputs, json!({ "email": "a@b.example", "card": { "number": "4242" }, "invoice": { "number": "INV-1" } }));
        assert!(r.contains(&row("email", "redacted", "set, 11 characters")), "{r:?}");
        assert!(r.contains(&row("card.number", "redacted", "set, 4 characters")), "{r:?}");
        assert!(r.contains(&row("invoice.number", "shown", "\"INV-1\"")), "{r:?}");
    }

    #[test]
    fn the_value_beside_a_secret_name_in_pairs_is_redacted() {
        let r = rows(json!({
            "headers": [{ "name": "Authorization", "value": "token ghp_abcdefghijklmnopqrstuvwxyz0123" }, { "name": "Accept", "value": "text/plain" }],
            "env": [{ "name": "DB_PASSWORD", "value": "hunter2-prod-Pa55" }],
            "tuples": [["Authorization", "Token abcdefghijklmnop1234567890"], ["Accept", "text/plain"]],
        }));
        assert!(r.contains(&row("headers[0].value", "redacted", "set, 40 characters")), "{r:?}");
        assert!(r.contains(&row("headers[1].value", "shown", "\"text/plain\"")), "{r:?}");
        assert!(r.contains(&row("env[0].value", "redacted", "set, 17 characters")), "{r:?}");
        assert!(r.contains(&row("tuples[0][1]", "redacted", "set, 32 characters")), "{r:?}");
        assert!(r.contains(&row("tuples[1][1]", "shown", "\"text/plain\"")), "{r:?}");
    }

    #[test]
    fn urls_lose_their_passwords_and_secret_query_values() {
        assert_eq!(value_of(json!({ "url": "https://admin:hunter2@db.example.com/x" }), "url"), "\"https://admin:[redacted]@db.example.com/x\"");
        assert_eq!(
            value_of(json!({ "url": "https://api.example.com/v1/x?access_token=ya29.a0AfH6SMBxQ1&api_key=AbCdEf123&page=2&sig=abc" }), "url"),
            "\"https://api.example.com/v1/x?access_token=[redacted]&api_key=[redacted]&page=2&sig=[redacted]\""
        );
        assert_eq!(value_of(json!({ "u": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" }), "u"), "\"https://hooks.slack.com/[redacted]\"");
        assert_eq!(state_of(json!({ "u": "https://hooks.slack.com/services/T0/B0/XYZ" }), "u"), "masked");
        assert_eq!(value_of(json!({ "u": "mysql://root:toor@10.0.0.1/app" }), "u"), "\"mysql://root:[redacted]@10.0.0.1/app\"");
        assert_eq!(value_of(json!({ "u": "mongodb+srv://app:S3cret@cluster0.example.net/db" }), "u"), "\"mongodb+srv://app:[redacted]@cluster0.example.net/db\"");
        assert_eq!(value_of(json!({ "c": "Server=x;User Id=sa;Password=Hunter2!;" }), "c"), "\"Server=x;User Id=sa;Password=[redacted];\"");
        assert_eq!(value_of(json!({ "u": "https://api.stripe.com/v1/refunds?limit=3" }), "u"), "\"https://api.stripe.com/v1/refunds?limit=3\"");
    }

    #[test]
    fn credentials_inside_free_text_are_masked() {
        assert_eq!(value_of(json!({ "command": "PGPASSWORD=hunter2 psql -h db -U admin" }), "command"), "\"PGPASSWORD=[redacted] psql -h db -U admin\"");
        assert_eq!(value_of(json!({ "query": "ALTER USER admin WITH PASSWORD 'hunter2'" }), "query"), "\"ALTER USER admin WITH PASSWORD '[redacted]'\"");
        assert_eq!(value_of(json!({ "body": "{\"password\":\"hunter2\",\"user\":\"a\"}" }), "body"), "\"{\\\"password\\\":\\\"[redacted]\\\",\\\"user\\\":\\\"a\\\"}\"");
        let curl = value_of(json!({ "curl": "curl -H 'Authorization: Bearer sk_live_abcdefghijklmnop' https://x" }), "curl");
        assert!(!curl.contains("sk_live_abcdefghijklmnop") && curl.contains("[redacted]"), "{curl}");
        let mixed = value_of(json!({ "note": "deploy with ghp_abcdefghijklmnopqrstuvwxyz0123 then ping" }), "note");
        assert_eq!(mixed, "\"deploy with [redacted] then ping\"");
    }

    #[test]
    fn a_value_shaped_like_a_credential_is_redacted_under_any_name() {
        for value in [
            "sk_live_51Hx0000000000000000", "ghp_0123456789abcdefghij", "Bearer sometoken123", "Token abcdef0123456789abcdef",
            "Digest username=\"a\", response=\"6629fae49393a05397450978507c4ef1\"", "AWS4-HMAC-SHA256 Credential=AKIA/20250101, Signature=abcdef",
            "-----BEGIN PRIVATE KEY-----\nMIIE", "\n-----BEGIN RSA PRIVATE KEY-----\nMII",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlX2hlcmU", "eyJhbGciOiJSU0EtT0FFUCJ9.aaaa.bbbb.cccc.dddd",
            " eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "xoxb-1234-5678-abcdefgh", "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "ya29.a0AfH6SMBxQ1xyzxyzxyzxyz", "hf_abcdefghijklmnopqrstuvwxyzABCD",
            "SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEFGHIJ", "dop_v1_0123456789abcdef0123456789abcdef",
            "sk-ant-api03-abcdefghijklmnop", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQ",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7aaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(state_of(json!({ "note": value }), "note"), "redacted", "{value}");
        }
        for value in [
            "immediately", "sk-", "end of billing period", "eyJ only", "pri_01h8x", "Basic plan upgrade",
            "Token is required", "0123456789abcdef0123456789abcdef01234567", "https://example.com/key/value",
        ] {
            assert_eq!(state_of(json!({ "note": value }), "note"), "shown", "{value}");
        }
    }

    #[test]
    fn long_strings_are_cut_in_the_compact_rendering_and_whole_in_the_full_one() {
        let long = "a".repeat(5000);
        let r = rows(json!({ "body": long.clone() }));
        assert_eq!(r[0].1, "truncated");
        assert_eq!(r[0].2, format!("\"{}…\" (5000 characters)", "a".repeat(MAX_VALUE_CHARS)));
        let full = full_rows(json!({ "body": long.clone() }));
        assert!(full.complete());
        assert_eq!(full.rows[0].value, format!("\"{long}\""));
        let sql = format!("SELECT id FROM users WHERE id = 1 /* {} */; DROP TABLE users;", "x".repeat(100));
        assert_eq!(rows(json!({ "query": sql.clone() }))[0].1, "truncated");
        assert!(full_rows(json!({ "query": sql })).rows[0].value.contains("DROP TABLE users"));
        let url = format!("https://api.stripe.com{}@evil.example/v1/refunds", "%2Fv1%2Frefunds".repeat(8));
        assert!(full_rows(json!({ "url": url })).rows[0].value.contains("@evil.example"));
    }

    #[test]
    fn deep_structures_collapse_in_the_compact_rendering_and_open_in_the_full_one() {
        let deep = json!({ "body": { "data": { "attributes": { "price": { "unit_amount": 99999900 } } } } });
        assert_eq!(rows(deep.clone()), vec![row("body.data.attributes.price", "collapsed", "{1 field}")]);
        let full = full_rows(deep);
        assert!(full.complete());
        assert_eq!(full.rows[0].path, "body.data.attributes.price.unit_amount");
        assert_eq!(full.rows[0].value, "99999900");
    }

    #[test]
    fn rows_past_the_cap_are_counted_and_the_full_rendering_lists_them() {
        let mut m = Map::new();
        for i in 0..32 {
            m.insert(format!("A{i:02}"), json!("x"));
        }
        m.insert("effective_from".into(), json!("immediately"));
        let padded = Value::Object(m);
        let compact = render("http.request", &padded, &RenderInputs::defaults(), COMPACT);
        assert_eq!((compact.rows.len(), compact.omitted), (MAX_ROWS, 1));
        assert!(!compact.complete());
        assert!(!compact.rows.iter().any(|r| r.path == "effective_from"), "pushed off the card");
        let full = render("http.request", &padded, &RenderInputs::defaults(), FULL);
        assert!(full.complete());
        assert!(full.rows.iter().any(|r| r.path == "effective_from" && r.value == "\"immediately\""), "and never out of the full rendering");
    }

    #[test]
    fn a_policy_upsert_that_empties_device_signed_is_shown_whole() {
        let allow: Vec<String> = (0..34).map(|i| format!("paddle.read_{i:02}")).collect();
        let held = json!({ "kind": "policy_upsert", "grant_ids": null, "policy": {
            "id": "pol_paddle", "connection_id": "paddle_live", "name": "Paddle", "allow": allow,
            "deny": [], "requires_approval": [], "notify": [], "device_signed": [], "device_signed_quorum": 1 } });
        assert!(!render("permaura.policy.write", &held, &RenderInputs::defaults(), COMPACT).complete());
        let full = render("permaura.policy.write", &held, &RenderInputs::defaults(), FULL);
        assert!(full.complete());
        for path in ["policy.device_signed", "policy.deny", "policy.requires_approval"] {
            assert!(full.rows.iter().any(|r| r.path == path && r.value == "[]"), "{path}");
        }
    }

    #[test]
    fn the_full_rendering_stops_at_its_ceiling_and_is_not_served_in_part() {
        let big: Vec<Value> = (0..200_000).map(|i| json!({ "k": i, "s": "abcdefghij".repeat(5) })).collect();
        let started = std::time::Instant::now();
        let full = render("http.request", &json!({ "items": big }), &RenderInputs::defaults(), FULL);
        assert!(full.too_large && full.rows.is_empty() && !full.complete());
        assert!(full.size > FULL_CEILING_BYTES);
        let one_string = render("http.request", &json!({ "blob": "x".repeat(3 * FULL_CEILING_BYTES) }), &RenderInputs::defaults(), FULL);
        assert!(one_string.too_large);
        let body = format!("[{}0]", "0,".repeat(1_048_000));
        let v: Value = serde_json::from_str(&format!("{{\"items\":{body}}}")).unwrap();
        let compact = render("http.request", &v, &RenderInputs::defaults(), COMPACT);
        assert_eq!(compact.rows.len(), MAX_ROWS);
        let _ = render("http.request", &v, &RenderInputs::defaults(), FULL);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "bounded: {:?}", started.elapsed());
    }

    #[test]
    fn only_the_parameters_a_pinned_shape_forwards_are_rendered() {
        let forwarded: BTreeSet<String> = ["subscription_id", "effective_from"].into_iter().map(String::from).collect();
        let inputs = RenderInputs::new(permaura_core::default_redact_keys(), Some(forwarded));
        let mut m = Map::new();
        for i in 0..40 {
            m.insert(format!("A{i:02}"), json!("padding"));
        }
        m.insert("effective_from".into(), json!("immediately"));
        m.insert("subscription_id".into(), json!("sub_01h8"));
        let r = render("paddle.subscriptions.cancel", &Value::Object(m), &inputs, COMPACT);
        assert!(r.complete());
        assert_eq!(r.rows.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(), vec!["effective_from", "subscription_id"]);
    }

    #[test]
    fn invisible_direction_changing_and_lookalike_characters_are_spelled_out() {
        let r = rows(json!({ "effective_from": "immediately\u{202E}doirep_gnillib", "note": "a\u{200B}b\nc\"d" }));
        assert_eq!(r[0].2, "\"immediately\\u{202e}doirep_gnillib\"");
        assert_eq!(r[1].2, "\"a\\u{200b}b\\nc\\\"d\"");
        let r = rows(json!({ "amount\u{200B}": 1, "a b": 2 }));
        assert_eq!(r[0].0, "[\"a b\"]");
        assert_eq!(r[1].0, "[\"amount\\u{200b}\"]");
        assert_eq!(value_of(json!({ "to": "pаypal.com" }), "to"), "\"p\\u{0430}ypal.com\"");
        assert_eq!(value_of(json!({ "to": "Ελλάδα" }), "to"), "\"Ελλάδα\"", "a Greek word on its own is left alone");
        assert_eq!(value_of(json!({ "x": "immediately\u{0336}\u{0336}" }), "x"), "\"immediately\\u{0336}\\u{0336}\"");
        assert_eq!(value_of(json!({ "y": "\u{2800}" }), "y"), "\"\\u{2800}\"");
        assert_eq!(value_of(json!({ "z": "a\u{3000}b" }), "z"), "\"a\\u{3000}b\"");
        assert_eq!(value_of(json!({ "u": "a\u{FFFC}b" }), "u"), "\"a\\u{fffc}b\"");
        assert_eq!(value_of(json!({ "v": "line\u{0085}two" }), "v"), "\"line\\u{0085}two\"");
        assert_eq!(value_of(json!({ "w": "Café 東京 🚀" }), "w"), "\"Café 東京 🚀\"");
        assert_eq!(escape("Approve 'x' on 'y'?\u{202e}", false), "Approve 'x' on 'y'?\\u{202e}");
        assert_eq!(escape("a\\u{202e}", false), "a\\\\u{202e}", "a literal escape cannot pass for a real one");
    }

    #[test]
    fn a_huge_key_is_cut_in_the_compact_path_and_marks_the_row() {
        let key = "k".repeat(500);
        let r = rows(json!({ key.clone(): 1 }));
        assert_eq!(r[0].0, format!("[\"{}…\"]", "k".repeat(MAX_KEY_CHARS)));
        assert_eq!(r[0].1, "truncated");
        assert_eq!(full_rows(json!({ key.clone(): 1 })).rows[0].path, key);
    }

    /// Adversarial strings for a scan that restarts at every word start: each one used to cost seconds at 16 KB and minutes at 64 KB.
    fn adversarial(unit: &str, bytes: usize) -> String {
        unit.repeat(bytes / unit.len())
    }

    const ADVERSARIAL: &[&str] = &["a.", "sk-", "eyJ.", "x=", "digest a=", "password=", "a.sk-eyJ.x=-----BEGIN ", "Bearer a1 "];

    fn mask_on_every_path(s: &str, inputs: &RenderInputs) {
        std::hint::black_box(mask(s, inputs));
        std::hint::black_box(render("http.request", &json!({ "v": s }), inputs, FULL));
        std::hint::black_box(render("http.request", &json!({ "v": s }), inputs, COMPACT));
        std::hint::black_box(stored_intent(s));
        std::hint::black_box(ServedText::of(&paddle(Some(s))));
    }

    fn timed(f: impl FnOnce()) -> std::time::Duration {
        let started = std::time::Instant::now();
        f();
        started.elapsed()
    }

    /// Compares equal work rather than a deadline: one 64 KiB string costs about what sixteen 4 KiB strings cost when masking is linear and far more when it is quadratic, and both runs last about as long, so a slow or loaded machine slows them alike.
    #[test]
    fn masking_is_linear_on_adversarial_strings() {
        let inputs = RenderInputs::defaults();
        for unit in ADVERSARIAL {
            let (small, large) = (adversarial(unit, 4 * 1024), adversarial(unit, 64 * 1024));
            let (mut sixteen_small, mut one_large) = (std::time::Duration::MAX, std::time::Duration::MAX);
            for _ in 0..3 {
                sixteen_small = sixteen_small.min(timed(|| (0..16).for_each(|_| mask_on_every_path(&small, &inputs))));
                one_large = one_large.min(timed(|| mask_on_every_path(&large, &inputs)));
            }
            assert!(one_large < sixteen_small * 4, "{unit:?}: one 64 KiB string took {one_large:?}, sixteen of 4 KiB {sixteen_small:?}");
        }
    }

    #[test]
    fn a_long_reason_is_kept_cut_and_masked_and_says_so() {
        let reason = format!("{} ghp_abcdefghijklmnopqrstuvwxyz0123 {}", "refund ".repeat(10), "z".repeat(10_000));
        let kept = stored_intent(&reason);
        assert!(kept.len() < MAX_STORED_INTENT_BYTES + 64, "{}", kept.len());
        assert!(kept.contains("[redacted]") && !kept.contains("ghp_abcdefghijklmnopqrstuvwxyz0123"));
        assert!(kept.ends_with(&format!("… (cut from {} characters)", reason.chars().count())), "{}", &kept[kept.len() - 60..]);
        assert_eq!(stored_intent("Cancel at period end."), "Cancel at period end.");
    }

    #[test]
    fn a_secret_longer_than_the_card_is_masked_whole_before_the_card_cuts_it() {
        let password = "P".repeat(1300);
        let url = format!("https://admin:{password}@db.example.com/x");
        assert_eq!(rows(json!({ "u": url })), vec![row("u", "masked", "\"https://admin:[redacted]@db.example.com/x\"")]);
        let jwt = format!("{} eyJhbGciOiJIUzI1NiJ9.eyJ{}.c2lnbmF0dXJl", "x".repeat(60), "A".repeat(1500));
        let card = rows(json!({ "t": jwt }));
        assert!(!card[0].2.contains("eyJhbGciOiJIUzI1NiJ9"), "{}", card[0].2);
        let secret_then_text = format!("sk_live_{}{}", "a".repeat(1200), " now refund everything");
        let card = rows(json!({ "w": secret_then_text.clone() }));
        let full = full_rows(json!({ "w": secret_then_text }));
        assert_eq!(card[0].1, full.rows[0].state.as_str(), "the card and the full rendering agree on what is secret");
    }

    #[test]
    fn the_second_round_names_and_pairs_are_redacted() {
        for key in [
            "recovery_phrase", "backup_phrase", "wallet_words", "secret_recovery_phrase", "session_id", "sessionid",
            "JSESSIONID", "PHPSESSID", "mfa_code", "oauth_code", "two_factor_code", "verification_code", "auth_code",
            "parola", "heslo", "clave", "mdp", "jelszo", "pword", "psw", "pin_code", "pincode", "ssh_private",
            "creds", "auth_header",
        ] {
            assert_ne!(name_rule(key), NameRule::Plain, "{key} names a secret");
        }
        assert_eq!(name_rule("tokens"), NameRule::SecretUnlessNumber);
        assert_eq!(state_of(json!({ "tokens": 5 }), "tokens"), "shown");
        assert_eq!(state_of(json!({ "card": { "number": "4242424242424242", "exp_month": 12 } }), "card.number"), "redacted");
        assert_eq!(state_of(json!({ "card": { "number": "4242424242424242", "exp_month": 12 } }), "card.exp_month"), "shown");
        assert_eq!(state_of(json!({ "source": { "object": "card", "number": "4000056655665556" } }), "source.number"), "redacted");
        assert_eq!(state_of(json!({ "invoice": { "number": "INV-1" } }), "invoice.number"), "shown");
        assert_eq!(state_of(json!({ "grant_type": "authorization_code", "code": "4/0AX4XfWh-oauth-code" }), "code"), "redacted");
        assert_eq!(state_of(json!({ "country": "AU", "code": "61" }), "code"), "shown", "a bare code elsewhere is not a grant");
        let r = rows(json!({ "headers": [{ "header_name": "Authorization", "header_value": "rawtoken0123456789abc" }, { "k": "password", "v": "hunter2" }] }));
        assert!(r.contains(&row("headers[0].header_value", "redacted", "set, 21 characters")), "{r:?}");
        assert!(r.contains(&row("headers[1].v", "redacted", "set, 7 characters")), "{r:?}");
        assert_eq!(value_of(json!({ "c": "psql --password hunter2 --host db" }), "c"), "\"psql --password [redacted] --host db\"");
        assert_eq!(value_of(json!({ "c": "gh auth login --token ghx_plain_value_1 --hostname x" }), "c"), "\"gh auth login --token [redacted] --hostname x\"");
        assert_eq!(state_of(json!({ "ssh_private": "b3BlbnNzaC1rZXktdjEAAAAA" }), "ssh_private"), "redacted");
        assert_eq!(state_of(json!({ "note": "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU" }), "note"), "redacted", "an OpenSSH key body by its shape");
        assert_eq!(state_of(json!({ "identity": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl" }), "identity"), "redacted");
    }

    #[test]
    fn armenian_lookalikes_math_letters_and_format_characters_are_spelled_out() {
        assert_eq!(value_of(json!({ "x": "g\u{0585}\u{0585}gle.com" }), "x"), "\"g\\u{0585}\\u{0585}gle.com\"");
        assert_eq!(value_of(json!({ "x": "\u{1D41E}vil" }), "x"), "\"\\u{1d41e}vil\"");
        assert_eq!(value_of(json!({ "x": "a\u{13430}b" }), "x"), "\"a\\u{13430}b\"");
        assert_eq!(value_of(json!({ "x": "a\u{1BCA0}b" }), "x"), "\"a\\u{1bca0}b\"");
        assert_eq!(value_of(json!({ "x": "Երևան" }), "x"), "\"Երևան\"", "an Armenian word on its own is left alone");
    }

    #[test]
    fn non_object_params_still_render() {
        assert_eq!(rows(json!(null)), vec![]);
        assert_eq!(rows(json!("hello")), vec![row("(params)", "shown", "\"hello\"")]);
        assert_eq!(rows(json!([1, "two"])), vec![row("[0]", "shown", "1"), row("[1]", "shown", "\"two\"")]);
    }

    fn paddle(intent: Option<&str>) -> PendingApproval {
        PendingApproval {
            id: "appr_1".into(),
            session_id: "sess_1".into(),
            capability: "paddle.subscriptions.cancel".into(),
            resource: "paddle_live".into(),
            message: "Approve 'subscriptions.cancel' on 'paddle_live'?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: json!({ "subscription_id": "sub_01h8", "effective_from": "immediately" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: 1,
            expires_at: None,
            risk: Some(permaura_core::RiskTier::High),
            action_description: Some("Cancel a subscription.".into()),
            intent: intent.map(str::to_string),
            required_tier: "device_signed".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        }
    }

    #[test]
    fn the_renderings_and_their_digests_are_stable_for_one_row() {
        let a = paddle(Some("Cancel at the end of the billing period."));
        let inputs = RenderInputs::defaults();
        assert_eq!(compact(&a, &inputs), compact(&a, &inputs));
        assert!(compact(&a, &inputs).complete);
        let digest = full_digest(&a, &inputs).unwrap();
        let mut other = a.clone();
        other.params = json!({ "subscription_id": "sub_01h8", "effective_from": "next_billing_period" }).into();
        assert_ne!(full_digest(&other, &inputs).unwrap(), digest, "different parameters, different digest");
        let text = ServedText::of(&a);
        let served = json!({
            "capability": text.capability, "resource": text.resource, "risk": text.risk,
            "action_description": text.action_description, "message": text.message, "intent": text.intent,
            "params_display": compact(&a, &inputs), "params_display_full": full(&a, &inputs),
        });
        assert_eq!(permaura_relay::approval_display_full_digest_of(&served), Ok(digest.clone()));
        assert_eq!(permaura_relay::approval_shown_full_digest(&served), Ok(digest));
    }

    #[test]
    fn the_agents_intent_is_escaped_masked_and_capped() {
        let text = ServedText::of(&paddle(Some("Cancel \u{202e}later with ghp_abcdefghijklmnopqrstuvwxyz0123")));
        assert_eq!(text.intent.as_deref(), Some("Cancel \\u{202e}later with [redacted]"));
        let long = ServedText::of(&paddle(Some(&"y".repeat(1000)))).intent.unwrap();
        assert_eq!(long, format!("{}… (1000 characters)", "y".repeat(MAX_INTENT_CHARS)));
        assert_eq!(ServedText::of(&paddle(Some("  "))).intent, None);
        assert_eq!(ServedText::of(&paddle(None)).intent, None);
    }

    #[test]
    fn a_token_suffixed_name_hides_a_number_and_only_a_plural_tokens_count_stays_visible() {
        for key in ["token", "otp_token", "mfa_token", "verification_token", "api_token", "sms_token", "authToken"] {
            assert_eq!(state_of(json!({ key: 482913 }), key), "redacted", "{key} holding a number");
            assert_eq!(state_of(json!({ key: "482913" }), key), "redacted", "{key} holding a string");
        }
        assert_eq!(state_of(json!({ "api_token": 90817263544536271u64 }), "api_token"), "redacted");
        for key in ["tokens", "max_tokens", "prompt_tokens", "completion_tokens", "token_count", "token_type"] {
            assert_eq!(state_of(json!({ key: 1024 }), key), "shown", "{key} counts tokens");
        }
        assert_eq!(state_of(json!({ "pair": ["otp_token", 482913] }), "pair[1]"), "redacted", "the two-item array form");
        assert_eq!(state_of(json!({ "fields": [{ "name": "otp_token", "value": 482913 }] }), "fields[0].value"), "redacted", "the name/value form");
        assert_eq!(value_of(json!({ "q": "otp_token=482913&user=a" }), "q"), "\"otp_token=[redacted]&user=a\"");
        assert_eq!(value_of(json!({ "q": "max_tokens=1024&user=a" }), "q"), "\"max_tokens=1024&user=a\"");
    }

    #[test]
    fn a_card_number_is_hidden_through_arrays_and_nesting() {
        let r = rows(json!({ "cards": [{ "number": "4242424242424242", "cvc": "123", "exp_month": 12 }] }));
        assert!(r.contains(&row("cards[0].number", "redacted", "set, 16 characters")), "{r:?}");
        assert!(r.contains(&row("cards[0].cvc", "redacted", "set, 3 characters")), "{r:?}");
        assert!(r.contains(&row("cards[0].exp_month", "shown", "12")), "{r:?}");
        assert_eq!(state_of(json!({ "card": { "details": { "number": "4242424242424242" } } }), "card.details.number"), "redacted");
        assert_eq!(state_of(json!({ "payment_method": { "card": { "number": "4242424242424242" } } }), "payment_method.card.number"), "redacted");
        assert_eq!(state_of(json!({ "cards": [[{ "number": "4242424242424242" }]] }), "cards[0][0].number"), "redacted");
        assert_eq!(state_of(json!({ "card": [{ "cvv": 123 }] }), "card[0].cvv"), "redacted");
        assert_eq!(state_of(json!({ "source": { "object": "card", "billing": { "number": "4000056655665556" } } }), "source.billing.number"), "redacted");
        assert_eq!(state_of(json!({ "card_details": { "number": 4242424242424242u64 } }), "card_details.number"), "redacted");
        assert_eq!(state_of(json!({ "invoices": [{ "number": "INV-1" }] }), "invoices[0].number"), "shown");
        assert_eq!(state_of(json!({ "discard": { "number": "INV-1" } }), "discard.number"), "shown", "a word that only contains card");
    }

    #[test]
    fn a_pkce_verifier_is_hidden_and_so_is_the_code_beside_it() {
        let exchange = json!({
            "grant_type": "authorization_code",
            "code": "SplxlOBeZQQYbYS6WxSbIA",
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "redirect_uri": "https://client.example.com/cb",
        });
        assert_eq!(state_of(exchange.clone(), "code"), "redacted");
        assert_eq!(state_of(exchange.clone(), "code_verifier"), "redacted");
        assert_eq!(state_of(exchange, "redirect_uri"), "shown");
        for key in ["code_verifier", "codeVerifier", "pkce_verifier"] {
            assert_eq!(state_of(json!({ key: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" }), key), "redacted", "{key} on its own");
        }
        assert_eq!(state_of(json!({ "code_verifier": "x", "code": "SplxlOBeZQQYbYS6WxSbIA" }), "code"), "redacted");
        assert_eq!(state_of(json!({ "verifier": "email" }), "verifier"), "shown", "a bare verifier is not PKCE's");
    }

    #[test]
    fn a_form_encoded_oauth_exchange_hides_its_code_and_verifier() {
        assert_eq!(
            value_of(json!({ "body": "grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&redirect_uri=https%3A%2F%2Fc.example%2Fcb" }), "body"),
            "\"grant_type=authorization_code&code=[redacted]&code_verifier=[redacted]&redirect_uri=https%3A%2F%2Fc.example%2Fcb\""
        );
        assert_eq!(
            value_of(json!({ "body": "code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fc.example%2Fcb&client_id=app" }), "body"),
            "\"code=[redacted]&redirect_uri=https%3A%2F%2Fc.example%2Fcb&client_id=app\"",
            "the code comes before the parameter that marks the exchange"
        );
        assert_eq!(
            value_of(json!({ "url": "https://provider.example/token?grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fc.example%2Fcb" }), "url"),
            "\"https://provider.example/token?grant_type=authorization_code&code=[redacted]&redirect_uri=https%3A%2F%2Fc.example%2Fcb\""
        );
        assert_eq!(
            value_of(json!({ "raw": "{\"grant_type\": \"authorization_code\", \"code\": \"SplxlOBeZQQYbYS6WxSbIA\"}" }), "raw"),
            "\"{\\\"grant_type\\\": \\\"authorization_code\\\", \\\"code\\\": \\\"[redacted]\\\"}\""
        );
        assert_eq!(value_of(json!({ "q": "country=AU&code=61" }), "q"), "\"country=AU&code=61\"", "a bare code elsewhere is not a grant");
        assert_eq!(value_of(json!({ "q": "see the grant_type docs, code=61" }), "q"), "\"see the grant_type docs, code=61\"", "naming a parameter is not sending it");
    }

    #[test]
    fn a_camel_case_card_container_hides_its_number_and_its_code() {
        for key in ["creditCard", "cardDetails", "paymentCard", "giftCard", "CreditCard"] {
            let r = rows(json!({ "input": { key: { "number": "4111111111111111", "expirationMonth": "12" } } }));
            assert!(r.contains(&row(&format!("input.{key}.number"), "redacted", "set, 16 characters")), "{key}: {r:?}");
            assert!(r.contains(&row(&format!("input.{key}.expirationMonth"), "shown", "\"12\"")), "{key}: {r:?}");
        }
        assert_eq!(state_of(json!({ "payment": { "creditCard": { "cardNumber": "4111111111111111", "cardCode": "123" } } }), "payment.creditCard.cardCode"), "redacted", "Authorize.net's CVV");
        assert_eq!(state_of(json!({ "source": { "type": "card", "number": "4242424242424242" } }), "source.number"), "redacted", "Checkout.com's card source");
        assert_eq!(state_of(json!({ "paymentMethod": { "type": "scheme", "number": "4111111111111111" } }), "paymentMethod.number"), "redacted", "Adyen's card scheme");
        assert_eq!(state_of(json!({ "creditor": { "number": "INV-1" } }), "creditor.number"), "shown", "a word that only starts like credit card");
    }

    #[test]
    fn the_exchange_code_rule_masks_only_a_bare_code_and_not_other_codes() {
        let text = "redirect_uri=https%3A%2F%2Fc.example%2Fcb&code=SplxlOBeZQQYbYS6WxSbIA&country_code=AU&currency_code=USD&postal_code=6000";
        assert_eq!(
            value_of(json!({ "q": text }), "q"),
            "\"redirect_uri=https%3A%2F%2Fc.example%2Fcb&code=[redacted]&country_code=AU&currency_code=USD&postal_code=6000\""
        );
        assert_eq!(
            value_of(json!({ "raw": "{\"redirect_uri\": \"x\", \"status_code\": 200, \"code\": \"abc12345\"}" }), "raw"),
            "\"{\\\"redirect_uri\\\": \\\"x\\\", \\\"status_code\\\": 200, \\\"code\\\": \\\"[redacted]\\\"}\""
        );
    }

    #[test]
    fn a_bracketed_form_name_is_judged_whole() {
        assert_eq!(
            value_of(json!({ "body": "card[number]=4111111111111111&card[cvc]=123&amount=1000" }), "body"),
            "\"card[number]=[redacted]&card[cvc]=[redacted]&amount=1000\""
        );
        assert_eq!(value_of(json!({ "body": "user[password]=hunter2&user[name]=ann" }), "body"), "\"user[password]=[redacted]&user[name]=ann\"");
        assert_eq!(value_of(json!({ "body": "customer[api_key]=abc123def&page=2" }), "body"), "\"customer[api_key]=[redacted]&page=2\"");
        assert_eq!(value_of(json!({ "body": "items[0][name]=pen&items[0][qty]=2" }), "body"), "\"items[0][name]=pen&items[0][qty]=2\"");
    }

    #[test]
    fn a_card_number_shape_is_hidden_under_a_card_name_or_inside_a_card() {
        for (params, path) in [
            (json!({ "card": "4242424242424242" }), "card"),
            (json!({ "ccnumber": "4111 1111 1111 1111" }), "ccnumber"),
            (json!({ "card_num": 4111111111111111u64 }), "card_num"),
            (json!({ "cc": "4111-1111-1111-1111" }), "cc"),
            (json!({ "card": { "details": { "value": "4000056655665556" } } }), "card.details.value"),
        ] {
            assert_eq!(state_of(params.clone(), path), "redacted", "{params}");
        }
        assert_eq!(state_of(json!({ "card": "4242424242424241" }), "card"), "shown", "a number that fails the Luhn check");
        assert_eq!(state_of(json!({ "imei": "490154203237518" }), "imei"), "shown", "a Luhn-valid number under a name that is not a card's");
        assert_eq!(state_of(json!({ "order": { "reference": "4242424242424242" } }), "order.reference"), "shown", "outside any card");
    }

    #[test]
    fn the_assets_a_swap_trades_stay_visible_and_other_token_names_do_not() {
        let r = rows(json!({ "sellToken": "USDC", "buyToken": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "sellAmount": "1000000", "sell_token": "DAI", "from_token": "ETH", "to_token": "USDT" }));
        for key in ["sellToken", "buyToken", "sell_token", "from_token", "to_token", "sellAmount"] {
            assert!(r.iter().any(|row| row.0 == key && row.1 == "shown"), "{key}: {r:?}");
        }
        assert_eq!(
            value_of(json!({ "url": "https://api.0x.org/swap/v1/quote?sellToken=USDC&buyToken=WETH&sellAmount=100" }), "url"),
            "\"https://api.0x.org/swap/v1/quote?sellToken=USDC&buyToken=WETH&sellAmount=100\""
        );
        for key in ["otp_token", "access_token", "auth_token", "bearer_token"] {
            assert_eq!(state_of(json!({ key: "a1b2c3d4" }), key), "redacted", "{key}");
        }
    }
}
