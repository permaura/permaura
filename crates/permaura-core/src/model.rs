//! Core domain model: principals, resources, actions, risk tiers, decisions and grants.
//!
//! These types are the shared vocabulary the policy engine, connectors, gateway, daemon and CLI all speak. They are all `serde`-serializable so they can cross the MCP / REST boundary unchanged, and the wire form uses `snake_case`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::PermauraError;

/// Who or what is asking, in the `principal` shape. The policy engine does not read
/// it (it keys on the agent id); it is carried as the relay frame's `SessionCtx` identity,
/// and `user`, `device` and `org` are present only when the caller knew them.
///
/// Serialized example: `{"user":"sam","agent":"codex-cli","device":"sam-macbook"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Principal {
    /// `user:<id>`: the human ultimately responsible for the session.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user: Option<String>,
    /// `agent:<id>`: the agent making the call (codex-cli, claude-code, cursor, ...).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub agent: Option<String>,
    /// `device:<id>`: the device the call originated from.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub device: Option<String>,
    /// `org:<id>`: the organization / workspace, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub org: Option<String>,
}

impl Principal {
    /// Construct a principal for a single agent. Useful in tests and simple local sessions.
    pub fn agent(agent: impl Into<String>) -> Self {
        Principal {
            agent: Some(agent.into()),
            ..Default::default()
        }
    }

    /// Construct a principal for a single user.
    pub fn user(user: impl Into<String>) -> Self {
        Principal {
            user: Some(user.into()),
            ..Default::default()
        }
    }
}

/// What an action touches
/// (`secret:braintree_prod`, `integration:github_acme`, `repo:acme/app`,
/// `environment:production`, `transaction:abc123`).
///
/// A `kind`/`name` pair. Nothing in the policy engine or the gateway reads it: policies are
/// scoped by connection id and capability action id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// The resource family: `secret`, `integration`, `repo`, `environment`, `transaction`, ...
    pub kind: String,
    /// The concrete resource name within that family.
    pub name: String,
}

impl Resource {
    /// Build a resource from a `kind` and `name`.
    pub fn new(kind: impl Into<String>, name: impl Into<String>) -> Self {
        Resource {
            kind: kind.into(),
            name: name.into(),
        }
    }

    /// Render as the `kind:name` short form (e.g. `secret:braintree_prod`).
    pub fn qualified(&self) -> String {
        format!("{}:{}", self.kind, self.name)
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.name)
    }
}

/// The normalized set of actions Permaura recognizes: deliberately coarse verbs (`read`,
/// `create`, `refund`, ...). The policy engine does not read it; grants and policies key on
/// capability action ids. The gateway uses it to hold a request to its action, so a read-like
/// action may only send a GET or a GraphQL query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Read a single record or metadata.
    Read,
    /// Search a collection.
    Search,
    /// List a collection.
    List,
    /// Create a new record.
    Create,
    /// Update an existing record.
    Update,
    /// Delete a record.
    Delete,
    /// Execute an arbitrary operation (e.g. a generic HTTP call).
    Execute,
    /// Trigger a deploy.
    Deploy,
    /// Refund a payment.
    Refund,
    /// Charge a payment.
    Charge,
    /// Rotate a secret.
    RotateSecret,
    /// Export data out of a system.
    Export,
    /// Send a message / notification.
    Send,
}

impl Action {
    /// The canonical `snake_case` wire name for this action.
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Search => "search",
            Action::List => "list",
            Action::Create => "create",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::Execute => "execute",
            Action::Deploy => "deploy",
            Action::Refund => "refund",
            Action::Charge => "charge",
            Action::RotateSecret => "rotate_secret",
            Action::Export => "export",
            Action::Send => "send",
        }
    }

    /// A *baseline* risk tier for the action: mutating and financial verbs are high/critical.
    /// The floor an unvouched manifest line's declared risk is held to (`presets` in the gateway); every capability
    /// carries its own `risk`, which is what the engine reads.
    pub fn baseline_risk(&self) -> RiskTier {
        match self {
            Action::Read | Action::Search | Action::List => RiskTier::Low,
            Action::Export => RiskTier::High,
            Action::Create | Action::Update | Action::Execute | Action::Deploy | Action::Send => {
                RiskTier::High
            }
            Action::Delete
            | Action::Refund
            | Action::Charge
            | Action::RotateSecret => RiskTier::Critical,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Action {
    type Err = PermauraError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let action = match s {
            "read" => Action::Read,
            "search" => Action::Search,
            "list" => Action::List,
            "create" => Action::Create,
            "update" => Action::Update,
            "delete" => Action::Delete,
            "execute" => Action::Execute,
            "deploy" => Action::Deploy,
            "refund" => Action::Refund,
            "charge" => Action::Charge,
            "rotate_secret" => Action::RotateSecret,
            "export" => Action::Export,
            "send" => Action::Send,
            other => {
                return Err(PermauraError::InvalidInput(format!(
                    "unknown action: {other}"
                )))
            }
        };
        Ok(action)
    }
}

/// The four risk tiers. Ordered so comparisons
/// (`risk >= RiskTier::High`) work directly in the policy engine.
///
/// The `Default` is [`RiskTier::High`]: an unclassified action should be treated as
/// dangerous until a human says otherwise, which is the conservative, deny-leaning posture the product demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Read metadata, list records: allow within grant.
    Low,
    /// Read customer details, small exports: treated like `Low` by the engine. Masking and limits
    /// come from redaction and grants, not from the tier.
    Medium,
    /// Write records, create PR, trigger deploy: the engine floors the rung at `approve`, so the
    /// call is held until an operator bearer or a device signature resolves it.
    #[default]
    High,
    /// Refund, charge, delete, rotate a production secret: held exactly like `High`. Only a
    /// policy's `device_signed` rung requires a paired device.
    Critical,
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RiskTier::Low => "low",
            RiskTier::Medium => "medium",
            RiskTier::High => "high",
            RiskTier::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// The kind of human approval an action requires when it is escalated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// Unused: nothing produces it. Touch ID is a desktop-app prompt before signing, and no
    /// decision requires it.
    TouchId,
    /// Held at the `approve` rung: an operator bearer or a device signature resolves it, and a
    /// push goes to registered phones on a best-effort basis.
    Push,
    /// Resolution requires an ed25519 signature from a paired approver device: an operator
    /// bearer alone can never resolve it (the `device_signed` ladder rung).
    DeviceSigned,
    /// Unused: nothing produces it. Two-person approval is [`Policy::device_signed_quorum`] on
    /// the `device_signed` rung, counting distinct people.
    TwoPerson,
}

/// A concrete approval requirement attached to a `requires_approval` decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    /// Which approval mechanism is required.
    #[serde(rename = "type")]
    pub kind: ApprovalKind,
    /// Always `true`: an approval releases the one held call it was raised for and creates no grant. Nothing reads this field.
    pub single_use: bool,
    /// A short message naming the capability and connection, stored as the held approval's `message`. The call's parameters are shown separately, by the approval display.
    pub message: String,
}

impl ApprovalRequirement {
    /// Build a single-use approval requirement of the given kind.
    pub fn single_use(kind: ApprovalKind, message: impl Into<String>) -> Self {
        ApprovalRequirement {
            kind,
            single_use: true,
            message: message.into(),
        }
    }
}

/// A rung on the approval ladder: the per-action verdict a policy assigns. Ordered from least to
/// most restrictive so the engine can take the **most restrictive** rung across every policy that
/// permits an action (`max`): a permissive policy can never lower an action another policy holds
/// higher. `Deny` sits at the top because deny always wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rung {
    /// Execute immediately, no human (today's plain `allow`).
    Auto,
    /// Execute immediately, but push an after-the-fact notification to enrolled devices.
    Notify,
    /// Hold for a human; resolvable by an operator bearer or a device signature.
    Approve,
    /// Hold for a human; resolvable ONLY by an ed25519 signature from a paired approver device.
    DeviceSigned,
    /// Never allowed (deny wins).
    Deny,
}

impl Rung {
    /// The tier string carried on a held approval / the wire (`approve` | `device_signed`). Only
    /// the two holding rungs have one; the rest never produce a `PendingApproval`.
    pub fn tier_str(self) -> Option<&'static str> {
        match self {
            Rung::Approve => Some("approve"),
            Rung::DeviceSigned => Some("device_signed"),
            _ => None,
        }
    }
}

/// The three terminal outcomes of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// The action may proceed.
    Allow,
    /// The action is forbidden.
    Deny,
    /// The action needs human approval before it may proceed.
    RequiresApproval,
}

/// The result of evaluating a request against policy. This is the single object
/// the gateway returns to the agent as the authorization verdict.
///
/// Serialized example:
/// ```json
/// {
///   "decision": "requires_approval",
///   "reason": "Action 'transactions.refund' is classified 'critical' risk and requires approval.",
///   "approval": { "type": "push", "single_use": true, "message": "Approve 'transactions.refund' on 'braintree_production'?" }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The verdict.
    #[serde(rename = "decision")]
    pub kind: DecisionKind,
    /// A human-readable explanation, suitable for an audit log and for `permaura.explain_denial`.
    pub reason: String,
    /// Present only when `kind == RequiresApproval`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub approval: Option<ApprovalRequirement>,
}

impl Decision {
    /// Build an `allow` decision.
    pub fn allow(reason: impl Into<String>) -> Self {
        Decision {
            kind: DecisionKind::Allow,
            reason: reason.into(),
            approval: None,
        }
    }

    /// Build a `deny` decision.
    pub fn deny(reason: impl Into<String>) -> Self {
        Decision {
            kind: DecisionKind::Deny,
            reason: reason.into(),
            approval: None,
        }
    }

    /// Build a `requires_approval` decision with an attached requirement.
    pub fn requires_approval(reason: impl Into<String>, approval: ApprovalRequirement) -> Self {
        Decision {
            kind: DecisionKind::RequiresApproval,
            reason: reason.into(),
            approval: Some(approval),
        }
    }

    /// True if the action may proceed without further human interaction.
    pub fn is_allowed(&self) -> bool {
        matches!(self.kind, DecisionKind::Allow)
    }
}

/// Where a request comes from, and, on a secret's metadata, which requests may use it. Every
/// call executes in the gateway process either way: a request is `RemoteAllowed` when it arrived
/// over a tunnel, a public URL or the relay, or when the gateway is hosted, and the custody gate
/// refuses it when the secret names locations without `RemoteAllowed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLocation {
    /// A request made on this gateway's own host; on a secret, usable only by such requests.
    #[default]
    LocalOnly,
    /// A request that arrived remotely or is served by a hosted gateway; on a secret, usable by
    /// such requests too.
    RemoteAllowed,
}

/// A configured integration instance: Braintree prod, GitHub @github_acme, a Vercel
/// account, a fal.ai endpoint. A [`Connection`] is the thing a credential attaches to and
/// the scope a [`Policy`] is written against. It holds the capabilities the integration
/// exposes and an operator master-switch (`disabled_capabilities`) that denies a capability
/// for *every* grant, regardless of policy. It deliberately holds **no** actions and **no**
/// agents: those live on policies and grants respectively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// Stable id and the policy scope key (e.g. `braintree_production`). Capability
    /// `resource` fields point at this id.
    pub id: String,
    /// The connector family that backs it: `braintree`, `github`, `vercel`, `fal`,
    /// `generic-http`, …
    pub connector: String,
    /// The operator-chosen instance name (e.g. `Braintree production`).
    pub name: String,
    /// An honest, human label for the connector (e.g. `fal.ai`, not `Generic HTTP`).
    pub label: String,
    /// The vault secret id whose sealed credential this connection uses. Empty until a
    /// credential is added.
    #[serde(default)]
    pub secret_id: String,
    /// The capability ids this connection exposes (e.g. `braintree.transactions.search`).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// The operator master-switch: capability ids switched **off** here are denied for
    /// every grant on this connection, above any policy (the real capability toggle).
    #[serde(default)]
    pub disabled_capabilities: Vec<String>,
    /// The connection-level kill switch: when `true`, every capability on this connection is
    /// denied for every grant, above any policy, a reversible "pause this service" the operator
    /// flips, distinct from removing it. Defaults `false` so connections persisted before this
    /// field deserialize as enabled.
    #[serde(default)]
    pub disabled: bool,
    /// The operator-defined host allowlist enforced at invoke time. Required (non-empty) for
    /// generic-HTTP connections, whose target host is agent-supplied: a request whose host is
    /// not on this list is denied, and an empty list on a generic-HTTP connection fails closed.
    /// Empty for typed connectors, whose upstream host is pinned at config/import time. Entries
    /// are host names (no scheme/path); a leading `*.` matches subdomains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
    /// Unix-millisecond creation time.
    #[serde(default)]
    pub created_at: i64,
    /// Response field names redacted on every call through this connection, on top of the gateway's
    /// defaults. Copied from the manifest at creation so a connection keeps its redaction when its
    /// manifest is uninstalled; it can only add to the effective set, never remove a default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact_fields: Vec<String>,
    /// Where a discovered connection's capabilities came from, so a re-sync can read the same source
    /// again and diff it against what the operator reviewed. `None` for preset and hand-built
    /// connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ConnectionSource>,
    /// The catalog entry a connection was made from, recorded at creation, so revoking an installed
    /// manifest refuses only the connections made from it. `None` for one made before this was
    /// recorded, and for one imported from a bundle whose claim the gateway does not keep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub made_from: Option<CatalogOrigin>,
}

/// Which catalog entry a connection's capabilities were copied from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogOrigin {
    /// The gateway's own code: a compiled preset, or a connector family it builds itself.
    BuiltIn,
    /// The operator's own source, an OpenAPI document or a WordPress site, read when the connection was made. No manifest made it, so no revocation names it.
    Discovered,
    /// An installed manifest at `version`, signed with `key_id`, or the operator's own unsigned one when `key_id` is `None`.
    Installed {
        /// The installed version the capabilities were copied from.
        version: u32,
        /// The signing key's id, as the install recorded it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_id: Option<String>,
    },
}

/// The kind of document a discovered connection was derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A WordPress site's REST index (and, once a credential is sealed, its Abilities API).
    Wordpress,
    /// An OpenAPI 3.x document.
    Openapi,
}

/// The discovery source behind a connection: what was read, from where, and a digest of what the
/// operator reviewed. The capabilities themselves are stored; this is never re-read at call time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionSource {
    /// What kind of document this is.
    pub kind: SourceKind,
    /// What the operator bound: the site URL for WordPress, the spec URL for OpenAPI.
    pub url: String,
    /// WordPress: the canonical REST root the capabilities are pinned to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rest_root: Option<String>,
    /// WordPress: the REST namespaces the operator imported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
    /// WordPress: whether the Abilities API is also a source.
    #[serde(default)]
    pub abilities: bool,
    /// A digest of the source document at the last import or re-sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Unix-millisecond time of the last import or re-sync.
    #[serde(default)]
    pub synced_at: i64,
}

/// A reusable permission **template scoped to a connection**. A policy says only *what is
/// allowed, what is denied, and what a human must approve*: it names no agent, no expiry,
/// no call limits (those are a [`Grant`] concern). One connection may have several policies
/// (e.g. "read-only" and "read-plus-create").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Policy {
    /// Stable id (e.g. `pol_123`).
    pub id: String,
    /// The connection this policy is scoped to ([`Connection::id`]).
    pub connection_id: String,
    /// Operator-facing name (e.g. `Read-only`).
    #[serde(default)]
    pub name: String,
    /// Capability action ids explicitly allowed (e.g. `transactions.search`).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Capability action ids explicitly denied. Deny always wins over allow.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Capability action ids that, even when allowed, must be escalated to a human.
    /// This is the `approve` rung of the approval ladder: resolvable by an operator bearer
    /// or a device signature.
    #[serde(default)]
    pub requires_approval: Vec<String>,
    /// Capability action ids that execute immediately but push an after-the-fact notification
    /// to enrolled devices (the `notify` rung: awareness without blocking).
    #[serde(default)]
    pub notify: Vec<String>,
    /// Capability action ids whose approval may ONLY be resolved by an ed25519 signature from a
    /// paired approver device (the `device_signed` rung): an operator bearer riding the
    /// semi-trusted broker is never sufficient. Fails closed when no device is paired.
    #[serde(default)]
    pub device_signed: Vec<String>,
    /// How many **distinct people**, each signing from a paired device, must sign before a
    /// `device_signed` action from this policy runs: the two-person rule. Two devices bound to one
    /// person count once. `1` (the default, and what every pre-existing policy deserializes to) is
    /// the single-signature behavior this shipped with.
    ///
    /// Only the `device_signed` rung honors it: the lower rungs have no signature to count.
    #[serde(default = "default_quorum")]
    pub device_signed_quorum: u8,
    /// Response field names redacted on every call this policy permits, on top of the gateway's
    /// defaults, the connection's list and its manifest's. Like every other redaction source it can
    /// only add to the effective set; see [`crate::effective_redact_keys`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact_fields: Vec<String>,
}

/// One signature: the pre-quorum behaviour, and what a policy stored before this field existed
/// must keep meaning.
fn default_quorum() -> u8 {
    1
}

impl Policy {
    /// True if `action_id` is on this policy's deny list.
    pub fn denies(&self, action_id: &str) -> bool {
        self.deny.iter().any(|a| a == action_id)
    }

    /// True if `action_id` is on this policy's allow list.
    pub fn allows(&self, action_id: &str) -> bool {
        self.allow.iter().any(|a| a == action_id)
    }

    /// How many distinct devices this policy demands for `action_id`, or `None` when the policy
    /// does not hold it at the `device_signed` rung (nothing to count signatures for).
    pub fn quorum_for(&self, action_id: &str) -> Option<u8> {
        self.device_signed
            .iter()
            .any(|a| a == action_id)
            .then(|| self.device_signed_quorum.max(1))
    }

    /// True if `action_id` is on this policy's requires-approval list.
    pub fn needs_approval(&self, action_id: &str) -> bool {
        self.requires_approval.iter().any(|a| a == action_id)
    }

    /// True if `action_id` is on this policy's notify list.
    pub fn notifies(&self, action_id: &str) -> bool {
        self.notify.iter().any(|a| a == action_id)
    }

    /// True if `action_id` is on this policy's device-signed list.
    pub fn needs_device_signature(&self, action_id: &str) -> bool {
        self.device_signed.iter().any(|a| a == action_id)
    }

    /// This policy's verdict for `action_id` as a ladder rung, or `None` if the policy is silent
    /// on the action (lists it nowhere). Within one policy the most restrictive listing wins
    /// (`deny > device_signed > approve > notify > auto`), so an action listed in several lists
    /// resolves unambiguously. An action in any non-deny rung counts as **permitted**: the engine
    /// no longer requires it to also sit in `allow` (that redundancy was a footgun the console's
    /// per-action verdict removes).
    pub fn rung_for(&self, action_id: &str) -> Option<Rung> {
        if self.denies(action_id) {
            Some(Rung::Deny)
        } else if self.needs_device_signature(action_id) {
            Some(Rung::DeviceSigned)
        } else if self.needs_approval(action_id) {
            Some(Rung::Approve)
        } else if self.notifies(action_id) {
            Some(Rung::Notify)
        } else if self.allows(action_id) {
            Some(Rung::Auto)
        } else {
            None
        }
    }
}

/// Who a [`Grant`] is for: a single named agent, or every agent (the "any agent may use
/// this policy without an individual grant" case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantTarget {
    /// Applies to every agent (approved). The agent-wide grant.
    AllAgents,
    /// Applies to exactly one agent id (e.g. `codex-cli`).
    Agent(String),
}

impl GrantTarget {
    /// True if this target covers `agent_id` (either it names it, or it is all-agents).
    pub fn matches(&self, agent_id: &str) -> bool {
        match self {
            GrantTarget::AllAgents => true,
            GrantTarget::Agent(a) => a == agent_id,
        }
    }
}

/// The window a [`Grant`]'s `max_calls` budget is measured over. All windows are **rolling**
/// (trailing-from-now), not calendar/timezone-aligned: `Day` means "the last 24 hours", not
/// "since local midnight". The budget counts matching calls newer than one window ago.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrantPeriod {
    /// Rolling 24-hour window.
    Day,
    /// Rolling 7-day window.
    Week,
    /// Rolling 30-day window.
    Month,
    /// Over the whole life of the grant (no reset). The default when a period is unset.
    #[default]
    Total,
}

impl GrantPeriod {
    /// The length of one period in seconds, or `None` for [`GrantPeriod::Total`] (no window).
    pub fn window_secs(&self) -> Option<i64> {
        match self {
            GrantPeriod::Day => Some(86_400),
            GrantPeriod::Week => Some(7 * 86_400),
            GrantPeriod::Month => Some(30 * 86_400),
            GrantPeriod::Total => None,
        }
    }
}

/// One agent's membership in a [`Grant`], optionally carrying a per-agent call ceiling that
/// overrides the grant's `default_per_agent_limit` for just this agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAgent {
    /// The agent id this membership row covers.
    pub agent_id: String,
    /// This agent's per-`period` cap, overriding `default_per_agent_limit`. `None` = use the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_agent_limit: Option<u64>,
}

impl GrantAgent {
    /// A membership row with no per-agent override.
    pub fn new(agent_id: impl Into<String>) -> Self {
        GrantAgent {
            agent_id: agent_id.into(),
            per_agent_limit: None,
        }
    }
}

/// Who a [`Grant`] covers: **every** approved agent (the wildcard, including agents that
/// enrol in the future), or a specific, enumerated set of agents (each with an optional per-agent
/// limit). `AllAgents` is a flag (no rows) so "every agent, including future ones" stays cheap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantAgents {
    /// Every approved agent, present and future.
    AllAgents,
    /// A specific set of agents.
    Agents(Vec<GrantAgent>),
}

impl Default for GrantAgents {
    /// An empty specific set (covers nobody), the safe default if neither flag nor rows are given.
    fn default() -> Self {
        GrantAgents::Agents(Vec::new())
    }
}

/// A **many-to-many bundle** binding a set of [`Policy`]s to a set of agents under two-tier limits.
/// A grant carries *no action lists*: those are inherited from its policies. Exactly one
/// grant is the always-present, pausable **Default** baseline (`is_default`) that every approved
/// agent inherits with zero per-agent setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Grant {
    /// Stable identifier (e.g. `gr_123`).
    pub grant_id: String,
    /// Operator-facing, referenceable name ("Default", "Billing agents", …).
    #[serde(default)]
    pub name: String,
    /// The pause switch: a disabled grant is fully inert. It contributes neither allows,
    /// denies, nor budget to resolution. Re-enabling restores it unchanged.
    pub enabled: bool,
    /// Exactly one grant is the Default baseline at a time. The Default cannot be deleted
    /// while it holds this flag; setting it on another grant clears it from the old one.
    #[serde(default)]
    pub is_default: bool,
    /// The policies this grant activates. MAY span multiple connections.
    #[serde(default)]
    pub policy_ids: Vec<String>,
    /// Who the grant covers: all agents, or a specific set (each with an optional per-agent limit).
    pub agents: GrantAgents,
    /// The budget window for BOTH tiers below.
    #[serde(default)]
    pub period: GrantPeriod,
    /// The hard ceiling across ALL agents in this grant per `period`. When set, "it rules
    /// all": once combined usage reaches it, every agent is denied until the window rolls over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overall_limit: Option<u64>,
    /// Each agent's per-`period` cap unless a [`GrantAgent::per_agent_limit`] overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_per_agent_limit: Option<u64>,
    /// Hard expiry: after this instant the grant is dead. `None` = no expiry.
    #[serde(skip_serializing_if = "Option::is_none", default, with = "opt_rfc3339")]
    pub expires_at: Option<OffsetDateTime>,
}

impl Grant {
    /// True if this grant covers `agent_id` (names it, or is an all-agents grant).
    pub fn targets(&self, agent_id: &str) -> bool {
        match &self.agents {
            GrantAgents::AllAgents => true,
            GrantAgents::Agents(v) => v.iter().any(|GrantAgent { agent_id: id, per_agent_limit: _ }| id == agent_id),
        }
    }

    /// True if this is an all-agents (wildcard) grant.
    pub fn is_all_agents(&self) -> bool {
        matches!(self.agents, GrantAgents::AllAgents)
    }

    /// The agent ids this grant names (empty for an all-agents grant).
    pub fn agent_ids(&self) -> Vec<String> {
        match &self.agents {
            GrantAgents::AllAgents => Vec::new(),
            GrantAgents::Agents(v) => v.iter().map(|a| a.agent_id.clone()).collect(),
        }
    }

    /// The effective per-`period` per-agent ceiling for `agent_id`: the agent's own override if set,
    /// otherwise the grant's `default_per_agent_limit`. `None` = no per-agent ceiling.
    pub fn effective_per_agent_limit(&self, agent_id: &str) -> Option<u64> {
        if let GrantAgents::Agents(v) = &self.agents {
            if let Some(a) = v.iter().find(|a| a.agent_id == agent_id) {
                if a.per_agent_limit.is_some() {
                    return a.per_agent_limit;
                }
            }
        }
        self.default_per_agent_limit
    }

    /// True if the grant is enabled and not past its expiry at `now`.
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.enabled && self.expires_at.map_or(true, |exp| now < exp)
    }

    /// Every instant authorization can change without a stored edit, kept beside `is_live`.
    pub fn authorization_change_points(&self) -> impl Iterator<Item = OffsetDateTime> {
        let Self { grant_id: _, name: _, enabled: _, is_default: _, policy_ids: _, agents: _, period: _, overall_limit: _, default_per_agent_limit: _, expires_at } = self;
        (*expires_at).into_iter()
    }

    /// The always-present, all-agents, empty **Default** baseline grant.
    pub fn default_baseline(grant_id: impl Into<String>) -> Self {
        Grant {
            grant_id: grant_id.into(),
            name: "Default".into(),
            enabled: true,
            is_default: true,
            policy_ids: Vec::new(),
            agents: GrantAgents::AllAgents,
            period: GrantPeriod::Total,
            overall_limit: None,
            default_per_agent_limit: None,
            expires_at: None,
        }
    }
}

/// Deserialize a [`Grant`] from either the v2 shape or the legacy slim shape, migrating losslessly.
/// Implemented by hand (not derived) so every load path (the sqlite blob store, REST
/// bodies, tests) automatically upgrades an old `{ policy_id, target, max_calls }` grant.
impl<'de> Deserialize<'de> for Grant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawGrant {
            grant_id: String,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            enabled: Option<bool>,
            #[serde(default)]
            is_default: bool,
            #[serde(default)]
            policy_ids: Option<Vec<String>>,
            #[serde(default)]
            agents: Option<GrantAgents>,
            #[serde(default)]
            period: Option<GrantPeriod>,
            #[serde(default)]
            overall_limit: Option<u64>,
            #[serde(default)]
            default_per_agent_limit: Option<u64>,
            #[serde(default, with = "opt_rfc3339")]
            expires_at: Option<OffsetDateTime>,
            // ── legacy slim-grant fields (the migration source) ──
            #[serde(default)]
            policy_id: Option<String>,
            #[serde(default)]
            target: Option<GrantTarget>,
            #[serde(default)]
            max_calls: Option<u64>,
        }

        let raw = RawGrant::deserialize(deserializer)?;

        // policy_ids: prefer the v2 array, else lift the legacy single policy_id.
        let policy_ids = raw.policy_ids.unwrap_or_else(|| {
            raw.policy_id
                .clone()
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect()
        });

        // agents: prefer the v2 set, else map the legacy target.
        let agents = raw.agents.unwrap_or_else(|| match raw.target {
            Some(GrantTarget::AllAgents) => GrantAgents::AllAgents,
            Some(GrantTarget::Agent(a)) => GrantAgents::Agents(vec![GrantAgent::new(a)]),
            None => GrantAgents::default(),
        });

        // Legacy `max_calls` becomes the per-agent default; the legacy grant had no overall ceiling.
        let default_per_agent_limit = raw.default_per_agent_limit.or(raw.max_calls);

        Ok(Grant {
            grant_id: raw.grant_id,
            name: raw.name.unwrap_or_default(),
            enabled: raw.enabled.unwrap_or(true),
            is_default: raw.is_default,
            policy_ids,
            agents,
            period: raw.period.unwrap_or_default(),
            overall_limit: raw.overall_limit,
            default_per_agent_limit,
            expires_at: raw.expires_at,
        })
    }
}

/// serde helper: serialize `Option<OffsetDateTime>` as RFC3339 strings.
mod opt_rfc3339 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S>(value: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(dt) => {
                let s = dt.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
                s.serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => OffsetDateTime::parse(&s, &Rfc3339)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_roundtrips_through_str() {
        for (s, a) in [
            ("read", Action::Read),
            ("rotate_secret", Action::RotateSecret),
            ("refund", Action::Refund),
            ("send", Action::Send),
        ] {
            assert_eq!(Action::from_str(s).unwrap(), a);
            assert_eq!(a.as_str(), s);
            assert_eq!(a.to_string(), s);
        }
    }

    #[test]
    fn unknown_action_is_rejected() {
        let err = Action::from_str("self_destruct").unwrap_err();
        assert!(matches!(err, PermauraError::InvalidInput(_)));
    }

    #[test]
    fn action_serde_uses_snake_case() {
        let json = serde_json::to_string(&Action::RotateSecret).unwrap();
        assert_eq!(json, "\"rotate_secret\"");
        let back: Action = serde_json::from_str("\"refund\"").unwrap();
        assert_eq!(back, Action::Refund);
    }

    #[test]
    fn risk_tiers_are_ordered() {
        assert!(RiskTier::Critical > RiskTier::High);
        assert!(RiskTier::High > RiskTier::Medium);
        assert!(RiskTier::Medium > RiskTier::Low);
    }

    #[test]
    fn baseline_risk_matches_tiering_principle() {
        assert_eq!(Action::Read.baseline_risk(), RiskTier::Low);
        assert_eq!(Action::Refund.baseline_risk(), RiskTier::Critical);
        assert_eq!(Action::Charge.baseline_risk(), RiskTier::Critical);
        assert_eq!(Action::RotateSecret.baseline_risk(), RiskTier::Critical);
        assert_eq!(Action::Create.baseline_risk(), RiskTier::High);
    }

    #[test]
    fn decision_serializes_like_the_spec() {
        let d = Decision::requires_approval(
            "Refunds are classified as critical financial actions.",
            ApprovalRequirement::single_use(
                ApprovalKind::TouchId,
                "Codex wants to refund AUD 49.00 for Braintree transaction abc123.",
            ),
        );
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["decision"], "requires_approval");
        assert_eq!(v["approval"]["type"], "touch_id");
        assert_eq!(v["approval"]["single_use"], true);
    }

    #[test]
    fn allow_decision_has_no_approval_field() {
        let d = Decision::allow("read is allowed by grant gr_123");
        let v = serde_json::to_value(&d).unwrap();
        assert!(v.get("approval").is_none());
        assert!(d.is_allowed());
    }

    #[test]
    fn policy_allow_deny_approval_lookup() {
        let policy = Policy {
            id: "pol_123".into(),
            connection_id: "braintree_production".into(),
            name: "Read-only".into(),
            allow: vec!["transactions.search".into()],
            deny: vec!["transactions.refund".into()],
            requires_approval: vec!["customers.read".into()],
            notify: vec!["webhooks.list".into()],
            device_signed: vec!["transactions.void".into()],
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        };
        assert!(policy.allows("transactions.search"));
        assert!(policy.denies("transactions.refund"));
        assert!(policy.needs_approval("customers.read"));
        assert!(!policy.allows("transactions.refund"));
        assert!(policy.notifies("webhooks.list"));
        assert!(policy.needs_device_signature("transactions.void"));
        assert_eq!(policy.rung_for("transactions.refund"), Some(Rung::Deny));
        assert_eq!(policy.rung_for("transactions.void"), Some(Rung::DeviceSigned));
        assert_eq!(policy.rung_for("customers.read"), Some(Rung::Approve));
        assert_eq!(policy.rung_for("webhooks.list"), Some(Rung::Notify));
        assert_eq!(policy.rung_for("transactions.search"), Some(Rung::Auto));
        assert_eq!(policy.rung_for("unlisted.action"), None);
    }

    #[test]
    fn grant_target_matches_agent_or_all() {
        let specific = GrantTarget::Agent("codex-cli".into());
        assert!(specific.matches("codex-cli"));
        assert!(!specific.matches("claude-code"));
        assert!(GrantTarget::AllAgents.matches("anyone"));
    }

    #[test]
    fn grant_target_serde_is_readable() {
        let v = serde_json::to_value(GrantTarget::Agent("codex-cli".into())).unwrap();
        assert_eq!(v, serde_json::json!({ "agent": "codex-cli" }));
        let all = serde_json::to_value(GrantTarget::AllAgents).unwrap();
        assert_eq!(all, serde_json::json!("all_agents"));
    }

    #[test]
    fn grant_v2_roundtrips() {
        let g = Grant {
            grant_id: "gr_123".into(),
            name: "Billing agents".into(),
            enabled: true,
            is_default: false,
            policy_ids: vec!["pol_a".into(), "pol_b".into()],
            agents: GrantAgents::Agents(vec![
                GrantAgent::new("codex-cli"),
                GrantAgent {
                    agent_id: "claude-code".into(),
                    per_agent_limit: Some(50),
                },
            ]),
            period: GrantPeriod::Month,
            overall_limit: Some(1000),
            default_per_agent_limit: Some(100),
            expires_at: None,
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: Grant = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
        assert!(g.targets("codex-cli"));
        assert!(!g.targets("someone-else"));
        // The per-agent override wins over the default; a member without one falls back to the default.
        assert_eq!(g.effective_per_agent_limit("claude-code"), Some(50));
        assert_eq!(g.effective_per_agent_limit("codex-cli"), Some(100));
    }

    #[test]
    fn legacy_slim_grant_migrates_losslessly() {
        // An old-shape blob: single policy_id, a specific target, a per-grant max_calls.
        let legacy = serde_json::json!({
            "grant_id": "gr_old",
            "policy_id": "pol_ro",
            "target": { "agent": "codex-cli" },
            "max_calls": 100,
            "period": "day"
        });
        let g: Grant = serde_json::from_value(legacy).unwrap();
        assert_eq!(g.policy_ids, vec!["pol_ro".to_string()]);
        assert_eq!(g.agent_ids(), vec!["codex-cli".to_string()]);
        assert_eq!(g.default_per_agent_limit, Some(100)); // max_calls → per-agent default
        assert_eq!(g.overall_limit, None); // legacy grants had no overall ceiling
        assert!(g.enabled); // defaults to enabled
        assert!(!g.is_default);
        assert_eq!(g.period, GrantPeriod::Day);

        // An all-agents legacy grant maps to the wildcard.
        let legacy_all = serde_json::json!({
            "grant_id": "gr_all", "policy_id": "pol_x", "target": "all_agents", "max_calls": 5
        });
        let g2: Grant = serde_json::from_value(legacy_all).unwrap();
        assert!(g2.is_all_agents());
        assert_eq!(g2.default_per_agent_limit, Some(5));
    }

    #[test]
    fn grant_agents_serde_shapes() {
        assert_eq!(
            serde_json::to_value(GrantAgents::AllAgents).unwrap(),
            serde_json::json!("all_agents")
        );
        let specific = serde_json::to_value(GrantAgents::Agents(vec![GrantAgent::new("a")])).unwrap();
        assert_eq!(specific, serde_json::json!({ "agents": [{ "agent_id": "a" }] }));
    }
}
