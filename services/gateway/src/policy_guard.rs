//! The control-plane mutation guard.
//!
//! A compromised control plane could reach `PUT /v1/policies` / `/v1/grants` and try to *loosen*
//! authorization: mint a new permit, drop a `device_signed` rung, or bind a policy to more agents,
//! then resolve its own held calls on a bearer. `rest::apply_or_hold` consults this module for a
//! change that arrives remotely (the broker, a tunnel or other public ingress, a hosted worker, a
//! web page; see `rest::RemoteFlag`) on a gateway that has ever had an approver device enrolled and
//! whose operator has not explicitly opted approvals down to `approve`
//! (`service::control_plane_hold_required`). It decides whether such a change is **strictly
//! tightening** (apply now) or must be **held as a `device_signed` approval** (a human signs the
//! exact diff on a paired device).
//!
//! Over loopback, or on a gateway no device was ever paired to, the tightening classifier is not
//! consulted: only destructive changes ([`is_destructive`]) and credential moves are held there, and
//! only while a device is trusted. After an explicit opt-down none of these is held.
//!
//! Soundness rule: while the guard is armed it must never APPLY a loosening mutation, but holding
//! one that does tighten is only friction (the operator signs it, or makes it from the gateway's own
//! host). So every classifier here is conservative: when in doubt, it reports "not tightening" and
//! the mutation is held.

use crate::store::Agent;
use permaura_core::{Connection, DecisionKind, Grant, GrantAgents, Policy, RiskTier, Rung};
use permaura_policy::{DecisionInput, PolicyEngine, RequestContext, Unmetered};
use serde::{Deserialize, Serialize};

/// A proposed control-plane mutation, captured verbatim so it can be held (as an approval's
/// `params`, which `request_hash` then binds) and later applied byte-identically on resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Mutation {
    /// Create or replace a policy, optionally syncing its grant membership to exactly `grant_ids`.
    PolicyUpsert {
        /// The full proposed policy.
        policy: Policy,
        /// When present, sync this policy's grant membership to exactly these grants.
        #[serde(default)]
        grant_ids: Option<Vec<String>>,
    },
    /// Delete a policy by id (and detach it from every grant).
    PolicyDelete {
        /// The policy id to delete.
        policy_id: String,
    },
    /// Delete a stored credential outright.
    ///
    /// The most destructive single call in the surface, and the one an export hold does not cover: an
    /// export being held stops a credential being *taken*, and says nothing about it being destroyed.
    SecretDelete {
        /// The secret id to delete.
        secret_id: String,
    },
    /// Delete an agent, revoking its sessions and removing it from every grant that names it.
    AgentDelete {
        /// The agent id to delete.
        agent_id: String,
    },
    /// Delete a connection, cascading through its policies, capabilities and credential.
    ///
    /// The widest-reaching delete in the surface: it takes the connection, every policy that named
    /// it, those policies' places in every grant, its capabilities, and its credential where nothing
    /// else still references the same secret. Recoverable only from a backup.
    ConnectionDelete {
        /// The connection id to delete.
        connection_id: String,
    },
    /// Create or replace a grant.
    GrantUpsert {
        /// The full proposed grant.
        grant: Grant,
    },
    /// Delete a grant by id.
    GrantDelete {
        /// The grant id to delete.
        grant_id: String,
    },
    /// Re-enable a capability on a connection (remove it from `disabled_capabilities`): the capability
    /// kill switch sits *above* policy, so re-opening it is a loosening the guard must gate.
    CapabilityEnable {
        /// The connection whose capability is being re-enabled.
        connection_id: String,
        /// The capability id to re-enable.
        capability: String,
    },
    /// A sparse connection patch: un-pause the kill switch and/or repoint an SSH target. The
    /// loosening directions (un-pause, any SSH target/host-key edit) are held; a pause or rename
    /// tightens.
    ConnectionPatch {
        /// The connection being patched.
        connection_id: String,
        /// The sparse patch to apply.
        patch: ConnPatch,
    },
    /// Promote a pending agent to Approved (it can then invoke): defeats the new-agent approval
    /// gate, so the promotion is a loosening.
    AgentApprove {
        /// The agent id to approve.
        agent_id: String,
    },
    /// Create or replace an agent record verbatim. Loosening only when it lands (or keeps) an
    /// **Approved** agent that was not already approved: the `register_agent`/`update_agent` paths.
    AgentUpsert {
        /// The full proposed agent record.
        agent: Agent,
    },
    /// Promote a *staged* (already sealed-at-rest) credential into a connection's live secret. Used
    /// by the held-by-reference credential path: the plaintext never rides in the approval params
    /// (only the two secret ids do), so holding a credential change leaks no secret at rest.
    CredentialPromote {
        /// The connection whose live credential is being set.
        connection_id: String,
        /// The connection's live secret id the staged blob is promoted into.
        secret_id: String,
        /// The sealed staging secret id (created by `set_connection_credential`) this hold binds.
        staging_secret_id: String,
        /// Hex SHA-256 of the staged sealed envelope at the moment it was parked, so the device's signature covers the bytes and not only their id; promotion refuses a staged row that no longer matches.
        #[serde(default)]
        staged_sha256: String,
    },
    /// Flip a runtime broker switch: the global pause kill switch (which sits above policy) or the
    /// new-agent approval gate. Both switches are recorded in gateway meta, so they survive a
    /// restart, and `PERMAURA_REQUIRE_AGENT_APPROVAL` can also engage the new-agent gate for one run.
    /// Only the RELEASING direction (un-pause; require-approval off) loosens and is held; the
    /// ENGAGING direction (pause on; require-approval on) tightens and applies at once.
    BrokerToggle {
        /// Which runtime switch to flip.
        toggle: BrokerToggleKind,
        /// The requested value. `true` engages the switch (tightening), `false` releases it (loosening).
        value: bool,
    },
    /// Trust a device signing key. Once a usable key is trusted, this is held for that device's
    /// co-signature (hardware the control plane never touches) unless a recovery code or recovery
    /// ticket authorizes it, or the device presents the exact key already trusted; the first device
    /// is trusted on first use. Revocation and keys provisioned through `PERMAURA_APPROVER_KEYS`
    /// also write the keyring.
    ApproverKeyTrust {
        /// The approver id being trusted (`device:<id>`), as it will appear in an `ApprovalResult`.
        approver_id: String,
        /// The base64 ed25519 public key to trust. The pairing handler has already verified a fresh
        /// possession proof over it; holding the mutation binds THAT key, so the resolution cannot
        /// be redirected onto a different one.
        approver_pubkey: String,
        /// The person the key will approve for, so a two-person rule counts it as that person: the
        /// ticket's actor on a hosted worker, the person named at the host on a self-run gateway.
        /// Held with the key, so a co-signer confirms both. Absent when the pairing named nobody.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        person: Option<String>,
        /// The fingerprint of the key this enrolment retires under `approver_id`, read when it was asked
        /// for. It applies only while that is still the key there, so a held replacement cannot retire a
        /// key that took its place since. Absent when it replaces nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replaces: Option<String>,
    },
    /// Set (or clear) the approval-floor override. Held on the same terms.
    ApprovalFloorSet {
        /// The target floor (`approve` or `device_signed`), or `None` to clear the override and let
        /// enrolment decide the effective floor again.
        floor: Option<String>,
    },
    /// Revoke an approver key. Held when it is the LAST usable key on a self-run gateway, which empties the
    /// keyring so that nothing is held for a device signature afterwards and takes the same recovery
    /// authority as lowering the floor; and when someone other than the gateway's owner removes a key that
    /// is not provably theirs, which a device independent of them has to confirm.
    ApproverKeyRevoke {
        /// The approver id whose key is being revoked.
        approver_id: String,
    },
    /// Install or replace a connector manifest in the runtime catalog. It decides where the credential
    /// of every connection made from it is sent, so it is held like any other loosening.
    ConnectorInstall {
        /// The verified manifest exactly as it will be stored (a `presets::Preset`).
        manifest: serde_json::Value,
        /// Its version, which must still be newer than the installed one when this applies.
        version: u32,
        /// Whether Permaura signed it, as verified when it was asked for.
        provenance: crate::manifest::Provenance,
    },
    /// Remove an installed connector manifest from the runtime catalog.
    ConnectorRemove {
        /// The manifest id.
        connector_id: String,
    },
    /// The owner sets a capability's risk tier and whether it asks for an approval on every call,
    /// against the posture it carried when this was asked for. Lowering either is a loosening: the
    /// posture a document's author could not lower, the owner may, through the held path.
    CapabilityPosture {
        /// The connection the capability belongs to.
        connection_id: String,
        /// The full capability id.
        capability: String,
        /// The risk tier to set.
        risk: RiskTier,
        /// Whether every call asks for an approval.
        requires_approval: bool,
        /// The capability as it stood when this was asked for; it applies only while that is still so.
        from: PostureFrom,
    },
}

/// A capability's posture and pinned shape when a [`Mutation::CapabilityPosture`] was asked for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PostureFrom {
    /// Its action.
    pub action: permaura_core::Action,
    /// Its risk tier.
    pub risk: RiskTier,
    /// Whether every call asked for an approval.
    pub requires_approval: bool,
    /// The method it sends.
    pub method: crate::connectors::HttpMethod,
    /// The path template it sends to.
    pub path: String,
}

/// A sparse patch of a connection, mirrored from the REST `PatchConnectionReq` so it can be held
/// verbatim as approval params. Only the fields present are changed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ConnPatch {
    /// Flip the connection-level kill switch (`false` un-pauses, a loosening; `true` pauses).
    #[serde(default)]
    pub disabled: Option<bool>,
    /// A new operator-facing label (already trimmed + non-empty by the handler).
    #[serde(default)]
    pub label: Option<String>,
    /// A new instance name (already trimmed + non-empty by the handler).
    #[serde(default)]
    pub name: Option<String>,
    /// An SSH target repoint (any edit is treated as insecurity-increasing and held).
    #[serde(default)]
    pub ssh: Option<SshPatch>,
}

/// The SSH-target slice of a [`ConnPatch`] (host/port/user/host-key/auth). Mirrors the REST
/// `SshTargetPatch`; a serialisable copy so a held connection patch survives round-tripping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SshPatch {
    /// New target host.
    #[serde(default)]
    pub host: Option<String>,
    /// New target port.
    #[serde(default)]
    pub port: Option<u16>,
    /// New login user.
    #[serde(default)]
    pub user: Option<String>,
    /// New expected host-key fingerprint (switches the target to verified mode).
    #[serde(default)]
    pub host_key_sha256: Option<String>,
    /// Explicitly drop host-key verification. Meant for development, but nothing restricts it to a
    /// dev build, which is one reason the guard never classifies an SSH edit as tightening.
    #[serde(default)]
    pub insecure: Option<bool>,
    /// Switch between private-key (`false`) and password (`true`) auth.
    #[serde(default)]
    pub password_auth: Option<bool>,
}

/// The runtime broker switch a [`Mutation::BrokerToggle`] flips. Both switches share the same
/// polarity: `true` is the more restrictive state (deny every invoke / hold newly-seen agents),
/// `false` the looser one, so the loosening direction is identical (`value == false`) for both.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrokerToggleKind {
    /// The global kill switch (`paused`). `false` un-pauses, resuming agent invokes above policy.
    Pause,
    /// The new-agent approval gate (`require_agent_approval`). `false` lets a newly-seen OAuth agent
    /// land Approved automatically instead of Pending, silently defeating the new-agent gate.
    RequireAgentApproval,
}

/// What the store says about one id a held change names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    /// Nothing is known: the caller has no store, or reading it failed.
    Unknown,
    /// The store has no record under this id.
    Missing,
    /// The record exists, and this is its display name, which may be blank.
    Found(String),
}

impl Stored {
    fn name(&self) -> Option<&str> {
        match self {
            Stored::Found(n) => Some(n),
            _ => None,
        }
    }
}

/// The display names a held change's title is written with, looked up when the change is held.
///
/// Every lookup defaults to [`Stored::Unknown`], so [`NoStore`] is the whole implementation for a caller
/// with no store, and the title then names things by id.
pub trait MutationNames {
    /// A connection's [`connection_display_name`].
    fn connection(&self, _id: &str) -> Stored {
        Stored::Unknown
    }
    /// A policy's name.
    fn policy(&self, _id: &str) -> Stored {
        Stored::Unknown
    }
    /// A grant's name.
    fn grant(&self, _grant_id: &str) -> Stored {
        Stored::Unknown
    }
    /// An agent's name.
    fn agent(&self, _id: &str) -> Stored {
        Stored::Unknown
    }
    /// The display name of the connection that uses `secret_id` as its credential.
    fn secret_owner(&self, _secret_id: &str) -> Stored {
        Stored::Unknown
    }
    /// The name of the paired device that signs as `approver_id`.
    fn device(&self, _approver_id: &str) -> Stored {
        Stored::Unknown
    }
    /// The key `approver_id` is trusted with now, when that is a different key from `new_key`.
    fn displaced_key(&self, _approver_id: &str, _new_key: &str) -> Option<String> {
        None
    }
    /// Whether revoking `approver_id` would leave no trusted device. Assumed with no keyring to read, which
    /// is the revocation every hold of one was before another person's device could be held too.
    fn last_trusted_device(&self, _approver_id: &str) -> bool {
        true
    }
    /// The stored policy an edit would replace, so the title can say what the edit changes.
    fn policy_record(&self, _id: &str) -> Option<Policy> {
        None
    }
    /// The stored grant an edit would replace, so the title can say what the edit changes.
    fn grant_record(&self, _grant_id: &str) -> Option<Grant> {
        None
    }
    /// The ids of the stored grants that include `policy_id`.
    fn grants_including(&self, _policy_id: &str) -> Option<Vec<String>> {
        None
    }
    /// Every host a connection's credential is sent to, as `connectors::shown_host` writes it.
    fn connection_hosts(&self, _id: &str) -> Vec<String> {
        Vec::new()
    }
}

/// [`MutationNames`] for a caller with no store: every title names things by id.
pub struct NoStore;

impl MutationNames for NoStore {}

/// The most characters of a name a title shows before cutting it with an ellipsis.
pub const MAX_NAME_CHARS: usize = 64;

/// How a title names a connection: its label and its name together when they differ, because several
/// connections can share a label (two "Gmail" connections are told apart only by name), else whichever
/// it has. This is how the console and the phone name a connection too.
pub fn connection_display_name(label: &str, name: &str) -> String {
    let (label, name) = (label.trim(), name.trim());
    match (label.is_empty(), name.is_empty()) {
        (false, false) if label.to_lowercase() != name.to_lowercase() => format!("{label} \u{b7} {name}"),
        (false, _) => label.to_string(),
        (true, _) => name.to_string(),
    }
}

/// Double quotes, and the characters that read as one, a name could use to close its own quotes.
const QUOTE_LOOKALIKES: [char; 9] =
    ['\u{201c}', '\u{201d}', '\u{201e}', '\u{201f}', '\u{2033}', '\u{301d}', '\u{301e}', '\u{301f}', '\u{ff02}'];

/// `name` as a title shows it, inside curly quotes, cut to at most [`MAX_NAME_CHARS`] characters
/// including the ellipsis.
///
/// Agent names are chosen by agents and every other name can be edited from the console, so a quote
/// inside a name becomes a straight one: otherwise a name could close its quotes and append a second
/// change to the sentence. Invisible, direction-changing and look-alike characters are left as they
/// are here and spelled out once, at serve time, by `approval_display::ServedText`, which is what every
/// surface prints and the display digest binds.
pub fn quoted_name(name: &str) -> String {
    let name: String =
        name.trim().chars().map(|c| if QUOTE_LOOKALIKES.contains(&c) { '"' } else { c }).collect();
    if name.chars().count() <= MAX_NAME_CHARS {
        return format!("\u{201c}{name}\u{201d}");
    }
    let kept: String = name.chars().take(MAX_NAME_CHARS - 1).collect();
    format!("\u{201c}{kept}\u{2026}\u{201d}")
}

/// The first of `candidates` that is not blank, quoted, else `id` quoted.
fn shown(candidates: &[Option<&str>], id: &str) -> String {
    let name = candidates.iter().flatten().find(|n| !n.trim().is_empty()).copied().unwrap_or(id);
    quoted_name(name)
}

/// `parts` joined the way a sentence lists them: `a`, `a and b`, `a, b and c`.
fn listed(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// What a connection patch changes, one plain clause per field present.
fn patch_clauses(patch: &ConnPatch) -> Vec<String> {
    let mut parts = Vec::new();
    match patch.disabled {
        Some(true) => parts.push("pause it".to_string()),
        Some(false) => parts.push("resume it".to_string()),
        None => {}
    }
    if let Some(label) = &patch.label {
        parts.push(format!("rename it to {}", quoted_name(label)));
    }
    if let Some(name) = &patch.name {
        parts.push(format!("change its instance name to {}", quoted_name(name)));
    }
    let Some(ssh) = &patch.ssh else { return parts };
    let before = parts.len();
    if let Some(host) = &ssh.host {
        parts.push(format!("change its SSH host to {}", quoted_name(host)));
    }
    if let Some(port) = ssh.port {
        parts.push(format!("change its SSH port to {port}"));
    }
    if let Some(user) = &ssh.user {
        parts.push(format!("change its SSH user to {}", quoted_name(user)));
    }
    let new_key = ssh.host_key_sha256.as_deref().map(|k| !k.trim().is_empty());
    match (ssh.insecure, new_key) {
        (Some(true), Some(true)) => {
            parts.push("turn off host-key checking instead of using the new expected host key".to_string())
        }
        (Some(true), _) => parts.push("turn off host-key checking".to_string()),
        (_, Some(true)) => parts.push("change its expected host key".to_string()),
        (Some(false), _) => parts.push("leave host-key checking as it is".to_string()),
        (None, Some(false)) => parts.push("leave its expected host key as it is".to_string()),
        (None, None) => {}
    }
    match ssh.password_auth {
        Some(true) => parts.push("switch it to password sign-in".to_string()),
        Some(false) => parts.push("switch it to key sign-in".to_string()),
        None => {}
    }
    if parts.len() == before {
        parts.push("save its SSH settings unchanged".to_string());
    }
    parts
}

/// The approval floor in plain words, for a floor value this gateway knows.
fn plain_floor(floor: &str) -> Option<&'static str> {
    match crate::service::ApprovalFloor::from_str(floor)? {
        crate::service::ApprovalFloor::Approve => Some("an approval"),
        crate::service::ApprovalFloor::DeviceSigned => Some("a paired device's signature"),
    }
}

/// How many changes an edit's title lists before it counts the rest.
pub const MAX_LISTED_CHANGES: usize = 3;

/// Where one policy leaves one action, ordered least to most restrictive, the way the guard orders
/// access: a higher quorum is stricter, and an active deny is stricter than not mentioning the action,
/// because a deny also stops every other policy permitting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stance {
    Auto,
    Notify,
    Approve,
    Device(u8),
    Absent,
    Deny,
}

fn stance(p: &Policy, action: &str) -> Stance {
    match p.rung_for(action) {
        Some(Rung::Auto) => Stance::Auto,
        Some(Rung::Notify) => Stance::Notify,
        Some(Rung::Approve) => Stance::Approve,
        Some(Rung::DeviceSigned) => Stance::Device(p.quorum_for(action).unwrap_or(1)),
        Some(Rung::Deny) => Stance::Deny,
        None => Stance::Absent,
    }
}

fn stance_words(s: Stance) -> String {
    match s {
        Stance::Auto => "runs without asking".to_string(),
        Stance::Notify => "runs with a notification".to_string(),
        Stance::Approve => "needs approval".to_string(),
        Stance::Device(n) if n > 1 => format!("needs {n} paired devices"),
        Stance::Device(_) => "needs a paired device".to_string(),
        Stance::Absent => "is not allowed".to_string(),
        Stance::Deny => "is blocked".to_string(),
    }
}

/// The order changes are listed in: what widens access first, since that is what held the edit, then
/// grant membership, which can go either way, then what narrows access, then a rename.
const WIDENS: u8 = 0;
const MEMBERSHIP: u8 = 1;
const NARROWS: u8 = 2;
const RENAMES: u8 = 3;

/// `changes` as a title lists them: in order, at most [`MAX_LISTED_CHANGES`], then a count of the rest.
/// `None` when there is nothing to list.
fn listed_changes(mut changes: Vec<(u8, String)>) -> Option<String> {
    if changes.is_empty() {
        return None;
    }
    changes.sort_by_key(|(order, _)| *order);
    let rest = changes.len().saturating_sub(MAX_LISTED_CHANGES);
    let mut out =
        changes.into_iter().take(MAX_LISTED_CHANGES).map(|(_, text)| text).collect::<Vec<_>>().join("; ");
    if rest > 0 {
        out.push_str(&format!("; and {rest} more change{}", if rest == 1 { "" } else { "s" }));
    }
    Some(out)
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// What replacing `old` with `new` changes, for the policy's title. `before` and `after` are the grants
/// that include it now and the ones the edit syncs it to, when the edit syncs membership at all.
fn policy_changes(
    old: &Policy,
    new: &Policy,
    before: Option<&[String]>,
    after: Option<&[String]>,
    names: &impl MutationNames,
) -> Vec<(u8, String)> {
    let mut changes = Vec::new();
    let mut actions: Vec<&str> = actions_of(old).chain(actions_of(new)).collect();
    actions.sort_unstable();
    actions.dedup();
    for action in actions {
        let (was, now) = (stance(old, action), stance(new, action));
        if was != now {
            let order = if now < was { WIDENS } else { NARROWS };
            changes.push((order, format!("{action}: {} \u{2192} {}", stance_words(was), stance_words(now))));
        }
    }
    if old.connection_id != new.connection_id {
        let from = shown(&[names.connection(&old.connection_id).name()], &old.connection_id);
        changes.push((WIDENS, format!("moved from {from}")));
    }
    let hidden = |p: &Policy, f: &String| p.redact_fields.iter().any(|g| g.eq_ignore_ascii_case(f));
    let fewer = old.redact_fields.iter().filter(|f| !hidden(new, f)).count();
    let more = new.redact_fields.iter().filter(|f| !hidden(old, f)).count();
    let fields = |n: usize| if n == 1 { "field" } else { "fields" };
    if fewer > 0 {
        changes.push((WIDENS, format!("hides {fewer} fewer {}", fields(fewer))));
    }
    if more > 0 {
        changes.push((NARROWS, format!("hides {more} more {}", fields(more))));
    }
    if let (Some(before), Some(after)) = (before, after) {
        let grant = |id: &String| shown(&[names.grant(id).name()], id);
        for id in after.iter().filter(|id| !before.contains(id)) {
            changes.push((MEMBERSHIP, format!("now on {}", grant(id))));
        }
        for id in before.iter().filter(|id| !after.contains(id)) {
            changes.push((MEMBERSHIP, format!("no longer on {}", grant(id))));
        }
    }
    if !new.name.trim().is_empty() && new.name.trim() != old.name.trim() {
        changes.push((RENAMES, format!("renamed to {}", quoted_name(&new.name))));
    }
    changes
}

fn limit_words(limit: Option<u64>) -> String {
    limit.map_or_else(|| "no limit".to_string(), |n| n.to_string())
}

fn period_words(period: &permaura_core::GrantPeriod) -> &'static str {
    match period {
        permaura_core::GrantPeriod::Day => "per day",
        permaura_core::GrantPeriod::Week => "per week",
        permaura_core::GrantPeriod::Month => "per 30 days",
        permaura_core::GrantPeriod::Total => "in total",
    }
}

fn expiry_words(expiry: Option<time::OffsetDateTime>) -> String {
    match expiry {
        None => "never".to_string(),
        Some(t) => {
            let t = t.to_offset(time::UtcOffset::UTC);
            format!("{}-{:02}-{:02} {:02}:{:02} UTC", t.year(), u8::from(t.month()), t.day(), t.hour(), t.minute())
        }
    }
}

/// What replacing `old` with `new` changes, for the grant's title.
fn grant_changes(old: &Grant, new: &Grant, names: &impl MutationNames) -> Vec<(u8, String)> {
    let mut changes = Vec::new();
    let agent = |id: &str| shown(&[names.agent(id).name()], id);
    let order = |widens: bool| if widens { WIDENS } else { NARROWS };
    if new.enabled != old.enabled {
        changes.push((order(new.enabled), if new.enabled { "turned on" } else { "paused" }.to_string()));
    }
    if new.is_default != old.is_default {
        let text = if new.is_default { "made the Default" } else { "no longer the Default" };
        changes.push((order(new.is_default), text.to_string()));
    }
    match (&old.agents, &new.agents) {
        (GrantAgents::Agents(_), GrantAgents::AllAgents) => changes.push((WIDENS, "now covers every agent".to_string())),
        (GrantAgents::AllAgents, GrantAgents::Agents(members)) => {
            let shown: Vec<String> = members.iter().take(MAX_LISTED_CHANGES).map(|m| agent(&m.agent_id)).collect();
            let who = match members.len() {
                0 => "no agents".to_string(),
                n if n > MAX_LISTED_CHANGES => {
                    format!("{} and {}", shown.join(", "), plural(n - MAX_LISTED_CHANGES, "more agent", "more agents"))
                }
                _ => listed(&shown),
            };
            changes.push((NARROWS, format!("covers only {who} instead of every agent")));
        }
        (GrantAgents::Agents(was), GrantAgents::Agents(now)) => {
            for m in now.iter().filter(|m| !was.iter().any(|w| w.agent_id == m.agent_id)) {
                changes.push((WIDENS, format!("now covers {}", agent(&m.agent_id))));
            }
            for w in was.iter().filter(|w| !now.iter().any(|m| m.agent_id == w.agent_id)) {
                changes.push((NARROWS, format!("no longer covers {}", agent(&w.agent_id))));
            }
            for m in now {
                let Some(w) = was.iter().find(|w| w.agent_id == m.agent_id) else { continue };
                if w.per_agent_limit != m.per_agent_limit {
                    let words = |l: Option<u64>| l.map_or_else(|| "the grant's default".to_string(), |n| n.to_string());
                    changes.push((
                        order(!limit_is_tighter_or_equal(w.per_agent_limit, m.per_agent_limit)),
                        format!("limit for {}: {} \u{2192} {}", agent(&m.agent_id), words(w.per_agent_limit), words(m.per_agent_limit)),
                    ));
                }
            }
        }
        (GrantAgents::AllAgents, GrantAgents::AllAgents) => {}
    }
    let policy = |id: &String| shown(&[names.policy(id).name()], id);
    for id in new.policy_ids.iter().filter(|id| !old.policy_ids.contains(id)) {
        changes.push((WIDENS, format!("now includes {}", policy(id))));
    }
    for id in old.policy_ids.iter().filter(|id| !new.policy_ids.contains(id)) {
        changes.push((NARROWS, format!("no longer includes {}", policy(id))));
    }
    if new.overall_limit != old.overall_limit {
        changes.push((
            order(!limit_is_tighter_or_equal(old.overall_limit, new.overall_limit)),
            format!("overall limit: {} \u{2192} {}", limit_words(old.overall_limit), limit_words(new.overall_limit)),
        ));
    }
    if new.default_per_agent_limit != old.default_per_agent_limit {
        changes.push((
            order(!limit_is_tighter_or_equal(old.default_per_agent_limit, new.default_per_agent_limit)),
            format!(
                "limit per agent: {} \u{2192} {}",
                limit_words(old.default_per_agent_limit),
                limit_words(new.default_per_agent_limit)
            ),
        ));
    }
    // Any change of window can multiply the allowance, which is why the guard holds every one.
    if new.period != old.period {
        changes.push((WIDENS, format!("budget period: {} \u{2192} {}", period_words(&old.period), period_words(&new.period))));
    }
    if new.expires_at != old.expires_at {
        changes.push((
            order(expiry_extends(old.expires_at, new.expires_at)),
            format!("expiry: {} \u{2192} {}", expiry_words(old.expires_at), expiry_words(new.expires_at)),
        ));
    }
    if !new.name.trim().is_empty() && new.name.trim() != old.name.trim() {
        changes.push((RENAMES, format!("renamed to {}", quoted_name(&new.name))));
    }
    changes
}

impl Mutation {
    /// A one-line summary that names things by id, for a caller with no store. Every hold path uses
    /// [`Self::summary_in`].
    pub fn summary(&self) -> String {
        self.summary_in(&NoStore)
    }

    /// The title an approver reads for this change: plain words, with the display names `names` has
    /// for what it touches, and the id wherever a name is missing or blank.
    ///
    /// The ids stay in the approval's params, which every surface can show as details, so the title
    /// repeats none except where a name is absent and the key fingerprints. Those two are the
    /// security content of a pairing: a co-signer who cannot see WHICH key is being trusted cannot
    /// tell the owner's watch from an attacker's key under the same id, and because
    /// `ApproverKeyring::add` inserts over an existing id, a replacement has to say it replaces.
    ///
    /// An edit of a stored policy or grant also says what it changes, because the params hold the whole
    /// proposed record and the loosening that held it is one line among many there.
    pub fn summary_in(&self, names: &impl MutationNames) -> String {
        let connection = |id: &str| shown(&[names.connection(id).name()], id);
        match self {
            Mutation::PolicyUpsert { policy, grant_ids } => {
                let stored = names.policy(&policy.id);
                let (verb, name) = match stored {
                    Stored::Found(_) => ("Change", shown(&[stored.name(), Some(&policy.name)], &policy.id)),
                    Stored::Missing => ("Add", shown(&[Some(&policy.name)], &policy.id)),
                    Stored::Unknown => ("Add or change", shown(&[Some(&policy.name)], &policy.id)),
                };
                let head = format!("{verb} the policy {name} for {}", connection(&policy.connection_id));
                let before = names.grants_including(&policy.id);
                let changes = names.policy_record(&policy.id).and_then(|old| {
                    listed_changes(policy_changes(&old, policy, before.as_deref(), grant_ids.as_deref(), names))
                });
                match changes {
                    Some(changes) => format!("{head}: {changes}"),
                    None => head,
                }
            }
            Mutation::PolicyDelete { policy_id } => {
                let name = shown(&[names.policy(policy_id).name()], policy_id);
                match names.policy_record(policy_id) {
                    Some(stored) => format!("Delete the policy {name} for {}", connection(&stored.connection_id)),
                    None => format!("Delete the policy {name}"),
                }
            }
            Mutation::SecretDelete { secret_id } => match names.secret_owner(secret_id) {
                Stored::Found(owner) if !owner.trim().is_empty() => {
                    format!("Delete the saved credential for {}", quoted_name(&owner))
                }
                _ => format!("Delete the saved credential {}", quoted_name(secret_id)),
            },
            Mutation::AgentDelete { agent_id } => {
                format!("Remove the agent {}", shown(&[names.agent(agent_id).name()], agent_id))
            }
            Mutation::ConnectionDelete { connection_id } => {
                format!("Delete the connection {} and everything that uses it", connection(connection_id))
            }
            Mutation::GrantUpsert { grant } => {
                let stored = names.grant(&grant.grant_id);
                let (verb, name) = match stored {
                    Stored::Found(_) => ("Change", shown(&[stored.name(), Some(&grant.name)], &grant.grant_id)),
                    Stored::Missing => ("Add", shown(&[Some(&grant.name)], &grant.grant_id)),
                    Stored::Unknown => ("Add or change", shown(&[Some(&grant.name)], &grant.grant_id)),
                };
                let head = format!("{verb} the grant {name}");
                match names.grant_record(&grant.grant_id).and_then(|old| listed_changes(grant_changes(&old, grant, names))) {
                    Some(changes) => format!("{head}: {changes}"),
                    None => head,
                }
            }
            Mutation::GrantDelete { grant_id } => {
                format!("Delete the grant {}", shown(&[names.grant(grant_id).name()], grant_id))
            }
            Mutation::CapabilityEnable { connection_id, capability } => {
                let action = capability
                    .strip_prefix(connection_id.as_str())
                    .and_then(|rest| rest.strip_prefix('.'))
                    .filter(|a| !a.is_empty())
                    .unwrap_or(capability);
                format!("Turn on {} for {}", quoted_name(action), connection(connection_id))
            }
            Mutation::ConnectionPatch { connection_id, patch } => {
                let head = format!("Change the connection {}", connection(connection_id));
                match patch_clauses(patch) {
                    parts if parts.is_empty() => head,
                    parts => format!("{head}: {}", listed(&parts)),
                }
            }
            Mutation::AgentApprove { agent_id } => {
                format!("Let the agent {} connect", shown(&[names.agent(agent_id).name()], agent_id))
            }
            Mutation::AgentUpsert { agent } => format!(
                "Add and approve the agent {}",
                shown(&[Some(&agent.name), names.agent(&agent.id).name()], &agent.id)
            ),
            Mutation::CredentialPromote { connection_id, .. } => {
                let head = format!("Save the new credential for {}", connection(connection_id));
                match names.connection_hosts(connection_id) {
                    hosts if hosts.is_empty() => head,
                    hosts => format!("{head}, sent to {}", listed(&hosts)),
                }
            }
            Mutation::BrokerToggle { toggle, value } => match (toggle, value) {
                (BrokerToggleKind::Pause, true) => "Pause every agent".to_string(),
                (BrokerToggleKind::Pause, false) => "Resume every agent".to_string(),
                (BrokerToggleKind::RequireAgentApproval, true) => {
                    "Require approval before new agents can act".to_string()
                }
                (BrokerToggleKind::RequireAgentApproval, false) => {
                    "Let new agents act without approval".to_string()
                }
            },
            // The fingerprint is `service::key_fingerprint`, the crate's ONE scheme, the same one the
            // collected signatures and the ticket binding are matched on. A second scheme here would
            // print a value that looked like the key's identity but matched nothing else in the
            // system, which is worse than printing none.
            Mutation::ApproverKeyTrust { approver_id, approver_pubkey, person, .. } => {
                let device = shown(&[names.device(approver_id).name()], approver_id);
                let fp = crate::service::key_fingerprint(approver_pubkey);
                let title = match names.displaced_key(approver_id, approver_pubkey) {
                    Some(old) => format!(
                        "Replace the trusted key for {device}: key {} becomes {fp}",
                        crate::service::key_fingerprint(&old)
                    ),
                    None => format!("Trust {device} to approve (key {fp})"),
                };
                match person {
                    Some(person) => format!("{title} for {}", quoted_name(person)),
                    None => title,
                }
            }
            Mutation::ApprovalFloorSet { floor } => match floor {
                Some(f) => {
                    let floor = plain_floor(f).map(quoted_name).unwrap_or_else(|| quoted_name(f));
                    format!("Require at least {floor} for every held action")
                }
                None => "Remove the minimum approval override".to_string(),
            },
            Mutation::ApproverKeyRevoke { approver_id } if names.last_trusted_device(approver_id) => format!(
                "Remove {}, the last trusted device. After this nothing will need a device signature",
                shown(&[names.device(approver_id).name()], approver_id)
            ),
            Mutation::ApproverKeyRevoke { approver_id } => format!(
                "Remove {} from the trusted devices, so it can no longer approve anything",
                shown(&[names.device(approver_id).name()], approver_id)
            ),
            Mutation::ConnectorInstall { manifest, version, provenance } => {
                let text = |key: &str| manifest.get(key).and_then(serde_json::Value::as_str).unwrap_or_default();
                let id = text("id");
                let trust = match provenance {
                    crate::manifest::Provenance::Signed { .. } => "Permaura-signed",
                    crate::manifest::Provenance::User => "unsigned",
                };
                let head = format!(
                    "Install version {version} of the {trust} connector {} ({})",
                    shown(&[Some(text("name"))], id),
                    quoted_name(id)
                );
                let sent = match crate::connectors::shown_host(text("base_url")) {
                    Some(host) => format!("{head}, which sends credentials to {host}"),
                    None => format!("{head}, which sends credentials to a host each connection sets"),
                };
                let Some(oauth) = manifest.get("oauth").filter(|o| o.is_object()) else { return sent };
                let host = |key: &str| {
                    oauth
                        .get(key)
                        .and_then(serde_json::Value::as_str)
                        .and_then(crate::connectors::shown_host)
                        .unwrap_or_else(|| "an address that names no host".into())
                };
                format!(
                    "{sent}, its OAuth client secret and authorization codes to {}, and its OAuth sign-in to {}",
                    host("token_url"),
                    host("authorize_url")
                )
            }
            Mutation::ConnectorRemove { connector_id } => {
                format!("Remove the installed connector {} from the catalog", quoted_name(connector_id))
            }
            Mutation::CapabilityPosture { connection_id, capability, risk, requires_approval, from } => {
                let action = capability
                    .strip_prefix(connection_id.as_str())
                    .and_then(|rest| rest.strip_prefix('.'))
                    .filter(|a| !a.is_empty())
                    .unwrap_or(capability);
                let gate = |approval: bool| if approval { "an approval on every call" } else { "no approval of its own" };
                format!(
                    "Set {} on {} ({} {}) to {risk} risk with {}, where it was {} risk with {}",
                    quoted_name(action),
                    connection(connection_id),
                    from.method.as_str(),
                    crate::service::quoted_http_path(&from.path),
                    gate(*requires_approval || *risk >= RiskTier::High),
                    from.risk,
                    gate(from.requires_approval || from.risk >= RiskTier::High)
                )
            }
        }
    }
}

/// The store snapshot a classifier reads to decide whether a mutation loosens authorization. Held
/// by reference so [`is_strictly_tightening`] never copies the whole store.
pub struct GuardContext<'a> {
    /// Every policy currently in the store.
    pub policies: &'a [Policy],
    /// Every grant currently in the store.
    pub grants: &'a [Grant],
    /// Every connection currently in the store.
    pub connections: &'a [Connection],
    /// Every registered agent currently in the store.
    pub agents: &'a [Agent],
}

/// How permissive an action is, as the pair the ladder actually decides it by: the rung, and how many
/// distinct devices must sign at that rung. Ordered least → most restrictive, so the derived `Ord`
/// reads exactly as the engine does: rung first, and between two `device_signed` permits the one
/// asking for fewer signatures is the more permissive. A quorum only means anything at
/// `device_signed`; every lower rung pairs with `1`, which is inert because the rung already
/// separates them.
type Access = (Rung, u8);

/// What the engine puts on `action` for `agent` on `connection_id`: `None` when it denies the action,
/// else the rung and quorum it would hold a call at. This IS [`PolicyEngine::resolve`], so the guard and
/// the enforcement path share one definition of what is in force. Budget is left out (an exhausted
/// grant still contributes its rung, exactly as it does in the engine) and so is the capability's own
/// risk floor, which an edit to policies or grants cannot move.
fn engine_access(
    engine: &PolicyEngine,
    agent: &str,
    connection_id: &str,
    action: &str,
    now: time::OffsetDateTime,
) -> Option<Access> {
    let input = DecisionInput {
        capability_id: action.to_string(),
        action: permaura_core::Action::Read,
        connection_id: connection_id.to_string(),
        risk: RiskTier::Low,
        capability_requires_approval: false,
        agent_id: agent.to_string(),
        context: RequestContext::new(String::new(), now),
    };
    let r = engine.resolve(&input, &Unmetered);
    (r.decision.kind != DecisionKind::Deny).then_some((r.rung, r.quorum))
}

/// An all-agents grant binding `policy_ids`: the worst case of who a policy might share a grant with.
fn binding_of(policy_ids: Vec<String>) -> Grant {
    Grant {
        grant_id: String::new(),
        name: String::new(),
        enabled: true,
        is_default: false,
        policy_ids,
        agents: GrantAgents::AllAgents,
        period: permaura_core::GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    }
}

/// Whether replacing `old` with `new` (either absent for a create or a delete) can lower what the engine
/// puts on any action for an agent bound to that policy, whichever of the other policies in `others` it
/// shares a grant with. The engine takes the most restrictive bar over every permitting policy and lets
/// any deny win, so the worst case is the policy alone or beside exactly one other: a second permit can
/// only raise the bar, and a deny makes both sides equal.
fn policy_edit_loosens(others: &[Policy], old: Option<&Policy>, new: Option<&Policy>) -> bool {
    policy_edit_loosening(others, old, new).is_some()
}

/// [`policy_edit_loosens`], answering with the highest quorum any loosened action demands before the
/// edit, or `None` when nothing loosens.
fn policy_edit_loosening(others: &[Policy], old: Option<&Policy>, new: Option<&Policy>) -> Option<u8> {
    let now = time::OffsetDateTime::now_utc();
    let mut scope: Vec<(&str, &str)> = old
        .into_iter()
        .chain(new)
        .flat_map(|p| actions_of(p).map(move |a| (p.connection_id.as_str(), a)))
        .collect();
    scope.sort_unstable();
    scope.dedup();
    let engine = |edited: Option<&Policy>, beside: Option<&Policy>| {
        let policies: Vec<Policy> = edited.into_iter().chain(beside).cloned().collect();
        let ids = policies.iter().map(|p| p.id.clone()).collect();
        PolicyEngine::with(vec![binding_of(ids)], policies)
    };
    scope
        .iter()
        .flat_map(|(conn, action)| {
            std::iter::once(None)
                .chain(others.iter().filter(|o| o.connection_id == *conn).map(Some))
                .filter_map(|beside| {
                    loosened(
                        engine_access(&engine(old, beside), "", conn, action, now),
                        engine_access(&engine(new, beside), "", conn, action, now),
                    )
                })
                .collect::<Vec<_>>()
        })
        .max()
}

/// Is `after` a more permissive ceiling than `before`? `None` (denied) is the most restrictive, so
/// denied→permitted is a loosening, as is any drop to a lower rung, or, at the same rung, a drop in
/// the number of devices that must sign. Without that second term a 2-of-2 edited down to 1-of-1
/// compared equal, so the guard called the edit tightening and applied it unsigned over the broker:
/// the two-person rule removable by exactly the semi-trusted control plane it exists to survive.
fn loosens(before: Option<Access>, after: Option<Access>) -> bool {
    match (before, after) {
        (None, Some(_)) => true,           // newly permitted (deny-by-default → permitted)
        (Some(b), Some(a)) => a < b,        // permit rung, or its quorum, became more permissive
        (_, None) => false,                 // became denied (or stayed denied), never a loosening
    }
}

/// When `before` → `after` loosens, the quorum `before` demands: what a change that lowers the bar has
/// to clear, so one device cannot remove a rule that takes two. A newly permitted action had no quorum.
fn loosened(before: Option<Access>, after: Option<Access>) -> Option<u8> {
    loosens(before, after).then(|| before.map_or(1, |(_, q)| q.max(1)))
}

/// Whether moving from `before` to `after` (policies and grants) lowers what the engine puts on any action
/// for any agent, at any moment from now on: a rung or a quorum dropped, or an action newly permitted.
///
/// Every agent some grant names is resolved by id, and one id no grant names stands for every other
/// agent, which only an all-agents grant reaches. The engine applies the most restrictive bar over every
/// permitting policy of every live grant that reaches the agent, so disabling, unbinding or editing the
/// grant or policy that carries the strict bar is a loosening even while a laxer policy stays bound. So is
/// bringing that grant's expiry forward, though nothing differs until the new expiry passes, which is why
/// each side is resolved at every moment in [`moments`]. Past [`CLASSIFICATION_BUDGET`] it answers that the change
/// loosens, at the most people any rule on the connections it touches asks for.
fn any_principal_loosens(before: (&[Policy], &[Grant]), after: (&[Policy], &[Grant])) -> bool {
    principal_loosening(before, after).is_some()
}

/// The grants on any of `sides` that can be a candidate on one of `connections`: those binding a policy (from any of
/// `policies`) scoped to it. Whether another grant is live never changes what the engine answers there.
fn bearing_on<'a>(sides: &[&'a [Grant]], policies: &[&[Policy]], connections: &[&str]) -> Vec<&'a Grant> {
    let on = |id: &String| {
        policies.iter().flat_map(|side| side.iter()).any(|p| &p.id == id && connections.contains(&p.connection_id.as_str()))
    };
    sides.iter().flat_map(|side| side.iter()).filter(|g| g.policy_ids.iter().any(on)).collect()
}

/// Now, and every later moment one of `grants` that reaches `agent` expires. A grant is live until its expiry and
/// nothing else in the engine reads the clock, so what `agent` is answered through `grants` changes only at these
/// moments, and resolving at each is resolving at every moment from now on.
fn moments(agent: &str, grants: &[&Grant], now: time::OffsetDateTime) -> Vec<time::OffsetDateTime> {
    let mut at: Vec<time::OffsetDateTime> =
        grants.iter().filter(|g| g.targets(agent)).flat_map(|g| g.authorization_change_points()).filter(|e| *e > now).collect();
    at.push(now);
    at.sort();
    at.dedup();
    at
}

/// Each of `agents` with the moments at which what it is answered through `grants` can change.
fn moments_of<'a>(agents: &'a [String], grants: &[&Grant], now: time::OffsetDateTime) -> Vec<(&'a str, Vec<time::OffsetDateTime>)> {
    agents.iter().map(|a| (a.as_str(), moments(a, grants, now))).collect()
}

/// What one classification may spend, in the [`estate_cost`] of each resolve. Past it the guard answers as a loosening
/// held and confirmed at [`past_budget_quorum`]; with no ceiling, an estate whose grants each end at their own moment
/// made every classification grow with the cube of its size. A unit takes about 10 ns where grants dominate the cost and
/// under 1 ns where action lists do, so this keeps one classification near three seconds at worst while an owner's
/// 1,500-action site, or twenty agents on time-boxed grants over thirty policies, is still worked out in full.
const CLASSIFICATION_BUDGET: u64 = 300_000_000;

/// Whether `resolves` against an estate whose [`estate_cost`] is `cost` fits [`CLASSIFICATION_BUDGET`].
fn within_budget(resolves: usize, cost: usize) -> bool {
    (resolves as u64).saturating_mul(cost.max(1) as u64) <= CLASSIFICATION_BUDGET
}

/// Include the membership scan and every policy-id lookup each engine resolution performs.
fn estate_cost(grants: &[Grant], policies: &[Policy]) -> usize {
    grants.iter().fold(policies.iter().map(|p| actions_of(p).count()).sum::<usize>(), |cost, g| {
        let members = match &g.agents { permaura_core::GrantAgents::AllAgents => 1, permaura_core::GrantAgents::Agents(rows) => rows.len().max(1) };
        cost.saturating_add(1).saturating_add(members).saturating_add(g.policy_ids.len().saturating_mul(policies.len().max(1)))
    })
}

/// How many resolves checking every action in `scope` for every agent at its moments takes, on `sides` estates.
fn resolves_for(scope: usize, moments: &[(&str, Vec<time::OffsetDateTime>)], sides: usize) -> usize {
    scope.saturating_mul(moments.iter().map(|(_, at)| at.len()).sum::<usize>()).saturating_mul(sides)
}

/// The most people any rule among `policies` on `connections` asks for: never less than what a change there can
/// lower, for a classification that stops at its budget.
fn most_people_on(policies: &[Policy], connections: &[&str]) -> u8 {
    policies
        .iter()
        .filter(|p| !p.device_signed.is_empty() && connections.contains(&p.connection_id.as_str()))
        .map(|p| p.device_signed_quorum.max(1))
        .max()
        .unwrap_or(1)
}

/// [`any_principal_loosens`], answering with the highest quorum any loosened (agent, action) demands
/// before the change, or `None` when nothing loosens.
fn principal_loosening(before: (&[Policy], &[Grant]), after: (&[Policy], &[Grant])) -> Option<u8> {
    match lowerings(before, after, &[]) {
        Ok(found) => found.iter().map(|l| l.before.map_or(1, |(_, q)| q.max(1))).max(),
        Err(PastBudget(most)) => Some(most),
    }
}

/// One (agent, connection, action) at one moment where a change lowers what the engine puts on the action.
struct Lowered<'a> {
    agent: String,
    connection: &'a str,
    action: &'a str,
    before: Option<Access>,
    after: Access,
}

/// A classification that stopped at [`CLASSIFICATION_BUDGET`], with the most people any rule on the connections it
/// touched asks for.
struct PastBudget(u8);

/// The connections moving from `before` to `after` can change what the engine answers on: those a changed policy, or a
/// policy a changed grant binds, sits on.
fn affected_connections<'a>(before: (&'a [Policy], &'a [Grant]), after: (&'a [Policy], &'a [Grant])) -> Vec<&'a str> {
    let changed_policies = before.0.iter().chain(after.0).filter(|p| {
        let other = if before.0.contains(p) { after.0 } else { before.0 };
        !other.contains(p)
    });
    let changed_grants = before.1.iter().chain(after.1).filter(|g| {
        let other = if before.1.contains(g) { after.1 } else { before.1 };
        !other.contains(g)
    });
    let mut affected: Vec<&str> = changed_policies.map(|p| p.connection_id.as_str()).collect();
    for g in changed_grants {
        affected.extend(
            before.0.iter().chain(after.0).filter(|p| g.policy_ids.contains(&p.id)).map(|p| p.connection_id.as_str()),
        );
    }
    affected.sort_unstable();
    affected.dedup();
    affected
}

/// The quorum a change whose effect could not be worked out within [`CLASSIFICATION_BUDGET`] is held and confirmed at:
/// the most people any rule on the connections it touches asks for, and the highest mark there. Whatever it lowers was
/// held at no more than that, so the change is never applied on fewer signatures than what it lowers took, and never
/// stranded for being too large to compare.
pub fn past_budget_quorum(mutation: &Mutation, ctx: &GuardContext, marks: &std::collections::BTreeMap<ActionKey, u8>) -> u8 {
    let Some((policies, grants)) = binding_state_after(mutation, ctx) else { return 1 };
    let affected = affected_connections((ctx.policies, ctx.grants), (&policies, &grants));
    let marked = marks.iter().filter(|((conn, _), _)| affected.contains(&conn.as_str())).map(|(_, q)| *q).max().unwrap_or(1);
    most_people_on(ctx.policies, &affected).max(marked)
}

/// Every (agent, connection, action, moment) at which moving from `before` to `after` lowers what the engine puts on the
/// action, over every agent a grant on either side names, every one of `also` (resolved by id whether a grant names it
/// or not), and one id that stands for every other agent.
fn lowerings<'a>(
    before: (&'a [Policy], &'a [Grant]),
    after: (&'a [Policy], &'a [Grant]),
    also: &[String],
) -> Result<Vec<Lowered<'a>>, PastBudget> {
    let now = time::OffsetDateTime::now_utc();
    let mut agents = principals(before.1, after.1);
    for id in also {
        if !agents.contains(id) {
            agents.push(id.clone());
        }
    }
    let affected = affected_connections(before, after);
    let mut scope: Vec<(&str, &str)> = before
        .0
        .iter()
        .chain(after.0)
        .filter(|p| affected.contains(&p.connection_id.as_str()))
        .flat_map(|p| actions_of(p).map(move |a| (p.connection_id.as_str(), a)))
        .collect();
    scope.sort_unstable();
    scope.dedup();
    if !within_budget(agents.len().saturating_mul(2), estate_cost(before.1, before.0).max(estate_cost(after.1, after.0))) {
        return Err(PastBudget(most_people_on(before.0, &affected)));
    }
    let moments = moments_of(&agents, &bearing_on(&[before.1, after.1], &[before.0, after.0], &affected), now);
    let cost = estate_cost(before.1, before.0).max(estate_cost(after.1, after.0));
    if !within_budget(resolves_for(scope.len(), &moments, 2).saturating_add(agents.len().saturating_mul(2)), cost) {
        return Err(PastBudget(most_people_on(before.0, &affected)));
    }
    let was = PolicyEngine::with(before.1.to_vec(), before.0.to_vec());
    let now_is = PolicyEngine::with(after.1.to_vec(), after.0.to_vec());
    let mut found = Vec::new();
    for (connection, action) in scope {
        for (agent, at) in &moments {
            for at in at {
                let (was, is) = (engine_access(&was, agent, connection, action, *at), engine_access(&now_is, agent, connection, action, *at));
                if let (true, Some(after)) = (loosens(was, is), is) {
                    found.push(Lowered { agent: agent.to_string(), connection, action, before: was, after });
                }
            }
        }
    }
    Ok(found)
}

/// One principal, connection and action a held change lowers, and the most permissive rung and quorum it falls to
/// there at any moment from now on. `principal` is an agent id, or `None` for every agent no grant names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweredTo {
    /// The agent, or `None` for every agent no grant named.
    pub principal: Option<String>,
    /// The connection the action is on.
    pub connection: String,
    /// The action.
    pub action: String,
    /// The rung it falls to.
    pub rung: Rung,
    /// The devices that rung asks for.
    pub quorum: u8,
}

/// What a held policy or grant change loosens, worked out on the estate it was held against: every principal,
/// connection and action it lowers, with the agents grants named then. Kept by the gateway beside the hold, so the
/// confirm can tell a change whose effect has since grown, because another change removed what masked it, from the
/// change that was asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Loosening {
    /// The agents a grant named when it was worked out.
    pub named: Vec<String>,
    /// What it lowers, one entry per principal, connection and action.
    pub lowered: Vec<LoweredTo>,
}

/// What working out a held change's effect came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldEffect {
    /// The change is not a direct policy or grant edit (a connection or agent delete included, whatever its cascade removes), so there is no lowering for another change to unmask.
    NotBinding,
    /// Working it out would have passed [`CLASSIFICATION_BUDGET`], so a confirm cannot prove that its effect stayed within the held effect.
    PastBudget,
    /// What it lowers.
    Lowers(Loosening),
}

/// What `mutation` loosens on the estate in `ctx`, with every agent in `also` resolved by id: at the confirm, the
/// agents named when the change was held, so one a grant named then is never read as an agent no grant names.
pub fn held_effect(mutation: &Mutation, ctx: &GuardContext, also: &[String]) -> HeldEffect {
    let Some((policies, grants)) = binding_state_after(mutation, ctx) else { return HeldEffect::NotBinding };
    let mut named: Vec<String> = ctx.grants.iter().chain(&grants).flat_map(|g| g.agent_ids()).collect();
    named.sort();
    named.dedup();
    let found = match lowerings((ctx.policies, ctx.grants), (&policies, &grants), also) {
        Ok(found) => found,
        Err(PastBudget(_)) => return HeldEffect::PastBudget,
    };
    let mut lowered: std::collections::BTreeMap<(Option<String>, &str, &str), Access> = std::collections::BTreeMap::new();
    for l in found {
        let principal = (named.contains(&l.agent) || also.contains(&l.agent)).then(|| l.agent.clone());
        let lowest = lowered.entry((principal, l.connection, l.action)).or_insert(l.after);
        *lowest = (*lowest).min(l.after);
    }
    let mut all_named = named;
    all_named.extend(also.iter().cloned());
    all_named.sort();
    all_named.dedup();
    HeldEffect::Lowers(Loosening {
        named: all_named,
        lowered: lowered
            .into_iter()
            .map(|((principal, connection, action), (rung, quorum))| LoweredTo {
                principal,
                connection: connection.to_string(),
                action: action.to_string(),
                rung,
                quorum,
            })
            .collect(),
    })
}

impl Loosening {
    /// The first thing `now` lowers that this record, kept when the change was held, did not, or lowers further. An agent
    /// no grant named then is compared with what the change lowered for every such agent.
    pub fn widened_in(&self, now: &Loosening) -> Option<String> {
        now.lowered.iter().find_map(|l| {
            let then = match &l.principal {
                Some(agent) if self.named.contains(agent) => Some(agent.clone()),
                _ => None,
            };
            let recorded = self
                .lowered
                .iter()
                .find(|r| r.principal == then && r.connection == l.connection && r.action == l.action);
            let who = l.principal.as_deref().unwrap_or("an agent no grant names");
            match recorded {
                None => Some(format!("{}.{} for {who} now falls to {:?} x{}, which it did not when the change was held", l.connection, l.action, l.rung, l.quorum)),
                Some(r) if (l.rung, l.quorum) < (r.rung, r.quorum) => Some(format!(
                    "{}.{} for {who} now falls to {:?} x{}, below the {:?} x{} it fell to when the change was held",
                    l.connection, l.action, l.rung, l.quorum, r.rung, r.quorum
                )),
                Some(_) => None,
            }
        })
    }
}

/// The quorum a held `mutation` needs when the estate cannot raise it: one device, for every kind except a direct policy
/// or grant edit and the approval floor, since [`hold_quorum_with_marks`] reads the estate only for those. A connection
/// or agent delete is one of the one-device kinds, even though its cascade removes policies or grant members.
/// `None` for those, whose quorum is worked out from the estate. Every kind is named, so a new one is placed here.
pub fn quorum_without_estate(mutation: &Mutation) -> Option<u8> {
    match mutation {
        Mutation::PolicyUpsert { .. }
        | Mutation::PolicyDelete { .. }
        | Mutation::GrantUpsert { .. }
        | Mutation::GrantDelete { .. }
        | Mutation::ApprovalFloorSet { .. } => None,
        Mutation::SecretDelete { .. }
        | Mutation::AgentDelete { .. }
        | Mutation::ConnectionDelete { .. }
        | Mutation::CapabilityEnable { .. }
        | Mutation::CapabilityPosture { .. }
        | Mutation::ConnectionPatch { .. }
        | Mutation::AgentApprove { .. }
        | Mutation::AgentUpsert { .. }
        | Mutation::CredentialPromote { .. }
        | Mutation::BrokerToggle { .. }
        | Mutation::ApproverKeyTrust { .. }
        | Mutation::ApproverKeyRevoke { .. }
        | Mutation::ConnectorInstall { .. }
        | Mutation::ConnectorRemove { .. } => Some(1),
    }
}

/// The policy and grant sets `mutation` leaves behind as `apply_mutation` writes them, a promotion to the Default
/// included, or `None` for a change that moves neither.
pub(crate) fn estate_after(mutation: &Mutation, ctx: &GuardContext) -> Option<(Vec<Policy>, Vec<Grant>)> {
    let (policies, mut grants) = binding_state_after(mutation, ctx)?;
    if let Mutation::GrantUpsert { grant } = mutation {
        if grant.is_default {
            for g in grants.iter_mut().filter(|g| g.grant_id != grant.grant_id) {
                g.is_default = false;
            }
        }
    }
    Some((policies, grants))
}

/// The policy and grant sets a policy/grant mutation leaves behind, mirroring `apply_mutation`: a
/// policy upsert's `grant_ids` sync adds the policy to exactly those grants and removes it from the
/// rest, and a policy delete detaches it everywhere. `None` for any other mutation.
fn binding_state_after(mutation: &Mutation, ctx: &GuardContext) -> Option<(Vec<Policy>, Vec<Grant>)> {
    let mut policies = ctx.policies.to_vec();
    let mut grants = ctx.grants.to_vec();
    match mutation {
        Mutation::PolicyUpsert { policy, grant_ids } => {
            policies.retain(|p| p.id != policy.id);
            policies.push(policy.clone());
            if let Some(ids) = grant_ids {
                for g in &mut grants {
                    let has = g.policy_ids.contains(&policy.id);
                    let want = ids.contains(&g.grant_id);
                    if want && !has {
                        g.policy_ids.push(policy.id.clone());
                    } else if !want && has {
                        g.policy_ids.retain(|p| p != &policy.id);
                    }
                }
            }
        }
        Mutation::PolicyDelete { policy_id } => {
            policies.retain(|p| &p.id != policy_id);
            for g in &mut grants {
                g.policy_ids.retain(|p| p != policy_id);
            }
        }
        Mutation::GrantUpsert { grant } => {
            grants.retain(|g| g.grant_id != grant.grant_id);
            grants.push(grant.clone());
        }
        Mutation::GrantDelete { grant_id } => grants.retain(|g| &g.grant_id != grant_id),
        _ => return None,
    }
    Some((policies, grants))
}

/// All action ids either policy mentions on any list (permit or deny), for the ceiling scan.
fn actions_of(p: &Policy) -> impl Iterator<Item = &str> {
    let Policy { id: _, connection_id: _, name: _, allow, deny, requires_approval, notify, device_signed, device_signed_quorum: _, redact_fields: _ } = p;
    allow
        .iter()
        .chain(deny)
        .chain(requires_approval)
        .chain(notify)
        .chain(device_signed)
        .map(String::as_str)
}

/// Whether replacing `existing` with `proposed` keeps every redaction `existing` contributes.
///
/// A policy's `redact_fields` apply to every call it permits, so an edit takes redaction away by
/// dropping an entry, by moving the policy to another connection, or by no longer mentioning an
/// action it used to (a co-bound policy can go on permitting that action, now unredacted). The access
/// ceiling sees none of those, so they are checked separately and held when they happen. Moving an
/// action to `deny` keeps it mentioned, which is right: a bound denying policy stops the call outright.
fn policy_keeps_redaction(existing: &Policy, proposed: &Policy) -> bool {
    if existing.redact_fields.is_empty() {
        return true;
    }
    proposed.connection_id == existing.connection_id
        && existing
            .redact_fields
            .iter()
            .all(|f| proposed.redact_fields.iter().any(|g| g.eq_ignore_ascii_case(f)))
        && actions_of(existing).all(|a| actions_of(proposed).any(|b| b == a))
}

/// Whether replacing (`Some`) or deleting (`None`) the grant `existing` keeps the redaction its
/// policies contribute. A redacting policy only applies to the calls of the agents its grant reaches
/// while that grant is live, so unbinding it, disabling the grant, narrowing its audience or bringing
/// its expiry forward all take redaction away from calls a laxer co-bound grant may still permit.
fn grant_keeps_redaction(policies: &[Policy], existing: &Grant, proposed: Option<&Grant>) -> bool {
    let redacting =
        |id: &String| policies.iter().any(|p| &p.id == id && !p.redact_fields.is_empty());
    if !existing.policy_ids.iter().any(redacting) {
        return true;
    }
    let Some(proposed) = proposed else { return false };
    existing.policy_ids.iter().filter(|id| redacting(id)).all(|id| proposed.policy_ids.contains(id))
        && (proposed.enabled || !existing.enabled)
        && audience_is_subset(proposed, existing)
        && !expiry_extends(proposed.expires_at, existing.expires_at)
}

/// Whether applying `proposed` over `current` (replacing the same-id policy, or adding a new one)
/// cannot lower what the engine puts on any action, whichever other policy on the connection it is
/// bound beside (see [`policy_edit_loosens`]). Sound regardless of which grants bind which policies, so a
/// mutation that could ever expand access is reported `false`. An edit that takes away redaction the
/// policy contributes is also reported `false`; see [`policy_keeps_redaction`].
pub fn policy_upsert_is_tightening(current: &[Policy], proposed: &Policy) -> bool {
    let existing = current.iter().find(|p| p.id == proposed.id);
    if existing.is_some_and(|e| !policy_keeps_redaction(e, proposed)) {
        return false;
    }
    let others: Vec<Policy> = current.iter().filter(|p| p.id != proposed.id).cloned().collect();
    !policy_edit_loosens(&others, existing, Some(proposed))
}

/// A policy delete is tightening iff it cannot lower what the engine puts on any action the policy
/// mentions, whichever other policy on the connection it was bound beside. Deleting a deny re-permits the
/// action under a co-bound permit, and deleting a stricter permit drops the action to a co-bound laxer
/// one, so both are held; deleting the only permit leaves the action denied by default, which tightens.
/// So is deleting a policy that carries `redact_fields`, which takes its redaction away from every call
/// a co-bound policy goes on permitting.
pub fn policy_delete_is_tightening(current: &[Policy], policy_id: &str) -> bool {
    let Some(target) = current.iter().find(|p| p.id == policy_id) else {
        // Deleting a non-existent policy is a no-op; treat as tightening (nothing loosens).
        return true;
    };
    if !target.redact_fields.is_empty() {
        return false;
    }
    let others: Vec<Policy> = current.iter().filter(|p| p.id != policy_id).cloned().collect();
    !policy_edit_loosens(&others, Some(target), None)
}

/// A grant upsert is tightening iff the proposed grant is a *subset* of the existing one: no new
/// policies, no new agents, no wider audience, no raised limits, no longer expiry, and it is not
/// being promoted to the Default baseline. A brand-new grant (no existing) always ADDS
/// authorization, so it is never tightening. This is deliberately coarse (it holds some benign
/// edits) because a precise grant analysis is not worth the blast radius, and holding is safe.
///
/// It judges the grant alone. Dropping a policy that carried a deny or the strict bar, or narrowing,
/// switching off or ending sooner the grant that carried it, can still lower what the rest of the estate
/// leaves in force; [`is_strictly_tightening`] holds that through [`any_principal_loosens`].
pub fn grant_upsert_is_tightening(current: &[Grant], proposed: &Grant) -> bool {
    let Some(existing) = current.iter().find(|g| g.grant_id == proposed.grant_id) else {
        return false; // a new grant always adds authorization
    };
    // No policy the existing grant did not already activate.
    if proposed.policy_ids.iter().any(|p| !existing.policy_ids.contains(p)) {
        return false;
    }
    // Audience may only narrow. Any move toward all-agents, or a new specific agent, loosens.
    if !audience_is_subset(existing, proposed) {
        return false;
    }
    // Limits may only tighten (a smaller ceiling, or newly-imposed one). A raised or removed limit
    // loosens.
    if !limit_is_tighter_or_equal(existing.overall_limit, proposed.overall_limit)
        || !limit_is_tighter_or_equal(
            existing.default_per_agent_limit,
            proposed.default_per_agent_limit,
        )
    {
        return false;
    }
    // Per-member overrides may only tighten. `audience_is_subset` matches members by id only, so a
    // member could keep its id while its `per_agent_limit` override (or its fallback to a looser
    // default) is raised, a budget loosening. Compare each proposed member's EFFECTIVE per-agent
    // limit (override, else the grant default) against the existing one, which for an all-agents
    // grant is its default: narrowing all agents to one while raising that one's ceiling loosens.
    if let GrantAgents::Agents(new) = &proposed.agents {
        for m in new {
            if !limit_is_tighter_or_equal(
                existing.effective_per_agent_limit(&m.agent_id),
                proposed.effective_per_agent_limit(&m.agent_id),
            ) {
                return false;
            }
        }
    }
    // A shorter budget WINDOW multiplies the effective allowance (N per day ≫ N total), so any
    // period change with a limit in force could loosen. Conservatively require the period unchanged.
    if proposed.period != existing.period {
        return false;
    }
    // Being enabled where it was disabled loosens; expiry pushed later loosens; becoming Default
    // (broader reach) loosens.
    if proposed.enabled && !existing.enabled {
        return false;
    }
    if expiry_extends(existing.expires_at, proposed.expires_at) {
        return false;
    }
    if proposed.is_default && !existing.is_default {
        return false;
    }
    true
}

/// `proposed`'s audience must not exceed `existing`'s: never widen to all-agents, never add an
/// agent the existing grant did not target.
fn audience_is_subset(existing: &Grant, proposed: &Grant) -> bool {
    match (&existing.agents, &proposed.agents) {
        (GrantAgents::AllAgents, _) => true, // already the widest; anything is ⊆
        (_, GrantAgents::AllAgents) => false, // widening to all-agents loosens
        (GrantAgents::Agents(old), GrantAgents::Agents(new)) => {
            new.iter().all(|n| old.iter().any(|o| o.agent_id == n.agent_id))
        }
    }
}

/// A limit is "tighter or equal" when it is at most the old one. `None` = unlimited (the loosest),
/// so `None`→`Some` tightens and `Some`→`None` loosens.
fn limit_is_tighter_or_equal(old: Option<u64>, new: Option<u64>) -> bool {
    match (old, new) {
        (_, None) => old.is_none(), // removing a limit only "stays equal" if there was none
        (None, Some(_)) => true,    // imposing a limit where none existed tightens
        (Some(o), Some(n)) => n <= o,
    }
}

/// Does `new` expiry sit later than `old` (a longer-lived, hence looser, grant)? `None` = never
/// expires (loosest); so `Some`→`None` extends, and a later timestamp extends.
fn expiry_extends(old: Option<time::OffsetDateTime>, new: Option<time::OffsetDateTime>) -> bool {
    match (old, new) {
        (None, _) => false,        // already never-expires; cannot extend further
        (Some(_), None) => true,   // removing the expiry extends to forever
        (Some(o), Some(n)) => n > o,
    }
}

/// Re-enabling a capability that is currently disabled re-opens it above policy, a loosening. An
/// enable that removes nothing (already enabled, or an unknown connection) changes no access.
pub fn capability_enable_is_tightening(
    connections: &[Connection],
    connection_id: &str,
    capability: &str,
) -> bool {
    match connections.iter().find(|c| c.id == connection_id) {
        Some(c) => !c.disabled_capabilities.iter().any(|x| x == capability),
        None => true, // unknown connection: apply is a no-op/404, nothing loosens
    }
}

/// A connection patch is tightening unless it re-opens access. Un-pausing a killed connection
/// re-enables every capability on it (a loosening), and **any** SSH-target edit is treated as
/// potentially insecurity-increasing (a repoint sends the sealed credential to a new host and a
/// host-key change can drop verification), so every SSH edit is held. A pause, rename, or no-op
/// un-pause only tightens or is neutral.
pub fn connection_patch_is_tightening(
    connections: &[Connection],
    connection_id: &str,
    patch: &ConnPatch,
) -> bool {
    if patch.ssh.is_some() {
        return false;
    }
    let disabled_now = connections
        .iter()
        .find(|c| c.id == connection_id)
        .map(|c| c.disabled)
        .unwrap_or(false);
    if patch.disabled == Some(false) && disabled_now {
        return false; // un-pause re-opens the connection
    }
    true
}

/// Approving an agent promotes it from Pending to Approved (it may then invoke), a loosening,
/// unless it is already Approved or unknown (a no-op).
pub fn agent_approve_is_tightening(agents: &[Agent], agent_id: &str) -> bool {
    match agents.iter().find(|a| a.id == agent_id) {
        Some(a) => a.is_approved(), // already approved → no-op → tightening
        None => true,               // unknown agent: apply will 404, nothing loosens
    }
}

/// Upserting an agent loosens only when it lands an **Approved** agent that was not already
/// approved: a brand-new approved agent (register) or a rename that would create one. A Pending
/// upsert, or a rename of an already-approved agent, never widens access.
pub fn agent_upsert_is_tightening(agents: &[Agent], proposed: &Agent) -> bool {
    if !proposed.is_approved() {
        return true; // landing/keeping Pending never loosens
    }
    match agents.iter().find(|a| a.id == proposed.id) {
        Some(existing) => existing.is_approved(), // rename of an already-approved agent: neutral
        None => false,                            // creating a new Approved agent loosens
    }
}

/// A runtime broker toggle is strictly tightening when it is ENGAGED (`value == true`: pause the
/// world / require approval) and loosening when RELEASED (`value == false`: un-pause / auto-approve
/// new agents). Both switches share this polarity, so the rule is kind-independent; a no-op flip to
/// the current value, held over the broker, is at worst harmless signing friction.
pub fn broker_toggle_is_tightening(value: bool) -> bool {
    value
}

/// How many distinct devices must sign a held `mutation` before it applies: the highest quorum any action
/// it loosens demands today, for any agent, or for the policy it edits wherever that policy is bound.
/// A change that lowers an action's quorum, or removes the policy, grant or rung that carries it, so
/// needs the same signatures the action itself does. `1` when it loosens nothing that takes more.
pub fn hold_quorum(mutation: &Mutation, ctx: &GuardContext) -> u8 {
    let bound = binding_state_after(mutation, ctx)
        .and_then(|(policies, grants)| principal_loosening((ctx.policies, ctx.grants), (&policies, &grants)));
    let edited = match mutation {
        Mutation::PolicyUpsert { policy, .. } => {
            let others: Vec<Policy> = ctx.policies.iter().filter(|p| p.id != policy.id).cloned().collect();
            policy_edit_loosening(&others, ctx.policies.iter().find(|p| p.id == policy.id), Some(policy))
        }
        Mutation::PolicyDelete { policy_id } => {
            let others: Vec<Policy> = ctx.policies.iter().filter(|p| &p.id != policy_id).cloned().collect();
            policy_edit_loosening(&others, ctx.policies.iter().find(|p| &p.id == policy_id), None)
        }
        _ => None,
    };
    bound.into_iter().chain(edited).max().unwrap_or(1).max(1)
}

/// A connection and one of its actions, the unit a quorum high-water mark is kept for.
pub type ActionKey = (String, String);

/// Every agent id a grant on either side names, plus one no grant names standing for every other agent.
fn principals(before: &[Grant], after: &[Grant]) -> Vec<String> {
    let mut agents: Vec<String> = before.iter().chain(after).flat_map(|g| g.agent_ids()).collect();
    agents.sort();
    agents.dedup();
    let unnamed = (0u32..).map(|n| format!("\u{0}unnamed-{n}")).find(|id| !agents.contains(id));
    agents.extend(unnamed);
    agents
}

/// The quorum above one each (connection, action) is held at, now or at any later moment: the most distinct people
/// the engine asks for it, over every agent a grant names and every agent it does not. A rule that a freeze masks
/// until it ends is in force from then on, so it is counted now; otherwise a step that only tightens could take it
/// out of force before it bites, and putting the action back would owe it nothing.
pub fn quorums_in_force(policies: &[Policy], grants: &[Grant]) -> std::collections::BTreeMap<ActionKey, u8> {
    let now = time::OffsetDateTime::now_utc();
    // Only an action some policy holds on more than one device can be held above one, and at no more than that.
    let mut candidates: std::collections::BTreeMap<(&str, &str), u8> = std::collections::BTreeMap::new();
    for p in policies.iter().filter(|p| p.device_signed_quorum > 1 && grants.iter().any(|g| g.is_live(now) && g.policy_ids.contains(&p.id))) {
        for action in &p.device_signed {
            let most = candidates.entry((p.connection_id.as_str(), action.as_str())).or_insert(1);
            *most = (*most).max(p.device_signed_quorum);
        }
    }
    let mut connections: Vec<&str> = candidates.keys().map(|(conn, _)| *conn).collect();
    connections.dedup();
    let agents = principals(grants, grants);
    if !within_budget(agents.len(), estate_cost(grants, policies)) {
        return candidates.into_iter().map(|((conn, action), q)| ((conn.to_string(), action.to_string()), q)).collect();
    }
    let moments = moments_of(&agents, &bearing_on(&[grants], &[policies], &connections), now);
    if !within_budget(resolves_for(candidates.len(), &moments, 1).saturating_add(agents.len()), estate_cost(grants, policies)) {
        // Never below the truth: each is counted at the most any policy asks for it.
        return candidates.into_iter().map(|((conn, action), q)| ((conn.to_string(), action.to_string()), q)).collect();
    }
    let engine = PolicyEngine::with(grants.to_vec(), policies.to_vec());
    let mut out = std::collections::BTreeMap::new();
    for (conn, action) in candidates.keys() {
        for (agent, at) in &moments {
            for at in at {
                if let Some((Rung::DeviceSigned, q)) = engine_access(&engine, agent, conn, action, *at) {
                    if q > 1 {
                        let mark = out.entry((conn.to_string(), action.to_string())).or_insert(q);
                        *mark = (*mark).max(q);
                    }
                }
            }
        }
    }
    out
}

/// The quorum a policy or grant mutation needs because of a high-water mark, and the actions that
/// raised it: the highest mark on any (connection, action) the mutation newly permits, or lowers below
/// that mark, for any agent at any moment from now on. A rule taken out of force by a tightening edit
/// (moved to `deny`, its grant disabled) leaves its mark behind, so putting the action back below it takes
/// the people it took.
pub fn high_water_quorum(
    mutation: &Mutation,
    ctx: &GuardContext,
    marks: &std::collections::BTreeMap<ActionKey, u8>,
) -> (u8, Vec<ActionKey>) {
    let mut lowered = Vec::new();
    if marks.values().all(|q| *q <= 1) {
        return (1, lowered);
    }
    let Some((policies, grants)) = binding_state_after(mutation, ctx) else { return (1, lowered) };
    let affected: std::collections::BTreeSet<&str> = ctx.policies.iter().chain(&policies).filter(|p| {
        let other = if ctx.policies.contains(p) { &policies } else { ctx.policies };
        !other.contains(p) || ctx.grants.iter().chain(&grants).any(|g| {
            let other = if ctx.grants.contains(g) { &grants } else { ctx.grants };
            !other.contains(g) && g.policy_ids.contains(&p.id)
        })
    }).map(|p| p.connection_id.as_str()).collect();
    let marked: Vec<(&ActionKey, u8)> = marks.iter().filter(|((conn, _), m)| **m > 1 && affected.contains(conn.as_str())).map(|(k, m)| (k, *m)).collect();
    let mut connections: Vec<&str> = marked.iter().map(|((conn, _), _)| conn.as_str()).collect();
    connections.dedup();
    let agents = principals(ctx.grants, &grants);
    if !within_budget(agents.len().saturating_mul(2), estate_cost(ctx.grants, ctx.policies).max(estate_cost(&grants, &policies))) {
        return (marked.iter().map(|(_, m)| *m).max().unwrap_or(1), lowered);
    }
    let moments =
        moments_of(&agents, &bearing_on(&[ctx.grants, &grants], &[ctx.policies, &policies], &connections), time::OffsetDateTime::now_utc());
    let cost = estate_cost(ctx.grants, ctx.policies).max(estate_cost(&grants, &policies));
    if !within_budget(resolves_for(marked.len(), &moments, 2).saturating_add(agents.len().saturating_mul(2)), cost) {
        // Past the budget the change pays the highest mark and settles none, since it is not known to move any.
        return (marked.iter().map(|(_, m)| *m).max().unwrap_or(1), lowered);
    }
    let was = PolicyEngine::with(ctx.grants.to_vec(), ctx.policies.to_vec());
    let now_is = PolicyEngine::with(grants, policies);
    let mut quorum = 1;
    for ((conn, action), mark) in marked {
        let below = moments.iter().any(|(agent, at)| {
            at.iter().any(|at| {
                let before = engine_access(&was, agent, conn, action, *at);
                let after = engine_access(&now_is, agent, conn, action, *at);
                loosens(before, after) && after.is_some_and(|(rung, q)| rung < Rung::DeviceSigned || q < mark)
            })
        });
        if below {
            quorum = quorum.max(mark);
            lowered.push((conn.clone(), action.clone()));
        }
    }
    (quorum, lowered)
}

/// [`hold_quorum`] with the high-water `marks` (stored and in force) applied. Lowering the approval
/// floor lets an operator bearer resolve `approve`-tier holds and, as an explicit opt-down to
/// `approve`, stops holding control-plane changes, exports, destructive changes and credential moves
/// for a device (`device_signed` rungs still need one). So it needs the highest quorum in force or
/// marked, capped at the people the keyring can put behind a hold, so that one owner with one device
/// is never bricked.
pub fn hold_quorum_with_marks(
    mutation: &Mutation,
    ctx: &GuardContext,
    marks: &std::collections::BTreeMap<ActionKey, u8>,
    reachable_people: u8,
) -> u8 {
    if let Mutation::ApprovalFloorSet { floor } = mutation {
        if floor.as_deref() == Some("device_signed") {
            return 1;
        }
        let highest = marks.values().copied().max().unwrap_or(1);
        return highest.min(reachable_people.max(1)).max(1);
    }
    hold_quorum(mutation, ctx).max(high_water_quorum(mutation, ctx, marks).0)
}

/// Whether this mutation destroys configuration that cannot be reconstructed from what is left.
///
/// **A separate axis from [`is_strictly_tightening`].** Tightening asks "can this grant anyone more
/// access?", and deleting a connection, a credential or an agent never can, which is why those are
/// hard-coded `true` there (a grant delete is classified on the deny, strict bar or redaction it
/// removes). That is correct about permission and silent about data: the same call also destroys the
/// policy, the grant, the connection or the credential, and nothing short of a backup brings it back.
/// So `rest::apply_or_hold` holds a destructive mutation wherever it arrives from, loopback included,
/// while a device is trusted and approvals are not opted down.
///
/// It matters because of who can reach these endpoints. The operator token is a `0600` file, so on a
/// machine that runs agents it is readable by every agent the owner runs. With export held, such an
/// agent can no longer take the credentials. Without this, it can still delete them, and every guard
/// in the path agrees that deleting is the safe direction.
///
/// The one delete that reads the store is an agent's, see [`agent_delete_is_destructive`]: an agent
/// still waiting to be approved is a row and nothing else, and removing it is the Deny button.
pub fn is_destructive(mutation: &Mutation, ctx: &GuardContext) -> bool {
    match mutation {
        Mutation::AgentDelete { agent_id } => agent_delete_is_destructive(ctx.agents, ctx.grants, agent_id),
        Mutation::PolicyDelete { .. }
        | Mutation::GrantDelete { .. }
        | Mutation::ConnectionDelete { .. }
        | Mutation::SecretDelete { .. } => true,
        _ => false,
    }
}

/// Removing an approved agent destroys its access and every grant row that names it, so it is held
/// like any other delete. Removing a Pending one destroys nothing: it was never approved, so every
/// session it holds can invoke nothing, and when no grant names it the row is all the delete touches,
/// which one enrolment code and one `permaura.enroll` reconstruct exactly. Holding that made Deny on
/// a waiting agent raise a hold whose own Deny kept the agent. A Pending agent a grant names stays
/// held, whatever put the grant there: the cascade edits or deletes that grant, which only a backup
/// brings back. An id the store does not know is held too; the handler 404s before the guard sees one,
/// and if another path ever routes it here, holding is the safe answer.
pub fn agent_delete_is_destructive(agents: &[Agent], grants: &[Grant], agent_id: &str) -> bool {
    let pending = agents.iter().any(|a| a.id == agent_id && !a.is_approved());
    let named = grants.iter().any(|g| match &g.agents {
        GrantAgents::Agents(members) => members.iter().any(|m| m.agent_id == agent_id),
        GrantAgents::AllAgents => false,
    });
    !pending || named
}

/// The tightening classifier `rest::apply_or_hold` calls for a remote change while the guard is
/// armed: is this mutation strictly tightening given the current store contents?
pub fn is_strictly_tightening(mutation: &Mutation, ctx: &GuardContext) -> bool {
    if let Some((policies, grants)) = binding_state_after(mutation, ctx) {
        if any_principal_loosens((ctx.policies, ctx.grants), (&policies, &grants)) {
            return false;
        }
    }
    match mutation {
        Mutation::PolicyUpsert { policy, grant_ids } => {
            // A grant_ids sync rides along with the upsert; treat any membership change as
            // potentially loosening (it can bind the policy to more grants), so require an empty or
            // absent sync to qualify as tightening on its own.
            let no_grant_widening = grant_ids.as_ref().map_or(true, |ids| {
                // Holding is safe; only skip the hold when the sync cannot add membership. We can't
                // cheaply prove that here, so any explicit grant_ids sync forces the hold.
                ids.is_empty()
            });
            // The one sync that reaches here, an empty one, unbinds the policy from every grant.
            let unbinds_redaction = grant_ids.as_ref().is_some_and(|ids| {
                ctx.policies.iter().any(|p| p.id == policy.id && !p.redact_fields.is_empty())
                    && ctx
                        .grants
                        .iter()
                        .any(|g| g.policy_ids.contains(&policy.id) && !ids.contains(&g.grant_id))
            });
            no_grant_widening && !unbinds_redaction && policy_upsert_is_tightening(ctx.policies, policy)
        }
        Mutation::PolicyDelete { policy_id } => policy_delete_is_tightening(ctx.policies, policy_id),
        Mutation::GrantUpsert { grant } => {
            grant_upsert_is_tightening(ctx.grants, grant)
                && ctx
                    .grants
                    .iter()
                    .find(|g| g.grant_id == grant.grant_id)
                    .map_or(true, |e| grant_keeps_redaction(ctx.policies, e, Some(grant)))
        }
        // Removing a grant can lift a deny or a strict bar it carried, which the principal check above
        // holds, and it can remove the redaction a policy it binds contributes to calls another grant
        // still permits.
        Mutation::GrantDelete { grant_id } => ctx
            .grants
            .iter()
            .find(|g| &g.grant_id == grant_id)
            .map_or(true, |e| grant_keeps_redaction(ctx.policies, e, None)),
        // Likewise: a connection nobody can reach cannot be reached MORE by being deleted. Tightening
        // on the permission axis and maximally destructive on the other, which is what `is_destructive`
        // is for. The same is true of a credential and an agent.
        Mutation::ConnectionDelete { .. } => true,
        Mutation::SecretDelete { .. } => true,
        Mutation::AgentDelete { .. } => true,
        Mutation::CapabilityEnable { connection_id, capability } => {
            capability_enable_is_tightening(ctx.connections, connection_id, capability)
        }
        Mutation::ConnectionPatch { connection_id, patch } => {
            connection_patch_is_tightening(ctx.connections, connection_id, patch)
        }
        Mutation::AgentApprove { agent_id } => agent_approve_is_tightening(ctx.agents, agent_id),
        Mutation::AgentUpsert { agent } => agent_upsert_is_tightening(ctx.agents, agent),
        // A credential injection has no tightening direction to prove (it always changes the
        // upstream identity the connection acts as), so over the broker it is always held.
        Mutation::CredentialPromote { .. } => false,
        Mutation::BrokerToggle { value, .. } => broker_toggle_is_tightening(*value),
        // Trusting a key only ever ADDS a signer to the approver keyring, so there is no tightening
        // direction to prove and the classifier can never let one through unheld. Nothing here
        // decides whether the enrolment is legitimate: the co-signature by an already-trusted
        // device does, and it only exists because this returns `false`.
        Mutation::ApproverKeyTrust { .. } => false,
        // Lowering the floor re-opens bearer-only resolutions, which is the loosening this whole
        // module exists to hold. Raising it is fail-safe and never reaches the guard (the handler
        // applies a raise directly); were it ever routed here, holding it is only signing friction,
        // which is the trade the soundness rule already prefers.
        Mutation::ApprovalFloorSet { .. } => false,
        // Emptying the keyring re-opens trust on first use and switches every device hold off, which
        // is a loosening however fail-safe a single revocation looks.
        Mutation::ApproverKeyRevoke { .. } => false,
        // A manifest decides where a connection made from it sends its credential, and removing one can
        // bring a bundled preset of the same id back into the catalog; neither has a direction to prove.
        Mutation::ConnectorInstall { .. } | Mutation::ConnectorRemove { .. } => false,
        // Raising the risk while keeping any approval only adds a gate; anything else removes one.
        Mutation::CapabilityPosture { risk, requires_approval, from, .. } => {
            *risk >= from.risk && (*requires_approval || !from.requires_approval)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AgentStatus;
    use permaura_core::{GrantAgent, GrantAgents, GrantPeriod};

    fn pol(id: &str, conn: &str, allow: &[&str], device_signed: &[&str]) -> Policy {
        Policy {
            id: id.into(),
            connection_id: conn.into(),
            name: id.into(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: vec![],
            requires_approval: vec![],
            notify: vec![],
            device_signed: device_signed.iter().map(|s| s.to_string()).collect(),
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        }
    }

    #[test]
    fn adding_a_new_permit_is_not_tightening() {
        let current = vec![pol("p1", "c", &["read"], &[])];
        // p1 now also permits `refund` at auto, a new permit, so it loosens.
        let proposed = pol("p1", "c", &["read", "refund"], &[]);
        assert!(!policy_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn raising_a_rung_is_tightening() {
        // refund moves from auto (allow) to device_signed, strictly more restrictive.
        let current = vec![pol("p1", "c", &["read", "refund"], &[])];
        let proposed = pol("p1", "c", &["read"], &["refund"]);
        assert!(policy_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn lowering_a_rung_is_not_tightening() {
        // refund moves from device_signed down to auto, a loosening.
        let current = vec![pol("p1", "c", &["read"], &["refund"])];
        let proposed = pol("p1", "c", &["read", "refund"], &[]);
        assert!(!policy_upsert_is_tightening(&current, &proposed));
    }

    /// A policy holding `action` at `device_signed` behind a quorum of `quorum` distinct devices.
    fn pol_quorum(id: &str, conn: &str, action: &str, quorum: u8) -> Policy {
        let mut p = pol(id, conn, &[], &[action]);
        p.device_signed_quorum = quorum;
        p
    }

    #[test]
    fn dropping_the_quorum_is_not_tightening() {
        // The rung is `device_signed` on both sides, so before the quorum was part of the ceiling
        // this compared equal and the guard applied it unsigned over the broker, a two-person rule
        // deleted by the control plane, with a success toast. Raising it stays tightening.
        let current = vec![pol_quorum("p1", "c", "refund", 2)];
        assert!(!policy_upsert_is_tightening(&current, &pol_quorum("p1", "c", "refund", 1)));
        assert!(policy_upsert_is_tightening(&current, &pol_quorum("p1", "c", "refund", 3)));
        // An unchanged quorum is still tightening (nothing moved), so the new term cannot make every
        // edit to a two-person policy unsignable.
        assert!(policy_upsert_is_tightening(&current, &pol_quorum("p1", "c", "refund", 2)));
    }

    #[test]
    fn new_policy_permitting_a_new_action_is_not_tightening() {
        let current = vec![pol("p1", "c", &["read"], &[])];
        let proposed = pol("p2", "c", &[], &["refund"]); // new device_signed permit still loosens vs deny
        assert!(!policy_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn dropping_a_strict_rung_beside_a_lax_policy_is_not_tightening() {
        // The engine holds refund at the strictest bar of every policy bound to the agent, so an agent
        // bound to both is held at device_signed today. Editing p_strict's refund away drops it to auto.
        let current = vec![pol("p_strict", "c", &[], &["refund"]), pol("p_lax", "c", &["refund"], &[])];
        let proposed = pol("p_strict", "c", &[], &[]);
        assert!(!policy_upsert_is_tightening(&current, &proposed));
    }

    fn pol_deny(id: &str, conn: &str, allow: &[&str], deny: &[&str]) -> Policy {
        Policy {
            id: id.into(),
            connection_id: conn.into(),
            name: String::new(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            requires_approval: vec![],
            notify: vec![],
            device_signed: vec![],
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        }
    }

    #[test]
    fn deleting_a_deny_guardrail_is_not_tightening() {
        // p_guard force-denies refund (deny-wins) while p_work permits it: refund is DENIED today.
        // Deleting p_guard re-permits refund: a loosening that must be held.
        let current = vec![pol_deny("p_guard", "c", &[], &["refund"]), pol("p_work", "c", &["refund"], &[])];
        assert!(!policy_delete_is_tightening(&current, "p_guard"));
    }

    #[test]
    fn emptying_a_deny_list_over_upsert_is_not_tightening() {
        let current = vec![pol_deny("p_guard", "c", &[], &["refund"]), pol("p_work", "c", &["refund"], &[])];
        let proposed = pol_deny("p_guard", "c", &[], &[]); // deny dropped → refund goes denied→permitted
        assert!(!policy_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn adding_a_deny_is_tightening() {
        let current = vec![pol("p1", "c", &["refund"], &[])];
        let proposed = pol_deny("p1", "c", &["refund"], &["refund"]); // now denied (deny-wins)
        assert!(policy_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn shortening_the_budget_window_is_not_tightening() {
        let mut existing = grant("g1", &["p1"], false, Some(100));
        existing.period = GrantPeriod::Total;
        let mut proposed = grant("g1", &["p1"], false, Some(100));
        proposed.period = GrantPeriod::Day; // N/day ≫ N total → a budget loosening
        assert!(!grant_upsert_is_tightening(&[existing], &proposed));
    }

    #[test]
    fn raising_a_member_per_agent_override_is_not_tightening() {
        let lo = GrantAgent { agent_id: "codex-cli".into(), per_agent_limit: Some(10) };
        let hi = GrantAgent { agent_id: "codex-cli".into(), per_agent_limit: Some(1000) };
        let existing = Grant { agents: GrantAgents::Agents(vec![lo]), ..grant("g1", &["p1"], false, None) };
        let proposed = Grant { agents: GrantAgents::Agents(vec![hi]), ..grant("g1", &["p1"], false, None) };
        assert!(!grant_upsert_is_tightening(&[existing], &proposed));
    }

    #[test]
    fn narrowing_all_agents_while_raising_a_members_override_is_not_tightening() {
        let mut existing = grant("g1", &["p1"], true, None);
        existing.default_per_agent_limit = Some(5);
        let proposed = Grant {
            agents: GrantAgents::Agents(vec![GrantAgent { agent_id: "codex-cli".into(), per_agent_limit: Some(1_000_000) }]),
            ..existing.clone()
        };
        assert!(!grant_upsert_is_tightening(&[existing], &proposed));
    }

    #[test]
    fn narrowing_all_agents_to_one_agent_within_the_default_is_tightening() {
        let mut existing = grant("g1", &["p1"], true, None);
        existing.default_per_agent_limit = Some(5);
        let proposed = Grant {
            agents: GrantAgents::Agents(vec![GrantAgent { agent_id: "codex-cli".into(), per_agent_limit: Some(3) }]),
            ..existing.clone()
        };
        assert!(grant_upsert_is_tightening(&[existing], &proposed));
    }

    #[test]
    fn lowering_a_member_per_agent_override_is_tightening() {
        let hi = GrantAgent { agent_id: "codex-cli".into(), per_agent_limit: Some(1000) };
        let lo = GrantAgent { agent_id: "codex-cli".into(), per_agent_limit: Some(10) };
        let existing = Grant { agents: GrantAgents::Agents(vec![hi]), ..grant("g1", &["p1"], false, None) };
        let proposed = Grant { agents: GrantAgents::Agents(vec![lo]), ..grant("g1", &["p1"], false, None) };
        assert!(grant_upsert_is_tightening(&[existing], &proposed));
    }

    #[test]
    fn deleting_a_sole_device_signed_policy_is_not_tightening() {
        // p1 is the ONLY policy permitting refund (at device_signed). Deleting it drops refund to
        // deny-by-default. That is MORE restrictive, so deletion never loosens... unless a laxer
        // policy exists. Here none does → deletion is tightening.
        let current = vec![pol("p1", "c", &[], &["refund"])];
        assert!(policy_delete_is_tightening(&current, "p1"));
    }

    #[test]
    fn deleting_a_strict_policy_beside_a_lax_one_is_not_tightening() {
        // An agent bound to both is held at device_signed by p_strict. Deleting it drops refund to
        // p_lax's auto, a loosening. Deleting p_lax leaves p_strict's bar in force, so that tightens.
        let current = vec![pol("p_strict", "c", &[], &["refund"]), pol("p_lax", "c", &["refund"], &[])];
        assert!(!policy_delete_is_tightening(&current, "p_strict"));
        assert!(policy_delete_is_tightening(&current, "p_lax"));
    }

    fn grant(id: &str, policies: &[&str], all_agents: bool, limit: Option<u64>) -> Grant {
        Grant {
            grant_id: id.into(),
            name: String::new(),
            enabled: true,
            is_default: false,
            policy_ids: policies.iter().map(|s| s.to_string()).collect(),
            agents: if all_agents {
                GrantAgents::AllAgents
            } else {
                GrantAgents::Agents(vec![GrantAgent::new("codex-cli")])
            },
            period: GrantPeriod::Total,
            overall_limit: limit,
            default_per_agent_limit: None,
            expires_at: None,
        }
    }

    #[test]
    fn new_grant_is_never_tightening() {
        assert!(!grant_upsert_is_tightening(&[], &grant("g1", &["p1"], true, None)));
    }

    #[test]
    fn adding_a_policy_to_a_grant_is_not_tightening() {
        let current = vec![grant("g1", &["p1"], false, None)];
        let proposed = grant("g1", &["p1", "p2"], false, None);
        assert!(!grant_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn widening_to_all_agents_is_not_tightening() {
        let current = vec![grant("g1", &["p1"], false, None)];
        let proposed = grant("g1", &["p1"], true, None);
        assert!(!grant_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn lowering_a_limit_is_tightening() {
        let current = vec![grant("g1", &["p1"], false, Some(100))];
        let proposed = grant("g1", &["p1"], false, Some(10));
        assert!(grant_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn raising_a_limit_is_not_tightening() {
        let current = vec![grant("g1", &["p1"], false, Some(10))];
        let proposed = grant("g1", &["p1"], false, Some(100));
        assert!(!grant_upsert_is_tightening(&current, &proposed));
    }

    #[test]
    fn removing_a_limit_is_not_tightening() {
        let current = vec![grant("g1", &["p1"], false, Some(10))];
        let proposed = grant("g1", &["p1"], false, None);
        assert!(!grant_upsert_is_tightening(&current, &proposed));
    }

    fn agent_grant(id: &str, policies: &[&str], agent: &str) -> Grant {
        Grant { agents: GrantAgents::Agents(vec![GrantAgent::new(agent)]), ..grant(id, policies, false, None) }
    }

    fn tightening(m: Mutation, policies: &[Policy], grants: &[Grant]) -> bool {
        is_strictly_tightening(&m, &GuardContext { policies, grants, connections: &[], agents: &[] })
    }

    /// The ceiling mask, first variant: a deny no grant binds is inert to the engine, but the connection-wide
    /// ceiling let it mask the next edit, which dropped the bound agent's `device_signed` rung to auto.
    #[test]
    fn an_unbound_deny_cannot_mask_a_bound_agents_rung_dropping() {
        let strict = pol("p_strict", "c", &[], &["refund"]);
        let grants = vec![agent_grant("g_a", &["p_strict"], "agent-a")];
        let decoy = pol_deny("p_decoy", "c", &[], &["refund"]);
        // Step one, the unbound deny: inert, so it applies.
        let step_one = Mutation::PolicyUpsert { policy: decoy.clone(), grant_ids: None };
        assert!(tightening(step_one, &[strict.clone()], &grants));
        // Step two drops refund from device_signed to auto for agent-a: held.
        let step_two = Mutation::PolicyUpsert { policy: pol("p_strict", "c", &["refund"], &[]), grant_ids: None };
        assert!(!tightening(step_two, &[strict, decoy], &grants));
    }

    /// The ceiling mask, second variant: a lax policy bound to a DIFFERENT agent set the connection-wide ceiling to
    /// auto already, so dropping this agent's rung compared equal.
    #[test]
    fn a_lax_policy_bound_to_another_agent_cannot_mask_a_rung_dropping() {
        let strict = pol("p_strict", "c", &[], &["refund"]);
        let lax = pol("p_lax", "c", &["refund"], &[]);
        let grants = vec![agent_grant("g_a", &["p_strict"], "agent-a"), agent_grant("g_b", &["p_lax"], "agent-b")];
        let edit = Mutation::PolicyUpsert { policy: pol("p_strict", "c", &["refund"], &[]), grant_ids: None };
        assert!(!tightening(edit, &[strict.clone(), lax.clone()], &grants));
        // Raising the rung for agent-a is still a tightening, with both bound.
        let raise = Mutation::PolicyUpsert { policy: pol_deny("p_strict", "c", &[], &["refund"]), grant_ids: None };
        assert!(tightening(raise, &[strict, lax], &grants));
    }

    /// Taking a deny-bearing policy out of the grant that binds it to an agent re-permits the action
    /// for that agent, though the grant only got narrower.
    #[test]
    fn unbinding_a_deny_from_an_agent_is_not_tightening() {
        let policies = vec![pol("p_work", "c", &["refund"], &[]), pol_deny("p_guard", "c", &[], &["refund"])];
        let grants = vec![agent_grant("g_work", &["p_work"], "agent-a"), agent_grant("g_guard", &["p_guard"], "agent-a")];
        let narrowed = Mutation::GrantUpsert { grant: agent_grant("g_guard", &[], "agent-a") };
        assert!(!tightening(narrowed, &policies, &grants));
        assert!(!tightening(Mutation::GrantDelete { grant_id: "g_guard".into() }, &policies, &grants));
        let unbind = Mutation::PolicyUpsert { policy: policies[1].clone(), grant_ids: Some(vec![]) };
        assert!(!tightening(unbind, &policies, &grants));
    }

    /// The exploit: agent-a is reached by g_lax (refund auto) and g_strict (refund
    /// device_signed, quorum 2), and the engine holds refund for two signatures. The guard read the laxest
    /// bound policy as the one in force, so each edit below looked like no change and applied unheld.
    fn strict_beside_lax() -> (Vec<Policy>, Vec<Grant>) {
        let policies = vec![pol("p_lax", "c", &["refund"], &[]), pol_quorum("p_strict", "c", "refund", 2)];
        let grants = vec![agent_grant("g_lax", &["p_lax"], "agent-a"), agent_grant("g_strict", &["p_strict"], "agent-a")];
        (policies, grants)
    }

    #[test]
    fn disabling_the_grant_that_carries_the_strict_rule_is_not_tightening() {
        let (policies, grants) = strict_beside_lax();
        let disabled = Grant { enabled: false, ..grants[1].clone() };
        assert!(!tightening(Mutation::GrantUpsert { grant: disabled }, &policies, &grants));
        assert!(!tightening(Mutation::GrantDelete { grant_id: "g_strict".into() }, &policies, &grants));
    }

    #[test]
    fn editing_the_strict_policy_down_beside_a_lax_one_is_not_tightening() {
        let (policies, grants) = strict_beside_lax();
        for weaker in [pol("p_strict", "c", &[], &[]), pol_quorum("p_strict", "c", "refund", 1)] {
            let edit = Mutation::PolicyUpsert { policy: weaker.clone(), grant_ids: None };
            assert!(!tightening(edit, &policies, &grants), "{weaker:?}");
        }
        assert!(!tightening(Mutation::PolicyDelete { policy_id: "p_strict".into() }, &policies, &grants));
    }

    #[test]
    fn raising_the_strict_policy_or_removing_the_lax_one_is_tightening() {
        let (policies, grants) = strict_beside_lax();
        let raised = Mutation::PolicyUpsert { policy: pol_quorum("p_strict", "c", "refund", 3), grant_ids: None };
        assert!(tightening(raised, &policies, &grants));
        let unbound = Mutation::GrantUpsert { grant: agent_grant("g_lax", &[], "agent-a") };
        assert!(tightening(unbound, &policies, &grants));
    }

    #[test]
    fn reordering_a_grants_policies_is_tightening() {
        let policies = vec![pol("p_lax", "c", &["refund"], &[]), pol_quorum("p_strict", "c", "refund", 2)];
        let grants = vec![agent_grant("g", &["p_strict", "p_lax"], "agent-a")];
        let reordered = Mutation::GrantUpsert { grant: agent_grant("g", &["p_lax", "p_strict"], "agent-a") };
        assert!(tightening(reordered, &policies, &grants));
    }

    #[test]
    fn an_unbound_policy_never_becomes_a_mark_when_the_estate_exceeds_the_budget() {
        let policies = vec![pol_quorum("unbound", "c", "refund", 2), pol("bound", "c", &["refund"], &[])];
        let now = time::OffsetDateTime::now_utc();
        let mut grants: Vec<Grant> = (0..310).map(|i| {
            let mut g = agent_grant(&format!("g{i}"), &["bound"], "a");
            g.agents = GrantAgents::AllAgents;
            g.expires_at = Some(now + time::Duration::minutes(i + 1));
            g
        }).collect();
        let mut named = agent_grant("named", &["bound"], "a");
        named.agents = GrantAgents::Agents((0..310).map(|i| GrantAgent::new(format!("a{i}"))).collect());
        grants.push(named);
        assert!(quorums_in_force(&policies, &grants).is_empty(), "an unbound rule cannot leave a quorum mark");
    }

    fn quorum_to_hold(m: Mutation, policies: &[Policy], grants: &[Grant]) -> u8 {
        hold_quorum(&m, &GuardContext { policies, grants, connections: &[], agents: &[] })
    }

    /// One device could sign away a two-device rule: every held change needed a single signature.
    #[test]
    fn removing_a_two_person_rule_needs_two_devices() {
        let (policies, grants) = strict_beside_lax();
        let disabled = Grant { enabled: false, ..grants[1].clone() };
        let cases = [
            Mutation::GrantUpsert { grant: disabled },
            Mutation::GrantDelete { grant_id: "g_strict".into() },
            Mutation::PolicyUpsert { policy: pol_quorum("p_strict", "c", "refund", 1), grant_ids: None },
            Mutation::PolicyUpsert { policy: pol("p_strict", "c", &["refund"], &[]), grant_ids: None },
            Mutation::PolicyDelete { policy_id: "p_strict".into() },
        ];
        for m in cases {
            assert_eq!(quorum_to_hold(m.clone(), &policies, &grants), 2, "{m:?}");
        }
    }

    #[test]
    fn a_change_that_lowers_nothing_taking_two_needs_one_device() {
        let (policies, grants) = strict_beside_lax();
        let raised = Mutation::PolicyUpsert { policy: pol_quorum("p_strict", "c", "refund", 3), grant_ids: None };
        assert_eq!(quorum_to_hold(raised, &policies, &grants), 1);
        let new_permit = Mutation::PolicyUpsert { policy: pol("p_new", "c", &["read"], &[]), grant_ids: None };
        assert_eq!(quorum_to_hold(new_permit, &policies, &grants), 1);
        let toggle = Mutation::BrokerToggle { toggle: BrokerToggleKind::Pause, value: false };
        assert_eq!(quorum_to_hold(toggle, &policies, &grants), 1);
    }

    #[test]
    fn an_unbound_policy_keeps_its_own_quorum_for_where_it_may_be_bound() {
        let policies = vec![pol_quorum("p_three", "c", "refund", 3)];
        let lowered = Mutation::PolicyUpsert { policy: pol_quorum("p_three", "c", "refund", 1), grant_ids: None };
        assert_eq!(quorum_to_hold(lowered, &policies, &[]), 3);
    }

    /// The two-step loosening, modeled: denying the action tightens, and re-permitting it is held at
    /// one signature from the store alone, but at the rule's two once the mark is kept.
    #[test]
    fn a_kept_mark_floors_the_re_permit_after_a_deny() {
        let all = |ids: &[&str]| Grant {
            grant_id: "g_all".into(),
            name: "all".into(),
            enabled: true,
            is_default: false,
            policy_ids: ids.iter().map(|s| s.to_string()).collect(),
            agents: GrantAgents::AllAgents,
            period: GrantPeriod::Total,
            overall_limit: None,
            default_per_agent_limit: None,
            expires_at: None,
        };
        let strict = vec![pol_quorum("p", "stripe", "refunds.create", 2)];
        let grants = vec![all(&["p"])];
        let marks = quorums_in_force(&strict, &grants);
        assert_eq!(marks.get(&("stripe".to_string(), "refunds.create".to_string())), Some(&2));

        let mut denied = pol("p", "stripe", &[], &[]);
        denied.deny = vec!["refunds.create".into()];
        let step1 = Mutation::PolicyUpsert { policy: denied.clone(), grant_ids: None };
        assert!(tightening(step1, &strict, &grants), "step one tightens");
        assert!(quorums_in_force(&[denied.clone()], &grants).is_empty(), "and takes the rule out of force");

        let step2 = Mutation::PolicyUpsert { policy: pol("p", "stripe", &["refunds.create"], &[]), grant_ids: None };
        let ctx = GuardContext { policies: std::slice::from_ref(&denied), grants: &grants, connections: &[], agents: &[] };
        assert_eq!(hold_quorum(&step2, &ctx), 1, "the store alone has forgotten the rule");
        assert_eq!(hold_quorum_with_marks(&step2, &ctx, &marks, 3), 2, "the mark has not");
        let at_the_mark = Mutation::PolicyUpsert { policy: pol_quorum("p", "stripe", "refunds.create", 2), grant_ids: None };
        assert_eq!(hold_quorum_with_marks(&at_the_mark, &ctx, &marks, 3), 1, "putting the rule back lowers nothing");

        let floor = Mutation::ApprovalFloorSet { floor: Some("approve".into()) };
        assert_eq!(hold_quorum_with_marks(&floor, &ctx, &marks, 3), 2, "the floor takes the highest mark");
        assert_eq!(hold_quorum_with_marks(&floor, &ctx, &marks, 1), 1, "capped at the people who can sign");
    }

    /// Nothing differs at the moment of the edit, but once the new expiry passes the refund runs at the lax
    /// grant's auto instead of on two devices, so the edit is held for the two devices the rule takes.
    #[test]
    fn ending_the_strict_grant_sooner_beside_a_lax_one_is_not_tightening() {
        let policies = vec![pol_quorum("p_strict", "c", "refund", 2), pol("p_lax", "c", &["refund"], &[])];
        let strict = grant("g_strict", &["p_strict"], true, None);
        let grants = vec![strict.clone(), grant("g_lax", &["p_lax"], true, None)];
        let soon = Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1));
        let ended_sooner = Mutation::GrantUpsert { grant: Grant { expires_at: soon, ..strict } };
        assert!(!tightening(ended_sooner.clone(), &policies, &grants));
        assert_eq!(quorum_to_hold(ended_sooner, &policies, &grants), 2);
    }

    /// A two-person rule a freeze masks until it ends is in force from then on, so it is marked now: otherwise moving
    /// it to deny (a tightening, applied unheld) and putting it back at auto would take one signature instead of two.
    #[test]
    fn a_two_person_rule_a_freeze_masks_until_it_ends_is_marked_now() {
        let mut freeze = grant("g_freeze", &["p_freeze"], true, None);
        freeze.expires_at = Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1));
        let grants = vec![freeze, grant("g_rule", &["p_rule"], true, None)];
        let policies = vec![pol_deny("p_freeze", "c", &[], &["refund"]), pol_quorum("p_rule", "c", "refund", 2)];
        let marks = quorums_in_force(&policies, &grants);
        assert_eq!(marks.get(&("c".to_string(), "refund".to_string())), Some(&2), "the rule bites when the freeze ends");

        let mut denied = pol("p_rule", "c", &[], &[]);
        denied.deny = vec!["refund".into()];
        let after_step_one = vec![policies[0].clone(), denied];
        let step_two = Mutation::PolicyUpsert { policy: pol("p_rule", "c", &["refund"], &[]), grant_ids: None };
        let ctx = GuardContext { policies: &after_step_one, grants: &grants, connections: &[], agents: &[] };
        assert_eq!(hold_quorum_with_marks(&step_two, &ctx, &marks, 3), 2);
    }

    /// Every one of `n` all-agents grants carries the same rule and ends at its own moment, and `n` agents are named,
    /// so checking every agent at every moment costs about `n` cubed visits.
    fn estate_past_the_budget(n: usize) -> (Vec<Policy>, Vec<Grant>) {
        let now = time::OffsetDateTime::now_utc();
        let mut grants: Vec<Grant> = (0..n)
            .map(|i| Grant {
                expires_at: Some(now + time::Duration::minutes(10 + i as i64)),
                ..grant(&format!("g{i}"), &["p"], true, None)
            })
            .collect();
        let named = (0..n).map(|i| GrantAgent::new(format!("agent-{i}"))).collect();
        grants.push(Grant { agents: GrantAgents::Agents(named), ..grant("g_named", &["p"], false, None) });
        (vec![pol("p", "c", &[], &["refund"])], grants)
    }

    /// Ending one of them sooner changes nothing anyone may do, but proving it would take tens of millions of
    /// visits, so the classification stops at its budget and holds the change instead.
    #[test]
    fn a_classification_past_its_work_budget_holds_the_change() {
        let (mut policies, grants) = estate_past_the_budget(500);
        policies[0] = pol_quorum("p", "c", "refund", 2);
        let sooner = Grant { expires_at: Some(time::OffsetDateTime::now_utc() + time::Duration::minutes(5)), ..grants[0].clone() };
        let started = std::time::Instant::now();
        assert!(!tightening(Mutation::GrantUpsert { grant: sooner.clone() }, &policies, &grants));
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "and it says so without doing the work: {:?}", started.elapsed());
        let change = Mutation::GrantUpsert { grant: sooner };
        assert_eq!(quorum_to_hold(change.clone(), &policies, &grants), 2);
        let marks = quorums_in_force(&policies, &grants);
        assert_eq!(marks.get(&("c".into(), "refund".into())), Some(&2));
        let ctx = GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
        assert_eq!(high_water_quorum(&change, &ctx, &marks).0, 2);
        let unrelated = [(("elsewhere".into(), "refund".into()), 3)].into();
        assert_eq!(high_water_quorum(&change, &ctx, &unrelated).0, 1);
    }

    /// A grant that binds nothing on the connection a change touches cannot change what anyone is answered there, so
    /// its expiry costs that change nothing, and a large estate elsewhere still has its edits judged rather than held.
    #[test]
    fn grants_elsewhere_do_not_spend_a_changes_budget() {
        let (mut policies, mut grants) = estate_past_the_budget(500);
        policies[0].connection_id = "elsewhere".into();
        policies.push(pol("p_c", "c", &["refund"], &[]));
        let g = grant("g_c", &["p_c"], true, None);
        grants.push(g.clone());
        let sooner = Grant { expires_at: Some(time::OffsetDateTime::now_utc() + time::Duration::minutes(5)), ..g };
        assert!(tightening(Mutation::GrantUpsert { grant: sooner }, &policies, &grants));
    }

    /// A policy on `conn` listing `n` actions named from `prefix`.
    fn wide(id: &str, conn: &str, prefix: &str, n: usize) -> Policy {
        let actions: Vec<String> = (0..n).map(|i| format!("{prefix}{i}")).collect();
        pol(id, conn, &actions.iter().map(String::as_str).collect::<Vec<_>>(), &[])
    }

    /// A grant of `policies` to the named `agents`, ending `minutes` from now when given.
    fn named(id: &str, policies: &[String], agents: impl IntoIterator<Item = String>, minutes: Option<i64>) -> Grant {
        Grant {
            policy_ids: policies.to_vec(),
            agents: GrantAgents::Agents(agents.into_iter().map(GrantAgent::new).collect()),
            expires_at: minutes.map(|m| time::OffsetDateTime::now_utc() + time::Duration::minutes(m)),
            ..grant(id, &[], false, None)
        }
    }

    /// Estates an owner or a team builds are worked out in full rather than answered at the most people: pausing a
    /// grant on them is judged, so it can be confirmed.
    #[test]
    fn realistic_estates_are_worked_out_within_the_budget() {
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let default = grant("default", &[], true, None);
        // A solo owner with a 1,500-route WordPress site beside two small connections, three agents and one grant that ends.
        let solo = (
            vec![wide("w1", "wp", "r", 750), wide("w2", "wp", "w", 750), wide("o1", "x", "x", 50), wide("o2", "y", "y", 30)],
            vec![default.clone(), named("main", &ids(&["w1", "w2", "o1", "o2"]), (1..=3).map(|i| format!("a{i}")), Some(60))],
        );
        // Twelve agents on sixteen 75-action policies, whose eight time-boxed grants also share a 300-action site.
        let mut team_policies: Vec<Policy> = (0..16).map(|i| wide(&format!("p{i}"), &format!("c{}", i / 2), &format!("a{}_", i % 2), 75)).collect();
        team_policies.push(wide("shared", "wp", "wp", 300));
        let team_grants: Vec<Grant> = std::iter::once(default.clone())
            .chain((0..8).map(|k| {
                named(&format!("g{k}"), &ids(&[&format!("p{}", 2 * k), &format!("p{}", 2 * k + 1), "shared"]), (0..6).map(|j| format!("a{}", (k * 6 + j) % 12)), Some(60 + k as i64))
            }))
            .collect();
        // Twenty agents on thirty 50-action policies over ten connections, each of twenty time-boxed grants binding three.
        let wider_policies: Vec<Policy> = (0..30).map(|i| wide(&format!("p{i}"), &format!("c{}", i / 3), &format!("a{}_", i % 3), 50)).collect();
        let wider_grants: Vec<Grant> = std::iter::once(default)
            .chain((0..20).map(|k| {
                let bound = [k % 30, (k + 10) % 30, (k + 20) % 30].map(|i| format!("p{i}"));
                named(&format!("g{k}"), &bound, (0..5).map(|j| format!("a{}", (k * 5 + j) % 20)), Some(60 + k as i64))
            }))
            .collect();
        let mut past = Vec::new();
        for (what, policies, grants, paused) in
            [("solo", solo.0, solo.1, "main"), ("team", team_policies, team_grants, "g0"), ("twenty", wider_policies, wider_grants, "g0")]
        {
            let grant = Grant { enabled: false, ..grants.iter().find(|g| g.grant_id == paused).unwrap().clone() };
            let ctx = GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
            if matches!(held_effect(&Mutation::GrantUpsert { grant }, &ctx, &[]), HeldEffect::PastBudget) {
                past.push(what);
            }
        }
        assert!(past.is_empty(), "pausing a grant is answered at the most people instead of worked out: {past:?}");
    }

    /// A change held without reading the estate takes what the full working-out says it takes, on an estate whose
    /// rules and marks ask for three people.
    #[test]
    fn a_change_held_without_the_estate_takes_what_the_estate_would_say() {
        let policies = vec![pol_quorum("p", "c", "refund", 3), pol_deny("d", "c", &["read"], &["refund"])];
        let grants = vec![grant("g", &["p"], true, None), agent_grant("g_d", &["d"], "codex-cli")];
        let marks: std::collections::BTreeMap<ActionKey, u8> = [(("c".to_string(), "refund".to_string()), 3)].into();
        let ctx = GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
        let estate_free = [
            Mutation::SecretDelete { secret_id: "s".into() },
            Mutation::AgentDelete { agent_id: "codex-cli".into() },
            Mutation::ConnectionDelete { connection_id: "c".into() },
            Mutation::CapabilityEnable { connection_id: "c".into(), capability: "c.refund".into() },
            Mutation::ConnectionPatch { connection_id: "c".into(), patch: ConnPatch { disabled: Some(false), ..ConnPatch::default() } },
            Mutation::AgentApprove { agent_id: "codex-cli".into() },
            Mutation::AgentUpsert { agent: agent("codex-cli", AgentStatus::Approved) },
            Mutation::CredentialPromote {
                connection_id: "c".into(),
                secret_id: "s".into(),
                staging_secret_id: "t".into(),
                staged_sha256: String::new(),
            },
            Mutation::BrokerToggle { toggle: BrokerToggleKind::Pause, value: false },
            Mutation::ApproverKeyTrust { approver_id: "device:x".into(), approver_pubkey: String::new(), person: None, replaces: None },
            Mutation::ApproverKeyRevoke { approver_id: "device:x".into() },
            Mutation::ConnectorInstall {
                manifest: serde_json::json!({}),
                version: 1,
                provenance: crate::manifest::Provenance::User,
            },
            Mutation::ConnectorRemove { connector_id: "acme".into() },
        ];
        for m in &estate_free {
            assert_eq!(quorum_without_estate(m), Some(hold_quorum_with_marks(m, &ctx, &marks, 3)), "{m:?}");
        }
        let from_the_estate = [
            Mutation::PolicyUpsert { policy: pol("p", "c", &["refund"], &[]), grant_ids: None },
            Mutation::PolicyDelete { policy_id: "p".into() },
            Mutation::GrantUpsert { grant: Grant { enabled: false, ..grants[0].clone() } },
            Mutation::GrantDelete { grant_id: "g".into() },
            Mutation::ApprovalFloorSet { floor: Some("approve".into()) },
        ];
        for m in &from_the_estate {
            assert_eq!(quorum_without_estate(m), None, "{m:?}");
        }
        assert_eq!(hold_quorum_with_marks(&from_the_estate[0], &ctx, &marks, 3), 3, "lowering the rule takes its three people");
        assert_eq!(hold_quorum_with_marks(&from_the_estate[4], &ctx, &marks, 3), 3, "and so does lowering the floor");
    }

    /// Switching on an all-agents permit lowers refunds for agents no grant names, but not for `codex-cli`, held at the
    /// device by its own grant. Remove that grant (a tightening) and the same switch would lower `codex-cli` too: it is
    /// judged by name at the confirm, so that reads as more than was held, not as one more agent no grant names.
    #[test]
    fn an_agent_named_when_a_change_was_held_is_judged_by_name_at_its_confirm() {
        let policies = vec![pol("p_lax", "c", &["refund"], &[]), pol("p_strict", "c", &[], &["refund"])];
        let lax_off = Grant { enabled: false, ..grant("g_lax", &["p_lax"], true, None) };
        let switch_on = Mutation::GrantUpsert { grant: Grant { enabled: true, ..lax_off.clone() } };
        let effect = |grants: &[Grant], also: &[String]| {
            match held_effect(&switch_on, &GuardContext { policies: &policies, grants, connections: &[], agents: &[] }, also) {
                HeldEffect::Lowers(l) => l,
                other => panic!("expected an effect, got {other:?}"),
            }
        };
        let held_against = vec![lax_off.clone(), agent_grant("g_codex", &["p_strict"], "codex-cli")];
        let then = effect(&held_against, &[]);
        assert_eq!(then.named, vec!["codex-cli".to_string()]);
        assert!(then.widened_in(&effect(&held_against, &then.named)).is_none(), "the same estate lowers the same");

        let codex_grant_removed = vec![lax_off];
        let now = effect(&codex_grant_removed, &then.named);
        let why = then.widened_in(&now).expect("codex-cli now falls to auto, which it did not");
        assert!(why.contains("codex-cli"), "{why}");
        assert!(then.widened_in(&effect(&codex_grant_removed, &[])).is_none(), "read as an agent no grant names, it would pass");
    }

    #[test]
    fn ending_the_lax_grant_sooner_or_a_denying_one_later_is_judged_by_what_stays() {
        let mut deny = pol("p_deny", "c", &[], &[]);
        deny.deny = vec!["refund".into()];
        let policies = vec![pol_quorum("p_strict", "c", "refund", 2), pol("p_lax", "c", &["refund"], &[]), deny];
        let lax = grant("g_lax", &["p_lax"], true, None);
        let grants = vec![grant("g_strict", &["p_strict"], true, None), lax.clone()];
        let soon = Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1));
        let lax_sooner = Mutation::GrantUpsert { grant: Grant { expires_at: soon, ..lax } };
        assert!(tightening(lax_sooner, &policies, &grants), "the two-device rule stays in force throughout");

        let denying = grant("g_deny", &["p_deny"], true, None);
        let grants = vec![denying.clone(), grant("g_lax", &["p_lax"], true, None)];
        let deny_sooner = Mutation::GrantUpsert { grant: Grant { expires_at: soon, ..denying } };
        assert!(!tightening(deny_sooner, &policies, &grants), "the refund is permitted once the deny ends");
    }

    #[test]
    fn grant_delete_is_always_tightening() {
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
        assert!(is_strictly_tightening(&Mutation::GrantDelete { grant_id: "g1".into() }, &ctx));
    }

    // ── The other operator-plane loosening endpoints ─────────────────────────────────────

    fn conn(id: &str, disabled: bool, disabled_caps: &[&str]) -> Connection {
        Connection {
            id: id.into(),
            connector: "braintree".into(),
            name: id.into(),
            label: id.into(),
            secret_id: String::new(),
            capabilities: vec![],
            disabled_capabilities: disabled_caps.iter().map(|s| s.to_string()).collect(),
            disabled,
            allowed_hosts: vec![],
            created_at: 0,
            redact_fields: Vec::new(),
            source: None,
            made_from: None,
        }
    }

    fn agent(id: &str, status: AgentStatus) -> Agent {
        Agent { id: id.into(), name: id.into(), status, enrolled_at: 0 }
    }

    #[test]
    fn re_enabling_a_disabled_capability_is_not_tightening() {
        let c = vec![conn("c", false, &["refund"])];
        assert!(!capability_enable_is_tightening(&c, "c", "refund"));
    }

    #[test]
    fn enabling_an_already_enabled_capability_is_a_noop() {
        let c = vec![conn("c", false, &[])];
        assert!(capability_enable_is_tightening(&c, "c", "refund"));
    }

    #[test]
    fn unpausing_a_killed_connection_is_not_tightening() {
        let c = vec![conn("c", true, &[])];
        let patch = ConnPatch { disabled: Some(false), ..Default::default() };
        assert!(!connection_patch_is_tightening(&c, "c", &patch));
    }

    #[test]
    fn pausing_and_renaming_a_connection_is_tightening() {
        let c = vec![conn("c", false, &[])];
        assert!(connection_patch_is_tightening(
            &c,
            "c",
            &ConnPatch { disabled: Some(true), ..Default::default() }
        ));
        assert!(connection_patch_is_tightening(
            &c,
            "c",
            &ConnPatch { name: Some("new".into()), ..Default::default() }
        ));
        // Un-pausing an already-enabled connection is a no-op → tightening.
        assert!(connection_patch_is_tightening(
            &c,
            "c",
            &ConnPatch { disabled: Some(false), ..Default::default() }
        ));
    }

    #[test]
    fn any_ssh_target_edit_is_not_tightening() {
        let c = vec![conn("c", false, &[])];
        // Even a host-key *upgrade* is held: the guard cannot cheaply tell an upgrade from a
        // repoint, and holding a genuine tightening is only friction.
        let patch = ConnPatch {
            ssh: Some(SshPatch { host_key_sha256: Some("aa:bb".into()), ..Default::default() }),
            ..Default::default()
        };
        assert!(!connection_patch_is_tightening(&c, "c", &patch));
    }

    #[test]
    fn approving_a_pending_agent_is_not_tightening() {
        let a = vec![agent("bot", AgentStatus::Pending)];
        assert!(!agent_approve_is_tightening(&a, "bot"));
    }

    #[test]
    fn approving_an_already_approved_agent_is_a_noop() {
        let a = vec![agent("bot", AgentStatus::Approved)];
        assert!(agent_approve_is_tightening(&a, "bot"));
    }

    #[test]
    fn creating_a_new_approved_agent_is_not_tightening() {
        assert!(!agent_upsert_is_tightening(&[], &agent("bot", AgentStatus::Approved)));
    }

    #[test]
    fn renaming_an_approved_agent_is_tightening() {
        let a = vec![agent("bot", AgentStatus::Approved)];
        assert!(agent_upsert_is_tightening(&a, &agent("bot", AgentStatus::Approved)));
    }

    #[test]
    fn a_pending_agent_upsert_never_loosens() {
        assert!(agent_upsert_is_tightening(&[], &agent("bot", AgentStatus::Pending)));
    }

    #[test]
    fn deleting_a_pending_agent_is_not_destructive() {
        let a = vec![agent("bot", AgentStatus::Pending)];
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &a };
        assert!(!is_destructive(&Mutation::AgentDelete { agent_id: "bot".into() }, &ctx));
        // A grant covering every agent is untouched by the cascade, so it changes nothing here.
        let g = vec![grant("g_all", &[], true, None)];
        let ctx = GuardContext { policies: &[], grants: &g, connections: &[], agents: &a };
        assert!(!is_destructive(&Mutation::AgentDelete { agent_id: "bot".into() }, &ctx));
    }

    #[test]
    fn deleting_an_approved_agent_is_destructive() {
        let a = vec![agent("bot", AgentStatus::Approved)];
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &a };
        assert!(is_destructive(&Mutation::AgentDelete { agent_id: "bot".into() }, &ctx));
    }

    #[test]
    fn deleting_a_pending_agent_a_grant_names_is_destructive() {
        let a = vec![agent("codex-cli", AgentStatus::Pending)];
        let g = vec![grant("g1", &[], false, None)]; // names codex-cli specifically
        let ctx = GuardContext { policies: &[], grants: &g, connections: &[], agents: &a };
        assert!(is_destructive(&Mutation::AgentDelete { agent_id: "codex-cli".into() }, &ctx));
    }

    #[test]
    fn deleting_an_unknown_agent_is_destructive() {
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
        assert!(is_destructive(&Mutation::AgentDelete { agent_id: "ghost".into() }, &ctx));
    }

    #[test]
    fn a_credential_promotion_is_never_tightening() {
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
        let m = Mutation::CredentialPromote {
            connection_id: "c".into(),
            secret_id: "sec_c".into(),
            staging_secret_id: "sec_staging_x".into(),
            staged_sha256: String::new(),
        };
        assert!(!is_strictly_tightening(&m, &ctx));
    }

    #[test]
    fn engaging_a_broker_toggle_is_tightening() {
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
        for toggle in [BrokerToggleKind::Pause, BrokerToggleKind::RequireAgentApproval] {
            let m = Mutation::BrokerToggle { toggle, value: true };
            assert!(is_strictly_tightening(&m, &ctx), "engaging {toggle:?} must apply immediately");
        }
    }

    #[test]
    fn releasing_a_broker_toggle_is_not_tightening() {
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
        for toggle in [BrokerToggleKind::Pause, BrokerToggleKind::RequireAgentApproval] {
            let m = Mutation::BrokerToggle { toggle, value: false };
            assert!(!is_strictly_tightening(&m, &ctx), "releasing {toggle:?} must be held over the broker");
        }
    }

    #[test]
    fn trusting_an_approver_key_is_never_tightening() {
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
        let m = Mutation::ApproverKeyTrust {
            approver_id: "device:sam-iphone".into(),
            approver_pubkey: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=".into(),
            person: None,
            replaces: None,
        };
        assert!(!is_strictly_tightening(&m, &ctx), "enrolling device N must be co-signed, never applied");
    }

    #[test]
    fn setting_or_clearing_the_approval_floor_is_never_tightening() {
        let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
        for floor in [Some("approve".to_string()), Some("device_signed".to_string()), None] {
            let m = Mutation::ApprovalFloorSet { floor: floor.clone() };
            assert!(!is_strictly_tightening(&m, &ctx), "floor {floor:?} must be held, never auto-applied");
        }
    }

    /// A store's names for the titles, keyed by id. An id it does not list is [`Stored::Missing`].
    #[derive(Default)]
    struct Names {
        connections: Vec<(&'static str, &'static str)>,
        policies: Vec<(&'static str, &'static str)>,
        grants: Vec<(&'static str, &'static str)>,
        agents: Vec<(&'static str, &'static str)>,
        secrets: Vec<(&'static str, &'static str)>,
        devices: Vec<(&'static str, &'static str)>,
        displaced: Option<&'static str>,
        policy_records: Vec<Policy>,
        grant_records: Vec<Grant>,
    }

    fn look(table: &[(&str, &str)], id: &str) -> Stored {
        table.iter().find(|(k, _)| *k == id).map_or(Stored::Missing, |(_, v)| Stored::Found(v.to_string()))
    }

    impl MutationNames for Names {
        fn connection(&self, id: &str) -> Stored {
            look(&self.connections, id)
        }
        fn policy(&self, id: &str) -> Stored {
            look(&self.policies, id)
        }
        fn grant(&self, grant_id: &str) -> Stored {
            look(&self.grants, grant_id)
        }
        fn agent(&self, id: &str) -> Stored {
            look(&self.agents, id)
        }
        fn secret_owner(&self, secret_id: &str) -> Stored {
            look(&self.secrets, secret_id)
        }
        fn device(&self, approver_id: &str) -> Stored {
            look(&self.devices, approver_id)
        }
        fn displaced_key(&self, _approver_id: &str, _new_key: &str) -> Option<String> {
            self.displaced.map(str::to_string)
        }
        fn policy_record(&self, id: &str) -> Option<Policy> {
            self.policy_records.iter().find(|p| p.id == id).cloned()
        }
        fn grant_record(&self, grant_id: &str) -> Option<Grant> {
            self.grant_records.iter().find(|g| g.grant_id == grant_id).cloned()
        }
        fn grants_including(&self, policy_id: &str) -> Option<Vec<String>> {
            Some(
                self.grant_records
                    .iter()
                    .filter(|g| g.policy_ids.iter().any(|p| p == policy_id))
                    .map(|g| g.grant_id.clone())
                    .collect(),
            )
        }
    }

    /// The estate the live examples came from: the connection named "SSH Speed Test 2".
    fn estate() -> Names {
        Names {
            connections: vec![("ssh_ssh_speed_test_2", "SSH Speed Test 2")],
            policies: vec![("pol_29aa6dead0309473f8537c52b0abe16f", "Restart only")],
            grants: vec![("gr_default", "Everyone")],
            agents: vec![("agt_7f3", "Claude Code")],
            secrets: vec![("sec_ssh_ssh_speed_test_2", "SSH Speed Test 2")],
            devices: vec![("device:sam-watch", "Sam's Apple Watch")],
            displaced: None,
            policy_records: Vec::new(),
            grant_records: Vec::new(),
        }
    }

    fn named_pol(id: &str, name: &str) -> Policy {
        Policy { name: name.into(), ..pol(id, "ssh_ssh_speed_test_2", &["restart-app"], &[]) }
    }

    fn named_grant(id: &str, name: &str) -> Grant {
        Grant { name: name.into(), ..grant(id, &[], true, None) }
    }

    #[test]
    fn every_policy_and_grant_title_names_what_it_changes() {
        let n = estate();
        let edit = Mutation::PolicyUpsert {
            policy: named_pol("pol_29aa6dead0309473f8537c52b0abe16f", "Restart only"),
            grant_ids: Some(vec!["gr_default".into()]),
        };
        assert_eq!(edit.summary_in(&n), "Change the policy \u{201c}Restart only\u{201d} for \u{201c}SSH Speed Test 2\u{201d}");
        let add = Mutation::PolicyUpsert { policy: named_pol("pol_new", "Deploys"), grant_ids: None };
        assert_eq!(add.summary_in(&n), "Add the policy \u{201c}Deploys\u{201d} for \u{201c}SSH Speed Test 2\u{201d}");
        let delete = Mutation::PolicyDelete { policy_id: "pol_29aa6dead0309473f8537c52b0abe16f".into() };
        assert_eq!(delete.summary_in(&n), "Delete the policy \u{201c}Restart only\u{201d}");

        let change = Mutation::GrantUpsert { grant: named_grant("gr_default", "Everyone") };
        assert_eq!(change.summary_in(&n), "Change the grant \u{201c}Everyone\u{201d}");
        let add = Mutation::GrantUpsert { grant: named_grant("gr_ops", "Ops agents") };
        assert_eq!(add.summary_in(&n), "Add the grant \u{201c}Ops agents\u{201d}");
        let delete = Mutation::GrantDelete { grant_id: "gr_default".into() };
        assert_eq!(delete.summary_in(&n), "Delete the grant \u{201c}Everyone\u{201d}");
    }

    #[test]
    fn every_connection_credential_and_agent_title_names_what_it_changes() {
        let n = estate();
        let conn = "ssh_ssh_speed_test_2".to_string();
        let cases = [
            (
                Mutation::CredentialPromote {
                    connection_id: conn.clone(),
                    secret_id: "sec_ssh_ssh_speed_test_2".into(),
                    staging_secret_id: "sec_staging_4ef3".into(),
                    staged_sha256: String::new(),
                },
                "Save the new credential for \u{201c}SSH Speed Test 2\u{201d}",
            ),
            (
                Mutation::SecretDelete { secret_id: "sec_ssh_ssh_speed_test_2".into() },
                "Delete the saved credential for \u{201c}SSH Speed Test 2\u{201d}",
            ),
            (
                Mutation::ConnectionDelete { connection_id: conn.clone() },
                "Delete the connection \u{201c}SSH Speed Test 2\u{201d} and everything that uses it",
            ),
            (
                Mutation::CapabilityEnable { connection_id: conn.clone(), capability: format!("{conn}.restart-app") },
                "Turn on \u{201c}restart-app\u{201d} for \u{201c}SSH Speed Test 2\u{201d}",
            ),
            (Mutation::AgentDelete { agent_id: "agt_7f3".into() }, "Remove the agent \u{201c}Claude Code\u{201d}"),
            (Mutation::AgentApprove { agent_id: "agt_7f3".into() }, "Let the agent \u{201c}Claude Code\u{201d} connect"),
            (
                Mutation::AgentUpsert { agent: Agent { name: "Codex".into(), ..agent("agt_new", AgentStatus::Approved) } },
                "Add and approve the agent \u{201c}Codex\u{201d}",
            ),
        ];
        for (m, want) in cases {
            assert_eq!(m.summary_in(&n), want);
        }
    }

    #[test]
    fn a_connection_patch_names_every_field_it_changes() {
        let n = estate();
        let patch = |patch: ConnPatch| Mutation::ConnectionPatch { connection_id: "ssh_ssh_speed_test_2".into(), patch }.summary_in(&n);
        assert_eq!(
            patch(ConnPatch { disabled: Some(false), ..Default::default() }),
            "Change the connection \u{201c}SSH Speed Test 2\u{201d}: resume it"
        );
        assert_eq!(
            patch(ConnPatch { disabled: Some(true), label: Some("Speed".into()), ..Default::default() }),
            "Change the connection \u{201c}SSH Speed Test 2\u{201d}: pause it and rename it to \u{201c}Speed\u{201d}"
        );
        let everything = ConnPatch {
            disabled: Some(false),
            label: Some("Speed".into()),
            name: Some("speed-2".into()),
            ssh: Some(SshPatch {
                host: Some("db2.internal".into()),
                port: Some(2222),
                user: Some("deploy".into()),
                host_key_sha256: Some("SHA256:abc".into()),
                insecure: None,
                password_auth: Some(true),
            }),
        };
        assert_eq!(
            patch(everything),
            "Change the connection \u{201c}SSH Speed Test 2\u{201d}: resume it, rename it to \u{201c}Speed\u{201d}, change its \
             instance name to \u{201c}speed-2\u{201d}, change its SSH host to \u{201c}db2.internal\u{201d}, change its SSH port to \
             2222, change its SSH user to \u{201c}deploy\u{201d}, change its expected host key and switch it to password sign-in"
        );
        let insecure = |insecure, key: Option<&str>, password_auth| ConnPatch {
            ssh: Some(SshPatch { insecure, host_key_sha256: key.map(str::to_string), password_auth, ..Default::default() }),
            ..Default::default()
        };
        assert_eq!(
            patch(insecure(Some(true), None, Some(false))),
            "Change the connection \u{201c}SSH Speed Test 2\u{201d}: turn off host-key checking and switch it to key sign-in"
        );
        assert_eq!(
            patch(insecure(Some(true), Some("SHA256:abc"), None)),
            "Change the connection \u{201c}SSH Speed Test 2\u{201d}: turn off host-key checking instead of using the new \
             expected host key"
        );
        assert_eq!(
            patch(insecure(Some(false), None, None)),
            "Change the connection \u{201c}SSH Speed Test 2\u{201d}: leave host-key checking as it is"
        );
        assert_eq!(
            patch(ConnPatch { ssh: Some(SshPatch::default()), ..Default::default() }),
            "Change the connection \u{201c}SSH Speed Test 2\u{201d}: save its SSH settings unchanged"
        );
    }

    #[test]
    fn the_runtime_switches_read_as_what_they_do() {
        let n = estate();
        let toggle = |toggle, value| Mutation::BrokerToggle { toggle, value }.summary_in(&n);
        assert_eq!(toggle(BrokerToggleKind::Pause, true), "Pause every agent");
        assert_eq!(toggle(BrokerToggleKind::Pause, false), "Resume every agent");
        assert_eq!(toggle(BrokerToggleKind::RequireAgentApproval, true), "Require approval before new agents can act");
        assert_eq!(toggle(BrokerToggleKind::RequireAgentApproval, false), "Let new agents act without approval");
    }

    #[test]
    fn pairing_titles_name_the_device_the_key_and_the_floor() {
        let mut n = estate();
        let trust = Mutation::ApproverKeyTrust { approver_id: "device:sam-watch".into(), approver_pubkey: "x".into(), person: None, replaces: None };
        let fp = crate::service::key_fingerprint("x");
        assert_eq!(
            trust.summary_in(&n),
            format!("Trust \u{201c}Sam's Apple Watch\u{201d} to approve (key {fp})"),
            "a co-signer who cannot see WHICH key is being enrolled is not confirming a diff",
        );
        // Enrolling over an id that already holds a different key is a trust-root ROTATION, not an
        // addition: `ApproverKeyring::add` inserts over the existing entry, so the title has to say so.
        n.displaced = Some("old-key");
        assert_eq!(
            trust.summary_in(&n),
            format!(
                "Replace the trusted key for \u{201c}Sam's Apple Watch\u{201d}: key {} becomes {fp}",
                crate::service::key_fingerprint("old-key")
            ),
        );

        let floor = |floor: Option<&str>| Mutation::ApprovalFloorSet { floor: floor.map(str::to_string) }.summary_in(&n);
        assert_eq!(floor(Some("approve")), "Require at least \u{201c}an approval\u{201d} for every held action");
        assert_eq!(
            floor(Some("device_signed")),
            "Require at least \u{201c}a paired device's signature\u{201d} for every held action"
        );
        assert_eq!(floor(None), "Remove the minimum approval override");

        let revoke = Mutation::ApproverKeyRevoke { approver_id: "device:sam-watch".into() };
        assert_eq!(
            revoke.summary_in(&n),
            "Remove \u{201c}Sam's Apple Watch\u{201d}, the last trusted device. After this nothing will need a device signature"
        );
    }

    /// Re-presenting the SAME key is idempotent, not a rotation: the keyring reports nothing displaced,
    /// and the title must stay the plain one rather than claiming a replacement.
    #[test]
    fn re_enrolling_the_same_key_is_not_reported_as_a_replacement() {
        let trust = Mutation::ApproverKeyTrust { approver_id: "device:sam-watch".into(), approver_pubkey: "same-key".into(), person: None, replaces: None };
        assert!(trust.summary_in(&estate()).starts_with("Trust \u{201c}Sam's Apple Watch\u{201d} to approve"));
        let bound = Mutation::ApproverKeyTrust {
            approver_id: "device:sam-watch".into(),
            approver_pubkey: "same-key".into(),
            person: Some("user_sam".into()),
            replaces: None,
        };
        assert!(
            bound.summary_in(&estate()).ends_with("for \u{201c}user_sam\u{201d}"),
            "a co-signer sees whose device it will count as"
        );
    }

    #[test]
    fn a_missing_or_blank_name_falls_back_to_the_id() {
        let mut n = estate();
        n.connections = vec![("ssh_ssh_speed_test_2", "   ")];
        n.policies = vec![];
        let edit = Mutation::PolicyUpsert {
            policy: named_pol("pol_29aa6dead0309473f8537c52b0abe16f", ""),
            grant_ids: None,
        };
        assert_eq!(
            edit.summary_in(&n),
            "Add the policy \u{201c}pol_29aa6dead0309473f8537c52b0abe16f\u{201d} for \u{201c}ssh_ssh_speed_test_2\u{201d}"
        );
        assert_eq!(
            Mutation::AgentApprove { agent_id: "agt_unknown".into() }.summary_in(&n),
            "Let the agent \u{201c}agt_unknown\u{201d} connect"
        );
        assert_eq!(
            Mutation::SecretDelete { secret_id: "sec_orphan".into() }.summary_in(&n),
            "Delete the saved credential \u{201c}sec_orphan\u{201d}"
        );
        assert_eq!(
            Mutation::ApproverKeyRevoke { approver_id: "device:lost".into() }.summary_in(&n),
            "Remove \u{201c}device:lost\u{201d}, the last trusted device. After this nothing will need a device signature"
        );
        // A caller with no store names everything by id, and does not guess whether a policy is new.
        let no_store = Mutation::PolicyUpsert { policy: named_pol("pol_x", ""), grant_ids: None };
        assert_eq!(no_store.summary(), "Add or change the policy \u{201c}pol_x\u{201d} for \u{201c}ssh_ssh_speed_test_2\u{201d}");
    }

    /// The Hosted Production example: a Gmail policy whose `messages.trash` needs approval, on the
    /// "Everyone" grant, with a second grant it is not on.
    fn gmail_policy() -> Policy {
        Policy {
            id: "pol_t5".into(),
            connection_id: "gmail".into(),
            name: "t5-conn-3, read access".into(),
            allow: vec!["messages.list".into(), "messages.get".into()],
            deny: vec![],
            requires_approval: vec!["messages.trash".into()],
            notify: vec![],
            device_signed: vec!["messages.send".into()],
            device_signed_quorum: 1,
            redact_fields: vec!["body".into(), "snippet".into()],
        }
    }

    fn gmail_estate() -> Names {
        Names {
            // Two connections share the label "Gmail" in Hosted Production; HoldNames adds the name.
            connections: vec![("gmail", "Gmail \u{b7} t5-conn-3"), ("gmail_work", "Gmail \u{b7} t5-conn-6")],
            policies: vec![("pol_t5", "t5-conn-3, read access"), ("pol_send", "Sending")],
            grants: vec![("gr_default", "Everyone"), ("gr_ops", "Ops agents")],
            agents: vec![("agt_a", "Claude Code"), ("agt_b", "Codex"), ("agt_c", "Cursor"), ("agt_d", "Aider")],
            policy_records: vec![gmail_policy()],
            grant_records: vec![
                Grant { name: "Everyone".into(), ..grant("gr_default", &["pol_t5"], true, None) },
                Grant { name: "Ops agents".into(), ..grant("gr_ops", &[], false, None) },
            ],
            ..Names::default()
        }
    }

    fn policy_edit(policy: Policy, grant_ids: Option<&[&str]>) -> String {
        let grant_ids = grant_ids.map(|ids| ids.iter().map(|s| s.to_string()).collect());
        Mutation::PolicyUpsert { policy, grant_ids }.summary_in(&gmail_estate())
    }

    const GMAIL_HEAD: &str =
        "Change the policy \u{201c}t5-conn-3, read access\u{201d} for \u{201c}Gmail \u{b7} t5-conn-3\u{201d}";

    #[test]
    fn a_policy_edit_says_which_action_it_loosens() {
        let mut p = gmail_policy();
        p.requires_approval.clear();
        p.allow.push("messages.trash".into());
        assert_eq!(
            policy_edit(p, Some(&["gr_default"])),
            format!("{GMAIL_HEAD}: messages.trash: needs approval \u{2192} runs without asking")
        );
    }

    #[test]
    fn loosening_changes_are_listed_before_tightening_ones() {
        let mut p = gmail_policy();
        p.allow = vec!["messages.get".into(), "messages.trash".into()];
        p.requires_approval = vec!["messages.list".into()];
        p.deny = vec!["messages.delete".into()];
        assert_eq!(
            policy_edit(p, None),
            format!(
                "{GMAIL_HEAD}: messages.trash: needs approval \u{2192} runs without asking; messages.delete: is not allowed \
                 \u{2192} is blocked; messages.list: runs without asking \u{2192} needs approval"
            ),
            "the change that held the edit comes first, though it sorts last"
        );
    }

    #[test]
    fn a_quorum_change_is_named_on_the_actions_it_moves() {
        let mut p = gmail_policy();
        p.device_signed_quorum = 2;
        assert_eq!(policy_edit(p, None), format!("{GMAIL_HEAD}: messages.send: needs a paired device \u{2192} needs 2 paired devices"));
        let mut p = gmail_policy();
        p.device_signed.clear();
        p.device_signed_quorum = 3;
        assert_eq!(policy_edit(p, None), format!("{GMAIL_HEAD}: messages.send: needs a paired device \u{2192} is not allowed"));
    }

    #[test]
    fn a_policy_edit_names_the_grants_it_joins_and_leaves() {
        assert_eq!(
            policy_edit(gmail_policy(), Some(&["gr_ops"])),
            format!("{GMAIL_HEAD}: now on \u{201c}Ops agents\u{201d}; no longer on \u{201c}Everyone\u{201d}")
        );
        assert_eq!(policy_edit(gmail_policy(), Some(&["gr_default"])), GMAIL_HEAD, "an unchanged sync is no change");
    }

    #[test]
    fn a_rename_and_a_move_are_named_and_the_title_keeps_the_known_name() {
        let mut p = gmail_policy();
        p.name = "Gmail read".into();
        assert_eq!(policy_edit(p, None), format!("{GMAIL_HEAD}: renamed to \u{201c}Gmail read\u{201d}"));
        let mut p = gmail_policy();
        p.connection_id = "gmail_work".into();
        assert_eq!(
            policy_edit(p, None),
            "Change the policy \u{201c}t5-conn-3, read access\u{201d} for \u{201c}Gmail \u{b7} t5-conn-6\u{201d}: moved from \
             \u{201c}Gmail \u{b7} t5-conn-3\u{201d}"
        );
        assert_eq!(
            Mutation::PolicyDelete { policy_id: "pol_t5".into() }.summary_in(&gmail_estate()),
            "Delete the policy \u{201c}t5-conn-3, read access\u{201d} for \u{201c}Gmail \u{b7} t5-conn-3\u{201d}",
            "a stored policy's delete names its connection, since two connections can each have a policy of one name"
        );
    }

    #[test]
    fn a_connection_is_named_by_label_and_name_when_they_differ() {
        assert_eq!(connection_display_name("Gmail", "t5-conn-3"), "Gmail \u{b7} t5-conn-3");
        assert_eq!(connection_display_name("Gmail", "t5-conn-6"), "Gmail \u{b7} t5-conn-6");
        assert_eq!(connection_display_name(" Gmail ", "gmail"), "Gmail", "the same after trimming and case is one name");
        assert_eq!(connection_display_name("Gmail", "  "), "Gmail");
        assert_eq!(connection_display_name("", "t5-conn-3"), "t5-conn-3");
        assert_eq!(connection_display_name("", ""), "");
        let combined = connection_display_name(&"L".repeat(40), &"n".repeat(40));
        assert_eq!(
            quoted_name(&combined),
            format!("\u{201c}{} \u{b7} {}\u{2026}\u{201d}", "L".repeat(40), "n".repeat(MAX_NAME_CHARS - 1 - 43)),
            "the cap applies to the combined text"
        );
    }

    #[test]
    fn a_long_diff_lists_three_changes_and_counts_the_rest() {
        let mut p = gmail_policy();
        p.allow = vec!["messages.list".into(), "messages.get".into(), "messages.trash".into(), "messages.send".into()];
        p.requires_approval.clear();
        p.device_signed.clear();
        p.redact_fields = vec!["SNIPPET".into(), "subject".into()];
        p.name = "Everything".into();
        assert_eq!(
            policy_edit(p, Some(&["gr_default", "gr_ops"])),
            format!(
                "{GMAIL_HEAD}: messages.send: needs a paired device \u{2192} runs without asking; messages.trash: needs approval \
                 \u{2192} runs without asking; hides 1 fewer field; and 3 more changes"
            )
        );
        let mut p = gmail_policy();
        p.requires_approval.clear();
        p.redact_fields.clear();
        p.name = "Everything".into();
        p.notify = vec!["messages.get".into()];
        assert_eq!(
            policy_edit(p, None),
            format!(
                "{GMAIL_HEAD}: hides 2 fewer fields; messages.get: runs without asking \u{2192} runs with a notification; \
                 messages.trash: needs approval \u{2192} is not allowed; and 1 more change"
            ),
            "taking an action off every list narrows this policy, so it follows the redaction it loosens"
        );
    }

    #[test]
    fn an_edit_that_changes_nothing_visible_keeps_the_plain_title() {
        assert_eq!(policy_edit(gmail_policy(), None), GMAIL_HEAD);
        // Also listing an action on a laxer list changes nothing: the strictest listing still wins.
        let mut p = gmail_policy();
        p.allow.push("messages.trash".into());
        p.redact_fields = vec!["BODY".into(), "snippet".into()];
        assert_eq!(policy_edit(p, Some(&["gr_default"])), GMAIL_HEAD);
    }

    fn grant_edit(grant: Grant) -> String {
        Mutation::GrantUpsert { grant }.summary_in(&gmail_estate())
    }

    #[test]
    fn a_grant_edit_says_what_it_widens_then_what_it_narrows() {
        let ops = gmail_estate().grant_records[1].clone();
        let mut g = ops.clone();
        g.enabled = false;
        g.agents = GrantAgents::Agents(vec![GrantAgent::new("agt_a")]);
        g.policy_ids = vec!["pol_t5".into()];
        assert_eq!(
            grant_edit(g),
            "Change the grant \u{201c}Ops agents\u{201d}: now covers \u{201c}Claude Code\u{201d}; now includes \
             \u{201c}t5-conn-3, read access\u{201d}; paused; and 1 more change",
            "the fourth change, codex-cli leaving, is counted rather than listed"
        );

        let mut g = ops.clone();
        g.is_default = true;
        g.overall_limit = Some(100);
        g.period = GrantPeriod::Day;
        assert_eq!(
            grant_edit(g),
            "Change the grant \u{201c}Ops agents\u{201d}: made the Default; budget period: in total \u{2192} per day; overall \
             limit: no limit \u{2192} 100"
        );

        let mut existing = ops.clone();
        existing.overall_limit = Some(100);
        existing.expires_at = Some(time::OffsetDateTime::UNIX_EPOCH);
        existing.agents = GrantAgents::Agents(vec![GrantAgent { agent_id: "agt_b".into(), per_agent_limit: Some(10) }]);
        let mut names = gmail_estate();
        names.grant_records = vec![existing.clone()];
        let mut g = existing.clone();
        g.overall_limit = None;
        g.expires_at = None;
        g.agents = GrantAgents::Agents(vec![GrantAgent { agent_id: "agt_b".into(), per_agent_limit: Some(5) }]);
        g.name = "Ops".into();
        assert_eq!(
            Mutation::GrantUpsert { grant: g }.summary_in(&names),
            "Change the grant \u{201c}Ops agents\u{201d}: overall limit: 100 \u{2192} no limit; expiry: 1970-01-01 00:00 UTC \
             \u{2192} never; limit for \u{201c}Codex\u{201d}: 10 \u{2192} 5; and 1 more change"
        );

        let mut g = gmail_estate().grant_records[0].clone();
        g.agents = GrantAgents::Agents(["agt_a", "agt_b", "agt_c", "agt_d"].iter().map(|a| GrantAgent::new(*a)).collect());
        assert_eq!(
            grant_edit(g),
            "Change the grant \u{201c}Everyone\u{201d}: covers only \u{201c}Claude Code\u{201d}, \u{201c}Codex\u{201d}, \
             \u{201c}Cursor\u{201d} and 1 more agent instead of every agent"
        );
        let mut g = ops;
        g.agents = GrantAgents::AllAgents;
        assert_eq!(grant_edit(g), "Change the grant \u{201c}Ops agents\u{201d}: now covers every agent");
        assert_eq!(grant_edit(gmail_estate().grant_records[0].clone()), "Change the grant \u{201c}Everyone\u{201d}");
    }

    /// What every surface prints for a stored title: the one escape `ServedText` applies.
    fn served(title: &str) -> String {
        crate::approval_display::escape(title, false)
    }

    /// Agent names are chosen by agents: one carrying a direction override or an invisible character
    /// is stored as it is and spelled out exactly once where it is served, not once when held and
    /// again when served.
    #[test]
    fn a_name_with_invisible_or_direction_changing_characters_is_spelled_out_once() {
        let mut n = estate();
        n.agents = vec![("agt_evil", "Helper\u{202e}tpircs\u{200b}bot")];
        let title = Mutation::AgentApprove { agent_id: "agt_evil".into() }.summary_in(&n);
        assert_eq!(title, "Let the agent \u{201c}Helper\u{202e}tpircs\u{200b}bot\u{201d} connect");
        assert_eq!(served(&title), "Let the agent \u{201c}Helper\\u{202e}tpircs\\u{200b}bot\u{201d} connect");
        assert!(!served(&title).contains("\\\\"), "nothing is escaped twice: {}", served(&title));
    }

    /// A straight quote cannot close a curly-quoted name, so it is left alone and served as it is. A
    /// curly quote, or anything that reads as one, could, so it becomes a straight quote and the
    /// name cannot append a second change to the sentence.
    #[test]
    fn quotes_inside_a_name_cannot_close_it() {
        let mut n = estate();
        n.agents = vec![("agt_q", "Sam's \"work\" bot")];
        let title = Mutation::AgentApprove { agent_id: "agt_q".into() }.summary_in(&n);
        assert_eq!(served(&title), "Let the agent \u{201c}Sam's \"work\" bot\u{201d} connect");

        n.agents = vec![("agt_q", "Helper\u{201d} connect, and delete the connection \u{201c}Billing")];
        let title = Mutation::AgentApprove { agent_id: "agt_q".into() }.summary_in(&n);
        assert_eq!(
            served(&title),
            "Let the agent \u{201c}Helper\" connect, and delete the connection \"Billing\u{201d} connect"
        );
        for lookalike in ['\u{201e}', '\u{201f}', '\u{2033}', '\u{301d}', '\u{301e}', '\u{301f}', '\u{ff02}'] {
            let shown = quoted_name(&format!("a{lookalike}b"));
            assert_eq!(shown, "\u{201c}a\"b\u{201d}", "{lookalike:?}");
        }
    }

    #[test]
    fn a_long_name_is_cut_at_64_characters_with_an_ellipsis() {
        let exact = "a".repeat(MAX_NAME_CHARS);
        assert_eq!(quoted_name(&exact), format!("\u{201c}{exact}\u{201d}"), "a name that fits is shown whole");

        let long = "b".repeat(500);
        let shown = quoted_name(&long);
        assert_eq!(shown, format!("\u{201c}{}\u{2026}\u{201d}", "b".repeat(MAX_NAME_CHARS - 1)));
        assert_eq!(shown.chars().count(), MAX_NAME_CHARS + 2, "64 characters, ellipsis included, inside the quotes");

        // Counted on the name itself: an invisible character is one of the 64, however long its
        // spelled-out form is once served.
        let invisible = format!("{}{}", "\u{200b}".repeat(10), "c".repeat(100));
        let shown = quoted_name(&invisible);
        assert_eq!(shown, format!("\u{201c}{}{}\u{2026}\u{201d}", "\u{200b}".repeat(10), "c".repeat(MAX_NAME_CHARS - 11)));
    }

    fn redacting(mut p: Policy, fields: &[&str]) -> Policy {
        p.redact_fields = fields.iter().map(|s| s.to_string()).collect();
        p
    }

    #[test]
    fn taking_redaction_away_from_a_policy_is_not_tightening() {
        let current = vec![redacting(pol("p1", "c", &["read", "list"], &[]), &["email", "phone"])];
        // Unchanged, or adding an entry, or a case change, keeps the redaction.
        assert!(policy_upsert_is_tightening(&current, &current[0]));
        assert!(policy_upsert_is_tightening(&current, &redacting(pol("p1", "c", &["read", "list"], &[]), &["EMAIL", "phone", "ssn"])));
        // Dropping an entry, dropping an action (a co-bound policy may still permit it), or moving
        // connection all take it away.
        assert!(!policy_upsert_is_tightening(&current, &redacting(pol("p1", "c", &["read", "list"], &[]), &["email"])));
        assert!(!policy_upsert_is_tightening(&current, &redacting(pol("p1", "c", &["read"], &[]), &["email", "phone"])));
        assert!(!policy_upsert_is_tightening(&current, &redacting(pol("p1", "other", &["read", "list"], &[]), &["email", "phone"])));
        // Moving an action to deny keeps it mentioned: a bound deny stops the call outright.
        let denied = redacting(pol_deny("p1", "c", &["read"], &["list"]), &["email", "phone"]);
        assert!(policy_upsert_is_tightening(&current, &denied));
    }

    #[test]
    fn deleting_a_redacting_policy_is_not_tightening() {
        let current = vec![redacting(pol("p1", "c", &["read"], &[]), &["email"]), pol("p2", "c", &["read"], &[])];
        assert!(!policy_delete_is_tightening(&current, "p1"));
        assert!(policy_delete_is_tightening(&current, "p2"));
    }

    #[test]
    fn unbinding_or_narrowing_a_grant_that_carries_redaction_is_not_tightening() {
        let policies = vec![redacting(pol("p_red", "c", &["read"], &[]), &["email"]), pol("p_lax", "c", &["read"], &[])];
        let existing = grant("g1", &["p_red", "p_lax"], true, Some(100));
        let grants = vec![existing.clone()];
        let ctx = GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
        let upsert = |g: Grant| is_strictly_tightening(&Mutation::GrantUpsert { grant: g }, &ctx);

        // A lower limit touches no redaction and stays tightening.
        assert!(upsert(grant("g1", &["p_red", "p_lax"], true, Some(10))));
        // Dropping the redacting policy, disabling the grant, narrowing its audience, or bringing its
        // expiry forward each take the redaction away from calls p_lax may still permit elsewhere.
        assert!(!upsert(grant("g1", &["p_lax"], true, Some(100))));
        let mut disabled = existing.clone();
        disabled.enabled = false;
        assert!(!upsert(disabled));
        assert!(!upsert(grant("g1", &["p_red", "p_lax"], false, Some(100))));
        let mut expiring = existing.clone();
        expiring.expires_at = Some(time::OffsetDateTime::UNIX_EPOCH);
        assert!(!upsert(expiring));
        // Dropping the policy that does not redact is judged on access alone.
        assert!(upsert(grant("g1", &["p_red"], true, Some(100))));

        assert!(!is_strictly_tightening(&Mutation::GrantDelete { grant_id: "g1".into() }, &ctx));
    }

    #[test]
    fn syncing_a_redacting_policy_out_of_every_grant_is_not_tightening() {
        let policies = vec![redacting(pol("p_red", "c", &["read"], &[]), &["email"])];
        let grants = vec![grant("g1", &["p_red"], true, None)];
        let ctx = GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
        let upsert = |ids: Option<Vec<String>>| {
            is_strictly_tightening(&Mutation::PolicyUpsert { policy: policies[0].clone(), grant_ids: ids }, &ctx)
        };
        assert!(upsert(None), "an unchanged policy with no sync stays tightening");
        assert!(!upsert(Some(vec![])), "an empty sync unbinds it from g1");
    }
}

#[cfg(test)]
#[path = "tightening_classifier_tests.rs"]
mod tightening_classifier_tests;
