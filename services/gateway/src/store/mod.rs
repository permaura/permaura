//! The gateway's persistence boundary.
//!
//! [`Store`] is the trait every endpoint depends on. The shipped gateway uses the
//! `rusqlite`-backed store (the `sqlite` feature, `~/.permaura/gateway.db` by default,
//! snapshotted to object storage on a hosted worker); [`memory::MemoryStore`] is the
//! always-available in-memory store the demo and tests run on (an `RwLock<HashMap>`
//! over agents, sessions, grants, the vault, the capability registry, and the
//! hash-chained [`AuditLog`]), and must always work.

pub mod memory;

#[cfg(feature = "sqlite")]
pub mod migrations;

#[cfg(feature = "sqlite")]
pub mod sqlite;

pub mod lock;

/// The SQLite store made durable for a stateless worker by snapshotting to object storage.
#[cfg(feature = "sqlite")]
pub mod persisted;

pub(crate) mod bridge;

#[cfg(feature = "sqlite")]
mod reseal;

use permaura_core::{AuditEvent, AuditPayload, Connection, Grant, Policy, SealedSecret, SecretRecord};

use crate::connectors::Capability;
use crate::error::GatewayError;
use crate::manifest::InstalledManifest;

/// Where an agent is in the enrolment handshake. An agent self-registers over MCP and
/// lands as [`AgentStatus::Pending`]; an operator then [`AgentStatus::Approved`]s it. Only
/// approved agents can have their invokes authorized: a pending agent is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// Self-registered over MCP, awaiting a human's approval. Cannot invoke yet.
    Pending,
    /// Approved by an operator. May invoke (subject to grants).
    ///
    /// This is the serde default so an agent blob persisted before the status field existed
    /// (or one an operator creates directly) reads back as approved rather than silently
    /// losing access. New MCP self-enrolments set [`AgentStatus::Pending`] explicitly.
    #[default]
    Approved,
}

/// A registered agent (codex-cli, claude-code, cursor).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Agent {
    /// Stable agent id, e.g. `codex-cli`.
    pub id: String,
    /// Human-friendly name.
    pub name: String,
    /// Where the agent is in the connect→approve handshake.
    #[serde(default)]
    pub status: AgentStatus,
    /// Unix-millisecond time the agent first enrolled.
    #[serde(default)]
    pub enrolled_at: i64,
}

impl Agent {
    /// Construct an approved agent (the operator-created / seeded path).
    pub fn approved(id: impl Into<String>, name: impl Into<String>, enrolled_at: i64) -> Self {
        Agent {
            id: id.into(),
            name: name.into(),
            status: AgentStatus::Approved,
            enrolled_at,
        }
    }

    /// True if this agent may have its invokes authorized.
    pub fn is_approved(&self) -> bool {
        matches!(self.status, AgentStatus::Approved)
    }
}

/// A one-time enrolment ticket the console mints (`POST /v1/agents/enroll`) and an agent
/// redeems over MCP (`permaura.enroll`). Holds no secret: redeeming it creates a *pending*
/// agent, which a human still has to approve, so a leaked code cannot grant access on its own.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrolmentCode {
    /// The human-pasteable code (e.g. `ENRL-7F3A-9C21-4B8D-E0F1-A2B3-C4D5-E6F7-0819`) as minted, and its digest once stored.
    pub code: String,
    /// The suggested agent name shown to the operator (optional, set when minting).
    #[serde(default)]
    pub label: Option<String>,
    /// Unix-millisecond mint time.
    pub created_at: i64,
    /// Unix-millisecond expiry: after this the code is dead.
    pub expires_at: i64,
    /// Set once an agent has redeemed it (single use).
    #[serde(default)]
    pub used: bool,
}

/// What a session's bearer token is allowed to do. The control plane (console / desktop /
/// CLI / pairing) holds an **operator** token and may drive every endpoint. An **agent**
/// token, minted by MCP self-enrolment or the relay, may only *invoke* capabilities and
/// discover/enrol; it must never be able to mutate the console (approve itself, create
/// grants/policies/connections, write credentials, …). This is the trust boundary that
/// stops a self-enrolled agent from escalating Pending → Approved-with-grants on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    /// Full control plane. The serde default so pre-existing and operator-opened sessions keep
    /// working; agent-scoped paths (MCP enrol, the enrolment-code bootstrap bearer, OAuth agent
    /// tokens, the relay) mint the agent role.
    #[default]
    Operator,
    /// Invoke + discovery + enrol only. No console mutations.
    Agent,
}

/// How long a control-plane session opened via `POST /v1/sessions` authenticates for. Short on
/// purpose and cheap to enforce: the console re-opens transparently on a 401, so bounding it costs
/// nothing a user can feel.
pub const OPERATOR_SESSION_TTL_MS: i64 = 12 * 60 * 60 * 1000;

/// How long an agent's bearer authenticates for. This is the token that actually sits on an agent's
/// disk, so it is the one worth capping, but generously: there is no rotation-with-overlap yet, so a
/// lapsed agent must re-enrol, and a month is long enough that this is a rare event rather than a
/// weekly chore. Tighten it once rotation lands.
pub const AGENT_SESSION_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// How long a session row outlives the moment it stopped being usable, before the sweep deletes it.
///
/// Not zero, deliberately: "my token stopped working yesterday" is answered by the row still being
/// there to look at. A week of that is enough, and after it the row is only weight in a snapshot.
pub const DEAD_SESSION_GRACE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Marks a value as the stored form rather than a bearer, so a read-modify-write cannot re-hash it.
pub const SESSION_HASH_PREFIX: &str = "sha256:";

/// What goes in the `sessions.token` column, and what a lookup compares against.
///
/// A database read used to be a bearer read: the column held the token itself, so a stray SELECT or
/// a copy of the database handed over every live session.
///
/// Already-hashed input passes through, and that is load-bearing rather than tidy. Revoking, touching
/// and expiring all read a session, change a field and write it back, so the value arriving here is
/// usually the stored form and not a bearer at all. Hashing it again would file the row under a hash
/// of a hash and lose it, which is what an existing revocation test caught.
pub fn session_token_hash(token: &str) -> String {
    if token.starts_with(SESSION_HASH_PREFIX) {
        return token.to_string();
    }
    bearer_lookup_hash(token)
}

/// The lookup key for a bearer a caller presented. Never passes a prefixed value through: a stored digest handed back as a bearer must hash to a key that matches no row, or reading the sessions table would be the same as holding every session in it.
pub fn bearer_lookup_hash(bearer: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{SESSION_HASH_PREFIX}{:x}", Sha256::digest(bearer.as_bytes()))
}

/// The row form of a session: the stored hash in place of the bearer, in the column and in the JSON.
pub fn session_at_rest(session: &Session) -> Session {
    Session { token: session_token_hash(&session.token), ..session.clone() }
}

/// The row form of an enrolment code: the same digest a session keeps, in the key and in the JSON. A redeemed code is the bearer of the session it opened (see `EnforcementService::authenticate`), so a row that kept it in clear handed a database reader that agent's session for its whole sliding life. Look a presented code up with [`bearer_lookup_hash`].
pub fn enrolment_code_at_rest(code: &EnrolmentCode) -> EnrolmentCode {
    EnrolmentCode { code: session_token_hash(&code.code), ..code.clone() }
}

/// An agent session: the bearer token an agent presents maps to one of these.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// Stable session id, e.g. `sess_abc`.
    pub id: String,
    /// The agent this session belongs to.
    pub agent_id: String,
    /// The user ultimately responsible, if known.
    pub user_id: Option<String>,
    /// The device the session originated from, if known.
    pub device_id: Option<String>,
    /// The opaque bearer token the agent presents on every call.
    pub token: String,
    /// What this token may do (control plane vs invoke-only). Defaults to operator.
    #[serde(default)]
    pub role: SessionRole,
    /// Unix-millisecond creation time.
    pub created_at: i64,
    /// Whether the session has been revoked (`permaura.revoke_session`).
    pub revoked: bool,
    /// Unix-ms after which this token stops authenticating.
    ///
    /// `None` means no absolute expiry, and is reserved for the install's ROOT operator credential
    /// ([`crate::seed::clean_bootstrap`]): it is published to `operator.token` for the npm launcher and
    /// scraped by the desktop supervisor, so expiring it would strand an install with no way back in.
    /// Rotation-with-overlap is the follow-up that makes capping it possible.
    ///
    /// Sessions written before this field existed deserialize to `None`, so an existing install keeps
    /// working rather than logging everyone out on upgrade.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Unix-ms of the most recent successful authentication. Advisory (inventory / idle reporting),
    /// never an authorization input.
    #[serde(default)]
    pub last_used_at: Option<i64>,
    /// The workspace member acting through this session, when a permaura.com operator token named
    /// one. Recorded in audit summaries, and read for two narrowing decisions only: a held change
    /// records it as who asked, so that member's own devices cannot confirm it alone, and a change
    /// that moves a stored credential takes the gateway's owner or a member whose token carries
    /// permaura.com's signed `vault_export` claim; a role alone never confers it. See
    /// [`SessionActor`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<SessionActor>,
    /// What kind of bearer this is, recorded when it is minted: at rest the bearer is only a digest
    /// (see [`session_at_rest`]), so its prefix cannot be read back off the row.
    #[serde(default, skip_serializing_if = "SessionClass::is_unrecorded")]
    pub class: SessionClass,
    /// The session whose bearer opened this one through `POST /v1/sessions`, so retiring a bearer can retire what was opened from it. `None` for every other session, and for every row stored before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_by: Option<String>,
}

/// The kinds of operator bearer this gateway mints and later has to find again among its sessions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionClass {
    /// Every other session, and every row stored before classes were recorded.
    #[default]
    Unrecorded,
    /// A token published to `operator.token` for the CLI, the desktop supervisor and the installer (`pgt_`).
    OperatorToken,
    /// The console session permaura.com holds sealed for a loopback-only gateway (`pgc_`).
    Console,
}

impl SessionClass {
    /// Whether no class was recorded, so the row's JSON is unchanged for every other session.
    pub fn is_unrecorded(&self) -> bool {
        *self == SessionClass::Unrecorded
    }
}

/// Who is acting behind a shared operator identity, from a permaura.com operator token's `act` claim.
///
/// The console mints every token for a hosted gateway with the gateway owner's `sub`, whichever member
/// is at the keyboard, because the gateway accepts no other subject. This is what lets the audit chain
/// name the member anyway. It is permaura.com's statement about who asked, the same authority that
/// names the actor on a step-up ticket, so the gateway uses it to narrow what a request may do and
/// never to widen what the token's `sub` already allows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionActor {
    /// The acting member's permaura.com user id.
    pub sub: String,
    /// Their display name when they acted, when the console sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Their organization role when permaura.com names one, `owner` or `admin` and nothing else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `Some(true)` when permaura.com signed that the acting member holds the Export the vault capability, the standing a change that moves a stored credential takes. Never widened from a role: the console signs it only for holders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_export: Option<bool>,
}

/// Who asked for a held control-plane change, so the person who asked is not the one who confirms it.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct HoldRequester {
    /// The account the request was made as: the acting member a permaura.com operator token or
    /// step-up ticket names, in the namespace a hosted worker binds approver keys to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    /// The device the requesting operator session belongs to, when it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// The most independent of the requester any trusted key was when the hold was created. Confirming it
    /// takes at least this much for as long as it waits, so revoking the devices that were independent of
    /// the requester cannot turn their own device into a sufficient signer. `None` on a hold created before
    /// this was recorded, which takes what the keyring offers when it is confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_independence: Option<crate::relay::approver::Independence>,
}

impl HoldRequester {
    /// How an approval surface is shown who asked: the person as the opaque handle `GET /v1/approver-keys` lists keys under, never the account id, so a device can tell its own request from someone else's without the queue naming anyone. Absent parts are omitted.
    pub fn served(&self) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        if let Some(person) = &self.person {
            out.insert("person_handle".into(), crate::service::person_handle(person).into());
        }
        if let Some(device_id) = &self.device_id {
            out.insert("device_id".into(), device_id.clone().into());
        }
        if let Some(independence) = self.required_independence {
            out.insert("required_independence".into(), serde_json::json!(independence));
        }
        serde_json::Value::Object(out)
    }

    /// `None` when the request named nobody, so a hold never records an empty requester.
    pub fn named(person: Option<String>, device_id: Option<String>) -> Option<Self> {
        let person = person.filter(|p| !p.trim().is_empty());
        let device_id = device_id.filter(|d| !d.trim().is_empty());
        (person.is_some() || device_id.is_some()).then_some(Self { person, device_id, required_independence: None })
    }
}

impl Session {
    /// Has this session's absolute lifetime run out at `now` (unix-ms)? A `None` expiry never has.
    pub fn is_expired(&self, now: i64) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    /// Whether this row is the only record that its holder was stopped, so deleting it lets that holder back in.
    ///
    /// A revoked OAuth agent row: the client still holds a valid permaura.com token, and with no row its next call
    /// registers it afresh. A revoked relayed identity: the control plane can relay that session again, and the next
    /// relayed invoke would recreate the row unrevoked. The dead-session sweep and a restore's invalidation both keep
    /// these, and both read this one rule.
    pub fn is_revocation_tombstone(&self) -> bool {
        self.revoked && (self.id.starts_with("sess_oauth:") || self.id.starts_with("relay:"))
    }
}

/// The status a held call lands in when a human approved it, the durable claim was spent, and the
/// execution then failed.
///
/// It is not `denied`, because a denial is the claim that nothing ran and the upstream request may
/// well have landed; it is not `approved`, because there is no result; and it is not left `pending`,
/// because that is a question on an operator's dashboard that has in fact been answered, and the
/// control plane would go on waiting for it. The audit chain carries which of `unknown` and
/// `refused` the upstream outcome was; this row only says the resolution is over.
///
/// **It is terminal.** [`crate::service::EnforcementService::resolve_approval`] returns any
/// non-`pending` approval unchanged, so a second approve cannot re-run the call, and the spent
/// `claim_once` row refuses it a second time even if this status were edited back by hand.
pub const APPROVAL_UNRESOLVED: &str = "unresolved";

/// The status of a held control-plane change nobody confirmed before its deadline. Terminal like [`APPROVAL_UNRESOLVED`]: nothing was applied, and the change has to be asked for again.
pub const APPROVAL_EXPIRED: &str = "expired";

/// The `resource` every held control-plane change is filed under. A held agent call names its connection there, which is why no connection may take this id.
pub const CONTROL_PLANE_RESOURCE: &str = "control-plane";

/// How long a held control-plane change waits for a device before it is retired as [`APPROVAL_EXPIRED`].
pub const CONTROL_PLANE_HOLD_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// A pending approval created when a decision is `requires_approval`. The gateway
/// records it so a human (from the console or desktop, or by signing on a paired device) can
/// later resolve it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingApproval {
    /// Stable approval id, e.g. `appr_abc`.
    pub id: String,
    /// The session that triggered it.
    pub session_id: String,
    /// The capability awaiting approval.
    pub capability: String,
    /// The resource the capability acts on.
    pub resource: String,
    /// Human-readable description of exactly what is being approved.
    pub message: String,
    /// `pending` | `approved` | `denied` | [`APPROVAL_UNRESOLVED`] | [`APPROVAL_EXPIRED`].
    pub status: String,
    /// The grant that authorized the held call, so its budget can be charged and the
    /// approval audited against the exact policy→grant chain. `None` for approvals seeded
    /// directly (e.g. in tests) or created before this field existed.
    #[serde(default)]
    pub grant_id: Option<String>,
    /// The policy the held call was evaluated against.
    #[serde(default)]
    pub policy_id: Option<String>,
    /// The agent-supplied params, retained so the held call can be executed verbatim once a human approves.
    /// Kept as the text the row stores, in canonical key order, so reading a row (or every row) costs its bytes and builds no tree; the call's execution parses it under the memory budget when a human approves it.
    #[serde(default)]
    pub params: permaura_core::JsonText,
    /// The redacted upstream result, populated when the approval is approved and the held call runs. `None` while pending or denied. Kept as its text, as the agent received it.
    #[serde(default)]
    pub result: Option<permaura_core::JsonText>,
    /// The upstream HTTP status of the executed call, if any.
    #[serde(default)]
    pub result_status: Option<u16>,
    /// Why this approval was resolved the way it was, when it was not a human's decision.
    ///
    /// Written by reconciliation, with [`crate::reconcile::DENIED_BY_RESTORE`]: the restore's invalidation
    /// denies every pending approval on a restored database, and a row that simply read `denied`
    /// would tell an owner their approver had refused a call nobody ever saw. Also written, with
    /// [`crate::service::DENIED_SESSION_ENDED`], when a human approved a held call whose session had
    /// been revoked, had expired or was gone, so the gateway refused it. `None` is every approval a
    /// human resolved and every row stored before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_reason: Option<String>,
    /// Unix-millisecond creation time (drives the queue ordering and TTL).
    #[serde(default)]
    pub created_at: i64,
    /// Absolute unix-ms moment this hold is abandoned, captured when it was held. `None` means it
    /// has no deadline. That is every hold while [`crate::relay::APPROVAL_TTL_MS`] is zero, and
    /// also what a row stored before this field existed actually had.
    ///
    /// Captured rather than recomputed so a change to the TTL cannot move a live hold's deadline
    /// under a human who is already looking at it.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// The gateway's own risk classification of the held capability, captured at hold time.
    ///
    /// `None` reports as `unknown`, never as a tier. A capability's risk is editable, so
    /// classifying it at read time would let an edit rewrite what the human is being asked about a
    /// request held an hour ago; and a row that predates this field has no classification to
    /// recover, which is a thing to admit rather than guess.
    #[serde(default)]
    pub risk: Option<permaura_core::RiskTier>,
    /// One human sentence naming what runs if this is approved: the capability's own description,
    /// or the summary of a held control-plane change. `None` when the gateway has none, and the
    /// client falls back to `message`.
    #[serde(default)]
    pub action_description: Option<String>,
    /// What the agent said the call is for (its `reason`), kept so an approver can read the claim
    /// against the parameters. The agent's words, never the gateway's; `None` for a hold no agent asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// The ladder rung this approval must be resolved at: `approve` (an operator bearer or a
    /// device signature) or `device_signed` (a device signature ONLY). Defaults to `approve`,
    /// which covers every approval stored before this field existed and preserves their
    /// bearer-resolvable behaviour.
    #[serde(default = "default_required_tier")]
    pub required_tier: String,
    /// How many **distinct** paired devices must sign before this runs (the two-person rule).
    /// `1` (the default, and what every approval stored before this field existed deserialises
    /// to) is the single-signature behaviour. Only meaningful on the `device_signed` tier.
    #[serde(default = "default_required_signatures")]
    pub required_signatures: u8,
    /// The verified signatures collected so far, in arrival order. Written **only** after a
    /// signature has passed every check in `verify_signed_approval`, so this is a record of
    /// proven approvals, never of attempts.
    #[serde(default)]
    pub signatures: Vec<CollectedSignature>,
    /// Who asked for a held control-plane change or vault export. `None` on a held agent call, whose
    /// requester is its session, and on a hold whose request named nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<HoldRequester>,
}

/// What an agent polling its approval reads ([`Store::get_approval_outcome`]): the row's status fields and its result, without its params, which this gateway may have written several times longer than the body they were sent in. The result is the row's own bytes, served without a copy.
#[derive(Debug, Clone)]
pub struct ApprovalOutcome {
    /// As [`PendingApproval::id`].
    pub id: String,
    /// As [`PendingApproval::session_id`].
    pub session_id: String,
    /// As [`PendingApproval::status`].
    pub status: String,
    /// As [`PendingApproval::message`].
    pub message: String,
    /// As [`PendingApproval::result_status`].
    pub result_status: Option<u16>,
    /// As [`PendingApproval::expires_at`].
    pub expires_at: Option<i64>,
    /// As [`PendingApproval::risk`].
    pub risk: Option<permaura_core::RiskTier>,
    /// As [`PendingApproval::action_description`].
    pub action_description: Option<String>,
    /// The result's JSON text, `None` while there is none.
    pub result: Option<axum::body::Bytes>,
}

impl ApprovalOutcome {
    /// As [`PendingApproval::risk_label`].
    pub fn risk_label(&self) -> String {
        self.risk.map_or_else(|| RISK_UNKNOWN.to_string(), |r| r.to_string())
    }

    /// The outcome of `approval`.
    pub fn of(approval: PendingApproval) -> Self {
        ApprovalOutcome {
            id: approval.id,
            session_id: approval.session_id,
            status: approval.status,
            message: approval.message,
            result_status: approval.result_status,
            expires_at: approval.expires_at,
            risk: approval.risk,
            action_description: approval.action_description,
            result: approval.result.map(|result| axum::body::Bytes::from(result.into_string())),
        }
    }

    /// The outcome of the approval whose stored row is `text`, read without building its params or copying its result, which is served from the row's own bytes: one copy of the row, where reading it whole held its text and the row beside it.
    pub fn from_row_text(text: String) -> Result<Self, serde_json::Error> {
        #[derive(serde::Deserialize)]
        struct Row<'a> {
            id: String,
            session_id: String,
            status: String,
            message: String,
            #[serde(default)]
            result_status: Option<u16>,
            #[serde(default)]
            expires_at: Option<i64>,
            #[serde(default)]
            risk: Option<permaura_core::RiskTier>,
            #[serde(default)]
            action_description: Option<String>,
            #[serde(default, borrow)]
            result: Option<&'a serde_json::value::RawValue>,
        }
        let bytes = axum::body::Bytes::from(text);
        let row: Row<'_> = serde_json::from_slice(&bytes)?;
        let result = row.result.map(|raw| {
            let len = raw.get().len();
            match (raw.get().as_ptr() as usize).checked_sub(bytes.as_ptr() as usize) {
                Some(at) if at + len <= bytes.len() => bytes.slice(at..at + len),
                _ => axum::body::Bytes::copy_from_slice(raw.get().as_bytes()),
            }
        });
        Ok(ApprovalOutcome {
            id: row.id,
            session_id: row.session_id,
            status: row.status,
            message: row.message,
            result_status: row.result_status,
            expires_at: row.expires_at,
            risk: row.risk,
            action_description: row.action_description,
            result,
        })
    }
}

/// The one spelling of "this gateway did not classify it", so nine surfaces cannot disagree about
/// what an unclassified approval is called.
pub const RISK_UNKNOWN: &str = "unknown";

impl PendingApproval {
    /// The wire spelling of this approval's captured risk: a tier, or `unknown`.
    pub fn risk_label(&self) -> String {
        self.risk.map_or_else(|| RISK_UNKNOWN.to_string(), |r| r.to_string())
    }

    /// Whether this is a held control-plane change: filed under [`CONTROL_PLANE_RESOURCE`] with no requesting agent session.
    pub fn is_control_plane_hold(&self) -> bool {
        self.session_id.is_empty() && self.resource == CONTROL_PLANE_RESOURCE
    }

    /// When this hold stops being decidable, in unix ms, or `None` when it never does.
    ///
    /// The captured [`Self::expires_at`] is the authority, and this is the number every client is
    /// shown as well as the one [`Self::is_expired`] enforces, so display and enforcement cannot
    /// disagree. Recomputing it from a TTL constant would let them drift the moment that constant
    /// changed.
    ///
    /// The one exception is a held control-plane change stored with no deadline, which an earlier
    /// build wrote for every one of them: it lapses [`CONTROL_PLANE_HOLD_TTL_MS`] after it
    /// was held, because a held change that never lapses lets a stale request (a removal of
    /// someone's device, say) be confirmed days later by whoever still can. Every other `None`
    /// never expires: an agent call was accepted on the understanding that it would wait.
    pub fn deadline(&self) -> Option<i64> {
        self.expires_at.or_else(|| {
            self.is_control_plane_hold().then(|| self.created_at.saturating_add(CONTROL_PLANE_HOLD_TTL_MS))
        })
    }

    /// Has this hold run out at `now` (unix ms)? Read against [`Self::deadline`].
    pub fn is_expired(&self, now: i64) -> bool {
        matches!(self.deadline(), Some(t) if now > t)
    }
}

/// One verified device signature on a pending approval.
///
/// Records the approver **and** a fingerprint of the worker-local trusted key it verified
/// against. The key matters independently: two approver ids backed by the same key are one
/// physical device, and must not be able to satisfy a two-person rule between them.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CollectedSignature {
    /// The approver id that signed, e.g. `device:sam-iphone`.
    pub approver: String,
    /// A short fingerprint of the trusted public key the signature verified against. Not a
    /// credential: a public key digest, used for distinctness and for the console to show
    /// *which* device signed.
    pub key_fp: String,
    /// The signer's `decided_at`, unix ms.
    pub decided_at: i64,
}

/// One signature: the pre-quorum behaviour, and what an approval stored before the field
/// existed must keep meaning.
fn default_required_signatures() -> u8 {
    1
}

/// The default rung for an approval with no explicit tier: the bearer-or-signature `approve`
/// rung, matching pre-ladder behaviour.
pub fn default_required_tier() -> String {
    "approve".to_string()
}

/// Which custody layer physically holds a secret's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyKind {
    /// The gateway's own sealed `secrets` rows, opened under the local KEK passphrase.
    ///
    /// The serde default, and the floor beneath everything: a secret with no custody record at all
    /// resolves here, so an install that never enrols anything behaves exactly as it always did.
    #[default]
    LocalVault,
    /// An Infisical project the worker fetches from at call time (BYO vault).
    Infisical,
    /// A cloud KMS: the record carries the wrapped ciphertext and the CMK does the unwrapping, so
    /// the plaintext exists only for the life of one call and never at rest on this worker.
    Kms,
}

impl CustodyKind {
    /// The persisted / wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            CustodyKind::LocalVault => "local_vault",
            CustodyKind::Infisical => "infisical",
            CustodyKind::Kms => "kms",
        }
    }

    /// True when the bytes live outside this gateway's own store.
    pub fn is_external(self) -> bool {
        !matches!(self, CustodyKind::LocalVault)
    }
}

/// Where one secret's bytes live, recorded per secret, in the store.
///
/// Custody used to be an environment variable (`PERMAURA_KMS_SECRETS`, `PERMAURA_INFISICAL_SECRETS`),
/// which meant enrolling a secret required a redeploy and nothing in the product ever wrote one. As a
/// store row it is a runtime fact: enrolment is an operation, and the set of externally-held secrets
/// can be **enumerated** (see [`crate::secret_inventory`]) rather than inferred.
///
/// The record holds no plaintext. The KMS ciphertext it carries is not a secret: only `Decrypt`
/// permission on the CMK turns it back into plaintext, and that permission is the custody root.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretCustody {
    /// The secret id this record is custody for: the same id capabilities and connections carry.
    pub secret_id: String,
    /// Which layer holds the bytes.
    pub kind: CustodyKind,
    /// KMS only: the wrapped ciphertext produced once at enrolment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_ciphertext: Option<Vec<u8>>,
    /// KMS only: the CMK resource name the ciphertext was wrapped under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
    /// Infisical only: the remote secret name, when it differs from `secret_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infisical_name: Option<String>,
    /// Unix-millisecond time custody was recorded.
    #[serde(default)]
    pub enrolled_at: i64,
}

impl SecretCustody {
    /// A record pinning a secret to the local sealed vault: the explicit spelling of the default.
    pub fn local(secret_id: impl Into<String>, enrolled_at: i64) -> Self {
        SecretCustody {
            secret_id: secret_id.into(),
            kind: CustodyKind::LocalVault,
            kms_ciphertext: None,
            kms_key_id: None,
            infisical_name: None,
            enrolled_at,
        }
    }

    /// A KMS record: the wrapped ciphertext plus the CMK it was wrapped under.
    pub fn kms(
        secret_id: impl Into<String>,
        ciphertext: Vec<u8>,
        key_id: impl Into<String>,
        enrolled_at: i64,
    ) -> Self {
        SecretCustody {
            secret_id: secret_id.into(),
            kind: CustodyKind::Kms,
            kms_ciphertext: Some(ciphertext),
            kms_key_id: Some(key_id.into()),
            infisical_name: None,
            enrolled_at,
        }
    }

    /// An Infisical record. `remote_name` is only needed when the Infisical secret is named
    /// differently from `secret_id`.
    pub fn infisical(
        secret_id: impl Into<String>,
        remote_name: Option<String>,
        enrolled_at: i64,
    ) -> Self {
        SecretCustody {
            secret_id: secret_id.into(),
            kind: CustodyKind::Infisical,
            kms_ciphertext: None,
            kms_key_id: None,
            infisical_name: remote_name,
            enrolled_at,
        }
    }
}

/// `gateway_meta` key holding the serialized approver keyring: its home on every placement unless
/// `PERMAURA_APPROVER_KEYS_PATH` names a file.
///
/// A hosted worker (Mode C) has no other durable home, since its filesystem is gone on the next cold
/// start: a keyring file there would forget every device a tenant paired at a scale-to-zero, and
/// re-pairing would be the *only* way back to a device-signed approval.
pub const APPROVER_KEYRING_META: &str = "approver_keyring";

/// `gateway_meta` key holding this gateway's **approval audience**: a random value minted once and
/// bound into every v2 device signature, so a signature a device made for this gateway verifies here
/// and nowhere else. Public by design (it is served beside every approval); what matters is that it
/// differs per gateway and never changes, because each device pins it at pairing.
pub const APPROVAL_AUDIENCE_META: &str = "approval_audience";

/// `gateway_meta` key holding the approver ids that have presented a valid v2 (audience-bound)
/// signature here, as a JSON array. A v1 signature from any of them is refused even while v1 is
/// otherwise accepted: a device that signs v2 for this gateway never needs to sign v1 for it, so a v1
/// signature carrying its id can only have been collected somewhere else.
pub const DEVICE_SIG_V2_APPROVERS_META: &str = "device_sig_v2_approvers";

/// `gateway_meta` key holding the approver ids that have presented a valid v3 signature here, one
/// that binds the parameter rendering the approver was shown, as a JSON array. An approval
/// signed by any of them without that binding is refused: their app shows the parameters before it
/// signs, so an approval that does not bind them did not come from it.
pub const DEVICE_SIG_DISPLAY_APPROVERS_META: &str = "device_sig_display_approvers";

/// `gateway_meta` key holding the approval-floor override.
///
/// The floor is derived (`device_signed` once anything has ever been enrolled), so on a hosted
/// worker it inherits the keyring's durability problem and makes it worse: losing the keyring resets
/// `ever_enrolled()`, the floor silently falls back to `approve`, and bearer-only approval
/// resolution re-opens on an install whose owner believes a phone is required. That is a fail-OPEN
/// caused by nothing more than an idle container being reaped, which is why both facts move into the
/// store rather than staying on disk.
pub const APPROVAL_FLOOR_META: &str = "approval_floor";

/// `gateway_meta` key holding the quorum high-water marks: for each (connection, action) a rule above
/// one has held, the most people it took, kept after the rule leaves force until a change signed by that
/// many people moves the action.
pub const QUORUM_HIGH_WATER_META: &str = "quorum_high_water";

/// `gateway_meta` key that is `1` while the stored floor is an opt-down written with no device
/// trusted, so the next first device paired clears it rather than inheriting it.
pub const APPROVAL_FLOOR_UNANCHORED_META: &str = "approval_floor_unanchored";

/// `gateway_meta` key that is `1` once this gateway has written down the floor it was enforcing before
/// the policy decided it (`EnforcementService::adopt_enrolment_floor`), so no later start does it again.
pub const APPROVAL_FLOOR_ADOPTED_META: &str = "approval_floor_adopted";

/// `gateway_meta` key prefix, followed by an approval id, for what a held policy or grant change loosened on the estate
/// it was held against (`policy_guard::HeldEffect`), together with a digest of that estate. Written by the gateway beside the hold and read at the confirm;
/// nothing a device signs or a surface shows carries it. Emptied, best effort, when the gateway confirms, denies, expires
/// or retires the hold itself; a hold a restore denies leaves its row, which nothing reads again.
pub const HELD_EFFECT_META_PREFIX: &str = "held_effect:";

/// How deeply a stored approval's `result` may nest. serde_json reads 128 levels at most and the row
/// wraps the result in one more, so an upstream body at its limit was written and could never be read
/// back; anything deeper than this is replaced by a marker when the row is written.
pub const MAX_STORED_RESULT_DEPTH: usize = 64;

/// The most bytes of `result` a stored approval keeps (8 MiB); a larger one is replaced by a marker naming its size. Above what a call can bring back under the default response and transfer caps (5 MiB, and a 5 MiB SFTP body base64-encoded, about 6.7 MiB), so for a realistic document it applies only to a cap an operator raised.
/// Writing a row holds it and its text written at its length, then the text and SQLite's copy of it, and reading one back holds its text and the row: twice a result this size at most, inside an execution's share of the hosted memory arithmetic ([`crate::limits::DEFAULT_HOSTED_JSON_POOL_BYTES`]).
pub const MAX_STORED_RESULT_BYTES: usize = 8 * 1024 * 1024;

/// How many bytes `cap` takes as a stored row: its fields as JSON, as the SQLite store writes them.
pub fn capability_row_bytes(cap: &Capability) -> u64 {
    #[derive(serde::Serialize)]
    struct Row<'a> {
        id: &'a str,
        description: &'a str,
        risk: permaura_core::RiskTier,
        action: permaura_core::Action,
        requires_approval: bool,
        resource: &'a str,
        secret_id: &'a str,
        kind: crate::connectors::CapabilityKind,
        command: &'a Option<crate::connectors::CommandSpec>,
        http: &'a Option<crate::connectors::HttpSpec>,
        ssh: &'a Option<crate::connectors::SshSpec>,
    }
    let row = Row {
        id: &cap.id,
        description: &cap.description,
        risk: cap.risk,
        action: cap.action,
        requires_approval: cap.requires_approval,
        resource: &cap.resource,
        secret_id: &cap.secret_id,
        kind: cap.kind,
        command: &cap.command,
        http: &cap.http,
        ssh: &cap.ssh,
    };
    row_len(&row)
}

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

/// How many bytes `value` takes as one row's JSON text, counted as it is written and never held.
pub fn row_len<T: serde::Serialize + ?Sized>(value: &T) -> u64 {
    let mut counted = Counted(0);
    match serde_json::to_writer(&mut counted, value) {
        Ok(()) => counted.0 as u64,
        Err(_) => 0,
    }
}

/// `value` as one row's JSON text, written into a buffer allocated once at its length, so a large row is never held beside a doubled buffer it is growing into.
pub(crate) fn row_text<T: serde::Serialize>(value: &T) -> serde_json::Result<String> {
    let mut counted = Counted(0);
    serde_json::to_writer(&mut counted, value)?;
    let mut out = Vec::with_capacity(counted.0);
    serde_json::to_writer(&mut out, value)?;
    // serde_json writes UTF-8 only.
    Ok(String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// Cut a stored approval's `result` to what the store can always read back: anything nested deeper
/// than [`MAX_STORED_RESULT_DEPTH`] becomes a marker, and a result larger than
/// [`MAX_STORED_RESULT_BYTES`] becomes one marker naming its size. Every store applies it on write.
/// The size is judged first, on the result and then on its cut before the cut is written, so a bounding never holds more than two documents of that size.
pub(crate) fn bound_stored_result(approval: &mut PendingApproval) {
    let Some(result) = approval.result.as_mut() else { return };
    let omitted = |bytes: usize| {
        permaura_core::JsonText::from_value(&serde_json::json!({
            "omitted": format!("the result was {bytes} bytes, more than a stored approval keeps"),
            "bytes": bytes,
        }))
    };
    let bytes = result.len();
    if bytes > MAX_STORED_RESULT_BYTES {
        tracing::warn!(approval = %approval.id, bytes, "this approval's result is too large to store; it is stored as a marker");
        *result = omitted(bytes);
        return;
    }
    let marker = format!("[omitted: nested more than {MAX_STORED_RESULT_DEPTH} levels deep]");
    match permaura_core::json_stream::cut_deeper_than(result, MAX_STORED_RESULT_DEPTH, &marker, MAX_STORED_RESULT_BYTES) {
        permaura_core::json_stream::Cut::Unchanged => {}
        permaura_core::json_stream::Cut::Cut(cut) => {
            tracing::warn!(
                approval = %approval.id,
                "this approval's result nests deeper than {MAX_STORED_RESULT_DEPTH} levels; the deeper part is stored as a marker"
            );
            *result = cut;
        }
        permaura_core::json_stream::Cut::TooLarge(bytes) => {
            tracing::warn!(approval = %approval.id, bytes, "this approval's result, cut at its depth limit, is too large to store; it is stored as a marker");
            *result = omitted(bytes);
        }
    }
}

/// The refusal [`Store::mint_enrolment_code`] gives when `live` codes are already waiting to be redeemed.
pub fn too_many_enrolment_codes(live: usize) -> GatewayError {
    GatewayError::TooManyRequests {
        reason: "enrolment_codes".to_string(),
        message: format!(
            "{live} enrolment codes are already waiting to be redeemed on this gateway, the most it keeps; use one, or wait for one to expire (15 minutes after it was minted), then mint another"
        ),
        retry_after_secs: 60,
        scope: None,
    }
}

/// `gateway_meta` key holding "Pause all agents", `true` or `false` (absent is `false`).
///
/// It lived only in memory, so any cold start (a fleet roll, a crash, a stale exit) lifted it with no
/// device signature while the console said every action stays denied until resumed.
pub const BROKER_PAUSED_META: &str = "broker_paused";

/// `gateway_meta` key holding the new-agent approval gate, `true` or `false` (absent leaves it to its default, see `EnforcementService::agent_gate_default`), kept
/// for the same reason as [`BROKER_PAUSED_META`]. `PERMAURA_REQUIRE_AGENT_APPROVAL` engages the gate
/// for a run without writing this row.
pub const BROKER_REQUIRE_AGENT_APPROVAL_META: &str = "broker_require_agent_approval";

/// `gateway_meta` key: `1` when the stored new-agent gate `false` was written on a gateway reachable from off the host while no device was trusted, so the first device paired clears it back to the default, as [`APPROVAL_FLOOR_UNANCHORED_META`] does for the floor.
pub const BROKER_REQUIRE_AGENT_APPROVAL_UNANCHORED_META: &str = "broker_require_agent_approval_unanchored";

/// `gateway_meta` key holding the new-agent gate default the audit chain last recorded, `true` or `false`; absent before any was, which is what every gateway upgraded from a build where the gate had no default reads.
pub const AGENT_GATE_DEFAULT_RECORDED_META: &str = "agent_gate_default_recorded";

/// `gateway_meta` key holding the unix-millisecond boot of the first run that had `PERMAURA_AGENTS_PAUSED` set since agents last ran, empty once a run without it has moved every agent session's clock past the pause. While it is set no agent session is expired, retired or deleted for having gone unused.
pub const AGENTS_PAUSED_SINCE_META: &str = "agents_paused_since";

/// When the current deployment pause began ([`AGENTS_PAUSED_SINCE_META`]), `None` when agents are not paused.
pub fn agents_paused_since(store: &dyn Store) -> Result<Option<i64>, GatewayError> {
    Ok(store.get_meta(AGENTS_PAUSED_SINCE_META)?.and_then(|v| v.parse::<i64>().ok()))
}

/// `gateway_meta` key holding the unix-millisecond start of the first build here that records who asked for a held control-plane change or export. A hold naming nobody from before it predates the recording rather than naming nobody.
pub const HOLD_REQUESTERS_RECORDED_SINCE_META: &str = "hold_requesters_recorded_since";

/// `gateway_meta` key holding the **replay floor**: a unix-millisecond instant at or below which
/// every one-time token is refused, whatever the `one_time_claims` ledger says.
///
/// Single use is enforced by that ledger, and a restore rolls the ledger back to what it held when
/// the checkpoint was taken. Every step-up ticket, pairing ticket, recovery code claim and approval
/// claim spent since is therefore unspent again, and a copy of any of them that leaked in the
/// meantime becomes live. The floor is the fact the ledger cannot supply: it is set once, during
/// reconciliation, to at least the instant the abandoned generation reached, and after that a token
/// minted before the restore cannot be presented no matter how the ledger was rewound.
///
/// **Absent means no floor**, which is every gateway that has never been restored, and on those the
/// behaviour is exactly what it was. It is never lowered:
/// [`crate::restore::raise_replay_floor`] is the only writer and it takes a maximum.
pub const REPLAY_FLOOR_META: &str = "replay_floor_ms";

/// The most approvals one gateway will hold waiting for a human (1024).
///
/// The number and the threat both come from the in-memory store, which has carried this cap and its
/// reasoning ("a flood of relayed `requires_approval` calls cannot grow it without bound, a remote
/// memory-DoS") since long before this constant existed. It lives here because the store that
/// actually ships is SQLite and the two must agree: a mitigation present only in the store nobody
/// runs in production is worse than no mitigation, because it reads as covered.
///
/// It counts **pending** rows only. A resolved approval is a cached result, and a queue of holds a
/// human has already dealt with is not the thing an attacker can grow.
///
/// On a hosted worker the cost is not memory alone: every hold is a full snapshot upload, so 1024 of
/// them is 1024 uploads and a permanently larger database (`relay::APPROVAL_TTL_MS` is 0, so no held
/// agent call ever expires on its own).
///
/// *Measure:* the realistic count of simultaneously pending approvals for one operator, which is a
/// small number, and the snapshot bytes 1024 held approvals add, because a hold carries the agent's whole
/// `params`, so that is the figure that decides whether 1024 is generous or already too large.
pub const MAX_PENDING_APPROVALS: usize = 1024;

/// What a caller is told to wait when the hold queue is full, in seconds (300).
///
/// A politeness rather than a promise: nothing here clears on a timer, because a hold is cleared by
/// a human. Long enough that a retrying agent is not the reason an operator cannot work through the
/// queue.
const APPROVAL_BACKLOG_RETRY_AFTER_SECS: u64 = 300;

/// The refusal both stores raise when a new hold would pass [`MAX_PENDING_APPROVALS`].
///
/// A 429 rather than a 403: the caller is not forbidden from asking, there is no room to record the
/// question right now, and the remedy is a human working through the queue. `reason` is
/// `approval_backlog`, distinct from the admission limiter's `rate`, `queue` and `busy` and from the
/// audit ceiling's `audit_backlog`, because the four have nothing in common but the status code.
pub fn too_many_pending_approvals(pending: usize) -> GatewayError {
    GatewayError::TooManyRequests {
        reason: "approval_backlog".to_string(),
        message: format!(
            "this gateway already holds {pending} approvals waiting for a human, at its \
             {MAX_PENDING_APPROVALS} ceiling; no new call can be held until some are resolved"
        ),
        retry_after_secs: APPROVAL_BACKLOG_RETRY_AFTER_SECS,
        scope: None,
    }
}

/// Refuse a write that would move a settled approval to another status.
///
/// Once an approval has left `pending` it records how a human's question ended, and the audit chain holds
/// the event that ended it. The settled status itself can be written again, with a result added, but a
/// write carrying any other status comes from a view taken before it settled (the boot settlement calling
/// a finished call interrupted, a second resolution), and it is refused rather than allowed to rewrite the
/// record.
pub(crate) fn refuse_settled_approval_rewrite(id: &str, from: &str, to: &str) -> Result<(), GatewayError> {
    if from == "pending" || from == to {
        return Ok(());
    }
    Err(GatewayError::Conflict(format!(
        "approval '{id}' is already settled as {from}, and a settled approval keeps its status: it was not changed to {to}"
    )))
}

/// The refusal for a set of holds made together, such as a vault import's credential fills, that would pass [`MAX_PENDING_APPROVALS`] while `pending` is still below it: it names the set's own size and the room left, since the gateway is not yet at its ceiling. At or past the ceiling it is [`too_many_pending_approvals`].
pub fn too_many_held_together(holding: usize, pending: usize) -> GatewayError {
    if pending >= MAX_PENDING_APPROVALS {
        return too_many_pending_approvals(pending);
    }
    let free = MAX_PENDING_APPROVALS - pending;
    GatewayError::TooManyRequests {
        reason: "approval_backlog".to_string(),
        message: format!(
            "this would hold {holding} approvals for a human together, but the gateway has room for {free} more \
             ({pending} of {MAX_PENDING_APPROVALS} are waiting); none was held. Resolve some, or send fewer at once"
        ),
        retry_after_secs: APPROVAL_BACKLOG_RETRY_AFTER_SECS,
        scope: None,
    }
}

/// Wall-clock unix milliseconds, the store layer's one notion of "now", used to prune claims whose
/// token has already expired. Shared so the three stores cannot disagree about what has lapsed.
/// How long a [`CallDiagnostic`] is kept before the next write prunes it.
pub const CALL_DIAGNOSTICS_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// The most [`CallDiagnostic`] rows kept, whatever their age, so an agent hammering a failing
/// upstream cannot grow the store (or, on a hosted worker, its snapshot) without bound.
pub const CALL_DIAGNOSTICS_MAX: usize = 1_000;

/// The free-text explanation of one failed call, kept beside the audit chain rather than in it.
///
/// The chain is signed and permanent, and redaction works by key name, so an upstream that echoes a
/// credential inside an error string would be signed into history with no way to remove it. This row
/// can be purged ([`Store::purge_call_diagnostics`]) and ages out on its own. The terminal event it
/// explains carries `"diagnostic": true`, so a reader can tell "purged" from "never had one".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallDiagnostic {
    /// The seq of the terminal audit event this explains.
    pub audit_seq: u64,
    /// Unix ms it was written.
    pub recorded_at: i64,
    /// What went wrong, already trimmed and capped.
    pub message: String,
    /// Response headers that are on the allowlist but whose values are upstream-chosen text (request
    /// ids, `www-authenticate`), and so are kept here rather than signed into the chain.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// One grant's counting window: which grant, and the earliest event timestamp that counts towards
/// it. A `Total`-period grant's window starts at [`i64::MIN`], which is every event ever recorded.
///
/// Borrowed rather than owned because the caller already holds the grants it built these from, and a
/// count taken on the execution path should not allocate a string per grant to ask its question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantWindow<'a> {
    /// The grant whose budget is being measured.
    pub grant_id: &'a str,
    /// The earliest `timestamp` that counts, inclusive.
    pub since_ms: i64,
}

/// What a grant and each agent within it have already spent, as a tally rather than as the events
/// it was taken from.
///
/// Both tiers are counted in the same pass because the policy engine consults both for the same
/// grant, and counting per-agent for **every** agent seen rather than only for the caller
/// keeps the answer correct whoever asks. The map is bounded by the distinct `(grant, agent)` pairs
/// that actually appear in the window, which is a handful in practice and never more than the
/// window itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantUsageCounts {
    totals: std::collections::HashMap<String, u64>,
    per_agent: std::collections::HashMap<(String, String), u64>,
}

impl GrantUsageCounts {
    /// Calls charged to this grant across all its agents, within the window it was counted over.
    pub fn total(&self, grant_id: &str) -> u64 {
        self.totals.get(grant_id).copied().unwrap_or(0)
    }

    /// Every agent that has been charged against `grant_id` within the window, in order.
    pub fn agents(&self, grant_id: &str) -> Vec<String> {
        let mut agents: Vec<String> = self
            .per_agent
            .keys()
            .filter(|(grant, _)| grant == grant_id)
            .map(|(_, agent)| agent.clone())
            .collect();
        agents.sort();
        agents
    }

    /// Calls charged to one `(grant, agent)` pair within the same window.
    pub fn agent(&self, grant_id: &str, agent_id: &str) -> u64 {
        self.per_agent
            .get(&(grant_id.to_string(), crate::audit_bound::agent_key(agent_id).into_owned()))
            .copied()
            .unwrap_or(0)
    }

    /// Charge `count` calls to a grant, and to the agent inside it unless the charge names none.
    ///
    /// The one place both tiers move, so a scan of the chain and a read of the counter cannot come
    /// to different answers about what a charge with no agent on it does: it counts towards the
    /// grant and towards no agent.
    pub(crate) fn add(&mut self, grant_id: &str, agent_id: &str, count: u64) {
        *self.totals.entry(grant_id.to_string()).or_insert(0) += count;
        if agent_id != GRANT_USAGE_NO_AGENT {
            *self
                .per_agent
                .entry((grant_id.to_string(), crate::audit_bound::agent_key(agent_id).into_owned()))
                .or_insert(0) += count;
        }
    }
}

/// Tally `events` against `windows`: the one filter, shared by every store so two of them cannot
/// come to different answers about the same chain.
///
/// The filter is [`charged_grant`]: a terminal event that spends budget, carrying this grant's id in
/// its summary, timestamped at or after the grant's window. An event whose `agent_id` is absent
/// counts towards the grant total and towards no agent, which is what the per-agent equality test
/// compared against.
pub(crate) fn tally_grant_usage<'a>(
    windows: &[GrantWindow<'_>],
    events: impl Iterator<Item = &'a AuditEvent>,
) -> GrantUsageCounts {
    let mut counts = GrantUsageCounts::default();
    if windows.is_empty() {
        return counts;
    }
    // Grant ids are unique, so one event charges at most one window and the lookup decides which.
    let by_id: std::collections::HashMap<&str, i64> =
        windows.iter().map(|w| (w.grant_id, w.since_ms)).collect();
    for event in events {
        let Some(grant_id) = charged_grant(event) else { continue };
        let Some(&since) = by_id.get(grant_id) else { continue };
        if event.timestamp < since {
            continue;
        }
        counts.add(grant_id, charge_agent(&event.payload), 1);
    }
    counts
}

/// The materialised counter, for a store that has no SQL of its own.
///
/// Keyed exactly like the `grant_usage` table so the two answer the same question the same way:
/// `(grant_id, agent_id, period_start) -> count`, read by summing every row of the grant whose
/// `period_start` is at or after the window's start.
#[derive(Debug, Default)]
pub(crate) struct GrantUsageTable {
    rows: std::collections::HashMap<(String, String, i64), u64>,
    /// When the fold last ran, so it runs at most once an interval rather than once a charge.
    last_compacted_ms: i64,
}

impl GrantUsageTable {
    /// File one charge, then fold anything past its detail window.
    pub(crate) fn charge(&mut self, grant_id: &str, agent_id: &str, timestamp: i64, now_ms: i64) {
        let key = (grant_id.to_string(), agent_id.to_string(), charge_period_start(timestamp));
        *self.rows.entry(key).or_insert(0) += 1;
        self.compact(now_ms);
    }

    /// Fold every row older than the detail window into its grant and agent's `period_start = 0`
    /// row, which is below every rolling window's start and inside every `Total` one.
    pub(crate) fn compact(&mut self, now_ms: i64) {
        if now_ms - self.last_compacted_ms < GRANT_USAGE_COMPACT_INTERVAL_MS {
            return;
        }
        self.last_compacted_ms = now_ms;
        let horizon = now_ms - GRANT_USAGE_DETAIL_MS;
        let stale: Vec<((String, String, i64), u64)> = self
            .rows
            .iter()
            .filter(|((_, _, start), _)| *start > 0 && *start < horizon)
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        for (key, count) in stale {
            self.rows.remove(&key);
            *self.rows.entry((key.0, key.1, 0)).or_insert(0) += count;
        }
    }

    /// Both tiers over `windows`, by the same predicate the SQL read uses.
    pub(crate) fn read(&self, windows: &[GrantWindow<'_>]) -> GrantUsageCounts {
        let mut counts = GrantUsageCounts::default();
        for window in windows {
            for ((grant_id, agent_id, start), count) in &self.rows {
                if grant_id != window.grant_id || *start < window.since_ms {
                    continue;
                }
                counts.add(grant_id, agent_id, *count);
            }
        }
        counts
    }

    /// One grant's charges since `since_ms` in `buckets` buckets, by the same rule the SQL read uses.
    pub(crate) fn series(&self, grant_id: &str, since_ms: i64, bucket_ms: i64, buckets: usize) -> Vec<u64> {
        let mut counts = vec![0u64; buckets];
        if buckets == 0 || bucket_ms <= 0 {
            return counts;
        }
        for ((grant, _, start), count) in &self.rows {
            if grant != grant_id || *start < since_ms {
                continue;
            }
            counts[(((*start - since_ms) / bucket_ms) as usize).min(buckets - 1)] += *count;
        }
        counts
    }

    /// Drop every row, for a rebuild that is about to refile the whole chain.
    pub(crate) fn clear(&mut self) {
        self.rows.clear();
        self.last_compacted_ms = 0;
    }
}

/// What an `allow` or `approved` audit append spends against a grant's budget.
///
/// Passed to [`Store::append_audit_charged`] so the counter moves inside the same SQLite
/// transaction as the event that charges it. It cannot be a caller-side `run_atomically`, because
/// [`Store::append_audit`] refuses inside a store transaction: the signed chain in memory has no
/// rollback, so an audit append is always its own unit and anything that must move with it has to
/// move inside it.
///
/// The agent is deliberately **not** here. It is taken from the payload the same append is sealing,
/// so the row and the chain cannot come to different answers about who spent the call, which is the
/// one drift a materialised counter could have that an audit scan could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantCharge {
    /// The grant this call is charged to: the id the engine matched and the event records.
    pub grant_id: String,
}

impl GrantCharge {
    /// One call against `grant_id`.
    pub fn new(grant_id: impl Into<String>) -> Self {
        GrantCharge { grant_id: grant_id.into() }
    }
}

/// The `agent_id` a charge with no agent on it is filed under.
///
/// Empty rather than null so the primary key stays three non-null columns, and safe because no real
/// agent id is empty: [`GrantUsageCounts::agent`] answers zero for it, which is what an audit scan
/// answers for an agent it never saw.
pub(crate) const GRANT_USAGE_NO_AGENT: &str = "";

/// How long a charge keeps its own millisecond before it is folded into the grant's running total
/// at `period_start = 0`.
///
/// Strictly longer than the longest window a [`permaura_core::GrantPeriod`] can name (30 days), and
/// that is what makes the fold lossless rather than approximate. A rolling window asks for
/// `period_start >= now - window`, which no folded row can satisfy and no row older than the window
/// could have satisfied either; a `Total` grant asks for everything and the folded row is counted.
/// Fold any sooner and a `Month` grant would silently lose the oldest day of its own window.
pub(crate) const GRANT_USAGE_DETAIL_MS: i64 = 31 * 86_400_000;

/// The least time between two compactions of the usage table.
///
/// The fold is a write, and on a hosted worker every write is a snapshot upload, so it must not run
/// once per charge. A worker that scales to zero compacts on its first charge after a cold start,
/// which is the case that matters: the rows it would be folding are the ones the previous instance
/// left behind.
pub(crate) const GRANT_USAGE_COMPACT_INTERVAL_MS: i64 = 3_600_000;

/// Where one charge is filed: its own millisecond, so a rolling window that asks
/// `period_start >= since` gets exactly the events an audit scan's `timestamp >= since` would.
///
/// This is the whole reason the counter can be identical to the scan it replaces rather than merely
/// close to it. A tumbling bucket, "the start of the grant's current window" as the contract first
/// drafted it, cannot be: the window a grant is read over slides with the clock and
/// its boundary falls wherever the read happens to land.
pub(crate) fn charge_period_start(event_timestamp: i64) -> i64 {
    event_timestamp
}

/// The agent a charge is filed under, from the event that carries it.
pub(crate) fn charge_agent(payload: &AuditPayload) -> &str {
    payload.agent_id.as_deref().unwrap_or(GRANT_USAGE_NO_AGENT)
}

/// Whether this event is one the counter charges, and the grant it charges to.
///
/// The clauses [`tally_grant_usage`] filters on, minus the window ([`charged_grant_of`]). A rebuild reads it out of the
/// chain; a live append is told it by the caller and agrees with this by construction.
pub(crate) fn charged_grant(event: &AuditEvent) -> Option<&str> {
    charged_grant_of(&event.payload)
}

/// The grant a terminal event spends budget against, or `None` when it spends none: the one rule the live append and every scan of the chain apply.
///
/// The budget counts calls that reached the upstream, so an `error` spends only when its trace saw the request leave (`dispatched: true`), or when a later boot closed it as `interrupted`, where nothing can rule that out; an error raised before dispatch spends nothing, whatever outcome it may claim.
pub(crate) fn charged_grant_of(payload: &AuditPayload) -> Option<&str> {
    let spends = match payload.decision.as_str() {
        "allow" | "approved" => true,
        "error" => {
            payload.summary.get("dispatched").and_then(|v| v.as_bool()) == Some(true)
                || payload.summary.get("error_kind").and_then(|v| v.as_str()) == Some(crate::service::INTERRUPTED_ERROR_KIND)
        }
        _ => false,
    };
    if !spends {
        return None;
    }
    payload.summary.get("grant_id").and_then(|v| v.as_str())
}

/// The charge a terminal append files, from the payload it seals, so the row and the chain are one rule.
pub(crate) fn charge_of(payload: &AuditPayload) -> Option<GrantCharge> {
    charged_grant_of(payload).map(GrantCharge::new)
}

/// The trait every gateway endpoint depends on. Synchronous and `Send + Sync` so it
/// can live in shared `AppState` behind an `Arc`; implementations guard their own
/// interior mutability.
pub trait Store: Send + Sync {
    /// Which backend this is: `memory`, `sqlite` or `sqlite+gcs`. Reported
    /// unauthenticated by `/health` because it is the difference between a real install and one whose
    /// grants, secrets and audit chain evaporate on restart, and nothing else over the wire
    /// distinguishes them. `sqlite` and `sqlite+gcs` are that distinction on a hosted worker, whose
    /// filesystem does not survive a restart.
    ///
    /// Deliberately a required method with no default: a new backend that forgot to name itself
    /// would report as one of the existing ones, which is exactly the mis-triage the field exists to
    /// prevent.
    fn kind(&self) -> &'static str;

    // ── agents ────────────────────────────────────────────────────────────────
    /// Register (upsert) an agent.
    fn put_agent(&self, agent: Agent) -> Result<(), GatewayError>;
    /// Fetch an agent by id.
    fn get_agent(&self, id: &str) -> Result<Option<Agent>, GatewayError>;
    /// List all agents.
    fn list_agents(&self) -> Result<Vec<Agent>, GatewayError>;
    /// Delete an agent by id. Returns whether it existed.
    fn delete_agent(&self, id: &str) -> Result<bool, GatewayError>;

    // ── sessions ──────────────────────────────────────────────────────────────
    /// Create a session.
    fn put_session(&self, session: Session) -> Result<(), GatewayError>;
    /// Create a session only if no row has its id. Returns whether it was written; `false` leaves the
    /// existing row exactly as it was.
    ///
    /// For a writer that decided to create on having read no row: a row that appeared since (an
    /// owner's tombstone among them) must win over that stale decision, which [`Store::put_session`]
    /// would overwrite.
    fn insert_session(&self, session: Session) -> Result<bool, GatewayError>;
    /// Record that the session `id`, presented as `token`, was used at `now`, in place.
    ///
    /// Writes `last_used_at` and, when `extend_expiry_to` is given, `expires_at`, each only ever
    /// forward, and nothing else in the row. Returns `false` and writes nothing when the row is gone,
    /// revoked, expired at `now`, or no longer carries `token` (the stored form or the bearer).
    ///
    /// One atomic step against the current row, never a read followed by a write: the race this closes was a touch
    /// that wrote back the whole row it had read at authentication, replacing a revocation that landed
    /// in between with `revoked: false`.
    fn touch_session(&self, id: &str, token: &str, now: i64, extend_expiry_to: Option<i64>) -> Result<bool, GatewayError>;
    /// Resolve a session by its bearer token (the auth hot path).
    fn session_by_token(&self, token: &str) -> Result<Option<Session>, GatewayError>;
    /// Fetch a session by id.
    fn get_session(&self, id: &str) -> Result<Option<Session>, GatewayError>;
    /// List all sessions.
    fn list_sessions(&self) -> Result<Vec<Session>, GatewayError>;
    /// Mark a session revoked, in place, writing nothing else in the row. Returns whether it existed.
    fn revoke_session(&self, id: &str) -> Result<bool, GatewayError>;
    /// Bring a live session's expiry forward to `at`, never later than it already is, in place and writing nothing else in the row. Returns whether a live row was there. For retiring a bearer after a grace that every later boot honors, where [`Store::revoke_session`] would end it at once.
    fn expire_session_by(&self, id: &str, at: i64) -> Result<bool, GatewayError>;

    /// Delete every session row except the revocation tombstones ([`Session::is_revocation_tombstone`]),
    /// returning how many went.
    ///
    /// The one caller is [`crate::reconcile`], for the restore's invalidation. Deleting rather than
    /// revoking, and the difference is not cosmetic: a revoked row is still a row, and a restore
    /// that rolls the database back to a checkpoint rolls `revoked` back with it, so a token
    /// somebody revoked after the checkpoint would authenticate again. Nothing survives a delete.
    ///
    /// The tombstones are the exception because they work the other way round: each one is the only
    /// record that a holder whose credential lives outside this database was stopped, so deleting it
    /// is what would let that holder back in. Keeping one can only ever refuse a caller.
    ///
    /// Deliberately not a default implementation over [`Store::list_sessions`] and
    /// [`Store::revoke_session`]: that default would revoke, which is the behaviour this method
    /// exists to be distinguishable from.
    fn delete_live_sessions(&self) -> Result<u64, GatewayError>;

    /// Delete one session row. Returns whether it was there.
    ///
    /// Distinct from [`Store::revoke_session`], which keeps the row so a caller presenting that token
    /// is told it was revoked. This is for rows nothing can present any more: the sweep uses it on
    /// sessions whose expiry passed long ago, because a table that only ever grows is carried by
    /// every hosted snapshot upload and every restore.
    fn delete_session(&self, id: &str) -> Result<bool, GatewayError>;

    /// Delete one session row only if `dead` holds for the row as it stands when the delete lands,
    /// judged and deleted in one guarded operation. Returns whether a row was deleted.
    ///
    /// For a cleanup that picks rows from an earlier [`Store::list_sessions`]: a revocation can land
    /// after that read, and judging the snapshot then calling [`Store::delete_session`] deleted a row
    /// that had become a tombstone. No default implementation, so a store added later has to say how
    /// it keeps the judgement and the delete together.
    fn delete_session_if(&self, id: &str, dead: &dyn Fn(&Session) -> bool) -> Result<bool, GatewayError>;

    // ── connections (first-class configured integration instances) ──────────────
    /// Store (upsert) a connection.
    fn put_connection(&self, connection: Connection) -> Result<(), GatewayError>;
    /// Fetch a connection by id.
    fn get_connection(&self, id: &str) -> Result<Option<Connection>, GatewayError>;
    /// List all connections.
    fn list_connections(&self) -> Result<Vec<Connection>, GatewayError>;
    /// Delete a connection by id. Returns whether it existed.
    fn delete_connection(&self, id: &str) -> Result<bool, GatewayError>;

    // ── policies (reusable permission templates, scoped to a connection) ────────
    /// Store (upsert) a policy.
    fn put_policy(&self, policy: Policy) -> Result<(), GatewayError>;
    /// Fetch a policy by id.
    fn get_policy(&self, id: &str) -> Result<Option<Policy>, GatewayError>;
    /// List all policies.
    fn list_policies(&self) -> Result<Vec<Policy>, GatewayError>;
    /// All policies scoped to a given connection.
    fn policies_for_connection(&self, connection_id: &str) -> Result<Vec<Policy>, GatewayError>;
    /// Delete a policy by id. Returns whether it existed.
    fn delete_policy(&self, id: &str) -> Result<bool, GatewayError>;

    // ── grants (bind a policy → agent(s) under limits) ──────────────────────────
    /// Store a grant.
    fn put_grant(&self, grant: Grant) -> Result<(), GatewayError>;
    /// Fetch a grant by id.
    fn get_grant(&self, grant_id: &str) -> Result<Option<Grant>, GatewayError>;
    /// All grants.
    fn list_grants(&self) -> Result<Vec<Grant>, GatewayError>;
    /// Replace the grant with the same `grant_id`. Returns whether one existed.
    fn update_grant(&self, grant: Grant) -> Result<bool, GatewayError>;
    /// Delete a grant by `grant_id`. Returns whether it existed.
    fn delete_grant(&self, grant_id: &str) -> Result<bool, GatewayError>;

    // ── agent enrolment codes (one-time, redeemed over MCP) ─────────────────────
    /// Store a freshly-minted enrolment code.
    fn put_enrolment_code(&self, code: EnrolmentCode) -> Result<(), GatewayError>;
    /// Store a code `POST /v1/agents/enroll` minted, unless `live_max` codes are already waiting to be redeemed as of `now_ms`, which is [`too_many_enrolment_codes`] and writes nothing. A code that is stored takes every code past its expiry with it, redeemed or not, since nothing can redeem one. One step, so two mints cannot both pass the count.
    ///
    /// No default, for the reason [`Self::delete_unconsumed_enrolment_codes`] has none.
    fn mint_enrolment_code(&self, code: EnrolmentCode, now_ms: i64, live_max: usize) -> Result<(), GatewayError>;
    /// Redeem an enrolment code: returns it (and marks it used) only if it exists, has not
    /// been used, and has not expired as of `now_ms`. Otherwise returns `None`.
    fn consume_enrolment_code(
        &self,
        code: &str,
        now_ms: i64,
    ) -> Result<Option<EnrolmentCode>, GatewayError>;
    /// Whether [`Self::consume_enrolment_code`] would redeem `code` as of `now_ms`, read without redeeming it or writing anything. Admission control asks it of a bearer that names no session, and authentication asks it before the consuming write. No default, for the reason [`Self::delete_unconsumed_enrolment_codes`] has none.
    fn enrolment_code_redeemable(&self, code: &str, now_ms: i64) -> Result<bool, GatewayError>;
    /// The stored digest ([`bearer_lookup_hash`]) of every enrolment code [`Self::consume_enrolment_code`] would still redeem as of `now_ms`, for `/health`'s bearer proof: a client about to present a code it has not redeemed yet asks the gateway to prove it holds it. Defaults to none, which only means a code is not proved before it is redeemed; the stores a self-run gateway uses list them.
    fn live_enrolment_code_digests(&self, _now_ms: i64) -> Result<Vec<String>, GatewayError> {
        Ok(Vec::new())
    }
    /// Delete every enrolment code that has not been redeemed, returning how many there were.
    ///
    /// The one caller is [`crate::reconcile`], for the restore's invalidation: a restored unconsumed code
    /// is a live invitation to self-enrol as a new agent, minted before the restore and unredeemable
    /// only because somebody redeemed it in a generation that has been thrown away.
    ///
    /// Already-redeemed codes are left alone. They are spent markers rather than credentials, and
    /// removing one would make the code it names mintable again.
    ///
    /// No default implementation, for the reason [`Store::audit_len`] has none: a store added later
    /// that silently did nothing here would leave a restored tenant handing out enrolments, and the
    /// failure is invisible at the call site.
    fn delete_unconsumed_enrolment_codes(&self) -> Result<u64, GatewayError>;

    // ── secrets (sealed) ───────────────────────────────────────────────────────
    /// Store (or replace) a sealed secret record.
    fn put_secret(&self, record: SecretRecord) -> Result<(), GatewayError>;
    /// Fetch a sealed secret record by id.
    fn get_secret(&self, id: &str) -> Result<Option<SecretRecord>, GatewayError>;
    /// Replace a secret's sealed value only while the stored envelope is still `expected`, keeping
    /// the stored metadata, as one step no other write to the secret can interleave with. Returns
    /// whether the swap happened: `false` means the secret was replaced or removed since `expected`
    /// was read, and nothing was written.
    ///
    /// Required rather than defaulted: a default written as a read followed by a write would be the
    /// check-then-write this method exists to replace.
    fn put_secret_if_unchanged(&self, id: &str, expected: &SealedSecret, sealed: SealedSecret) -> Result<bool, GatewayError>;
    /// List secret ids (never values).
    fn list_secret_ids(&self) -> Result<Vec<String>, GatewayError>;
    /// Delete a sealed secret by id. Returns whether it existed.
    fn delete_secret(&self, id: &str) -> Result<bool, GatewayError>;

    // ── secret custody (which layer holds each secret) ─────────────────────────
    /// Store (upsert) a secret's custody record, keyed by `secret_id`.
    fn put_secret_custody(&self, custody: SecretCustody) -> Result<(), GatewayError>;
    /// Fetch a secret's custody record. `None` means "no record": the local vault.
    fn get_secret_custody(&self, secret_id: &str) -> Result<Option<SecretCustody>, GatewayError>;
    /// Every custody record. The enumeration seam's view of externally-held secrets.
    fn list_secret_custody(&self) -> Result<Vec<SecretCustody>, GatewayError>;
    /// Delete a custody record (custody reverts to the local vault). Returns whether it existed.
    fn delete_secret_custody(&self, secret_id: &str) -> Result<bool, GatewayError>;

    // ── capabilities ──────────────────────────────────────────────────────────
    /// Register a capability in the gateway's catalog.
    fn put_capability(&self, cap: Capability) -> Result<(), GatewayError>;
    /// Fetch a capability by id.
    fn get_capability(&self, id: &str) -> Result<Option<Capability>, GatewayError>;
    /// List all registered capabilities.
    fn list_capabilities(&self) -> Result<Vec<Capability>, GatewayError>;
    /// Delete a capability by id (used to clean up a removed connection's catalog entries).
    /// Returns whether it existed.
    fn delete_capability(&self, id: &str) -> Result<bool, GatewayError>;

    // ── approvals ─────────────────────────────────────────────────────────────
    /// Record a change to an approval, or a pending one.
    ///
    /// Refuses a **new** hold beyond [`MAX_PENDING_APPROVALS`], with
    /// [`too_many_pending_approvals`]. Updating an approval that is already there always works,
    /// whatever the count, because that is how a human clears the queue, except that a settled
    /// approval never moves to another status ([`refuse_settled_approval_rewrite`]). The rule is about
    /// status alone: a write that keeps the status replaces every other field. A new hold is
    /// [`Store::insert_approval`].
    fn put_approval(&self, approval: PendingApproval) -> Result<(), GatewayError>;
    /// Record a new hold, refused with a conflict when an approval with its id is already there, so a
    /// hold never writes over another. The same cap as [`Store::put_approval`].
    fn insert_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        if self.get_approval(&approval.id)?.is_some() {
            return Err(GatewayError::Conflict(format!(
                "an approval with id '{}' already exists, and a new hold never writes over one",
                approval.id
            )));
        }
        self.put_approval(approval)
    }
    /// Fetch an approval by id.
    fn get_approval(&self, id: &str) -> Result<Option<PendingApproval>, GatewayError>;
    /// An approval's outcome, what an agent polling it reads, without building its params ([`ApprovalOutcome`]).
    fn get_approval_outcome(&self, id: &str) -> Result<Option<ApprovalOutcome>, GatewayError> {
        Ok(self.get_approval(id)?.map(ApprovalOutcome::of))
    }
    /// Update an approval's status. Returns the updated record. A settled approval keeps its status, as in [`Store::put_approval`].
    fn set_approval_status(
        &self,
        id: &str,
        status: &str,
    ) -> Result<Option<PendingApproval>, GatewayError>;
    /// List approvals, optionally filtered to a single status (e.g. `pending`), most recent first.
    fn list_approvals(&self, status: Option<&str>) -> Result<Vec<PendingApproval>, GatewayError>;
    /// How many approvals are pending, the figure [`MAX_PENDING_APPROVALS`] bounds.
    fn count_pending_approvals(&self) -> Result<usize, GatewayError> {
        Ok(self.list_approvals(Some("pending"))?.len())
    }
    /// The staged credential row each pending control-plane hold names, with who asked for it: all the staged-bytes bound needs to charge a row to its requester.
    ///
    /// Asked on every credential hold under the control-plane lock, and the SQLite store never deletes an approval row, so a store that keeps rows serialized answers from those two fields rather than reading every hold's whole `params`.
    fn pending_staging_owners(&self) -> Result<Vec<(String, Option<HoldRequester>)>, GatewayError> {
        Ok(self
            .list_pending_control_plane_holds()?
            .into_iter()
            .filter_map(|a| Some((permaura_core::json_stream::string_at(&a.params, "/staging_secret_id")?, a.requested_by)))
            .collect())
    }
    /// Every pending control-plane hold (a gateway-made hold of a change, with no requesting session), most recent first, read without the agents' held calls: the questions the hold path asks of the queue (is this change already held, does a hold name this staged row) are about these alone.
    fn list_pending_control_plane_holds(&self) -> Result<Vec<PendingApproval>, GatewayError> {
        Ok(self.list_approvals(Some("pending"))?.into_iter().filter(PendingApproval::is_control_plane_hold).collect())
    }
    /// The stored bytes of every pending control-plane hold (a gateway-made hold of a change, with no requesting session), checked against their own held-params budget before another is held; a change alone in the queue may take them past it.
    fn pending_control_plane_hold_bytes(&self) -> Result<u64, GatewayError> {
        let mut total = 0u64;
        for approval in self.list_approvals(Some("pending"))? {
            if approval.is_control_plane_hold() {
                total += row_len(&approval);
            }
        }
        Ok(total)
    }
    /// The bytes every capability row takes, as stored: the figure [`crate::limits::LimitsConfig::capability_bytes`] bounds.
    fn capability_bytes(&self) -> Result<u64, GatewayError> {
        let mut total = 0u64;
        for cap in self.list_capabilities()? {
            total += capability_row_bytes(&cap);
        }
        Ok(total)
    }
    /// The stored bytes of every pending hold an agent's call made (a row with a requesting session), checked against the held-params budget before another is held; a hold alone in the queue may take them past it. Gateway-made holds are not counted.
    fn pending_hold_bytes(&self) -> Result<u64, GatewayError> {
        let mut total = 0u64;
        for approval in self.list_approvals(Some("pending"))? {
            if !approval.session_id.is_empty() {
                total += row_len(&approval);
            }
        }
        Ok(total)
    }

    // ── installed connector manifests (runtime marketplace catalog) ─────────────
    /// Store (upsert) an installed connector manifest, keyed by its manifest id.
    fn put_connector_manifest(&self, manifest: InstalledManifest) -> Result<(), GatewayError>;
    /// Fetch an installed connector manifest by id.
    fn get_connector_manifest(&self, id: &str) -> Result<Option<InstalledManifest>, GatewayError>;
    /// List all installed connector manifests.
    fn list_connector_manifests(&self) -> Result<Vec<InstalledManifest>, GatewayError>;
    /// Delete an installed connector manifest by id. Returns whether it existed.
    fn delete_connector_manifest(&self, id: &str) -> Result<bool, GatewayError>;

    // ── durable trust state (small key/value rows + one-shot claims) ───────────
    // None of these three get a default implementation, deliberately. A default would let a store
    // added later inherit a silent no-op for state the approval ladder depends on (a keyring that
    // never persists, a floor that never sticks, a ticket that can always be replayed), and every
    // one of those failures is invisible at the call site and open rather than closed.

    /// Read a small key/value row; `None` means the key has never been written.
    ///
    /// The values are gateway-internal facts, not tenant data: [`APPROVER_KEYRING_META`],
    /// [`APPROVAL_FLOOR_META`], the audit signing key, the re-seal marker. Implementations must
    /// distinguish "no such row" from a read that failed: returning `None` for a failed read would
    /// present an unreadable keyring as an empty one, which lowers the approval floor.
    fn get_meta(&self, key: &str) -> Result<Option<String>, GatewayError>;

    /// Write (upsert) a small key/value row. Last write wins.
    fn put_meta(&self, key: &str, value: &str) -> Result<(), GatewayError>;

    /// Atomically claim a one-shot token id. `true` the first time this `(scope, jti)` is seen,
    /// `false` on every replay of it.
    ///
    /// The uniqueness enforced here is the *database's*, not this process's, and that is the whole
    /// point: a hosted worker can be several Cloud Run instances at once, so a process-local set of
    /// spent ids would let one ticket be spent once per instance, which is not single use. The
    /// scope namespaces unrelated token families so two of them cannot collide on a shared jti.
    ///
    /// Callers **must** branch on the returned bool. A single-use ticket whose single-use check is
    /// dropped is not a ticket at all: it degrades into a reusable bearer for the whole of its TTL,
    /// so anyone who observes it once (a log line, a proxy, a screenshot) can spend it themselves
    /// until it expires.
    ///
    /// Rows past `expires_at_ms` may be pruned at any time by any caller, so `expires_at_ms` must be
    /// the token's own expiry and never a shorter one: a claim that lapses before its token does
    /// makes the token replayable again for the remainder of its life.
    fn claim_once(&self, scope: &str, jti: &str, expires_at_ms: i64) -> Result<bool, GatewayError>;

    // ── audit log (hash-chained, signed) ───────────────────────────────────────
    /// Append a payload to the tamper-evident audit log, returning the sealed event.
    ///
    /// Provided rather than implemented, so there is exactly one append per store and a caller that
    /// forgets a charge cannot reach a different code path from one that supplies it.
    fn append_audit(&self, payload: AuditPayload) -> Result<AuditEvent, GatewayError> {
        self.append_audit_charged(payload, None)
    }

    /// Append, and in the same unit spend `charge` against its grant's budget.
    ///
    /// The increment lives inside this call, under the same transaction as the row, because
    /// [`Store::append_audit`] refuses inside a caller's transaction and a grant budget that can
    /// drift from the chain that justifies it is an authorization bug. It can only ever undercount
    /// against a successful append if the two are not one unit, and undercounting widens a grant the
    /// owner believes is spent.
    ///
    /// No default implementation, for the reason [`Store::audit_len`] has none: a store added later
    /// that inherited an append which silently charged nothing would reset every `Period::Total`
    /// budget the first time anything was pruned.
    fn append_audit_charged(
        &self,
        payload: AuditPayload,
        charge: Option<GrantCharge>,
    ) -> Result<AuditEvent, GatewayError>;

    /// Read the audit events (most-recent-last), optionally limited.
    fn audit_events(&self, limit: Option<usize>) -> Result<Vec<AuditEvent>, GatewayError>;

    /// Append, charge, and store `diagnostic` as the explanation of the new event, as one unit.
    ///
    /// `diagnostic.audit_seq` is ignored and set to the appended event's seq. The explanation is best
    /// effort: a failure to store it is logged and the event still stands, because losing an error
    /// message must never cost a recorded call. Provided so that a store whose writes are expensive
    /// (the hosted snapshot) can override it to pay for one persist rather than two.
    fn append_audit_explained(
        &self,
        payload: AuditPayload,
        charge: Option<GrantCharge>,
        diagnostic: Option<CallDiagnostic>,
    ) -> Result<AuditEvent, GatewayError> {
        let event = self.append_audit_charged(payload, charge)?;
        if let Some(mut diagnostic) = diagnostic {
            diagnostic.audit_seq = event.seq;
            if let Err(e) = self.put_call_diagnostic(diagnostic) {
                tracing::warn!(seq = event.seq, error = %e, "could not store a call diagnostic");
            }
        }
        Ok(event)
    }

    /// Append the pre-execution `"attempt"` that fences an execution, saying separately whether it
    /// was recorded and whether it is durable.
    ///
    /// `Err` means nothing was recorded. `Ok((event, Some(e)))` means the event is recorded on this
    /// instance and its upload failed: the execution must not run on a record that is not durable,
    /// and the attempt it leaves behind has to be closed as refused, or the chain carries an
    /// `"attempt"` with nothing after it once the upload succeeds. A store that uploads
    /// nothing never answers the second shape.
    fn append_audit_fence(&self, payload: AuditPayload) -> Result<(AuditEvent, Option<GatewayError>), GatewayError> {
        self.append_audit(payload).map(|event| (event, None))
    }

    /// [`Store::append_audit_explained`] for the terminal event of an execution that has already run.
    ///
    /// The one append a store must not refuse because an earlier commit is still waiting to be
    /// carried. The execution it closes has happened, so refusing the record prevents nothing and
    /// leaves an `"attempt"` with nothing after it. A store that holds writes back behind a
    /// failed upload records this one locally and carries it with the next upload that succeeds; an
    /// error from such a store means the event is not durable yet, never that it was not recorded.
    fn append_audit_terminal(
        &self,
        payload: AuditPayload,
        charge: Option<GrantCharge>,
        diagnostic: Option<CallDiagnostic>,
    ) -> Result<AuditEvent, GatewayError> {
        self.append_audit_explained(payload, charge, diagnostic)
    }

    /// Try again to make durable a local commit whose upload failed. `Ok(true)` when nothing is left
    /// waiting, which a store that uploads nothing always answers.
    fn carry_pending(&self) -> Result<bool, GatewayError> {
        Ok(true)
    }

    /// [`Store::carry_pending`] as the drain's last act before the process exits: a store that spaces its
    /// attempts after a failure makes this one regardless, since nothing comes after it.
    fn carry_before_exit(&self) -> Result<bool, GatewayError> {
        self.carry_pending()
    }

    /// Whether a local commit is waiting on an upload, read without waiting behind one in flight, so a
    /// request can carry it ([`Store::carry_pending`]). `false` from every store that uploads nothing.
    fn owes_upload(&self) -> bool {
        false
    }

    /// Record (upsert) the explanation of a failed call, then prune rows older than
    /// [`CALL_DIAGNOSTICS_RETENTION_MS`] and beyond [`CALL_DIAGNOSTICS_MAX`], oldest first.
    fn put_call_diagnostic(&self, diagnostic: CallDiagnostic) -> Result<(), GatewayError>;

    /// Every stored diagnostic whose event seq is at or after `from_seq`, ascending.
    fn call_diagnostics(&self, from_seq: u64) -> Result<Vec<CallDiagnostic>, GatewayError>;

    /// Delete every stored diagnostic, returning how many there were. The chain is untouched.
    fn purge_call_diagnostics(&self) -> Result<u64, GatewayError>;

    /// How many events the **hot** store holds, without materialising any of them.
    ///
    /// Deliberately not a default implementation over [`Store::audit_events`]. The one caller is the
    /// audit ceiling ([`crate::audit_ceiling`]) on the execution path, and a default that cloned the
    /// whole chain to count it would add, per invocation, exactly the cost the ceiling exists to
    /// bound. A store added later has to answer this cheaply or say why it cannot.
    ///
    /// It counts the hot window, not the chain: after a prune the archive holds the rest, and what
    /// this number is about is the bytes this instance is carrying.
    fn audit_len(&self) -> Result<u64, GatewayError>;

    /// Two-tier grant call counts, tallied **in place** over the hot window.
    ///
    /// No longer the authorization path: that is [`Store::read_grant_usage`], which reads the
    /// materialised counter and is the only one of the two that survives a prune. This is what the
    /// counter is checked against and rebuilt from, and it is kept because a derived fact needs a
    /// source to be compared with.
    ///
    /// Deliberately not a default implementation over [`Store::audit_events`]. That is what this
    /// replaced: every invocation cloned the whole resident chain to count a handful of events and
    /// held the clone until the execution returned, so at eight concurrent executions an event cost
    /// about ten times what it costs on its own. A store added later has to count without
    /// materialising, or say why it cannot.
    ///
    /// The answer is a small tally, so the caller holds no borrow on the chain and the store's lock
    /// is released before anything is executed.
    fn count_grant_usage(
        &self,
        windows: &[GrantWindow<'_>],
    ) -> Result<GrantUsageCounts, GatewayError>;

    /// The same two tiers, read from the materialised counter rather than from the chain.
    ///
    /// **This is the authorization path.** [`Store::count_grant_usage`] is the same question asked
    /// of the hot window, and it is now a rebuild and verification path only: it answers correctly
    /// only while nothing has been pruned, which is exactly the assumption the archive removes.
    ///
    /// The two must agree event for event before any prune, which is what
    /// `the_usage_counter_and_an_audit_scan_agree_before_any_prune` asserts over generated histories
    /// covering every period kind. No default implementation, so a store that cannot keep a counter
    /// has to say so rather than quietly answer from a window.
    fn read_grant_usage(
        &self,
        windows: &[GrantWindow<'_>],
    ) -> Result<GrantUsageCounts, GatewayError>;

    /// One grant's charges since `since_ms`, counted into `buckets` buckets of `bucket_ms` each, out of
    /// the materialised counter. A charge past the last bucket is counted in the last one.
    ///
    /// For the usage sparkline, which used to clone the whole hot window on every request to count
    /// one grant's events: on a hosted worker that was a read anyone with a session could repeat until
    /// the instance ran out of memory. The answer is `buckets` numbers whatever the window holds, and
    /// it is complete for every rolling window because the counter keeps each charge's own millisecond
    /// for longer than the longest one ([`GRANT_USAGE_DETAIL_MS`]).
    fn grant_usage_series(
        &self,
        grant_id: &str,
        since_ms: i64,
        bucket_ms: i64,
        buckets: usize,
    ) -> Result<Vec<u64>, GatewayError>;

    /// Rebuild the materialised counter from scratch, returning how many charges were filed.
    ///
    /// `archived` supplies the events below the hot window's base, newest-last, and the store adds
    /// its own hot window afterwards, so the two together are the whole chain. It must be exactly
    /// seq 0 up to the base, each event linking to the one before and the last to the signed
    /// boundary's base hash; anything short of that is refused and the counter is left as it was.
    /// An empty iterator is therefore only accepted from a store that has never pruned.
    ///
    /// Only the linkage is checked here. Authenticating what was archived is the caller's job, and
    /// [`crate::archive::ArchivedEvents`] is the one reader that does it.
    ///
    /// The one caller is `POST /v1/grants/rebuild-usage`, operator only. It exists because a counter
    /// is a derived fact and the chain is the source: anything that can put the two out of step (a
    /// restore, a grant whose period was widened after its rows were folded) has a way back that
    /// does not involve trusting the counter.
    fn rebuild_grant_usage(
        &self,
        archived: &mut dyn Iterator<Item = Result<AuditEvent, GatewayError>>,
    ) -> Result<u64, GatewayError>;

    /// Up to `limit` events starting at absolute `from_seq`, in order.
    ///
    /// The bounded read the archive writer and the export stream take, so neither has to materialise
    /// a window that may hold tens of thousands of events to work on five thousand of them. A
    /// `from_seq` below the base returns what the store still holds and no error: the events below
    /// the base are in the archive, and this method's job is to say what is here.
    ///
    /// No default implementation, for the reason [`Store::audit_len`] has none: a default over
    /// [`Store::audit_events`] would clone the whole window to return a slice of it, which is the
    /// cost the bounded read exists to avoid.
    fn audit_events_from(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, GatewayError>;

    /// Drop every event at or below `end_seq` and advance the signed boundary, in one unit.
    ///
    /// The rows, the in-memory chain and the re-signed [`permaura_core::audit::AuditBoundary`] move
    /// together or not at all. `audit_boundary` never moves independently of its prune: a
    /// boundary rewound on its own would hide a prune, and a prune without its boundary leaves a
    /// window whose first row is not where the boundary says it starts, which is a hole and a
    /// refusal to open.
    ///
    /// The caller must already have proved the segment durably published. This method takes that on
    /// trust because it cannot check it, which is why the only caller is
    /// [`crate::archive::AuditArchive`] and why the proof is four checks rather than one.
    ///
    /// Returns how many rows were removed.
    fn prune_audit_to(
        &self,
        end_seq: u64,
        base_hash: &str,
        segment_head: &str,
    ) -> Result<u64, GatewayError>;

    /// Seal an archive segment manifest under this store's audit key.
    ///
    /// The key never leaves the store, which is the same rule
    /// [`permaura_core::AuditLog::seal_boundary`] exists for: the archive writer publishes something
    /// a verifier will accept without ever being able to sign an event.
    fn seal_audit_segment(
        &self,
        draft: permaura_core::audit::AuditSegmentDraft,
    ) -> Result<permaura_core::audit::AuditSegment, GatewayError>;

    /// Seal the archive index under this store's audit key, on the same terms.
    fn seal_audit_index(
        &self,
        index: permaura_core::audit::AuditArchiveIndex,
        written_at: &str,
    ) -> Result<permaura_core::audit::AuditArchiveIndex, GatewayError>;

    /// The raw 32 bytes of the audit verifying key.
    ///
    /// What a cross-boundary verification checks an archived segment against. A segment carries its
    /// own copy of the key, and a verifier that believed that copy would be checking a signature
    /// against the key of whoever wrote it.
    fn audit_verifying_key(&self) -> Result<[u8; 32], GatewayError>;

    /// The recorded rekey this store honors (`permaura audit rekey`), or `None`. Every event below its
    /// seq was signed under a key this store no longer holds, so a verifier checks those for their
    /// hash and linkage only, and says so.
    fn audit_rekey(&self) -> Result<Option<permaura_core::audit::AuditRekey>, GatewayError> {
        Ok(None)
    }

    /// Verify the audit chain; `None` means intact, `Some(seq)` the first broken event.
    fn verify_audit(&self) -> Result<Option<u64>, GatewayError>;

    /// The signed boundary this store is running under, or `None` for a store that keeps no
    /// boundary record at all.
    ///
    /// `None` and a genesis boundary are different answers and must stay so: the first is a store
    /// with no boundary to fork and nothing to archive into, the second is one that has a boundary
    /// and has archived nothing yet. No default implementation, because a store that answered
    /// `None` by inheritance would report a pruned window as an unpruned one.
    fn audit_boundary(&self) -> Result<Option<permaura_core::audit::AuditBoundary>, GatewayError>;

    /// The epoch this store's audit boundary names, or `None` for a store that keeps no boundary
    /// record at all.
    ///
    /// `None` and `Some(0)` are different answers and must stay so: the first is a store with no
    /// boundary to fork, the second is one sitting in the original epoch.
    fn audit_epoch(&self) -> Result<Option<u64>, GatewayError> {
        Ok(self.audit_boundary()?.map(|b| b.epoch))
    }

    /// Fork the chain: write and re-sign the audit boundary at exactly `epoch`, returning whether
    /// that moved it.
    ///
    /// **Exactly `epoch`, not "one more than whatever is there", and that is what makes a retry
    /// safe.** Reconciliation records the epoch it intends to fork to before it forks, so a crash
    /// between the two leaves a boot that asks for the same number and is answered `false` rather
    /// than one that forks a second time and leaves two epochs describing one fork.
    ///
    /// **The signing order is the trap.** A boundary naming a non-zero epoch must verify under this
    /// store's audit key or the store refuses to open (see `load_audit_boundary`), so the key has to
    /// be resolved before the boundary is written, and the write and the re-sign have to be one
    /// unit. A store that cannot resolve a key that will still be there on the next open must refuse
    /// rather than write a boundary nothing can verify.
    ///
    /// Refuses to go backwards: an epoch below the current one is the one direction that could make
    /// two forks share a number.
    ///
    /// The fork is appended to the boundary's signed lineage with `restore_id`, the parent epoch and
    /// the current base as its cutoff, which is how the archive tells this store's history from the
    /// parent's abandoned suffix. The epoch number itself is chosen by the caller from somewhere a
    /// restore cannot roll back ([`crate::archive::AuditArchive::claim_epoch`]), because two
    /// restores of one checkpoint read the same epoch out of it.
    fn fork_audit_epoch(&self, epoch: u64, restore_id: &str) -> Result<bool, GatewayError>;

    /// Why this store is not currently able to make writes durable, for `/health` and the console;
    /// `None` when it is. Only a store with somewhere remote to fail against ever answers.
    fn degraded(&self) -> Option<String> {
        None
    }

    /// Take the lock every store call queues on and touch the connection, without waiting: `Ok(false)` while another thread holds it.
    /// [`answers_within`] polls this so `/health` fails when the store stops answering instead of reporting a deadlocked worker as live.
    fn liveness_touch(&self) -> Result<bool, GatewayError> {
        Ok(true)
    }

    /// Run `f` as one unit of work: on a store that can, every write inside it lands together or not
    /// at all, and a store that snapshots to object storage uploads once at the end rather than once
    /// per write. The default is plain sequential execution, which is what the in-memory store has
    /// always been. Prefer [`Store::transaction`] on a `dyn Store`, which carries a return value.
    fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError>;

    /// Run `f`, a change followed by its audit append, holding every upload to the end, so the change
    /// becomes durable only together with its record. Not a transaction, since an audit append
    /// cannot run inside one: a store that uploads nothing simply runs `f`.
    fn change_with_record(&self, f: &mut dyn FnMut() -> Result<(), GatewayError>) -> Result<(), GatewayError> {
        f()
    }

    /// Count the requests that make this store upload a snapshot, carrying the tally in the snapshots
    /// themselves. `false` from every store that uploads nothing, which is all of them but one.
    fn attach_meter(&self, meter: std::sync::Arc<dyn SnapshotMeter>) -> bool {
        let _ = meter;
        false
    }
}

/// Something that counts the requests which changed a snapshotting store, and keeps its tally in a
/// `gateway_meta` row written just before the snapshot those requests upload anyway, so the count is
/// as durable as the data and never costs an upload of its own. See [`crate::fair_use`].
pub trait SnapshotMeter: Send + Sync {
    /// A commit that changed at least one row just landed on the current task.
    fn note_mutation(&self);
    /// The `gateway_meta` row the next snapshot should carry, or `None` when the stored one is current.
    fn pending_stamp(&self) -> Option<(&'static str, String)>;
    /// The value from [`SnapshotMeter::pending_stamp`] was written.
    fn stamped(&self, value: &str);
}

/// How often [`answers_within`] retries a store that is busy.
const LIVENESS_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// Whether `store` answers [`Store::liveness_touch`] within `within`.
///
/// Polled rather than waited on, so a store that never answers leaves no thread blocked behind it: an unauthenticated `/health` on a public URL must not be a way to pile up threads on a held lock.
pub async fn answers_within(store: std::sync::Arc<dyn Store>, within: std::time::Duration) -> Result<(), GatewayError> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if store.liveness_touch()? {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(GatewayError::StoreUnavailable(format!(
                "the store did not answer within {} ms",
                within.as_millis()
            )));
        }
        tokio::time::sleep(LIVENESS_POLL).await;
    }
}

impl dyn Store + '_ {
    /// [`Store::run_atomically`] with a return value, for handlers that build something inside.
    pub fn transaction<T>(&self, f: impl FnOnce(&dyn Store) -> Result<T, GatewayError>) -> Result<T, GatewayError> {
        let mut f = Some(f);
        let mut out = None;
        self.run_atomically(&mut |store| {
            let f = f.take().expect("run_atomically calls its closure exactly once");
            out = Some(f(store)?);
            Ok(())
        })?;
        out.ok_or_else(|| GatewayError::Internal("run_atomically returned without calling its closure".into()))
    }
}
