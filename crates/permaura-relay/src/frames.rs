//! The relay frame payloads. **No frame carries a secret**: the worker returns only
//! redacted results.

use serde::{Deserialize, Serialize};

use permaura_core::{Decision, ExecutionLocation, Principal};

use crate::error::RelayErrorCode;
use crate::ProtocolVersion;

// ── handshake ───────────────────────────────────────────────────────────────────

/// W→CP, unauthenticated. Claims an identity; proves nothing. Read before version
/// negotiation, so its schema is frozen across protocol versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// The worker claiming to connect.
    pub worker_id: String,
    /// The highest protocol version the worker speaks.
    pub max_version: ProtocolVersion,
}

/// CP→W. The server-issued challenge: the worker cannot pre-sign a value it chose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// 32 random bytes, base64, which the control-plane hub (not built yet) is meant to make
    /// single-use, bound to this socket and short-lived.
    pub challenge: String,
    /// Opaque per-connection id, folded into every signed frame's preimage so signatures
    /// bind to THIS socket (anti cross-connection replay).
    pub connection_id: String,
}

/// W→CP. The signed handshake; the enclosing `Signed<Hello>.sig` covers the canonical Hello
/// preimage (worker_id ‖ org_id ‖ challenge, bound to connection_id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// The worker id (matches the stored `Worker`).
    pub worker_id: String,
    /// The worker's org, which the control-plane hub (not built yet) is meant to re-check against
    /// the stored `Worker.org_id`, failing the handshake on a mismatch.
    pub org_id: String,
    /// The echoed `Challenge.challenge`.
    pub challenge: String,
    /// The echoed `Challenge.connection_id`.
    pub connection_id: String,
    /// The highest protocol version the worker speaks.
    pub max_version: ProtocolVersion,
    /// Platform string for diagnostics (`macos` / `linux` / `ios`).
    pub platform: String,
    /// The worker build version.
    pub agent_version: String,
    /// Reserved for workload identity (OIDC). `None` in v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_attestation: Option<String>,
}

/// CP→W. Accepts the worker, pins the version, sets the heartbeat cadence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAck {
    /// The negotiated protocol version.
    pub version: ProtocolVersion,
    /// Bumped per (re)connect, for the control-plane hub (not built yet) to fence a stale prior
    /// socket for this worker.
    pub session_epoch: u64,
    /// Expected heartbeat interval.
    pub heartbeat_interval_ms: u64,
    /// Missed heartbeats before the CP marks the worker offline.
    pub heartbeat_miss_limit: u32,
    /// The CP's clock. The worker does not read it today.
    pub server_time: i64,
}

// ── liveness ──────────────────────────────────────────────────────────────────────

/// W↔CP liveness. Worker→CP also reports load + the resources it serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Sender clock (unix ms).
    pub at: i64,
    /// Worker→CP: in-flight invoke count, for the CP to shed load off a saturated worker. The
    /// worker currently always sends 0.
    #[serde(default)]
    pub inflight: u32,
    /// Worker→CP: resources this worker currently serves, for the CP to mark a resource
    /// unavailable the instant its worker drops. The worker currently never sends a list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving: Option<Vec<String>>,
}

// ── money path ──────────────────────────────────────────────────────────────────

/// CP→W: a relayed capability invocation. Carries no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeRequest {
    /// CP-minted, globally unique: the idempotency key the worker dedupes on.
    pub job_id: String,
    /// WHO is calling: identity only, never an authz verdict, never a CP bearer.
    pub session_ctx: SessionCtx,
    /// The capability id, verbatim as `EnforcementService::invoke` expects.
    pub capability: String,
    /// The agent-supplied params.
    pub params: serde_json::Value,
    /// CP-computed via the canonical `request_hash`; the worker recomputes and rejects a mismatch.
    pub request_hash: String,
    /// The agent's stated intent (audited, never trusted for authorization).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Ignored by the worker, which runs every relayed job as `RemoteAllowed`: the field sits
    /// outside `request_hash`, so it is not trusted.
    pub execution_location: ExecutionLocation,
    /// Absolute unix-ms deadline; the worker drops a job already past it.
    pub deadline_ms: i64,
}

/// The relay's translation of the CP-authenticated agent into worker-local identity. Identity
/// ONLY: the CP's bearer never crosses the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCtx {
    /// CP-side agent session id, for audit correlation.
    pub cp_session_id: String,
    /// Re-checked against the socket's bound org; a cross-org frame is dropped.
    pub org_id: String,
    /// The principal the CP authenticated (user/agent/device/org). Maps onto the worker's Session.
    pub principal: Principal,
    /// Marks this invoke as relayed. The worker does not read it: a relayed call is recorded
    /// under a `relay:`-prefixed session id and runs as `RemoteAllowed`.
    pub origin: InvokeOrigin,
    /// When the CP authenticated the agent session (unix ms).
    pub authenticated_at: i64,
}

/// Where an invoke originated. Neither the audit log nor the policy engine reads it today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvokeOrigin {
    /// A local stdio/REST call on the worker itself.
    Local,
    /// Relayed from a remote agent via the control plane.
    Relay,
}

/// W→CP: the redacted outcome of an invoke, keyed by `job_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeResult {
    /// The job this answers.
    pub job_id: String,
    /// The redacted outcome.
    pub outcome: RelayOutcome,
}

/// Serde mirror of the gateway's `InvokeOutcome`, re-declared here so `permaura-relay` does
/// **not** depend on the gateway crate (keeps the dependency arrow gateway → relay). `Decision`
/// is the real `permaura-core` type; `result` is already redacted by the worker, so no secret
/// ever appears here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RelayOutcome {
    /// Allowed and executed: redacted result + upstream HTTP status.
    Allowed {
        /// The policy decision (always allow).
        decision: Decision,
        /// The redacted upstream result: never a secret.
        result: serde_json::Value,
        /// The upstream HTTP status (or synthetic 200/502 for command capabilities).
        http_status: u16,
    },
    /// Escalated to a human: the approval id + message to poll on. The full body is not
    /// mirrored; the worker pushes the terminal result on the same `job_id`.
    RequiresApproval {
        /// The policy decision (requires approval).
        decision: Decision,
        /// The worker-local approval id to poll.
        approval_id: String,
        /// Human-readable description of what is being approved.
        message: String,
        /// Absolute unix-ms deadline for the hold, or `None` when it has none. Same field, same
        /// meaning, as the REST 202's `expires_at`.
        #[serde(default)]
        expires_at: Option<i64>,
        /// The worker's captured risk classification, or `unknown`.
        #[serde(default)]
        risk: String,
        /// One human sentence naming what runs if this is approved.
        #[serde(default)]
        action_description: Option<String>,
    },
    /// Denied by policy.
    Denied {
        /// The policy decision (deny), with its reason.
        decision: Decision,
    },
}

// ── approval round-trip ───────────────────────────────────────────────────────────

/// W→CP: a held call needs human approval, for the control-plane hub (not built yet) to fan out
/// to the phone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// The job awaiting approval.
    pub job_id: String,
    /// The worker-local `PendingApproval` id.
    pub approval_id: String,
    /// The capability awaiting approval.
    pub capability: String,
    /// The resource it acts on.
    pub resource: String,
    /// A short message naming the capability and connection; the call's parameters are not in it.
    pub message: String,
    /// Binds the approval to the exact held request; the signer signs over this.
    pub request_hash: String,
    /// Absolute unix-ms moment the worker abandons the held call, or `None` for a hold with no
    /// deadline. An `Option` rather than a zero sentinel so this says the same thing as the REST
    /// body's `expires_at` instead of being a second encoding of it: a control plane fanning this
    /// out to a phone must not have to know that 0 means forever.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// The worker's own risk classification of the held capability, captured when it was held:
    /// `low` | `medium` | `high` | `critical` | `unknown`. `unknown` means unclassified, never safe.
    #[serde(default)]
    pub risk: String,
    /// One human sentence naming what runs if this is approved. `None` when the worker has none,
    /// and the reader falls back to `message`.
    #[serde(default)]
    pub action_description: Option<String>,
}

/// phone→CP→W: the approval decision, **signed by the approver's device key**.
///
/// The control plane is only a relay for these bytes: it cannot forge `device_sig` (it never
/// holds an approver device key) and cannot redirect the approval onto a different call (the
/// signature binds `request_hash`). The worker verifies `device_sig` over
/// [`approval_result_preimage`](crate::approval_result_preimage) against an approver key it holds
/// **locally**. A compromised control plane can therefore drop or delay an approval but never forge
/// one: the human-approval gate that bounds the semi-trusted-CP threat model is anchored to a
/// private key that only ever exists on the device.
///
/// Enrolment of that key is out-of-band and CP-free on a local or tunnelled gateway. On a hosted
/// worker, which has no loopback client to prove an operator is physically present, the first
/// device is enrolled under an owner-scoped Operator session plus a single-use step-up ticket, and
/// only the first: every device after it is co-signed by one already trusted. So a compromised CP
/// gets at most one device on a worker that has never paired, and none on a worker that has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResult {
    /// The job this resolves.
    pub job_id: String,
    /// The approval being resolved.
    pub approval_id: String,
    /// Approve or deny.
    pub approve: bool,
    /// MUST equal the held `PendingApproval`'s hash; the worker rejects a mismatch so the relay
    /// cannot redirect an approval onto a different call.
    pub request_hash: String,
    /// Who approved (`user:<id>` / `device:<id>`); the worker resolves this to the trusted key in
    /// its local approver keyring.
    pub approver: String,
    /// When the decision was made (unix ms).
    pub decided_at: i64,
    /// The approver's device ed25519 public key (base64), for audit/UX. **Not trusted for
    /// verification**: the worker verifies against its locally-held keyring entry for `approver`,
    /// so a relay that swaps this field cannot make the worker trust a different key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_pubkey: Option<String>,
    /// The gateway the device signed this for, when it signed
    /// [`approval_result_preimage_v2`](crate::approval_result_preimage_v2). `None` marks a v1
    /// signature over [`approval_result_preimage`](crate::approval_result_preimage), which names no
    /// gateway and is accepted only while the worker still takes v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The device's [`approval_display_full_digest`](crate::approval_display_full_digest) of the rendering it
    /// showed the approver, when it signed
    /// [`approval_result_preimage_v3`](crate::approval_result_preimage_v3). The worker recomputes the
    /// digest from the held call and refuses a mismatch. `None` marks a v1 or v2 signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_digest: Option<String>,
    /// base64(ed25519) signature by the approver's device key over the v3 preimage when
    /// `display_digest` is set, else the v2 preimage when `audience` is set, else the v1 preimage.
    /// The trust anchor of a device-signed approval.
    pub device_sig: String,
}

// ── control ───────────────────────────────────────────────────────────────────────

/// CP→W (signed): a revocation or killswitch. Cannot be forged, because it is `Signed<Revoke>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum Revoke {
    /// Stop honouring invokes carrying this CP session id.
    Session {
        /// The CP agent session to stop honouring.
        cp_session_id: String,
    },
    /// Treat this grant as absent until re-synced.
    Grant {
        /// The grant to drop.
        grant_id: String,
    },
    /// Disable this worker: drop the channel, go offline, refuse reconnect until re-enrolled.
    Worker {
        /// The worker to disable.
        worker_id: String,
    },
    /// Org-wide "disable all" killswitch: stop serving all invokes and drop the org's socket.
    Killswitch {
        /// The org to lock down.
        org_id: String,
    },
}

// ── errors ────────────────────────────────────────────────────────────────────────

/// Either direction: a structured error. Never secret-bearing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayErrorFrame {
    /// Set when the error answers a specific job, so only that job fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// The error code.
    pub code: RelayErrorCode,
    /// Summary only: never secret-bearing (same discipline as audit redaction).
    pub message: String,
    /// True → the sender closes the connection after this frame.
    #[serde(default)]
    pub fatal: bool,
    /// Hint to the peer: re-dispatch (Internal/RateLimited) vs surface a hard failure.
    #[serde(default)]
    pub retryable: bool,
}
