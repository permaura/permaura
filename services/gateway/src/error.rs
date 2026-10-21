//! Gateway error type and its HTTP rendering.
//!
//! Every fallible handler returns [`GatewayError`]; [`IntoResponse`] maps each variant
//! to a stable status code and a JSON `{ "error": ... }` body. Crucially, the
//! enforcement loop maps a *policy* outcome (deny / requires_approval) to HTTP status
//! via [`GatewayError`] too, so the REST surface speaks the policy verdicts directly:
//! Deny → 403, RequiresApproval is handled as a 202 success body (not an error).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// The single error type the gateway's handlers return.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The bearer token was missing or did not resolve to a live session → 401.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// The caller is authenticated, but the action needs a fresh step-up pairing ticket that was
    /// absent, malformed, stale, already spent, or bound to something else → 401 (deliberately NOT
    /// 403). 403 tells a client "you may never do this" and ends the interaction; the whole point
    /// of a step-up is that the client CAN proceed after re-authenticating at permaura.com, so the
    /// status has to be the one that means "authenticate again". Returning 403 here would strand
    /// the console with no way to start the re-auth it is being asked for.
    #[error("step-up required: {0}")]
    StepUpRequired(String),

    /// Policy denied the action → 403. Carries the human-readable reason.
    #[error("denied: {0}")]
    Denied(String),

    /// A referenced entity (capability, secret, approval, ...) was not found → 404.
    #[error("not found: {0}")]
    NotFound(String),

    /// The request body / params were malformed → 400.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// The request is well formed but no longer matches the state it was prepared against → 409: an
    /// import whose reviewed digest the upstream has since moved away from, or a re-sync that needs a
    /// credential the connection does not hold yet. Resubmitting unchanged fails the same way.
    #[error("conflict: {0}")]
    Conflict(String),

    /// An unexpected internal failure → 500. Never leaks secret material.
    #[error("internal error: {0}")]
    Internal(String),

    /// The store behind this gateway could not be reached or has moved on → 503. The request did
    /// nothing durable and can be retried once storage is back; a 500 would tell the caller the
    /// gateway itself broke, and an operator reading the console would look in the wrong place.
    #[error("gateway storage unavailable: {0}")]
    StoreUnavailable(String),

    /// The OAuth resource server holds no signing keys yet: its JWKS fetch from permaura.com has not
    /// landed → 503, RETRYABLE. On a cold worker (a fresh provision, or one just scaled up from zero)
    /// the first authenticated request can arrive before the keys do, and until they do NO bearer
    /// (valid or not) can be verified. Deliberately NOT the 401 that means "your token is bad": the
    /// two are the same three digits on the wire, and a caller told 401 here would re-pair a gateway
    /// whose credential was fine all along. The remedy is to retry, so the status has to say so.
    #[error("verifier warming: {0}")]
    VerifierWarming(String),

    /// A resource limit refused the request before anything was executed → 429, with `Retry-After`.
    ///
    /// `reason` is the machine-readable label of the limit that fired and is echoed in the body,
    /// because several limits map to this status: the admission limits in [`crate::limits`]
    /// (`rate`, `queue`, `busy`, `chain_walk`), the per-session denial budget (`denials`), the hot-audit
    /// ceiling in [`crate::audit_ceiling`] (`audit_backlog`), the held-approval ceilings in
    /// [`crate::store`] (`approval_backlog`, `held_params`), the JSON memory pool (`memory`), a draining
    /// gateway (`draining`), and the bounds on staged credentials, enrolment codes and bundle key
    /// derivation (`staged_credential_bytes`, `enrolment_codes`, `bundle_open`). A caller that only
    /// sees 429 cannot tell "slow down" from "this gateway's store is full", and those want different
    /// responses.
    ///
    /// Each is meant to be raised BEFORE any audit event for that request exists: before the
    /// pre-execution `"attempt"` append for the admission limits and the audit ceiling, and in place of
    /// the `requires_approval` append for the held-approval ceilings. Raised after an `"attempt"`, the request has already fenced an
    /// execution and 429 would be a lie.
    #[error("too many requests: {message}")]
    TooManyRequests {
        /// The stable label of the limit that fired (`rate`, `queue`, `busy`, …).
        reason: String,
        /// The human-readable explanation.
        message: String,
        /// Seconds to put in `Retry-After`. Never zero: zero means "retry now", which is the one
        /// thing a shed caller must not do.
        retry_after_secs: u64,
        /// For a rate limit, whose rate: `session` (this caller's own bucket) or `worker` (the whole
        /// hosted gateway's). `None` for the capacity and backlog limits, which have no one to name.
        scope: Option<&'static str>,
    },

    /// A create was refused because this tenant is at a plan allowance → **409 Conflict**.
    ///
    /// 409 rather than 422, and deliberately not 429. 422 says the representation could not be
    /// processed, which points the caller at its own body; the body is fine here and rewriting it
    /// changes nothing. 409 is the status for a request that conflicts with the current state of the
    /// target resource, and RFC 9110 attaches to it exactly the remedy that applies: enough
    /// information for the caller to resolve the conflict and resubmit. Delete an agent and the same
    /// request succeeds. 429 is wrong for a third reason: it means "you are going too fast", and a
    /// caller that waits at its ceiling waits forever.
    ///
    /// Raised before the store write it guards, so a refusal has created nothing. The audited denial
    /// that accompanies it is appended by the caller, because appending is a store mutation and
    /// [`crate::allowances`] holds no store.
    #[error("allowance exceeded: {message}")]
    AllowanceExceeded {
        /// Which allowance refused (`agents`, `secrets`, `grants`, `connections`).
        allowance: String,
        /// How many live rows of that kind this gateway holds.
        current: u64,
        /// The configured ceiling.
        limit: u64,
        /// The human-readable explanation.
        message: String,
    },

    /// This tenant is under an execution hold → **423 Locked**.
    ///
    /// 423 rather than 503 because the condition is deliberate and will not clear on retry, and
    /// rather than 403 because the caller's authorization is not what is wrong: the same caller
    /// will be allowed through once the hold is lifted. See [`crate::restore`].
    ///
    /// Carries the three facts and only the three facts a refused caller is told. The hold object
    /// also records who set it and which checkpoint is being promoted, and neither belongs in a
    /// response to an agent.
    #[error("execution is held: {reason} (hold {hold_id}, state {state})")]
    ExecutionHeld {
        /// The hold id, as the restoration authority minted it.
        hold_id: String,
        /// The state that refused: `held`, `reconciling`, `absent`, `unreadable`.
        state: String,
        /// One sentence saying which layer refused and why.
        reason: String,
    },

    /// An upstream call or command ran past the gateway's execution ceiling → 504. Distinct from
    /// `Internal` because the gateway did not fail: it refused to keep waiting, and the remedy is
    /// the upstream's or a larger budget, not a bug report.
    #[error("upstream timed out: {0}")]
    UpstreamTimeout(String),

    /// A document is too costly to hold at all: its parsed tree would pass the worker's whole JSON memory budget, or an agent call's params would pass the one ceiling on their unpacked size → 413 (a tool error on `/mcp`). Sending the same thing again fails the same way; the remedy is a smaller or flatter request, or the call split into smaller ones.
    #[error("too large: {0}")]
    TooLarge(String),

    /// The persistent store was written by a newer gateway than this binary understands. Never
    /// reaches HTTP: it is a boot-time refusal the binary turns into
    /// [`crate::store::migrations::EXIT_STORE_SCHEMA_TOO_NEW`], so a supervisor can stop respawning
    /// on the exit code rather than by matching the message text. It is a distinct variant purely so
    /// that decision is made on a type, never on a substring of our own error.
    #[error("{0}")]
    SchemaTooNew(String),

    /// Another live process holds the self-run store, and stayed holding it for the whole bounded wait.
    /// Never reaches HTTP: it is a boot-time refusal the binary turns into
    /// [`crate::store::migrations::EXIT_STORE_HELD`], for the same reason as [`Self::SchemaTooNew`].
    #[error("{0}")]
    StoreHeld(String),

    /// A self-run store holds a signed audit chain and the `gateway.db.auditkey` beside it is gone. Never
    /// reaches HTTP: a boot-time refusal the binary turns into
    /// [`crate::store::migrations::EXIT_AUDIT_KEY_MISSING`], so a supervisor can say why it stopped.
    #[error("{0}")]
    AuditKeyMissing(String),
}

impl GatewayError {
    fn status(&self) -> StatusCode {
        match self {
            GatewayError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            GatewayError::StepUpRequired(_) => StatusCode::UNAUTHORIZED,
            GatewayError::Denied(_) => StatusCode::FORBIDDEN,
            GatewayError::NotFound(_) => StatusCode::NOT_FOUND,
            GatewayError::BadRequest(_) => StatusCode::BAD_REQUEST,
            GatewayError::Conflict(_) => StatusCode::CONFLICT,
            GatewayError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::StoreUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::VerifierWarming(_) => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            GatewayError::AllowanceExceeded { .. } => StatusCode::CONFLICT,
            GatewayError::ExecutionHeld { .. } => StatusCode::LOCKED,
            GatewayError::UpstreamTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
            GatewayError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            GatewayError::SchemaTooNew(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::StoreHeld(_) => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::AuditKeyMissing(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl GatewayError {
    /// A failed outbound HTTP call as an [`GatewayError::Internal`] whose text cannot carry a URL: the
    /// only way connector transport text reaches a REST body, an MCP tool error or the 500 log line.
    pub fn upstream(context: &str, err: &anyhow::Error) -> Self {
        GatewayError::Internal(format!("{context}: {}", crate::connectors::transport_error_text(err)))
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = self.status();
        // The backstop for a 500 nothing else recorded: every other variant is something a caller
        // did, and the failures that produce `Internal` are logged where they happen, but anything
        // missed reaches the operator as a status code and nothing else. Logged here rather than at
        // the variant's origin so there is exactly one line per request, whatever raised it.
        if let GatewayError::Internal(message) = &self {
            tracing::error!(error = %message, "a request failed with an internal error");
        }
        // A 429 carries two extras: `Retry-After`, without which a shed client's only sane strategy
        // is to retry immediately and make the condition worse, and `reason`, which is how a caller
        // tells one limit from another (see the variant's doc comment).
        if let GatewayError::TooManyRequests {
            reason,
            message,
            retry_after_secs,
            scope,
        } = &self
        {
            let retry = (*retry_after_secs).max(1);
            // A rate limit names whose rate it was and where the numbers are published, so an agent
            // author reading the body finds the fair-use page rather than guessing at a cap.
            let body = match scope {
                Some(scope) => json!({
                    "error": "rate_limited",
                    "scope": scope,
                    "docs": crate::fair_use::DOCS_URL,
                    "message": message,
                    "reason": reason,
                    "retry_after": retry,
                }),
                None => json!({
                    "error": format!("too many requests: {message}"),
                    "reason": reason,
                    "retry_after": retry,
                }),
            };
            return (status, [(axum::http::header::RETRY_AFTER, retry.to_string())], Json(body))
                .into_response();
        }
        // A 409 names the allowance and both numbers, so a console can render "25 of 25 agents" from
        // the refusal itself rather than having to go and count. Without the count a caller is told
        // only that something is full, which is the shape of message that sends an operator looking
        // in the wrong place.
        if let GatewayError::AllowanceExceeded {
            allowance,
            current,
            limit,
            message,
        } = &self
        {
            return (
                status,
                Json(json!({
                    "error": format!("allowance exceeded: {message}"),
                    "allowance": allowance,
                    "current": current,
                    "limit": limit,
                })),
            )
                .into_response();
        }
        // A 423 names the hold, so an operator reading a console does not have to go and find out
        // which hold is on this workspace and what state it is in. The same three fields reach an
        // MCP caller as the JSON-RPC error's `data`.
        if let GatewayError::ExecutionHeld { hold_id, state, reason } = &self {
            return (
                status,
                Json(json!({
                    "error": self.to_string(),
                    "hold_id": hold_id,
                    "state": state,
                    "reason": reason,
                })),
            )
                .into_response();
        }
        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

impl From<permaura_core::PermauraError> for GatewayError {
    fn from(e: permaura_core::PermauraError) -> Self {
        use permaura_core::PermauraError as B;
        match e {
            B::NotFound(m) => GatewayError::NotFound(m),
            B::InvalidInput(m) => GatewayError::BadRequest(m),
            // A modified artefact is a bad input, not a gateway fault: 400, and it keeps its own
            // message, which is the whole reason it is a separate variant.
            B::Tampered(m) => GatewayError::BadRequest(m),
            B::Denied(m) => GatewayError::Denied(m),
            other => GatewayError::Internal(other.to_string()),
        }
    }
}
