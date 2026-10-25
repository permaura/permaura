//! The REST v1 surface: every endpoint, mapped onto the shared
//! [`EnforcementService`] and [`Store`]. The enforcement loop lives in
//! [`crate::service`]; these handlers are thin translation between HTTP and that core.

use std::collections::BTreeMap;

use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use permaura_core::{
    seal, Cipher, Connection, ExecutionLocation, Grant, GrantAgent, GrantAgents, GrantPeriod,
    GrantTarget, Policy, SecretMetadata, SecretRecord,
};

use crate::connectors::{
    Capability, SshConnector, SshCredentialKind, SshExecCommand, SshHostKey, SshTarget,
    DEFAULT_SFTP_MAX_BYTES,
};
use crate::error::GatewayError;
use crate::request_body::{JsonBody, NoBody, OptionalJsonBody};
use crate::service::{request_hash, short_id, vault_passphrase, InvokeOutcome, SignedApprovalOutcome};
use crate::store::{
    Agent, AgentStatus, EnrolmentCode, PendingApproval, Session, SessionRole, Store,
    OPERATOR_SESSION_TTL_MS,
};
use permaura_relay::ApprovalResult;

/// How fresh a device's possession proof must be (unix-ms window), for a pairing and for a request a
/// trusted device signs for itself. Short: both are interactive, so a captured proof should not stay
/// replayable for long.
const PAIRING_FRESHNESS_MS: i64 = 2 * 60 * 1000;
use crate::AppState;

/// `GET /`: the page a browser gets when someone visits the gateway itself.
///
/// Open, and open by necessity: it is a plain navigation carrying no credential. It discloses only
/// that a Permaura gateway answers here, which unauthenticated `/health` already says.
pub async fn landing() -> axum::response::Html<String> {
    axum::response::Html(crate::landing::page(None))
}

/// Every unmatched path. Still a 404 (clients decide what a gateway supports by which paths 404,
/// the CLI's own health fallback among them), but a browser now gets the landing page instead of the
/// empty body it used to, and everything else gets the `{"error": ...}` shape every other miss on
/// this surface returns rather than nothing at all.
pub async fn not_found(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    if wants_html(&headers) {
        return (
            StatusCode::NOT_FOUND,
            axum::response::Html(crate::landing::page(Some(
                "That address is not part of this gateway.",
            ))),
        )
            .into_response();
    }
    // The path is reflected for diagnosis; `Json` escapes it, and it never reaches the HTML page.
    GatewayError::NotFound(format!("no route for {method} {}", uri.path())).into_response()
}

/// Whether the caller is a browser navigating, rather than a client calling. Navigations send an
/// `Accept` naming `text/html`; `*/*` from curl or a fetch does not, and gets JSON.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// `GET /health`: liveness for anyone, and a summary of seeded state and audit health for a caller
/// that can prove who it is.
///
/// The full document names the exact version and build, says whether this gateway is behind the
/// released manifest, and counts agents, grants and pending approvals. Unauthenticated, on a public
/// tunnel, that is a fingerprint: it tells a stranger which build to look up and that this host is
/// running an old one, alongside a usage signal about its operator. The hostname is not a secret and
/// was never meant to be the protection, but it used to be a hash, and now an operator can choose a
/// readable name, so guessing one is realistic in a way it was not before.
///
/// Liveness stays open, because that is what an uptime check needs and it discloses nothing a closed
/// port would not: only this gateway answers with this body, so `status: ok` still proves the gateway
/// itself is up rather than merely the edge in front of it.
///
/// A challenge gets a proof of the published operator token back on either body, and that proof, never the body, is what tells a local client this listener is its gateway before it presents the token anywhere ([`permaura_core::health_proof`]). A gateway linked to permaura.com also proves the console sessions permaura.com may hold, for the browser-direct console.
pub async fn health(
    State(state): State<AppState>,
    Extension(HealthPort(port)): Extension<HealthPort>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let proof = health_proof(&state, port, &headers);
    let console_proof = console_health_proof(&state, port, &headers);
    // First, before anything else reads the store: a store that stopped answering fails the probe instead of hanging it.
    let mut bearer_proof = None;
    let mut resp = match crate::store::answers_within(state.service.store().clone(), HEALTH_STORE_BOUND).await {
        Ok(()) => {
            bearer_proof = (!remote).then(|| bearer_health_proof(&state, port, &headers)).flatten();
            let full = authed(&state, &headers).is_ok();
            health_document(&state, full)?.into_response()
        }
        Err(e) => e.into_response(),
    };
    if let Some(proof) = bearer_proof {
        resp.headers_mut().insert(permaura_core::health_proof::BEARER_PROOF_HEADER, proof);
    }
    if let Some(proof) = proof {
        resp.headers_mut().insert(permaura_core::health_proof::PROOF_HEADER, proof);
    }
    if let Some(proof) = console_proof {
        resp.headers_mut().insert(permaura_core::health_proof::CONSOLE_PROOF_HEADER, proof);
    }
    Ok(resp)
}

/// How long `/health` waits for the store before answering 503: under the hosted liveness probe's 5 s timeout, so a wedged worker fails three probes 30 s apart and is restarted.
pub(crate) const HEALTH_STORE_BOUND: std::time::Duration = std::time::Duration::from_secs(3);

/// The port this gateway was bound to, which `/health`'s proof is computed over.
#[derive(Clone, Copy)]
pub struct HealthPort(pub u16);

/// The answer to a `/health` challenge, when there is a well-formed one and a published token to key
/// it with. A malformed challenge gets no proof and no error: the body is unchanged either way.
fn health_proof(state: &AppState, port: u16, headers: &HeaderMap) -> Option<axum::http::HeaderValue> {
    let challenge = headers
        .get(permaura_core::health_proof::CHALLENGE_HEADER)?
        .to_str()
        .ok()?;
    let token = state.published_token.get()?;
    let proof = permaura_core::health_proof::proof(&token, port, challenge)?;
    axum::http::HeaderValue::from_str(&proof).ok()
}

/// The answer to a `/health` challenge naming a bearer by its key ([`permaura_core::health_proof::bearer_key`]): the proof keyed on the digest this gateway keeps for it, when that digest is a live session's or an enrolment code's it would still redeem. A client checks it before it presents an agent token or a code, which no operator-token proof can vouch for.
///
/// Asked only of a request from this machine (the caller checks [`RemoteFlag`], which a hosted worker always sets): the scan runs under the store lock every agent call needs, and only a client on this machine, about to dial loopback, has any use for the answer. A hosted worker is reached over TLS at a public name instead.
fn bearer_health_proof(state: &AppState, port: u16, headers: &HeaderMap) -> Option<axum::http::HeaderValue> {
    use permaura_core::health_proof::{bearer_key, bearer_proof, is_valid_bearer_key, is_valid_challenge, BEARER_KEY_HEADER, CHALLENGE_HEADER};
    let challenge = headers.get(CHALLENGE_HEADER)?.to_str().ok()?;
    let key = headers.get(BEARER_KEY_HEADER)?.to_str().ok()?;
    if state.hosted || !is_valid_challenge(challenge) || !is_valid_bearer_key(key) {
        return None;
    }
    let store = state.service.store();
    let now = now_ms();
    let sessions = store.list_sessions().ok()?;
    let live_sessions = sessions
        .iter()
        .filter(|s| !s.token.is_empty() && state.service.stored_session_is_live(s, now))
        .map(|s| crate::store::session_token_hash(&s.token));
    let codes = store.live_enrolment_code_digests(now).ok()?;
    let answer = match live_sessions.chain(codes).find(|digest| bearer_key(digest) == key) {
        Some(digest) => bearer_proof(&digest, port, challenge)?,
        None => permaura_core::health_proof::BEARER_PROOF_NONE.to_string(),
    };
    axum::http::HeaderValue::from_str(&answer).ok()
}

/// The answer to a `/health` challenge keyed on each console session permaura.com may hold for this gateway, newest first, comma separated: the browser-direct console holds one of those and never the operator token, so it checks this header rather than [`health_proof`]'s. Absent when permaura.com holds none.
fn console_health_proof(state: &AppState, port: u16, headers: &HeaderMap) -> Option<axum::http::HeaderValue> {
    let challenge = headers
        .get(permaura_core::health_proof::CHALLENGE_HEADER)?
        .to_str()
        .ok()?;
    let proofs: Vec<String> = state
        .held_console_sessions
        .get()
        .iter()
        .filter_map(|session| permaura_core::health_proof::proof(session, port, challenge))
        .take(permaura_core::health_proof::CONSOLE_PROOF_MAX)
        .collect();
    if proofs.is_empty() {
        return None;
    }
    axum::http::HeaderValue::from_str(&proofs.join(",")).ok()
}

fn health_document(state: &AppState, full: bool) -> Result<Json<serde_json::Value>, GatewayError> {
    if !full {
        return Ok(Json(json!({ "status": "ok", "service": "permaura-gateway" })));
    }
    let store = state.service.store();
    let agents = store.list_agents()?.len();
    let caps = store.list_capabilities()?.len();
    let grants = store.list_grants()?.len();
    let audit_intact = store.verify_audit()?.is_none();
    let (approvals_pending, approvals_stalled) = approval_queue_depth(store.as_ref());
    Ok(Json(json!({
        "status": "ok",
        "service": "permaura-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        // The commit this binary was built from (see `build.rs`). Two builds of one version are
        // otherwise identical over the wire, which makes "is the fix deployed" unanswerable.
        "build_sha": env!("PERMAURA_BUILD_SHA"),
        // real | mock | demo. A `--demo` gateway answers every endpoint like a real one, so without
        // this neither a probe nor support triage can tell a customer's install from a seeded toy
        // whose operator bearer is published.
        "posture": state.posture.as_str(),
        // memory | sqlite | sqlite+gcs. The difference between an install that survives a restart and
        // one whose grants, secrets and audit chain evaporate with the process.
        "store_kind": store.kind(),
        // Set while a hosted store has a commit its bucket does not (writes and executions are
        // refused until an upload succeeds), and while the hot audit store is above its warning
        // threshold. Both are conditions of the store an operator has to act on, and the console
        // already reads this field, so folding the second in is what makes it visible at all.
        "store_degraded": state.service.degraded(),
        // real | dev: whether credentials are sealed under a genuine key or the PUBLIC dev constant.
        "vault_kek": if crate::service::vault_kek_is_dev() { "dev" } else { "real" },
        // The customer-felt approval failure every liveness probe misses: a held call nobody was ever
        // notified about leaves the gateway perfectly healthy and the agent silently blocked.
        // Counts only: never the capability, resource or message, which would leak what an operator
        // is being asked to approve to an unauthenticated caller.
        "approvals_pending": approvals_pending,
        "approvals_stalled": approvals_stalled,
        // true / false / null, where null means no signed manifest has been verified yet: offline,
        // disabled, or not yet checked. See `crate::release`.
        "manifest_behind": crate::release::manifest_behind(),
        // "local" while a tunnel connector this process started runs with the configuration it wrote, "stopped" once the guard stopped it because the connector reported another, or `permaura remote disable` stopped it (the reason beside it), null when it runs none. See `crate::tunnel`.
        "tunnel_ingress": crate::tunnel::connector().ingress(),
        "tunnel_stop_reason": crate::tunnel::connector().stop_reason(),
        // "accepted" while this gateway's resource server takes permaura.com tokens, "refused" once `permaura remote disable` withdrew it, null when it has none.
        "remote_tokens": state.service.oauth().map(|o| if o.is_withdrawn() { "refused" } else { "accepted" }),
        "agents": agents,
        "capabilities": caps,
        "grants": grants,
        "audit_chain_intact": audit_intact,
        // The key the chain is signed with, so a control plane holding a pin can tell a re-keyed store
        // from this gateway's own history. See `crate::audit_key`.
        "audit_key": crate::audit_key::report_for(store.as_ref()),
        // Admission control: what is in flight, what the bounds are, and how much has been shed.
        // Authenticated-only like the rest of this block, and per-instance. See `crate::limits`.
        "limits": state.limits.health_snapshot(),
        // This month's mutating calls against the fair-use thresholds, and the state they put the
        // worker in. Durable across cold starts, unlike `limits`. `null` on a gateway that is not
        // hosted, which is never counted. See `crate::fair_use`.
        "fair_use": state.fair_use.health(),
        // The plan allowances, each as `{current, limit, refused}`, with a `limit` of null meaning
        // unlimited. This is the block a console reads to show usage against the cap, and reading it
        // is the difference between showing what this worker enforces and asserting what a plan row
        // says: an admin page that cannot see these numbers has no way to know whether the worker in
        // front of it carries the knobs at all. Every `limit` null is a self-hosted gateway, or a
        // hosted one the provisioner has not yet reconciled. See `crate::allowances`.
        "allowances": allowances_snapshot(&state),
        // The execution hold, as the last read left it: reported, never rechecked, because a
        // status document must not be the thing that wakes an idle instance. `null` means this
        // gateway has no hold configured at all, which must not read as "open": one is a gateway
        // that was never told about holds, the other is one that checked and is free to execute.
        // State and hold id only; the reason names the checkpoint a restore is promoting and
        // belongs in the 423, not here. See `crate::restore`.
        "execution_hold": crate::restore::health_snapshot(state.service.execution_hold()),
        "agents_paused": state.service.agents_paused(),
        // The reconciliation this gateway is in, if any. Counts and a state, never an id of
        // anything restored: `/health` is read by the console and by the hosted fleet check, and a
        // list of a tenant's grants and secrets is not a status document's business. `null` means
        // this gateway has never been restored, which must not read as "reconciled".
        "reconciliation": state
            .service
            .reconciliation()
            .ok()
            .flatten()
            .map(|r| r.health_snapshot())
            .unwrap_or(serde_json::Value::Null),
        // The hot audit store: how many events it holds, the two thresholds, which band that is,
        // and how many executions the ceiling has refused since this container started. Nothing
        // prunes the chain yet, so this is the number that says how long this worker has left before
        // it stops admitting work. See `crate::audit_ceiling`.
        "audit_pressure": state
            .service
            .audit_ceiling()
            .health_snapshot(store.audit_len().unwrap_or(0)),
        // The archive writer. `{"enabled": false}` means this gateway publishes nothing and prunes
        // nothing, which is every gateway until the flag is turned on for it. When it is on, the
        // fields to watch while enabling a tenant are `pending` (events waiting to leave the hot
        // store), `segments` and `last_error`: a `pending` that climbs while `segments` does not is
        // a writer that cannot publish, and the ceiling will start refusing before anything else
        // says so. See `crate::archive`.
        "audit_archive": match state.service.audit_archive() {
            Some(archive) => {
                archive.health_snapshot(archive.pending(store.as_ref()).unwrap_or(0))
            }
            None => json!({ "enabled": false }),
        },
    })))
}

/// The `allowances` block for `/health`: every allowance with its live count and its ceiling.
///
/// A store read failure reports that allowance as zero rather than failing the whole document, for
/// the reason [`approval_queue_depth`] does the same: liveness is the more valuable of the two
/// answers, and the reads above this point already fail loudly if the store is unreadable at all.
fn allowances_snapshot(state: &AppState) -> serde_json::Value {
    let counts: Vec<(crate::allowances::Allowance, u64)> = crate::allowances::Allowance::ALL
        .iter()
        .map(|a| (*a, state.service.allowance_count(*a).unwrap_or(0)))
        .collect();
    state.service.allowances().health_snapshot(&counts)
}

/// How long a held call may sit unresolved before it counts as **stalled** rather than merely
/// pending. Held agent calls do not expire ([`crate::relay::APPROVAL_TTL_MS`] is 0), so depth alone never distinguishes
/// "a human is deciding" from "the notification path is broken and nobody knows". Override with
/// `PERMAURA_APPROVAL_STALL_MS` for a deployment whose approvers are genuinely slower than this.
const APPROVAL_STALL_MS: i64 = 30 * 60 * 1000;

fn approval_stall_ms() -> i64 {
    std::env::var("PERMAURA_APPROVAL_STALL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(APPROVAL_STALL_MS)
}

/// `(pending, stalled)` for the approval queue. A store read failure reports `(0, 0)` rather than
/// failing the whole health document: `/health` liveness is the more valuable of the two answers,
/// and the three reads above already fail loudly if the store is unreadable at all.
fn approval_queue_depth(store: &dyn crate::store::Store) -> (usize, usize) {
    let Ok(pending) = store.list_approvals(Some("pending")) else {
        return (0, 0);
    };
    let cutoff = crate::store::now_ms().saturating_sub(approval_stall_ms());
    let stalled = pending.iter().filter(|a| a.created_at <= cutoff).count();
    (pending.len(), stalled)
}

// ── Auth helper ─────────────────────────────────────────────────────────────────

/// Pull the bearer token out of the `Authorization` header.
fn bearer(headers: &HeaderMap) -> Result<String, GatewayError> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| GatewayError::Unauthorized("missing Authorization header".into()))?;
    let token = raw.strip_prefix("Bearer ").unwrap_or(raw).trim();
    if token.is_empty() {
        return Err(GatewayError::Unauthorized("empty bearer token".into()));
    }
    Ok(token.to_string())
}

fn authed(state: &AppState, headers: &HeaderMap) -> Result<Session, GatewayError> {
    let token = bearer(headers)?;
    state.service.authenticate(&token)
}

/// Like [`authed`] but additionally requires an **operator** (control-plane) session. Agent
/// tokens (minted by MCP self-enrolment or the relay) are rejected: they may invoke and
/// enrol, never mutate the console. This is the gate that stops a self-enrolled, not-yet-
/// approved agent from approving itself or granting itself access, and it is required on every
/// state-changing / credential / approval endpoint.
fn operator_authed(state: &AppState, headers: &HeaderMap) -> Result<Session, GatewayError> {
    let session = authed(state, headers)?;
    if session.role != SessionRole::Operator {
        return Err(GatewayError::Denied(
            "operator role required: agent tokens cannot drive the console".into(),
        ));
    }
    Ok(session)
}

/// Refuses a caller that is not an operator from its headers alone, before the body is read, because a bulk body is the largest the gateway accepts and a hostile one parses into a tree many times its size.
/// Each handler still authenticates for itself, so mounting one elsewhere cannot drop the check.
pub(crate) async fn operator_before_body(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Err(refusal) = operator_authed(&state, req.headers()) {
        let limit = state.limits.config().body_bulk_bytes;
        return refuse_after_draining(req, limit, refusal.into_response()).await;
    }
    next.run(req).await
}

/// Answers `refusal` after reading and discarding at most `limit` bytes of the body, one chunk at a time.
/// hyper closes a connection whose request body was left unread, and a close with the client's bytes still unread in the socket is a reset, which a client still uploading sees in place of the status.
pub(crate) async fn refuse_after_draining(req: Request, limit: usize, refusal: Response) -> Response {
    use futures_util::StreamExt as _;
    // A client waiting on `100 Continue` has sent no body yet, and reading would invite the one being refused.
    let expects_continue = req
        .headers()
        .get(axum::http::header::EXPECT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
    // Reading cannot finish a body declared larger than the limit, so it would only delay the answer.
    let declared_over = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > limit as u64);
    if expects_continue || declared_over {
        return refusal;
    }
    let mut body = req.into_body().into_data_stream();
    let mut read = 0usize;
    while read < limit {
        match body.next().await {
            Some(Ok(chunk)) => read = read.saturating_add(chunk.len()),
            _ => break,
        }
    }
    refusal
}

/// Whether a request arrived over the semi-trusted broker / a public ingress, or from a web page,
/// rather than from a client on the gateway's own host, computed once per request by [`tag_remote`]
/// and carried as a request extension so every operator-plane guard reads exactly one value. `pub`
/// because it appears in the `pub` handler signatures that extract it, but it is only ever
/// constructed by [`tag_remote`].
#[derive(Clone, Copy, Debug)]
pub struct RemoteFlag(pub bool);

/// The single remote-ness predicate. A call is remote when:
///  - `hosted`: a Mode C worker on Cloud Run is directly internet-exposed and has NO loopback client
///    at all, so every request is remote. (Cloudflare headers are absent here: there is no tunnel in
///    front, so the header heuristic cannot catch it; the explicit flag must.)
///  - Cloudflare stamps `Cf-Connecting-Ip`/`Cf-Ray` on tunnelled (Mode B) requests and strips any
///    client-supplied copies at the edge, so their presence proves the call came in over the tunnel.
///  - any other HTTP forwarder (a bring-your-own tunnel (ngrok, Tailscale Funnel) or a local
///    reverse proxy) stamps standard forwarding headers on what it relays. Those daemons connect
///    from loopback, so the peer check below cannot see past them and the headers are the only
///    signal separating their traffic from a local browser's. A local caller gains nothing by adding
///    these headers (fail-closed), and a remote caller cannot remove what the forwarder adds.
///    Residual: a raw TCP forwarder (`ssh -R`) adds no headers and relays from loopback, so it stays
///    indistinguishable; the docs steer BYO users to HTTP tunnels for exactly this reason.
///  - the TCP **peer address is non-loopback**: a request from off-host on an exposed gateway. This
///    is the fix for a BYO / non-Cloudflare public ingress (a Pro+ user who set `PERMAURA_PUBLIC_URL`
///    and binds `0.0.0.0`): it stamps no Cloudflare header, so without the peer check it read as
///    loopback and defeated the guard. `None` (connect-info absent: a Unix socket, or an embedded
///    `oneshot` in tests) is treated as loopback: an off-host caller cannot reach either.
///  - the request carries an **`Origin`** other than the desktop app's own webview: a web page sent
///    it. permaura.com's console reaches a loopback-only gateway straight from the browser with the
///    stored operator bearer, so its peer is loopback, but the code driving it was served by someone
///    else. Browsers always send `Origin` on that cross-origin fetch and a page cannot forge it; the
///    CLI, the desktop supervisor and mcp-stdio send none.
///  - the bearer is one **permaura.com holds**: a JWT, which only permaura.com mints for this gateway,
///    or a console session ([`crate::CONSOLE_TOKEN_PREFIX`]), the copy it keeps sealed for the console.
///    permaura.com's Cloudflare account can push the managed tunnel's connector a configuration of
///    its own, or route private-network traffic through it, either of which delivers requests from
///    loopback with no forwarder header until the gateway's guard stops the connector about a second
///    later; a request carrying one of its bearers is permaura.com's, wherever it arrived from. A
///    local bearer is never JWT-shaped and never a console session.
fn compute_is_remote(hosted: bool, headers: &HeaderMap, peer: Option<SocketAddr>) -> bool {
    hosted
        || headers.contains_key("cf-connecting-ip")
        || headers.contains_key("cf-ray")
        || headers.contains_key("x-forwarded-for")
        || headers.contains_key("x-real-ip")
        || headers.contains_key("forwarded")
        || sent_by_a_web_page(headers)
        || presents_a_permaura_com_bearer(headers)
        || peer.is_some_and(|p| !p.ip().is_loopback())
}

/// Whether a request came through a tunnel or proxy (any of the forwarding headers [`compute_is_remote`] reads) or from an address that is not loopback: what a demo refuses. No peer address, which only an in-process test call lacks, reads as this machine.
pub(crate) fn forwarded_or_off_host(req: &Request) -> bool {
    let headers = req.headers();
    ["cf-connecting-ip", "cf-ray", "x-forwarded-for", "x-real-ip", "forwarded"].iter().any(|h| headers.contains_key(*h))
        || req.extensions().get::<ConnectInfo<SocketAddr>>().is_some_and(|ci| !ci.0.ip().is_loopback())
}

/// Whether the bearer has a JWT's shape, by the same test `authenticate` uses to try it as one, or is a console session.
fn presents_a_permaura_com_bearer(headers: &HeaderMap) -> bool {
    headers
        .get_all(axum::http::header::AUTHORIZATION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|raw| raw.strip_prefix("Bearer ").unwrap_or(raw).trim())
        .any(|bearer| bearer.matches('.').count() == 2 || crate::is_console_token(bearer))
}

/// The origins the desktop app's webview fetches from. Only an app installed on this machine can load
/// a page there, so it holds no authority a local process does not already have.
#[cfg(windows)]
const DESKTOP_WEBVIEW_ORIGINS: &[&str] = &["tauri://localhost", "http://tauri.localhost"];
#[cfg(not(windows))]
const DESKTOP_WEBVIEW_ORIGINS: &[&str] = &["tauri://localhost"];

fn sent_by_a_web_page(headers: &HeaderMap) -> bool {
    headers
        .get_all(axum::http::header::ORIGIN)
        .iter()
        .any(|origin| !DESKTOP_WEBVIEW_ORIGINS.iter().any(|app| origin.as_bytes() == app.as_bytes()))
}

/// Middleware: stamp every request with its computed [`RemoteFlag`] before it reaches a handler, so
/// the operator-plane guards read a single, consistently-derived value (including the peer address,
/// which is only available here as a connection extension, not in the handler's `HeaderMap`).
pub(crate) async fn tag_remote(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0);
    let remote = compute_is_remote(state.hosted, req.headers(), peer);
    req.extensions_mut().insert(RemoteFlag(remote));
    next.run(req).await
}

/// Reject a request to the loopback-only operator plane when it can't be trusted as loopback-local.
///
/// The session-open primitive, self-run approver-key pairing, a self-run floor lowering and shutdown
/// rest on the operator bearer, a 0600 file on the gateway's host, plus placement. None of them may be
/// reachable remotely, so a caller that is not a loopback client on this machine is refused here.
/// `remote` is the [`RemoteFlag`] the [`tag_remote`] middleware computed. The authenticated proxy
/// and `/mcp` (OAuth, audience-bound, owner-locked) are unaffected.
fn reject_if_remote(remote: bool) -> Result<(), GatewayError> {
    if remote {
        return Err(GatewayError::Denied(
            "operator plane is loopback-only: not exposed on a hosted, tunnelled, or proxied gateway, or to a web page"
                .into(),
        ));
    }
    Ok(())
}

/// A remote request to a self-run gateway where nothing would hold it for a device: none is paired, or approvals are explicitly opted down. Whatever reaches a credential already here is refused outright rather than applied on the operator token alone; a hosted worker has no host to fall back to and keeps its own rules.
fn unpaired_remote_self_run(state: &AppState, remote: bool) -> bool {
    !state.hosted && remote && !state.service.vault_export_hold_required()
}

/// The refusal for an operation that reaches a credential already here, when [`unpaired_remote_self_run`].
fn unpaired_remote_refusal(what: &str) -> GatewayError {
    GatewayError::Denied(format!(
        "{what}, and no device is paired to confirm it (or approvals are opted down, so nothing holds it for one), so it is refused from a web page or over a tunnel or the network. Do it from the desktop app or the permaura CLI on the gateway's own machine, or pair a device or raise the approval floor first."
    ))
}

/// The refusal for a change that moves a stored credential on a hosted worker no device is paired to: there is no host to make it from, and nothing to hold it for.
fn unpaired_hosted_refusal(what: &str) -> GatewayError {
    GatewayError::Denied(format!(
        "{what}, and no device is paired to this gateway to confirm it, so it is refused. Pair a device first."
    ))
}

/// Who asked for a remote control-plane change, as a hold records it: the member permaura.com names
/// in the operator token, and the device the session belongs to. A loopback request names nobody,
/// because there the hold exists against the owner's own agents rather than another person.
fn requester_of(op: &Session, remote: bool) -> Option<crate::store::HoldRequester> {
    if !remote {
        return None;
    }
    crate::store::HoldRequester::named(op.actor.as_ref().map(|a| a.sub.clone()), op.device_id.clone())
}

/// Whether a remote caller may change where a stored credential is sent or how it is presented: the
/// standing a vault export takes, since the next call hands the credential to whatever host is
/// chosen. Where permaura.com names the acting member, that is the gateway's owner, or a member whose
/// operator token carries the signed `vault_export` claim the console mints only for a holder of the
/// Export the vault capability; a role alone (`act_role`) never confers it, so an admin without Export
/// cannot move a credential the docs say only Export hands over. Where nothing names anyone, a self-run
/// gateway's own operator bearer is its owner's credential, as it is for an export, while a hosted
/// worker, whose console always names who is acting, has nobody to grant it to.
fn may_move_a_credential(state: &AppState, op: &Session, remote: bool) -> bool {
    if !remote {
        return true;
    }
    let Some(actor) = op.actor.as_ref() else { return !state.hosted && !op.token.is_empty() };
    let owner = state.service.oauth().and_then(|o| o.owner_sub());
    owner.as_deref() == Some(actor.sub.as_str()) || actor.vault_export == Some(true)
}

/// Who may make a change that moves a stored credential, for the refusal a caller without that standing reads.
const CREDENTIAL_MOVE_STANDING: &str =
    "the gateway's owner, or a member permaura.com says holds Export the vault";

/// Refuse a change that moves a credential already stored here (`what` says which) on the terms every route that can make one shares; the device hold, where one applies, comes on top.
fn refuse_a_credential_move(state: &AppState, op: &Session, remote: bool, what: &str) -> Result<(), GatewayError> {
    if unpaired_remote_self_run(state, remote) {
        return Err(unpaired_remote_refusal(what));
    }
    if state.hosted && !state.service.any_device_trusted() {
        return Err(unpaired_hosted_refusal(what));
    }
    if !may_move_a_credential(state, op, remote) {
        return Err(GatewayError::Denied(format!(
            "{what}, which hands that credential to whoever chooses the host, so it takes the standing a vault export does: {CREDENTIAL_MOVE_STANDING}. Ask one of them to make this change."
        )));
    }
    Ok(())
}

/// The header a step-up pairing ticket is presented in. A header and not a body field so the two
/// endpoints that take one share exactly the same shape, and so a ticket never lands in the URL,
/// where every proxy, browser history and access log on the path would keep a copy of a credential
/// whose entire security property is that it is spent once.
const PAIRING_TICKET_HEADER: &str = "x-permaura-pairing-ticket";

/// How long a spent ticket's `jti` is kept in the store's single-use ledger. Deliberately far longer
/// than any ticket can stay verifiable (a 180s TTL, and a re-authentication the AS may assert for at
/// most a few minutes), because the failure directions are not symmetric: a row kept too long costs
/// a few bytes, while a row pruned while its ticket is still live makes that ticket replayable again
/// for the rest of its life.
const TICKET_CLAIM_RETENTION_MS: i64 = 30 * 60 * 1000;

/// Who may write the approver keyring, lower the approval floor or issue recovery codes on THIS
/// request.
///
/// `Loopback` is the positional anchor. `HostedOwner` is the identity anchor on Mode C.
/// `SelfRunOwner` and `RecoveryTicket` carry a verified permaura.com ticket on a self-run gateway.
/// `RecoveryCode` is a spent recovery code.
pub(crate) enum PairingAuthority {
    /// The request came from a client on the gateway's own host. Nothing else is required: being
    /// able to talk to loopback is the proof.
    Loopback,
    /// A hosted (Mode C) worker: an owner-scoped OAuth operator session plus a verified, purpose-
    /// bound, audience-bound step-up ticket the AS minted after a fresh re-authentication. The
    /// fields are what the AS asserted about that re-auth, carried through to the audit record.
    ///
    /// "Owner" here describes the WORKER the anchor addresses, not the person. The ticket's `sub`
    /// and the operator session are both pinned to the owner because that is how a ticket is tied to
    /// one worker; on a team account the human who re-authenticated is whichever member holds
    /// `device.manage`, and `actor_sub` is the only field that names them.
    HostedOwner {
        /// The ticket's unique id, spent exactly once via `Store::claim_once`.
        jti: String,
        /// When the AS asserts the actor re-authenticated (unix seconds).
        auth_time: i64,
        /// The factors the AS asserts they used (RFC 8176).
        amr: Vec<String>,
        /// Who the AS asserts did it. `None` when the AS is too old to name one, which the audit
        /// record renders as an explicit null rather than omitting, so a reader is never left to
        /// infer that the absent actor was the owner.
        actor_sub: Option<String>,
        /// Their display name as the AS supplied it. Self-set, so it is a label to read and never a
        /// thing to match on.
        actor_name: Option<String>,
        /// The organization role the AS asserts behind `actor_sub`, `owner` or `admin` and nothing
        /// else. Read by the trust-root standing checks (first pairing, replacing another person's
        /// key, a floor change with no device trusted, and a revocation that would empty the
        /// keyring), and recorded in the audit detail.
        actor_role: Option<String>,
        /// Whether the AS names the worker's own account as the actor (`act_sub` equal to `sub`).
        actor_is_owner: bool,
        /// The `approver-revoke` ticket's signed `remove_alone` claim; see [`crate::oauth::PairingTicket::remove_alone`].
        remove_alone: bool,
    },
    /// A self-run gateway's revocation, or recovery code issuance, from off its own machine: the same operator session and verified ticket as [`PairingAuthority::HostedOwner`], for an `approver-revoke` or `recovery-codes-issue` ticket only.
    SelfRunOwner {
        /// The ticket's unique id, spent exactly once via `Store::claim_once`.
        jti: String,
        /// When the AS asserts the actor re-authenticated (unix seconds).
        auth_time: i64,
        /// The factors the AS asserts they used (RFC 8176).
        amr: Vec<String>,
        /// Who the AS asserts did it, `None` when it named nobody.
        actor_sub: Option<String>,
        /// Their display name as the AS supplied it.
        actor_name: Option<String>,
        /// The `approver-revoke` ticket's signed `remove_alone` claim; see [`crate::oauth::PairingTicket::remove_alone`].
        remove_alone: bool,
    },
    /// A single-use recovery code, issued when this gateway's first device was trusted and spent
    /// here. The RECOVERY anchor for a self-run gateway: it authorises the two controls that switch
    /// the device-signed hold off (lowering the floor, revoking the last key) without the device, and
    /// the operator bearer alone cannot produce one, since only Argon2id hashes are stored.
    RecoveryCode {
        /// Which of the issued codes was spent, so the owner can strike it off their copy.
        index: usize,
    },
    /// A single-use `recovery` ticket permaura.com minted after a fresh re-authentication, spent on a
    /// SELF-RUN gateway that is an OAuth resource server. The identity anchor, made available off
    /// Mode C: a gateway with remote access on already trusts an authorization server, so an owner
    /// whose device and codes are both gone has somewhere to prove who they are.
    ///
    /// It is not available to a gateway with no OAuth configuration, and nothing stands in for it
    /// there. Its host-side route is `permaura approver reset` with the gateway stopped, which
    /// takes a recovery code while a device is trusted. With neither the device nor a code,
    /// `permaura uninstall --purge-data` is what is left, and it destroys every credential.
    RecoveryTicket {
        /// The ticket's unique id, spent exactly once via `Store::claim_once`.
        jti: String,
        /// When the AS asserts the actor re-authenticated (unix seconds).
        auth_time: i64,
        /// The factors the AS asserts they used (RFC 8176).
        amr: Vec<String>,
        /// Who the AS asserts did it, `None` when it named nobody.
        actor_sub: Option<String>,
        /// Their display name as the AS supplied it.
        actor_name: Option<String>,
        /// The organization role the AS says entitled them, `None` for the owner's own ticket from an
        /// AS that names none. Recorded so the chain says on what standing a non-owner recovered.
        actor_role: Option<String>,
    },
}

impl PairingAuthority {
    /// Who asked, as a hold records it: the actor a ticket names. A positional or recovery-code anchor
    /// names nobody.
    fn requester(&self) -> Option<crate::store::HoldRequester> {
        match self {
            PairingAuthority::HostedOwner { actor_sub, .. }
            | PairingAuthority::SelfRunOwner { actor_sub, .. }
            | PairingAuthority::RecoveryTicket { actor_sub, .. } => {
                crate::store::HoldRequester::named(actor_sub.clone(), None)
            }
            PairingAuthority::Loopback | PairingAuthority::RecoveryCode { .. } => None,
        }
    }

    /// The audit `authority` label: what permitted the change, as an owner reading the chain later
    /// needs to see it. Never `device_cosigned`: none of these anchors is a device signature.
    fn label(&self) -> &'static str {
        match self {
            PairingAuthority::Loopback => "loopback",
            PairingAuthority::HostedOwner { .. } => AUTHORITY_HOSTED_OWNER_TICKET,
            PairingAuthority::SelfRunOwner { .. } => AUTHORITY_SELF_RUN_OWNER_TICKET,
            PairingAuthority::RecoveryCode { .. } => crate::recovery::AUTHORITY_RECOVERY_CODE,
            PairingAuthority::RecoveryTicket { .. } => crate::recovery::AUTHORITY_RECOVERY_TICKET,
        }
    }

    /// What this anchor contributes to an audit record's `detail`. For a hosted step-up that is the
    /// ticket id, the re-authentication the AS asserted, and WHO the AS says performed it: on a
    /// worker with no host to stand at, this is the only evidence an owner has afterwards that a
    /// trust-on-first-use enrolment was tied to a live sign-in rather than to a leaked bearer.
    ///
    /// `actor_sub` is written on every hosted record, `null` included. An org can hand
    /// `device.manage` to several people, so `auth_time` and `amr` on their own describe a
    /// re-authentication by *somebody*, and the owner reading this later, having been emailed
    /// about an enrolment they do not recognise, needs to know whether that somebody was them. An
    /// omitted key would be read as "the owner, obviously"; an explicit null cannot be.
    fn audit_detail(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut detail = serde_json::Map::new();
        if let PairingAuthority::RecoveryCode { index } = self {
            detail.insert("recovery_code_index".into(), json!(index));
        }
        if let PairingAuthority::RecoveryTicket { actor_role, .. } | PairingAuthority::HostedOwner { actor_role, .. } = self {
            detail.insert("actor_role".into(), json!(actor_role));
        }
        let ticket = match self {
            PairingAuthority::HostedOwner { jti, auth_time, amr, actor_sub, actor_name, .. }
            | PairingAuthority::SelfRunOwner { jti, auth_time, amr, actor_sub, actor_name, .. }
            | PairingAuthority::RecoveryTicket { jti, auth_time, amr, actor_sub, actor_name, .. } => {
                Some((jti, auth_time, amr, actor_sub, actor_name))
            }
            _ => None,
        };
        if let PairingAuthority::HostedOwner { remove_alone: true, .. } | PairingAuthority::SelfRunOwner { remove_alone: true, .. } = self {
            // The actor is named beside it, under `actor_sub`.
            detail.insert("remove_alone".into(), json!(true));
            detail.insert("capability".into(), json!(DEVICE_REMOVE_ANY_CAPABILITY));
        }
        if let Some((jti, auth_time, amr, actor_sub, actor_name)) = ticket {
            detail.insert("ticket_jti".into(), json!(jti));
            detail.insert("auth_time".into(), json!(auth_time));
            detail.insert("amr".into(), json!(amr));
            detail.insert("actor_sub".into(), json!(actor_sub));
            detail.insert("actor_name".into(), json!(actor_name));
        }
        detail
    }
}

/// Phrase the 401 a caller gets when it has not presented a ticket it needs, following `/mcp`'s
/// precedent of naming where the client should go to obtain credentials. `/mcp` can answer with a
/// real `WWW-Authenticate` challenge because it builds its own [`Response`]; [`GatewayError`] renders
/// as a bare status plus a JSON body and cannot carry a header, so the same pointer is carried in the
/// message text instead. If a machine-readable challenge is wanted here later, it needs a header-
/// carrying variant on `GatewayError`, not a bespoke response built in this module.
fn step_up_challenge(state: &AppState, purpose: crate::oauth::TicketPurpose) -> String {
    let metadata = state
        .service
        .live_oauth()
        .map(|o| format!("{}/.well-known/oauth-protected-resource/mcp", o.config().public_url))
        .unwrap_or_else(|| "this gateway's authorization server".to_string());
    format!(
        "this action needs a fresh '{}' pairing ticket in the {PAIRING_TICKET_HEADER} header; re-authenticate at the authorization server described by {metadata} to obtain one",
        purpose.claim()
    )
}

/// The PLACEMENT half of [`pairing_authority`], split out so a handler can settle it BEFORE it
/// inspects any credential.
///
/// The asymmetry is load-bearing rather than an oversight: Mode B *has* a host, so the positional
/// anchor is available there and is strictly stronger than any identity assertion the control plane
/// could make: a tunnelled gateway's owner can always walk to the machine. Only Mode C, which has no
/// loopback client to offer at all, gets the substitute. Handing the substitute to Mode B would mean
/// a compromised permaura.com could enrol its own key on gateways that never needed it to.
///
/// Order matters to the caller as much as the verdict does. A Mode B caller can never satisfy this,
/// so it must be told so (403, [`reject_if_remote`]'s own wording) rather than being sent off to
/// re-authenticate (401) for a door that is shut. Checking its bearer first produces the wrong
/// answer, so `pair_approver_key` runs this before `operator_authed`. `set_approval_floor`
/// authenticates first because raising the floor is open on every mode.
fn pairing_placement_allows(state: &AppState, remote: bool) -> Result<(), GatewayError> {
    if state.hosted {
        return Ok(());
    }
    reject_if_remote(remote)
}

/// Resolve which anchor (if any) authorises a keyring write / floor lowering on this request.
///
/// `op` is the caller's already-verified **operator** session; the handler authenticates once and
/// passes it in, so no path here authenticates a second time. It is required on every branch,
/// including the loopback one: an agent token must not reach the trust root on any mode.
///
/// The order is the security argument, so it is fixed:
///  1. **Placement** ([`pairing_placement_allows`]): a non-hosted remote caller is refused here,
///     before anything else is consulted.
///  2. **Not remote → `Loopback`.** Every Mode A and Mode B path, and every existing test, reaches
///     the same verdict it always did.
///  3. A **ticket** must be presented, or the caller is told to go and re-authenticate (401, not
///     403; see [`GatewayError::StepUpRequired`]).
///  4. The gateway must actually **be** a Resource Server. With no AS-issued identity to verify
///     against there is no identity anchor, and a hosted worker with none has no safe pairing path:
///     refuse rather than fall back to trusting the bearer alone.
///  5. The ticket verifies against the JWKS the gateway already trusts, for this exact purpose,
///     audience and binding.
///  6. The operator session's `user_id` equals the ticket's `sub`, or the session carries no
///     `user_id` at all, which on a hosted worker means owner authority by construction (see
///     [`session_may_spend_owner_ticket`]). `verify_ticket` has already pinned `sub` to
///     `PERMAURA_OWNER_SUB`, so this last step ties the ticket and the session to one and the same
///     WORKER: a ticket minted for one tenant cannot be spent against another's session, and a
///     stolen session cannot be driven with another tenant's ticket.
///
/// Step 6 is deliberately not an actor check, and reading it as one is the mistake to avoid. Both
/// sides of that equality are the owner because both are how a hosted worker is addressed; the
/// person is `ticket.actor_sub`, which the gateway cannot verify at all (it holds no org roster)
/// and therefore records rather than enforces. Membership and the `device.manage` capability are
/// checked where they are knowable, at the AS, before a ticket exists.
///
/// The ticket is deliberately NOT spent here. Verification is pure, so the caller can run the
/// remaining checks (a possession proof, a freshness window) and spend the `jti` immediately before
/// the write it authorises: spending it earlier would burn a ticket on a request that then failed
/// for an unrelated reason and force the owner through another re-authentication.
fn pairing_authority(
    state: &AppState,
    op: &Session,
    remote: bool,
    headers: &HeaderMap,
    purpose: crate::oauth::TicketPurpose,
    bind: crate::oauth::TicketBinding<'_>,
) -> Result<PairingAuthority, GatewayError> {
    pairing_placement_allows(state, remote)?;
    if !remote {
        return Ok(PairingAuthority::Loopback);
    }
    ticket_authority(state, op, headers, purpose, bind)
}

/// Steps 3 to 6 of [`pairing_authority`], which a remote revocation also takes, on a self-run gateway as well as a hosted one.
fn ticket_authority(
    state: &AppState,
    op: &Session,
    headers: &HeaderMap,
    purpose: crate::oauth::TicketPurpose,
    bind: crate::oauth::TicketBinding<'_>,
) -> Result<PairingAuthority, GatewayError> {
    let token = headers
        .get(PAIRING_TICKET_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| GatewayError::StepUpRequired(step_up_challenge(state, purpose)))?;
    let oauth = state.service.oauth().ok_or_else(|| {
        GatewayError::Denied(
            "this gateway is not an OAuth resource server, so it has no identity anchor to verify a ticket against".into(),
        )
    })?;
    let ticket = verify_ticket_audited(state, oauth, token, purpose, bind).map_err(|e| {
        // A ticket pinned to another device was minted for a different revocation, and asking for a fresh step-up would loop on the same mismatch.
        if e.unbound && matches!(bind, crate::oauth::TicketBinding::ApproverId { .. }) {
            GatewayError::Denied(format!("revocation ticket refused: {e}"))
        } else {
            GatewayError::StepUpRequired(format!("pairing ticket rejected: {e}"))
        }
    })?;
    if !session_may_spend_owner_ticket(op, &ticket.sub) {
        return Err(GatewayError::Denied(
            "the pairing ticket was minted for a different account than this operator session".into(),
        ));
    }
    let actor_is_owner = ticket.actor_sub.as_deref() == Some(ticket.sub.as_str());
    let crate::oauth::PairingTicket { jti, auth_time, amr, actor_sub, actor_name, actor_role, remove_alone, .. } = ticket;
    Ok(if state.hosted {
        PairingAuthority::HostedOwner { jti, auth_time, amr, actor_sub, actor_name, actor_role, actor_is_owner, remove_alone }
    } else {
        PairingAuthority::SelfRunOwner { jti, auth_time, amr, actor_sub, actor_name, remove_alone }
    })
}

/// [`crate::oauth::OAuthRs::verify_ticket`], recording a ticket refused for its `amr` the way a refused recovery ticket is recorded: it verified as the AS's own, so the AS minted a step-up below policy.
fn verify_ticket_audited(
    state: &AppState,
    oauth: &crate::oauth::OAuthRs,
    token: &str,
    purpose: crate::oauth::TicketPurpose,
    bind: crate::oauth::TicketBinding<'_>,
) -> Result<crate::oauth::PairingTicket, crate::oauth::TicketRejected> {
    use crate::oauth::{TicketBinding, TicketPurpose};
    let rejected = match oauth.verify_ticket(token, purpose, bind, now_ms() / 1000) {
        Ok(ticket) => return Ok(ticket),
        Err(rejected) => rejected,
    };
    let Some(weak) = &rejected.weak_step_up else {
        return Err(rejected);
    };
    let (target, authority) = match (bind, purpose) {
        (TicketBinding::ApproverKey { approver_id, .. } | TicketBinding::ApproverId { approver_id }, _) => {
            (approver_id, if state.hosted { AUTHORITY_HOSTED_OWNER_TICKET } else { AUTHORITY_SELF_RUN_OWNER_TICKET })
        }
        (TicketBinding::None, TicketPurpose::Recovery) => ("recovery-ticket", crate::recovery::AUTHORITY_RECOVERY_TICKET),
        (TicketBinding::None, TicketPurpose::RecoveryCodesIssue) => ("recovery-codes", AUTHORITY_SELF_RUN_OWNER_TICKET),
        (TicketBinding::None, _) => ("approval-floor", AUTHORITY_HOSTED_OWNER_TICKET),
    };
    let mut detail = serde_json::Map::new();
    let reason = if purpose.needs_two_factors() {
        "ticket refused: its amr does not hold the password and a second factor, two different strong methods, or one strong method and a backup code"
    } else {
        "ticket refused: its amr names no password, passkey or phone approval"
    };
    detail.insert("reason".into(), json!(reason));
    detail.insert("purpose".into(), json!(purpose.claim()));
    detail.insert("ticket_jti".into(), json!(weak.jti));
    detail.insert("amr".into(), json!(weak.amr));
    detail.insert("actor_sub".into(), json!(weak.actor_sub));
    detail.insert("actor_name".into(), json!(weak.actor_name));
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        target,
        None,
        authority,
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(error = %e, "a ticket refused for its amr was not recorded in the audit chain");
    }
    Err(rejected)
}

/// Step 6 of [`pairing_authority`]: may this operator session spend a ticket minted for `owner_sub`?
///
/// The equality is the rule and stays the rule for every session that names a user. What this adds is
/// the one case where the session names nobody: a store-backed operator session with `user_id: None`.
/// That session shape is not a gap in the check, it is a credential the worker minted for ITSELF.
/// `seed::clean_bootstrap` (and its rotation twin) create it at boot and publish it to
/// `operator.token`, and on a hosted worker there is no other producer, because
/// `POST /v1/sessions`, the one route that lets a caller choose a `user_id`, is refused as
/// loopback-only on every remote request and a hosted worker is unconditionally remote. So such a
/// session can only have been created by the worker's own boot path on behalf of the account the
/// worker was provisioned for. It is owner authority already; requiring it to *say* so meant the
/// published operator token could never spend a ticket at all, which took `permaura approver pair
/// --ticket` and `permaura approver revoke --ticket` out of service on the only mode that needs them.
///
/// The alternative (stamping `PERMAURA_OWNER_SUB` into the session at bootstrap) was rejected
/// because it only reaches a worker whose store is bootstrapped after the change. Every already
/// provisioned worker keeps its `NULL` row, and the CLI fallback is exactly what an owner reaches for
/// when the console path has failed them.
///
/// It does not weaken anything for a JWT session. `operator_session_from_jwt` always sets
/// `user_id: Some(claims.sub)`, and `verify` has already pinned that `sub` to `PERMAURA_OWNER_SUB`,
/// so a JWT session takes the equality branch every time. The empty-`token` guard makes that
/// structural rather than incidental: a JWT session carries no token string (its bearer is the JWT
/// the caller already holds), so even a future change that stopped setting `user_id` there could not
/// slide into this branch.
fn session_may_spend_owner_ticket(op: &Session, owner_sub: &str) -> bool {
    match op.user_id.as_deref() {
        Some(user_id) => user_id == owner_sub,
        None => !op.token.is_empty(),
    }
}

/// The step-up a revocation takes: none at a self-run gateway's own machine, where the operator bearer is enough, and otherwise an `approver-revoke` ticket bound to `approver_id`. Verified here; the caller spends it immediately before acting.
///
/// The step-up it demanded is RETURNED rather than discarded, so the audit record for the revocation can name it: a record saying only `operator_revocation` would describe a bearer, which is the credential that was deliberately not sufficient.
fn revocation_step_up(
    state: &AppState,
    op: &Session,
    remote: bool,
    headers: &HeaderMap,
    approver_id: &str,
) -> Result<Option<PairingAuthority>, GatewayError> {
    if !remote {
        return Ok(None);
    }
    if !state.hosted && state.service.oauth().is_none() {
        return Err(GatewayError::Denied(
            "revoking a device from anywhere but this gateway's own machine takes a fresh step-up at \
             permaura.com, and this gateway has no remote-access configuration to verify one: revoke \
             it from the gateway's own machine"
                .into(),
        ));
    }
    let bind = crate::oauth::TicketBinding::ApproverId { approver_id };
    ticket_authority(state, op, headers, crate::oauth::TicketPurpose::ApproverRevoke, bind).map(Some)
}

/// Whether the presented ticket claims to be a `recovery` one. Unverified on purpose: it only picks which full verification runs.
fn presents_recovery_ticket(headers: &HeaderMap) -> bool {
    headers
        .get(PAIRING_TICKET_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|t| crate::oauth::unverified_ticket_purpose(t.trim()))
        .is_some_and(|p| p == crate::oauth::TicketPurpose::Recovery.claim())
}

/// Revoke an approver key with [`revocation_step_up`] enforced, under the control-plane lock so "is this the last usable key?" cannot change between the answer and the revocation.
///
/// Without the lock the check is a read-then-write two callers can both pass: two concurrent revocations on a self-run gateway each see the other's device still usable, each skips the recovery authority, and between them they empty the keyring on the bearer alone. It also serialises against [`apply_or_hold_pairing`], so a pairing cannot land in the gap either.
///
/// The audit record is written HERE, so `DELETE /v1/approver-keys/:id` and `DELETE /v1/devices/:id`
/// emit one identical event. Reconciliation's device removal revokes outside this function and
/// records `recovery.remove` instead. The key it names is read from the KEYRING, which
/// is the thing being revoked; the push registry is a different set and answers `None` for every
/// approver that never registered for notifications, which is precisely the approver whose revocation
/// most needs to be legible.
///
/// The audit failure is logged, not propagated: the revocation has already landed and is the
/// fail-safe direction, so answering 500 would tell the caller their lost device is still trusted
/// when it is not.
async fn guarded_revoke_approver_key(
    state: &AppState,
    op: &Session,
    remote: bool,
    headers: &HeaderMap,
    approver_id: &str,
) -> Result<Guarded, GatewayError> {
    let _cp = state.service.control_plane_mutex().lock().await;
    let purpose = crate::oauth::TicketPurpose::ApproverRevoke;
    // Self-run and tunnelled gateways: the revocation that would EMPTY the keyring takes the recovery
    // authority on top of any step-up, because after it nothing is held for a device signature. A device
    // co-signs it, a recovery code applies it now, or a permaura.com recovery ticket does where this
    // gateway has an authorization server.
    if !state.hosted && state.service.revoking_would_empty_keyring(approver_id) {
        refuse_delayed_recovery(state, headers)?;
        let mutation = crate::policy_guard::Mutation::ApproverKeyRevoke {
            approver_id: approver_id.to_string(),
        };
        // A remote recovery ticket is also the step-up: the same re-authentication at the same AS, and one header cannot carry both tickets.
        let step_up = if presents_recovery_ticket(headers) {
            None
        } else {
            revocation_step_up(state, op, remote, headers, approver_id)?
        };
        let authority = match step_up {
            Some(_) => PairingAuthority::Loopback,
            None => with_recovery_ticket(state, op, PairingAuthority::Loopback, headers)?,
        };
        let authority = with_recovery_code(state, authority, headers)?;
        if let Some(s) = &step_up {
            spend_pairing_ticket(state, s, purpose, TicketSubject::Revoke { approver_id })?;
        }
        let outcome = recover_or_hold(state, &mutation, &authority, step_up.as_ref()).await?;
        if let (Guarded::Held(_, body), Some(s)) = (&outcome, &step_up) {
            let mut detail = s.audit_detail();
            detail.insert("approval_id".into(), body["approval_id"].clone());
            if let Err(e) = state.service.audit_approver_pairing(
                "requires_approval",
                approver_id,
                state.service.trusted_approver_key(approver_id).as_deref(),
                s.label(),
                serde_json::Value::Object(detail),
            ) {
                tracing::error!(approver = %approver_id, error = %e, "a held approver-key revocation was not recorded in the audit chain");
            }
        }
        return Ok(outcome);
    }
    let step_up = revocation_step_up(state, op, remote, headers, approver_id)?;
    if state.hosted && state.service.revoking_would_empty_keyring(approver_id) {
        refuse_emptying_unless_manager(state, step_up.as_ref(), approver_id)?;
    }
    if let Some(s) = &step_up {
        spend_pairing_ticket(state, s, purpose, TicketSubject::Revoke { approver_id })?;
        if revocation_takes_a_device(state, s, approver_id) {
            return hold_revocation_for_a_device(state, op, remote, s, approver_id);
        }
    }
    let revoked_key = state.service.trusted_approver_key(approver_id);
    let from_env = state.service.approver_key_from_environment(approver_id);
    state.service.revoke_approver_key(approver_id)?;
    let emptied = !state.service.any_device_trusted();
    if emptied {
        crate::recovery::clear(state.service.store().as_ref())?;
    }

    let (authority, mut detail) = match &step_up {
        Some(a) => (a.label(), a.audit_detail()),
        None => (AUTHORITY_OPERATOR_REVOCATION, serde_json::Map::new()),
    };
    detail.insert("revoked".into(), json!(true));
    detail.insert("emptied_keyring".into(), json!(emptied));
    if from_env {
        detail.insert("source".into(), json!("environment"));
    }
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        approver_id,
        revoked_key.as_deref(),
        authority,
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(approver = %approver_id, error = %e, "an approver-key revocation was not recorded in the audit chain");
    }
    let mut body = json!({ "approver_id": approver_id, "trusted": false, "emptied_keyring": emptied });
    if from_env {
        body["source"] = json!("environment");
        body["note"] = json!(
            "this key is set in PERMAURA_APPROVER_KEYS: it stays revoked while the variable names it, and any other key put there under this id is trusted. Remove it from the variable as well"
        );
    }
    Ok(Guarded::Applied(body))
}

/// The permaura.com capability under which a member removes any device alone, named in the audit record of a revocation an `approver-revoke` ticket's `remove_alone` claim applied at once.
const DEVICE_REMOVE_ANY_CAPABILITY: &str = "device.remove.any";

/// Whether a revocation made on `step_up` waits for a device rather than applying at once: it does unless the
/// gateway's owner made it, permaura.com signed that the actor may remove any device alone (`remove_alone`), or the
/// key is provably the actor's own. Separation of duty asks for the device most independent of whoever asked for a
/// held change, so removing a device that is someone else's, or nobody's in particular, would otherwise let a
/// manager strip the devices that stand between them and their own request.
fn revocation_takes_a_device(state: &AppState, step_up: &PairingAuthority, approver_id: &str) -> bool {
    let owners = match step_up {
        PairingAuthority::HostedOwner { remove_alone: true, .. } | PairingAuthority::SelfRunOwner { remove_alone: true, .. } => true,
        PairingAuthority::HostedOwner { actor_is_owner, .. } => *actor_is_owner,
        PairingAuthority::SelfRunOwner { actor_sub: Some(actor), .. } => {
            state.service.oauth().is_some_and(|o| o.owner_sub().as_deref() == Some(actor.as_str()))
        }
        _ => false,
    };
    let actor = step_up.requester().unwrap_or_default();
    !owners
        && state
            .service
            .approver_keyring_snapshot()
            .independence(approver_id, &actor)
            .is_some_and(|i| i > crate::relay::approver::Independence::Requester)
}

/// Hold a revocation [`revocation_takes_a_device`] says waits, for a device of someone other than the actor,
/// with the ticket that asked for it already spent. The device being removed may confirm its own removal.
fn hold_revocation_for_a_device(
    state: &AppState,
    op: &Session,
    remote: bool,
    step_up: &PairingAuthority,
    approver_id: &str,
) -> Result<Guarded, GatewayError> {
    let mutation = crate::policy_guard::Mutation::ApproverKeyRevoke { approver_id: approver_id.to_string() };
    let requester = step_up.requester().or_else(|| requester_of(op, remote));
    let approval = state.service.hold_mutation_approval(POLICY_WRITE_CAP, &mutation, HELD_OTHERS_DEVICE_NOTE, requester)?;
    let mut detail = step_up.audit_detail();
    detail.insert("approval_id".into(), json!(approval.id));
    if let Err(e) = state.service.audit_approver_pairing(
        "requires_approval",
        approver_id,
        state.service.trusted_approver_key(approver_id).as_deref(),
        step_up.label(),
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(approver = %approver_id, error = %e, "a held approver-key revocation was not recorded in the audit chain");
    }
    Ok(Guarded::Held(StatusCode::ACCEPTED, held_body(&approval)))
}

/// Whether an `act_role` claim names an organization owner or admin, the standing a recovery rests on. Compared by value here even though verification already drops every other value to `None`, so a later change to that filter cannot widen either check that reads it.
fn is_manager_role(role: Option<&str>) -> bool {
    matches!(role, Some("owner" | "admin"))
}

/// Whether a hosted ticket may set or clear a worker's trust root: the owner's own re-authentication, or that of an owner or admin of the organization as the AS asserts in `act_role`. An unnamed actor has neither.
fn has_trust_root_standing(authority: &PairingAuthority) -> bool {
    matches!(
        authority,
        PairingAuthority::HostedOwner { actor_sub: Some(_), actor_role, actor_is_owner, .. }
            if *actor_is_owner || is_manager_role(actor_role.as_deref())
    )
}

/// A hosted pairing that would trust the worker's FIRST device takes the same standing as emptying the
/// keyring: that device is the root every later one is co-signed from. The web refuses a member's ticket
/// for it when minting, and this holds the rule for a keyring emptied while such a ticket was still valid.
fn refuse_first_pairing_unless_manager(
    state: &AppState,
    authority: &PairingAuthority,
    approver_id: &str,
    approver_pubkey: &str,
) -> Result<(), GatewayError> {
    if has_trust_root_standing(authority) {
        return Ok(());
    }
    let mut detail = authority.audit_detail();
    detail.insert(
        "reason".into(),
        json!("pairing refused: it would be the first trusted device, and the ticket is neither the owner's own nor an organization owner's or admin's"),
    );
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        approver_id,
        Some(approver_pubkey),
        authority.label(),
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(approver = %approver_id, error = %e, "a refused first pairing was not recorded in the audit chain");
    }
    Err(GatewayError::Denied(
        "this gateway has no trusted device, so this one would become the device every later one is \
         confirmed from, and only the gateway's owner or an owner or admin of its organization can pair \
         that: ask an owner or admin to pair a device first"
            .into(),
    ))
}

/// A hosted pairing that would retire a key another device already holds under the same approver id is
/// that entry's person's own, or an organization owner's or admin's: a replacement removes the key as a
/// revocation does, and a member who could replace another person's key could make themselves the only
/// approver. A key paired before keys named a person is nobody's in particular, so only a manager may
/// replace it.
fn refuse_replacement_unless_entitled(
    state: &AppState,
    authority: &PairingAuthority,
    approver_id: &str,
    approver_pubkey: &str,
) -> Result<(), GatewayError> {
    let keyring = state.service.approver_keyring_snapshot();
    let own = matches!(
        authority,
        PairingAuthority::HostedOwner { actor_sub: Some(actor), .. } if keyring.person(approver_id) == Some(actor.as_str())
    );
    if own || has_trust_root_standing(authority) {
        return Ok(());
    }
    let mut detail = authority.audit_detail();
    detail.insert(
        "reason".into(),
        json!("pairing refused: it would replace a key another person holds under this approver id, and the ticket is neither that person's nor an organization owner's or admin's"),
    );
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        approver_id,
        Some(approver_pubkey),
        authority.label(),
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(approver = %approver_id, error = %e, "a refused key replacement was not recorded in the audit chain");
    }
    Err(GatewayError::Denied(
        "this approver id already holds a trusted key that is not yours to replace: only the person it \
         belongs to, or an owner or admin of the organization, can replace it. Pair your device under \
         an approver id of its own"
            .into(),
    ))
}

/// A hosted floor change while no device is trusted takes the standing the first pairing does: it
/// applies on the ticket alone, and the state it leaves is inherited by every device paired after it.
fn refuse_unanchored_floor_unless_manager(state: &AppState, authority: &PairingAuthority) -> Result<(), GatewayError> {
    if has_trust_root_standing(authority) {
        return Ok(());
    }
    let mut detail = authority.audit_detail();
    detail.insert(
        "reason".into(),
        json!("floor change refused: no device is trusted, and the ticket is neither the owner's own nor an organization owner's or admin's"),
    );
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        "approval-floor",
        None,
        authority.label(),
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(error = %e, "a refused floor change was not recorded in the audit chain");
    }
    Err(GatewayError::Denied(
        "this gateway has no trusted device, so a floor change would apply on this ticket alone and \
         stay in force after the next device is paired, and only the gateway's owner or an owner or \
         admin of its organization can make it: ask an owner or admin, or pair a device first"
            .into(),
    ))
}

/// A hosted revocation that would leave no trusted approver is the owner's own, or that of an owner or
/// admin of the organization as the AS asserts in `act_role`: the rule a self-run recovery
/// ticket already takes. After it the next enrolment is trust on first use, so a member who could empty
/// the keyring could then pair a device of their own as the worker's only approver, with no
/// co-signature from anyone. A revocation that leaves another approver trusted keeps its ticket rule.
fn refuse_emptying_unless_manager(
    state: &AppState,
    step_up: Option<&PairingAuthority>,
    approver_id: &str,
) -> Result<(), GatewayError> {
    if step_up.is_some_and(has_trust_root_standing) {
        return Ok(());
    }
    let mut detail = step_up.map(PairingAuthority::audit_detail).unwrap_or_default();
    detail.insert(
        "reason".into(),
        json!("revocation refused: it would leave no trusted approver, and the ticket is neither the owner's own nor an organization owner's or admin's"),
    );
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        approver_id,
        state.service.trusted_approver_key(approver_id).as_deref(),
        step_up.map_or(AUTHORITY_HOSTED_OWNER_TICKET, PairingAuthority::label),
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(approver = %approver_id, error = %e, "a refused emptying revocation was not recorded in the audit chain");
    }
    Err(GatewayError::Denied(
        "revoking this device would leave this gateway with no trusted approver, and only the gateway's \
         owner or an owner or admin of its organization can do that: pair another device first, or ask \
         an owner or admin to remove it"
            .into(),
    ))
}

/// Refuse `X-Permaura-Recovery: delayed`, by name and with the routes that do work.
///
/// The delayed path applied a recovery on a 24-hour timer with no second factor at all, on the
/// argument that every paired device would be told and could cancel it. `POST /v1/devices/enroll`
/// took an operator bearer and a caller-chosen approver id and would replace that approver's push
/// entry with one carrying no token, so the bearer could silence the announcement and wait; push is
/// best effort besides. A timer is not an authority. Refused rather than ignored, so a caller that
/// still sends the header gets told what to do instead of a hold it cannot resolve.
fn refuse_delayed_recovery(state: &AppState, headers: &HeaderMap) -> Result<(), GatewayError> {
    let asked = headers
        .get(crate::recovery::RECOVERY_INTENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("delayed"));
    if !asked {
        return Ok(());
    }
    Err(GatewayError::Denied(format!(
        "recovery that completes on a timer has been removed: it could be finished by the operator \
         bearer alone, which is the credential it was meant to be independent of. {}",
        recovery_routes_hint(state)
    )))
}

/// What a caller with no device signature is told to do, which depends on what this gateway has.
///
/// An OAuth resource server has an authorization server to re-authenticate at, so the identity anchor
/// is a real route for it. A gateway with no OAuth configuration has no third authority and is told
/// so plainly: with the device and the codes both gone, the only route left is
/// `permaura uninstall --purge-data`, which destroys every credential it holds.
fn recovery_routes_hint(state: &AppState) -> String {
    let mut hint = String::from(
        "A device this gateway trusts has to confirm this. If that device is gone, present one of \
         the recovery codes issued when it was paired in the X-Permaura-Recovery-Code header",
    );
    if state.service.live_oauth().is_some() {
        hint.push_str(
            ", or re-authenticate at permaura.com for a single-use recovery ticket and present it \
             in the X-Permaura-Pairing-Ticket header",
        );
        hint.push('.');
    } else {
        hint.push_str(
            ". This gateway has no remote-access configuration, so it has no authorization server \
             to re-authenticate at and no third route: with the device and the codes both gone, \
             nothing removes the device and keeps the vault. `permaura uninstall --purge-data` on the \
             host starts this gateway over and destroys every credential it holds.",
        );
    }
    hint
}

/// Upgrade a loopback anchor to [`PairingAuthority::RecoveryCode`] when the request carries a valid
/// code. The code is SPENT here, so this is called only where a code is an authority: the two
/// controls that switch the device-signed hold off (an emptying revocation, a floor lowering) and
/// issuing a fresh code set, and only once the request is otherwise going to proceed.
///
/// A code presented while no device is trusted is ignored rather than burned: nothing is held in
/// that state, so there is nothing for the code to buy. A hosted worker refuses codes outright; its
/// second factor is the ticket, and no codes are issued there.
fn with_recovery_code(
    state: &AppState,
    authority: PairingAuthority,
    headers: &HeaderMap,
) -> Result<PairingAuthority, GatewayError> {
    let Some(presented) = headers
        .get(crate::recovery::RECOVERY_CODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        return Ok(authority);
    };
    if state.hosted {
        return Err(GatewayError::Denied(
            "a hosted gateway does not accept recovery codes; re-authenticate at permaura.com for a ticket".into(),
        ));
    }
    if !matches!(authority, PairingAuthority::Loopback) || !state.service.any_device_trusted() {
        return Ok(authority);
    }
    match crate::recovery::consume(state.service.store().as_ref(), presented, now_ms())? {
        Some(index) => Ok(PairingAuthority::RecoveryCode { index }),
        None => {
            let mut detail = serde_json::Map::new();
            detail.insert("reason".into(), json!("recovery code refused: unknown, already spent, or from an earlier pairing"));
            if let Err(e) = state.service.audit_approver_pairing(
                "deny",
                "recovery-code",
                None,
                crate::recovery::AUTHORITY_RECOVERY_CODE,
                serde_json::Value::Object(detail),
            ) {
                tracing::error!(error = %e, "a refused recovery code was not recorded in the audit chain");
            }
            Err(GatewayError::Denied(
                "recovery code not accepted: it is unknown, already used, or was issued for an earlier pairing".into(),
            ))
        }
    }
}

/// Upgrade a loopback anchor to [`PairingAuthority::RecoveryTicket`] when the request carries a
/// verified single-use `recovery` ticket. The identity anchor, on a SELF-RUN gateway.
///
/// Available only where `state.service.oauth()` is `Some`, which is every gateway with remote access
/// configured. That is not an arbitrary condition: a gateway with no authorization server has nowhere
/// for its owner to re-authenticate, so a device signature and a recovery code are its only recovery
/// authorities.
///
/// Verified through the same [`crate::oauth::OAuthRs::verify_ticket`] a hosted worker uses, under its
/// own [`crate::oauth::TicketPurpose::Recovery`] so neither a pairing nor a floor ticket is spendable
/// here, and pinned to this gateway's owner exactly as the hosted path pins it. Spent immediately, so
/// one re-authentication authorises one control. The re-authentication must be the owner's own, or
/// that of someone the AS says currently owns or administers the organization (`act_role`).
///
/// Hosted is left alone: it reaches its ticket through [`pairing_authority`] already, under the
/// purpose that names each control, and a code or this ticket would be a second door into the same
/// room.
fn with_recovery_ticket(
    state: &AppState,
    op: &Session,
    authority: PairingAuthority,
    headers: &HeaderMap,
) -> Result<PairingAuthority, GatewayError> {
    let Some(token) = headers
        .get(PAIRING_TICKET_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return Ok(authority);
    };
    if state.hosted || !matches!(authority, PairingAuthority::Loopback) {
        return Ok(authority);
    }
    let purpose = crate::oauth::TicketPurpose::Recovery;
    let oauth = state.service.oauth().ok_or_else(|| {
        GatewayError::Denied(
            "this gateway is not an OAuth resource server, so it has no identity anchor to recover \
             against; use a device signature or a recovery code"
                .into(),
        )
    })?;
    let ticket = verify_ticket_audited(state, oauth, token, purpose, crate::oauth::TicketBinding::None)
        .map_err(|e| GatewayError::StepUpRequired(format!("recovery ticket rejected: {e}")))?;
    if !session_may_spend_owner_ticket(op, &ticket.sub) {
        return Err(GatewayError::Denied(
            "the recovery ticket was minted for a different account than this operator session".into(),
        ));
    }
    // `sub` is always the owner, so only `act_sub` says whose re-authentication this is. The owner's own
    // is accepted, and so is that of whoever currently owns or administers the organization, as the AS
    // asserts in `act_role`: roles move, and recovery has to follow them or a departed linker locks the
    // organization out. Anyone else's would let them empty the keyring that holds every device hold.
    let owners_own = ticket.actor_sub.as_deref() == Some(ticket.sub.as_str());
    let managers = ticket.actor_sub.is_some() && is_manager_role(ticket.actor_role.as_deref());
    if !owners_own && !managers {
        // Recorded like a refused recovery code: a member's attempt on the owner's keyring is exactly what the owner needs to see.
        let mut detail = serde_json::Map::new();
        detail.insert("reason".into(), json!("recovery ticket refused: not the owner's own, and no owner or admin role"));
        detail.insert("ticket_jti".into(), json!(ticket.jti));
        detail.insert("actor_sub".into(), json!(ticket.actor_sub));
        detail.insert("actor_name".into(), json!(ticket.actor_name));
        detail.insert("actor_role".into(), json!(ticket.actor_role));
        if let Err(e) = state.service.audit_approver_pairing(
            "deny",
            "recovery-ticket",
            None,
            crate::recovery::AUTHORITY_RECOVERY_TICKET,
            serde_json::Value::Object(detail),
        ) {
            tracing::error!(error = %e, "a refused recovery ticket was not recorded in the audit chain");
        }
        return Err(GatewayError::Denied(
            "a recovery ticket must be the gateway owner's own re-authentication or that of an owner or \
             admin of its organization: this one names neither, so it cannot lower the floor or empty the keyring"
                .into(),
        ));
    }
    let authority = PairingAuthority::RecoveryTicket {
        jti: ticket.jti,
        auth_time: ticket.auth_time,
        amr: ticket.amr,
        actor_sub: ticket.actor_sub,
        actor_name: ticket.actor_name,
        actor_role: ticket.actor_role,
    };
    spend_recovery_ticket(state, &authority, purpose)?;
    Ok(authority)
}

/// Spend a recovery ticket's `jti`, so one re-authentication authorises exactly one control.
///
/// Separate from [`spend_pairing_ticket`] only because that one matches on
/// [`PairingAuthority::HostedOwner`]; the ledger, the scope and the replay refusal are identical.
fn spend_recovery_ticket(
    state: &AppState,
    authority: &PairingAuthority,
    purpose: crate::oauth::TicketPurpose,
) -> Result<(), GatewayError> {
    let PairingAuthority::RecoveryTicket { jti, auth_time, .. } = authority else {
        return Ok(());
    };
    // The replay floor, immediately before the claim, because the claim is the check a restore
    // invalidated: the ledger this ticket would be spent against was rolled back with the database.
    // `auth_time` is the re-authentication the AS asserted, which is at or before the ticket was
    // issued, so this refuses at least everything the floor is meant to refuse.
    crate::restore::refuse_if_replayed_across_a_restore(
        state.service.store().as_ref(),
        auth_time.saturating_mul(1000),
        "recovery ticket",
    )?;
    if state.service.store().claim_once(purpose.scope(), jti, now_ms() + TICKET_CLAIM_RETENTION_MS)? {
        return Ok(());
    }
    let mut detail = authority.audit_detail();
    detail.insert("reason".into(), json!("recovery ticket replayed: this jti was already spent"));
    detail.insert("purpose".into(), json!(purpose.claim()));
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        "recovery-ticket",
        None,
        authority.label(),
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(jti = %jti, error = %e, "a replayed recovery ticket was not recorded in the audit chain");
    }
    Err(GatewayError::StepUpRequired(
        "this recovery ticket has already been spent; re-authenticate for a new one".into(),
    ))
}

/// The recovery funnel for the two controls that switch the device-signed hold off, called with the
/// control-plane lock ALREADY held. A recovery code or a verified recovery ticket applies the change
/// now; otherwise it is held for a device co-signature exactly like an enrolment.
///
/// There is no third outcome. The delayed path that used to sit here applied the change on a timer
/// with no second factor, and the bearer that was meant to be insufficient could silence the
/// notification the timer's safety rested on.
async fn recover_or_hold(
    state: &AppState,
    m: &crate::policy_guard::Mutation,
    authority: &PairingAuthority,
    step_up: Option<&PairingAuthority>,
) -> Result<Guarded, GatewayError> {
    if matches!(
        authority,
        PairingAuthority::RecoveryCode { .. } | PairingAuthority::RecoveryTicket { .. }
    ) {
        let mut detail = authority.audit_detail();
        if let Some(s) = step_up {
            detail.extend(s.audit_detail());
        }
        return Ok(Guarded::Applied(apply_mutation_as(
            state.service.store().as_ref(),
            state.service.as_ref(),
            m,
            authority.label(),
            detail,
        )?));
    }
    let requester = step_up.and_then(PairingAuthority::requester).or_else(|| authority.requester());
    let message = trust_root_note(m, &requester);
    let approval = state.service.hold_change_approval(POLICY_WRITE_CAP, m, message, requester).await?;
    let mut body = held_body(&approval);
    body["recovery"] = json!(recovery_routes_hint(state));
    Ok(Guarded::Held(StatusCode::ACCEPTED, body))
}

/// The audit `authority` for a revocation the operator bearer alone authorised: one made at a self-run gateway's own machine that leaves another usable key behind.
const AUTHORITY_OPERATOR_REVOCATION: &str = "operator_revocation";

/// The audit `authority` for a change a hosted worker applied on a verified step-up ticket.
const AUTHORITY_HOSTED_OWNER_TICKET: &str = "hosted_owner_ticket";

/// The audit `authority` for a self-run gateway's change from off its own machine on a verified ticket: an `approver-revoke` or a `recovery-codes-issue` one.
const AUTHORITY_SELF_RUN_OWNER_TICKET: &str = "self_run_owner_ticket";

/// What a step-up ticket was presented against, so a REFUSED spend can be recorded against something
/// more specific than "a ticket". Each variant is a purpose a ticket exists for.
enum TicketSubject<'a> {
    /// A key enrolment: the approver id and the public key the ticket was bound to.
    ApproverKey { approver_id: &'a str, pubkey: &'a str },
    /// A revocation of this approver id.
    Revoke { approver_id: &'a str },
    /// The approval floor, which has no per-object identity: there is only one.
    ApprovalFloor,
    /// A self-run gateway's recovery code set, issued from off its own machine.
    RecoveryCodes,
}

impl TicketSubject<'_> {
    /// The `(approver_id, pubkey)` pair the audit record names. `None` for the key means this event
    /// concerns no particular key, and the record then omits the fingerprint rather than inventing
    /// one (see [`crate::service::EnforcementService::audit_approver_pairing`]).
    fn audit_target(&self) -> (&str, Option<&str>) {
        match self {
            TicketSubject::ApproverKey { approver_id, pubkey } => (approver_id, Some(pubkey)),
            TicketSubject::Revoke { approver_id } => (approver_id, None),
            TicketSubject::ApprovalFloor => ("approval-floor", None),
            TicketSubject::RecoveryCodes => ("recovery-codes", None),
        }
    }
}

/// Spend a step-up ticket, so it authorises exactly one write. A no-op on the loopback anchor,
/// which is positional and has nothing to spend.
///
/// Call this AFTER every other check and immediately BEFORE the write it authorises. `claim_once`
/// enforces uniqueness in the *database*, which is the only place it can be enforced on a worker
/// that may be several Cloud Run instances at once: a process-local set would let one ticket be
/// spent once per instance, which is not single use.
///
/// A replayed ticket is AUDITED before the error is returned. It is the single most
/// interesting security event this feature can produce (every claim on it verified, which means it
/// was minted by the real AS for the real owner, and something is now presenting it a second time)
/// and on a hosted worker the audit chain is the only place an owner would ever see it. Returning
/// early here, as this used to, meant the one refusal that says "someone else has your ticket" was
/// the one refusal nothing recorded. The write failure is logged rather than propagated: the caller
/// is already being refused, and turning a 401 into a 500 would tell them the opposite of what
/// happened. A ticket refused at the restore replay floor, before the claim, is logged, not recorded.
fn spend_pairing_ticket(
    state: &AppState,
    authority: &PairingAuthority,
    purpose: crate::oauth::TicketPurpose,
    subject: TicketSubject<'_>,
) -> Result<(), GatewayError> {
    let (PairingAuthority::HostedOwner { jti, auth_time, .. }
    | PairingAuthority::SelfRunOwner { jti, auth_time, .. }) = authority
    else {
        return Ok(());
    };
    // See `spend_recovery_ticket`: the floor goes immediately before the claim, and `auth_time` is
    // the conservative reading of when this ticket came into existence.
    crate::restore::refuse_if_replayed_across_a_restore(
        state.service.store().as_ref(),
        auth_time.saturating_mul(1000),
        "pairing ticket",
    )?;
    let claimed = state.service.store().claim_once(
        purpose.scope(),
        jti,
        now_ms() + TICKET_CLAIM_RETENTION_MS,
    )?;
    if claimed {
        return Ok(());
    }
    let mut detail = authority.audit_detail();
    detail.insert("reason".into(), json!("pairing ticket replayed: this jti was already spent"));
    detail.insert("purpose".into(), json!(purpose.claim()));
    let (approver_id, pubkey) = subject.audit_target();
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        approver_id,
        pubkey,
        authority.label(),
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(jti = %jti, error = %e, "a replayed pairing ticket was not recorded in the audit chain");
    }
    Err(GatewayError::StepUpRequired(
        "this pairing ticket has already been spent: re-authenticate for a new one".into(),
    ))
}

/// The synthetic capability id under which a held control-plane mutation is queued as an approval.
/// It is not a real connector capability: [`crate::service::EnforcementService::resolve_approval`]
/// special-cases it to apply the stored [`crate::policy_guard::Mutation`] instead of executing an
/// upstream call.
pub(crate) const POLICY_WRITE_CAP: &str = "permaura.policy.write";

/// The `resource` ids the gateway files its own holds under: a held control-plane change and a held vault
/// export. A held agent call carries its connection's id there instead, so a connection with one of these
/// ids would put an agent's call in front of an approver as a settings change or an export.
pub(crate) const RESERVED_HOLD_RESOURCES: [&str; 2] = [crate::store::CONTROL_PLANE_RESOURCE, VAULT_RESOURCE];

/// Whether `id` is in the namespace of the gateway's own control-plane actions (`permaura.policy.write`,
/// `permaura.vault.export`), or is one of [`RESERVED_HOLD_RESOURCES`]. A capability id is its connection's
/// id and an action, so a connection named into the namespace could import a capability that a resolution
/// would apply as a stored control-plane change.
pub(crate) fn is_reserved_id(id: &str) -> bool {
    id == "permaura" || id.starts_with("permaura.") || RESERVED_HOLD_RESOURCES.contains(&id)
}

/// The credential slot a connection takes when nothing names one for it.
pub(crate) fn derived_secret_slot(connection_id: &str) -> String {
    format!("sec_{connection_id}")
}

/// Refuse a connection or capability id in the reserved namespace; see [`is_reserved_id`].
pub(crate) fn refuse_reserved_id(what: &str, id: &str) -> Result<(), GatewayError> {
    if !is_reserved_id(id) {
        return Ok(());
    }
    let why = if RESERVED_HOLD_RESOURCES.contains(&id) {
        "the gateway files its own held changes and exports under it"
    } else {
        "the permaura namespace belongs to the gateway's own control-plane actions"
    };
    Err(GatewayError::BadRequest(format!("{what} id '{id}' is reserved: {why}")))
}

fn refuse_reserved_capabilities(caps: &[Capability]) -> Result<(), GatewayError> {
    caps.iter().try_for_each(|c| refuse_reserved_id("capability", &c.id))
}

/// The most bytes a connection's id, name or label, or an SSH exec action, may take where an API call creates or renames the connection: every hold that names one stores a copy, and every audit event on an SSH capability names its action. An import, and a preset connection whose caller sends no label, cuts its label to it instead ([`cut_label`]); the rows a vault bundle restores keep what they carry.
const MAX_NAME_BYTES: usize = 128;

/// `label` cut to [`MAX_NAME_BYTES`] between characters. An import, and a preset connection with no label sent, cuts rather than refuses its label: the console sends a WordPress site's own name, or takes a manifest's own label, neither of which its user can edit.
fn cut_label(mut label: String) -> String {
    if label.len() > MAX_NAME_BYTES {
        let end = (0..=MAX_NAME_BYTES).rev().find(|&at| label.is_char_boundary(at)).unwrap_or(0);
        label.truncate(end);
        label.truncate(label.trim_end().len());
    }
    label
}

/// Refuse `value` when it is longer than [`MAX_NAME_BYTES`], without echoing it.
fn refuse_long_name(what: &str, value: &str) -> Result<(), GatewayError> {
    refuse_longer_than(what, value, MAX_NAME_BYTES)
}

/// Refuse `value` when it is longer than `max` bytes, without echoing it.
fn refuse_longer_than(what: &str, value: &str, max: usize) -> Result<(), GatewayError> {
    if value.len() <= max {
        return Ok(());
    }
    Err(GatewayError::BadRequest(format!(
        "the {what} is {} bytes, more than the {max} it may be; shorten it",
        value.len()
    )))
}

/// Refuse a connection an API call creates whose id, name or label is longer than [`MAX_NAME_BYTES`].
fn refuse_long_connection_names(id: &str, name: &str, label: &str) -> Result<(), GatewayError> {
    refuse_long_name("connection id", id)?;
    refuse_long_name("connection name", name)?;
    refuse_long_name("connection label", label)
}

/// The most bytes a capability id an import or re-sync derives from an OpenAPI operation or a WordPress route may take: the connection id, a dot and the operation's name, which FastAPI writes by default from the whole path.
const MAX_DERIVED_CAPABILITY_ID_BYTES: usize = 512;

/// Take out of `caps` each capability whose id is longer than [`MAX_DERIVED_CAPABILITY_ID_BYTES`], and its id out of `disabled`, returning where each was and why it was left out, so one long operation never refuses the rest. Ids and paths are shown cut.
fn leave_out_long_capability_ids(caps: &mut Vec<Capability>, disabled: &mut Vec<String>) -> Vec<(String, String)> {
    let mut left_out = Vec::new();
    caps.retain(|cap| {
        if cap.id.len() <= MAX_DERIVED_CAPABILITY_ID_BYTES {
            return true;
        }
        let at = match &cap.http {
            Some(http) => format!("{} {}", http.method.as_str(), cut_for_display(&http.path, 64)),
            None => cut_for_display(&cap.id, 64),
        };
        left_out.push((
            at,
            format!(
                "left out: its capability id would be {} bytes, more than the {MAX_DERIVED_CAPABILITY_ID_BYTES} a capability id may be",
                cap.id.len()
            ),
        ));
        false
    });
    disabled.retain(|id| id.len() <= MAX_DERIVED_CAPABILITY_ID_BYTES);
    left_out
}

/// `text` cut to `chars` characters, marked when it was cut.
fn cut_for_display(text: &str, chars: usize) -> String {
    match text.char_indices().nth(chars) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_string(),
    }
}

/// The synthetic action id every approver-keyring event is written under in the audit chain (see
/// [`crate::service::EnforcementService::audit_approver_pairing`]). Named on the REST surface because
/// a held enrolment is queued under [`POLICY_WRITE_CAP`] like every other control-plane hold, so the
/// 202 body has to carry this id for a console to tell a pending *device enrolment*, the one hold
/// whose whole point is that a device signs it, apart from a pending policy edit.
pub(crate) const APPROVER_PAIR_CAP: &str = "permaura.approver.pair";

/// The audit `authority` [`apply_mutation`] writes on the trust-root records (key trust or
/// revocation, floor and agent-gate changes). Only `resolve_approval` reaches those arms through
/// `apply_mutation`, on a verified device signature. Its other callers apply mutations that write no
/// such record.
const AUTHORITY_DEVICE_COSIGNED: &str = "device_cosigned";

/// Whether `secret_id` has a KMS custody record: this gateway's own wrapping of that credential, so deleting the secret or its last connection deletes it as it does a sealed row, and the slot is free again.
/// An Infisical record, an env enrolment or a dynamic id names an operator's vault and is never removed here.
fn kms_wrapped(store: &dyn Store, secret_id: &str) -> Result<bool, GatewayError> {
    Ok(store.get_secret_custody(secret_id)?.is_some_and(|c| c.kind == crate::store::CustodyKind::Kms))
}

/// Whether applying `m` first records the quorum high-water marks in force: every change that can take a rule out of
/// force does.
pub(crate) fn notes_quorum_marks(m: &crate::policy_guard::Mutation) -> bool {
    use crate::policy_guard::Mutation;
    matches!(
        m,
        Mutation::PolicyUpsert { .. }
            | Mutation::PolicyDelete { .. }
            | Mutation::GrantUpsert { .. }
            | Mutation::GrantDelete { .. }
            | Mutation::ConnectionDelete { .. }
            | Mutation::AgentDelete { .. }
    )
}

/// Apply a control-plane mutation through the same store operations the REST handlers use, so a
/// held-then-signed mutation lands byte-identically to an immediately-applied one. Shared by the
/// handlers (immediate apply) and `resolve_approval` (apply on device-signed resolution).
///
/// The arms that write a trust-root audit record label the authority [`AUTHORITY_DEVICE_COSIGNED`]
/// here, and only `resolve_approval` reaches them through this signature, on a verified device
/// signature over the exact held diff. An in-process caller that applies a trust-root mutation on
/// some *other* authority (a loopback operator, a hosted owner's step-up ticket) must go through
/// [`apply_mutation_as`] and name what actually permitted it, or the audit chain would attribute a
/// first-device enrolment to a co-signature that never happened.
pub(crate) fn apply_mutation(
    store: &dyn Store,
    service: &crate::service::EnforcementService,
    m: &crate::policy_guard::Mutation,
) -> Result<serde_json::Value, GatewayError> {
    apply_mutation_as(store, service, m, AUTHORITY_DEVICE_COSIGNED, serde_json::Map::new())
}

/// An audit record a mutation arm produced but must not write where it stands: `append_audit` refuses
/// to run inside a store transaction, because the signed chain it extends is held in memory and a
/// rollback cannot retract a link already sealed into it. Handed back and written after the commit.
struct TrustRecord {
    decision: &'static str,
    approver_id: String,
    pubkey: Option<String>,
    detail: serde_json::Value,
}

/// [`apply_mutation`] with the authorising anchor named explicitly, for the paths that apply a
/// mutation without a device co-signature. `authority` and `detail` only reach the audit record;
/// they never change what is written to the store, so the held and immediate paths stay
/// byte-identical.
///
/// `detail` carries the evidence that anchor rests on: for a hosted step-up, the ticket id and the
/// re-authentication the AS asserted. It matters most on the branch that needs it most: a
/// trust-on-first-use enrolment lands on nothing but that ticket, on a worker with no host anyone
/// could have stood at, so an `allow` record that named only the authority would leave an owner
/// unable to tell an enrolment they performed from one a leaked bearer performed for them.
pub(crate) fn apply_mutation_as(
    store: &dyn Store,
    service: &crate::service::EnforcementService,
    m: &crate::policy_guard::Mutation,
    authority: &str,
    detail: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, GatewayError> {
    apply_mutation_against(store, service, m, authority, detail, None)
}

/// The approval-params key under which a held grant, policy or agent upsert carries [`held_row_digest`] of the row it was asked against, so the device's signature covers it.
pub(crate) const HELD_BASE_KEY: &str = "base_sha256";

/// Digest of the live row a grant, policy or agent upsert would replace, `None` for every other mutation.
/// A policy upsert that also sets its grant membership covers that membership, because confirming it rewrites both.
pub(crate) fn held_row_digest(
    store: &dyn Store,
    m: &crate::policy_guard::Mutation,
) -> Result<Option<String>, GatewayError> {
    use crate::policy_guard::Mutation;
    let row = match m {
        Mutation::GrantUpsert { grant } => json!({ "grant": store.get_grant(&grant.grant_id)? }),
        Mutation::PolicyUpsert { policy, grant_ids } => {
            let members = match grant_ids {
                Some(_) => {
                    let mut ids: Vec<String> = store
                        .list_grants()?
                        .into_iter()
                        .filter(|g| g.policy_ids.contains(&policy.id))
                        .map(|g| g.grant_id)
                        .collect();
                    ids.sort();
                    Some(ids)
                }
                None => None,
            };
            json!({ "policy": store.get_policy(&policy.id)?, "grants": members })
        }
        Mutation::AgentUpsert { agent } => json!({ "agent": store.get_agent(&agent.id)? }),
        _ => return Ok(None),
    };
    let bytes = serde_json::to_vec(&row)
        .map_err(|e| GatewayError::Internal(format!("held row could not be encoded: {e}")))?;
    Ok(Some(permaura_core::audit::sha256_hex(&bytes)))
}

/// What a held grant or policy upsert names, for its refusal and its audit record.
fn held_row_target(m: &crate::policy_guard::Mutation) -> (&'static str, &str) {
    match m {
        crate::policy_guard::Mutation::GrantUpsert { grant } => ("grant", grant.grant_id.as_str()),
        crate::policy_guard::Mutation::PolicyUpsert { policy, .. } => ("policy", policy.id.as_str()),
        crate::policy_guard::Mutation::AgentUpsert { agent } => ("agent", agent.id.as_str()),
        _ => ("row", ""),
    }
}

/// Applies a mutation a device signed for. A grant, policy or agent upsert is applied only while the live row is still the one it was asked against: confirming a whole-row edit held before a later tightening would otherwise undo that tightening.
/// Whether the row a held change edits is no longer the one it was asked against, or it binds none it should. The apply
/// refuses such a change and records why ([`apply_held_mutation`]), so the confirm leaves it to that refusal.
pub(crate) fn held_row_moved(
    store: &dyn Store,
    m: &crate::policy_guard::Mutation,
    params: &permaura_core::JsonText,
) -> Result<bool, GatewayError> {
    let Some(found) = held_row_digest(store, m)? else { return Ok(false) };
    Ok(permaura_core::json_stream::string_at(params, &format!("/{HELD_BASE_KEY}")).as_deref() != Some(found.as_str()))
}

pub(crate) fn apply_held_mutation(
    store: &dyn Store,
    service: &crate::service::EnforcementService,
    m: &crate::policy_guard::Mutation,
    params: &permaura_core::JsonText,
) -> Result<serde_json::Value, GatewayError> {
    if held_row_digest(store, m)?.is_none() {
        return apply_mutation(store, service, m);
    }
    let (kind, id) = held_row_target(m);
    let Some(expected) = permaura_core::json_stream::string_at(params, &format!("/{HELD_BASE_KEY}")) else {
        let mut payload = permaura_core::AuditPayload::new(POLICY_WRITE_CAP, crate::store::CONTROL_PLANE_RESOURCE, "deny");
        payload.summary = json!({
            "reason": "the change was held by an earlier gateway version that did not bind the row it was asked against; it was refused",
            "kind": kind,
            "id": id,
        });
        store.append_audit(payload)?;
        return Err(GatewayError::Conflict(format!(
            "this change to {kind} '{id}' was held before this version of the gateway, so it was not applied; ask for it again."
        )));
    };
    apply_mutation_against(store, service, m, AUTHORITY_DEVICE_COSIGNED, serde_json::Map::new(), Some(&expected))
}

/// Inside the unit of work that applies `m`: refuse when the row is no longer the one the hold was asked against, noting what was found for the audit record written after the rollback.
fn refuse_a_stale_held_row(
    store: &dyn Store,
    m: &crate::policy_guard::Mutation,
    expected_base: Option<&str>,
    stale_base: &mut Option<String>,
) -> Result<(), GatewayError> {
    let Some(expected) = expected_base else { return Ok(()) };
    let found = held_row_digest(store, m)?.unwrap_or_default();
    if found == expected {
        return Ok(());
    }
    let (kind, id) = held_row_target(m);
    *stale_base = Some(found);
    Err(GatewayError::Conflict(format!(
        "{kind} '{id}' changed after this edit was held, so confirming it would undo that change; it was not applied. Ask for the edit again against the {kind} as it is now."
    )))
}

fn apply_mutation_against(
    store: &dyn Store,
    service: &crate::service::EnforcementService,
    m: &crate::policy_guard::Mutation,
    authority: &str,
    detail: serde_json::Map<String, serde_json::Value>,
    expected_base: Option<&str>,
) -> Result<serde_json::Value, GatewayError> {
    let mut detail = Some(detail);
    let mut applied = serde_json::Value::Null;
    store.change_with_record(&mut || {
        applied = apply_and_record(store, service, m, authority, detail.take().unwrap_or_default(), expected_base)?;
        Ok(())
    })?;
    Ok(applied)
}

/// [`apply_mutation_against`]'s body: the change, then the records written after its unit of work.
fn apply_and_record(
    store: &dyn Store,
    service: &crate::service::EnforcementService,
    m: &crate::policy_guard::Mutation,
    authority: &str,
    detail: serde_json::Map<String, serde_json::Value>,
    expected_base: Option<&str>,
) -> Result<serde_json::Value, GatewayError> {
    use crate::policy_guard::{BrokerToggleKind, Mutation};
    // Before the change, so a rule above one that it takes out of force leaves its mark behind.
    if notes_quorum_marks(m) {
        service.note_quorum_marks()?;
    }
    refuse_a_changed_staged_credential(store, m)?;
    refuse_a_first_credential_over_the_allowance(store, service, m)?;
    let mut trust_record: Option<TrustRecord> = None;
    let mut floor_change: Option<(Option<crate::service::ApprovalFloor>, Option<crate::service::ApprovalFloor>)> = None;
    let mut gate_change: Option<(bool, bool, bool)> = None;
    let detail_for_floor = detail.clone();
    let mut stale_base: Option<String> = None;
    // Every arm is one unit of work, so a cascade that fails part-way (a policy detached from its
    // grants but not deleted, an agent gone with its grants still covering it) cannot be left behind,
    // and a snapshotting store uploads once per mutation rather than once per row.
    let out = store.transaction(|store| match m {
        Mutation::PolicyUpsert { policy, grant_ids } => {
            refuse_a_stale_held_row(store, m, expected_base, &mut stale_base)?;
            store.put_policy(policy.clone())?;
            if let Some(ids) = grant_ids {
                sync_policy_grants(store, &policy.id, ids)?;
            }
            Ok(json!({ "policy_id": policy.id }))
        }
        Mutation::PolicyDelete { policy_id } => {
            detach_policy_from_grants(store, policy_id)?;
            store.delete_policy(policy_id)?;
            Ok(json!({ "policy_id": policy_id, "deleted": true }))
        }
        Mutation::GrantUpsert { grant } => {
            refuse_a_stale_held_row(store, m, expected_base, &mut stale_base)?;
            validate_policies(store, &grant.policy_ids)?;
            let made_default = grant.is_default;
            let grant_id = grant.grant_id.clone();
            // Upsert by id: replace in place if it exists (put_grant only appends), else insert.
            if !store.update_grant(grant.clone())? {
                store.put_grant(grant.clone())?;
            }
            if made_default {
                make_sole_default(store, &grant_id)?;
            }
            Ok(json!({ "grant_id": grant_id }))
        }
        // The cascade lives HERE rather than in the handler, and that placement is the whole point:
        // a held mutation is replayed through `apply_mutation` when the device signs, so any effect
        // left behind in the handler would simply not happen on the approved path. Moving it was the
        // prerequisite for holding this delete at all.
        Mutation::SecretDelete { secret_id } => {
            let sealed = store.delete_secret(secret_id)?;
            let wrapped = kms_wrapped(store, secret_id)? && store.delete_secret_custody(secret_id)?;
            if !sealed && !wrapped {
                return Err(GatewayError::NotFound(format!("secret '{secret_id}'")));
            }
            service.note_credential_change(secret_id);
            Ok(json!({ "secret_id": secret_id, "deleted": true }))
        }
        // Same reason the connection cascade lives here: a held mutation is replayed through this
        // function on the approved path, so an effect left in the handler would not happen when the
        // device signs. Deleting the agent and leaving its grants covering nobody would be worse than
        // not holding at all.
        Mutation::AgentDelete { agent_id } => {
            if !store.delete_agent(agent_id)? {
                return Err(GatewayError::NotFound(format!("agent '{agent_id}'")));
            }
            for sess in store.list_sessions()? {
                if sess.agent_id == *agent_id && !sess.revoked {
                    store.revoke_session(&sess.id)?;
                }
            }
            if agent_id.starts_with("oauth:")
                && store.get_session(&crate::service::oauth_session_id(agent_id))?.is_none()
            {
                store.put_session(crate::service::oauth_tombstone(agent_id))?;
            }
            // Remove the agent from every grant that names it. A specific-agents grant left covering
            // nobody (and not the Default) is deleted, preserving the property that a re-registered
            // agent never silently inherits a grant the operator believed they had destroyed.
            for mut g in store.list_grants()? {
                if let GrantAgents::Agents(members) = &g.agents {
                    if members.iter().any(|m| m.agent_id == *agent_id) {
                        let remaining: Vec<GrantAgent> =
                            members.iter().filter(|m| m.agent_id != *agent_id).cloned().collect();
                        if remaining.is_empty() && !g.is_default {
                            store.delete_grant(&g.grant_id)?;
                        } else {
                            g.agents = GrantAgents::Agents(remaining);
                            store.update_grant(g)?;
                        }
                    }
                }
            }
            // Removing an agent is a decision too, and it leaves nothing to fetch: a notice that outlived the row it
            // points at is a doorbell for a door that is gone. Announced here so a held delete clears it as well.
            service.announce_agent_resolved(agent_id);
            Ok(json!({ "agent_id": agent_id, "deleted": true }))
        }
        Mutation::ConnectionDelete { connection_id } => {
            let connection = store
                .get_connection(connection_id)?
                .ok_or_else(|| GatewayError::NotFound(format!("connection '{connection_id}'")))?;
            // Detach this connection's policies from every grant → delete the policies →
            // capabilities → secret → the connection itself. (A grant bundles policies across
            // connections, so we detach rather than delete the grant; a grant left empty is inert.)
            let policies = store.policies_for_connection(connection_id)?;
            for p in &policies {
                detach_policy_from_grants(store, &p.id)?;
            }
            for p in policies {
                store.delete_policy(&p.id)?;
            }
            // Remove this connection's capabilities from the catalog so stale entries can't linger.
            for cap_id in &connection.capabilities {
                store.delete_capability(cap_id)?;
            }
            // Delete the credential ONLY if nothing else still references the same secret id:
            // another connection, or a still-registered capability (the seeded generic
            // `http.request` shares `sec_github_acme`, so deleting the GitHub connection must not
            // yank it out from under it).
            let mut released = false;
            if !connection.secret_id.is_empty() {
                let referenced_by_connection = store
                    .list_connections()?
                    .iter()
                    .any(|c| c.id != connection.id && c.secret_id == connection.secret_id);
                let referenced_by_capability = store
                    .list_capabilities()?
                    .iter()
                    .any(|c| c.secret_id == connection.secret_id);
                if !referenced_by_connection && !referenced_by_capability {
                    store.delete_secret(&connection.secret_id)?;
                    if kms_wrapped(store, &connection.secret_id)? {
                        store.delete_secret_custody(&connection.secret_id)?;
                    }
                    released = true;
                }
            }
            store.delete_connection(connection_id)?;
            service.note_connection_removed(connection_id);
            if released {
                service.note_credential_change(&connection.secret_id);
            }
            Ok(json!({ "connection_id": connection_id, "deleted": true }))
        }
        Mutation::GrantDelete { grant_id } => {
            // A held delete is applied later, by which time the grant may have been made the Default.
            if store.get_grant(grant_id)?.is_some_and(|g| g.is_default) {
                return Err(GatewayError::BadRequest(DEFAULT_GRANT_UNDELETABLE.into()));
            }
            store.delete_grant(grant_id)?;
            Ok(json!({ "grant_id": grant_id, "deleted": true }))
        }
        Mutation::CapabilityEnable { connection_id, capability } => {
            let mut connection = store
                .get_connection(connection_id)?
                .ok_or_else(|| GatewayError::NotFound(format!("connection '{connection_id}'")))?;
            connection.disabled_capabilities.retain(|c| c != capability);
            store.put_connection(connection)?;
            Ok(json!({ "connection_id": connection_id, "capability": capability, "enabled": true }))
        }
        Mutation::ConnectionPatch { connection_id, patch } => {
            apply_connection_patch(store, connection_id, patch, service.memory().capability_bytes())
        }
        Mutation::AgentApprove { agent_id } => {
            let mut agent = store
                .get_agent(agent_id)?
                .ok_or_else(|| GatewayError::NotFound(format!("agent '{agent_id}'")))?;
            agent.status = AgentStatus::Approved;
            store.put_agent(agent)?;
            // Here rather than in the handler, so a held approve applied through its own approval also clears the
            // "new agent is waiting" notice; left in the handler alone, hosted gateways never closed it.
            service.announce_agent_resolved(agent_id);
            Ok(json!({ "agent_id": agent_id, "status": "approved" }))
        }
        Mutation::AgentUpsert { agent } => {
            refuse_a_stale_held_row(store, m, expected_base, &mut stale_base)?;
            store.put_agent(agent.clone())?;
            Ok(json!({ "agent_id": agent.id }))
        }
        Mutation::CredentialPromote { connection_id, secret_id, staging_secret_id, staged_sha256 } => {
            crate::secret_inventory::refuse_staging_secret_id("secret", secret_id)?;
            if staged_sha256.is_empty() {
                return Err(held_without_a_digest(connection_id));
            }
            let staged = store
                .get_secret(staging_secret_id)?
                .ok_or_else(|| GatewayError::NotFound(format!("staged secret '{staging_secret_id}'")))?;
            if crate::secret_inventory::staged_digest(&staged.sealed) != *staged_sha256 {
                return Err(staged_credential_changed(staging_secret_id, connection_id));
            }
            // Preserve the live secret's metadata (labels/rotation) if it already existed, else adopt
            // the staged record's. The sealed bytes are the ones the device signed a digest of.
            let _publish = service.lock_secret_publication();
            let live = store.get_secret(secret_id)?;
            if live.is_none() {
                service
                    .refuse_if_over_allowance_unrecorded(crate::allowances::Allowance::Secrets)
                    .map_err(|e| first_credential_refusal(connection_id, e))?;
            }
            let metadata = live.map(|s| s.metadata).unwrap_or_else(|| staged.metadata.clone());
            store.put_secret(SecretRecord { id: secret_id.clone(), sealed: staged.sealed, metadata })?;
            service.note_credential_change(secret_id);
            store.delete_secret(staging_secret_id)?;
            Ok(json!({ "connection_id": connection_id, "rotated": true }))
        }
        Mutation::BrokerToggle { toggle, value } => {
            // The service owns both switches and records them in the store, inside this unit. Reached
            // either immediately (loopback / no device enrolled / engaging direction) or on a
            // device-signed resolution of a held release.
            match toggle {
                BrokerToggleKind::Pause => {
                    service.set_paused(*value)?;
                    Ok(json!({ "paused": *value }))
                }
                BrokerToggleKind::RequireAgentApproval => {
                    service.set_require_agent_approval(*value)?;
                    Ok(json!({ "require_agent_approval": *value }))
                }
            }
        }
        // The ONE writer for the approver keyring. The immediate first-device path
        // ([`apply_or_hold_pairing`]) and a co-signed resolution both land here, so a held enrolment
        // trusts exactly the key an immediate one would and neither can drift from the other.
        Mutation::ApproverKeyTrust { approver_id, approver_pubkey, person, replaces } => {
            let first_device = !service.any_device_trusted();
            let gate_before = service.require_agent_approval();
            // The durable variant, not the best-effort one: on a hosted worker the store IS the
            // keyring, so a pairing that failed to persist is forgotten by the next refresh and by
            // the next cold start while the tenant has been told their phone is enrolled and now
            // believes approvals require it. Surfacing the failure lets them retry a pairing that
            // would otherwise evaporate silently.
            if !service.trust_approver_key_replacing(approver_id, approver_pubkey, person.as_deref(), replaces.as_deref())? {
                return Err(GatewayError::Denied("malformed approver public key".into()));
            }
            let cleared = first_device && service.clear_unanchored_agent_gate_off()?;
            gate_change = Some((gate_before, service.require_agent_approval(), cleared))
                .filter(|(from, to, cleared)| from != to || *cleared);
            // The moment the first device is trusted is the moment the export and delete holds arm,
            // and the moment the owner needs a way back that is not the bearer. Hosted issues none:
            // its recovery authority is the permaura.com ticket.
            let recovery_codes = if first_device && !crate::recovery::hosted() {
                Some(crate::recovery::issue(store, now_ms())?)
            } else {
                None
            };
            // An opt-down written while no device was trusted was confirmed by no device holder, and
            // inherited it would leave every device hold disarmed from this pairing on with nothing to
            // say so. Cleared as recovery codes are when the keyring empties.
            if first_device && crate::recovery::hosted() && service.opt_down_unanchored()? {
                let stored = service.stored_approval_floor();
                if stored == Some(crate::service::ApprovalFloor::Approve) {
                    service.set_approval_floor(None)?;
                    floor_change = Some((stored, None));
                }
                service.set_opt_down_unanchored(false)?;
            }
            let mut detail = detail;
            detail.insert("person".into(), json!(person));
            trust_record = Some(TrustRecord {
                decision: "allow",
                approver_id: approver_id.clone(),
                pubkey: Some(approver_pubkey.clone()),
                detail: serde_json::Value::Object(detail),
            });
            // `key_fp` is echoed so the broker can name the exact key in the owner's notification
            // without decoding the ticket it forwarded: an unverified decode there would make the
            // one artefact that lets an owner recognise an enrolment they did not perform depend on
            // a claim nothing on that side checked.
            let floor = service.approval_floor();
            let mut out = json!({
                "approver_id": approver_id,
                "trusted": true,
                "key_fp": crate::service::key_fingerprint(approver_pubkey),
                // What the gateway will do with approvals now this key is trusted, and whether the
                // caller is the one who gets to decide. Enrolment used to answer this by itself, so
                // there was nothing to report; now that the policy decides by default, the client
                // that just paired is the only surface positioned to offer the blanket alternative:
                // it has the operator's attention, at the one moment the question makes sense.
                //
                // `offer_raise` rather than the client inferring it from `first_device`: a second
                // device paired onto a gateway whose floor was already raised must not be asked
                // again, and a client that worked that out for itself would be re-deriving a rule
                // that lives here.
                "approval_floor": floor.as_str(),
                "first_device": first_device,
                "offer_raise": floor != crate::service::ApprovalFloor::DeviceSigned,
                // Whether this key counts as a person toward a two-person rule. A key bound to nobody
                // can satisfy a single-signature rule and is never the second person.
                "person_bound": service.approver_keyring_snapshot().person(approver_id).is_some(),
                // The audience the device pins for this gateway, handed over at the one moment the
                // device knows for certain which gateway it is talking to.
                "approval_audience": service.served_approval_audience(),
            });
            if let Some(codes) = recovery_codes {
                out["recovery_codes"] = json!(codes);
            }
            Ok(out)
        }
        Mutation::ApproverKeyRevoke { approver_id } => {
            let revoked_key = service.trusted_approver_key(approver_id);
            let gate_before = service.require_agent_approval();
            service.revoke_approver_key(approver_id)?;
            gate_change = Some((gate_before, service.require_agent_approval(), false)).filter(|(from, to, _)| from != to);
            let emptied = !service.any_device_trusted();
            if emptied {
                crate::recovery::clear(store)?;
            }
            let mut detail = detail;
            detail.insert("revoked".into(), json!(true));
            detail.insert("emptied_keyring".into(), json!(emptied));
            trust_record = Some(TrustRecord {
                decision: "deny",
                approver_id: approver_id.clone(),
                pubkey: revoked_key,
                detail: serde_json::Value::Object(detail),
            });
            Ok(json!({ "approver_id": approver_id, "trusted": false, "emptied_keyring": emptied }))
        }
        Mutation::ApprovalFloorSet { floor } => {
            // Re-parse rather than trust the held string. A value THIS build cannot parse must never
            // degrade to `None`, because `None` means "clear the override", which on a gateway with
            // a device enrolled lowers nothing but on one without a device re-opens bearer
            // resolution. A hold written by a future build naming a floor this one does not know is
            // refused at resolution instead of being guessed at.
            let target = match floor.as_deref() {
                None => None,
                Some(raw) => Some(crate::service::ApprovalFloor::from_str(raw).ok_or_else(|| {
                    GatewayError::BadRequest(format!("unknown approval floor '{raw}'"))
                })?),
            };
            // Propagated, not logged: a floor change the store refused reverts within
            // `KEYRING_REFRESH_MS`, so answering success would tell a signer their held opt-down
            // landed moments before it silently undid itself.
            let before = service.stored_approval_floor();
            service.set_approval_floor(target)?;
            service.set_opt_down_unanchored(
                target == Some(crate::service::ApprovalFloor::Approve) && !service.any_device_trusted(),
            )?;
            let effective = service.approval_floor();
            floor_change = Some((before, target));
            Ok(json!({
                "approval_floor": effective.as_str(),
                "signed_approvals_required": effective == crate::service::ApprovalFloor::DeviceSigned,
                "approval_floor_override": target.map(crate::service::ApprovalFloor::as_str),
                "approvals_opted_down": target == Some(crate::service::ApprovalFloor::Approve),
            }))
        }
        Mutation::ConnectorInstall { manifest, version, provenance } => {
            let preset: crate::presets::Preset = serde_json::from_value(manifest.clone())
                .map_err(|e| GatewayError::BadRequest(format!("invalid manifest: {e}")))?;
            // Again here, so a held install cannot land over a newer version, or a signed one, installed since it was asked for.
            if let Some(existing) = store.get_connector_manifest(&preset.id)? {
                refuse_unsigned_over_signed(&preset.id, provenance, &existing)?;
                if *version <= existing.version {
                    return Err(GatewayError::BadRequest(format!(
                        "version {version} is not newer than the installed version {}",
                        existing.version
                    )));
                }
                refuse_unseating_a_revoked_connector(store, service, &preset.id)?;
            }
            let mut out = installed_connector_json(&preset, *version, provenance);
            // Read from the manifest the change carries, which is what the hold described and the device signed over.
            let endpoint_hosts = preset.endpoint_hosts();
            let installed = crate::manifest::InstalledManifest {
                manifest: preset,
                version: *version,
                provenance: provenance.clone(),
                installed_at: now_ms(),
                endpoint_hosts,
            };
            store.put_connector_manifest(installed.clone())?;
            // A vault imported before this signed manifest held its lines to their shape; they return to what Permaura vouches for.
            // Recorded with the install itself, which the audit record of this change carries as `restored`.
            let restored = crate::posture_floor::restore_vouched(store, &installed.preset())?;
            out["restored"] = json!(restored.iter().map(|m| m.capability.as_str()).collect::<Vec<_>>());
            Ok(out)
        }
        Mutation::CapabilityPosture { connection_id, capability, risk, requires_approval, from } => {
            apply_capability_posture(store, connection_id, capability, *risk, *requires_approval, from)
        }
        Mutation::ConnectorRemove { connector_id } => {
            refuse_unseating_a_revoked_connector(store, service, connector_id)?;
            if !store.delete_connector_manifest(connector_id)? {
                return Err(GatewayError::NotFound(format!("installed connector '{connector_id}'")));
            }
            Ok(json!({ "removed": true, "id": connector_id, "connector_id": connector_id }))
        }
    });
    // After the rollback, because the chain append cannot run inside a unit of work.
    if let (Some(found), Some(expected)) = (stale_base, expected_base) {
        let (kind, id) = held_row_target(m);
        let mut payload = permaura_core::AuditPayload::new(POLICY_WRITE_CAP, crate::store::CONTROL_PLANE_RESOURCE, "deny");
        payload.summary = json!({
            "reason": "the row changed after this edit was held; confirming it would have undone that change, so it was refused",
            "kind": kind,
            "id": id,
            "expected_sha256": expected,
            "found_sha256": found,
        });
        store.append_audit(payload)?;
    }
    let out = out?;
    if matches!(m, Mutation::SecretDelete { .. } | Mutation::ConnectionDelete { .. }) {
        service.forget_rotations_of_deleted_secrets();
    }
    // After the commit, so the chain records a trust change that actually landed. Propagated rather
    // than logged: enrolling a device is what arms the whole human-approval gate, and an enrolment
    // nobody can review afterwards is worse than one that asks to be retried. Both writes are
    // idempotent, so a caller that retries on this error re-records rather than enrolling twice.
    if let Some(record) = trust_record {
        service.audit_approver_pairing(
            record.decision,
            &record.approver_id,
            record.pubkey.as_deref(),
            authority,
            record.detail,
        )?;
    }
    if let Some((from, to)) = floor_change {
        let mut detail = detail_for_floor;
        if matches!(m, Mutation::ApproverKeyTrust { .. }) {
            detail.insert(
                "reason".into(),
                json!("an opt-down written while no device was trusted does not survive the first device paired"),
            );
        }
        service.audit_approval_floor(from, to, authority, detail)?;
    }
    if let Some((from, to, cleared)) = gate_change {
        service.audit_agent_gate_default(from, to, cleared, authority)?;
    }
    Ok(out)
}

/// The refusal for a `credential_promote` whose staged row is not the one the device signed for.
fn staged_credential_changed(staging_secret_id: &str, connection_id: &str) -> GatewayError {
    GatewayError::Conflict(format!(
        "the staged credential '{staging_secret_id}' is not the one this approval was held for, so it was not saved for '{connection_id}': something rewrote it after the hold. Ask for the credential change again."
    ))
}

/// The refusal for a `credential_promote` an earlier build parked without a digest of the staged bytes: nothing can show the staged row is the one the device signed for, and nothing suggests it is not.
fn held_without_a_digest(connection_id: &str) -> GatewayError {
    GatewayError::Conflict(format!(
        "this credential change for '{connection_id}' was held before this version of the gateway, so it was not saved; ask for it again."
    ))
}

/// Refuse, and record, a `credential_promote` whose staged envelope no longer hashes to what its hold signed over, or that an earlier build held without a digest at all. Outside the mutation's own transaction because the chain append cannot run inside one, and before it so a refusal writes nothing.
fn refuse_a_changed_staged_credential(store: &dyn Store, m: &crate::policy_guard::Mutation) -> Result<(), GatewayError> {
    let crate::policy_guard::Mutation::CredentialPromote { connection_id, secret_id, staging_secret_id, staged_sha256 } = m else {
        return Ok(());
    };
    let mut payload = permaura_core::AuditPayload::new(SECRET_WRITE_ACTION, VAULT_RESOURCE, "deny");
    if staged_sha256.is_empty() {
        payload.summary = json!({
            "reason": "the change was held by an earlier gateway version that did not bind the staged credential's digest; the promotion was refused",
            "connection_id": connection_id,
            "secret_id": secret_id,
            "staging_secret_id": staging_secret_id,
        });
        store.append_audit(payload)?;
        return Err(held_without_a_digest(connection_id));
    }
    let Some(staged) = store.get_secret(staging_secret_id)? else { return Ok(()) };
    let found = crate::secret_inventory::staged_digest(&staged.sealed);
    if found == *staged_sha256 {
        return Ok(());
    }
    payload.summary = json!({
        "reason": "the staged credential changed after its hold was signed over; the promotion was refused",
        "connection_id": connection_id,
        "secret_id": secret_id,
        "staging_secret_id": staging_secret_id,
        "expected_sha256": staged_sha256,
        "found_sha256": found,
    });
    store.append_audit(payload)?;
    Err(staged_credential_changed(staging_secret_id, connection_id))
}

/// Refuse a `credential_promote` that would add a secret past the Secrets allowance. Staged rows are not charged, so several first credentials held while one slot was free would each promote; the count is taken again here, outside the mutation's transaction for the reason [`refuse_a_changed_staged_credential`] is.
fn refuse_a_first_credential_over_the_allowance(
    store: &dyn Store,
    service: &crate::service::EnforcementService,
    m: &crate::policy_guard::Mutation,
) -> Result<(), GatewayError> {
    let crate::policy_guard::Mutation::CredentialPromote { connection_id, secret_id, .. } = m else {
        return Ok(());
    };
    if store.get_secret(secret_id)?.is_some() {
        return Ok(());
    }
    service
        .refuse_if_over_allowance(crate::allowances::Allowance::Secrets, None)
        .map_err(|e| first_credential_refusal(connection_id, e))
}

/// An allowance refusal of an approved first credential, worded for the signer who approved it.
fn first_credential_refusal(connection_id: &str, e: GatewayError) -> GatewayError {
    match e {
        GatewayError::AllowanceExceeded { allowance, current, limit, message } => GatewayError::AllowanceExceeded {
            allowance,
            current,
            limit,
            message: format!("the credential for '{connection_id}' was approved but not saved: {message}, then ask for the change again"),
        },
        other => other,
    }
}

/// Release any resource a held mutation reserved but never applied: when it is denied, expires, or is approved and
/// then fails to apply, which spends its claim so nothing can apply it later. Today only a
/// [`crate::policy_guard::Mutation::CredentialPromote`] parks a sealed staging secret; deleting it keeps a credential
/// change that will never land from orphaning a blob no route may remove. Best-effort.
pub(crate) fn cleanup_denied_mutation(store: &dyn Store, m: &crate::policy_guard::Mutation) {
    if let crate::policy_guard::Mutation::CredentialPromote { staging_secret_id, .. } = m {
        // A row 1.3.46 parked sits where connection slots are derived, so a connection may have bound it since, and then it is that connection's credential.
        if matches!(secret_backing_ref(store, staging_secret_id), Ok(None)) {
            let _ = store.delete_secret(staging_secret_id);
        }
    }
}

/// Apply a held/immediate [`crate::policy_guard::ConnPatch`] to a connection: the SSH-target edits
/// (via [`apply_ssh_target_patch`]) and the kill-switch/label/name. The single writer for both the
/// immediate path and a signed-then-applied hold, so a signed connection change lands identically.
fn apply_connection_patch(
    store: &dyn Store,
    connection_id: &str,
    patch: &crate::policy_guard::ConnPatch,
    capability_bytes: u64,
) -> Result<serde_json::Value, GatewayError> {
    let mut connection = store
        .get_connection(connection_id)?
        .ok_or_else(|| GatewayError::NotFound(format!("connection '{connection_id}'")))?;
    if let Some(ssh) = &patch.ssh {
        let sp = SshTargetPatch {
            host: ssh.host.clone(),
            port: ssh.port,
            user: ssh.user.clone(),
            host_key_sha256: ssh.host_key_sha256.clone(),
            insecure: ssh.insecure,
            password_auth: ssh.password_auth,
        };
        let rewritten = apply_ssh_target_patch(store, &connection, &sp, capability_bytes)?;
        if rewritten == 0 {
            return Err(GatewayError::BadRequest(
                "this SSH connection has no capabilities to update".into(),
            ));
        }
    }
    if let Some(disabled) = patch.disabled {
        connection.disabled = disabled;
    }
    // label/name were trimmed + validated non-empty by the handler before the hold, so apply them
    // as-is here (the held ConnPatch carries clean values).
    if let Some(label) = &patch.label {
        connection.label = label.clone();
    }
    if let Some(name) = &patch.name {
        connection.name = name.clone();
    }
    let (disabled, label, name) =
        (connection.disabled, connection.label.clone(), connection.name.clone());
    store.put_connection(connection)?;
    Ok(json!({ "connection_id": connection_id, "disabled": disabled, "label": label, "name": name }))
}

/// The note on a control-plane change held because it arrived from off this gateway's machine, when the hold names nobody as having asked: the case only a device of the gateway's owner can confirm.
pub const HELD_REMOTE_NOTE: &str = "Approve only if you made this change. It came through your Permaura account, so a paired device has to confirm it.";

/// The note on a control-plane change held because it arrived from off this gateway's machine, when the hold records who asked: step 10a refuses the requester's own device while a device more provably someone else's is trusted, and never the owner's. The phone mirrors this text and keys on the opening words.
pub const HELD_REQUESTED_NOTE: &str = "Approve only if you know who asked for this change and agree with it. Unless they are the gateway's owner, the person who asked cannot confirm it from their own device while a device paired to someone else is trusted.";

/// The note on a remote hold, by whether it records who asked.
fn held_remote_note(requester: &Option<crate::store::HoldRequester>) -> &'static str {
    if requester.is_some() {
        HELD_REQUESTED_NOTE
    } else {
        HELD_REMOTE_NOTE
    }
}

/// The note on a destructive change held although it came from this gateway's own machine.
pub const HELD_DESTRUCTIVE_NOTE: &str = "Approve only if you made this change. It deletes something only a backup can bring back, so a paired device has to confirm it.";

/// The note on a loopback change that would send an existing credential somewhere new.
pub const HELD_RETARGET_NOTE: &str = "Approve only if you made this change. It changes where a stored credential is sent or how it is presented, so a paired device has to confirm it.";

/// The note on a device pairing held for a co-signature.
pub const HELD_PAIRING_NOTE: &str = "Approve only if you are pairing this device yourself. A device you already trust has to confirm it.";

/// The note on a device pairing held for a co-signature when the hold records who is pairing: the same rule as [`HELD_REQUESTED_NOTE`], in a pairing's words. The phone mirrors this text and keys on the opening words.
pub const HELD_PAIRING_REQUESTED_NOTE: &str = "Approve only if you know who is pairing this device and agree with it. Unless they are the gateway's owner, the person pairing it cannot confirm it from their own device while a device paired to someone else is trusted.";

/// The note on removing a device, asked for by someone other than the gateway's owner, that is not provably theirs.
pub const HELD_OTHERS_DEVICE_NOTE: &str = "Approve only if this device should stop approving. Someone other than the gateway's owner asked to remove it, and it is not shown to be theirs, so a device of somebody else has to confirm it.";

/// The note on any other trust-root change held for a co-signature: lowering the approval floor, or
/// removing the last trusted device.
pub const HELD_TRUST_NOTE: &str = "Approve only if you made this change. It changes what approvals need, so a device you already trust has to confirm it.";

/// [`HELD_TRUST_NOTE`] for a hold that records who asked: the same rule as [`HELD_REQUESTED_NOTE`]. The phone mirrors this text and keys on the opening words.
pub const HELD_TRUST_REQUESTED_NOTE: &str = "Approve only if you know who asked for this change and agree with it. It changes what approvals need, so a device you already trust has to confirm it. Unless they are the gateway's owner, the person who asked cannot confirm it from their own device while a device paired to someone else is trusted.";

fn trust_root_note(m: &crate::policy_guard::Mutation, requester: &Option<crate::store::HoldRequester>) -> &'static str {
    match m {
        crate::policy_guard::Mutation::ApproverKeyTrust { .. } if requester.is_some() => HELD_PAIRING_REQUESTED_NOTE,
        crate::policy_guard::Mutation::ApproverKeyTrust { .. } => HELD_PAIRING_NOTE,
        _ if requester.is_some() => HELD_TRUST_REQUESTED_NOTE,
        _ => HELD_TRUST_NOTE,
    }
}

/// The `202` body every held control-plane mutation answers with. Shared so the three producers
/// (the generic guard, the trust-root guard and the credential hold) cannot drift.
///
/// `expires_at` is the part worth naming: a held control-plane change lapses a day after it was held
/// ([`crate::store::CONTROL_PLANE_HOLD_TTL_MS`]), and this is that deadline. It is never omitted: a
/// client has to be able to tell "this hold has no deadline" from "this gateway did not tell me", and
/// one that reads a missing field as zero renders a deadline in 1970.
///
/// The text fields are the served ones, escaped exactly as [`approval_json`] serves them, so the caller
/// is shown the same title and note a device is shown and signs over.
fn held_body(approval: &PendingApproval) -> serde_json::Value {
    let text = crate::approval_display::ServedText::of(approval);
    json!({
        "approval_id": approval.id,
        "status": "requires_approval",
        "required_tier": "device_signed",
        "required_signatures": approval.required_signatures,
        "message": text.message,
        // What the gateway actually did, not what a reader would like it to mean. A push goes to
        // every non-revoked entry in the registry that HAS a token, and Expo may still drop it; a
        // trusted key with no push entry, an Apple Watch, or a phone that declined notifications gets
        // nothing. Saying "every paired device has been told" made a best-effort fan-out sound like a
        // guarantee, and a recovery path was once built on believing it.
        "notified": "Notified where a push token is registered. Delivery is best effort and some \
                     trusted devices have no push entry at all, so this is not a guarantee that \
                     anyone has seen it.",
        // Read off the row, so the 202 and the queue row for the same approval can never disagree
        // about when it ends: the desktop card counts down to this.
        "expires_at": approval.deadline(),
        "risk": text.risk,
        "action_description": text.action_description,
    })
}

/// The result of routing a control-plane mutation through [`apply_or_hold`].
pub(crate) enum Guarded {
    /// Held for a `device_signed` approval; the caller returns this 202 verbatim.
    Held(StatusCode, serde_json::Value),
    /// Applied immediately because nothing required a hold; the caller shapes its own success
    /// response.
    Applied(serde_json::Value),
}

/// The funnel most mutating control-plane handlers route through. Under the control-plane lock (so
/// the classifier's store snapshot cannot shift before the apply) it HOLDS the mutation as a
/// `device_signed` approval when it is destructive or moves a stored credential and a device is
/// trusted with approvals not opted down, wherever it arrived from. It also holds when the request
/// came from off the host while
/// [`crate::service::EnforcementService::control_plane_hold_required`] is true and the mutation is
/// not strictly tightening (per [`crate::policy_guard`]). Otherwise it is applied immediately and
/// recorded.
async fn apply_or_hold(
    state: &AppState,
    remote: bool,
    op: &Session,
    mutation: &crate::policy_guard::Mutation,
) -> Result<Guarded, GatewayError> {
    let _cp = state.service.control_plane_mutex().lock().await;
    if moves_a_credential(mutation) {
        refuse_a_credential_move(
            state,
            op,
            remote,
            "this edit would change where an SSH connection's stored credential is sent, or how it is presented",
        )?;
    }
    if matches!(mutation, crate::policy_guard::Mutation::ConnectorInstall { .. }) {
        const WHAT: &str = "installing a connector decides where the credential of every connection made from it is sent";
        if unpaired_remote_self_run(state, remote) {
            return Err(unpaired_remote_refusal(WHAT));
        }
        if state.hosted && !state.service.any_device_trusted() {
            return Err(unpaired_hosted_refusal(WHAT));
        }
    }
    let store = state.service.store();
    let policies = store.list_policies()?;
    let grants = store.list_grants()?;
    let connections = store.list_connections()?;
    let agents = store.list_agents()?;
    // Two independent reasons to hold, and they gate differently on purpose.
    //
    // A DESTRUCTIVE mutation holds wherever it arrived from, exactly like a vault export and for the
    // same reason: `control_plane_hold_required` starts with `remote &&`, trusting loopback because
    // whoever reaches it is assumed to be the owner at the host, and an agent running as the owner IS
    // loopback. It also skips the tightening test, which would otherwise exempt every delete: that
    // test asks whether a change can grant more access, and a delete never can, which says nothing
    // about the configuration it destroys on the way.
    let destructive = crate::policy_guard::is_destructive(
        mutation,
        &crate::policy_guard::GuardContext { policies: &policies, grants: &grants, connections: &connections, agents: &agents },
    );
    let destructive_hold = destructive && state.service.vault_export_hold_required();
    // Moving where an existing credential goes, or how it is presented, holds on the same terms: the
    // next call would hand the stored secret to whatever host the bearer chose.
    let retarget_hold = moves_a_credential(mutation) && state.service.vault_export_hold_required();
    let must_hold = destructive_hold
        || retarget_hold
        || state.service.control_plane_hold_required(remote) && !{
            // The classification resolves the estate at every moment a grant can change it, so it runs off the runtime's
            // workers, still under the control-plane lock this call holds.
            let mutation = mutation.clone();
            let (policies, grants) = (policies.clone(), grants.clone());
            state.service.classify(move || {
                let ctx = crate::policy_guard::GuardContext {
                    policies: &policies,
                    grants: &grants,
                    connections: &connections,
                    agents: &agents,
                };
                crate::policy_guard::is_strictly_tightening(&mutation, &ctx)
            })
            .await?
        };
    if !must_hold {
        if notes_quorum_marks(mutation) {
            state.service.prepare_quorum_marks(policies, grants).await?;
        }
        let title = state.service.describe_mutation(mutation);
        let mut applied = serde_json::Value::Null;
        store.change_with_record(&mut || {
            applied = apply_mutation(store.as_ref(), state.service.as_ref(), mutation)?;
            state.service.audit_applied_mutation(POLICY_WRITE_CAP, mutation, &title, &applied, op, remote)
        })?;
        return Ok(Guarded::Applied(applied));
    }
    // Hold it: a device_signed approval whose params ARE the mutation (request_hash binds them, so
    // the signature covers the exact diff), titled for the approver's prompt. Only a destructive
    // change is held over loopback, so a local hold says why it needs a device rather than where it
    // came from.
    let requester = requester_of(op, remote);
    let message = if remote {
        held_remote_note(&requester)
    } else if retarget_hold {
        HELD_RETARGET_NOTE
    } else {
        HELD_DESTRUCTIVE_NOTE
    };
    let approval = state.service.hold_change_approval(POLICY_WRITE_CAP, mutation, message, requester).await?;
    Ok(Guarded::Held(StatusCode::ACCEPTED, held_body(&approval)))
}

/// Whether `mutation` changes where a credential this gateway already holds is sent, or how it is
/// presented: an SSH connection's host, port, user, host key or auth kind.
fn moves_a_credential(mutation: &crate::policy_guard::Mutation) -> bool {
    match mutation {
        crate::policy_guard::Mutation::ConnectionPatch { patch, .. } => patch.ssh.as_ref().is_some_and(|ssh| {
            ssh.host.is_some()
                || ssh.port.is_some()
                || ssh.user.is_some()
                || ssh.host_key_sha256.is_some()
                || ssh.insecure.is_some()
                || ssh.password_auth.is_some()
        }),
        _ => false,
    }
}

/// The [`apply_or_hold`] of the trust root: the funnel for the two mutations that write the approver
/// keyring or lower the approval floor.
///
/// It differs from [`apply_or_hold`] in three ways, each deliberate:
///  - **No classifier.** Trusting a device signing key is never "strictly tightening" in the
///    [`crate::policy_guard`] sense and asking would only ever return the same answer.
///  - **[`crate::service::EnforcementService::any_device_trusted`], not `any_device_enrolled`.** The
///    sticky `ever_enrolled` flag would hold an enrolment for a co-signature from a device that has
///    been revoked, a hold nothing on earth can satisfy. On a self-run gateway that is awkward; on
///    a hosted worker, with no host to pair from, it locks the tenant out of ever pairing again.
///  - **The keyring is re-read from the store first**, ignoring the refresh TTL. A hosted tenant can
///    be served by several Cloud Run instances at once, and two of them holding a stale empty
///    snapshot would each believe theirs is the first device and each take the trust-on-first-use
///    branch that is supposed to happen exactly once per worker.
///
/// A hold goes into the existing queue under [`POLICY_WRITE_CAP`], is pushed to the enrolled devices,
/// and is applied by `resolve_approval`'s existing branch on a verified signature. There is no new
/// resolution machinery. `required_signatures` is what `mutation_quorum` says: one for a key
/// pairing or revocation, and for a floor lowering the highest two-person rule the gateway has
/// carried, capped at the people its trusted keys can reach.
async fn apply_or_hold_pairing(
    state: &AppState,
    m: &crate::policy_guard::Mutation,
    authority: &PairingAuthority,
) -> Result<Guarded, GatewayError> {
    let _cp = state.service.control_plane_mutex().lock().await;
    state.service.refresh_keyring_now();
    // Re-pairing a device whose EXACT key this worker already trusts changes nothing, so there is
    // nothing for a co-signer to decide. Holding it produced a 202 telling the owner to confirm the
    // enrolment on another paired device, which, on the common path of a phone that lost its local
    // state and re-ran the ceremony, is the very phone in their hand. It is safe to treat as done
    // because reaching this point required a possession proof signed by that key's PRIVATE half: only
    // the device itself can present it, and a caller who could would already be able to sign
    // approvals with it. The trust state after this branch is byte-identical to the trust state
    // before it.
    //
    // Binding a person to a trusted key that has none is how a key paired before keys named a person
    // comes to count as one. It applies here only when it cannot raise how many people the keyring can
    // put behind an approval (the person is already bound to another key, or nobody else is bound);
    // otherwise it is the second person arriving and is held like any later device, so a loopback
    // bearer cannot mint one alone. A key already bound to a DIFFERENT person is refused rather than
    // held, because the device itself is trusted and could co-sign its own re-attribution: revoking it
    // and pairing it again puts it in front of another device instead.
    let mut binds_a_trusted_key = false;
    let already_trusted = match m {
        crate::policy_guard::Mutation::ApproverKeyTrust { approver_id, approver_pubkey, person, .. } => {
            let keyring = state.service.approver_keyring_snapshot();
            if keyring.trusted_key(approver_id) != Some(approver_pubkey.as_str()) {
                false
            } else {
                match (keyring.person(approver_id), person.as_deref()) {
                    (Some(bound), Some(asked)) if bound != asked => {
                        return Err(GatewayError::Denied(
                            "this device already approves for a different person; revoke it and pair it \
                             again to change whose approvals it counts as"
                                .into(),
                        ))
                    }
                    (None, Some(asked)) if keyring.binding_adds_a_person(approver_id, asked) => {
                        binds_a_trusted_key = true;
                        false
                    }
                    _ => true,
                }
            }
        }
        _ => false,
    };
    if let crate::policy_guard::Mutation::ApproverKeyTrust { approver_id, approver_pubkey, .. } = m {
        if state.hosted && !state.service.any_device_trusted() {
            refuse_first_pairing_unless_manager(state, authority, approver_id, approver_pubkey)?;
        }
    }
    if matches!(m, crate::policy_guard::Mutation::ApprovalFloorSet { .. })
        && state.hosted
        && !state.service.any_device_trusted()
    {
        refuse_unanchored_floor_unless_manager(state, authority)?;
    }
    // Once a device is trusted, every write through this funnel is held for that device's signature
    // wherever it arrived from, loopback included. The operator token is a 0600 file, so on a machine
    // that runs agents it is readable by every agent the owner runs; a loopback call it authorises is
    // not evidence of a human. Enrolment held that way already. Lowering the floor did not: over
    // loopback it applied on the bearer alone as the documented recovery control, which meant the
    // one call that switches the export hold off was the one call the hold did not cover.
    //
    // Recovery is still reachable, through an authority the bearer does not carry: a recovery code
    // issued when the first device paired, or, where this gateway is an OAuth resource server, a
    // single-use permaura.com recovery ticket. Both apply here at once; neither can be produced by
    // reading `operator.token`.
    let must_hold = !already_trusted
        && state.service.any_device_trusted()
        && !matches!(
            authority,
            PairingAuthority::RecoveryCode { .. } | PairingAuthority::RecoveryTicket { .. }
        );
    // The key this enrolment would displace, read inside the critical section. The held title reads it
    // again under the same lock, so it names the trust root the co-signer is actually being asked to
    // retire rather than one that has since moved.
    let displaced = match m {
        crate::policy_guard::Mutation::ApproverKeyTrust { approver_id, approver_pubkey, .. } => {
            let keyring = state.service.approver_keyring_snapshot();
            keyring
                .trusted_key(approver_id)
                .filter(|k| *k != approver_pubkey.as_str())
                .map(|k| k.to_string())
        }
        _ => None,
    };
    let stamped;
    let m = match (m, &displaced) {
        (crate::policy_guard::Mutation::ApproverKeyTrust { approver_id, approver_pubkey, person, .. }, Some(old)) => {
            if state.hosted {
                refuse_replacement_unless_entitled(state, authority, approver_id, approver_pubkey)?;
            }
            stamped = crate::policy_guard::Mutation::ApproverKeyTrust {
                approver_id: approver_id.clone(),
                approver_pubkey: approver_pubkey.clone(),
                person: person.clone(),
                replaces: Some(crate::service::key_fingerprint(old)),
            };
            &stamped
        }
        _ => m,
    };
    if !must_hold {
        // On the hosted trust-on-first-use branch this is structurally impossible today: that branch
        // is only reached when `any_device_trusted()` is false, i.e. every entry is revoked, and
        // `trusted_key` returns `None` for a revoked entry, so nothing live can be displaced. The
        // refusal is here so that a future change which broke that invariant fails CLOSED rather than
        // letting a ticket alone rotate a live trust root with no co-signature. Loopback is
        // deliberately not covered: re-pairing a device id with a fresh key is the long-standing
        // Mode A/B rotation flow, positionally anchored, and refusing it would remove the only way an
        // operator at the host can rotate a device key.
        if displaced.is_some() && matches!(authority, PairingAuthority::HostedOwner { .. }) {
            return Err(GatewayError::Denied(
                "this approver id already holds a different trusted key; rotating it needs a co-signature from a device this gateway already trusts".into(),
            ));
        }
        let mut detail = authority.audit_detail();
        if already_trusted {
            // So the chain distinguishes a re-pair that changed nothing from an enrolment that armed
            // the approval gate. Both are `allow`, and only one of them is an event.
            detail.insert("already_trusted".into(), json!(true));
        }
        return Ok(Guarded::Applied(apply_mutation_as(
            state.service.store().as_ref(),
            state.service.as_ref(),
            m,
            authority.label(),
            detail,
        )?));
    }
    // A self-run floor lowering held here goes through the recovery funnel, so its 202 names the
    // recovery routes that would apply it at once. Enrolment never does: no recovery authority adds
    // a device.
    if matches!(authority, PairingAuthority::Loopback)
        && !matches!(m, crate::policy_guard::Mutation::ApproverKeyTrust { .. })
    {
        return recover_or_hold(state, m, authority, None).await;
    }
    let requester = authority.requester();
    let message = trust_root_note(m, &requester);
    let approval = state.service.hold_change_approval(POLICY_WRITE_CAP, m, message, requester).await?;
    let mut body = held_body(&approval);
    // Every control-plane hold shares `POLICY_WRITE_CAP`, so without these a caller cannot tell a
    // pending device enrolment from a pending policy edit, and the broker cannot name the key in the
    // owner's notification.
    if let crate::policy_guard::Mutation::ApproverKeyTrust { approver_id, approver_pubkey, .. } = m {
        body["action"] = json!(APPROVER_PAIR_CAP);
        body["approver_id"] = json!(approver_id);
        body["key_fp"] = json!(crate::service::key_fingerprint(approver_pubkey));
        body["approval_audience"] = json!(state.service.served_approval_audience());
        // The key is trusted already and stays so; what waits on the co-signer is only whose approvals it counts as.
        body["already_trusted"] = json!(binds_a_trusted_key);
    }
    // On a hosted worker the floor lowering's 202 has to say what to do next rather than leave the
    // owner staring at a hold only the device they have lost could resolve. Revoking that device first
    // is a real, reachable step under its own step-up, and after it this same call applies at once.
    if matches!(m, crate::policy_guard::Mutation::ApprovalFloorSet { .. }) {
        body["recovery"] = json!(
            "A device this gateway trusts is still enrolled, so it has to confirm this. If that \
             device is genuinely gone, revoke it first and then repeat this request, which will \
             apply straight away."
        );
    }
    Ok(Guarded::Held(StatusCode::ACCEPTED, body))
}

/// `POST /v1/shutdown`: graceful stop. **Operator-authenticated AND loopback-only** (refused on a
/// hosted or tunnelled gateway, like session open and self-run pairing). This is the
/// portable stop path the desktop supervisor and the npm CLI call before falling back to a hard kill:
/// on Windows a `CREATE_NO_WINDOW` gateway that is a child of a GUI parent never receives console-close
/// events, so an in-band request is the only clean stop. Firing the signal lets the binary drain
/// in-flight requests, then exit.
///
/// `202 Accepted` when the binary armed the shutdown signal; `500` when this gateway is embedded (the
/// daemon or tests reuse the router but must not self-terminate their host), never a silent no-op.
/// The body says how many executions are still running and how long the drain gives them, so a
/// client can tell its user a call is finishing rather than leave a quit that seems to hang, and names
/// the process, so a local caller can tell when it has exited.
pub async fn shutdown_gateway(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    reject_if_remote(remote)?;
    operator_authed(&state, &headers)?;
    match &state.shutdown {
        Some(signal) => {
            tracing::info!("operator requested graceful shutdown via POST /v1/shutdown");
            let running = state.service.executions().running();
            signal.notify_one();
            Ok((
                StatusCode::ACCEPTED,
                Json(json!({
                    "draining": true,
                    "running": running,
                    "drain_window_secs": crate::drain::DRAIN_WINDOW.as_secs(),
                    // So a local caller can wait for this process to exit: it stops answering as the drain begins and goes on writing its store until the drain ends.
                    "pid": std::process::id(),
                })),
            ))
        }
        None => Err(GatewayError::Internal(
            "graceful shutdown is not available on this gateway (embedded runtime)".into(),
        )),
    }
}

// ── /v1/remote/disable ────────────────────────────────────────────────────────

/// The variables that bring a resource server back at the next start when the gateway's own environment sets them, which outranks `config.toml`, so `permaura remote disable` cannot remove them by editing the file.
const REMOTE_ENVIRONMENT: [&str; 3] = ["PERMAURA_PUBLIC_URL", "PERMAURA_AS_ISSUER", "PERMAURA_AS_JWKS"];

/// `POST /v1/remote/disable`: turn remote access off in this running gateway, the half of `permaura remote disable` that editing files cannot do. **Operator-authenticated AND loopback-only**, like `POST /v1/shutdown`: it is a kill switch for an owner who distrusts permaura.com or the tunnel, so nothing arriving through either may use it, and a hosted worker never may.
///
/// It withdraws the OAuth resource server, so from now on no permaura.com token or ticket verifies, then kills the tunnel connector this process runs and waits for it to exit, and records what it did as a [`REMOTE_DISABLE_ACTION`] audit event. The answer says what it found: `connector` is `stopped` (with its pid), `none` (this process runs none: the desktop app's, another tunnel or a reverse proxy may still forward to this address, and `tunnel_before` says whether the guard had already stopped this process's own) or `running` (it did not exit, with why, answered 500); `remote_tokens` is `refused` or `none` (no resource server was running); `environment` names the [`REMOTE_ENVIRONMENT`] variables this process's environment set, which the next start applies again. Nothing here survives a restart: the files `permaura remote disable` edits are what keep it off.
pub async fn disable_remote_access(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    reject_if_remote(remote)?;
    let op = operator_authed(&state, &headers)?;
    // The task survives a disconnected caller and attempts the audit append even if the caller no longer awaits it.
    tokio::spawn(turn_remote_access_off(state, op))
        .await
        .map_err(|e| GatewayError::Internal(format!("turning remote access off did not finish: {e}")))
}

/// The work behind [`disable_remote_access`]: withdraw, stop, then record, and answer what it found.
async fn turn_remote_access_off(state: AppState, op: Session) -> (StatusCode, Json<serde_json::Value>) {
    let remote_tokens = match state.service.oauth() {
        Some(rs) => {
            rs.withdraw();
            "refused"
        }
        None => "none",
    };
    let tunnel_before = crate::tunnel::connector().ingress();
    let turned_off = match state.tunnel.clone() {
        Some(slot) => tokio::task::spawn_blocking(move || crate::tunnel::turn_off(&slot, crate::tunnel::TURN_OFF_WITHIN))
            .await
            .unwrap_or_else(|e| crate::tunnel::TurnedOff::Unknown(format!("stopping the tunnel connector did not finish: {e}"))),
        None => crate::tunnel::TurnedOff::Nothing,
    };
    let tunnel_after = crate::tunnel::connector().ingress();
    let tunnel_stop_reason = crate::tunnel::connector().stop_reason();
    let environment: Vec<&str> = REMOTE_ENVIRONMENT.into_iter().filter(|key| crate::config::pinned_by_environment(key)).collect();
    let supervised_by_app = crate::config::supervised_by_app();
    let (status, connector, pid, detail) = match turned_off {
        crate::tunnel::TurnedOff::Nothing => (StatusCode::OK, "none", None, None),
        crate::tunnel::TurnedOff::Stopped(pid) => (StatusCode::OK, "stopped", Some(pid), None),
        crate::tunnel::TurnedOff::StillRunning(pid, why) => (StatusCode::INTERNAL_SERVER_ERROR, "running", Some(pid), Some(why)),
        crate::tunnel::TurnedOff::Unknown(why) => (StatusCode::INTERNAL_SERVER_ERROR, "running", None, Some(why)),
    };
    tracing::warn!(connector, remote_tokens, environment = ?environment, "remote access turned off in the running gateway (POST /v1/remote/disable)");
    // Recorded after the fact: a kill switch the store cannot record still has to switch, so a failed append is reported in the answer rather than undoing anything.
    let mut payload = permaura_core::AuditPayload::new(REMOTE_DISABLE_ACTION, "remote-access", if status.is_success() { "allow" } else { "error" });
    payload.agent_id = Some(op.agent_id.clone());
    payload.session_id = Some(op.id.clone());
    payload.user_id = op.user_id.clone();
    payload.device_id = op.device_id.clone();
    payload.summary = json!({
        "connector": connector,
        "connector_pid": pid,
        "detail": detail,
        "remote_tokens": remote_tokens,
        "environment": environment,
        "supervised_by_app": supervised_by_app,
        "tunnel_before": tunnel_before,
        "tunnel_after": tunnel_after,
        "tunnel_stop_reason": tunnel_stop_reason,
    });
    insert_actor(&mut payload.summary, &op);
    let audited = match state.service.store().append_audit(payload) {
        Ok(_) => None,
        Err(e) => {
            tracing::error!(error = %e, "remote access was turned off, but the audit chain could not record it");
            Some(e.to_string())
        }
    };
    (
        status,
        Json(json!({
            "connector": connector,
            "connector_pid": pid,
            "detail": detail,
            "remote_tokens": remote_tokens,
            "environment": environment,
            "supervised_by_app": supervised_by_app,
            "tunnel_before": tunnel_before,
        "tunnel_after": tunnel_after,
        "tunnel_stop_reason": tunnel_stop_reason,
            "audited": audited.is_none(),
            "audit_error": audited,
        })),
    )
}

/// The audit action recorded when `POST /v1/remote/disable` turns remote access off.
pub const REMOTE_DISABLE_ACTION: &str = "permaura.remote.disable";

/// The audit action recorded when a start serves remote access: a resource server taking permaura.com tokens, and whether a tunnel connector is configured to front it. The counterpart of [`REMOTE_DISABLE_ACTION`], so the chain shows remote access coming back as well as going.
pub const REMOTE_SERVING_ACTION: &str = "permaura.remote.serving";

// ── /v1/announce ──────────────────────────────────────────────────────────────

/// What this gateway says about the workspaces it announces to. Never a secret: a fingerprint is
/// enough for the console to compare a link with the hash permaura.com holds for it.
fn announce_body(state: &AppState) -> serde_json::Value {
    let links = state.service.announce_links();
    json!({
        "configured": !links.is_empty(),
        "settable": announce_refusal(state).is_none(),
        "links": links
            .iter()
            .map(|c| json!({ "gateway_id": c.gateway_id(), "fingerprint": c.fingerprint() }))
            .collect::<Vec<_>>(),
    })
}

/// Why this gateway's links cannot be changed over REST, if they cannot.
///
/// The environment outranks `config.toml` everywhere else, so a value a supervisor or an operator
/// exported must not be quietly replaced here either: the next restart would put theirs back.
fn announce_refusal(state: &AppState) -> Option<(&'static str, &'static str)> {
    if state.hosted {
        return Some(("hosted", "a hosted gateway's announce credentials come from provisioning"));
    }
    if ["PERMAURA_GATEWAY_ID", "PERMAURA_ANNOUNCE_SECRET"]
        .iter()
        .any(|key| crate::config::pinned_by_environment(key))
    {
        return Some((
            "environment",
            "this gateway's announce credentials are set in its environment, which outranks anything set here",
        ));
    }
    None
}

fn announce_conflict(reason: &str, message: &str) -> Response {
    (StatusCode::CONFLICT, Json(json!({ "error": message, "reason": reason }))).into_response()
}

/// Persist the links and switch the running process over to them, in that order: a gateway must never
/// announce with credentials it will have forgotten after a restart.
fn apply_announce(state: &AppState, links: Vec<crate::announce::Config>) -> Result<bool, GatewayError> {
    let persisted = match &state.config_path {
        Some(path) => {
            let stated: Vec<crate::config::AnnounceLink> = links.iter().map(|c| c.to_link()).collect();
            crate::config::write_announce(path, &stated).map_err(GatewayError::Internal)?;
            true
        }
        None => false,
    };
    state.service.set_announce(links);
    Ok(persisted)
}

/// `GET /v1/announce`
pub async fn announce_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    operator_authed(&state, &headers)?;
    Ok(Json(announce_body(&state)))
}

/// Body of `PUT /v1/announce`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetAnnounceReq {
    /// The control plane's id for this gateway in one workspace.
    pub gateway_id: String,
    /// The secret permaura.com minted for that link, `gwa_...`.
    pub announce_secret: String,
}

/// `PUT /v1/announce`: add the link permaura.com minted when this gateway was linked to a workspace,
/// or replace its secret after a rotation. Additive, because a machine linked into several workspaces
/// announces to all of them; only the named link is touched.
pub async fn set_announce(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<SetAnnounceReq>,
) -> Result<Response, GatewayError> {
    operator_authed(&state, &headers)?;
    // Every pairing on this machine ends here, whatever permaura.com sent back, and it is the pairing that may have handed permaura.com `operator.token`, so the re-seal task rotates it. Counted before any refusal, since the token was handed over either way; never for a remote caller, which hands nothing over and must not be able to make the file churn.
    if !remote {
        state.service.pairings().note();
    }
    if let Some((reason, message)) = announce_refusal(&state) {
        return Ok(announce_conflict(reason, message));
    }
    let (gateway_id, secret) = (req.gateway_id.trim(), req.announce_secret.trim());
    if !crate::announce::is_gateway_id(gateway_id) {
        return Err(GatewayError::BadRequest("gateway_id is not a control-plane gateway id".into()));
    }
    // The value is never echoed, not even in the refusal.
    if !crate::announce::is_announce_secret(secret) {
        return Err(GatewayError::BadRequest("announce_secret is not an announce secret".into()));
    }
    let Some(config) = crate::announce::Config::new(gateway_id, secret) else {
        return Ok(announce_conflict(
            "control_plane",
            "PERMAURA_CONTROL_PLANE_URL is not https, so this gateway will not announce to it",
        ));
    };
    let mut links = state.service.announce_links();
    match links.iter().position(|c| c.gateway_id() == gateway_id) {
        // A rotation of a link already held: replaced in place, so the order holds steady.
        Some(at) => links[at] = config,
        None if links.len() >= crate::announce::MAX_LINKS => {
            return Ok(announce_conflict(
                "too_many_links",
                "this gateway already announces to as many workspaces as it will",
            ));
        }
        None => links.push(config),
    }
    let persisted = apply_announce(&state, links)?;
    tracing::info!(gateway_id, persisted, "announce link set: this gateway announces to it from now on");
    let mut body = announce_body(&state);
    body["persisted"] = json!(persisted);
    Ok(Json(body).into_response())
}

/// Body of `DELETE /v1/announce`, which may be empty.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ClearAnnounceReq {
    /// The one link to drop. Absent drops every link.
    #[serde(default)]
    pub gateway_id: Option<String>,
}

/// `DELETE /v1/announce`: stop announcing to a link that has been revoked, or to all of them. Naming
/// a link leaves the others alone, so unlinking one workspace cannot silence another.
pub async fn clear_announce(
    State(state): State<AppState>,
    headers: HeaderMap,
    OptionalJsonBody(req): OptionalJsonBody<ClearAnnounceReq>,
) -> Result<Response, GatewayError> {
    operator_authed(&state, &headers)?;
    let req = req.unwrap_or_default();
    if let Some((reason, message)) = announce_refusal(&state) {
        return Ok(announce_conflict(reason, message));
    }
    if req.gateway_id.as_deref().is_some_and(|id| id.trim().is_empty()) {
        return Err(GatewayError::BadRequest(
            "gateway_id is blank; name the link to drop, or send no gateway_id to drop every link".into(),
        ));
    }
    let before = state.service.announce_links();
    let after: Vec<crate::announce::Config> = match req.gateway_id.as_deref().map(str::trim) {
        // An id this gateway does not hold is a no-op rather than a refusal: the link is already
        // gone, which is what the caller wanted.
        Some(id) if !id.is_empty() => before.iter().filter(|c| c.gateway_id() != id).cloned().collect(),
        _ => Vec::new(),
    };
    if after.len() != before.len() {
        apply_announce(&state, after)?;
        tracing::info!(
            links = state.service.announce_links().len(),
            "announce link removed: this gateway no longer announces to it"
        );
    }
    Ok(Json(announce_body(&state)).into_response())
}

// ── POST /v1/sessions ─────────────────────────────────────────────────────────

/// Open a new agent session. Returns the session id and the bearer token to present.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionReq {
    /// The agent opening the session (must be registered).
    pub agent_id: String,
    /// The responsible user, if known.
    #[serde(default)]
    pub user_id: Option<String>,
    /// The originating device, if known.
    #[serde(default)]
    pub device_id: Option<String>,
}

/// Handler for `POST /v1/sessions`.
///
/// Requires an operator token, and loopback, and not both by accident.
///
/// This used to mint an **Operator**-role token to any caller that could reach the socket, on the
/// reasoning that loopback reachability is itself the authentication, the way a Unix socket's
/// filesystem mode authenticates its callers. A TCP listener on 127.0.0.1 has no such mode. Every
/// process on the machine can open it, whatever user it runs as, and on this product that set includes
/// the agents themselves: an agent that is meant to be held to its grants could POST here, receive
/// operator authority, and rewrite those grants. The thing the gateway exists to prevent was reachable
/// from inside the thing it was preventing it for.
///
/// So the bootstrap token is now presented like any other credential. There is no new concept to
/// distribute: `$PERMAURA_HOME/operator.token` (0600) already holds a real Operator session, written on
/// first boot and kept live by `ensure_published_operator_token`, and the CLI, the desktop supervisor
/// and the installer all read it already.
///
/// What this does NOT close, stated plainly so nobody assumes otherwise: a process running as the same
/// OS user can read that file, and can also read the store and the vault key beside it. Against a
/// same-user attacker this is not a boundary: it raises the bar from "can open a TCP socket" to "can
/// read this user's files", which is the difference between a sandboxed agent and an unsandboxed one.
/// A real boundary for same-user callers needs peer-credential checks on a Unix socket, or per-agent
/// identity, and neither is this function's job.
pub async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    JsonBody(req): JsonBody<CreateSessionReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    reject_if_remote(remote)?;
    let opener = operator_authed(&state, &headers)?;
    let store = state.service.store();
    if store.get_agent(&req.agent_id)?.is_none() {
        return Err(GatewayError::NotFound(format!("agent '{}'", req.agent_id)));
    }
    let id = format!("sess_{}", short_id());
    let token = format!("tok_{}", short_id());
    // Never outliving the bearer that opened it, so a token retired with a grace cannot open one that outlasts it.
    let expires_at = match opener.expires_at {
        Some(parent) => parent.min(now_ms() + OPERATOR_SESSION_TTL_MS),
        None => now_ms() + OPERATOR_SESSION_TTL_MS,
    };
    let summary = json!({
        "agent_id": crate::audit_bound::cut_text(&req.agent_id),
        "role": "operator",
        "expires_at": expires_at,
        // Who the session says it acts for: the identity holds and charges are recorded under.
        "user_id": req.user_id.as_deref().map(crate::audit_bound::cut_text),
        "device_id": req.device_id.as_deref().map(crate::audit_bound::cut_text),
    });
    let session = Session {
        class: Default::default(),
        opened_by: Some(opener.id.clone()),
        id: id.clone(),
        agent_id: req.agent_id,
        user_id: req.user_id,
        device_id: req.device_id,
        token: token.clone(),
        // POST /v1/sessions is the control-plane session-open primitive (console direct path,
        // CLI, pairing). Agent identities self-enrol over MCP, which mints an Agent-role token.
        role: SessionRole::Operator,
        created_at: now_ms(),
        revoked: false,
        // The console re-opens transparently on a 401, so a short cap costs nothing a user can feel.
        expires_at: Some(expires_at),
        last_used_at: None,
        actor: None,
    };
    let mut session = Some(session);
    store.change_with_record(&mut || {
        let Some(session) = session.take() else { return Ok(()) };
        store.put_session(session)?;
        // Operator authority whose issue is not in the chain does not stand.
        if let Err(e) = state.service.audit_authority(crate::service::SESSION_OPEN_ACTION, &id, &opener, summary.clone()) {
            let _ = store.revoke_session(&id);
            return Err(e);
        }
        Ok(())
    })?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "session_id": id, "token": token })),
    ))
}

/// `POST /v1/sessions/:id/revoke`-style revoke is exposed via the MCP tool; the REST
/// surface revokes through this DELETE-equivalent handler wired in the router.
pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Revoking an arbitrary session is operator-only. (An agent revokes its OWN session via the
    // MCP `permaura.revoke_session` tool.)
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let mut existed = false;
    store.change_with_record(&mut || {
        existed = store.revoke_session(&id)?;
        if existed {
            // The revocation stands if its record fails, which is the safe way round, and the caller is told.
            state.service.audit_authority(crate::service::SESSION_REVOKE_ACTION, &id, &op, json!({ "via": "rest" }))?;
        }
        Ok(())
    })?;
    if !existed {
        return Err(GatewayError::NotFound(format!("session '{id}'")));
    }
    Ok(Json(json!({ "session_id": id, "revoked": true })))
}

// ── Broker kill switch (global pause) ─────────────────────────────────────────────

/// `GET /v1/broker`: runtime broker state. Any live session may read it (an agent can learn it's
/// paused, and the console reads the new-agent approval gate from here).
pub async fn broker_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _session = authed(&state, &headers)?;
    Ok(Json(json!({
        "paused": state.service.is_paused(),
        "agents_paused": state.service.agents_paused(),
        "require_agent_approval": state.service.require_agent_approval(),
        "require_agent_approval_source": state.service.require_agent_approval_source().as_str(),
        // Same joined note as `/health`: durability trouble and audit pressure both land here,
        // because this is the field the console watches.
        "store_degraded": state.service.degraded(),
        // The hold and the reconciliation, beside it, from the same source `/health` reads so the
        // two documents cannot disagree. They are here because no client could see a held tenant
        // until an action was refused: the console's status pill reads this route, not `/health`,
        // so a worker that answers 423 to every execution looked perfectly healthy until somebody
        // tried something. State and ids only, and nothing that names what is being restored.
        "execution_hold": crate::restore::health_snapshot(state.service.execution_hold()),
        "reconciliation": state
            .service
            .reconciliation()
            .ok()
            .flatten()
            .map(|r| r.health_snapshot())
            .unwrap_or(serde_json::Value::Null),
        // Here as well as on the audit routes because this is the route every console poll reads, so
        // the control plane sees the key on the first connection rather than on the first audit view.
        "audit_key": crate::audit_key::report_for(state.service.store().as_ref()),
    })))
}

/// Body for `POST /v1/broker/pause`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseReq {
    /// True engages the kill switch (deny all invokes); false resumes.
    pub paused: bool,
}

/// `POST /v1/broker/pause`: flip the global kill switch. Operator-only: when paused, every agent
/// invoke is denied while the gateway stays up. The state is stored, so a restart keeps it.
/// Pausing (tightening) applies immediately; UN-pausing over the broker with a device
/// enrolled is HELD for a device signature ([`apply_or_hold`]): a compromised control
/// plane must not silently lift the kill switch back to policy-governed enforcement.
pub async fn set_broker_pause(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<PauseReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let mutation = crate::policy_guard::Mutation::BrokerToggle {
        toggle: crate::policy_guard::BrokerToggleKind::Pause,
        value: req.paused,
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::OK, Json(json!({ "paused": req.paused })))),
    }
}

/// Body for `POST /v1/broker/require-approval`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequireApprovalReq {
    /// True makes a newly-seen OAuth agent land Pending until an operator approves it.
    pub require_agent_approval: bool,
}

/// `POST /v1/broker/require-approval`: toggle whether a newly-seen OAuth agent must be approved by
/// an operator before it can invoke (on top of the AS sign-in consent). Operator-only. Stored, so a
/// restart keeps it and it wins over the default from then on (on once a device is paired on a
/// gateway reachable from off the host; `PERMAURA_REQUIRE_AGENT_APPROVAL` also engages it for a run). Affects only agents seen *after*
/// the change: existing approved/pending agents keep their status. Turning the gate ON (tightening)
/// applies immediately; turning it OFF over the broker with a device enrolled is HELD for a device
/// signature ([`apply_or_hold`]); else a compromised control plane could silently disable
/// the new-agent gate so every FUTURE OAuth agent lands Approved automatically.
pub async fn set_require_approval(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<RequireApprovalReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let mutation = crate::policy_guard::Mutation::BrokerToggle {
        toggle: crate::policy_guard::BrokerToggleKind::RequireAgentApproval,
        value: req.require_agent_approval,
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((
            StatusCode::OK,
            Json(json!({ "require_agent_approval": req.require_agent_approval })),
        )),
    }
}

// ── GET /v1/capabilities ────────────────────────────────────────────────────────

/// Handler for `GET /v1/capabilities`. Lists the capability catalog (id, description,
/// risk, requires_approval), never secrets.
pub async fn list_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let session = authed(&state, &headers)?;
    let store = state.service.store();
    let all = store.list_capabilities()?;
    // An operator drives the console and needs the whole catalogue. An agent is told this is what
    // its session may attempt, so it has to actually be that: a Pending agent can invoke nothing,
    // and an approved one can only reach connections some enabled grant points it at. Handing over
    // the full catalogue made the list a map of the estate for a session that could not call a
    // single entry on it.
    let caps: Vec<_> = all
        .into_iter()
        .filter(|c| session.role == SessionRole::Operator || reachable_by_agent(&state.service, &session.agent_id, c).unwrap_or(false))
        .map(|c| {
            json!({
                "id": c.id,
                "description": c.description,
                "risk": c.risk,
                "requires_approval": c.requires_approval,
                "resource": c.resource,
                "takes_owner_posture": c.kind == crate::connectors::CapabilityKind::Http && c.http.is_some(),
                "owner_posture": c.http.as_ref().and_then(|h| h.owner_posture),
            })
        })
        .collect();
    Ok(Json(json!({ "capabilities": caps })))
}

/// Whether `agent_id` could actually attempt `cap` right now: the agent is approved, the capability's
/// connection exists and is not switched off, the capability itself is not disabled on it, and some
/// enabled grant that targets this agent activates a policy on that connection.
///
/// Deliberately a *reachability* test, not a policy decision: it answers "could this session ever be
/// allowed to call this", which is what a capability listing claims to describe. The enforcement loop
/// still decides each individual call.
pub(crate) fn reachable_by_agent(
    service: &crate::service::EnforcementService,
    agent_id: &str,
    cap: &Capability,
) -> Result<bool, GatewayError> {
    let store = service.store().as_ref();
    match store.get_agent(agent_id)? {
        Some(a) if a.status == AgentStatus::Approved => {}
        _ => return Ok(false),
    }
    let Some(connection) = store.get_connection(&cap.resource)? else { return Ok(false) };
    if connection.disabled || connection.disabled_capabilities.iter().any(|d| d == &cap.id) {
        return Ok(false);
    }
    if service.connection_revocation(&connection)?.is_some() {
        return Ok(false);
    }
    let policies = store.policies_for_connection(&cap.resource)?;
    if policies.is_empty() {
        return Ok(false);
    }
    Ok(store.list_grants()?.into_iter().any(|g| {
        g.enabled && g.targets(agent_id) && g.policy_ids.iter().any(|pid| policies.iter().any(|p| &p.id == pid))
    }))
}

// ── GET /v1/agents ────────────────────────────────────────────────────────────────

/// Handler for `GET /v1/agents`. Lists registered agents (id + name). Auth required.
///
/// An agent session is shown only its own row: the other agents on a gateway, and whether they are
/// waiting, are the operator's business, and an agent that could read them could aim a prompt at one.
pub async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let session = authed(&state, &headers)?;
    let agents: Vec<_> = state
        .service
        .store()
        .list_agents()?
        .into_iter()
        .filter(|a| session.role == SessionRole::Operator || a.id == session.agent_id)
        .map(|a| json!({
            "id": a.id,
            "name": a.name,
            "status": a.status,
            "enrolled_at": a.enrolled_at,
        }))
        .collect();
    Ok(Json(json!({ "agents": agents })))
}

// ── GET /v1/sessions ──────────────────────────────────────────────────────────────

/// Handler for `GET /v1/sessions`. Lists sessions (never the bearer token).
///
/// `expires_at` is on every row, as a unix-ms number or an explicit `null`, never omitted: a client has to tell "no absolute deadline" from "this gateway did not say", and one that reads a missing field as zero renders every session as expired. It is the deadline as of this read. An agent's slides forward on use (`touch_session`), so a client derives remaining time from each response and never treats one as final.
///
/// Operator-only: the ids are what `permaura_revoke_session` takes, so listing them to agent tokens handed every agent the operator's session ids. `last_used_at` stays off the row all the same.
pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let sessions: Vec<_> = state
        .service
        .store()
        .list_sessions()?
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "agent_id": s.agent_id,
                "user_id": s.user_id,
                "device_id": s.device_id,
                "created_at": s.created_at,
                "expires_at": s.expires_at,
                "revoked": s.revoked,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": sessions })))
}

// ── GET /v1/grants ────────────────────────────────────────────────────────────────

/// Handler for `GET /v1/grants`. Lists all grants. Auth required.
pub async fn list_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    // Grants serialize in the slim shape: { grant_id, policy_id, target, max_calls?, period?,
    // expires_at? }. The console joins policy_id → policy → connection to render the
    // grant → connection → agent chain.
    let grants = state.service.store().list_grants()?;
    Ok(Json(json!({ "grants": grants })))
}

// ── GET /v1/secrets ───────────────────────────────────────────────────────────────

/// Handler for `GET /v1/secrets`. Lists every secret an operator can name, each with where it is held (`location`: `local_vault`, `kms` or `infisical`) and its **metadata only**: labels, risk classification, allowed execution locations, last use (which nothing records yet). An id an external custodian holds has no metadata here and reads as high risk. This route never serializes the sealed value. A secret is opened through the custody backend by an invoke, a WordPress Abilities re-sync, or a vault export (confirmed on a device while one is trusted and approvals are not opted down), which hands every credential over sealed under the requester's passphrase.
pub async fn list_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    // The inventory, not the raw rows: it drops a credential change parked for approval, which nothing can name, and adds the ids an external custodian holds, which the rows miss. An id named but held nowhere is left out, since nothing can be done with it here.
    let mut secrets = Vec::new();
    for entry in crate::secret_inventory::secret_inventory(store.as_ref())?.entries {
        if entry.location.is_unresolvable() {
            continue;
        }
        let metadata = store.get_secret(&entry.secret_id)?.map(|r| r.metadata).unwrap_or_else(|| permaura_core::SecretMetadata {
            risk_classification: permaura_core::RiskTier::High,
            ..Default::default()
        });
        secrets.push(json!({
            "id": entry.secret_id,
            "location": entry.location.as_str(),
            "labels": metadata.labels,
            "risk_classification": metadata.risk_classification,
            "allowed_execution_locations": metadata.allowed_execution_locations,
            "last_used_at": metadata.last_used_at,
        }));
    }
    Ok(Json(json!({ "secrets": secrets })))
}

// ── GET /v1/connections ─────────────────────────────────────────────────────────────

/// Render a stored [`Connection`] as the console's connection JSON: id, connector, honest
/// label, name, the capability ids it exposes (with the operator's disabled set), plus the
/// derived `secret_present` / `status` (a credential's presence, never its value) and a
/// back-compat `resource` alias (== id). SSH connections also surface their pinned target
/// (host/port/user + auth mode) so the console can render it, never the credential or the
/// host-key fingerprint. No secret material is ever exposed.
fn connection_json(state: &AppState, c: &Connection) -> Result<serde_json::Value, GatewayError> {
    let secret_present =
        !c.secret_id.is_empty() && state.service.store().get_secret(&c.secret_id)?.is_some();
    let mut body = json!({
        "id": c.id,
        // Back-compat alias for older clients that keyed on `resource`.
        "resource": c.id,
        "connector": c.connector,
        "name": c.name,
        "label": c.label,
        "capabilities": c.capabilities,
        "capability_count": c.capabilities.len(),
        "disabled_capabilities": c.disabled_capabilities,
        "disabled": c.disabled,
        "allowed_hosts": c.allowed_hosts,
        "secret_present": secret_present,
        "status": if c.disabled {
            "disabled"
        } else if secret_present {
            "healthy"
        } else {
            "disconnected"
        },
        "created_at": c.created_at,
        "redact_fields": c.redact_fields,
        "source": c.source,
    });
    let (base_url, pinned_hosts) = connection_pins(state.service.store().as_ref(), &c.id)?;
    body["base_url"] = json!(base_url);
    body["pinned_hosts"] = json!(pinned_hosts);
    // Capabilities whose every call is refused because they send this family's credential off its hosts: the console says to add the connection again as an import under its own id.
    body["pinned_elsewhere"] = json!(crate::posture_floor::pinned_elsewhere(state.service.store().as_ref(), c)?);
    let moved: Vec<serde_json::Value> = state.service.store().get_meta("last_posture_floor_pass")?
        .and_then(|text| serde_json::from_str::<Vec<serde_json::Value>>(&text).ok()).unwrap_or_default()
        .into_iter().filter(|m| m["connection"].as_str() == Some(c.id.as_str())).collect();
    body["posture_floor_changes"] = json!(moved);
    if c.connector == "ssh" {
        for cap_id in &c.capabilities {
            let Some(cap) = state.service.store().get_capability(cap_id)? else { continue };
            if let Some(spec) = cap.ssh {
                body["ssh"] = json!({
                    "host": spec.target.host,
                    "port": spec.target.port,
                    "user": spec.target.user,
                    "password_auth": spec.credential_kind == SshCredentialKind::Password,
                    "host_key_verified": !matches!(spec.target.host_key, SshHostKey::Insecure),
                });
                break;
            }
        }
    }
    Ok(body)
}

/// Where connection `id` sends its credential, read from its capabilities: see [`crate::connectors::connection_pins`].
pub(crate) fn connection_pins(store: &dyn Store, id: &str) -> Result<(Option<String>, Vec<String>), GatewayError> {
    let Some(connection) = store.get_connection(id)? else { return Ok((None, Vec::new())) };
    let mut caps = Vec::new();
    for cap_id in &connection.capabilities {
        caps.extend(store.get_capability(cap_id)?);
    }
    Ok(crate::connectors::connection_pins(&connection.connector, &caps))
}

/// Handler for `GET /v1/connections`. Lists the first-class stored connections.
pub async fn list_connections(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let mut connections = state.service.store().list_connections()?;
    connections.sort_by(|a, b| a.id.cmp(&b.id));
    let out: Vec<_> = connections
        .iter()
        .map(|c| connection_json(&state, c))
        .collect::<Result<_, _>>()?;
    Ok(Json(json!({ "connections": out })))
}

/// `GET /v1/connections/:id`: one connection plus the policies scoped to it.
///
/// An agent session sees a connection only when one of its own enabled grants activates a policy on
/// it, and then only those policies: another agent's policy on the same connection is not something
/// this one can be held to. Anything else answers as if the connection did not exist, so the route
/// cannot be used to probe for what is configured. A Pending agent reaches nothing.
pub async fn get_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let session = authed(&state, &headers)?;
    let store = state.service.store();
    let not_found = || GatewayError::NotFound(format!("connection '{id}'"));
    let connection = store.get_connection(&id)?.ok_or_else(not_found)?;
    let mut policies = store.policies_for_connection(&id)?;
    if session.role != SessionRole::Operator {
        let reached = agent_policy_ids(store.as_ref(), &session.agent_id)?;
        policies.retain(|p| reached.contains(&p.id));
        if policies.is_empty() {
            return Err(not_found());
        }
    }
    let mut body = connection_json(&state, &connection)?;
    body["policies"] = json!(policies);
    Ok(Json(body))
}

/// The policies `agent_id`'s own enabled grants activate, or none at all unless it is approved.
fn agent_policy_ids(store: &dyn Store, agent_id: &str) -> Result<std::collections::HashSet<String>, GatewayError> {
    if !matches!(store.get_agent(agent_id)?, Some(a) if a.status == AgentStatus::Approved) {
        return Ok(Default::default());
    }
    Ok(store
        .list_grants()?
        .into_iter()
        .filter(|g| g.enabled && g.targets(agent_id))
        .flat_map(|g| g.policy_ids)
        .collect())
}

/// The capabilities the connectors crate exposes for a known connector family, configured
/// for a new connection id + secret. Unknown connectors get no preset capabilities (the
/// operator/connector can register them later). This is what "Add connection" populates.
pub(crate) fn connector_capabilities(connector: &str, resource: &str, secret_id: &str) -> Vec<Capability> {
    use crate::connectors::{
        BraintreeConnector, Connector, FalConnector, GenericHttpConnector, GitHubConnector,
        VercelConnector,
    };
    match connector {
        "github" => GitHubConnector::new(resource, secret_id).capabilities(),
        "braintree" => BraintreeConnector::new(resource, secret_id).capabilities(),
        "vercel" => VercelConnector::new(resource, secret_id).capabilities(),
        "fal" => FalConnector::new(resource, secret_id).capabilities(),
        "generic-http" | "generic_http" | "http" => {
            GenericHttpConnector::new(resource, secret_id).capabilities()
        }
        _ => Vec::new(),
    }
}

/// Refuse a connection whose capabilities would run a local program, on a hosted worker.
///
/// Nothing in Permaura's own container is worth executing, and the credential would reach a child
/// process environment. No preset in [`connector_capabilities`] yields a `Command` capability today,
/// so this cannot fire through the built-in connectors; the live entry point for one is a vault
/// bundle, which refuses them on hosted in [`crate::vault_bundle`]. It is here so that registering a
/// CLI preset (the connectors crate already carries one) does not silently open the hole.
fn refuse_command_caps_on_hosted(hosted: bool, caps: &[Capability]) -> Result<(), GatewayError> {
    if hosted
        && caps.iter().any(|c| matches!(c.kind, permaura_connectors::CapabilityKind::Command))
    {
        return Err(GatewayError::BadRequest(
            "command connectors are not available on a hosted gateway: the container has nothing \
             to run and the credential would reach a child process"
                .to_string(),
        ));
    }
    Ok(())
}

/// Refuse an SSH host that is not a public address, on a hosted worker. The worker is Permaura's machine,
/// so the metadata server, its own loopback and the VPC are not a tenant's to dial; a gateway its owner
/// runs keeps its LAN. Screened again before every dial, against the address the name resolves to.
fn refuse_non_public_ssh_on_hosted(hosted: bool, host: &str) -> Result<(), GatewayError> {
    if !hosted {
        return Ok(());
    }
    crate::connectors::screen_host(host).map_err(|e| {
        GatewayError::BadRequest(format!(
            "a hosted gateway opens SSH sessions to public addresses only, so '{host}' is refused ({e})"
        ))
    })
}

/// Body for `POST /v1/connections`: add a configured integration instance.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateConnectionReq {
    /// Optional explicit connection id (defaults to a slug of the name).
    #[serde(default)]
    pub id: Option<String>,
    /// The connector family (`github`, `braintree`, `vercel`, `fal`, `generic-http`, `ssh`).
    pub connector: String,
    /// The operator-chosen instance name.
    pub name: String,
    /// An honest label for the connector (defaults to a title-cased connector name).
    #[serde(default)]
    pub label: Option<String>,
    /// Required when `connector == "ssh"`: the host/user/host-key + the exec and SFTP capabilities
    /// this SSH connection exposes. The credential (private key or password) is uploaded afterward
    /// via `POST …/credential`, exactly like every other connector.
    #[serde(default)]
    pub ssh: Option<SshConnectionConfig>,
    /// The operator host allowlist (host names, no scheme/path; `*.` allowed for subdomains).
    /// **Required and non-empty for generic-HTTP connections**: their target host is
    /// agent-supplied, so without an allowlist the proxy is an open egress hole. Optional for
    /// typed connectors (whose host is pinned), where it acts as an extra restriction.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

/// The SSH-specific half of [`CreateConnectionReq`]. Host, port, user and host-key are pinned here,
/// server-side, never agent-supplied. Each `exec` entry becomes its own risk-tiered, policy-able
/// capability (there is no free-form remote command).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshConnectionConfig {
    /// The host to dial.
    pub host: String,
    /// The SSH port (defaults to 22).
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// The remote login user.
    pub user: String,
    /// The expected SHA256 host-key fingerprint (required unless `insecure` is set).
    #[serde(default)]
    pub host_key_sha256: Option<String>,
    /// Explicitly disable host-key verification (dev/local only). Fail-closed: without a fingerprint
    /// and without this flag, connection creation is rejected.
    #[serde(default)]
    pub insecure: bool,
    /// Treat the uploaded credential as a password rather than a private key.
    #[serde(default)]
    pub password_auth: bool,
    /// When set, expose path-scoped `sftp.get`/`sftp.put`/`sftp.list` under this root.
    #[serde(default)]
    pub sftp_root: Option<String>,
    /// Per-transfer byte cap for SFTP (defaults to the connector default).
    #[serde(default)]
    pub sftp_max_bytes: Option<u64>,
    /// The exec commands to expose (each a distinct capability).
    #[serde(default)]
    pub exec: Vec<SshExecReq>,
}

/// One exec command in an [`SshConnectionConfig`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshExecReq {
    /// The capability id suffix after `ssh.`, e.g. `uptime`, `restart-service`.
    pub action: String,
    /// Human description (defaults to a generic one).
    #[serde(default)]
    pub description: String,
    /// The pinned remote-command argv template (`{name}` slots filled from allow-listed params).
    pub args_template: Vec<String>,
    /// The placeholder names an agent may fill.
    #[serde(default)]
    pub allowed_placeholders: Vec<String>,
    /// Risk tier (defaults to `High`: fail-safe, so it auto-escalates to approval unless lowered).
    #[serde(default)]
    pub risk: Option<permaura_core::RiskTier>,
    /// Whether this command always escalates to human approval.
    #[serde(default)]
    pub requires_approval: bool,
}

fn default_ssh_port() -> u16 {
    22
}

/// An exec command's allow-list, once each, refusing a template slot it does not allow (every call would fail on it) and an allowed name the template never fills (an agent would be told to send a value nothing reads).
fn ssh_exec_placeholders(e: &SshExecReq) -> Result<Vec<String>, GatewayError> {
    let mut slots = Vec::new();
    for element in &e.args_template {
        match element.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
            Some(name) => slots.push(name.to_string()),
            None if element.contains('{') || element.contains('}') => {
                return Err(GatewayError::BadRequest(format!("ssh exec '{}' has a malformed template element '{element}'", e.action)));
            }
            None => {}
        }
    }
    if let Some(slot) = slots.iter().find(|s| !e.allowed_placeholders.contains(s)) {
        return Err(GatewayError::BadRequest(format!(
            "ssh exec '{}' fills {{{slot}}}, which allowed_placeholders does not list",
            e.action
        )));
    }
    let mut allowed: Vec<String> = Vec::new();
    for name in &e.allowed_placeholders {
        if !slots.contains(name) {
            return Err(GatewayError::BadRequest(format!(
                "ssh exec '{}' allows '{name}', which its template never fills",
                e.action
            )));
        }
        if !allowed.contains(name) {
            allowed.push(name.clone());
        }
    }
    Ok(allowed)
}

/// Build an [`SshConnector`] from an operator's [`SshConnectionConfig`], rejecting an unsafe or
/// empty configuration. The host-key policy is fail-closed: a fingerprint is required unless the
/// operator explicitly opts into `insecure`.
fn build_ssh_connector(
    id: &str,
    secret_id: &str,
    cfg: &SshConnectionConfig,
) -> Result<SshConnector, GatewayError> {
    let fingerprint = cfg.host_key_sha256.as_ref().filter(|s| !s.trim().is_empty());
    if cfg.insecure && fingerprint.is_some() {
        return Err(GatewayError::BadRequest(
            "give an ssh connection 'host_key_sha256' or \"insecure\": true, not both: insecure would drop the fingerprint".into(),
        ));
    }
    if cfg.sftp_max_bytes.is_some() && cfg.sftp_root.is_none() {
        return Err(GatewayError::BadRequest("'sftp_max_bytes' limits SFTP, which only an 'sftp_root' exposes".into()));
    }
    let host_key = if cfg.insecure {
        SshHostKey::Insecure
    } else if let Some(fp) = fingerprint {
        SshHostKey::Fingerprint { sha256: fp.clone() }
    } else {
        return Err(GatewayError::BadRequest(
            "ssh connection requires 'host_key_sha256' (or an explicit \"insecure\": true for dev)".into(),
        ));
    };
    refuse_longer_than("ssh host", &cfg.host, MAX_SSH_HOST_BYTES)?;
    refuse_longer_than("ssh user", &cfg.user, MAX_SSH_USER_BYTES)?;
    if let SshHostKey::Fingerprint { sha256 } = &host_key {
        refuse_longer_than("ssh host_key_sha256", sha256, MAX_SSH_HOST_KEY_BYTES)?;
    }
    if cfg.exec.is_empty() && cfg.sftp_root.is_none() {
        return Err(GatewayError::BadRequest(
            "ssh connection exposes nothing: provide at least one 'exec' command or an 'sftp_root'".into(),
        ));
    }
    let mut conn = SshConnector::new(
        id,
        secret_id,
        SshTarget { host: cfg.host.clone(), port: cfg.port, user: cfg.user.clone(), host_key },
    );
    if cfg.password_auth {
        conn.credential_kind = SshCredentialKind::Password;
    }
    for e in &cfg.exec {
        refuse_long_name("ssh exec action", &e.action)?;
        if e.args_template.is_empty() {
            return Err(GatewayError::BadRequest(format!(
                "ssh exec '{}' has an empty args_template",
                e.action
            )));
        }
        let allowed = ssh_exec_placeholders(e)?;
        conn = conn.with_exec(SshExecCommand {
            action: e.action.clone(),
            description: if e.description.is_empty() {
                format!("SSH: run '{}' on the remote host", e.action)
            } else {
                e.description.clone()
            },
            risk: e.risk.unwrap_or(permaura_core::RiskTier::High),
            requires_approval: e.requires_approval,
            args_template: e.args_template.clone(),
            allowed_placeholders: allowed,
        });
    }
    if let Some(root) = &cfg.sftp_root {
        // An empty or relative root would let `join_scoped` anchor every agent path at the
        // filesystem root ("" + "/etc/passwd"), silently defeating containment; require an
        // absolute path (mirroring the non-empty treatment already applied to host_key_sha256).
        let root = root.trim();
        if root.is_empty() || !root.starts_with('/') {
            return Err(GatewayError::BadRequest(
                "ssh 'sftp_root' must be a non-empty absolute path".into(),
            ));
        }
        conn = conn.with_sftp(root, cfg.sftp_max_bytes.unwrap_or(DEFAULT_SFTP_MAX_BYTES));
    }
    Ok(conn)
}

/// Validate an operator-supplied allowlist entry: a bare host name (optionally a `*.` wildcard),
/// never a scheme, path, port, or whitespace. Returns the normalised (lower-cased, trimmed) entry.
fn validate_allowed_host(entry: &str) -> Result<String, GatewayError> {
    let e = entry.trim().to_ascii_lowercase();
    if e.is_empty()
        || e.contains("://")
        || e.contains('/')
        || e.contains(':')
        || e.contains('@')
        || e.contains('\\')
        || e.contains(|c: char| c.is_whitespace() || c.is_control())
    {
        return Err(GatewayError::BadRequest(format!(
            "invalid allowed_hosts entry '{entry}': use a bare host name like 'api.example.com' or '*.example.com'"
        )));
    }
    Ok(e)
}

/// Refuse binding a connection to a slot that already holds a credential, sealed here or held by an external custodian: the binding sends it to a host and auth kind of the caller's choosing, so it is a credential move, and while a device is trusted and approvals are not opted down it is refused on the operator token alone too.
/// An externally held slot counts because deleting a connection never removes its enrolment.
fn refuse_binding_an_existing_secret(
    state: &AppState,
    op: &Session,
    remote: bool,
    taker: &str,
    secret_id: &str,
) -> Result<(), GatewayError> {
    let sealed_here = state.service.store().get_secret(secret_id)?.is_some();
    if !sealed_here && !state.service.backend().holds_externally(secret_id)? {
        return Ok(());
    }
    refuse_a_credential_move(state, op, remote, &format!("{taker} would take over the credential already in '{secret_id}'"))?;
    if !state.service.vault_export_hold_required() {
        return Ok(());
    }
    let remedy = if sealed_here {
        "delete the old credential first (the device signs that)"
    } else {
        "lower the approval floor to approve while you create it (the device signs that)"
    };
    Err(GatewayError::Denied(format!(
        "a device is paired with this gateway and '{secret_id}' already holds a credential, so {taker} may not take it over on the operator token alone. Choose another connection id, or {remedy}."
    )))
}

const NEW_CONNECTION: &str = "a new connection";

/// The slot `connection` presents: its own `secret_id`, or for one that names none the derived slot, which binds whatever is stored there and so is held to [`refuse_binding_an_existing_secret`]; never a staged one.
fn connection_slot(state: &AppState, op: &Session, remote: bool, connection: &Connection) -> Result<String, GatewayError> {
    let slot = if connection.secret_id.is_empty() {
        derived_secret_slot(&connection.id)
    } else {
        connection.secret_id.clone()
    };
    crate::secret_inventory::refuse_staging_secret_id("the secret bound by connection", &slot)?;
    if connection.secret_id.is_empty() {
        let taker = format!("connection '{}', which has no credential of its own yet,", connection.id);
        refuse_binding_an_existing_secret(state, op, remote, &taker, &slot)?;
    }
    Ok(slot)
}

/// Handler for `POST /v1/connections`. Creates the connection and registers the connector's
/// capabilities against it. No credential yet: the connection starts **Disconnected** until
/// `POST …/credential` adds one.
pub async fn create_connection(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<CreateConnectionReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let id = req
        .id
        .unwrap_or_else(|| slugify(&format!("{}-{}", req.connector, req.name)));
    refuse_long_name("connection id", &id)?;
    refuse_reserved_id("connection", &id)?;
    if store.get_connection(&id)?.is_some() {
        return Err(GatewayError::BadRequest(format!("connection '{id}' already exists")));
    }
    state
        .service
        .refuse_if_over_allowance(crate::allowances::Allowance::Connections, Some(&op))?;
    // Normalise + validate the host allowlist, and require a non-empty one for the generic-HTTP
    // proxy: its target host is agent-supplied, so an empty allowlist is an open egress hole.
    let allowed_hosts: Vec<String> = req
        .allowed_hosts
        .iter()
        .map(|h| validate_allowed_host(h))
        .collect::<Result<_, _>>()?;
    if crate::connectors::is_generic_http_connector(&req.connector) && allowed_hosts.is_empty() {
        return Err(GatewayError::BadRequest(
            "a generic-HTTP connection requires a non-empty allowed_hosts allowlist (its target host is agent-supplied)".to_string(),
        ));
    }
    if req.ssh.is_some() && req.connector != "ssh" {
        return Err(GatewayError::BadRequest("'ssh' configuration applies only to an SSH connection".into()));
    }
    let builds_its_own = crate::connectors::connector::family_base_url(&req.connector).is_some()
        || req.connector == "ssh"
        || crate::connectors::is_generic_http_connector(&req.connector);
    if !builds_its_own
        && (names_a_self_built_family(&req.connector)
            || crate::presets::catalog().get(&req.connector).is_some()
            || store.get_connector_manifest(&req.connector)?.is_some())
    {
        return Err(GatewayError::BadRequest(format!(
            "'{}' connections are built from its catalog entry or its own import, which pin the host its credential is sent to; create one through that route rather than by hand",
            req.connector
        )));
    }
    let secret_id = derived_secret_slot(&id);
    // SSH connections carry their pinned host/user/host-key + capability set in the request; every
    // other family is a stateless preset keyed by name.
    use crate::connectors::Connector;
    let base_caps: Vec<Capability> = if req.connector == "ssh" {
        let cfg = req.ssh.as_ref().ok_or_else(|| {
            GatewayError::BadRequest("connector 'ssh' requires an 'ssh' config block".into())
        })?;
        // The length first: the hosted screen's refusal names the host.
        refuse_longer_than("ssh host", &cfg.host, MAX_SSH_HOST_BYTES)?;
        refuse_non_public_ssh_on_hosted(state.hosted, &cfg.host)?;
        build_ssh_connector(&id, &secret_id, cfg)?.capabilities()
    } else {
        connector_capabilities(&req.connector, &id, &secret_id)
    };
    // Before any capability is written, or a refusal would leave orphans behind.
    refuse_command_caps_on_hosted(state.hosted, &base_caps)?;
    for host in crate::connectors::connection_pins(&req.connector, &base_caps).1 {
        refuse_family_elsewhere(&req.connector, Some(host))?;
    }
    // Namespace each capability id by the connection id so two instances of the same
    // connector (e.g. two GitHub accounts) never collide in the global catalog. The action
    // segment after the first dot is preserved, so policies still key on `pull_requests.list`.
    let caps: Vec<Capability> = base_caps
        .into_iter()
        .map(|mut c| {
            if let Some((_, action)) = c.id.split_once('.') {
                c.id = format!("{id}.{action}");
            }
            c
        })
        .collect();
    let mut capability_ids: Vec<String> = caps.iter().map(|c| c.id.clone()).collect();
    capability_ids.sort();
    let connection = Connection {
        id: id.clone(),
        connector: req.connector.clone(),
        name: req.name,
        label: req.label.unwrap_or_else(|| title_case(&req.connector)),
        secret_id,
        capabilities: capability_ids,
        disabled_capabilities: vec![],
        disabled: false,
        allowed_hosts,
        created_at: now_ms(),
        redact_fields: Vec::new(),
        source: None,
        // Every connector this route accepts is built from the gateway's own code: a catalog or installed id is refused above.
        made_from: Some(permaura_core::CatalogOrigin::BuiltIn),
    };
    // One unit: a connection is never left half-built, and a snapshotting store uploads once.
    refuse_reserved_capabilities(&caps)?;
    refuse_long_connection_names(&connection.id, &connection.name, &connection.label)?;
    refuse_over_capability_bytes(&state, store.as_ref(), &caps, 0, "remove a connection first")?;
    refuse_binding_an_existing_secret(&state, &op, remote, NEW_CONNECTION, &connection.secret_id)?;
    store.transaction(|store| {
        for cap in &caps {
            store.put_capability(cap.clone())?;
        }
        store.put_connection(connection)
    })?;
    Ok((StatusCode::CREATED, Json(json!({ "connection_id": id }))))
}

/// Body for `POST /v1/connections/import-openapi`: no-code connector authoring from an OpenAPI
/// document, pasted as `spec` or read from the host the operator binds with `url` / `spec_url`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportOpenApiReq {
    /// Operator-chosen display name.
    pub name: String,
    /// The connection id (and capability-id prefix), e.g. `payments`. Defaults to a slug of `name`.
    #[serde(default)]
    pub id: Option<String>,
    /// Honest label for the connector (defaults to the name), cut to 128 bytes between characters.
    #[serde(default)]
    pub label: Option<String>,
    /// The OpenAPI 3.x document as raw text (JSON or YAML). Not together with `url` or `spec_url`.
    #[serde(default)]
    pub spec: Option<String>,
    /// The URL the operator binds. Without `spec_url` its host is probed for a document; either way
    /// every server the document names must be on it.
    #[serde(default)]
    pub url: Option<String>,
    /// Where the document is, on the bound host.
    #[serde(default)]
    pub spec_url: Option<String>,
    /// Which of the document's servers to pin, or the base for a document whose servers can't be
    /// pinned as written.
    #[serde(default)]
    pub base_url: Option<String>,
    /// How the credential is presented upstream, replacing what `securitySchemes` implies.
    #[serde(default, deserialize_with = "crate::request_body::strict_auth")]
    pub auth: Option<crate::connectors::AuthScheme>,
    /// The `digest` of the dry run the operator reviewed. A create refuses with 409 when the document
    /// has changed since, so what is stored is what was shown, and with 400 when a document read from
    /// `url` / `spec_url` comes without one. A pasted `spec` is the document itself and needs none.
    #[serde(default)]
    pub digest: Option<String>,
    /// Derive and return the preview without persisting anything.
    #[serde(default)]
    pub dry_run: bool,
}

/// `POST /v1/connections/import-openapi`: derive a typed connection + capabilities from an OpenAPI
/// document and return a review preview (each capability's method, path, action, risk, and whether it
/// requires approval or starts disabled), plus the pinned `base_url`, the candidate `servers`, the
/// chosen `auth`, `warnings` and the document's `digest`. `dry_run` persists nothing; otherwise the
/// connection is stored with its writes disabled and its `source` recorded. With several servers and
/// no `base_url`, a dry run answers `base_url: null` and a create answers 400 listing them. The
/// credential is added afterwards via `POST …/credential`. Operator-only.
pub async fn import_openapi_connection(
    State(state): State<AppState>,
    Extension(RemoteFlag(caller_remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ImportOpenApiReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(GatewayError::BadRequest("name is required".into()));
    }
    let id = req.id.as_deref().map(str::trim).map(str::to_string).unwrap_or_else(|| slugify(&name));
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(GatewayError::BadRequest(format!(
            "id '{id}' must be letters, digits, '_' or '-': it prefixes every capability id"
        )));
    }
    let label = cut_label(req.label.clone().unwrap_or_else(|| name.clone()));
    refuse_long_connection_names(&id, &name, &label)?;
    refuse_reserved_id("connection", &id)?;
    if store.get_connection(&id)?.is_some() {
        return Err(GatewayError::BadRequest(format!("connection '{id}' already exists")));
    }
    // Before the fetch and the parse, not after: reading an OpenAPI document is the expensive part of
    // this route and a tenant at its ceiling should not pay for it, on a dry run either.
    state
        .service
        .refuse_if_over_allowance(crate::allowances::Allowance::Connections, Some(&op))?;

    let remote = req.url.is_some() || req.spec_url.is_some();
    if req.spec.is_some() && remote {
        return Err(GatewayError::BadRequest(
            "send the document as spec, or where to find it as url/spec_url, not both".into(),
        ));
    }
    if req.spec.is_none() && !remote {
        return Err(GatewayError::BadRequest("spec, url or spec_url is required".into()));
    }
    // A document read from the bound host can change after the review, so nothing read from it is stored unless the create names the review it matches, and a create that will be refused fetches nothing. A pasted document is the document itself.
    if remote && !req.dry_run && req.digest.is_none() {
        return Err(GatewayError::BadRequest(
            "digest is required to create from url or spec_url: run the dry run, review it, and send the digest it returned, so what is stored is the document that was reviewed".into(),
        ));
    }
    let (doc, spec_url, bound_host) = match req.spec {
        Some(_) if remote => {
            return Err(GatewayError::BadRequest(
                "send the document as spec, or where to find it as url/spec_url, not both".into(),
            ))
        }
        Some(spec) => (spec.into_bytes(), None, None),
        None if remote => {
            let fetched =
                crate::openapi::fetch_document(state.service.http().as_ref(), req.url.as_deref(), req.spec_url.as_deref())
                    .await
                    .map_err(GatewayError::BadRequest)?;
            (fetched.bytes, Some(fetched.url), Some(fetched.bound_host))
        }
        None => return Err(GatewayError::BadRequest("spec, url or spec_url is required".into())),
    };
    let digest = crate::openapi::digest(&doc);
    if let Some(reviewed) = req.digest.as_deref() {
        if reviewed != digest {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "the document has changed since it was reviewed; run the dry run again",
                    "digest": digest,
                })),
            ));
        }
    }

    let secret_id = derived_secret_slot(&id);
    let mut derived = crate::openapi::derive(
        &doc,
        &crate::openapi::DeriveOptions {
            connection_id: id.clone(),
            secret_id: secret_id.clone(),
            spec_url: spec_url.clone(),
            bound_host,
            base_url: req.base_url.clone(),
            auth: req.auth.clone(),
        },
    )
    .map_err(GatewayError::BadRequest)?;
    for (at, why) in leave_out_long_capability_ids(&mut derived.capabilities, &mut derived.disabled_capabilities) {
        derived.warnings.push(format!("{at}: {why}"));
    }
    refuse_over_capability_bounds(&state, store.as_ref(), &derived.capabilities)?;

    let preview: Vec<serde_json::Value> = derived
        .capabilities
        .iter()
        .map(|c| {
            let http = c.http.as_ref();
            json!({
                "id": c.id,
                "description": c.description,
                "method": http.map(|h| h.method),
                "path": http.map(|h| h.path.as_str()),
                "action": c.action,
                "risk": c.risk,
                "requires_approval": c.requires_approval,
                "disabled": derived.disabled_capabilities.contains(&c.id),
            })
        })
        .collect();
    let mut body = json!({
        "spec_url": spec_url,
        "base_url": derived.base_url,
        "servers": derived.servers,
        "auth": derived.auth,
        "capabilities": preview,
        "warnings": derived.warnings,
        "digest": digest,
    });
    if req.dry_run {
        return Ok((StatusCode::OK, Json(body)));
    }
    if derived.base_url.is_none() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "bad request: the document names {} servers; choose one with base_url: {}",
                    derived.servers.len(),
                    derived.servers.join(", ")
                ),
                "servers": derived.servers,
            })),
        ));
    }

    let mut capability_ids: Vec<String> = derived.capabilities.iter().map(|c| c.id.clone()).collect();
    capability_ids.sort();
    let now = now_ms();
    let connection = Connection {
        id: id.clone(),
        connector: "openapi".to_string(),
        label,
        name,
        secret_id,
        capabilities: capability_ids,
        disabled_capabilities: derived.disabled_capabilities.clone(),
        disabled: false,
        allowed_hosts: Vec::new(), // typed connector: upstream host is pinned in each HttpSpec
        created_at: now,
        redact_fields: Vec::new(),
        source: Some(permaura_core::ConnectionSource {
            kind: permaura_core::SourceKind::Openapi,
            url: spec_url.unwrap_or_default(),
            rest_root: None,
            namespaces: Vec::new(),
            abilities: false,
            digest: Some(digest),
            synced_at: now,
        }),
        made_from: Some(permaura_core::CatalogOrigin::Discovered),
    };
    refuse_reserved_capabilities(&derived.capabilities)?;
    refuse_binding_an_existing_secret(&state, &op, caller_remote, NEW_CONNECTION, &connection.secret_id)?;
    store.transaction(|store| {
        for cap in &derived.capabilities {
            store.put_capability(cap.clone())?;
        }
        store.put_connection(connection)
    })?;

    body["connection_id"] = json!(id);
    Ok((StatusCode::CREATED, Json(body)))
}

/// Refuse an import whose operations are more than one import takes, or whose capabilities would take the gateway's capability rows past their ceiling. On a dry run too, so the preview says so before anything is asked for.
fn refuse_over_capability_bounds(state: &AppState, store: &dyn Store, capabilities: &[Capability]) -> Result<(), GatewayError> {
    let limits = state.limits.config();
    if capabilities.len() > limits.openapi_operations {
        return Err(GatewayError::TooLarge(format!(
            "the document describes {} operations, and one import takes at most {}; import a document that describes fewer",
            capabilities.len(),
            limits.openapi_operations
        )));
    }
    refuse_over_capability_bytes(state, store, capabilities, 0, "remove a connection or import a document that describes fewer operations")
}

/// Refuse writing `capabilities`, in place of rows taking `replacing` bytes, when the gateway's capability rows would grow past their ceiling ([`crate::limits::LimitsConfig::capability_bytes`]). Every path that writes capability rows asks it first: an import, a connection, a preset, a WordPress site and its re-sync, and an SSH target patch.
/// A write that adds nothing to what the rows take is never refused, so a gateway already past its ceiling can still re-sync a site that has not changed.
fn refuse_over_capability_bytes<'a>(
    state: &AppState,
    store: &dyn Store,
    capabilities: impl IntoIterator<Item = &'a Capability>,
    replacing: u64,
    remedy: &str,
) -> Result<(), GatewayError> {
    refuse_over_capability_ceiling(state.limits.config().capability_bytes, store, capabilities, replacing, remedy)
}

/// [`refuse_over_capability_bytes`] against `ceiling`, for a writer that has no [`AppState`]: a held change applied on its approval.
fn refuse_over_capability_ceiling<'a>(
    ceiling: u64,
    store: &dyn Store,
    capabilities: impl IntoIterator<Item = &'a Capability>,
    replacing: u64,
    remedy: &str,
) -> Result<(), GatewayError> {
    let (count, adding) = capabilities
        .into_iter()
        .fold((0usize, 0u64), |(n, bytes), cap| (n + 1, bytes + crate::store::capability_row_bytes(cap)));
    if adding <= replacing {
        return Ok(());
    }
    let held = store.capability_bytes()?;
    if held.saturating_sub(replacing).saturating_add(adding) > ceiling {
        return Err(GatewayError::TooLarge(format!(
            "these {count} capabilities take {adding} bytes, and with the {held} bytes this gateway's capabilities already take that is more than its {ceiling}-byte ceiling; {remedy}",
        )));
    }
    Ok(())
}

/// A short display label for an auth scheme, for the marketplace card/detail.
fn auth_label(a: &crate::connectors::AuthScheme) -> &'static str {
    use crate::connectors::AuthScheme::*;
    match a {
        Bearer => "bearer",
        Basic { .. } => "basic",
        ApiKeyHeader { .. } => "api-key (header)",
        ApiKeyQuery { .. } => "api-key (query)",
        Raw { .. } => "header token",
    }
}

/// Render one preset as marketplace JSON: the card metadata plus the classified capability list and
/// safe/gated counts (gated = disabled-by-default or approval-required). No connection is created.
fn preset_json(p: &crate::presets::Preset) -> serde_json::Value {
    let caps = p.preview();
    let gated = caps.iter().filter(|c| c.disabled || c.requires_approval).count();
    let safe = caps.len() - gated;
    let cap_json: Vec<_> = caps
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "description": c.description,
                "method": c.method,
                "path": c.path,
                "action": c.action,
                "risk": c.risk,
                "requires_approval": c.requires_approval,
                "disabled": c.disabled,
            })
        })
        .collect();
    json!({
        "id": p.id,
        "name": p.name,
        "label": p.label(),
        "vertical": p.vertical,
        "description": p.description,
        "base_url": p.base_url,
        "auth": auth_label(&p.auth),
        "logo": p.logo,
        "brand_color": p.brand_color,
        // The connector advertises OAuth when it carries OAuth metadata; `oauth_pkce` says whether the
        // zero-knowledge "Permaura app" layer is possible. Whether the *Managed* (hosted) layer is
        // offered is a separate web-side availability flag, not encoded here.
        "oauth_supported": p.oauth.is_some(),
        "oauth_pkce": p.oauth.as_ref().map(|o| o.pkce).unwrap_or(false),
        "wordpress": p.wordpress.as_ref().map(|w| json!({ "namespace": w.namespace })),
        // A WordPress preset's host is the operator's site and a templated `base_url` names none at all, so `from-preset` refuses either without the missing piece and the console must ask for it.
        "base_url_required": p.wordpress.is_some() || p.base_url.contains('{'),
        "safe_count": safe,
        "gated_count": gated,
        "capabilities": cap_json,
    })
}

/// `GET /v1/presets`, the marketplace catalog: every bundled preset with its pinned host, auth
/// scheme, and classified capabilities (which are safe-by-default reads vs gated risky verbs).
/// Operator-only, like the rest of the console surface.
pub async fn list_presets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    // Union: bundled presets plus installed manifests, installed shadowing a bundled preset of the
    // same id. A bundled preset is `provenance: builtin`; an installed one carries its stored
    // provenance (signed by Permaura, or user-provided).
    let installed = store.list_connector_manifests()?;
    let installed_ids: std::collections::HashSet<&str> =
        installed.iter().map(|m| m.manifest.id.as_str()).collect();
    let mut presets: Vec<serde_json::Value> = Vec::new();
    for p in crate::presets::catalog().list() {
        if installed_ids.contains(p.id.as_str()) {
            continue; // shadowed by an installed manifest
        }
        let mut j = preset_json(p);
        j["provenance"] = json!("builtin");
        presets.push(j);
    }
    for m in &installed {
        let mut j = preset_json(&m.preset());
        j["provenance"] = serde_json::to_value(&m.provenance).unwrap_or(json!("user"));
        j["version"] = json!(m.version);
        j["revoked"] = json!(state.pmconn_revocation.refuses_installed(m));
        presets.push(j);
    }
    Ok(Json(json!({ "presets": presets })))
}

/// Resolve a preset id to an owned [`crate::presets::Preset`], preferring an installed manifest over
/// a bundled preset of the same id, so `from-preset` instantiates installed connectors identically,
/// with the origin the connection records.
fn resolve_preset(
    store: &std::sync::Arc<dyn Store>,
    id: &str,
) -> Result<Option<(crate::presets::Preset, permaura_core::CatalogOrigin)>, GatewayError> {
    if let Some(m) = store.get_connector_manifest(id)? {
        let key_id = match &m.provenance {
            crate::manifest::Provenance::Signed { key_id } => Some(key_id.clone()),
            crate::manifest::Provenance::User => None,
        };
        return Ok(Some((m.preset(), permaura_core::CatalogOrigin::Installed { version: m.version, key_id })));
    }
    Ok(crate::presets::catalog().get(id).cloned().map(|p| (p, permaura_core::CatalogOrigin::BuiltIn)))
}

/// A connector/preset id must be `^[a-z0-9][a-z0-9._-]{0,63}$`: it flows into URLs, policy keys, and
/// the `connector.action` capability id form. Mirrors the web authoring validator and the gateway's
/// own `sanitize_id_segment` convention, and (unlike trimming) leaves no whitespace variants.
fn is_valid_connector_id(id: &str) -> bool {
    let mut chars = id.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Body for `POST /v1/connectors/install`: install a connector manifest at runtime. The manifest is
/// received as a raw JSON value (not a typed `Preset`) so the signature can be verified over the
/// bytes exactly as authored, before any deserialization materialises `#[serde(default)]` fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallConnectorReq {
    /// The connector definition (the `Preset` shape), as raw JSON.
    pub manifest: serde_json::Value,
    /// Monotonic version for this manifest id. A version ≤ the installed one is refused.
    pub version: u32,
    /// base64 Ed25519 signature over the canonical `{manifest, version}` bytes. Absent ⇒ user-provided.
    #[serde(default)]
    pub signature: Option<String>,
    /// The `key_id` the signature was produced with (the intermediate id for a v2 chained envelope).
    #[serde(default)]
    pub key_id: Option<String>,
    /// v2 chained envelope: the root-signed intermediate certificate the leaf signature chains to.
    /// Absent for a v1 flat envelope (verified directly against a pinned leaf key).
    #[serde(default, deserialize_with = "crate::request_body::strict_cert")]
    pub cert: Option<crate::manifest::IntermediateCert>,
    /// The envelope format the signer wrote: 2 for a chained envelope, which carries `cert`, and 1 (or absent) for a flat one. Checked against the envelope rather than ignored.
    #[serde(default)]
    pub envelope_version: Option<u32>,
}

/// `POST /v1/connectors/install`: add a connector to this gateway's runtime catalog. A
/// Permaura-signed manifest is verified against a pinned key; an unsigned manifest is accepted as
/// `provenance: user`. Enforces monotonic versioning (no downgrade). A manifest decides where the
/// credential of every connection made from it is sent, so the install goes through [`apply_or_hold`]:
/// held for a device from off the host while one is required, refused there when nothing could hold it,
/// and recorded in the audit chain either way. Operator-only.
pub async fn install_connector(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<InstallConnectorReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    if req.signature.is_none() {
        let unsigned = [("cert", req.cert.is_some()), ("key_id", req.key_id.is_some()), ("envelope_version", req.envelope_version.is_some())];
        if let Some((member, _)) = unsigned.iter().find(|(_, given)| *given) {
            return Err(GatewayError::BadRequest(format!(
                "'{member}' belongs to a signed envelope and is read only with its signature; without one the manifest installs as user-provided, so send the whole envelope or none of it"
            )));
        }
    }
    if let (Some(key_id), Some(cert)) = (req.key_id.as_deref(), req.cert.as_ref()) {
        if key_id != cert.key_id {
            return Err(GatewayError::BadRequest(format!(
                "key_id '{key_id}' is not the certificate's key '{}', which the signature is checked against",
                cert.key_id
            )));
        }
    }
    match (req.envelope_version, req.cert.is_some()) {
        (None, _) | (Some(1), false) | (Some(2), true) => {}
        (Some(v @ (1 | 2)), _) => {
            return Err(GatewayError::BadRequest(format!(
                "envelope_version {v} does not describe this envelope: a version 2 envelope carries a cert and a version 1 envelope does not"
            )))
        }
        (Some(v), _) => return Err(GatewayError::BadRequest(format!("envelope_version {v} is not one this gateway reads (1 or 2)"))),
    }

    // Verify the signature over the manifest bytes EXACTLY as received, before deserializing (a
    // `Preset` round-trip would materialise default fields and diverge from what the signer signed).
    // Handles both the v1 flat envelope (pinned leaf key) and the v2 chained envelope (root-signed
    // intermediate cert + leaf), honouring the root-signed revocation list.
    let provenance = crate::manifest::verify_envelope(
        &req.manifest,
        req.version,
        req.signature.as_deref(),
        req.key_id.as_deref(),
        req.cert.as_ref(),
        &crate::manifest::pmconn_root_pubkeys(),
        &crate::manifest::pmconn_pubkeys(),
        &state.pmconn_revocation,
        now_ms(),
    )
    .map_err(GatewayError::BadRequest)?;

    let manifest: crate::presets::Preset = serde_json::from_value(req.manifest)
        .map_err(|e| GatewayError::BadRequest(format!("invalid manifest: {e}")))?;
    // Validate the id strictly rather than trimming: the guard, the store key, and the resolver must
    // all agree on the same id (a whitespace-padded id that trims for the guard but stores untrimmed
    // would silently bypass the monotonic-version check). Matches the web authoring charset.
    let id = manifest.id.clone();
    if !is_valid_connector_id(&id) {
        return Err(GatewayError::BadRequest(
            "manifest id must match ^[a-z0-9][a-z0-9._-]{0,63}$".into(),
        ));
    }
    if manifest.capabilities.is_empty() {
        return Err(GatewayError::BadRequest("manifest has no capabilities".into()));
    }
    refuse_method_overrides(&manifest.instantiate(&id, "sec_preview").capabilities)?;

    // A user-provided (unsigned) manifest must NOT take the id of a connector the gateway already
    // knows: a bundled preset, or a family it builds itself. Otherwise an operator could install
    // {id: "stripe", base_url: attacker-host} and silently replace the trusted built-in's identity +
    // pinned SSRF-guard base_url. Only a Permaura-signed manifest may update a built-in id.
    if matches!(provenance, crate::manifest::Provenance::User)
        && (crate::presets::catalog().get(&id).is_some() || names_a_self_built_family(&id))
    {
        return Err(GatewayError::BadRequest(format!(
            "'{id}' is a built-in connector; only a Permaura-signed manifest may replace it"
        )));
    }
    refuse_family_elsewhere(&id, crate::connectors::shown_host(&manifest.base_url))?;

    // Monotonic version: an installed manifest may only be replaced by a strictly-newer version.
    // This blocks an untrusted relay from replaying an older (e.g. pre-fix) signed manifest.
    if let Some(existing) = store.get_connector_manifest(&id)? {
        refuse_unsigned_over_signed(&id, &provenance, &existing)?;
        if req.version <= existing.version {
            return Err(GatewayError::BadRequest(format!(
                "version {} is not newer than the installed version {}",
                req.version, existing.version
            )));
        }
        refuse_unseating_a_revoked_connector(store.as_ref(), &state.service, &id)?;
    }

    let mutation = crate::policy_guard::Mutation::ConnectorInstall {
        manifest: serde_json::to_value(&manifest)
            .map_err(|e| GatewayError::Internal(format!("manifest could not be encoded: {e}")))?,
        version: req.version,
        provenance,
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::CREATED, Json(applied))),
    }
}

/// An unsigned manifest never replaces an installed Permaura-signed one under the same id: removing the signed one is its own control-plane change, held where one is required, and only then may an unsigned one take the id.
fn refuse_unsigned_over_signed(
    id: &str,
    provenance: &crate::manifest::Provenance,
    existing: &crate::manifest::InstalledManifest,
) -> Result<(), GatewayError> {
    if matches!(provenance, crate::manifest::Provenance::User)
        && matches!(existing.provenance, crate::manifest::Provenance::Signed { .. })
    {
        return Err(GatewayError::Conflict(format!(
            "'{id}' is installed as a Permaura-signed connector, and an unsigned manifest cannot replace it. Remove the installed connector first (that removal is a change of its own, held for a device where one is required), then install this one."
        )));
    }
    Ok(())
}

/// A revoked installed connector is neither removed nor replaced while a connection under its id records no origin: such a connection is refused only while the revoked manifest is installed there, so removing or replacing it would let that connection run again. A connection that records its origin is judged by that origin, so it neither blocks this nor changes with it, and one made from a built-in preset falls back to it.
fn refuse_unseating_a_revoked_connector(
    store: &dyn Store,
    service: &crate::service::EnforcementService,
    id: &str,
) -> Result<(), GatewayError> {
    let Some(why) = service.connector_revocation(id)? else { return Ok(()) };
    let unrecorded: Vec<String> = store
        .list_connections()?
        .into_iter()
        .filter(|c| c.connector == id && c.made_from.is_none())
        .map(|c| c.id)
        .collect();
    if unrecorded.is_empty() {
        return Ok(());
    }
    Err(GatewayError::Conflict(format!(
        "'{id}' is revoked ({why}), and these connections under its id record nothing of what they were made from, so they are refused only while it stays installed: {}. Remove them first; removing or replacing the manifest while they exist would let them run again.",
        unrecorded.join(", ")
    )))
}

/// What an install reports, to its caller and to the audit chain: the manifest's id and name, its
/// version and provenance, the base URL it pins with that URL's host, every endpoint host it names,
/// and its capability preview.
fn installed_connector_json(
    manifest: &crate::presets::Preset,
    version: u32,
    provenance: &crate::manifest::Provenance,
) -> serde_json::Value {
    let mut vouched = manifest.clone();
    vouched.vouched = matches!(provenance, crate::manifest::Provenance::Signed { .. });
    let preview: Vec<serde_json::Value> = vouched
        .preview()
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "description": c.description,
                "method": c.method,
                "path": c.path,
                "action": c.action,
                "risk": c.risk,
                "requires_approval": c.requires_approval,
                "disabled": c.disabled,
            })
        })
        .collect();
    json!({
        "id": manifest.id,
        "connector_id": manifest.id,
        "name": manifest.name,
        "version": version,
        "provenance": provenance,
        "base_url": manifest.base_url,
        "host": crate::connectors::shown_host(&manifest.base_url),
        "endpoint_hosts": manifest.endpoint_hosts(),
        "capabilities": preview,
    })
}

/// Refuse capabilities any of which could run as another method than the one it shows, or as another
/// path ([`crate::connectors::method_override_refusal`]), so what an install or a connection previews is
/// what it sends.
fn refuse_method_overrides(capabilities: &[Capability]) -> Result<(), GatewayError> {
    for cap in capabilities {
        if let Some(why) = cap.http.as_ref().and_then(crate::connectors::method_override_refusal) {
            return Err(GatewayError::BadRequest(format!("capability '{}' is refused: {why}", cap.id)));
        }
    }
    Ok(())
}

/// Connector ids whose connections only the gateway's own routes build (an import, or the SSH and
/// generic-HTTP forms of `POST /v1/connections`): a manifest under one would wear that family's name
/// with none of its capabilities.
const SELF_BUILT_FAMILIES: &[&str] = &["wordpress", "openapi", "ssh", "generic-http", "generic_http", "http"];

/// Whether `id` names a connector family the gateway builds itself: one it pins to a fixed host, or one
/// of [`SELF_BUILT_FAMILIES`].
fn names_a_self_built_family(id: &str) -> bool {
    crate::connectors::connector::family_base_url(id).is_some() || SELF_BUILT_FAMILIES.contains(&id)
}

/// Refuse anything under the id of a family the gateway pins to fixed hosts
/// ([`crate::connectors::family_hosts`]) that would send its credential to `host` instead. The console
/// and the phone name a connection by that id.
fn refuse_family_elsewhere(family: &str, host: Option<String>) -> Result<(), GatewayError> {
    let pinned = crate::connectors::family_hosts(family);
    if pinned.is_empty() || host.as_deref().is_some_and(|h| pinned.contains(&h)) {
        return Ok(());
    }
    Err(GatewayError::BadRequest(format!(
        "'{family}' is a connector the gateway builds itself, pinned to {}, and this would send its credential to {} instead. A connection to another host is added as an OpenAPI import or a connector manifest under an id of its own.",
        pinned.join(", "),
        host.as_deref().unwrap_or("a host it does not name")
    )))
}

/// `GET /v1/connectors/installed`: list runtime-installed connector manifests (never any secret).
/// Operator-only.
pub async fn list_installed_connectors(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let items: Vec<serde_json::Value> = store
        .list_connector_manifests()?
        .iter()
        .map(|m| {
            json!({
                "id": m.manifest.id,
                "name": m.manifest.name,
                "vertical": m.manifest.vertical,
                "version": m.version,
                "provenance": m.provenance,
                "installed_at": m.installed_at,
                "endpoint_hosts": m.named_hosts(),
                "capability_count": m.manifest.capabilities.len(),
                "revoked": state.pmconn_revocation.refuses_installed(m),
            })
        })
        .collect();
    Ok(Json(json!({ "connectors": items })))
}

/// `DELETE /v1/connectors/:id`: remove an installed connector manifest from the catalog. Existing
/// connections created from it are untouched (they hold their own capability copies), which is why a
/// revoked one is refused while any connection under its id that records no origin still exists. Goes through [`apply_or_hold`] like an install.
/// Operator-only.
pub async fn delete_connector(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    if state.service.store().get_connector_manifest(&id)?.is_none() {
        return Err(GatewayError::NotFound(format!("installed connector '{id}'")));
    }
    refuse_unseating_a_revoked_connector(state.service.store().as_ref(), &state.service, &id)?;
    let mutation = crate::policy_guard::Mutation::ConnectorRemove { connector_id: id };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

/// Body for `POST /v1/connections/from-preset`: instantiate a marketplace preset.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FromPresetReq {
    /// The preset id, e.g. `stripe`.
    pub preset_id: String,
    /// The operator-chosen instance name.
    pub name: String,
    /// Optional explicit connection id (defaults to a slug of the name).
    #[serde(default)]
    pub id: Option<String>,
    /// Honest label (defaults to the preset's label).
    #[serde(default)]
    pub label: Option<String>,
    /// Override the manifest's pinned upstream host for THIS connection: the account-specific host
    /// a shared catalog manifest cannot know (a Mailchimp data centre, a DocuSign account base URI),
    /// or a vendor's sandbox. Operator-supplied, https-only, and fixed into every capability at
    /// creation, so it remains the SSRF pin.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Extra non-secret headers merged over the manifest's for THIS connection: the per-tenant
    /// header some APIs require (Xero's `Xero-tenant-id`). Credential-bearing names are refused: a
    /// secret belongs in the sealed credential, not in a connection record stored in the clear.
    #[serde(default)]
    pub static_headers: Option<BTreeMap<String, String>>,
    /// The operator's WordPress site, for a WordPress preset: the gateway discovers its REST root and
    /// pins the preset's namespace there. Refused for any other preset.
    #[serde(default)]
    pub site_url: Option<String>,
}

/// Header names that may never be set as a per-connection static header. `authorization` and
/// `proxy-authorization` would sit in the clear where the sealed credential belongs (and would be
/// overwritten by the auth scheme anyway); `cookie` is the same class; `host` would break routing to
/// the pinned upstream. Mirrors the "never a secret" rule the web authoring validator applies to a
/// manifest's own `static_headers`.
const FORBIDDEN_OVERRIDE_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie", "host"];

/// Substrings that make a header name look like it carries a credential. Deliberately broad: the cost
/// of a false positive is an operator renaming a header, and the cost of a false negative is a secret
/// persisted in plaintext outside the vault.
fn looks_like_credential(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["secret", "token", "password", "passwd", "apikey", "api-key", "api_key", "credential", "bearer"]
        .iter()
        .any(|needle| n.contains(needle))
}

/// Validate an operator-supplied per-connection `base_url`. This value becomes the SSRF pin for every
/// capability on the connection, so it must be an absolute https origin with nothing smuggled into it.
/// The OpenAPI importer holds a document's servers to the same rules (`openapi::check_pin`).
fn validate_override_base_url(raw: &str) -> Result<String, GatewayError> {
    let url = raw.trim().trim_end_matches('/');
    let bad = |m: &str| Err(GatewayError::BadRequest(format!("base_url {m}")));
    if url.is_empty() {
        return bad("must not be empty");
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return bad("must not contain whitespace or control characters");
    }
    // https only. A downgrade to http would send the injected credential in the clear, and the
    // manifest schema has required https since the catalog began.
    if !url.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")) {
        return bad("must be an absolute https:// URL");
    }
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return bad("must be an absolute https:// URL with a host");
    };
    if parsed.host_str().is_none_or(str::is_empty) {
        return bad("must include a host");
    }
    // Userinfo in the authority is how a credential gets smuggled into a URL, and it would also make
    // the effective host ambiguous to a reader auditing the connection.
    // The raw authority is checked too, so an empty `@` the parser drops is still refused.
    if !parsed.username().is_empty() || parsed.password().is_some() || url[8..].split(['/', '?', '#']).next().is_some_and(|a| a.contains('@')) {
        return bad("must not contain userinfo (user:pass@host)");
    }
    if url.contains('?') || url.contains('#') {
        return bad("must not contain a query string or fragment");
    }
    if url.contains(['{', '}']) {
        return bad("must not contain a template placeholder such as {site}");
    }
    if crate::connectors::url_host(url).is_none() {
        return bad("is not a URL the gateway can send to (a backslash in the host is refused)");
    }
    Ok(url.to_string())
}

/// Validate the per-connection `static_headers` override: real header tokens, no credential-bearing
/// names, and no CR/LF in a value (header injection).
fn validate_override_headers(
    headers: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, GatewayError> {
    let mut out = BTreeMap::new();
    for (name, value) in headers {
        let name = name.trim();
        if name.is_empty() {
            return Err(GatewayError::BadRequest("static_headers has an empty header name".into()));
        }
        // RFC 9110 field-name is a token; anything else can't be sent and usually means a typo or an
        // attempt to smuggle a second header in.
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
        {
            return Err(GatewayError::BadRequest(format!(
                "static_headers name '{name}' is not a valid HTTP header token"
            )));
        }
        if FORBIDDEN_OVERRIDE_HEADERS.iter().any(|f| name.eq_ignore_ascii_case(f))
            || looks_like_credential(name)
        {
            return Err(GatewayError::BadRequest(format!(
                "static_headers may not set '{name}': a credential belongs in the connection's sealed \
                 secret, not in a header stored in the clear"
            )));
        }
        if crate::connectors::is_method_override_header(name) {
            return Err(GatewayError::BadRequest(format!(
                "static_headers may not set '{name}': it asks the upstream to run every call as another method than the one each capability shows"
            )));
        }
        if value.contains(['\r', '\n']) {
            return Err(GatewayError::BadRequest(format!(
                "static_headers value for '{name}' must not contain CR or LF"
            )));
        }
        out.insert(name.to_string(), value.clone());
    }
    Ok(out)
}

/// Validate and assemble the per-connection overrides from a `from-preset` request.
fn validate_preset_overrides(req: &FromPresetReq) -> Result<crate::presets::PresetOverrides, GatewayError> {
    let base_url = match req.base_url.as_deref() {
        Some(raw) => Some(validate_override_base_url(raw)?),
        None => None,
    };
    let static_headers = match req.static_headers.as_ref() {
        Some(h) => validate_override_headers(h)?,
        None => BTreeMap::new(),
    };
    Ok(crate::presets::PresetOverrides { base_url, static_headers, ..Default::default() })
}

/// `POST /v1/connections/from-preset`: create a connection from a marketplace preset. Mirrors
/// `create_connection` but sources its capabilities from the curated preset: reads land enabled,
/// risky verbs land in `disabled_capabilities` (switched off until the operator opts them in). The
/// credential is added afterward via `POST …/credential`. Operator-only.
pub async fn create_from_preset(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<FromPresetReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    // Resolve from the union so an installed manifest is instantiable exactly like a bundled preset.
    let (preset, origin) = resolve_preset(store, &req.preset_id)?
        .ok_or_else(|| GatewayError::NotFound(format!("preset '{}'", req.preset_id)))?;
    if let Some(why) = state.service.connector_revocation(&req.preset_id)? {
        return Err(GatewayError::Conflict(format!(
            "connector '{}' is revoked ({why}), so no connection is made from it",
            req.preset_id
        )));
    }

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(GatewayError::BadRequest("name is required".to_string()));
    }
    // Validated before any field is moved out of `req`, and before anything is written, so a bad
    // override fails the whole call rather than leaving a half-built connection behind.
    let mut overrides = validate_preset_overrides(&req)?;
    let id = req
        .id
        .clone()
        .unwrap_or_else(|| slugify(&format!("{}-{}", preset.id, name)));
    refuse_long_name("connection id", &id)?;
    refuse_reserved_id("connection", &id)?;
    if store.get_connection(&id)?.is_some() {
        return Err(GatewayError::BadRequest(format!("connection '{id}' already exists")));
    }
    state
        .service
        .refuse_if_over_allowance(crate::allowances::Allowance::Connections, Some(&op))?;
    // After the allowance, so a tenant at its ceiling never sends a probe to anyone's site.
    let wordpress_source = pin_preset_host(&state, &preset, &req, &mut overrides).await?;
    let effective_base_url = overrides.base_url.clone().unwrap_or_else(|| preset.base_url.clone());
    let customised = !overrides.is_empty();
    let secret_id = derived_secret_slot(&id);
    let inst = preset.instantiate_with(&id, &secret_id, &overrides);
    for host in crate::connectors::connection_pins(&preset.id, &inst.capabilities).1 {
        refuse_family_elsewhere(&preset.id, Some(host))?;
    }
    refuse_method_overrides(&inst.capabilities)?;

    let preview: Vec<serde_json::Value> = inst
        .capabilities
        .iter()
        .map(|c| {
            let http = c.http.as_ref();
            json!({
                "id": c.id,
                "description": c.description,
                "method": http.map(|h| h.method),
                "path": http.map(|h| h.path.as_str()),
                "action": c.action,
                "risk": c.risk,
                "requires_approval": c.requires_approval,
                "disabled": inst.disabled_capabilities.contains(&c.id),
            })
        })
        .collect();

    let mut capability_ids: Vec<String> = inst.capabilities.iter().map(|c| c.id.clone()).collect();
    capability_ids.sort();
    let mut connection = Connection {
        id: id.clone(),
        connector: preset.id.clone(),
        name,
        // The console and the phone send no label, so the fallback is the manifest's own, which the user cannot edit.
        label: req.label.unwrap_or_else(|| cut_label(preset.label().to_string())),
        secret_id,
        capabilities: capability_ids,
        disabled_capabilities: inst.disabled_capabilities,
        disabled: false,
        // Preset connectors pin their upstream host in the catalog manifest. A generic-HTTP
        // preset (if any) still fails closed at invoke until an operator adds an allowlist.
        allowed_hosts: Vec::new(),
        created_at: now_ms(),
        redact_fields: preset.redact_fields.clone(),
        source: None,
        made_from: Some(origin),
    };
    connection.source = wordpress_source;
    // One unit, so a failure part-way leaves no capability without its connection. Seen on a live
    // worker when the snapshot upload failed between the two: the bucket carried the orphan.
    refuse_reserved_capabilities(&inst.capabilities)?;
    refuse_long_connection_names(&connection.id, &connection.name, &connection.label)?;
    refuse_over_capability_bytes(&state, store.as_ref(), &inst.capabilities, 0, "remove a connection first")?;
    refuse_binding_an_existing_secret(&state, &op, remote, NEW_CONNECTION, &connection.secret_id)?;
    store.transaction(|store| {
        for cap in &inst.capabilities {
            store.put_capability(cap.clone())?;
        }
        store.put_connection(connection)
    })?;
    Ok((
        StatusCode::CREATED,
        // `base_url` is echoed back so the caller can show the host this connection is actually
        // pinned to, which is the whole point when it was overridden; `customised` says whether it
        // deviates from the published manifest at all.
        Json(json!({
            "connection_id": id,
            "base_url": effective_base_url,
            "customised": customised,
            "capabilities": preview,
        })),
    ))
}

// ── WordPress: discover · import-wordpress · resync ─────────────────────────────

/// Pin the host of a preset connection whose manifest cannot name it: a WordPress preset, pinned to
/// the operator's own site, and any preset whose `base_url` is a template such as `https://{site}/…`,
/// which must never be pinned as written. Returns the discovery source a WordPress preset records.
///
/// With `site_url` the gateway discovers the site and requires the preset's namespace in its index.
/// Pretty permalinks fold the namespace into `base_url`; plain permalinks cannot, so each path is
/// prefixed with it and travels as `?rest_route=`.
async fn pin_preset_host(
    state: &AppState,
    preset: &crate::presets::Preset,
    req: &FromPresetReq,
    overrides: &mut crate::presets::PresetOverrides,
) -> Result<Option<permaura_core::ConnectionSource>, GatewayError> {
    let Some(wordpress) = &preset.wordpress else {
        if req.site_url.is_some() {
            return Err(GatewayError::BadRequest(format!(
                "site_url applies only to a WordPress preset, and '{}' is not one",
                preset.id
            )));
        }
        if overrides.base_url.is_none() && preset.base_url.contains('{') {
            return Err(GatewayError::BadRequest(format!(
                "preset '{}' has a templated base_url ({}): supply base_url for this connection",
                preset.id, preset.base_url
            )));
        }
        return Ok(None);
    };
    let namespace = wordpress.namespace.trim_matches('/').to_string();
    let source = |url: String, rest_root: Option<String>, digest: Option<String>| permaura_core::ConnectionSource {
        kind: permaura_core::SourceKind::Wordpress,
        url,
        rest_root,
        namespaces: vec![namespace.clone()],
        abilities: false,
        digest,
        synced_at: now_ms(),
    };
    match (req.site_url.as_deref(), overrides.base_url.clone()) {
        (Some(_), Some(_)) => Err(GatewayError::BadRequest(
            "give a WordPress preset site_url or base_url, not both".into(),
        )),
        (None, None) => Err(GatewayError::BadRequest(format!(
            "'{}' is a WordPress preset: site_url (or an explicit base_url) is required",
            preset.id
        ))),
        (None, Some(base_url)) => Ok(Some(source(base_url, None, None))),
        (Some(site_url), None) => {
            let site = discover_site(state, site_url).await?;
            let served = crate::wordpress::namespaces(&site.index);
            if !served.contains(&namespace) {
                return Err(GatewayError::BadRequest(format!(
                    "{} does not serve the {namespace} REST namespace; it serves: {}",
                    site.site_url,
                    served.join(", ")
                )));
            }
            let (base_url, route_param, path_prefix) = site.pin.preset_pin(&namespace);
            overrides.base_url = Some(base_url);
            overrides.route_param = route_param;
            overrides.path_prefix = path_prefix;
            let digest = crate::wordpress::digest(&site.index, Some(std::slice::from_ref(&namespace)));
            Ok(Some(source(site.site_url.clone(), Some(site.pin.rest_root()), Some(digest))))
        }
    }
}

/// Discover the WordPress site at `url`, or refuse with every URL that was tried.
async fn discover_site(state: &AppState, url: &str) -> Result<crate::wordpress::Site, GatewayError> {
    match crate::wordpress::discover(state.service.http().as_ref(), url)
        .await
        .map_err(GatewayError::BadRequest)?
    {
        crate::wordpress::Discovery::Found(site) => Ok(*site),
        crate::wordpress::Discovery::NotFound { tried, errors } => {
            // A transport error (an index over the response cap, an egress refusal) is the real answer when there is one, so it is named rather than folded into "nothing answered".
            let failures: Vec<String> = errors.iter().map(|(u, e)| format!("{u}: {e}")).collect();
            let detail = if failures.is_empty() { String::new() } else { format!("; {}", failures.join("; ")) };
            Err(GatewayError::BadRequest(format!(
                "no WordPress REST API answered at {url} (tried {}){detail}",
                tried.join(", ")
            )))
        }
    }
}

/// Body for `POST /v1/connections/discover`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverReq {
    /// What the operator entered: the site's home, or any page on it.
    pub url: String,
}

/// `POST /v1/connections/discover`: say what is at a URL before connecting it. Today that is a
/// WordPress REST index, probed on the entered host only; anything else is `{kind: "none", tried}`.
/// Reads public documents, never a credential, and writes nothing. Operator-only.
pub async fn discover_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<DiscoverReq>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let discovered = crate::wordpress::discover(state.service.http().as_ref(), &req.url)
        .await
        .map_err(GatewayError::BadRequest)?;
    Ok(Json(match discovered {
        crate::wordpress::Discovery::Found(site) => crate::wordpress::discover_json(&site),
        crate::wordpress::Discovery::NotFound { tried, errors } => {
            let mut body = json!({ "kind": "none", "tried": tried });
            if !errors.is_empty() {
                body["errors"] = json!(errors
                    .iter()
                    .map(|(url, error)| json!({ "url": url, "error": error }))
                    .collect::<Vec<_>>());
            }
            body
        }
    }))
}

/// A connection id this route will mint: it becomes the capability-id prefix, and the first dot of a
/// capability id is where the connection ends, so it may not contain one.
fn is_valid_connection_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
}

/// Body for `POST /v1/connections/import-wordpress`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportWordpressReq {
    /// The operator-chosen instance name.
    pub name: String,
    /// Optional explicit connection id (defaults to a slug of `wordpress-{name}`).
    #[serde(default)]
    pub id: Option<String>,
    /// Honest label for the connector (defaults to `WordPress`), cut to 128 bytes between characters.
    #[serde(default)]
    pub label: Option<String>,
    /// The site URL the operator entered. Discovery runs again here; nothing from an earlier
    /// `discover` call is trusted.
    pub url: String,
    /// The REST namespaces to import, e.g. `["bbpress/v1"]`.
    #[serde(default)]
    pub namespaces: Vec<String>,
    /// The digest a dry run returned, required to create. When it no longer matches, the site's API
    /// moved after the review and the import is refused rather than creating something nobody saw.
    #[serde(default)]
    pub digest: Option<String>,
    /// Derive and return the review without writing anything.
    #[serde(default)]
    pub dry_run: bool,
}

/// `POST /v1/connections/import-wordpress`: derive capabilities from a WordPress site's REST index for
/// the chosen namespaces. A dry run returns the review; otherwise the capabilities and the connection
/// are written in one transaction, writes land disabled, and the credential (an application password,
/// sealed as `user:password`) is added afterwards via `POST …/credential`. Operator-only.
pub async fn import_wordpress_connection(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ImportWordpressReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(GatewayError::BadRequest("name is required".into()));
    }
    let mut namespaces: Vec<String> = req
        .namespaces
        .iter()
        .map(|n| n.trim().trim_matches('/').to_string())
        .filter(|n| !n.is_empty())
        .collect();
    namespaces.sort();
    namespaces.dedup();
    if namespaces.is_empty() {
        return Err(GatewayError::BadRequest("namespaces: choose at least one REST namespace to import".into()));
    }
    let id = match req.id.as_deref().map(str::trim) {
        Some(id) => id.to_string(),
        None => slugify(&format!("wordpress-{name}")),
    };
    if !is_valid_connection_id(&id) {
        return Err(GatewayError::BadRequest(format!(
            "connection id '{id}' must be 1 to 64 of a-z, 0-9, _ and -"
        )));
    }
    let label = cut_label(req.label.as_deref().map(str::trim).filter(|l| !l.is_empty()).unwrap_or("WordPress").to_string());
    refuse_long_connection_names(&id, &name, &label)?;
    refuse_reserved_id("connection", &id)?;
    if store.get_connection(&id)?.is_some() {
        return Err(GatewayError::BadRequest(format!("connection '{id}' already exists")));
    }
    if !req.dry_run {
        // The site can change its index after the review, so nothing read from it is stored unless the create names the review it matches, and a create that will be refused reads nothing.
        if req.digest.is_none() {
            return Err(GatewayError::BadRequest(
                "digest is required to create: run the dry run, review it, and send the digest it returned, so what is stored is the API that was reviewed".into(),
            ));
        }
        // Before discovery: fetching and deriving an index is the expensive part of this route.
        state
            .service
            .refuse_if_over_allowance(crate::allowances::Allowance::Connections, Some(&op))?;
    }
    let site = discover_site(&state, &req.url).await?;
    let served = crate::wordpress::namespaces(&site.index);
    let missing: Vec<&str> = namespaces.iter().filter(|n| !served.contains(n)).map(String::as_str).collect();
    if !missing.is_empty() {
        return Err(GatewayError::BadRequest(format!(
            "{} does not serve {}; it serves: {}",
            site.site_url,
            missing.join(", "),
            served.join(", ")
        )));
    }
    let digest = crate::wordpress::digest(&site.index, Some(&namespaces));
    if let Some(reviewed) = req.digest.as_deref() {
        if reviewed != digest {
            return Err(GatewayError::Conflict(format!(
                "the site's API changed since it was reviewed (digest {reviewed} is now {digest}): run the \
                 dry run again and review what changed"
            )));
        }
    }
    let secret_id = derived_secret_slot(&id);
    let mut derived = crate::wordpress::derive(&site.index, &namespaces, &id, &secret_id, &site.pin);
    for (route, reason) in leave_out_long_capability_ids(&mut derived.capabilities, &mut derived.disabled) {
        derived.skipped.push(crate::wordpress::Skipped { route, reason });
    }
    if derived.capabilities.is_empty() {
        return Err(GatewayError::BadRequest(format!(
            "the selected namespaces yield no capabilities ({} routes skipped)",
            derived.skipped.len()
        )));
    }
    refuse_over_capability_bytes(&state, store.as_ref(), &derived.capabilities, 0, "remove a connection or select fewer namespaces")?;
    let redact_fields: Vec<String> =
        crate::wordpress::DEFAULT_REDACT_FIELDS.iter().map(|f| f.to_string()).collect();
    let previews: Vec<serde_json::Value> = derived
        .capabilities
        .iter()
        .map(|c| crate::wordpress::preview(c, derived.disabled.contains(&c.id)))
        .collect();
    let mut body = json!({
        "rest_root": site.pin.rest_root(),
        "routing": site.pin.routing.as_str(),
        "base_url": site.pin.base_url(),
        "capabilities": previews,
        "skipped": crate::wordpress::skipped_json(&derived.skipped),
        "redact_fields": redact_fields,
        "digest": digest,
    });
    if req.dry_run {
        return Ok((StatusCode::OK, Json(body)));
    }

    let mut capability_ids: Vec<String> = derived.capabilities.iter().map(|c| c.id.clone()).collect();
    capability_ids.sort();
    let now = now_ms();
    let connection = Connection {
        id: id.clone(),
        connector: "wordpress".to_string(),
        name,
        label,
        secret_id,
        capabilities: capability_ids,
        disabled_capabilities: derived.disabled.clone(),
        disabled: false,
        allowed_hosts: Vec::new(),
        created_at: now,
        redact_fields,
        source: Some(permaura_core::ConnectionSource {
            kind: permaura_core::SourceKind::Wordpress,
            url: site.site_url.clone(),
            rest_root: Some(site.pin.rest_root()),
            namespaces,
            abilities: false,
            digest: Some(digest),
            synced_at: now,
        }),
        made_from: Some(permaura_core::CatalogOrigin::Discovered),
    };
    refuse_reserved_capabilities(&derived.capabilities)?;
    refuse_binding_an_existing_secret(&state, &op, remote, NEW_CONNECTION, &connection.secret_id)?;
    store.transaction(|store| {
        for cap in &derived.capabilities {
            store.put_capability(cap.clone())?;
        }
        store.put_connection(connection)
    })?;
    body["connection_id"] = json!(id);
    Ok((StatusCode::CREATED, Json(body)))
}

/// Body for `POST /v1/connections/:id/resync`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResyncReq {
    /// Compute and return the diff without writing anything.
    #[serde(default)]
    pub dry_run: bool,
    /// Which sources to read: `rest`, `abilities`, or both. Defaults to `rest`, plus `abilities` once
    /// the connection has synced them before. An OpenAPI connection has one source, its document, which
    /// `rest` names.
    #[serde(default)]
    pub sources: Option<Vec<String>>,
}

/// Re-read an OpenAPI connection's document from the URL it was imported from and derive it again.
/// Returns the capabilities, the importer's warnings and the new digest.
///
/// The server the operator chose and the auth scheme the capabilities carry are not in the source, so
/// they are read back from the stored capabilities and passed as the overrides: a re-sync re-reads the
/// document, it does not re-guess the operator's choices.
async fn openapi_resync_capabilities(
    state: &AppState,
    connection: &Connection,
    source: &permaura_core::ConnectionSource,
    secret_id: &str,
) -> Result<(Vec<Capability>, Vec<String>, String), GatewayError> {
    if source.url.is_empty() {
        return Err(GatewayError::BadRequest(format!(
            "connection '{}' was imported from a pasted document, so there is no URL to read it again from: \
             import it again instead",
            connection.id
        )));
    }
    let store = state.service.store();
    let mut pinned = None;
    for cap_id in &connection.capabilities {
        if let Some(http) = store.get_capability(cap_id)?.and_then(|c| c.http) {
            pinned = Some(http);
            break;
        }
    }
    let fetched = crate::openapi::fetch_document(state.service.http().as_ref(), None, Some(&source.url))
        .await
        .map_err(GatewayError::BadRequest)?;
    let derived = crate::openapi::derive(
        &fetched.bytes,
        &crate::openapi::DeriveOptions {
            connection_id: connection.id.clone(),
            secret_id: secret_id.to_string(),
            spec_url: Some(fetched.url.clone()),
            bound_host: Some(fetched.bound_host.clone()),
            base_url: pinned.as_ref().map(|h| h.base_url.clone()),
            auth: pinned.map(|h| h.auth),
        },
    )
    .map_err(GatewayError::BadRequest)?;
    if derived.base_url.is_none() {
        return Err(GatewayError::BadRequest(format!(
            "the document now names {} servers and none matches the pinned one: {}",
            derived.servers.len(),
            derived.servers.join(", ")
        )));
    }
    Ok((derived.capabilities, derived.warnings, crate::openapi::digest(&fetched.bytes)))
}

/// Audit action for a re-sync that read a WordPress site's Abilities with the connection's sealed
/// credential: the gateway using a credential on the operator's behalf is recorded like any other use.
pub const ABILITIES_READ_ACTION: &str = "permaura.connection.abilities.read";

/// Record one read of the Abilities listing. Counts only; never a body or a value.
fn audit_abilities_read(
    state: &AppState,
    op: &Session,
    connection_id: &str,
    remote: bool,
    dry_run: bool,
    outcome: &Result<(Vec<serde_json::Value>, u32), GatewayError>,
) -> Result<(), GatewayError> {
    let (decision, mut summary) = match outcome {
        Ok((abilities, pages)) => {
            ("allow", json!({ "source": "abilities", "dry_run": dry_run, "pages": pages, "abilities": abilities.len() }))
        }
        Err(GatewayError::Denied(reason)) => {
            ("deny", json!({ "source": "abilities", "dry_run": dry_run, "reason": reason }))
        }
        Err(_) => ("allow", json!({ "source": "abilities", "dry_run": dry_run, "failed": true })),
    };
    insert_actor(&mut summary, op);
    summary["requested_remotely"] = json!(remote);
    let mut payload = permaura_core::AuditPayload::new(ABILITIES_READ_ACTION, connection_id, decision);
    payload.agent_id = Some(op.agent_id.clone());
    payload.session_id = Some(op.id.clone());
    payload.user_id = op.user_id.clone();
    payload.execution_location = Some("local".to_string());
    payload.summary = summary;
    state.service.store().append_audit(payload)?;
    Ok(())
}

/// `POST /v1/connections/:id/resync`: read a discovered connection's source again (a WordPress site's
/// REST index and Abilities, or an OpenAPI document from its URL) and diff it against what was
/// reviewed. Applying follows the pinning rule: new capabilities land disabled (reads too), changed
/// ones are overwritten and disabled, removed ones are reported and kept, never deleted. One that
/// differs only by its route context (path patterns it was stored without, or sibling routes) is
/// rewritten in place and keeps its switch (`refreshed`). The
/// `abilities` source needs the sealed credential, opened server-side through the same vault path
/// invoke uses. Operator-only.
pub async fn resync_connection(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<ResyncReq>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let connection = store
        .get_connection(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("connection '{id}'")))?;
    let Some(source) = connection.source.clone() else {
        return Err(GatewayError::BadRequest(format!(
            "connection '{id}' was not discovered from a site or a spec, so there is nothing to re-sync"
        )));
    };
    let openapi = source.kind == permaura_core::SourceKind::Openapi;
    if !openapi && connection.connector != "wordpress" {
        return Err(GatewayError::BadRequest(format!(
            "connection '{id}' was created from the '{}' preset, and re-sync for preset connections is not \
             wired yet",
            connection.connector
        )));
    }
    let (want_rest, want_abilities) = match &req.sources {
        None => (true, source.abilities),
        Some(list) => {
            if list.is_empty() {
                return Err(GatewayError::BadRequest("sources: name at least one of rest, abilities".into()));
            }
            if let Some(other) = list.iter().find(|s| !matches!(s.as_str(), "rest" | "abilities")) {
                return Err(GatewayError::BadRequest(format!(
                    "sources: '{other}' is not a source; use rest and/or abilities"
                )));
            }
            (list.iter().any(|s| s == "rest"), list.iter().any(|s| s == "abilities"))
        }
    };
    if openapi && want_abilities {
        return Err(GatewayError::BadRequest(
            "sources: abilities are a WordPress source; an OpenAPI connection re-reads its document (rest)".into(),
        ));
    }
    let secret_id = connection_slot(&state, &op, remote, &connection)?;
    if want_abilities && store.get_secret(&secret_id)?.is_none() {
        return Err(GatewayError::Conflict(format!(
            "the Abilities API lists nothing without a credential: seal the application password with \
             POST /v1/connections/{id}/credential, then re-sync"
        )));
    }

    let mut fresh: Vec<Capability> = Vec::new();
    let mut skipped = Vec::new();
    let mut warnings = Vec::new();
    let mut digest = source.digest.clone();
    if openapi {
        let (capabilities, derive_warnings, new_digest) =
            openapi_resync_capabilities(&state, &connection, &source, &secret_id).await?;
        fresh.extend(capabilities);
        warnings = derive_warnings;
        digest = Some(new_digest);
    } else {
        let pin = if want_rest {
            let site = discover_site(&state, &source.url).await?;
            let derived = crate::wordpress::derive(&site.index, &source.namespaces, &id, &secret_id, &site.pin);
            digest = Some(crate::wordpress::digest(&site.index, Some(&source.namespaces)));
            fresh.extend(derived.capabilities);
            skipped.extend(derived.skipped);
            site.pin
        } else {
            crate::wordpress::RestPin::from_rest_root(source.rest_root.as_deref().unwrap_or_default()).ok_or_else(
                || GatewayError::BadRequest(format!("connection '{id}' records no REST root to re-sync against")),
            )?
        };
        if want_abilities {
            let fetched = crate::wordpress::fetch_abilities(&state.service, &id, &secret_id, &pin).await;
            audit_abilities_read(&state, &op, &id, remote, req.dry_run, &fetched)?;
            let (abilities, _pages) = fetched?;
            let derived = crate::wordpress::derive_abilities(&abilities, &id, &secret_id, &pin);
            fresh.extend(derived.capabilities);
            skipped.extend(derived.skipped);
        }
    }

    let _control_plane = state.service.control_plane_mutex().lock().await;
    let connection = store.get_connection(&id)?.ok_or_else(|| GatewayError::NotFound(format!("connection '{id}'")))?;
    let in_scope = |cap_id: &str| {
        let ability = !openapi && crate::wordpress::is_ability_capability(&id, cap_id);
        (ability && want_abilities) || (!ability && want_rest)
    };
    let mut current: BTreeMap<String, Capability> = BTreeMap::new();
    for cap_id in connection.capabilities.iter().filter(|c| in_scope(c)) {
        if let Some(cap) = store.get_capability(cap_id)? {
            current.insert(cap_id.clone(), cap);
        }
    }
    let (mut added, mut changed, mut refreshed, mut unchanged, mut replaced) = (Vec::new(), Vec::new(), Vec::new(), 0usize, 0u64);
    for mut cap in fresh {
        if let Some(old) = current.get(&cap.id) {
            keep_owner_posture(old, &mut cap);
        }
        match current.remove(&cap.id) {
            None => added.push(cap),
            Some(old) if crate::wordpress::same_capability(&old, &cap) => unchanged += 1,
            Some(old) if crate::wordpress::only_refreshes_route_context(&old, &cap) => {
                replaced += crate::store::capability_row_bytes(&old);
                refreshed.push(cap);
            }
            Some(old) => {
                replaced += crate::store::capability_row_bytes(&old);
                changed.push(cap);
            }
        }
    }
    // Only what a re-sync adds is new; an id an earlier version stored is changed or kept whatever its length.
    for (at, why) in leave_out_long_capability_ids(&mut added, &mut Vec::new()) {
        if openapi {
            warnings.push(format!("{at}: {why}"));
        } else {
            skipped.push(crate::wordpress::Skipped { route: at, reason: why });
        }
    }
    let removed: Vec<Capability> = current.into_values().collect();
    let body = json!({
        "dry_run": req.dry_run,
        "added": added.iter().map(|c| crate::wordpress::preview(c, true)).collect::<Vec<_>>(),
        "changed": changed.iter().map(|c| crate::wordpress::preview(c, true)).collect::<Vec<_>>(),
        "refreshed": refreshed
            .iter()
            .map(|c| crate::wordpress::preview(c, connection.disabled_capabilities.contains(&c.id)))
            .collect::<Vec<_>>(),
        "removed": removed
            .iter()
            .map(|c| crate::wordpress::preview(c, connection.disabled_capabilities.contains(&c.id)))
            .collect::<Vec<_>>(),
        "unchanged": unchanged,
        "digest": digest,
        "skipped": crate::wordpress::skipped_json(&skipped),
        "warnings": warnings,
    });
    let writes: Vec<Capability> = added.into_iter().chain(changed).collect();
    refuse_over_capability_bytes(&state, store.as_ref(), writes.iter().chain(&refreshed), replaced, "remove a connection or re-sync fewer namespaces")?;
    if req.dry_run {
        return Ok(Json(body));
    }

    refuse_reserved_capabilities(&writes)?;
    store.transaction(|store| {
        // Re-read inside the transaction: the network reads above took seconds, and writing back the copy read before them could re-enable a capability the operator switched off meanwhile.
        let mut connection = store
            .get_connection(&id)?
            .ok_or_else(|| GatewayError::NotFound(format!("connection '{id}'")))?;
        for cap in &writes {
            store.put_capability(cap.clone())?;
            if !connection.capabilities.contains(&cap.id) {
                connection.capabilities.push(cap.id.clone());
            }
            if !connection.disabled_capabilities.contains(&cap.id) {
                connection.disabled_capabilities.push(cap.id.clone());
            }
        }
        for cap in refreshed.iter().filter(|c| connection.capabilities.contains(&c.id)) {
            store.put_capability(cap.clone())?;
        }
        connection.capabilities.sort();
        let mut source = connection.source.clone().unwrap_or(source);
        if want_rest {
            source.digest = digest.clone();
        }
        if want_abilities {
            source.abilities = true;
        }
        source.synced_at = now_ms();
        connection.source = Some(source);
        store.put_connection(connection)
    })?;
    Ok(Json(body))
}

/// Carry the owner's posture setting from a stored capability onto its re-derived self, while the
/// source still derives the posture the setting replaced for the same method and path; a change to
/// either (a new method, an annotation that raises the risk) drops it, so the re-sync shows the change.
fn keep_owner_posture(old: &Capability, fresh: &mut Capability) {
    let (Some(was), Some(now)) = (old.http.as_ref(), fresh.http.as_mut()) else { return };
    let Some(owner) = was.owner_posture else { return };
    let same_shape = was.method == now.method && was.path == now.path;
    let same_derivation = (fresh.action, fresh.risk, fresh.requires_approval) == (owner.from_action, owner.from_risk, owner.from_requires_approval);
    if same_shape && same_derivation {
        fresh.risk = owner.risk;
        fresh.requires_approval = owner.requires_approval;
        now.owner_posture = Some(owner);
    }
}

/// Handler for `DELETE /v1/connections/:id`. Removes the connection and everything scoped to
/// it: its capabilities, its policies (detached from every grant, which stay), and its credential
/// when no other connection or capability uses the same slot. Held for a device wherever it
/// arrives from while one is trusted and approvals are not opted down.
pub async fn delete_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    // Existence is checked before the hold, so a typo comes back as a 404 now rather than as a
    // notification asking someone to approve deleting something that was never there.
    if state.service.store().get_connection(&id)?.is_none() {
        return Err(GatewayError::NotFound(format!("connection '{id}'")));
    }
    let mutation = crate::policy_guard::Mutation::ConnectionDelete { connection_id: id.clone() };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

/// Body for `POST /v1/connections/:id/credential`: add or rotate the connection's credential.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionCredentialReq {
    /// The secret value (sealed immediately server-side; never echoed back).
    pub value: String,
}

/// A connection (or capability) id that currently uses `secret_id` as its live credential, if any.
/// A write to such a secret injects the upstream identity the gateway acts as on invoke (the exact
/// power [`set_connection_credential`] guards), so the *generic* secret-write endpoints
/// (`create_secret`, `rotate_secret`) must guard writes to a backing secret too, or they are a
/// trivial bypass of the credential hold. Covers capabilities as well (a capability carries its own
/// `secret_id`, e.g. the seeded generic `http.request`), reporting the owning connection id for the
/// approval prompt.
fn secret_backing_ref(store: &dyn Store, secret_id: &str) -> Result<Option<String>, GatewayError> {
    if secret_id.is_empty() {
        return Ok(None);
    }
    if let Some(c) = store.list_connections()?.into_iter().find(|c| c.secret_id == secret_id) {
        return Ok(Some(c.id));
    }
    if let Some(cap) = store.list_capabilities()?.into_iter().find(|c| c.secret_id == secret_id) {
        return Ok(Some(cap.resource)); // a capability's `resource` IS its connection id
    }
    Ok(None)
}

/// Why a credential a connection uses was written from off this host without a hold. One string, so a
/// vault-import slot fill and a secret write that do the same thing record it the same way.
const UNHELD_CREDENTIAL_WRITE: &str =
    "written from off this host with nothing to hold it for a device: none is paired, or approvals are opted down";

const SECRET_WRITE_ACTION: &str = "permaura.secret.write";

/// Record a remote write to the credential behind `connection_id` that nothing held for a device. A
/// local write, or one to a secret no connection uses, records nothing, as before.
fn audit_unheld_credential_write(
    state: &AppState,
    op: &Session,
    remote: bool,
    secret_id: &str,
    connection_id: Option<&str>,
) -> Result<(), GatewayError> {
    let (true, Some(connection_id)) = (remote, connection_id) else { return Ok(()) };
    audit_vault(state, op, SECRET_WRITE_ACTION, "allow", json!({
        "reason": UNHELD_CREDENTIAL_WRITE, "secret_id": secret_id, "connection_id": connection_id,
    }))
}

/// Publish a secret row, then run `record`; when `record` fails, the row goes back to what it was (a failed undo is logged and the write stands). What is recorded is the caller's choice: with [`audit_unheld_credential_write`], a loopback write or a write to a secret no connection uses stands with no audit event. Says whether the row replaced one.
fn publish_secret_with_record(
    state: &AppState,
    store: &dyn Store,
    secret: SecretRecord,
    op: &Session,
    record: impl FnOnce() -> Result<(), GatewayError>,
) -> Result<bool, GatewayError> {
    publish_secret_with_record_if(state, store, secret, op, |_| Ok(()), record)
}

/// [`publish_secret_with_record`] that writes only when `check` passes inside the unit that writes; see [`crate::service::EnforcementService::publish_secret`].
fn publish_secret_with_record_if(
    state: &AppState,
    store: &dyn Store,
    secret: SecretRecord,
    op: &Session,
    check: impl FnOnce(&dyn Store) -> Result<(), GatewayError>,
    record: impl FnOnce() -> Result<(), GatewayError>,
) -> Result<bool, GatewayError> {
    let id = secret.id.clone();
    let prior = store.get_secret(&id)?;
    let replaced = state.service.publish_secret(secret, Some(op), check)?;
    if let Err(e) = record() {
        let undone = match prior {
            Some(prior) => store.put_secret(prior),
            None => store.delete_secret(&id).map(|_| ()),
        };
        state.service.note_credential_change(&id);
        if let Err(undo) = undone {
            tracing::error!(secret_id = %id, error = %undo, "a credential write whose audit record failed could not be undone; it stands unrecorded");
        }
        return Err(e);
    }
    Ok(replaced)
}

/// Stage a sealed credential blob under a fresh id and hold a `device_signed` `CredentialPromote`
/// binding it to the live `secret_id` (owned by `connection_id`, shown in the prompt). Nothing
/// plaintext lands in the approval params (only the two secret ids) so holding a credential change
/// never leaks a secret at rest; the params carry a digest of the staged envelope, so the device's signature
/// (via `request_hash`) covers the exact bytes resolution promotes, and a staged row that no longer matches is
/// refused. The caller must already hold the control-plane lock. Returns the 202 body.
fn hold_credential_by_reference(
    state: &AppState,
    store: &dyn Store,
    connection_id: String,
    secret_id: String,
    sealed: permaura_core::SealedSecret,
    metadata: SecretMetadata,
    requested_by: Option<crate::store::HoldRequester>,
) -> Result<(StatusCode, serde_json::Value), GatewayError> {
    hold_credential_checked(state, store, connection_id, secret_id, sealed, metadata, requested_by, true)
}

/// [`hold_credential_by_reference`], checking the held-changes budget for this hold alone when `check_budget`, or not, for one of a vault import's fills, which are checked together first.
#[allow(clippy::too_many_arguments)]
fn hold_credential_checked(
    state: &AppState,
    store: &dyn Store,
    connection_id: String,
    secret_id: String,
    sealed: permaura_core::SealedSecret,
    metadata: SecretMetadata,
    requested_by: Option<crate::store::HoldRequester>,
    check_budget: bool,
) -> Result<(StatusCode, serde_json::Value), GatewayError> {
    crate::secret_inventory::refuse_staging_secret_id("secret", &secret_id)?;
    // Refused before the row is staged: a refusal that wrote would leave a row only a device-signed delete removes.
    let pending = store.count_pending_approvals()?;
    if pending >= crate::store::MAX_PENDING_APPROVALS {
        return Err(crate::store::too_many_pending_approvals(pending));
    }
    let staging_secret_id = crate::secret_inventory::mint_staging_secret_id();
    let adding = crate::secret_inventory::secret_row_bytes(&staging_secret_id, &sealed, &metadata);
    refuse_over_staged_bytes(state, store, requested_by.as_ref(), adding)?;
    let staged_sha256 = crate::secret_inventory::staged_digest(&sealed);
    store.put_secret(SecretRecord { id: staging_secret_id.clone(), sealed, metadata })?;
    let mutation = crate::policy_guard::Mutation::CredentialPromote {
        connection_id,
        secret_id,
        staging_secret_id: staging_secret_id.clone(),
        staged_sha256,
    };
    let held = if check_budget {
        state.service.hold_mutation_approval(POLICY_WRITE_CAP, &mutation, held_remote_note(&requested_by), requested_by)
    } else {
        state.service.hold_admitted_mutation_approval(POLICY_WRITE_CAP, &mutation, held_remote_note(&requested_by), requested_by)
    };
    let approval = match held {
        Ok(approval) => approval,
        Err(refused) => {
            match hold_names_staged_row(store, &staging_secret_id) {
                Ok(false) => {
                    if let Err(e) = store.delete_secret(&staging_secret_id) {
                        tracing::warn!(staging_secret_id = %staging_secret_id, error = %e, "a refused credential hold left its staged row behind");
                    }
                }
                Ok(true) => {
                    tracing::warn!(staging_secret_id = %staging_secret_id, error = %refused, "a credential hold was recorded before a later step failed; its staged row is kept so the hold can still be applied");
                }
                Err(e) => {
                    tracing::warn!(staging_secret_id = %staging_secret_id, error = %e, "could not tell whether a failed credential hold was recorded; its staged row is kept");
                }
            }
            return Err(refused);
        }
    };
    Ok((StatusCode::ACCEPTED, held_body(&approval)))
}

/// Who a staged row is charged to: the person a hold names, else its device, else everyone who asked from this host or named nobody, together.
fn staging_requester(requested_by: Option<&crate::store::HoldRequester>) -> Option<String> {
    requested_by.and_then(|r| r.person.clone().or_else(|| r.device_id.clone()))
}

/// Refuse a credential hold whose staged row (`adding` stored bytes, envelope and metadata) would take the requester's, or the gateway's, staged rows past [`crate::limits::LimitsConfig`]'s byte bounds. Every staged row counts toward the gateway's total, including one no hold names any more; the requester's share is the rows its pending holds name. Called under the control-plane lock, so the sum cannot move before the row is staged.
fn refuse_over_staged_bytes(
    state: &AppState,
    store: &dyn Store,
    requested_by: Option<&crate::store::HoldRequester>,
    adding: usize,
) -> Result<(), GatewayError> {
    let limits = state.limits.config();
    let me = staging_requester(requested_by);
    let owner_of: std::collections::HashMap<String, Option<String>> = store
        .pending_staging_owners()?
        .into_iter()
        .map(|(id, requested_by)| (id, staging_requester(requested_by.as_ref())))
        .collect();
    let (mut total, mut mine, mut orphaned) = (0usize, 0usize, 0usize);
    for id in store.list_secret_ids()?.into_iter().filter(|id| crate::secret_inventory::is_staging_secret_id(id)) {
        let Some(row) = store.get_secret(&id)? else { continue };
        let bytes = crate::secret_inventory::secret_row_bytes(&row.id, &row.sealed, &row.metadata);
        total = total.saturating_add(bytes);
        match owner_of.get(&id) {
            Some(owner) if *owner == me => mine = mine.saturating_add(bytes),
            Some(_) => {}
            None => orphaned = orphaned.saturating_add(bytes),
        }
    }
    let over = |held: usize, limit: usize| held.saturating_add(adding) > limit;
    let refusal = if over(mine, limits.staged_bytes_per_requester) {
        format!(
            "this credential change ({adding} bytes staged) would take the credential changes you have waiting for a device to more than the {} bytes one requester may have waiting ({mine} bytes now); approve or deny some of them first",
            limits.staged_bytes_per_requester
        )
    } else if over(total, limits.staged_bytes_per_gateway) {
        let free = if orphaned == 0 {
            "approve or deny some of them first".to_string()
        } else if orphaned == total {
            format!("all {orphaned} bytes are staged rows no waiting change names any more, which only deleting them (DELETE /v1/secrets/<id>) frees")
        } else {
            format!("approve or deny some of them first; {orphaned} bytes of that are staged rows no waiting change names any more, which only deleting them (DELETE /v1/secrets/<id>) frees")
        };
        format!(
            "this credential change ({adding} bytes staged) would take the credential changes waiting for a device on this gateway to more than its {}-byte ceiling ({total} bytes now); {free}",
            limits.staged_bytes_per_gateway
        )
    } else {
        return Ok(());
    };
    Err(GatewayError::TooManyRequests {
        reason: STAGED_BYTES_REASON.to_string(),
        message: refusal,
        retry_after_secs: STAGED_BYTES_RETRY_AFTER_SECS,
        scope: None,
    })
}

/// The `reason` a credential change refused at the staged-bytes bound carries.
pub const STAGED_BYTES_REASON: &str = "staged_credential_bytes";

/// The same wait the pending-approval ceiling asks for: room comes back only when a human resolves a hold.
const STAGED_BYTES_RETRY_AFTER_SECS: u64 = 300;

/// Whether a pending hold names `staging_secret_id`. A hold can be written before a later step fails (its audit record, or a hosted store that commits locally and fails the upload), and that hold resolves from this row.
fn hold_names_staged_row(store: &dyn Store, staging_secret_id: &str) -> Result<bool, GatewayError> {
    Ok(store.pending_staging_owners()?.iter().any(|(id, _)| id == staging_secret_id))
}

/// Handler for `POST /v1/connections/:id/credential`. Seals the value under the connection's
/// secret id (adding it if absent, rotating it if present). The value is never returned.
///
/// A credential injection has no tightening direction (it changes the upstream identity the
/// connection acts as), so over the broker, while this gateway still requires a device signature
/// ([`crate::service::EnforcementService::control_plane_hold_required`]), it is **held by reference**
/// via [`hold_credential_by_reference`]. Loopback, nothing ever enrolled, or a floor the operator has
/// since lowered seals straight into the live secret.
pub async fn set_connection_credential(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<ConnectionCredentialReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let mut connection = store
        .get_connection(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("connection '{id}'")))?;
    let slot = connection_slot(&state, &op, remote, &connection)?;
    // A first credential adds a secret row exactly as `POST /v1/secrets` does, so it is charged the same way.
    if store.get_secret(&slot)?.is_none() {
        state
            .service
            .refuse_if_over_allowance(crate::allowances::Allowance::Secrets, Some(&op))?;
    }
    if connection.secret_id != slot {
        connection.secret_id = slot;
        store.put_connection(connection.clone())?;
    }
    let sealed = seal(Cipher::Aes256Gcm, vault_passphrase(), zeroize::Zeroizing::new(req.value).as_bytes())
        .map_err(|e| GatewayError::Internal(format!("seal failed: {e}")))?;

    let _cp = state.service.control_plane_mutex().lock().await;
    let existing = store.get_secret(&connection.secret_id)?;
    let metadata = existing.as_ref().map(|s| s.metadata.clone()).unwrap_or_default();
    if state.service.control_plane_hold_required(remote) {
        let (code, body) = hold_credential_by_reference(
            &state,
            store.as_ref(),
            id.clone(),
            connection.secret_id.clone(),
            sealed,
            metadata,
            requester_of(&op, remote),
        )?;
        return Ok((code, Json(body)));
    }
    let mut record = Some(SecretRecord { id: connection.secret_id.clone(), sealed, metadata });
    let mut rotated = false;
    store.change_with_record(&mut || {
        let Some(record) = record.take() else { return Ok(()) };
        rotated = publish_secret_with_record(&state, store.as_ref(), record, &op, || {
            audit_unheld_credential_write(&state, &op, remote, &connection.secret_id, Some(&id))
        })?;
        Ok(())
    })?;
    Ok((StatusCode::OK, Json(json!({ "connection_id": id, "rotated": rotated }))))
}

/// Body for `PATCH /v1/connections/:id`, a sparse update: the kill switch, a rename, and/or
/// (for SSH connections) an edit of the pinned target.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchConnectionReq {
    /// `true` pauses the connection (every capability denied for every grant, above any policy);
    /// `false` re-enables it. The sealed credential and per-capability switches are untouched.
    #[serde(default)]
    pub disabled: Option<bool>,
    /// A new display label (the operator-facing name shown in the console).
    #[serde(default)]
    pub label: Option<String>,
    /// A new instance name. The connection id is stable and never changes.
    #[serde(default)]
    pub name: Option<String>,
    /// SSH-only: patch the pinned target (host/port/user/host-key/auth mode) of every SSH
    /// capability on this connection. Only the fields present are changed; the exec/SFTP ops and
    /// the sealed credential are untouched. Switching `password_auth` means the existing sealed
    /// secret is now read the other way; re-seal it via `POST …/credential` afterward.
    #[serde(default)]
    pub ssh: Option<SshTargetPatch>,
}

/// A sparse patch of an SSH connection's pinned target. Absent fields keep their current value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshTargetPatch {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub user: Option<String>,
    /// A new expected host-key fingerprint (switches the target to verified mode).
    #[serde(default)]
    pub host_key_sha256: Option<String>,
    /// Explicitly drop host-key verification (dev only). Takes precedence over `host_key_sha256`.
    #[serde(default)]
    pub insecure: Option<bool>,
    /// Switch between private-key (`false`) and password (`true`) auth.
    #[serde(default)]
    pub password_auth: Option<bool>,
}

/// The longest host an SSH target may pin, at create or by patch: a DNS name's limit.
const MAX_SSH_HOST_BYTES: usize = 253;
/// The longest login user an SSH target may pin, at create or by patch.
const MAX_SSH_USER_BYTES: usize = 256;
/// The longest host key an SSH target may pin, at create or by patch: room for any OpenSSH public key line, not only its fingerprint.
const MAX_SSH_HOST_KEY_BYTES: usize = 16 * 1024;

/// What an SSH target patch past the capability-bytes ceiling is told to do instead.
const SSH_TARGET_REMEDY: &str = "send shorter SSH target values or remove a connection first";

/// Refuse an [`SshTargetPatch`] whose host, user or host key, as it would be written, is longer than a real one: each is written into every SSH capability of the connection.
fn refuse_long_ssh_target(patch: &SshTargetPatch) -> Result<(), GatewayError> {
    [
        ("ssh host", &patch.host, MAX_SSH_HOST_BYTES),
        ("ssh user", &patch.user, MAX_SSH_USER_BYTES),
        ("ssh host_key_sha256", &patch.host_key_sha256, MAX_SSH_HOST_KEY_BYTES),
    ]
    .into_iter()
    .try_for_each(|(what, value, max)| value.as_deref().map_or(Ok(()), |v| refuse_longer_than(what, v.trim(), max)))
}

/// The rows an [`SshTargetPatch`] would write over a connection's SSH capabilities, and the bytes the rows they replace take.
fn ssh_target_rewrites(
    store: &dyn crate::store::Store,
    connection: &Connection,
    patch: &SshTargetPatch,
) -> Result<(Vec<Capability>, u64), GatewayError> {
    let mut rows = Vec::new();
    let mut replacing = 0;
    for cap_id in &connection.capabilities {
        let Some(mut cap) = store.get_capability(cap_id)? else { continue };
        let before = crate::store::capability_row_bytes(&cap);
        let Some(spec) = cap.ssh.as_mut() else { continue };
        if let Some(host) = &patch.host {
            spec.target.host = host.trim().to_string();
        }
        if let Some(port) = patch.port {
            spec.target.port = port;
        }
        if let Some(user) = &patch.user {
            spec.target.user = user.trim().to_string();
        }
        let fingerprint = patch.host_key_sha256.as_ref().filter(|s| !s.trim().is_empty());
        if patch.insecure == Some(true) && fingerprint.is_some() {
            return Err(GatewayError::BadRequest(
                "give an ssh target 'host_key_sha256' or \"insecure\": true, not both: insecure would drop the fingerprint".into(),
            ));
        }
        if patch.insecure == Some(false) && fingerprint.is_none() && matches!(spec.target.host_key, SshHostKey::Insecure) {
            return Err(GatewayError::BadRequest(
                "\"insecure\": false needs the 'host_key_sha256' to verify this unverified target against".into(),
            ));
        }
        if patch.insecure == Some(true) {
            spec.target.host_key = SshHostKey::Insecure;
        } else if let Some(fp) = fingerprint {
            spec.target.host_key = SshHostKey::Fingerprint { sha256: fp.trim().to_string() };
        }
        if let Some(password_auth) = patch.password_auth {
            spec.credential_kind = if password_auth {
                SshCredentialKind::Password
            } else {
                SshCredentialKind::PrivateKey
            };
        }
        replacing += before;
        rows.push(cap);
    }
    Ok((rows, replacing))
}

/// Apply an [`SshTargetPatch`] to every SSH capability of a connection, in place, once the rewritten rows fit under `capability_bytes`. Returns the number of capabilities rewritten (0 means the connection has no SSH capabilities).
fn apply_ssh_target_patch(
    store: &dyn crate::store::Store,
    connection: &Connection,
    patch: &SshTargetPatch,
    capability_bytes: u64,
) -> Result<usize, GatewayError> {
    if let Some(host) = &patch.host {
        if host.trim().is_empty() {
            return Err(GatewayError::BadRequest("ssh 'host' must be non-empty".into()));
        }
    }
    if let Some(user) = &patch.user {
        if user.trim().is_empty() {
            return Err(GatewayError::BadRequest("ssh 'user' must be non-empty".into()));
        }
    }
    let (rows, replacing) = ssh_target_rewrites(store, connection, patch)?;
    refuse_over_capability_ceiling(capability_bytes, store, &rows, replacing, SSH_TARGET_REMEDY)?;
    let rewritten = rows.len();
    for cap in rows {
        store.put_capability(cap)?;
    }
    Ok(rewritten)
}

/// Handler for `PATCH /v1/connections/:id`. Sparse update: flip the connection-level kill switch
/// (a reversible "pause this service", distinct from deleting the connection) and/or rename the
/// connection's label/name. The id is immutable: policies and capability ids key on it. Operator-only.
pub async fn patch_connection(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<PatchConnectionReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    if req.disabled.is_none() && req.label.is_none() && req.name.is_none() && req.ssh.is_none() {
        return Err(GatewayError::BadRequest(
            "nothing to update: provide 'disabled', 'label', 'name' and/or 'ssh'".into(),
        ));
    }
    let store = state.service.store();
    let connection = store
        .get_connection(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("connection '{id}'")))?;
    if req.ssh.is_some() && connection.connector != "ssh" {
        return Err(GatewayError::BadRequest(
            "'ssh' target edits apply only to SSH connections".into(),
        ));
    }
    if let Some(ssh) = &req.ssh {
        refuse_long_ssh_target(ssh)?;
        let (rows, replacing) = ssh_target_rewrites(store.as_ref(), &connection, ssh)?;
        refuse_over_capability_bytes(&state, store.as_ref(), &rows, replacing, SSH_TARGET_REMEDY)?;
    }
    if let Some(host) = req.ssh.as_ref().and_then(|s| s.host.as_deref()) {
        refuse_non_public_ssh_on_hosted(state.hosted, host.trim())?;
    }
    // Trim + validate label/name up front so a bad value 400s immediately (even on the held path);
    // the built ConnPatch then carries clean values [`apply_connection_patch`] can apply verbatim.
    let label = match req.label {
        Some(l) => {
            let l = l.trim().to_string();
            if l.is_empty() {
                return Err(GatewayError::BadRequest("'label' must be non-empty".into()));
            }
            refuse_long_name("connection label", &l)?;
            Some(l)
        }
        None => None,
    };
    let name = match req.name {
        Some(n) => {
            let n = n.trim().to_string();
            if n.is_empty() {
                return Err(GatewayError::BadRequest("'name' must be non-empty".into()));
            }
            refuse_long_name("connection name", &n)?;
            Some(n)
        }
        None => None,
    };
    let patch = crate::policy_guard::ConnPatch {
        disabled: req.disabled,
        label,
        name,
        ssh: req.ssh.as_ref().map(|s| crate::policy_guard::SshPatch {
            host: s.host.clone(),
            port: s.port,
            user: s.user.clone(),
            host_key_sha256: s.host_key_sha256.clone(),
            insecure: s.insecure,
            password_auth: s.password_auth,
        }),
    };
    let mutation = crate::policy_guard::Mutation::ConnectionPatch { connection_id: id, patch };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

/// Body for `POST /v1/connections/:id/capabilities`, the real capability master-switch.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToggleCapabilityReq {
    /// The full capability id to toggle (e.g. `braintree.transactions.refund`).
    pub capability: String,
    /// `true` to enable, `false` to switch it off for every grant on this connection.
    pub enabled: bool,
}

/// Handler for `POST /v1/connections/:id/capabilities`. Flips a capability's master-switch.
/// A disabled capability is denied for every grant, above any policy (enforced in the
/// service's connection gate).
pub async fn toggle_capability(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<ToggleCapabilityReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let mut connection = store
        .get_connection(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("connection '{id}'")))?;
    // Before either branch, so a typo cannot be recorded as a disable OR queued as a device-signed
    // enable of something that does not exist.
    validate_capability(store.as_ref(), &id, &req.capability)?;
    // Disabling a capability is a kill switch (strictly tightening) so it applies immediately even
    // over the broker. Re-enabling it re-opens access above policy, so it routes through the guard.
    if !req.enabled {
        connection.disabled_capabilities.retain(|c| c != &req.capability);
        connection.disabled_capabilities.push(req.capability.clone());
        store.put_connection(connection)?;
        return Ok((
            StatusCode::OK,
            Json(json!({ "connection_id": id, "capability": req.capability, "enabled": false })),
        ));
    }
    let mutation = crate::policy_guard::Mutation::CapabilityEnable {
        connection_id: id,
        capability: req.capability,
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

/// Body for `POST /v1/connections/:id/capability-posture`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPostureReq {
    /// The full capability id, e.g. `wordpress_forum.abilities.bbpress_get_topic`.
    pub capability: String,
    /// The risk tier to set.
    pub risk: permaura_core::RiskTier,
    /// Whether every call asks for an approval.
    pub requires_approval: bool,
}

/// Handler for `POST /v1/connections/:id/capability-posture`: the owner sets a capability's risk tier
/// and whether every call asks for an approval. The posture a manifest's author, an imported document
/// or a site's annotations could only ever raise, the owner may lower: lowering either is a loosening,
/// held for a device where one is required and recorded with the old posture and the new, and raising
/// applies at once. Only a capability with a pinned HTTP shape takes one. A re-sync keeps the setting
/// while the source still derives the posture it replaced for the same method and path.
pub async fn set_capability_posture(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<CapabilityPostureReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    if store.get_connection(&id)?.is_none() {
        return Err(GatewayError::NotFound(format!("connection '{id}'")));
    }
    validate_capability(store.as_ref(), &id, &req.capability)?;
    let cap = store
        .get_capability(&req.capability)?
        .ok_or_else(|| GatewayError::NotFound(format!("capability '{}'", req.capability)))?;
    let Some(http) = cap.http.as_ref().filter(|_| cap.kind == crate::connectors::CapabilityKind::Http) else {
        return Err(GatewayError::BadRequest(format!(
            "capability '{}' has no pinned HTTP shape: its posture is the gateway's own definition, not a document's, so it takes no owner setting",
            req.capability
        )));
    };
    let from = crate::policy_guard::PostureFrom {
        action: cap.action,
        risk: cap.risk,
        requires_approval: cap.requires_approval,
        method: http.method,
        path: http.path.clone(),
    };
    let mutation = crate::policy_guard::Mutation::CapabilityPosture {
        connection_id: id,
        capability: req.capability,
        risk: req.risk,
        requires_approval: req.requires_approval,
        from,
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

/// Apply an owner's posture setting to `capability`, only while it still carries the posture and shape
/// the setting was asked against. The setting is recorded on the capability with the posture the source
/// derived (the first one replaced, if the owner sets it again), and a setting back to that posture
/// clears the record.
fn apply_capability_posture(
    store: &dyn Store,
    connection_id: &str,
    capability: &str,
    risk: permaura_core::RiskTier,
    requires_approval: bool,
    from: &crate::policy_guard::PostureFrom,
) -> Result<serde_json::Value, GatewayError> {
    let connection = store
        .get_connection(connection_id)?
        .ok_or_else(|| GatewayError::NotFound(format!("connection '{connection_id}'")))?;
    let mut cap = store
        .get_capability(capability)?
        .filter(|c| connection.capabilities.contains(&c.id))
        .ok_or_else(|| GatewayError::NotFound(format!("capability '{capability}' on connection '{connection_id}'")))?;
    let unchanged = cap.kind == crate::connectors::CapabilityKind::Http && cap.http.as_ref().is_some_and(|h| {
        cap.action == from.action
            && cap.risk == from.risk
            && cap.requires_approval == from.requires_approval
            && h.method == from.method
            && h.path == from.path
    });
    if !unchanged {
        return Err(GatewayError::Conflict(format!(
            "capability '{capability}' has changed since this setting was asked for (a re-sync or another setting): ask again against what it is now"
        )));
    }
    let derived = cap.http.as_ref().and_then(|h| h.owner_posture).map_or(
        (cap.action, cap.risk, cap.requires_approval),
        |o| (o.from_action, o.from_risk, o.from_requires_approval),
    );
    cap.risk = risk;
    cap.requires_approval = requires_approval;
    if let Some(http) = cap.http.as_mut() {
        http.owner_posture = ((risk, requires_approval) != (derived.1, derived.2)).then_some(crate::connectors::OwnerPosture {
            risk,
            requires_approval,
            from_action: derived.0,
            from_risk: derived.1,
            from_requires_approval: derived.2,
        });
    }
    store.put_capability(cap)?;
    Ok(json!({
        "connection_id": connection_id,
        "capability": capability,
        "risk": risk,
        "requires_approval": requires_approval,
        "was": { "risk": from.risk, "requires_approval": from.requires_approval },
    }))
}

// ── /v1/policies ──────────────────────────────────────────────────────────────────

/// Handler for `GET /v1/policies`. Lists all policies (optionally one connection's).
#[derive(Deserialize)]
pub struct PoliciesQuery {
    /// Optional connection id filter.
    #[serde(default)]
    pub connection_id: Option<String>,
}

/// Handler for `GET /v1/policies`.
pub async fn list_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PoliciesQuery>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let policies = match q.connection_id {
        Some(cid) => store.policies_for_connection(&cid)?,
        None => store.list_policies()?,
    };
    Ok(Json(json!({ "policies": policies })))
}

/// Body for `POST /v1/policies` / `PUT /v1/policies/:id`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReq {
    /// Optional explicit policy id (POST only; defaults to a generated id).
    #[serde(default)]
    pub id: Option<String>,
    /// The connection this policy is scoped to.
    pub connection_id: String,
    /// Operator-facing name.
    #[serde(default)]
    pub name: String,
    /// Allowed action ids.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Denied action ids (deny wins).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Action ids that must be escalated to human approval (the `approve` rung).
    #[serde(default)]
    pub requires_approval: Vec<String>,
    /// Action ids that execute immediately but push an after-the-fact notification (`notify` rung).
    #[serde(default)]
    pub notify: Vec<String>,
    /// Action ids whose approval requires a device signature (`device_signed` rung).
    #[serde(default)]
    pub device_signed: Vec<String>,
    /// How many distinct people must sign a `device_signed` action (the two-person rule): a phone
    /// and its Watch are one person, and a key bound to nobody is never the second. Absent leaves
    /// whatever the stored policy already demands; see [`PolicyReq::into_policy`].
    #[serde(default)]
    pub device_signed_quorum: Option<u8>,
    /// Attach-from-creation: when present, sync this policy's grant membership to exactly
    /// these grants (add where missing, remove where present-but-unlisted). The shared "add to
    /// grants" multi-select posts this from both Add/Edit-policy and Add-connection. Omit to leave
    /// grant memberships untouched.
    #[serde(default)]
    pub grant_ids: Option<Vec<String>>,
}

impl PolicyReq {
    /// Build the proposed policy. `existing` is the stored policy this write replaces, if any.
    ///
    /// The quorum is the one field a write may legitimately not mention: every console and CLI that
    /// predates the two-person rule sends the five rung lists and nothing else, and reading absent as
    /// `1` turned any such edit into a silent 2-of-2 → 1-of-1 downgrade, the security property
    /// deleted by an unrelated rename, reported as success. So only an explicit quorum of at least
    /// one sets it; absent keeps what is stored (a zero, which would mean a device-signed action
    /// running with no signature at all, is refused before this), and a create with neither floors at one.
    ///
    /// `redact_fields` is not part of this request at all, so an edit keeps whatever the stored
    /// policy carries (a bundle import can set it) rather than silently stripping a redaction.
    fn into_policy(&self, id: String, existing: Option<&Policy>) -> Policy {
        Policy {
            id,
            connection_id: self.connection_id.clone(),
            name: self.name.clone(),
            allow: self.allow.clone(),
            deny: self.deny.clone(),
            requires_approval: self.requires_approval.clone(),
            notify: self.notify.clone(),
            device_signed: self.device_signed.clone(),
            device_signed_quorum: self
                .device_signed_quorum
                .filter(|q| *q >= 1)
                .or_else(|| existing.map(|p| p.device_signed_quorum))
                .unwrap_or(1)
                .max(1),
            redact_fields: existing.map(|p| p.redact_fields.clone()).unwrap_or_default(),
        }
    }
}

/// The action id the policy engine matches on: a capability id minus its connector prefix
/// (`elevenlabs.models.list` → `models.list`). Must stay identical to the derivation in
/// [`crate::service`]'s enforcement loop: a policy keyed on anything else silently matches nothing.
fn policy_action_id(capability_id: &str) -> String {
    capability_id
        .split_once('.')
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_else(|| capability_id.to_string())
}

/// A PUT whose body names a different record than its path: the path decides, so the body's id would be dropped.
fn refuse_another_id(kind: &str, body_id: Option<&str>, path_id: &str) -> Result<(), GatewayError> {
    match body_id {
        Some(body_id) if body_id != path_id => Err(GatewayError::BadRequest(format!(
            "the body names {kind} '{body_id}' and the path names '{path_id}'; send the path's id or none"
        ))),
        _ => Ok(()),
    }
}

/// Reject action ids the engine could never match, on every rung, at write time.
///
/// The engine compares by exact string equality against the *bare* action id, while the connections
/// list, the capability listing, the invoke call and the capability toggle all hand out the
/// *qualified* one. So a policy written from what the API returns is accepted, attaches to its grant,
/// reads back correctly, and matches nothing, including on `deny`. A deny that silently enforces
/// nothing is worse than a rejected write, so this refuses rather than normalises: a caller who wrote
/// the wrong thing needs telling, and quietly fixing it up leaves the next person's mental model
/// wrong in exactly the same way.
fn validate_policy_actions(store: &dyn Store, req: &PolicyReq) -> Result<(), GatewayError> {
    if req.device_signed_quorum == Some(0) {
        return Err(GatewayError::BadRequest(
            "device_signed_quorum must be at least 1; omit it to keep the stored quorum".into(),
        ));
    }
    let valid: std::collections::BTreeSet<String> = store
        .list_capabilities()?
        .into_iter()
        .filter(|c| c.resource == req.connection_id)
        .map(|c| policy_action_id(&c.id))
        .collect();

    for (rung, ids) in [
        ("allow", &req.allow),
        ("deny", &req.deny),
        ("requires_approval", &req.requires_approval),
        ("notify", &req.notify),
        ("device_signed", &req.device_signed),
    ] {
        for id in ids {
            if valid.contains(id) {
                continue;
            }
            // Name the qualified form explicitly when that is what was sent: it is the single most
            // common way to land here, because it is what every read path returns.
            let hint = match policy_action_id(id) {
                stripped if stripped != *id && valid.contains(&stripped) => {
                    format!(" Did you mean '{stripped}'? Policies key on the action id, not the qualified capability id.")
                }
                _ => String::new(),
            };
            let known = if valid.is_empty() {
                format!("connection '{}' has no capabilities", req.connection_id)
            } else {
                format!("valid ids for connection '{}': {}", req.connection_id, valid.iter().cloned().collect::<Vec<_>>().join(", "))
            };
            return Err(GatewayError::BadRequest(format!(
                "policy rung '{rung}' names unknown action '{id}'.{hint} {known}"
            )));
        }
    }
    Ok(())
}

/// Sync `policy_id`'s membership to exactly `grant_ids`: add it to listed grants that lack
/// it, remove it from grants that have it but are not listed. Persists only the grants that change.
fn sync_policy_grants(
    store: &dyn Store,
    policy_id: &str,
    grant_ids: &[String],
) -> Result<(), GatewayError> {
    let wanted: std::collections::HashSet<&str> = grant_ids.iter().map(|s| s.as_str()).collect();
    for mut g in store.list_grants()? {
        let has = g.policy_ids.iter().any(|p| p == policy_id);
        let want = wanted.contains(g.grant_id.as_str());
        if want && !has {
            g.policy_ids.push(policy_id.to_string());
            store.update_grant(g)?;
        } else if !want && has {
            g.policy_ids.retain(|p| p != policy_id);
            store.update_grant(g)?;
        }
    }
    Ok(())
}

/// Handler for `POST /v1/policies`. Optionally attaches the new policy to grants in the same call.
/// Over the broker with a device enrolled, a non-tightening create is held for a device signature
/// ([`apply_or_hold`]) rather than applied.
pub async fn create_policy(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<PolicyReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    validate_policy_actions(state.service.store().as_ref(), &req)?;
    let id = req.id.clone().unwrap_or_else(|| format!("pol_{}", short_id()));
    // A POST naming an existing id is an upsert too, so it reads the stored policy on the same terms
    // a PUT does; otherwise the quorum-preserving path would have a hole exactly one field wide.
    let existing = state.service.store().get_policy(&id)?;
    let mutation = crate::policy_guard::Mutation::PolicyUpsert {
        policy: req.into_policy(id.clone(), existing.as_ref()),
        grant_ids: req.grant_ids.clone(),
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::CREATED, Json(json!({ "policy_id": id })))),
    }
}

/// Handler for `PUT /v1/policies/:id`. Upserts the policy and (when `grant_ids` is present) syncs
/// its grant membership. Held for a device signature when it loosens access over the broker.
pub async fn update_policy(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<PolicyReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    refuse_another_id("policy", req.id.as_deref(), &id)?;
    validate_policy_actions(state.service.store().as_ref(), &req)?;
    let existing = state.service.store().get_policy(&id)?;
    let mutation = crate::policy_guard::Mutation::PolicyUpsert {
        policy: req.into_policy(id.clone(), existing.as_ref()),
        grant_ids: req.grant_ids.clone(),
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::OK, Json(json!({ "policy_id": id, "updated": true })))),
    }
}

/// Handler for `DELETE /v1/policies/:id`. Deletes the policy and detaches it from grants. Every
/// policy delete is destructive, so it is held for a device wherever it arrived from while one is
/// trusted and approvals are not opted down, and over the broker whenever it is not strictly
/// tightening (removing a policy that solely gated an action loosens access; see [`apply_or_hold`]).
pub async fn delete_policy(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    if state.service.store().get_policy(&id)?.is_none() {
        return Err(GatewayError::NotFound(format!("policy '{id}'")));
    }
    let mutation = crate::policy_guard::Mutation::PolicyDelete { policy_id: id.clone() };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::OK, Json(json!({ "policy_id": id, "deleted": true })))),
    }
}

/// Remove `policy_id` from every grant's `policy_ids`, persisting only the grants that changed.
fn detach_policy_from_grants(store: &dyn Store, policy_id: &str) -> Result<(), GatewayError> {
    for mut g in store.list_grants()? {
        if g.policy_ids.iter().any(|p| p == policy_id) {
            g.policy_ids.retain(|p| p != policy_id);
            store.update_grant(g)?;
        }
    }
    Ok(())
}

/// Slugify a string into a stable id (lowercase, non-alnum → `_`, collapsed).
fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut last_us = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_us = false;
        } else if !last_us {
            out.push('_');
            last_us = true;
        }
    }
    out.trim_matches('_').to_string()
}

/// Title-case a connector id for a default label (e.g. `github` → `Github`).
fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

// ── POST /v1/grants ─────────────────────────────────────────────────────────────

/// One agent in a grant request: a bare id (`"codex-cli"`) or an object carrying a per-agent
/// override (`{ "agent_id": "codex-cli", "per_agent_limit": 50 }`).
pub enum AgentSel {
    /// A bare agent id with no per-agent override.
    Id(String),
    /// An agent id plus an optional per-agent ceiling.
    Full {
        /// The agent id.
        agent_id: String,
        /// This agent's per-period cap, overriding the grant default. `null` = use the default.
        per_agent_limit: Option<u64>,
    },
}

/// The object form of an [`AgentSel`], read on its own so an unknown member is refused by name: an untagged enum would only say that no variant matched.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentOverride {
    agent_id: String,
    #[serde(default)]
    per_agent_limit: Option<u64>,
}

impl<'de> Deserialize<'de> for AgentSel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Shape;
        impl<'de> serde::de::Visitor<'de> for Shape {
            type Value = AgentSel;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an agent id, or an object with agent_id and per_agent_limit")
            }
            fn visit_str<E: serde::de::Error>(self, id: &str) -> Result<AgentSel, E> {
                Ok(AgentSel::Id(id.to_string()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<AgentSel, A::Error> {
                let agent = AgentOverride::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(AgentSel::Full { agent_id: agent.agent_id, per_agent_limit: agent.per_agent_limit })
            }
        }
        deserializer.deserialize_any(Shape)
    }
}

/// Body for `POST /v1/grants` and `PUT /v1/grants/:id`, a v2 grant bundle: bind a
/// set of policies to a set of agents (or all agents) under two-tier limits. No action lists.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantReq {
    /// Optional explicit grant id (POST only).
    #[serde(default)]
    pub grant_id: Option<String>,
    /// Operator-facing, referenceable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Pause switch. Absent ⇒ enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Make this the Default baseline; setting it clears the flag from the previous default.
    #[serde(default)]
    pub is_default: Option<bool>,
    /// The policies this grant activates. Accepts `policy_ids: [...]`, or a single legacy `policy_id`.
    #[serde(default)]
    pub policy_ids: Option<Vec<String>>,
    /// Back-compat convenience for a single policy.
    #[serde(default)]
    pub policy_id: Option<String>,
    /// Cover every approved agent (incl. future ones). When true, `agents` is ignored.
    #[serde(default)]
    pub all_agents: bool,
    /// The specific agents (ids or `{agent_id, per_agent_limit}`). Ignored when `all_agents`.
    #[serde(default)]
    pub agents: Vec<AgentSel>,
    /// The budget window for both tiers.
    #[serde(default)]
    pub period: Option<GrantPeriod>,
    /// The hard ceiling across all agents per period. `null` = no overall ceiling.
    #[serde(default)]
    pub overall_limit: Option<u64>,
    /// Each agent's per-period cap unless overridden per agent. `null` = no per-agent ceiling.
    #[serde(default)]
    pub default_per_agent_limit: Option<u64>,
    /// RFC3339 expiry. `null` = no expiry.
    #[serde(default)]
    pub expires_at: Option<String>,

    // ── legacy slim-grant fields, still accepted so pre-v2 API callers keep working ──
    /// Legacy single target: `"all_agents"` or `{ "agent": "id" }`. Used only when `all_agents`
    /// is false and `agents` is empty.
    #[serde(default, deserialize_with = "crate::request_body::strict_target")]
    pub target: Option<GrantTarget>,
    /// Legacy convenience: a bare agent id (absent ⇒ all agents).
    #[serde(default)]
    pub target_agent: Option<String>,
    /// Legacy per-grant cap; maps to `default_per_agent_limit` when that is unset.
    #[serde(default)]
    pub max_calls: Option<u64>,
}

impl GrantReq {
    /// The policies this grant activates, refusing a blank id rather than dropping it.
    ///
    /// It used to filter empties out silently, which turned `{"policy_ids": [""]}` into a grant with
    /// no policies at all: 201, a grant id, and an entry in the estate that activates nothing and
    /// never will. `validate_policies` never saw the blank, so the 404 everyone assumed was covering
    /// this case could not fire. Blank in an explicit array is a caller bug, and saying so is the
    /// only answer that does not leave somebody believing they granted something.
    ///
    /// The legacy singular `policy_id` keeps its tolerance: a pre-v2 caller sending `""` there meant
    /// "no policy", and that shape is still accepted as an empty list.
    fn resolve_policy_ids(&self) -> Result<Vec<String>, GatewayError> {
        if let Some(ids) = &self.policy_ids {
            if ids.iter().any(|p| p.trim().is_empty()) {
                return Err(GatewayError::BadRequest(
                    "policy_ids contains an empty id; name a policy or omit the field".into(),
                ));
            }
            return Ok(ids.clone());
        }
        Ok(self
            .policy_id
            .clone()
            .into_iter()
            .filter(|p| !p.trim().is_empty())
            .collect())
    }

    /// The agent set: the v2 `all_agents`/`agents` if given, else the legacy `target`/`target_agent`.
    fn resolve_agents(&self) -> GrantAgents {
        if self.all_agents {
            return GrantAgents::AllAgents;
        }
        if !self.agents.is_empty() {
            return GrantAgents::Agents(
                self.agents.iter().map(|a| match a {
                    AgentSel::Id(id) => GrantAgent::new(id.clone()),
                    AgentSel::Full { agent_id, per_agent_limit } => GrantAgent {
                        agent_id: agent_id.clone(),
                        per_agent_limit: *per_agent_limit,
                    },
                }).collect(),
            );
        }
        // Legacy fall-back.
        if let Some(t) = &self.target {
            return match t {
                GrantTarget::AllAgents => GrantAgents::AllAgents,
                GrantTarget::Agent(a) => GrantAgents::Agents(vec![GrantAgent::new(a.clone())]),
            };
        }
        match &self.target_agent {
            Some(a) if !a.is_empty() => GrantAgents::Agents(vec![GrantAgent::new(a.clone())]),
            _ => GrantAgents::default(),
        }
    }

    /// Refuse a body that names one thing twice, a v2 member and its legacy spelling or two agent selections, because only one of them would be read.
    fn refuse_two_spellings(&self) -> Result<(), GatewayError> {
        let target_agent = self.target_agent.as_deref().is_some_and(|a| !a.is_empty());
        let pairs = [
            (self.policy_ids.is_some() && self.policy_id.is_some(), "policy_ids", "policy_id"),
            (self.all_agents && !self.agents.is_empty(), "all_agents", "agents"),
            (self.all_agents && self.target.is_some(), "all_agents", "target"),
            (self.all_agents && target_agent, "all_agents", "target_agent"),
            (!self.agents.is_empty() && self.target.is_some(), "agents", "target"),
            (!self.agents.is_empty() && target_agent, "agents", "target_agent"),
            (self.target.is_some() && target_agent, "target", "target_agent"),
            (self.default_per_agent_limit.is_some() && self.max_calls.is_some(), "default_per_agent_limit", "max_calls"),
        ];
        match pairs.iter().find(|(both, ..)| *both) {
            Some((_, one, other)) => Err(GatewayError::BadRequest(format!(
                "'{one}' and '{other}' both say the same thing and only one would be read; send one of them"
            ))),
            None => Ok(()),
        }
    }

    fn into_grant(self, grant_id: String) -> Result<Grant, GatewayError> {
        self.refuse_two_spellings()?;
        let expires_at = match self.expires_at.as_deref() {
            Some(s) if !s.is_empty() => Some(
                OffsetDateTime::parse(s, &Rfc3339)
                    .map_err(|e| GatewayError::BadRequest(format!("invalid expires_at: {e}")))?,
            ),
            _ => None,
        };
        let policy_ids = self.resolve_policy_ids()?;
        let agents = self.resolve_agents();
        Ok(Grant {
            grant_id,
            name: self.name.unwrap_or_default(),
            enabled: self.enabled.unwrap_or(true),
            is_default: self.is_default.unwrap_or(false),
            policy_ids,
            agents,
            period: self.period.unwrap_or_default(),
            overall_limit: self.overall_limit,
            default_per_agent_limit: self.default_per_agent_limit.or(self.max_calls),
            expires_at,
        })
    }
}

/// Validate that every referenced policy exists. Returns the first missing one as a 404.
fn validate_policies(store: &dyn Store, policy_ids: &[String]) -> Result<(), GatewayError> {
    for pid in policy_ids {
        if store.get_policy(pid)?.is_none() {
            return Err(GatewayError::NotFound(format!("policy '{pid}'")));
        }
    }
    Ok(())
}

/// Validate that every agent a grant NAMES exists. Returns the first missing one as a 404, in the
/// same shape `create_session` uses, so a console gets one error vocabulary for "no such agent".
///
/// Only concrete ids are checked, and that is the point rather than an omission. A
/// [`GrantAgents::AllAgents`] grant deliberately names nobody and covers every approved agent
/// present and future, so there is nothing to look up; an empty `Agents` set covers nobody and is
/// equally legitimate. Validating those would break the two shapes an unscoped grant can take.
///
/// Without this a grant could be minted against an agent id that has never existed, and it would sit
/// in the estate looking like authorization while targeting nothing. The typo is silent: the grant
/// lists, it enables, it audits, and it can never match a caller.
fn validate_agents(store: &dyn Store, agents: &GrantAgents) -> Result<(), GatewayError> {
    let GrantAgents::Agents(named) = agents else { return Ok(()) };
    if named.len() > 1024 {
        return Err(GatewayError::BadRequest("a grant may name at most 1024 agents".into()));
    }
    for a in named {
        if store.get_agent(&a.agent_id)?.is_none() {
            return Err(GatewayError::NotFound(format!("agent '{}'", a.agent_id)));
        }
    }
    Ok(())
}

/// Validate that `capability` is one `connection_id` actually exposes.
///
/// The master switch stored a caller-supplied string and echoed it back, so a typo produced a 200,
/// a row in `disabled_capabilities` that matches nothing, and an operator's reasonable belief that
/// they had just switched something off. Nothing downstream ever reads that row, because nothing is
/// named by it.
fn validate_capability(
    store: &dyn Store,
    connection_id: &str,
    capability: &str,
) -> Result<(), GatewayError> {
    let exposed = store
        .list_capabilities()?
        .into_iter()
        .any(|c| c.resource == connection_id && c.id == capability);
    if exposed {
        return Ok(());
    }
    Err(GatewayError::NotFound(format!(
        "capability '{capability}' on connection '{connection_id}'"
    )))
}

/// Make `grant_id` the sole Default: clear `is_default` from every other grant (exactly
/// one default at a time). Best-effort persistence of the cleared grants.
fn make_sole_default(store: &dyn Store, grant_id: &str) -> Result<(), GatewayError> {
    for mut g in store.list_grants()? {
        if g.grant_id != grant_id && g.is_default {
            g.is_default = false;
            store.update_grant(g)?;
        }
    }
    Ok(())
}

/// Handler for `POST /v1/grants`. Validates the referenced policies exist, then stores the v2 grant.
pub async fn create_grant(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<GrantReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    // Grants are the authorization root: only an operator may mint one. (An agent token must
    // never self-grant; that would collapse deny-by-default.)
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let grant_id = req.grant_id.clone().unwrap_or_else(|| format!("gr_{}", short_id()));
    let grant = req.into_grant(grant_id.clone())?;
    // Only a grant id the store does not already hold adds a row: this route upserts, and editing a
    // grant at the ceiling must keep working.
    if store.get_grant(&grant_id)?.is_none() {
        state
            .service
            .refuse_if_over_allowance(crate::allowances::Allowance::Grants, Some(&op))?;
    }
    validate_policies(store.as_ref(), &grant.policy_ids)?;
    validate_agents(store.as_ref(), &grant.agents)?;
    // A brand-new grant always adds authorization, so over the broker with a device enrolled it is
    // held for a device signature rather than applied.
    let mutation = crate::policy_guard::Mutation::GrantUpsert { grant };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::CREATED, Json(json!({ "grant_id": grant_id })))),
    }
}

// ── POST /v1/invoke ─────────────────────────────────────────────────────────────

/// Handler request body for `POST /v1/invoke`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvokeReq {
    /// The capability id to invoke.
    pub capability: String,
    /// The agent-supplied parameters, read by the metered parse (see [`crate::memory::read_json`]).
    #[serde(default)]
    pub params: crate::connectors::json_budget::MeteredValue,
    /// The agent's stated intent (audited, not trusted for authorization).
    #[serde(default)]
    pub reason: Option<String>,
    /// Where the request would execute (defaults to local). Only ever makes the call stricter: a
    /// request this gateway knows is remote is treated as remote whatever this says.
    #[serde(default)]
    pub execution_location: ExecutionLocation,
    /// Ask for the verdict only: nothing runs, is held or is recorded, and any verdict, a deny
    /// included, answers 200.
    #[serde(default)]
    pub explain_only: bool,
}

/// Handler for `POST /v1/invoke`, the enforcement loop. Maps the three verdicts to
/// HTTP: Allow → 200, RequiresApproval → 202, Deny → 403. With `explain_only`, 200 and the verdict.
pub async fn invoke(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    // Admission lets a bearer that names nobody through to here, so its body must not be parsed before the bearer is resolved.
    let session = match authed(&state, &headers) {
        Ok(session) => session,
        Err(refusal) => {
            let limit = state.limits.config().body_exec_bytes;
            return refuse_after_draining(request, limit, refusal.into_response()).await;
        }
    };
    // The params become a tree only under the worker's JSON memory budget, reserved with the body an execution writes from them, and that charge travels with them into the execution.
    let budget = state.service.memory().clone();
    let slot = request.extensions().get::<crate::limits::ExecutionSlot>().cloned();
    let (req, charge, unpacked) =
        match crate::memory::read_json::<InvokeReq, AppState>(&budget, request, &state, "/v1/invoke").await {
            Ok(read) => read,
            Err(refusal) => return refusal,
        };
    match invoke_as(&state, remote, session, req, charge, unpacked, slot).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn invoke_as(
    state: &AppState,
    remote: bool,
    session: Session,
    req: InvokeReq,
    charge: crate::connectors::MemoryCharge,
    unpacked: u64,
    slot: Option<crate::limits::ExecutionSlot>,
) -> Result<Response, GatewayError> {
    let InvokeReq { capability, params, reason, execution_location, explain_only } = req;
    let params = crate::memory::AgentParams::charged(params.0, charge).holding(slot).measured(unpacked);
    let rhash = request_hash(&capability, &params);
    // The body's field can only make the call stricter: a forwarded or hosted request is remote.
    let location = if remote { ExecutionLocation::RemoteAllowed } else { execution_location };
    if explain_only {
        let decision = state.service.explain(&session, &capability, &params, location)?;
        return Ok((StatusCode::OK, Json(json!({ "decision": decision, "request_hash": rhash, "explain_only": true }))).into_response());
    }

    let outcome = state.service.invoke_admitted(&session, &capability, params, reason.as_deref(), location).await?;

    let body = match outcome {
        InvokeOutcome::Allowed { decision, result, status, room } => {
            let mut head = serde_json::Map::new();
            head.insert("decision".into(), json!(decision));
            head.insert("request_hash".into(), json!(rhash));
            head.insert("upstream_status".into(), json!(status));
            // Written in as the text it is held as: no tree of the result is built for the response.
            let mut response = crate::memory::document_response(StatusCode::OK, crate::memory::Assembled::object(head, "result", result));
            crate::delivery::HoldWhileSending::attach(&mut response, room);
            return Ok(response);
        }
        InvokeOutcome::RequiresApproval { decision, approval } => (
            StatusCode::ACCEPTED,
            json!({
                "decision": decision,
                "request_hash": crate::service::held_request_hash(&approval.capability, &approval.params),
                "approval_id": approval.id,
                "approval": {
                    "id": approval.id,
                    "status": approval.status,
                    "message": approval.message,
                },
            }),
        ),
        InvokeOutcome::Denied { decision } => (
            StatusCode::FORBIDDEN,
            json!({
                "decision": decision,
                "request_hash": rhash,
            }),
        ),
    };

    Ok((body.0, Json(body.1)).into_response())
}

// ── POST /v1/approvals ──────────────────────────────────────────────────────────

/// Resolve a pending approval. A human (or the desktop/phone biometric flow) posts the
/// approval id and the resolution. When the optional `device_sig` (+ `approver`, `request_hash`,
/// `decided_at`) fields are present, the resolution is **device-signed** and the gateway verifies
/// the ed25519 signature against its worker-local trusted key before running the held call: this
/// is the path the phone uses over the website broker, where the operator bearer alone is the
/// semi-trusted cloud and must not be sufficient.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveApprovalReq {
    /// The approval id to resolve.
    pub approval_id: String,
    /// `true` to approve, `false` to deny.
    pub approve: bool,
    /// The approver id that signed (`device:<id>` / `user:<id>`). Present only on a signed resolution.
    #[serde(default)]
    pub approver: Option<String>,
    /// The held call's request_hash the device signed over (re-bound server-side to the held call).
    #[serde(default)]
    pub request_hash: Option<String>,
    /// When the device made the decision (unix ms), bound by the signature and freshness-checked.
    #[serde(default)]
    pub decided_at: Option<i64>,
    /// The job id the device signed over (the approval id for a locally-held call).
    #[serde(default)]
    pub job_id: Option<String>,
    /// The device's ed25519 public key (base64), for audit/UX only: NOT trusted for verification.
    #[serde(default)]
    pub approver_pubkey: Option<String>,
    /// The gateway audience the device signed for (`approval_result_preimage_v2`), as served beside
    /// the approval. Absent on a v1 signature, which names no gateway.
    #[serde(default)]
    pub audience: Option<String>,
    /// The digest of the parameter rendering the device showed the approver
    /// (`approval_result_preimage_v3`), recomputed from what it rendered, never copied from
    /// `params_display.digest`. Absent on a v1 or v2 signature.
    #[serde(default)]
    pub display_digest: Option<String>,
    /// base64(ed25519) signature over the approval-result preimage. Its presence selects the signed path.
    #[serde(default)]
    pub device_sig: Option<String>,
}

/// Handler for `POST /v1/approvals`. Approving runs the held call and returns its
/// redacted result; denying records the refusal. Both go through the enforcement
/// service so the audit trail and execution stay in one place.
pub async fn resolve_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ResolveApprovalReq>,
) -> Result<Response, GatewayError> {
    // Resolving an approval EXECUTES the held high-risk call. It is the human-in-the-loop, so
    // only an operator may do it, never the agent whose own call is being gated.
    let op = operator_authed(&state, &headers)?;

    // Device-signed path: a signature was supplied → verify it against the worker-LOCAL trusted key
    // for `approver` (never the posted pubkey) before executing. This is the load-bearing check on
    // the live broker→REST transport; a broker-relayed operator bearer alone cannot forge it.
    if let Some(device_sig) = req.device_sig.clone() {
        let approver = req
            .approver
            .clone()
            .ok_or_else(|| GatewayError::Denied("signed approval missing 'approver'".into()))?;
        let request_hash = req
            .request_hash
            .clone()
            .ok_or_else(|| GatewayError::Denied("signed approval missing 'request_hash'".into()))?;
        let decided_at = req
            .decided_at
            .ok_or_else(|| GatewayError::Denied("signed approval missing 'decided_at'".into()))?;
        let result = ApprovalResult {
            job_id: req.job_id.clone().unwrap_or_else(|| req.approval_id.clone()),
            approval_id: req.approval_id.clone(),
            approve: req.approve,
            request_hash,
            approver,
            decided_at,
            approver_pubkey: req.approver_pubkey.clone(),
            audience: req.audience.clone().filter(|a| !a.trim().is_empty()),
            display_digest: req.display_digest.clone().filter(|d| !d.trim().is_empty()),
            device_sig,
        };
        let approver_id = result.approver.clone();
        let keyring = state.service.approver_keyring_snapshot();
        let outcome = {
            let _room = state.service.display_room_for_signed(&result).await?;
            state.service.verify_signed_approval(&keyring, &result)
        };
        let updated = match outcome {
            SignedApprovalOutcome::Verified => {
                state
                    .service
                    .resolve_approval(&req.approval_id, req.approve, "device_signed", Some(&approver_id))
                    .await?
            }
            SignedApprovalOutcome::AlreadyResolved(p) => p,
            SignedApprovalOutcome::AwaitingSignatures { approval, collected, required } => {
                // Valid and recorded, but the two-person rule wants another distinct device. 202:
                // accepted, not yet acted on. The body carries the progress so the signer's app
                // can say "1 of 2" rather than looking like the tap did nothing.
                tracing::info!(
                    approval = %req.approval_id,
                    approver = %approver_id,
                    collected,
                    required,
                    "device-signed approval recorded; awaiting more signatures (REST)"
                );
                let _room = state.service.display_room([&approval]).await?;
                let mut body = approval_json(&state, &approval, state.service.served_approval_audience().as_deref(), false);
                body.body["awaiting_signatures"] = json!(true);
                return Ok((axum::http::StatusCode::ACCEPTED, Json(body)).into_response());
            }
            SignedApprovalOutcome::Refused(why) => {
                tracing::warn!(approval = %req.approval_id, reason = %why, "device-signed approval refused (REST)");
                return Err(GatewayError::Denied(format!("device-signed approval refused: {why}")));
            }
        };
        return approval_response(&state, updated, false).await;
    }

    // Bearer-only path (no device signature). Refused when the gateway's approval floor sits at
    // device-signed (every bearer resolution blocked: the enrolled-device default / env force-on), OR when
    // THIS specific approval is a `device_signed`-tier rung even though the floor allows bearer
    // `approve`-tier resolutions. Either way an operator bearer riding the semi-trusted broker
    // cannot resolve it; only a device signature can.
    if state.service.require_device_signed_approval() {
        return Err(GatewayError::Denied(
            "this gateway requires device-signed approvals; resolve from a paired approval device".into(),
        ));
    }
    if let Some(pending) = state.service.store().get_approval(&req.approval_id)? {
        if pending.required_tier == "device_signed" {
            return Err(GatewayError::Denied(
                "this action requires a device-signed approval; resolve it from a paired approval device".into(),
            ));
        }
        // Belt and braces. A quorum is only ever set on the device_signed tier, which the check
        // above already refuses, but if one ever reached an approval a bearer can resolve, that
        // single bearer decision would silently stand in for the two people the rule demands.
        if pending.required_signatures > 1 {
            return Err(GatewayError::Denied(
                "this action requires signatures from several people's paired devices; resolve it from those devices".into(),
            ));
        }
    }
    // Each of these is read only alongside `device_sig`; on a bearer resolution that may otherwise proceed it would be dropped, and an `approver` would be recorded as the operator instead of the person it names.
    let signed_only = [
        ("approver", req.approver.is_some()),
        ("request_hash", req.request_hash.is_some()),
        ("decided_at", req.decided_at.is_some()),
        ("job_id", req.job_id.is_some()),
        ("approver_pubkey", req.approver_pubkey.is_some()),
        ("audience", req.audience.is_some()),
        ("display_digest", req.display_digest.is_some()),
    ];
    if let Some((member, _)) = signed_only.iter().find(|(_, given)| *given) {
        return Err(GatewayError::BadRequest(format!(
            "'{member}' is part of a device-signed resolution and is read only with device_sig; resolve with the operator bearer by sending approval_id and approve alone"
        )));
    }

    // The operator identity is what the chain can say about a bearer resolution: `operator:<sub>` for a
    // permaura.com sign-in, otherwise `operator`. Derived from the kind of session rather than copied
    // from its agent id, because `POST /v1/sessions` mints operator sessions under any registered
    // agent's id, and the chain must not name an agent as the human who approved.
    let approver = if op.agent_id.starts_with("operator:") { op.agent_id.as_str() } else { "operator" };
    let updated = state
        .service
        .resolve_approval_as(&req.approval_id, req.approve, "bearer", Some(approver), op.actor.as_ref())
        .await?;
    approval_response(&state, updated, false).await
}

/// Query for `GET /v1/approvals`.
#[derive(Deserialize)]
pub struct ApprovalsQuery {
    /// Optional status filter, e.g. `pending`.
    #[serde(default)]
    pub status: Option<String>,
}

/// Handler for `GET /v1/approvals`, the approval queue the desktop/phone app and the
/// `permaura pending` CLI render. Optionally filtered by `?status=pending`.
pub async fn list_approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ApprovalsQuery>,
) -> Result<Response, GatewayError> {
    // The pending-approval queue (with ids the resolve endpoint acts on) is operator-only.
    let _op = operator_authed(&state, &headers)?;
    let approvals = state
        .service
        .store()
        .list_approvals(q.status.as_deref())?;
    let audience = state.service.served_approval_audience();
    let running = state.service.executions().in_flight_approvals();
    let is_running = |a: &PendingApproval| a.status == "pending" && running.contains(&a.id);
    let room = state.service.display_room(approvals.iter().filter(|a| !is_running(a))).await?;
    // Written row by row around each result's own bytes, as `ApprovalListing` would serialize: the history lists every resolved result, each can be megabytes, and neither a copy beside its row nor the whole listing as one serialized body is held.
    let mut pieces = vec![axum::body::Bytes::from_static(b"{\"approvals\":[")];
    for (i, mut a) in approvals.into_iter().enumerate() {
        let result = a.result.take().unwrap_or_else(permaura_core::JsonText::null);
        // A row whose approval is running renders within the room the others reserved, or room the pool has at once, and is otherwise listed unrendered: queueing for room behind its own approval's reservation would hold every agent call queued behind it.
        let (_extra, render) = match crate::approval_display::tree_bytes(&a) {
            Some(tree) if is_running(&a) && tree > room.bytes() => match state.service.display_room_now([&a]) {
                Some(extra) => (Some(extra), true),
                None => (None, false),
            },
            _ => (None, true),
        };
        let serde_json::Value::Object(fields) = approval_json_rendered(&state, &a, audience.as_deref(), false, render).body else {
            return Err(GatewayError::Internal("an approval was not served as an object".into()));
        };
        if i > 0 {
            pieces.push(axum::body::Bytes::from_static(b","));
        }
        pieces.extend(crate::memory::Assembled::object(fields, "result", result).into_pieces());
    }
    pieces.push(axum::body::Bytes::from_static(b"]}"));
    let len = pieces.iter().map(|piece| piece.len()).sum();
    Ok(crate::memory::streamed_response(StatusCode::OK, len, pieces.into_iter()))
}

/// `GET /v1/approvals/:id`: poll an approval's status (`permaura.get_approval_status`).
/// Once approved, the response carries the redacted `result` of the held call.
pub async fn approval_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, GatewayError> {
    // Exposes the held call's redacted result once approved; operator-only on REST. (Agents
    // poll their own approvals through the MCP `permaura.get_approval_status` tool.)
    let _op = operator_authed(&state, &headers)?;
    let approval = state
        .service
        .store()
        .get_approval(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("approval '{id}'")))?;
    approval_response(&state, approval, true).await
}

/// One approval as a response, written around its result's own bytes as `ServedApproval` would serialize it, so the result is not copied beside the row it was read into.
/// A settled row is rendered only if the pool has room at once, and otherwise served with `params_rendered: false`: the answer to an approval that ran, or a denial recorded, is never a wait or a 429 for its rendering. So is a pending row whose approval is running, which nobody can act on until it settles: waiting for room behind its approval's own reservation would hold every agent call queued behind the wait.
async fn approval_response(state: &AppState, mut approval: PendingApproval, full: bool) -> Result<Response, GatewayError> {
    let running = state.service.executions().in_flight_approvals().contains(&approval.id);
    let (_room, render) = if approval.status == "pending" && !running {
        (state.service.display_room([&approval]).await?, true)
    } else {
        match state.service.display_room_now([&approval]) {
            Some(room) => (room, true),
            None => (crate::connectors::json_budget::MemoryCharge::none(), false),
        }
    };
    let result = approval.result.take().unwrap_or_else(permaura_core::JsonText::null);
    let serde_json::Value::Object(fields) = approval_json_rendered(state, &approval, state.service.served_approval_audience().as_deref(), full, render).body else {
        return Err(GatewayError::Internal("an approval was not served as an object".into()));
    };
    Ok(crate::memory::document_response(StatusCode::OK, crate::memory::Assembled::object(fields, "result", result)))
}

/// One approval as every surface reads it. `full` adds `params_display_full`, the uncapped rendering
/// an approve binds; only the single-approval read serves it, so a queue listing stays small.
fn approval_json(state: &AppState, a: &PendingApproval, audience: Option<&str>, full: bool) -> ServedApproval {
    approval_json_rendered(state, a, audience, full, true)
}

/// [`approval_json`], without building the params' tree when `render` is false: `params_display` has no rows, there is no `params_display_full`, and `params_rendered` is false.
fn approval_json_rendered(state: &AppState, a: &PendingApproval, audience: Option<&str>, full: bool, render: bool) -> ServedApproval {
    // The text fields are served escaped the way parameter values are, and the display digest
    // binds exactly these strings, so what a surface prints is what a device signs over.
    let text = crate::approval_display::ServedText::of(a);
    let inputs = crate::approval_display::RenderInputs::for_approval(state.service.store().as_ref(), a);
    let people_signed = state.service.people_signed(a);
    let mut body = json!({
        "id": a.id,
        "session_id": a.session_id,
        "capability": &text.capability,
        "resource": &text.resource,
        "message": &text.message,
        // What the agent said the call is for, served apart from the gateway's message so a surface
        // can label it as the agent's claim and set it against the parameters.
        "intent": &text.intent,
        "status": a.status,
        "created_at": a.created_at,
        "upstream_status": a.result_status,
        // The three metadata fields every approval surface carries, read back off the row exactly
        // as they were captured when the call was held, never recomputed here.
        //
        // `expires_at` is an absolute unix-ms epoch, or null for a hold with no deadline; it is
        // never omitted, because a client has to be able to tell "no deadline" from "this gateway
        // did not tell me", and one that reads a missing field as zero renders a deadline in 1970.
        // The same deadline the gateway enforces, including the day a held change stored without one lapses after.
        "expires_at": a.deadline(),
        // Why this approval ended where it did, or null when a human decided it. Never omitted, for
        // the same reason `expires_at` is not: reconciliation denies every pending approval with
        // the reason `restore`, and without this field that denial reaches every approval surface
        // looking exactly like an owner who said no.
        "resolution_reason": a.resolution_reason,
        // `unknown` on a row held before the gateway captured a classification. Deliberately not
        // backfilled from the catalogue: that guess is what this field exists to remove, and a
        // guess that renders as "low risk" on the approval screen is worse than an admission.
        "risk": &text.risk,
        "action_description": &text.action_description,
        // The ladder rung this approval must be resolved at (`approve` | `device_signed`): the
        // console renders a badge from it and hides bearer buttons for `device_signed` rows.
        "required_tier": a.required_tier,
        // Signing inputs for a device-signed approval: the phone signs a preimage bound to this
        // request_hash (recomputed here from the held call, so it can't be redirected) and job_id
        // (the approval id for a locally-held call).
        "request_hash": crate::service::held_request_hash(&a.capability, &a.params),
        // What the call would run with, redacted and capped, for every surface to show before a
        // human decides. A device binds the digest of what it rendered into a v3 signature,
        // and `verify_signed_approval` recomputes it from this row.
        "params_display": if render { crate::approval_display::compact_with(a, &inputs, &text) } else { crate::approval_display::unrendered_with(&text) },
        "job_id": a.id,
        // Which gateway a device signs for: bound into `approval_result_preimage_v2`. The same value
        // on every approval this gateway serves; a device pins it at pairing and refuses to sign when
        // the value served differs from its pin. Null only when this gateway cannot produce one.
        "approval_audience": audience,
        // Two-person progress. The console and the phone render "1 of 2" from these; `signatures`
        // names WHICH devices have signed so the second approver can see who they are joining.
        // Only public data: an approver id and a public-key fingerprint.
        // Both counts are PEOPLE, counted as the quorum counts them: an iPhone and the Watch paired
        // through it are one person, and a key bound to nobody is never the second.
        "required_signatures": a.required_signatures.max(1),
        "collected_signatures": people_signed,
        "people_signed": people_signed,
        "signatures": a.signatures.iter().map(|s| json!({
            "approver": s.approver,
            "key_fp": s.key_fp,
            "decided_at": s.decided_at,
        })).collect::<Vec<_>>(),
    });
    if full && render {
        body["params_display_full"] = json!(crate::approval_display::full_with(a, &inputs, &text));
    }
    if !render {
        body["params_rendered"] = json!(false);
    }
    // Only on a hold that records who asked, so a held agent call's JSON is unchanged: a device that is the requester's can stop offering Approve before the gateway refuses it.
    if let Some(requester) = &a.requested_by {
        body["requested_by"] = requester.served();
    }
    ServedApproval { body, result: a.result.clone() }
}

/// One approval as served: its fields, and its `result` written in as the text the row keeps, so a listing of results is never rebuilt into trees.
pub struct ServedApproval {
    /// Every field but `result`.
    pub body: serde_json::Value,
    /// The held call's redacted result, once it ran.
    pub result: Option<permaura_core::JsonText>,
}

impl Serialize for ServedApproval {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        if let Some(fields) = self.body.as_object() {
            for (key, value) in fields {
                map.serialize_entry(key, value)?;
            }
        }
        map.serialize_entry("result", &self.result)?;
        map.end()
    }
}

/// `GET /v1/approvals`'s body.
#[derive(Serialize)]
pub struct ApprovalListing {
    /// The approvals, most recent first.
    pub approvals: Vec<ServedApproval>,
}

// ── GET /v1/audit-events ────────────────────────────────────────────────────────

/// Query for `GET /v1/audit-events`.
#[derive(Deserialize)]
pub struct AuditQuery {
    /// Maximum number of (most recent) events to return, at most [`AUDIT_PAGE_MAX`].
    #[serde(default)]
    pub limit: Option<usize>,
}

/// The most events one `GET /v1/audit-events` returns, and what an absent `limit` means.
///
/// Every page is a copy of that many events out of the resident chain, and the route sits outside
/// admission control, so an unbounded page let a caller hold a copy of the whole hot window per
/// request. The clients ask for 50; the whole chain is `GET /v1/audit/export`, which streams.
pub const AUDIT_PAGE_MAX: usize = 1000;

/// Handler for `GET /v1/audit-events`. Returns the hash-chained events plus whether
/// the chain currently verifies.
///
/// It serves the **hot window**, and since the archive exists that is not the whole chain. The
/// response says so rather than letting a caller read a short answer as a complete one: `base_seq`
/// is where the window starts, and `window_only` is true whenever there is an archive behind it or
/// the caller asked for more events than the window holds. `chain_intact` names the range it
/// actually covers, because a bare `true` that silently covers less than it used to is exactly the
/// weakened assertion this whole change is meant to avoid. The full walk is
/// `GET /v1/audit/verify-full`.
pub async fn audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // The audit log reveals every action; operator-only.
    let _op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let limit = q.limit.unwrap_or(AUDIT_PAGE_MAX).min(AUDIT_PAGE_MAX);
    let events = store.audit_events(Some(limit))?;
    let intact = store.verify_audit()?.is_none();
    let base_seq = store.audit_boundary()?.map(|b| b.base_seq).unwrap_or(0);
    let held = store.audit_len()?;
    let truncated = held > limit as u64 && q.limit.is_none_or(|n| n > limit);
    // A sibling map rather than a field on each event, because an event is a signed record and a
    // verifier re-hashes exactly what it is given.
    let diagnostics: serde_json::Map<String, serde_json::Value> = match events.first() {
        Some(first) => store
            .call_diagnostics(first.seq)?
            .into_iter()
            .map(|d| {
                let mut entry = json!({ "message": d.message, "recorded_at": d.recorded_at });
                if !d.headers.is_empty() {
                    entry["headers"] = json!(d.headers);
                }
                (d.audit_seq.to_string(), entry)
            })
            .collect(),
        None => serde_json::Map::new(),
    };
    Ok(Json(json!({
        "events": events,
        "diagnostics": diagnostics,
        "diagnostics_retention_days": crate::store::CALL_DIAGNOSTICS_RETENTION_MS / (24 * 60 * 60 * 1000),
        "chain_intact": intact,
        // The window this answer covers, and the range `chain_intact` was decided over.
        "base_seq": base_seq,
        "verified_from": base_seq,
        "verified_to": if held == 0 { None } else { Some(base_seq + held - 1) },
        "archive_checked": false,
        "window_only": base_seq > 0 || q.limit.is_some_and(|n| n as u64 > held) || truncated,
        // The page size this answer was cut to, so a caller asking for more than the cap can tell.
        "limit": limit,
        // `chain_intact` says the window verifies under THIS key; whether this key is the one the chain
        // started under is a question only a copy held outside the store can answer.
        "audit_key": crate::audit_key::report_for(store.as_ref()),
        // A recorded rekey (`permaura audit rekey`): the events below `seq` were signed under a key this
        // store no longer holds, so `chain_intact` covers their hashes and links and not their signatures.
        "key_fork": store.audit_rekey()?.map(|r| json!({
            "seq": r.seq,
            "prior_head_seq": r.seq.checked_sub(1),
            "prior_head_hash": r.prior_head_hash,
            "at": r.taken_at,
            "signatures_unverifiable_below": r.seq,
        })),
    })))
}

/// Handler for `DELETE /v1/audit/diagnostics`. Delete every stored call diagnostic (the free-text
/// error messages kept beside the chain) and report how many there were. The chain is untouched, and
/// each event's `"diagnostic": true` then reads as "no longer retained".
pub async fn purge_call_diagnostics(
    State(state): State<AppState>,
    headers: HeaderMap,
    _: NoBody,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let purged = store.purge_call_diagnostics()?;
    // Recorded, so an event whose `"diagnostic": true` has no row can be told apart as purged rather
    // than aged out, and so the purge itself is attributable.
    let mut payload = permaura_core::AuditPayload::new(DIAGNOSTICS_PURGE_ACTION, "audit", "allow");
    payload.agent_id = Some(op.agent_id.clone());
    payload.session_id = Some(op.id.clone());
    payload.user_id = op.user_id.clone();
    payload.summary = json!({ "purged": purged });
    insert_actor(&mut payload.summary, &op);
    store.append_audit(payload)?;
    Ok(Json(json!({ "purged": purged })))
}

/// The audit action recorded when an operator purges the stored call diagnostics.
pub const DIAGNOSTICS_PURGE_ACTION: &str = "permaura.audit.diagnostics.purge";

// ── GET /v1/audit/verify-full · GET /v1/audit/export ─────────────────────────────────────────────

/// Handler for `GET /v1/audit/verify-full`. Walk the archive and then the hot window, and prove one
/// continuous signed chain from seq 0.
///
/// Operator only, and allowed to be slow: it fetches and hashes every published segment. 404 when
/// this gateway has no archive, because "there is nothing to walk" and "the walk found nothing
/// wrong" are different answers and a caller must not read the first as the second.
pub async fn verify_audit_full(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let walk = state.limits.try_chain_walk()?;
    let archive = state.service.audit_archive().cloned().ok_or_else(|| {
        GatewayError::NotFound(
            "this gateway has no audit archive configured, so there is nothing to verify across a boundary: GET /v1/audit-events reports the hot window".into(),
        )
    })?;
    let store = state.service.store().clone();
    let report = tokio::task::spawn_blocking(move || {
        let _walk = walk;
        archive.verify_full(store.as_ref())
    })
        .await
        .map_err(|e| GatewayError::Internal(format!("verification task: {e}")))??;
    Ok(Json(report.to_json()))
}

/// The key the export's last line carries, so a reader can tell the footer from an event without
/// having to count lines.
pub const EXPORT_FOOTER_KEY: &str = "permaura_audit_export";

/// Handler for `GET /v1/audit/export`. Stream the archive and then the hot window as one NDJSON.
///
/// Streamed rather than assembled, because the chain this exports is the one that did not fit in
/// the hot store: a tenant with half a million archived events would otherwise need all of them
/// resident to be handed any of them. One segment and one batch are in memory at a time.
///
/// The last line is a JSON object under [`EXPORT_FOOTER_KEY`] carrying the index, the boundary and
/// `complete`. With the archive unreachable the export still serves the hot window and marks itself
/// `"complete": false`; it is **never** a silent partial.
pub async fn export_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<axum::response::Response, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let walk = state.limits.try_chain_walk()?;
    let store = state.service.store().clone();
    let archive = state.service.audit_archive().cloned();
    let batch = crate::archive::DEFAULT_BATCH;

    // A small channel and a blocking producer: the store and the object store are both synchronous,
    // and back-pressure from a slow reader is what keeps the producer from running ahead of it.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(4);
    tokio::task::spawn_blocking(move || {
        let _walk = walk;
        let mut complete = true;
        let boundary = store.audit_boundary().ok().flatten();

        // Through the verified reader, so the export is exactly the history verification proves and
        // a rebuild would count: the store's own lineage, never an abandoned branch, and never a
        // segment that does not check out under the store's key.
        if let (Some(archive), Some(boundary)) = (archive.as_ref(), boundary.as_ref()) {
            let walk = crate::archive::ArchivedEvents::new(archive, store.as_ref());
            match walk {
                Ok(walk) if walk.boundary() == boundary => {
                    for event in walk {
                        match event {
                            Ok(event) => {
                                if !send_line(&tx, &event) {
                                    return;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "the audit export could not prove the whole archive; marking the export incomplete");
                                complete = false;
                                break;
                            }
                        }
                    }
                }
                Ok(_) => {
                    tracing::warn!("the audit boundary moved while the export started; marking the export incomplete");
                    complete = false;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the audit export could not read the archive; marking the export incomplete");
                    complete = false;
                }
            }
        } else if boundary.as_ref().is_some_and(|b| b.base_seq > 0) {
            // Pruned history this gateway cannot read is still history, and an export that began at
            // the hot window without saying so would be the silent partial the footer exists to stop.
            complete = false;
        }

        // The hot window, in batches, whatever happened above. It has to start exactly at the base
        // the archive walk proved up to: a prune in between moves the window on, and the events it
        // skipped are in neither half of this export.
        let mut cursor = boundary.as_ref().map(|b| b.base_seq).unwrap_or(0);
        loop {
            match store.audit_events_from(cursor, batch) {
                Ok(events) if events.is_empty() => break,
                Ok(events) => {
                    if events[0].seq != cursor {
                        complete = false;
                    }
                    cursor = events[events.len() - 1].seq + 1;
                    for event in events {
                        if !send_line(&tx, &event) {
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the audit export could not read the whole hot window");
                    complete = false;
                    break;
                }
            }
        }

        let index = archive
            .as_ref()
            .zip(boundary.as_ref())
            .and_then(|(a, b)| a.lineage_indexes(b).ok())
            .map(|i| serde_json::to_value(i).unwrap_or(serde_json::Value::Null));
        let footer = json!({
            EXPORT_FOOTER_KEY: {
                "complete": complete,
                "boundary": boundary,
                "index": index,
                "archive_configured": archive.is_some(),
            }
        });
        let mut line = serde_json::to_vec(&footer).unwrap_or_default();
        line.push(b'\n');
        let _ = tx.blocking_send(Ok(line));
    });

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    axum::response::Response::builder()
        .header("content-type", "application/x-ndjson")
        .body(axum::body::Body::from_stream(stream))
        .map_err(|e| GatewayError::Internal(format!("audit export response: {e}")))
}

/// Serialise one event as an NDJSON line and hand it to the stream. `false` means the reader has
/// gone, and the producer stops rather than serialising the rest of a chain nobody is reading.
fn send_line(
    tx: &tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    event: &permaura_core::AuditEvent,
) -> bool {
    let Ok(mut line) = serde_json::to_vec(event) else { return false };
    line.push(b'\n');
    tx.blocking_send(Ok(line)).is_ok()
}

// ── POST /v1/vault/export · /v1/vault/import/preview · /v1/vault/import ──────────

/// Audit action for an export. Deliberately its own id rather than a decision folded into some
/// capability's row: an export is the one call that legitimately concentrates every credential in
/// the estate, so it must be greppable on its own.
const VAULT_EXPORT_ACTION: &str = "permaura.vault.export";
/// Audit action for an import: the write half, likewise on its own id.
const VAULT_IMPORT_ACTION: &str = "permaura.vault.import";

/// The resource every vault-portability event is recorded against. There is no connection involved:
/// the subject is the vault itself.
pub(crate) const VAULT_RESOURCE: &str = "vault";

/// The capability a held export is recorded under, so a device prompt and the audit row name the
/// same thing the endpoint does.
pub(crate) const VAULT_EXPORT_CAP: &str = "permaura.vault.export";

/// Append an audit event for a vault export/import.
///
/// `summary` must carry counts and ids only. The bundle body, the passphrase and every secret value
/// are out of bounds here exactly as they are in a log line.
fn audit_vault(
    state: &AppState,
    session: &Session,
    action: &str,
    decision: &str,
    summary: serde_json::Value,
) -> Result<(), GatewayError> {
    let mut payload = permaura_core::AuditPayload::new(action, VAULT_RESOURCE, decision);
    payload.user_id = session.user_id.clone();
    payload.session_id = Some(session.id.clone());
    payload.summary = summary;
    insert_actor(&mut payload.summary, session);
    state.service.store().append_audit(payload)?;
    Ok(())
}

/// Name the workspace member behind an operator action in its audit summary, when the operator token
/// said who that was. Display only; see [`crate::store::SessionActor`].
fn insert_actor(summary: &mut serde_json::Value, session: &Session) {
    let (Some(actor), Some(map)) = (&session.actor, summary.as_object_mut()) else { return };
    map.insert("actor".into(), json!(actor.sub));
    if let Some(name) = &actor.name {
        map.insert("actor_name".into(), json!(name));
    }
}

/// Body for `POST /v1/vault/export`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultExportReq {
    /// The customer's passphrase, which seals the bundle. Never stored, never logged, never echoed:
    /// the copy on our side is the one we chose not to keep, so a lost passphrase is a lost bundle.
    pub passphrase: String,
    /// The approval a device has already signed, when resuming a held export. Absent on the first
    /// call, which is what gets held; the 202 body carries the id to come back with.
    #[serde(default)]
    pub approval_id: Option<String>,
    /// The `resume_secret` the 202 carried, required with `approval_id`. Only the caller that asked
    /// ever saw it, so another holder of the operator bearer cannot collect the bundle.
    #[serde(default)]
    pub resume_secret: Option<String>,
}

/// Body for `POST /v1/vault/import/preview` and `POST /v1/vault/import`.
///
/// Note what is *not* here: [`ImportOptions::hosted`]. That flag is what refuses a Command
/// capability outright on a hosted worker, so it is read from this process's own posture and a
/// client is given no way to set it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultImportReq {
    /// The bundle, verbatim as exported.
    #[serde(deserialize_with = "crate::request_body::strict_bundle")]
    pub bundle: permaura_core::VaultBundle,
    /// The passphrase it was sealed under.
    pub passphrase: String,
    /// What to do about ids that already exist here. Defaults to skip, so an import can never
    /// silently overwrite. Ignored by the preview.
    #[serde(default)]
    pub on_conflict: crate::vault_bundle::OnConflict,
    /// Opt in to writing capabilities that run a local program. The preview reports what the import would refuse with it.
    #[serde(default)]
    pub allow_command_capabilities: bool,
}

/// How long a bundle seal or open waits for the one running before it is turned away with a 429.
const BUNDLE_KDF_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// The permit for one bundle seal or open: [`crate::vault_bundle::BUNDLE_KDF`], waited for up to
/// [`BUNDLE_KDF_WAIT`].
async fn bundle_kdf_permit() -> Result<tokio::sync::SemaphorePermit<'static>, GatewayError> {
    bundle_kdf_permit_within(BUNDLE_KDF_WAIT).await
}

async fn bundle_kdf_permit_within(
    wait: std::time::Duration,
) -> Result<tokio::sync::SemaphorePermit<'static>, GatewayError> {
    match tokio::time::timeout(wait, crate::vault_bundle::BUNDLE_KDF.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(GatewayError::Internal("the bundle key-derivation gate is closed".into())),
        Err(_) => Err(GatewayError::TooManyRequests {
            reason: "bundle_open".into(),
            message: "another vault bundle is being sealed or opened on this gateway; try again shortly".into(),
            retry_after_secs: 5,
            scope: None,
        }),
    }
}

/// Open a bundle and read its payload, or fail with a message an operator can act on.
///
/// [`permaura_core::open_bundle`] reports a wrong passphrase and a tampered ciphertext identically and
/// as a `Crypto` error, which would otherwise render as a 500. To the operator both are a bad input,
/// and the difference between "check your passphrase" and "the gateway broke" is the whole usability
/// of this step. A header that disagrees with the seal arrives as `Tampered` and keeps its own message
/// through `From`, because a modified file is not fixed by retyping a passphrase.
fn open_bundle_payload(
    bundle: &permaura_core::VaultBundle,
    passphrase: &[u8],
) -> Result<crate::vault_bundle::BundlePayload, GatewayError> {
    use crate::vault_bundle::OpenPayloadError;
    crate::vault_bundle::open_payload(bundle, passphrase).map_err(|e| match e {
        OpenPayloadError::Open(permaura_core::PermauraError::Crypto(_)) => GatewayError::BadRequest(
            "the bundle could not be opened: the passphrase is wrong, or the sealed contents have \
             been damaged. Check for stray spaces at either end of the passphrase, and that you \
             copied all of it. Nothing has been imported."
                .into(),
        ),
        OpenPayloadError::Open(other) => GatewayError::from(other),
        OpenPayloadError::Unreadable(reason) => {
            GatewayError::BadRequest(format!("the bundle's payload is not readable by this build: {reason}"))
        }
    })
}

/// Handler for `POST /v1/vault/export`. Resolves every exportable secret through the custody seam,
/// re-seals the lot under the caller's passphrase, and returns the bundle.
///
/// POST, not GET, and that is load-bearing: the permaura.com proxy classifies every GET as an open
/// read available to any workspace member, so a GET here would hand the whole vault to a read-only
/// viewer.
pub async fn export_vault(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<VaultExportReq>,
) -> Result<axum::response::Response, GatewayError> {
    use axum::response::IntoResponse as _;
    let op = operator_authed(&state, &headers)?;
    // The execution hold. Not an upstream call, but the one route that concentrates every
    // credential this gateway holds into a single file, which makes it the exfiltration path a
    // tenant running on restored authority must not have. Above the approval branch so a held
    // export neither raises an approval nor burns one that was already signed.
    state.service.refuse_if_held()?;
    if unpaired_remote_self_run(&state, remote) {
        audit_vault(&state, &op, VAULT_EXPORT_ACTION, "deny", json!({ "reason": "refused from off this host: nothing would hold it for a device (none is paired, or approvals are opted down)" }))?;
        return Err(unpaired_remote_refusal("a vault export hands over every credential on this gateway"));
    }
    let passphrase = zeroize::Zeroizing::new(req.passphrase.into_bytes());
    if passphrase.is_empty() {
        return Err(GatewayError::BadRequest(
            "a passphrase is required: it is the only thing protecting the exported bundle".into(),
        ));
    }

    // The device gate. Held wherever the call arrived from, loopback included; see
    // `vault_export_hold_required`, and the operator token this authenticated with is a 0600 file
    // every process running as this user can read.
    //
    // A request that names a collect is always resolved against the hold it names, whether or not a hold would be required now: served only for a live, signed hold of the caller's, refused otherwise, never answered as a fresh export.
    if let Some(id) = req.approval_id.as_deref() {
        if let Err(e) = consume_export_approval(&state, id, req.resume_secret.as_deref()) {
            audit_vault(&state, &op, VAULT_EXPORT_ACTION, "deny", json!({ "approval_id": id, "reason": "a collect the named hold does not allow" }))?;
            return Err(e);
        }
    } else if req.resume_secret.is_some() {
        audit_vault(&state, &op, VAULT_EXPORT_ACTION, "deny", json!({ "reason": "a resume_secret with no approval_id" }))?;
        return Err(GatewayError::BadRequest(
            "this gateway holds no export to collect; send a new export request".into(),
        ));
    } else if state.service.vault_export_hold_required() {
        let message = "Confirm a vault export: this produces a single file containing every \
                       credential in this gateway, sealed under the requester's passphrase."
            .to_string();
        let (approval, resume_secret) =
            state.service.hold_vault_export_approval(VAULT_EXPORT_CAP, &message, requester_of(&op, remote))?;
        audit_vault(&state, &op, VAULT_EXPORT_ACTION, "hold", json!({ "approval_id": approval.id }))?;
        let mut body = held_body(&approval);
        body["resume_secret"] = json!(resume_secret);
        return Ok((StatusCode::ACCEPTED, Json(body)).into_response());
    }

    let store = state.service.store();
    let ids = crate::vault_bundle::enumerate_secret_ids(store.as_ref())?;
    let mut resolved = Vec::with_capacity(ids.len());
    for id in ids {
        // Which custody layer answered is not something the seam reports: `resolve` is uniform by
        // design, so it is inferred from whether the value is sealed in this store at all.
        let custody = if store.get_secret(&id)?.is_some() { "local_vault" } else { "external" };
        let opened = state.service.backend().resolve(&id).await.map_err(|e| {
            GatewayError::Internal(format!(
                "refusing to export a partial bundle: secret '{id}' could not be resolved through \
                 its custody backend ({e})"
            ))
        })?;
        resolved.push((
            id,
            custody.to_string(),
            crate::vault_bundle::SecretValue::new(opened.bytes().to_vec()),
        ));
        drop(opened);
    }

    let payload = crate::vault_bundle::build_payload(store.as_ref(), resolved)?;
    let counts = json!({
        "connections": payload.connections.len(),
        "policies": payload.policies.len(),
        "grants": payload.grants.len(),
        "capabilities": payload.capabilities.len(),
        "secrets": payload.secrets.len(),
    });
    let source = permaura_core::BundleSource {
        gateway_id: state.gateway_id.clone(),
        mode: if state.hosted { "hosted" } else { "self-run" }.to_string(),
    };
    let _kdf = bundle_kdf_permit().await?;
    let bundle = crate::vault_bundle::seal_payload(&passphrase, &payload, now_ms(), source)?;
    drop(payload);
    permaura_core::secret::clear_stack();

    audit_vault(&state, &op, VAULT_EXPORT_ACTION, "allow", counts)?;
    Ok(Json(bundle).into_response())
}

/// Check that a device really signed THIS export, and burn the approval so one signature cannot be
/// replayed into a second bundle.
///
/// One-shot matters more here than on a held mutation: a mutation reapplied is idempotent, whereas a
/// replayed export is another complete copy of every credential, obtainable from a signature the
/// owner gave once and reasonably believes was spent.
fn consume_export_approval(
    state: &AppState,
    approval_id: &str,
    resume_secret: Option<&str>,
) -> Result<(), GatewayError> {
    let store = state.service.store();
    let mut approval = store.get_approval(approval_id)?.ok_or_else(|| {
        GatewayError::BadRequest(format!(
            "this gateway holds no export to collect under approval '{approval_id}'; send a new export request"
        ))
    })?;
    if approval.capability != VAULT_EXPORT_CAP || !approval.session_id.is_empty() {
        return Err(GatewayError::BadRequest(format!(
            "approval '{approval_id}' was raised for {} and cannot authorise a vault export",
            approval.capability
        )));
    }
    // Before anything about the approval's state, so a caller without the secret learns nothing.
    let expected = permaura_core::json_stream::string_at(&approval.params, "/resume_sha256").unwrap_or_default();
    let presented = resume_secret.map(crate::service::export_resume_digest).unwrap_or_default();
    if expected.is_empty() || !digests_match(presented.as_bytes(), expected.as_bytes()) {
        return Err(GatewayError::Denied(format!(
            "approval '{approval_id}' can be collected only with the resume_secret returned to the caller that requested the export"
        )));
    }
    if approval.expires_at.is_some_and(|at| now_ms() > at) {
        return Err(GatewayError::BadRequest(format!(
            "approval '{approval_id}' expired before the bundle was collected: request another export and confirm it on your device"
        )));
    }
    if approval.status == "pending" && !state.service.vault_export_hold_required() {
        return Err(GatewayError::BadRequest(format!(
            "approval '{approval_id}' was waiting for a device that is no longer trusted, so nothing can confirm it; send a new export request"
        )));
    }
    if approval.status != "approved" {
        return Err(GatewayError::BadRequest(format!(
            "approval '{approval_id}' is {}; a vault export needs a device signature first",
            approval.status
        )));
    }
    // `result`, not `result_status`: the latter is an upstream HTTP status (`Option<u16>`) and has
    // no room for this. A vault-export approval executes no upstream call, so `result` is free.
    if approval.result.as_ref().and_then(|r| permaura_core::json_stream::string_at(r, "/vault_export")).is_some() {
        return Err(GatewayError::BadRequest(format!(
            "approval '{approval_id}' has already produced a bundle. Signatures are one-shot: \
             request another export and confirm it on your device."
        )));
    }
    // The database arbitrates concurrent instances. The spent marker outlives the approval's own
    // expiry, because pruning it would make a stale approval snapshot usable again.
    // A restored approval is an approval whose export claim was rolled back with the database, and
    // the signature that authorised it was given before the restore.
    crate::restore::refuse_if_replayed_across_a_restore(
        store.as_ref(),
        approval.created_at,
        "vault export approval",
    )?;
    if !store.claim_once("vault-export", approval_id, i64::MAX)? {
        return Err(GatewayError::BadRequest(format!(
            "approval '{approval_id}' has already been claimed for a vault export"
        )));
    }
    approval.result = Some(json!({ "vault_export": "consumed", "at": now_ms() }).into());
    store.put_approval(approval)?;
    Ok(())
}

fn digests_match(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Handler for `POST /v1/vault/import/preview`. Opens the bundle and describes what importing it
/// would do, writing nothing. A wrong passphrase fails here, which is the point of the step.
pub async fn preview_vault_import(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<VaultImportReq>,
) -> Result<Json<crate::vault_bundle::ImportManifest>, GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let passphrase = zeroize::Zeroizing::new(req.passphrase.into_bytes());
    let payload = {
        let _kdf = bundle_kdf_permit().await?;
        open_bundle_payload(&req.bundle, &passphrase)?
    };
    permaura_core::secret::clear_stack();
    let store = state.service.store();
    let mut manifest = crate::vault_bundle::preview(
        store.as_ref(),
        &payload,
        req.bundle.created_at_ms,
        req.bundle.source.gateway_id.clone(),
        req.bundle.source.mode.clone(),
    )?;
    // What `import_vault` would refuse from here with the same on_conflict, so the console can say so first.
    if state.service.control_plane_hold_required(remote) {
        manifest.broker_refusals = crate::vault_bundle::broker_import_refusals(
            store.as_ref(),
            state.service.backend().as_ref(),
            &payload,
            req.on_conflict,
        )?;
    } else if state.service.vault_export_hold_required()
        || unpaired_remote_self_run(&state, remote)
        || state.hosted && !state.service.any_device_trusted()
        || !may_move_a_credential(&state, &op, remote)
    {
        manifest.broker_refusals = crate::vault_bundle::credential_reach_refusals(
            store.as_ref(),
            state.service.backend().as_ref(),
            &payload,
            req.on_conflict,
        )?;
    }
    // What the import itself would refuse of this bundle with the same options, so the preview reads allow_command_capabilities as the import does.
    if remote && req.allow_command_capabilities {
        manifest.broker_refusals.push(REMOTE_COMMAND_IMPORT.into());
    }
    let opts = crate::vault_bundle::ImportOptions {
        on_conflict: req.on_conflict,
        allow_command_capabilities: req.allow_command_capabilities,
        hosted: state.hosted,
        revocation: None,
    };
    if let Err(refused) = crate::vault_bundle::validate(store.as_ref(), &payload, &opts) {
        manifest.broker_refusals.push(match refused {
            GatewayError::BadRequest(why) | GatewayError::Denied(why) | GatewayError::Conflict(why) => why,
            other => other.to_string(),
        });
    }
    Ok(Json(manifest))
}

/// Why an import that writes command capabilities is refused from anywhere but the gateway's own host.
const REMOTE_COMMAND_IMPORT: &str = "an import that writes capabilities which run a local program is accepted only from the gateway's own host";

/// Handler for `POST /v1/vault/import`. Opens the bundle, then applies it: idempotent upserts,
/// non-destructive unless the caller explicitly chose replace.
pub async fn import_vault(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<VaultImportReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    // A program that runs as the owner's OS user is only ever accepted from the owner's own host.
    if remote && req.allow_command_capabilities {
        audit_vault(&state, &op, VAULT_IMPORT_ACTION, "deny", json!({
            "reason": "command capabilities over the broker", "on_conflict": req.on_conflict,
        }))?;
        return Err(GatewayError::Denied(REMOTE_COMMAND_IMPORT.into()));
    }
    let passphrase = zeroize::Zeroizing::new(req.passphrase.into_bytes());
    // Before any write: a wrong passphrase or a tampered file stops the request here.
    let mut payload = {
        let _kdf = bundle_kdf_permit().await?;
        open_bundle_payload(&req.bundle, &passphrase)?
    };
    permaura_core::secret::clear_stack();
    let opts = crate::vault_bundle::ImportOptions {
        on_conflict: req.on_conflict,
        allow_command_capabilities: req.allow_command_capabilities,
        // This process's own posture, never the request body: a client that could set this would be
        // able to switch off the hosted refusal of Command capabilities.
        hosted: state.hosted,
        revocation: Some(state.pmconn_revocation.clone()),
    };
    // Before a credential fill below can park a hold a device could still approve for a bundle the apply then refuses.
    crate::vault_bundle::validate(state.service.store().as_ref(), &payload, &opts)?;
    let metadata_limit = state.limits.config().secret_metadata_bytes;
    for s in &payload.secrets {
        crate::secret_inventory::refuse_oversized_secret_metadata(&s.id, &s.metadata, metadata_limit)?;
    }

    let store = state.service.store();
    let _cp = state.service.control_plane_mutex().lock().await;
    // Judged under the control-plane lock, against the state the apply below will write into.
    let reach = crate::vault_bundle::credential_reach_refusals(
        store.as_ref(),
        state.service.backend().as_ref(),
        &payload,
        req.on_conflict,
    )?;
    // The refusals the PATCH funnel gives a change that moves a stored credential, for the bulk route that can make the same change.
    if !reach.is_empty() && !unpaired_remote_self_run(&state, remote) {
        let what = format!(
            "this import would replace a connection or capability, or attach new ones to a credential already here ({})",
            reach.join("; ")
        );
        let refused = if state.hosted && !state.service.any_device_trusted() {
            Some(("refused on a hosted worker no device is paired to", unpaired_hosted_refusal(&what)))
        } else if !may_move_a_credential(&state, &op, remote) {
            Some((
                "the requester lacks the standing a vault export takes",
                GatewayError::Denied(format!(
                    "{what}, which hands that credential to whoever chose the bundle's hosts, so it takes the standing a vault export does: {CREDENTIAL_MOVE_STANDING}. Ask one of them to make this import."
                )),
            ))
        } else {
            None
        };
        if let Some((reason, refusal)) = refused {
            audit_vault(&state, &op, VAULT_IMPORT_ACTION, "deny", json!({
                "reason": reason, "refusals": reach, "on_conflict": req.on_conflict,
                "source_gateway_id": req.bundle.source.gateway_id,
            }))?;
            return Err(refusal);
        }
    }
    if state.service.control_plane_hold_required(remote) {
        let refusals = crate::vault_bundle::broker_import_refusals(
            store.as_ref(),
            state.service.backend().as_ref(),
            &payload,
            req.on_conflict,
        )?;
        if !refusals.is_empty() {
            audit_vault(&state, &op, VAULT_IMPORT_ACTION, "deny", json!({
                "reason": "device signature required", "refusals": refusals, "on_conflict": req.on_conflict,
                "source_gateway_id": req.bundle.source.gateway_id,
            }))?;
            return Err(GatewayError::Denied(format!(
                "this import arrived over the broker and a paired device must sign control-plane changes, so it cannot be applied on a bearer alone ({}). Import it from the gateway's own host, or import only new connections and credentials and recreate policies and grants from the console.",
                refusals.join("; ")
            )));
        }
    } else if unpaired_remote_self_run(&state, remote) {
        let refusals = reach;
        if !refusals.is_empty() {
            audit_vault(&state, &op, VAULT_IMPORT_ACTION, "deny", json!({
                "reason": "refused from off this host: nothing would hold it for a device (none is paired, or approvals are opted down)", "refusals": refusals, "on_conflict": req.on_conflict,
                "source_gateway_id": req.bundle.source.gateway_id,
            }))?;
            return Err(unpaired_remote_refusal(&format!(
                "this import would replace a connection or capability, or attach new ones to a credential already here ({})",
                refusals.join("; ")
            )));
        }
    } else if state.service.vault_export_hold_required() {
        // Loopback is not evidence of a human: the operator token is a 0600 file every process the
        // owner runs can read, and this is the bulk route to pointing a credential already here at a
        // host of the bundle's choosing.
        let refusals = reach;
        if !refusals.is_empty() {
            audit_vault(&state, &op, VAULT_IMPORT_ACTION, "deny", json!({
                "reason": "device signature required", "refusals": refusals, "on_conflict": req.on_conflict,
                "source_gateway_id": req.bundle.source.gateway_id,
            }))?;
            return Err(GatewayError::Denied(format!(
                "a device is paired with this gateway, so an import may not replace a connection or capability or attach new ones to a credential already here on the operator token alone ({}). Import only new connections with their own credentials, or make the change from the console where the device signs it.",
                refusals.join("; ")
            )));
        }
    }
    // A bundled credential for an id a connection or capability here already names, with no row behind
    // it, sets that connection's credential: the write `POST /v1/secrets` holds for a device. It goes
    // exactly as that write would: held by reference while a device signature is required, else written.
    let mut fills: Vec<(String, String)> = Vec::new();
    for s in &payload.secrets {
        if store.get_secret(&s.id)?.is_none() {
            if let Some(conn) = secret_backing_ref(store.as_ref(), &s.id)? {
                fills.push((s.id.clone(), conn));
            }
        }
    }
    let mut held: Vec<serde_json::Value> = Vec::new();
    let mut unheld_fills = Vec::new();
    if !fills.is_empty() && remote {
        if !state.service.control_plane_hold_required(remote) {
            unheld_fills = fills.iter().map(|(id, conn)| format!("secret {id} for connection {conn}")).collect();
        } else {
            let (to_hold, rest): (Vec<_>, Vec<_>) =
                std::mem::take(&mut payload.secrets).into_iter().partition(|s| fills.iter().any(|(id, _)| *id == s.id));
            payload.secrets = rest;
            let mut sealed_fills = Vec::with_capacity(to_hold.len());
            for s in to_hold {
                let sealed = seal(Cipher::Aes256Gcm, vault_passphrase(), s.value.bytes())
                    .map_err(|e| GatewayError::Internal(format!("seal failed: {e}")))?;
                sealed_fills.push((s, sealed));
            }
            // The whole set against both bounds first, so a refusal stages none of it rather than the first few.
            let requester = requester_of(&op, remote);
            let shape = crate::secret_inventory::mint_staging_secret_id();
            let adding = sealed_fills
                .iter()
                .map(|(s, sealed)| crate::secret_inventory::secret_row_bytes(&shape, sealed, &s.metadata))
                .fold(0usize, usize::saturating_add);
            let pending = store.count_pending_approvals()?;
            let held_rows = || {
                sealed_fills.iter().try_fold(0u64, |total, (s, sealed)| {
                    let mutation = crate::policy_guard::Mutation::CredentialPromote {
                        connection_id: fills.iter().find(|(id, _)| *id == s.id).map(|(_, c)| c.clone()).unwrap_or_default(),
                        secret_id: s.id.clone(),
                        staging_secret_id: shape.clone(),
                        staged_sha256: crate::secret_inventory::staged_digest(sealed),
                    };
                    let row = state.service.control_plane_hold_bytes(POLICY_WRITE_CAP, &mutation, held_remote_note(&requester), requester.clone())?;
                    Ok::<u64, GatewayError>(total.saturating_add(row))
                })
            };
            let bounded = if pending.saturating_add(sealed_fills.len()) > crate::store::MAX_PENDING_APPROVALS {
                Err(crate::store::too_many_held_together(sealed_fills.len(), pending))
            } else {
                refuse_over_staged_bytes(&state, store.as_ref(), requester.as_ref(), adding).and_then(|()| {
                    state.service.refuse_over_control_plane_hold_bytes(held_rows()?, sealed_fills.len())
                })
            };
            if let Err(refused) = bounded {
                audit_vault(&state, &op, VAULT_IMPORT_ACTION, "deny", json!({
                    "reason": "the credential fills it would hold for a device pass a staging bound", "error": refused.to_string(),
                    "fills": sealed_fills.len(), "on_conflict": req.on_conflict, "source_gateway_id": req.bundle.source.gateway_id,
                }))?;
                return Err(refused);
            }
            for (s, sealed) in sealed_fills {
                let connection_id = fills.iter().find(|(id, _)| *id == s.id).map(|(_, c)| c.clone()).unwrap_or_default();
                let staged = hold_credential_checked(
                    &state,
                    store.as_ref(),
                    connection_id,
                    s.id.clone(),
                    sealed,
                    s.metadata.clone(),
                    requester_of(&op, remote),
                    false,
                );
                let mut body = match staged {
                    Ok((_, body)) => body,
                    Err(e) => {
                        audit_vault(&state, &op, VAULT_IMPORT_ACTION, "error", json!({
                            "stopped": "the import stopped while holding its credential fills; the holds before this error stand and nothing else was applied",
                            "error": e.to_string(), "held": held.iter().map(|h| h["approval_id"].clone()).collect::<Vec<_>>(),
                            "on_conflict": req.on_conflict, "source_gateway_id": req.bundle.source.gateway_id,
                        }))?;
                        return Err(e);
                    }
                };
                body["secret_id"] = json!(s.id);
                held.push(body);
            }
        }
    }
    let held_ids = held.iter().map(|h| h["approval_id"].clone()).collect::<Vec<_>>();
    let mut payload = Some(payload);
    let mut outcome = crate::vault_bundle::ImportOutcome::default();
    store.change_with_record(&mut || {
        let Some(payload) = payload.take() else { return Ok(()) };
        let applied = crate::vault_bundle::apply(store.as_ref(), payload, &opts, |id, metadata, bytes| {
            // Re-seal under THIS gateway's vault KEK, exactly as the credential-write path does: the
            // bundle's own passphrase protects the file in transit and nothing beyond it.
            let sealed = seal(Cipher::Aes256Gcm, vault_passphrase(), bytes)
                .map_err(|e| GatewayError::Internal(format!("seal failed: {e}")))?;
            store.put_secret(SecretRecord { id: id.to_string(), sealed, metadata: metadata.clone() })?;
            state.service.note_credential_change(id);
            Ok(())
        });
        let mut summary = json!({
            "on_conflict": req.on_conflict,
            "source_gateway_id": req.bundle.source.gateway_id,
            "source_mode": req.bundle.source.mode,
            "held": held_ids,
            "reason": (!unheld_fills.is_empty()).then_some(UNHELD_CREDENTIAL_WRITE),
            "filled": &unheld_fills,
        });
        // Entities are written one by one, so a failure part-way leaves what came before it standing, and the chain says so.
        let decision = match &applied {
            Ok(done) => {
                summary["written"] = json!(done.written);
                summary["skipped"] = json!(done.skipped);
                "allow"
            }
            Err(e) => {
                summary["stopped"] = json!("the import stopped part-way; what it wrote before this error stands");
                summary["error"] = json!(e.to_string());
                "error"
            }
        };
        audit_vault(&state, &op, VAULT_IMPORT_ACTION, decision, summary)?;
        outcome = applied?;
        Ok(())
    })?;
    let mut body = serde_json::to_value(&outcome)
        .map_err(|e| GatewayError::Internal(format!("import outcome could not be encoded: {e}")))?;
    if held.is_empty() {
        return Ok((StatusCode::OK, Json(body)));
    }
    body["status"] = json!("requires_approval");
    body["held"] = json!(held);
    Ok((StatusCode::ACCEPTED, Json(body)))
}

// ── POST /v1/secrets ────────────────────────────────────────────────────────────

/// Create a secret. The value is sealed server-side and never echoed back.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSecretReq {
    /// Optional explicit secret id.
    #[serde(default)]
    pub id: Option<String>,
    /// The secret value (sealed immediately; never returned).
    pub value: String,
    /// Optional metadata labels.
    #[serde(default)]
    pub labels: Vec<String>,
}

/// Handler for `POST /v1/secrets`. Guarded like [`set_connection_credential`]: an id `put` here is
/// an upsert, so a broker could otherwise overwrite a connection's LIVE credential by naming its id,
/// bypassing the credential hold. Over the broker while a device signature is still required, a write to a secret that
/// currently backs a connection/capability is held by reference; a brand-new unreferenced id applies.
pub async fn create_secret(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<CreateSecretReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    // Writing a credential into the vault is operator-only.
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let id = req.id.unwrap_or_else(|| format!("sec_{}", short_id()));
    crate::secret_inventory::refuse_staging_secret_id("secret", &id)?;
    let metadata = SecretMetadata { labels: req.labels, ..Default::default() };
    crate::secret_inventory::refuse_oversized_secret_metadata(&id, &metadata, state.limits.config().secret_metadata_bytes)?;
    // Writing over an existing secret is a rotation in everything but name and adds no row, so only
    // a new id is charged. Checked before the seal so a refused create never handles the value.
    if store.get_secret(&id)?.is_none() {
        state
            .service
            .refuse_if_over_allowance(crate::allowances::Allowance::Secrets, Some(&op))?;
    }
    let sealed = seal(Cipher::Aes256Gcm, vault_passphrase(), zeroize::Zeroizing::new(req.value).as_bytes())
        .map_err(|e| GatewayError::Internal(format!("seal failed: {e}")))?;
    let _cp = state.service.control_plane_mutex().lock().await;
    let backing = secret_backing_ref(store.as_ref(), &id)?;
    if state.service.control_plane_hold_required(remote) {
        if let Some(connection_id) = backing.clone() {
            let (code, body) =
                hold_credential_by_reference(&state, store.as_ref(), connection_id, id, sealed, metadata, requester_of(&op, remote))?;
            return Ok((code, Json(body)));
        }
    }
    let mut record = Some(SecretRecord { id: id.clone(), sealed, metadata });
    store.change_with_record(&mut || {
        let Some(record) = record.take() else { return Ok(()) };
        publish_secret_with_record(&state, store.as_ref(), record, &op, || {
            audit_unheld_credential_write(&state, &op, remote, &id, backing.as_deref())
        })
        .map(|_| ())
    })?;
    // Return only the id and a redaction marker, never the value.
    Ok((
        StatusCode::CREATED,
        Json(json!({ "secret_id": id, "value": permaura_core::REDACTED })),
    ))
}

/// Handler for `POST /v1/secrets/:id/rotate`. Re-seals a new value under the same id.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateSecretReq {
    /// The new secret value.
    pub value: String,
}

/// Handler for `POST /v1/secrets/:id/rotate`. Guarded like [`set_connection_credential`]: rotating a
/// secret that backs a connection/capability re-seals the live upstream credential, so over the
/// broker while a device signature is still required it is held by reference; an unreferenced secret
/// rotates immediately.
pub async fn rotate_secret(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<RotateSecretReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    // Rotating a credential is operator-only.
    let op = operator_authed(&state, &headers)?;
    crate::secret_inventory::refuse_staging_secret_id("secret", &id)?;
    let store = state.service.store();
    let existing = store
        .get_secret(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("secret '{id}'")))?;
    let sealed = seal(Cipher::Aes256Gcm, vault_passphrase(), zeroize::Zeroizing::new(req.value).as_bytes())
        .map_err(|e| GatewayError::Internal(format!("seal failed: {e}")))?;
    let _cp = state.service.control_plane_mutex().lock().await;
    let backing = secret_backing_ref(store.as_ref(), &id)?;
    if state.service.control_plane_hold_required(remote) {
        if let Some(connection_id) = backing.clone() {
            let (code, body) = hold_credential_by_reference(
                &state,
                store.as_ref(),
                connection_id,
                id,
                sealed,
                existing.metadata,
                requester_of(&op, remote),
            )?;
            return Ok((code, Json(body)));
        }
    }
    let mut record = Some(SecretRecord { id: id.clone(), sealed, metadata: existing.metadata });
    store.change_with_record(&mut || {
        let Some(record) = record.take() else { return Ok(()) };
        publish_secret_with_record(&state, store.as_ref(), record, &op, || {
            audit_unheld_credential_write(&state, &op, remote, &id, backing.as_deref())
        })
        .map(|_| ())
    })?;
    Ok((StatusCode::OK, Json(json!({ "secret_id": id, "rotated": true }))))
}

// ── POST /v1/devices/enroll · GET /v1/devices · DELETE /v1/devices/:id ────────────

/// Enroll an approval device (the operator's phone): its push token + the approver key it would
/// sign with. The pubkey is RECORDED for display but NOT yet trusted to verify a signature:
/// trusting a signing key is a worker-local pairing step (see push.rs / relay::approver).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollDeviceReq {
    /// A human-friendly device name.
    pub name: String,
    /// "ios" / "android".
    #[serde(default)]
    pub platform: Option<String>,
    /// The Expo push token, so approval notifications reach this device.
    #[serde(default)]
    pub push_token: Option<String>,
    /// The approver id this device signs as (e.g. `device:<uuid>`); generated if absent.
    #[serde(default)]
    pub approver_id: Option<String>,
    /// base64 ed25519 public key the device would sign approvals with (recorded, not yet trusted).
    #[serde(default)]
    pub approver_pubkey: Option<String>,
    /// Unix ms this request was signed at, when it re-registers a TRUSTED approver. Bounds replay.
    #[serde(default)]
    pub issued_at: Option<i64>,
    /// base64 ed25519 signature over
    /// [`permaura_relay::device_control_preimage`]`("device-enroll", approver_id, push_token,
    /// issued_at)`, made with the private half of the key this gateway already trusts for
    /// `approver_id`. Required only to re-register a trusted approver's entry; see the handler.
    #[serde(default)]
    pub sig: Option<String>,
    /// This gateway's approval audience when `sig` is over
    /// [`permaura_relay::device_control_preimage_v2`]; absent on a v1 signature.
    #[serde(default)]
    pub audience: Option<String>,
}

/// The `action` a device signs to re-register its own push entry.
const DEVICE_ENROLL_ACTION: &str = "device-enroll";

/// Verify a device signature over a control request made outside the approval queue.
///
/// Shared by the two places a trusted device speaks for itself without there being an approval to
/// co-sign: re-registering its own push entry, and asking for a fresh set of recovery codes. The
/// signer is resolved from the KEYRING, never from anything the request carries, so a caller cannot
/// nominate the key its own signature will be checked against.
///
/// Refusals are deliberately one message. Which of "no signature", "stale", "wrong key" applies is
/// information the caller already has if it is honest and does not need if it is not.
#[allow(clippy::too_many_arguments)]
fn verify_device_control(
    state: &AppState,
    trusted_key: &str,
    action: &str,
    approver_id: &str,
    subject: &str,
    issued_at: Option<i64>,
    sig: Option<&str>,
    audience: Option<&str>,
    what: &str,
) -> Result<(), GatewayError> {
    let refuse = |reason: &str| {
        let mut detail = serde_json::Map::new();
        detail.insert("reason".into(), json!(reason));
        detail.insert("action".into(), json!(action));
        if let Err(e) = state.service.audit_approver_pairing(
            "deny",
            approver_id,
            Some(trusted_key),
            AUTHORITY_DEVICE_SIGNED,
            serde_json::Value::Object(detail),
        ) {
            tracing::error!(error = %e, "a refused device-signed control request was not recorded in the audit chain");
        }
        GatewayError::Denied(format!(
            "{what} needs a signature from that device: sign device_control_preimage_v2(audience, \
             \"{action}\", approver_id, subject, issued_at) with its key, where audience is this \
             gateway's approval_audience, and send it as `sig` with `issued_at` and `audience`"
        ))
    };
    let (Some(issued_at), Some(sig)) = (issued_at, sig.map(str::trim).filter(|s| !s.is_empty()))
    else {
        return Err(refuse("no device signature was presented"));
    };
    if (now_ms() - issued_at).abs() > PAIRING_FRESHNESS_MS {
        return Err(refuse("device signature is stale (issued_at out of window)"));
    }
    let audience = audience.map(str::trim).filter(|a| !a.is_empty());
    if let Some(why) = state.service.device_signature_version_refusal(approver_id, audience) {
        return Err(refuse(&why));
    }
    let preimage = match audience {
        Some(a) => permaura_relay::device_control_preimage_v2(a, action, approver_id, subject, issued_at),
        None => permaura_relay::device_control_preimage(action, approver_id, subject, issued_at),
    };
    if permaura_relay::verify(trusted_key, &preimage, sig).is_err() {
        return Err(refuse("device signature did not verify against the trusted key"));
    }
    if audience.is_some() {
        state.service.note_v2_signer(approver_id);
    }
    Ok(())
}

/// The audit `authority` for a request a trusted device signed for itself, outside the approval
/// queue. Distinct from the approval path's own label because nothing was held or resolved here.
const AUTHORITY_DEVICE_SIGNED: &str = "device_signed_request";

/// Handler for `POST /v1/devices/enroll`. Operator-only: the operator enrols their own device.
///
/// **Replacing the entry of an approver whose key this gateway TRUSTS takes that device's
/// signature.** Everything else here is unchanged: enrolling a new approver id, or re-registering one
/// whose key was never trusted, still needs nothing but the operator bearer, which is what lets a
/// phone re-register its push token on every launch.
///
/// The one case that is different was a silencing primitive. The registry is keyed on a
/// caller-chosen `approver_id` and [`crate::push::DeviceRegistry::upsert`] replaces any entry that
/// shares it, so an operator bearer could enrol that same approver id with `push_token: null`, leave
/// the signing key trusted, and remove the only channel by which the owner would learn that a hold
/// was waiting. The key stays trusted, so nothing looks revoked; the notifications simply stop. That
/// was the load-bearing half of the delayed-recovery attack, and it is worth closing on its own
/// account because every approval hold announces itself through this registry.
///
/// The signature is over the push token being installed, so one obtained for a real re-registration
/// cannot be replayed to install a null one.
pub async fn enroll_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<EnrollDeviceReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let device_id = format!("device_{}", short_id());
    let approver_id = req
        .approver_id
        .filter(|a| !a.trim().is_empty())
        .unwrap_or_else(|| format!("device:{}", short_id()));
    let push_token = req.push_token.filter(|t| !t.trim().is_empty());
    // Only a TRUSTED approver's entry is protected. An enrolment that displaces nothing, or displaces
    // an entry whose key this gateway never trusted, is the ordinary phone-relaunch path.
    if let Some(trusted_key) = state.service.trusted_approver_key(&approver_id) {
        if state.service.device_registered_for_approver(&approver_id) {
            verify_device_control(
                &state,
                &trusted_key,
                DEVICE_ENROLL_ACTION,
                &approver_id,
                push_token.as_deref().unwrap_or_default(),
                req.issued_at,
                req.sig.as_deref(),
                req.audience.as_deref(),
                "re-registering the push entry of a device this gateway trusts",
            )?;
        }
    }
    state.service.enroll_device(crate::push::Device {
        id: device_id.clone(),
        name: req.name,
        platform: req.platform,
        push_token,
        approver_id: Some(approver_id.clone()),
        approver_pubkey: req.approver_pubkey.filter(|k| !k.trim().is_empty()),
        enrolled_at: now_ms(),
        revoked: false,
    });
    Ok((
        StatusCode::CREATED,
        Json(json!({ "device_id": device_id, "approver_id": approver_id, "enrolled": true })),
    ))
}

/// Handler for `GET /v1/devices`, the operator's enrolled devices (the raw push token is never leaked).
///
/// Handler for `GET /v1/devices`: every device that can sign approvals on this gateway, plus every
/// device that only registered for notifications.
///
/// The KEYRING is the spine of the list, joined to the push registry for a name and platform where a
/// registration exists. It used to be the registry alone, which is incomplete in both directions: a
/// phone that declined notifications, a simulator and an Apple Watch are all trusted to sign and had
/// no row here, and a row here can carry a key this gateway never trusted. A console that offered
/// revocation from this list therefore could not show the approvers that most needed revoking. A row
/// with no registration takes the approver id as its `id`, which `DELETE /v1/devices/:id` accepts.
pub async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let registry = state.service.list_devices();
    let mut devices: Vec<serde_json::Value> = Vec::new();
    let mut listed_devices: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (approver_id, key_fp, revoked) in state.service.approver_key_census() {
        let device = registry
            .iter()
            .find(|d| d.approver_id.as_deref() == Some(approver_id.as_str()));
        if let Some(d) = device {
            listed_devices.insert(d.id.clone());
        }
        devices.push(json!({
            "id": device.map(|d| d.id.clone()).unwrap_or_else(|| approver_id.clone()),
            "name": device.map(|d| d.name.clone()),
            "platform": device.and_then(|d| d.platform.clone()),
            "approver_id": approver_id,
            "key_fp": key_fp,
            "has_push_token": device.is_some_and(|d| d.push_token.is_some()),
            "has_signing_key": true,
            "is_trusted": !revoked,
            "enrolled_at": device.map(|d| d.enrolled_at).unwrap_or(0),
            "revoked": device.map(|d| d.revoked).unwrap_or(revoked),
        }));
    }
    // Registered for notifications but never paired: listed so the person can see the phone the
    // gateway will tell, and see that it cannot sign.
    for d in registry.iter().filter(|d| !listed_devices.contains(&d.id)) {
        devices.push(json!({
            "id": d.id,
            "name": d.name,
            "platform": d.platform,
            "approver_id": d.approver_id,
            "key_fp": serde_json::Value::Null,
            "has_push_token": d.push_token.is_some(),
            "has_signing_key": d.approver_pubkey.is_some(),
            "is_trusted": false,
            "enrolled_at": d.enrolled_at,
            "revoked": d.revoked,
        }));
    }
    // Envelope-level ladder state so the console (and desktop app) can render accurate copy: whether
    // bearer approvals are refused wholesale, and the effective floor (`approve` | `device_signed`).
    let floor = state.service.approval_floor();
    let stored = state.service.stored_approval_floor();
    Ok(Json(json!({
        "devices": devices,
        "signed_approvals_required": floor == crate::service::ApprovalFloor::DeviceSigned,
        "approval_floor": floor.as_str(),
        // The effective floor reads `approve` for an untouched gateway and for an explicit opt-down
        // alike, and only the opt-down switches the device holds off, so it is reported in its own right.
        "approval_floor_override": stored.map(crate::service::ApprovalFloor::as_str),
        "approvals_opted_down": stored == Some(crate::service::ApprovalFloor::Approve),
    })))
}

/// Handler for `DELETE /v1/devices/:id`: revoke a lost/rotated device. Also untrusts its signing
/// key (fail-safe): revoking the device in the console should stop it approving, not just stop pushes.
///
/// A device with an approver key goes through [`guarded_revoke_approver_key`], gated exactly as
/// `DELETE /v1/approver-keys/:id` is, so a remote caller's `approver-revoke` ticket is bound to the
/// device's APPROVER id, never the device id. A device row with no approver key only stops pushes.
/// The key revocation runs first and propagates, so a device is never de-registered on the strength
/// of a key revocation that was refused or did not persist.
pub async fn revoke_device(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    if let Some(approver_id) = state.service.device_approver(&id) {
        // A held key revocation leaves the device row in place too: the row is what the owner's
        // phone still signs as until the revocation actually lands.
        if let Guarded::Held(code, body) =
            guarded_revoke_approver_key(&state, &op, remote, &headers, &approver_id).await?
        {
            return Ok((code, Json(body)));
        }
    }
    if !state.service.revoke_device(&id) {
        // A row `GET /v1/devices` built from the keyring alone carries the approver id as its id, so
        // revoking it is revoking the key, with nothing in the registry to retire afterwards.
        if state.service.approver_key_census().iter().any(|(a, _, _)| a == &id) {
            return match guarded_revoke_approver_key(&state, &op, remote, &headers, &id).await? {
                Guarded::Held(code, body) => Ok((code, Json(body))),
                Guarded::Applied(_) => {
                    Ok((StatusCode::OK, Json(json!({ "device_id": id, "approver_id": id, "revoked": true }))))
                }
            };
        }
        return Err(GatewayError::NotFound(format!("device '{id}'")));
    }
    Ok((StatusCode::OK, Json(json!({ "device_id": id, "revoked": true }))))
}

// ── GET /v1/approver-keys · POST /v1/approver-keys/pair · DELETE /v1/approver-keys/:approver_id ──

/// Handler for `GET /v1/approver-keys`, every approver this worker has ever trusted, with the
/// fingerprint of its key and whether that key is still usable. Operator-authed.
///
/// **Why this exists at all, and why its absence was a way to brick a tenant.** Pairing writes the
/// KEYRING. It does not write the push-device registry; only `POST /v1/devices/enroll` does, and the
/// phone only calls that once push registration succeeds. A device paired in a simulator, by a user
/// who declined notifications, or from an Apple Watch is therefore fully trusted to sign approvals
/// and completely absent from `GET /v1/devices`. Both revocation surfaces listed that endpoint, so
/// such a key could not be seen, and what cannot be seen does not get revoked. Combined with the
/// sticky device-signed floor, losing that device left a hosted tenant unable to approve (the device
/// is gone), unable to revoke (the key was never listed) and unable to pair a replacement (held for a
/// co-signature only the lost device could give). Listing the keyring is what closes that: revocation
/// already works by approver id with no device row involved (`DELETE /v1/approver-keys/:approver_id`
/// → [`guarded_revoke_approver_key`] → the keyring), so nothing but the enumeration was missing.
///
/// Operator-authed and no more. This is a read of TRUST STATE, not of secrets: an approver id, a
/// fingerprint of a public key, and a boolean. Fingerprints rather than the keys themselves because
/// the fingerprint is what a pairing ticket is bound to and what the audit chain records, so it is
/// the value that joins the three surfaces up; the key material would add nothing actionable.
pub async fn list_approver_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    // Joined against the push registry so a console can label a row with the device's name where one
    // exists, but the keyring is the spine of the list, never the registry, so an approver with no
    // device row is still listed. `device_id: null` is the signal that this key can only be managed
    // from here.
    let devices = state.service.list_devices();
    let census = state.service.approver_key_census();
    let keyring = state.service.approver_keyring_snapshot();
    let keys: Vec<serde_json::Value> = census
        .into_iter()
        .map(|(approver_id, key_fp, revoked)| {
            let device = devices
                .iter()
                .find(|d| d.approver_id.as_deref() == Some(approver_id.as_str()));
            json!({
                "approver_id": approver_id,
                "key_fp": key_fp,
                "trusted": !revoked,
                "revoked": revoked,
                // False for a key paired before keys named a person: it never counts as the second
                // person toward a two-person rule until it is paired again.
                "person_bound": keyring.person(&approver_id).is_some(),
                "person_handle": keyring.person(&approver_id).map(crate::service::person_handle),
                // A key bound to the gateway's owner confirms any held change, whoever asked, so a device can tell up front that the requester rule does not apply to it.
                "is_owner": state.service.is_the_owners_device(&keyring, &approver_id),
                "device_id": device.map(|d| d.id.clone()),
                "name": device.map(|d| d.name.clone()),
            })
        })
        .collect();
    let floor = state.service.approval_floor();
    let stored = state.service.stored_approval_floor();
    Ok(Json(json!({
        "keys": keys,
        // The highest `device_signed_quorum` the trusted keys can meet today; a higher one holds its action until more people pair.
        "reachable_people": keyring.reachable_people(),
        "approval_floor": floor.as_str(),
        "signed_approvals_required": floor == crate::service::ApprovalFloor::DeviceSigned,
        "approval_floor_override": stored.map(crate::service::ApprovalFloor::as_str),
        "approvals_opted_down": stored == Some(crate::service::ApprovalFloor::Approve),
        "approval_audience": state.service.served_approval_audience(),
    })))
}

/// Body for `POST /v1/approver-keys/pair`, the worker-local pairing ceremony that TRUSTS a device's
/// signing key. The device proves possession of the private key by signing the pairing preimage.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairApproverKeyReq {
    /// The approver id being paired (`device:<id>`).
    pub approver_id: String,
    /// The base64 ed25519 public key to trust.
    pub approver_pubkey: String,
    /// When the possession proof was created (unix ms); freshness-bounded.
    pub issued_at: i64,
    /// base64(ed25519) signature over the pairing preimage, proving the device holds the private key.
    pub sig: String,
    /// Who the device approves for, so a two-person rule counts people rather than devices: the
    /// account the phone was signed in as, which its Watch shares. Read on a self-run gateway, where
    /// the person relaying the pairing at the host vouches for it. A hosted worker binds the actor the
    /// AS names on the ticket instead, and refuses a different person here.
    #[serde(default)]
    pub person: Option<String>,
}

/// The longest person a self-run pairing may name.
const MAX_PERSON_CHARS: usize = 128;

/// The person a pairing binds its key to (see [`PairApproverKeyReq::person`]).
fn pairing_person(
    authority: &PairingAuthority,
    req: &PairApproverKeyReq,
) -> Result<Option<String>, GatewayError> {
    if let PairingAuthority::HostedOwner { actor_sub, .. } = authority {
        if let Some(person) = req.person.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            if actor_sub.as_deref() != Some(person) {
                return Err(GatewayError::BadRequest(
                    "a hosted worker binds a key to the account its pairing ticket names, and this person is not that account; send no person, or that one".into(),
                ));
            }
        }
        return Ok(actor_sub.clone());
    }
    let Some(person) = req.person.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    if person.chars().count() > MAX_PERSON_CHARS || person.chars().any(char::is_control) {
        return Err(GatewayError::BadRequest(format!(
            "person must be at most {MAX_PERSON_CHARS} printable characters"
        )));
    }
    Ok(Some(person.to_string()))
}

/// Record a refused enrolment in the audit chain and turn the reason into the error the caller sees.
///
/// A refusal is written for a stale proof, a signature that did not verify, and a `user:` approver
/// id paired by another account; a ticket already spent is recorded by [`spend_pairing_ticket`].
/// Those are the events an owner needs to see, and on a hosted worker the audit chain is the only
/// place they are visible at all. A failure to *write* the record is logged rather than propagated:
/// the caller is already being refused, and turning a 403 into a 500 would tell them the opposite of
/// what happened.
fn refuse_pairing(
    state: &AppState,
    req: &PairApproverKeyReq,
    authority: &PairingAuthority,
    reason: &str,
) -> GatewayError {
    let mut detail = authority.audit_detail();
    detail.insert("reason".into(), json!(reason));
    if let Err(e) = state.service.audit_approver_pairing(
        "deny",
        &req.approver_id,
        Some(&req.approver_pubkey),
        authority.label(),
        serde_json::Value::Object(detail),
    ) {
        tracing::error!(approver = %req.approver_id, error = %e, "a refused approver pairing was not recorded in the audit chain");
    }
    GatewayError::Denied(reason.to_string())
}

/// Handler for `POST /v1/approver-keys/pair`. TRUSTS a device signing key: the one security-critical
/// WRITE to the approver keyring, and the write that arms the whole human-approval gate.
///
/// What authorises it depends on whether this gateway has a host a human could be standing at.
///
/// On a **local or tunnelled** gateway (Modes A and B) it is loopback-only, exactly as before: a
/// cloud compromised via `/api/gw` must not be able to enrol its own key and forge approvals, and
/// since `compute_is_remote` treats every non-loopback peer as remote, no device reaches this
/// endpoint directly. The device exports its pairing blob (approver_id, approver_pubkey, issued_at,
/// sig over the pairing preimage) and an operator on the gateway's own host relays it via
/// `permaura approver pair --blob`.
///
/// On a **hosted** worker (Mode C) there is no loopback client to be, so the positional anchor does
/// not exist and leaving the endpoint closed would mean a hosted tenant could never pair a device at
/// all. It is opened there, and only there, behind a strictly bounded substitute (see
/// [`pairing_authority`]): an owner-scoped OAuth operator session plus a single-use, purpose-bound,
/// audience-bound step-up ticket the AS minted after a fresh re-authentication. That anchor alone
/// enrols the **first** device: trust on first use, on a worker whose keyring is empty. Every later
/// device is additionally held for a co-signature from a device already trusted here, so a ticket
/// alone cannot add a device to a keyring that still holds a usable key. That is not a bound on a
/// compromised authorization server: a ticket naming the owner as actor revokes at once, the last key
/// included, so whoever can mint tickets can empty the keyring and then enrol the first device. The
/// refusals an owner needs to see (a stale proof, a bad signature, a `user:` id paired by another
/// account, a replayed ticket) are written to the audit chain; see [`refuse_pairing`]. Refusals of
/// placement, authentication or ticket verification are not.
///
/// The order below is the security argument. The possession proof runs before the ticket is spent, so
/// a malformed request does not burn a ticket and force another re-authentication; the ticket is
/// spent before the write, so a replay cannot reach the keyring.
pub async fn pair_approver_key(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<PairApproverKeyReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    // Placement before credentials. A Mode B caller is refused as loopback-only whatever it presents,
    // and it has to hear that as a 403: authenticating first turns a missing or stale bearer into a
    // 401, which tells a console to go and get credentials for a door that is shut to it forever.
    pairing_placement_allows(&state, remote)?;
    let op = operator_authed(&state, &headers)?;
    if !crate::relay::approver::approver_id_well_formed(&req.approver_id) {
        return Err(GatewayError::BadRequest(format!(
            "approver_id must be 1 to {} characters, start with a letter or digit, hold only letters, digits and _ - . : @, and not be one of {}, so permaura.com can address the key to revoke it",
            crate::relay::approver::MAX_APPROVER_ID_LEN,
            crate::relay::approver::RESERVED_APPROVER_IDS.join(", ")
        )));
    }
    // The ticket is pinned to this exact approver id AND this exact key, so intercepting one buys
    // nothing: it cannot be re-aimed at a key of the holder's own. `key_fingerprint` is the service's
    // scheme, never a second one: a fingerprint computed differently here would reject the very key
    // the AS minted the ticket for.
    let pubkey_fp = crate::service::key_fingerprint(&req.approver_pubkey);
    let purpose = crate::oauth::TicketPurpose::ApproverPair;
    let authority = pairing_authority(
        &state,
        &op,
        remote,
        &headers,
        purpose,
        crate::oauth::TicketBinding::ApproverKey {
            approver_id: &req.approver_id,
            pubkey_fp: &pubkey_fp,
        },
    )?;
    if (now_ms() - req.issued_at).abs() > PAIRING_FRESHNESS_MS {
        return Err(refuse_pairing(
            &state,
            &req,
            &authority,
            "pairing proof is stale (issued_at out of window)",
        ));
    }
    let preimage =
        permaura_relay::approver_pairing_preimage(&req.approver_id, &req.approver_pubkey, req.issued_at);
    if permaura_relay::verify(&req.approver_pubkey, &preimage, &req.sig).is_err() {
        return Err(refuse_pairing(&state, &req, &authority, "pairing signature did not verify"));
    }
    // An approver id of the form `user:<account>` names that account to separation of duty, so only a pairing bound to that same account may use it.
    let person = pairing_person(&authority, &req)?;
    if let Some(named) = req.approver_id.strip_prefix("user:") {
        if person.as_deref() != Some(named) {
            return Err(refuse_pairing(
                &state,
                &req,
                &authority,
                "an approver id of the form user:<account> may only be paired by that account",
            ));
        }
    }
    spend_pairing_ticket(
        &state,
        &authority,
        purpose,
        TicketSubject::ApproverKey {
            approver_id: &req.approver_id,
            pubkey: &req.approver_pubkey,
        },
    )?;
    let mutation = crate::policy_guard::Mutation::ApproverKeyTrust {
        approver_id: req.approver_id.clone(),
        approver_pubkey: req.approver_pubkey.clone(),
        person,
        replaces: None,
    };
    // The device being enrolled CANNOT co-sign its own enrolment, and that is structural rather than
    // a check written here: `verify_signed_approval` resolves the signer through
    // `keyring.trusted_key(&result.approver)` and refuses an approver the keyring does not already
    // hold, which the device being enrolled is not, by definition. Do not add a redundant guard for
    // it, and do not remove the property by resolving a signer from anything the request carries.
    match apply_or_hold_pairing(&state, &mutation, &authority).await? {
        Guarded::Held(code, body) => {
            let mut detail = authority.audit_detail();
            detail.insert("approval_id".into(), body["approval_id"].clone());
            state.service.audit_approver_pairing(
                "requires_approval",
                &req.approver_id,
                Some(&req.approver_pubkey),
                authority.label(),
                serde_json::Value::Object(detail),
            )?;
            Ok((code, Json(body)))
        }
        // `apply_mutation_as` already wrote the `allow` record under this authority: the enrolment
        // has exactly one audit event whichever branch it took.
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

/// Handler for `DELETE /v1/approver-keys/:approver_id`: untrust a device's signing key. Fail-safe
/// (only removes trust), so unlike pairing it may run through the console/broker.
///
/// Audited as the mirror of an enrolment: the same synthetic action against the same resource, with
/// decision `deny`: the key is now denied. Pairing emitted no audit event on any mode before this
/// change, which was survivable while the keyring only gated approvals; it is not now that enrolment
/// stickily raises the approval floor, so both directions are recorded on every mode rather than only
/// on the hosted one.
///
/// The record is written by [`guarded_revoke_approver_key`], not here, so this route and
/// `DELETE /v1/devices/:id` emit one identical event. It names the key read from the KEYRING and, when
/// a step-up authorised the revocation, the ticket that did so.
///
/// The revocation itself IS propagated: one that did not reach the store comes back as trusted on
/// the next refresh, so reporting success there would be the opposite of the truth.
///
/// Every revocation except one made at a self-run gateway's own machine takes an `approver-revoke`
/// ticket bound to `approver_id` (see [`revocation_step_up`]), or, for a self-run revocation that
/// would empty the keyring, a `recovery` ticket in its place. This route needs no device row and
/// never has: `approver_id` addresses the keyring directly, which is what makes
/// `GET /v1/approver-keys` a complete answer to a key that the push registry never saw.
pub async fn revoke_approver_key(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(approver_id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    match guarded_revoke_approver_key(&state, &op, remote, &headers, &approver_id).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

// ── PUT /v1/approval-floor ─────────────────────────────────────────────────────────

/// Body for `PUT /v1/approval-floor`: set the operator's approval-floor override.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalFloorReq {
    /// `"approve"` (opt down: re-enable bearer `approve`-tier resolutions after pairing),
    /// `"device_signed"` (opt up: refuse every bearer resolution), or `"default"` (clear the
    /// override; enrolment then decides).
    pub floor: String,
}

/// Handler for `PUT /v1/approval-floor`. Sets the worker-local floor that decides what a bare
/// operator bearer may resolve. **RAISING** the floor to `device_signed` is fail-safe and allowed
/// from anywhere (console button included), unchanged. **LOWERING** it (`approve`, or `default`
/// which may lower depending on enrolment) is a trust-root relaxation: on Modes A and B it is
/// accepted only from a loopback client on the gateway's own host (the desktop app or the permaura
/// CLI), and once a device is trusted it is held for that device's co-signature unless the request
/// carries a recovery code or a permaura.com recovery ticket. Operator-authed either way.
///
/// **Why this endpoint is in scope of hosted pairing at all.** Leave the lowering branch closed on a
/// hosted worker and hosted pairing becomes a one-way door. Pair one device on a hosted gateway and
/// the floor becomes `device_signed` stickily; because a hosted worker is unconditionally remote,
/// every non-tightening control-plane mutation from then on is held for a device signature; and there
/// is no host to run the opt-down from. Lose the device and the tenant's control plane is bricked
/// with no recovery path at all. So lowering is opened on Mode C behind the same anchor as pairing,
/// and, when a usable device still exists, additionally held for that device to co-sign, so the
/// ticket alone never re-opens bearer approvals on a worker that has working hardware. The ticket
/// suffices only when no usable device is left, which is precisely the recovery case this exists for.
pub async fn set_approval_floor(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ApprovalFloorReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    // Authentication first here, unlike pairing: raising the floor is fail-safe and reachable on every
    // mode, so there is no placement rule to settle before the bearer, and this endpoint has always
    // answered an unauthenticated caller with a 401.
    let op = operator_authed(&state, &headers)?;
    // Validated up front, before any mutation is constructed: an unparseable floor that only failed
    // at resolution time would have been queued as a hold, pushed to a device, signed by a human, and
    // only then refused.
    let target: Option<crate::service::ApprovalFloor> = match req.floor.trim() {
        "default" => None,
        other => Some(
            crate::service::ApprovalFloor::from_str(other)
                .ok_or_else(|| GatewayError::BadRequest(format!("unknown floor '{other}'")))?,
        ),
    };
    // Anything that is not an explicit raise-to-device_signed can only lower restrictiveness.
    if matches!(target, Some(crate::service::ApprovalFloor::DeviceSigned)) {
        state.service.set_approval_floor(target)?;
        state.service.set_opt_down_unanchored(false)?;
        let effective = state.service.approval_floor();
        return Ok((
            StatusCode::OK,
            Json(json!({
                "approval_floor": effective.as_str(),
                "signed_approvals_required": effective == crate::service::ApprovalFloor::DeviceSigned,
                "approval_floor_override": target.map(crate::service::ApprovalFloor::as_str),
                "approvals_opted_down": false,
            })),
        ));
    }
    refuse_delayed_recovery(&state, &headers)?;
    let purpose = crate::oauth::TicketPurpose::ApprovalFloorLower;
    let authority =
        pairing_authority(&state, &op, remote, &headers, purpose, crate::oauth::TicketBinding::None)?;
    spend_pairing_ticket(&state, &authority, purpose, TicketSubject::ApprovalFloor)?;
    // Self-run only, and a no-op on every branch that already resolved to something other than
    // loopback: a hosted worker took its ticket above, under the purpose that names this control.
    let authority = with_recovery_ticket(&state, &op, authority, &headers)?;
    let authority = with_recovery_code(&state, authority, &headers)?;
    let mutation = crate::policy_guard::Mutation::ApprovalFloorSet {
        floor: target.map(|f| f.as_str().to_string()),
    };
    match apply_or_hold_pairing(&state, &mutation, &authority).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

// ── GET /v1/recovery · POST /v1/recovery-codes ──────────────────────────────────────

/// Handler for `GET /v1/recovery`: how many recovery codes remain (never the codes), whether a
/// device is trusted, and whether this gateway accepts a permaura.com recovery ticket.
/// Operator-authed.
pub async fn recovery_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    operator_authed(&state, &headers)?;
    let store = state.service.store();
    let codes = crate::recovery::status(store.as_ref())?;
    Ok(Json(json!({
        "codes": codes,
        "device_trusted": state.service.any_device_trusted(),
        // Whether this gateway has the third authority at all. A console that cannot tell an owner
        // "re-authenticate at permaura.com" from "there is no route left but the keyring file on
        // this host" will offer the wrong one at the worst moment.
        "recovery_ticket_accepted": !state.hosted && state.service.live_oauth().is_some(),
    })))
}

/// Body for `POST /v1/recovery-codes` when a trusted device signs the request instead of presenting
/// a code. Every field is optional, so a caller using the code header sends no body at all.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCodesReq {
    /// The approver id whose trusted key signed this request.
    #[serde(default)]
    pub approver_id: Option<String>,
    /// Unix ms this request was signed at. Bounds replay.
    #[serde(default)]
    pub issued_at: Option<i64>,
    /// base64 ed25519 signature over
    /// [`permaura_relay::device_control_preimage_v2`]`(audience, "recovery-codes", approver_id, "",
    /// issued_at)`, or the v1 [`permaura_relay::device_control_preimage`] when `audience` is absent.
    #[serde(default)]
    pub sig: Option<String>,
    /// This gateway's approval audience, present when `sig` is a v2 signature.
    #[serde(default)]
    pub audience: Option<String>,
}

/// The `action` a device signs to ask for a fresh set of recovery codes.
const RECOVERY_CODES_ACTION: &str = "recovery-codes";

/// The account step-up issuing recovery codes takes from anywhere but this gateway's own machine: a `recovery-codes-issue` ticket, verified here and spent by the caller immediately before the set is issued. `None` at the machine, where placement is the proof.
fn recovery_codes_step_up(
    state: &AppState,
    op: &Session,
    remote: bool,
    headers: &HeaderMap,
) -> Result<Option<PairingAuthority>, GatewayError> {
    if !remote {
        return Ok(None);
    }
    let purpose = crate::oauth::TicketPurpose::RecoveryCodesIssue;
    if state.service.oauth().is_none() {
        return Err(GatewayError::Denied(
            "issuing recovery codes from anywhere but this gateway's own machine takes a fresh step-up at \
             permaura.com, and this gateway has no remote-access configuration to verify one: run \
             `permaura approver codes` on the gateway's own machine"
                .into(),
        ));
    }
    if headers.get(PAIRING_TICKET_HEADER).and_then(|v| v.to_str().ok()).is_none_or(|t| t.trim().is_empty()) {
        let detail = json!({
            "reason": "a recovery-code issue from off this machine carried no step-up ticket",
            "purpose": purpose.claim(),
        });
        if let Err(e) = state.service.audit_approver_pairing("deny", "recovery-codes", None, "remote_operator", detail) {
            tracing::error!(error = %e, "a refused remote recovery-code issue was not recorded in the audit chain");
        }
        return Err(GatewayError::StepUpRequired(format!(
            "{}. Issuing recovery codes from anywhere but this gateway's own machine replaces the set on paper, so \
             the ticket goes beside the device signature; or run `permaura approver codes` on the gateway's own machine",
            step_up_challenge(state, purpose)
        )));
    }
    ticket_authority(state, op, headers, purpose, crate::oauth::TicketBinding::None).map(Some)
}

/// Handler for `POST /v1/recovery-codes`: issue or replace the code set, and return it once.
///
/// Two authorities, and a bearer alone is neither. One of the current codes in the
/// `X-Permaura-Recovery-Code` header, or a signature from a device this gateway trusts.
///
/// **The device signature is not a convenience.** It used to accept only an existing code, which
/// closed the door on two states an owner reaches through no fault of their own: a gateway upgraded
/// while it already trusted a device never passed through first-pairing issuance and so has no codes
/// to present, and an owner who has spent or lost their set while the phone still works had no way
/// back to one. Both left a working device and no paper route, which is the state recovery codes
/// exist to prevent. The device that would co-sign the controls the codes stand in for is exactly the
/// right authority to ask for them.
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    OptionalJsonBody(body): OptionalJsonBody<RecoveryCodesReq>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let req = body.unwrap_or_default();
    let code_given = headers
        .get(crate::recovery::RECOVERY_CODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty());
    let signed = [("approver_id", req.approver_id.is_some()), ("issued_at", req.issued_at.is_some()), ("sig", req.sig.is_some()), ("audience", req.audience.is_some())];
    if let Some((member, _)) = signed.iter().find(|(_, given)| code_given && *given) {
        return Err(GatewayError::BadRequest(format!(
            "'{member}' is part of a device signature, which is not read beside a recovery code; send the code or the signature, not both"
        )));
    }
    if state.hosted {
        return Err(GatewayError::Denied(
            "a hosted gateway issues no recovery codes; its recovery authority is a permaura.com ticket".into(),
        ));
    }
    if !state.service.any_device_trusted() {
        return Err(GatewayError::BadRequest(
            "no device is trusted, so there is nothing for recovery codes to recover; they are issued when the first device pairs".into(),
        ));
    }
    let step_up = recovery_codes_step_up(&state, &op, remote, &headers)?;
    let _cp = state.service.control_plane_mutex().lock().await;
    let authority = with_recovery_code(&state, PairingAuthority::Loopback, &headers)?;
    let authority = match authority {
        code @ PairingAuthority::RecoveryCode { .. } => code,
        _ => {
            let approver_id = req
                .approver_id
                .as_deref()
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .ok_or_else(|| {
                    GatewayError::Denied(
                        "issuing recovery codes needs either one of the current codes in the \
                         X-Permaura-Recovery-Code header or a signature from a device this gateway \
                         trusts (send approver_id, issued_at and sig)"
                            .into(),
                    )
                })?;
            let trusted_key = state.service.trusted_approver_key(approver_id).ok_or_else(|| {
                GatewayError::Denied(format!(
                    "this gateway trusts no key for approver '{approver_id}'"
                ))
            })?;
            verify_device_control(
                &state,
                &trusted_key,
                RECOVERY_CODES_ACTION,
                approver_id,
                "",
                req.issued_at,
                req.sig.as_deref(),
                req.audience.as_deref(),
                "issuing recovery codes",
            )?;
            PairingAuthority::Loopback
        }
    };
    if let Some(s) = &step_up {
        spend_pairing_ticket(&state, s, crate::oauth::TicketPurpose::RecoveryCodesIssue, TicketSubject::RecoveryCodes)?;
    }
    let first_set = crate::recovery::status(state.service.store().as_ref())?.is_none();
    let codes = crate::recovery::issue(state.service.store().as_ref(), now_ms())?;
    let mut detail = authority.audit_detail();
    if let Some(s) = &step_up {
        detail.extend(s.audit_detail());
    }
    detail.insert("regenerated".into(), json!(!first_set));
    let label = match authority {
        PairingAuthority::RecoveryCode { .. } => authority.label(),
        // A device signed for itself; recording it as `loopback` would name the weaker of the two
        // credentials the request actually carried.
        _ => AUTHORITY_DEVICE_SIGNED,
    };
    state.service.audit_approver_pairing(
        "allow",
        "recovery-codes",
        None,
        label,
        serde_json::Value::Object(detail),
    )?;
    Ok(Json(json!({ "recovery_codes": codes, "first_set": first_set })))
}

// ── POST /v1/agents/register ─────────────────────────────────────────────────────

/// Register an agent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterAgentReq {
    /// Optional explicit agent id (defaults to a slug of the name).
    #[serde(default)]
    pub id: Option<String>,
    /// Human-friendly name.
    pub name: String,
}

/// Handler for `POST /v1/agents/register`. The operator-driven path (CLI / direct API): the
/// agent is created already **approved**. The friction-free, agent-initiated path is
/// `POST /v1/agents/enroll` + the MCP `permaura.enroll` handshake, which lands a *pending*
/// agent for a human to approve.
pub async fn register_agent(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<RegisterAgentReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    // Operator-created agents are pre-approved; this is a control-plane action.
    let op = operator_authed(&state, &headers)?;
    let id = req
        .id
        .unwrap_or_else(|| req.name.to_lowercase().replace(' ', "-"));
    if state.service.store().get_agent(&id)?.is_some() {
        return Err(GatewayError::BadRequest(format!("agent '{id}' already exists")));
    }
    // Before the hold, not after. A mutation held for a device signature is a mutation the operator
    // has been told will apply, and finding out at signing time that it never could is worse than
    // being refused at the moment of asking.
    state
        .service
        .refuse_if_over_allowance(crate::allowances::Allowance::Agents, Some(&op))?;
    // Creating an already-approved agent defeats the new-agent approval gate, so over the broker it
    // is held for a device signature (register is always a create → always loosening).
    let mutation = crate::policy_guard::Mutation::AgentUpsert {
        agent: Agent::approved(id.clone(), req.name, now_ms()),
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::CREATED, Json(json!({ "agent_id": id })))),
    }
}

/// Handler for `POST /v1/agents/enroll`. Mints a one-time enrolment code an agent pastes into
/// its MCP client; returns the MCP endpoint and the code. Redeeming the code (over MCP) lands
/// a *pending* agent for the operator to approve, no "create the agent first" friction.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollAgentReq {
    /// An optional suggested name shown next to the pending agent.
    #[serde(default)]
    pub label: Option<String>,
}

/// The longest label an enrolment code keeps (200 characters): a suggested name shown next to the pending agent, stored with the code.
pub const ENROLMENT_LABEL_MAX_CHARS: usize = 200;

/// Handler for `POST /v1/agents/enroll`.
pub async fn enroll_agent(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<EnrollAgentReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    state.service.refuse_enrolment_if_agents_paused()?;
    if req.label.as_deref().is_some_and(|label| label.chars().count() > ENROLMENT_LABEL_MAX_CHARS) {
        return Err(GatewayError::BadRequest(format!("label is longer than {ENROLMENT_LABEL_MAX_CHARS} characters")));
    }
    let now = now_ms();
    // All 128 bits of CSPRNG, grouped for legibility. The code becomes the agent's bearer for the life
    // of its session once redeemed (see `bootstrap_from_enrolment_code`), a hosted gateway takes it from
    // anywhere on the internet, and the store keeps it as an unsalted digest, so it has to withstand
    // being guessed online and searched for offline in a copy of the store, like every other bearer.
    let raw = short_id().to_uppercase();
    // A code a remote request minted (a console session, a permaura.com token, a forwarded call) carries the console prefix, so the agent bearer it becomes is remote on any transport, as the bearer that minted it was.
    let prefix = if remote { crate::CONSOLE_TOKEN_PREFIX } else { "" };
    let groups: Vec<&str> = (0..raw.len()).step_by(4).map(|at| &raw[at..at + 4]).collect();
    let code = format!("{prefix}ENRL-{}", groups.join("-"));
    // 15-minute validity is plenty to paste it into a client; a stale code is just dead.
    let expires_at = now + 15 * 60 * 1000;
    // The code's own times, which its redemption records too, join the two events without naming the code.
    let summary = json!({
        "label": &req.label,
        "expires_at": expires_at,
        "remote": remote,
        "code_created_at": now,
        "code_expires_at": expires_at,
    });
    let store = state.service.store();
    let mut minted = Some(EnrolmentCode { code: code.clone(), label: req.label, created_at: now, expires_at, used: false });
    store.change_with_record(&mut || {
        let Some(minted) = minted.take() else { return Ok(()) };
        store.mint_enrolment_code(minted, now, state.limits.config().live_enrolment_codes)?;
        // A code that would become an agent's bearer is not left redeemable without its record.
        if let Err(e) = state.service.audit_authority(crate::service::ENROLMENT_CODE_MINT_ACTION, "enrolment-code", &op, summary.clone()) {
            let _ = store.consume_enrolment_code(&code, now);
            return Err(e);
        }
        Ok(())
    })?;
    let mut body = json!({
        "code": code,
        "mcp_endpoint": "/mcp",
        "expires_at": expires_at,
        "instructions": "Paste this endpoint + code into your agent's MCP config (Claude Code / Codex / Cursor). It will appear here as Pending for you to approve.",
    });
    // When this gateway is an OAuth resource server (remote access on), advertise the codeless,
    // consent-based path too: a remote agent points its MCP client at the public URL, signs in to
    // Permaura, and consent IS the approval. The gateway is the source of truth for whether OAuth is
    // actually live (PERMAURA_PUBLIC_URL set), so deriving it here avoids the web DB drifting from it.
    if let Some(oauth) = state.service.live_oauth() {
        let map = body.as_object_mut().expect("enroll body is an object");
        map.insert("oauth".into(), json!(true));
        map.insert("public_mcp_url".into(), json!(oauth.config().mcp_resource));
        map.insert(
            "oauth_instructions".into(),
            json!("Remote agent: point your MCP client at the URL above, sign in to Permaura when prompted, and approve it on the consent screen: that consent is the approval. No code, and it appears already approved."),
        );
    }
    Ok((StatusCode::CREATED, Json(body)))
}

/// Handler for `POST /v1/agents/:id/approve`. Moves a pending agent to approved (one click).
/// Promotion to Approved defeats the new-agent approval gate, so over the broker with a device
/// enrolled it is held for a device signature; approving an already-approved agent is a no-op that
/// applies immediately.
pub async fn approve_agent(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    if state.service.store().get_agent(&id)?.is_none() {
        return Err(GatewayError::NotFound(format!("agent '{id}'")));
    }
    let mutation = crate::policy_guard::Mutation::AgentApprove { agent_id: id.clone() };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        // The notice is cleared by `apply_mutation_as`, on this path and on the held one alike.
        Guarded::Applied(_) => Ok((StatusCode::OK, Json(json!({ "agent_id": id, "status": "approved" })))),
    }
}

// ── POST /v1/devices/push-token ──────────────────────────────────────────────────

/// Register a phone's Expo push token so approval notifications can reach it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushTokenReq {
    /// The Expo push token from the phone app.
    pub token: String,
    /// The phone's platform, `ios` or `android`. Checked and not stored: a notification is addressed by the token alone.
    #[serde(default)]
    pub platform: Option<String>,
}

/// Handler for `POST /v1/devices/push-token`.
pub async fn register_push_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<PushTokenReq>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // Operator-only, like every other device route. Without this the endpoint took an unauthenticated
    // POST: anyone who could reach a gateway (a public tunnel bypasses the /api/gw proxy and
    // its gate) could register a push token and start receiving this account's approval notifications.
    // The phone already authenticates here, so requiring it breaks no client.
    let _op = operator_authed(&state, &headers)?;
    if let Some(platform) = req.platform.as_deref().filter(|p| !matches!(*p, "ios" | "android")) {
        return Err(GatewayError::BadRequest(format!("platform is 'ios' or 'android', not '{platform}'")));
    }
    state.service.register_push_token(req.token);
    Ok(Json(json!({ "registered": true })))
}

// ── PUT / DELETE /v1/agents/:id ───────────────────────────────────────────────────

/// Handler for `DELETE /v1/agents/:id`. Removes a registered agent **and cascades**: it
/// revokes the agent's sessions (so its bearer tokens die), removes it from every grant that
/// names it, and deletes a grant left naming nobody unless it is the Default. Without the
/// cascade, a later agent re-created under the same id would silently inherit the old grants,
/// access the operator believed they had destroyed.
pub async fn delete_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    if state.service.store().get_agent(&id)?.is_none() {
        return Err(GatewayError::NotFound(format!("agent '{id}'")));
    }
    let mutation = crate::policy_guard::Mutation::AgentDelete { agent_id: id.clone() };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        // The notice is cleared by `apply_mutation_as`, on this path and on the held one alike.
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

/// Body for `PUT /v1/agents/:id` (rename).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAgentReq {
    /// The new human-friendly name.
    pub name: String,
}

/// Handler for `PUT /v1/agents/:id`. Renames an agent (upsert by id).
pub async fn update_agent(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<UpdateAgentReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    // Preserve the agent's approval status + enrolment time across a rename; create as
    // approved if it does not exist (operator-driven rename of an unknown id). A rename that keeps a
    // Pending agent Pending, or renames an already-approved agent, applies immediately over the
    // broker; only *creating* a new Approved agent (unknown id) is held for a device signature.
    let (status, enrolled_at) = store
        .get_agent(&id)?
        .map(|a| (a.status, a.enrolled_at))
        .unwrap_or((AgentStatus::Approved, now_ms()));
    let mutation = crate::policy_guard::Mutation::AgentUpsert {
        agent: Agent { id: id.clone(), name: req.name, status, enrolled_at },
    };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::OK, Json(json!({ "agent_id": id, "updated": true })))),
    }
}

// ── PUT / DELETE /v1/grants/:id ───────────────────────────────────────────────────

/// Handler for `PUT /v1/grants/:id`. Replaces (or creates) the v2 grant with this id, the edit
/// path the grants console uses to change the policy/agent sets, limits, name, and flags.
pub async fn update_grant(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<GrantReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    refuse_another_id("grant", req.grant_id.as_deref(), &id)?;
    let grant = req.into_grant(id.clone())?;
    validate_policies(store.as_ref(), &grant.policy_ids)?;
    validate_agents(store.as_ref(), &grant.agents)?;
    // Held for a device signature when the edit widens authorization (new policy/agent, raised
    // limit, longer expiry, re-enabled, or promoted to Default) over the broker.
    let mutation = crate::policy_guard::Mutation::GrantUpsert { grant };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::OK, Json(json!({ "grant_id": id, "updated": true })))),
    }
}

/// Body for `PATCH /v1/grants/:id`, partial: the panic-pause toggle and/or default reassignment,
/// without resending the whole grant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantPatchReq {
    /// Flip the pause switch.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Make this grant the Default (clears the flag from the previous default). Cannot be unset
    /// directly; reassign Default to another grant instead.
    #[serde(default)]
    pub is_default: Option<bool>,
}

/// Handler for `PATCH /v1/grants/:id`. Enable/disable and Default reassignment.
pub async fn patch_grant(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<GrantPatchReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let mut grant = store
        .get_grant(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("grant '{id}'")))?;

    if let Some(enabled) = req.enabled {
        grant.enabled = enabled;
    }
    match req.is_default {
        Some(false) if grant.is_default => {
            return Err(GatewayError::BadRequest(
                "the Default cannot be unset directly: make another grant the Default instead".into(),
            ));
        }
        Some(true) => grant.is_default = true,
        _ => {}
    };
    // Re-enabling a paused grant or promoting one to Default widens reach, so over the broker it is
    // held for a device signature; pausing/other tightening patches apply immediately.
    let mutation = crate::policy_guard::Mutation::GrantUpsert { grant };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::OK, Json(json!({ "grant_id": id, "updated": true })))),
    }
}

/// Handler for `DELETE /v1/grants/:id`. Revokes (deletes) a grant, except the Default baseline,
/// which cannot be deleted while it holds `is_default`: there is always a baseline. Like every
/// other delete it goes through [`apply_or_hold`], so it is held for a device wherever it arrived from
/// while one is trusted and approvals are not opted down, and over the broker whenever it lowers a bar
/// some other grant leaves in force.
pub async fn delete_grant(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let grant = store
        .get_grant(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("grant '{id}'")))?;
    if grant.is_default {
        return Err(GatewayError::BadRequest(DEFAULT_GRANT_UNDELETABLE.into()));
    }
    let mutation = crate::policy_guard::Mutation::GrantDelete { grant_id: id.clone() };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(_) => Ok((StatusCode::OK, Json(json!({ "grant_id": id, "deleted": true })))),
    }
}

const DEFAULT_GRANT_UNDELETABLE: &str =
    "the Default grant cannot be deleted: reassign Default to another grant first";

/// Query for `GET /v1/grants/:id/usage`, an optional window override (defaults to the grant's period).
#[derive(Deserialize)]
pub struct UsageQuery {
    /// `day` | `week` | `month` | `total`. Absent ⇒ the grant's own period.
    #[serde(default)]
    pub window: Option<GrantPeriod>,
    /// Number of sparkline buckets to split the window into. Absent ⇒ 24.
    #[serde(default)]
    pub buckets: Option<usize>,
}

/// Handler for `GET /v1/grants/:id/usage`, two-tier usage stats for the grant card + detail view:
/// overall used vs ceiling, per-agent used vs each agent's limit, and a time-bucketed
/// series for the sparkline. Derived from the same counter that drives budget enforcement.
///
/// Operator only: it is a console view, and an agent has no console to render it. And it reads the
/// counter and nothing else. It used to clone the whole hot audit window on every request to find
/// one grant's events, which outside admission control let any session fill a hosted worker's
/// request slots and memory with copies of the chain. Its cost is now one indexed read of
/// this grant's rows and a fixed number of buckets, whatever the window holds.
pub async fn grant_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    let grant = store
        .get_grant(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("grant '{id}'")))?;

    let period = q.window.unwrap_or(grant.period);
    let now = now_ms();
    let window_ms = period.window_secs().map(|s| s * 1000);
    let since = window_ms.map(|w| now - w).unwrap_or(i64::MIN);

    // The counter is the number the engine authorizes against and the only one that survives a
    // prune, so the totals, the agents and the series all come from it and agree with each other.
    let window = crate::store::GrantWindow { grant_id: id.as_str(), since_ms: since };
    let counts = store.read_grant_usage(std::slice::from_ref(&window))?;
    let overall_used = counts.total(&id);

    // Per-agent breakdown: every agent that has charged this grant in the window, plus any listed.
    let mut agent_ids: std::collections::BTreeSet<String> = grant.agent_ids().into_iter().collect();
    let listed: std::collections::HashSet<String> =
        agent_ids.iter().map(|a| crate::audit_bound::agent_key(a).into_owned()).collect();
    agent_ids.extend(counts.agents(&id).into_iter().filter(|a| !listed.contains(a)));
    let agents: Vec<serde_json::Value> = agent_ids
        .into_iter()
        .map(|agent_id| {
            let limit = grant.effective_per_agent_limit(&agent_id);
            let used = counts.agent(&id, &agent_id);
            json!({ "agent_id": agent_id, "used": used, "limit": limit })
        })
        .collect();

    // Time-bucketed sparkline series over the window (skip for an unbounded Total period).
    let buckets = q.buckets.unwrap_or(24).clamp(1, 168);
    let series: Vec<serde_json::Value> = match window_ms {
        Some(w) if w > 0 => {
            let bucket_ms = (w / buckets as i64).max(1);
            store
                .grant_usage_series(&id, since, bucket_ms, buckets)?
                .into_iter()
                .enumerate()
                .map(|(i, c)| json!({ "t": since + i as i64 * bucket_ms, "count": c }))
                .collect()
        }
        _ => Vec::new(),
    };

    Ok(Json(json!({
        "grant_id": id,
        "period": period,
        "window_secs": period.window_secs(),
        "overall_limit": grant.overall_limit,
        "overall_used": overall_used,
        "default_per_agent_limit": grant.default_per_agent_limit,
        "agents": agents,
        "series": series,
        // Kept for clients that read it. The series used to be counted from the hot window and went
        // partial once the archive had pruned it; the counter keeps every charge in a rolling window,
        // so nothing here is partial any more.
        "window_only": false,
    })))
}

// ── POST /v1/grants/rebuild-usage ───────────────────────────────────────────────

/// Handler for `POST /v1/grants/rebuild-usage`. Recount every grant's budget from the chain itself.
///
/// The counter is a derived fact and the chain is the source. This is the way back when the two can
/// have drifted (after a restore, or after a grant's period was widened past the point where its
/// oldest rows had already been folded), and it is the reason the audit scan the counter replaced is
/// still in the code rather than deleted.
///
/// Operator only, and deliberately not on any automatic path: it walks the archive and the hot
/// window, so on a large tenant it is slow, and a budget that silently recomputes itself is a budget
/// nobody can reason about.
pub async fn rebuild_grant_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    _: NoBody,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let _op = operator_authed(&state, &headers)?;
    let walk = state.limits.try_chain_walk()?;
    let store = state.service.store().clone();
    let archive = state.service.audit_archive().cloned();
    let (filed, included) = tokio::task::spawn_blocking(move || {
        let _walk = walk;
        match archive {
            // The verified reader, not a bare walk of the index: a rebuild commits whatever it is
            // handed, so it is handed only a history that proves complete up to the signed boundary.
            // The store checks that coverage against the hot window it reads before the walk, and
            // under its lock that the window still continues from it, which is what stops a prune
            // landing during the walk from turning into a gap.
            Some(archive) => {
                let mut archived = crate::archive::ArchivedEvents::new(&archive, store.as_ref())?;
                Ok::<_, GatewayError>((store.rebuild_grant_usage(&mut archived)?, true))
            }
            None => {
                if let Some(boundary) = store.audit_boundary()?.filter(|b| b.base_seq > 0) {
                    return Err(GatewayError::Internal(format!(
                        "this store has archived seq 0 to {} and this gateway has no audit archive configured to read them back: a rebuild from the hot window alone would reset every grant's budget, so the counter is left as it is",
                        boundary.base_seq - 1
                    )));
                }
                Ok((store.rebuild_grant_usage(&mut std::iter::empty())?, false))
            }
        }
    })
    .await
    .map_err(|e| GatewayError::Internal(format!("rebuild task: {e}")))??;
    Ok(Json(json!({ "rebuilt": true, "charges": filed, "archive_included": included })))
}

// ── DELETE /v1/secrets/:id ────────────────────────────────────────────────────────

/// Whether `id` is a staged row a pending `credential_promote` still names. One no pending hold names is an orphan a failed or interrupted promotion left, which the hold can no longer discard, so the operator may.
fn parked_for_a_pending_hold(store: &dyn Store, id: &str) -> Result<bool, GatewayError> {
    if !crate::secret_inventory::is_staging_secret_id(id) {
        return Ok(false);
    }
    Ok(store
        .list_pending_control_plane_holds()?
        .iter()
        .any(|a| permaura_core::json_stream::string_at(&a.params, "/staging_secret_id").as_deref() == Some(id)))
}

/// Handler for `DELETE /v1/secrets/:id`. Removes a sealed secret (disconnects an integration).
pub async fn delete_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    Path(id): Path<String>,
    _: NoBody,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    let store = state.service.store();
    if parked_for_a_pending_hold(store.as_ref(), &id)? {
        crate::secret_inventory::refuse_staging_secret_id("secret", &id)?;
    }
    // Checked before the hold so a typo is a 404 now, rather than a notification asking someone to
    // approve destroying something that was never there.
    if store.get_secret(&id)?.is_none() && !kms_wrapped(store.as_ref(), &id)? {
        return Err(GatewayError::NotFound(format!("secret '{id}'")));
    }
    let mutation = crate::policy_guard::Mutation::SecretDelete { secret_id: id.clone() };
    match apply_or_hold(&state, remote, &op, &mutation).await? {
        Guarded::Held(code, body) => Ok((code, Json(body))),
        Guarded::Applied(applied) => Ok((StatusCode::OK, Json(applied))),
    }
}

// ── OAuth Resource Server metadata (RFC 9728 + the ChatGPT shim) ──────────────────

/// `GET /.well-known/oauth-protected-resource[/mcp]`: declares this gateway an OAuth resource
/// server and points clients at permaura.com as the Authorization Server (RS ≠ AS). 404 when the
/// gateway has no public URL (pure-local: opaque tokens only, no OAuth).
pub async fn protected_resource_metadata(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let oauth = state
        .service
        .oauth()
        .filter(|o| !o.is_withdrawn())
        .ok_or_else(|| GatewayError::NotFound("OAuth resource server is not enabled".into()))?;
    let c = oauth.config();
    Ok(Json(json!({
        "resource": c.mcp_resource,
        "authorization_servers": [c.issuer],
        // `offline_access` belongs here, not just in the AS's allow-list. A client that reads this
        // list and asks for exactly what it advertises would request `scope=mcp`, and the AS mints a
        // refresh token only when the GRANTED scopes contain offline_access, so advertising `mcp`
        // alone silently caps every agent's life at the access token's one hour, however the AS is
        // configured. The two have to agree or the fix on one side is inert.
        "scopes_supported": ["mcp", "offline_access"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Permaura gateway",
    })))
}

/// `GET /.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`: the
/// ChatGPT-compatibility shim. Some clients probe the MCP server's OWN origin for AS metadata
/// rather than following the protected-resource pointer, so we redirect them to permaura.com's
/// equivalents. 404 when OAuth is disabled.
pub async fn as_metadata_redirect(
    State(state): State<AppState>,
    uri: axum::http::Uri,
) -> Result<axum::response::Redirect, GatewayError> {
    let oauth = state
        .service
        .oauth()
        .filter(|o| !o.is_withdrawn())
        .ok_or_else(|| GatewayError::NotFound("OAuth resource server is not enabled".into()))?;
    Ok(axum::response::Redirect::temporary(&format!(
        "{}{}",
        oauth.config().issuer,
        uri.path()
    )))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    /// A body whose declared length is over the limit is answered at once, without reading any of it; one under the limit is still read to its end before the answer.
    #[tokio::test]
    async fn a_body_declared_over_the_limit_is_refused_without_reading_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let stalled_body = |read: Arc<AtomicUsize>| {
            let first = futures_util::stream::once(async move {
                read.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"0123456789"))
            });
            axum::body::Body::from_stream(futures_util::StreamExt::chain(first, futures_util::stream::pending()))
        };
        let refusal = || (StatusCode::UNAUTHORIZED, "no").into_response();

        let read = Arc::new(AtomicUsize::new(0));
        let req = Request::builder()
            .header(axum::http::header::CONTENT_LENGTH, "1048577")
            .body(stalled_body(read.clone()))
            .unwrap();
        let answered = tokio::time::timeout(std::time::Duration::from_secs(1), refuse_after_draining(req, 1 << 20, refusal())).await;
        assert_eq!(answered.expect("answered without waiting on the body").status(), StatusCode::UNAUTHORIZED);
        assert_eq!(read.load(Ordering::SeqCst), 0, "no byte of the body was read");

        let req = Request::builder()
            .header(axum::http::header::CONTENT_LENGTH, "10")
            .body(axum::body::Body::from("0123456789"))
            .unwrap();
        assert_eq!(refuse_after_draining(req, 1 << 20, refusal()).await.status(), StatusCode::UNAUTHORIZED);
    }

    /// A bundle seal or open that cannot get the one permit in time is turned away, not queued for ever.
    #[tokio::test]
    async fn a_bundle_derivation_kept_waiting_is_turned_away() {
        let _running = crate::vault_bundle::BUNDLE_KDF.acquire().await.unwrap();
        let err = bundle_kdf_permit_within(std::time::Duration::from_millis(20)).await.unwrap_err();
        assert!(
            matches!(&err, GatewayError::TooManyRequests { reason, .. } if reason == "bundle_open"),
            "{err:?}"
        );
    }

    fn peer(addr: &str) -> Option<SocketAddr> {
        Some(addr.parse().unwrap())
    }

    fn command_cap() -> Capability {
        Capability {
            id: "vercel-cli.whoami".into(),
            description: "Print the Vercel account the token belongs to".into(),
            risk: permaura_core::RiskTier::Low,
            action: permaura_core::Action::Read,
            requires_approval: false,
            resource: "vercel_prod".into(),
            secret_id: "sec-vercel".into(),
            kind: permaura_connectors::CapabilityKind::Command,
            command: Some(permaura_connectors::CommandSpec {
                program: "vercel".into(),
                args_template: vec!["whoami".into()],
                secret_env: "VERCEL_TOKEN".into(),
                allowed_placeholders: vec![],
            }),
            http: None,
            ssh: None,
        }
    }

    #[test]
    fn a_hosted_worker_refuses_to_add_a_command_connector() {
        let err = refuse_command_caps_on_hosted(true, &[command_cap()])
            .expect_err("a hosted worker must refuse a command connector");
        assert!(
            matches!(err, GatewayError::BadRequest(ref m) if m.contains("hosted gateway")),
            "the refusal must be a 400 that says why: {err:?}"
        );
    }

    #[test]
    fn a_self_run_gateway_still_adds_a_command_connector() {
        assert!(refuse_command_caps_on_hosted(false, &[command_cap()]).is_ok());
    }

    #[test]
    fn a_hosted_worker_still_adds_an_http_connector() {
        let caps = connector_capabilities("github", "gh_main", "sec-gh");
        assert!(!caps.is_empty(), "the github preset must yield capabilities");
        assert!(refuse_command_caps_on_hosted(true, &caps).is_ok());
    }

    #[test]
    fn hosted_worker_is_remote() {
        // A hosted (Mode C) worker is directly internet-exposed with no loopback client, so it is
        // remote even with no Cloudflare headers and no peer address.
        assert!(compute_is_remote(true, &HeaderMap::new(), None));
    }

    #[test]
    fn loopback_is_not_remote() {
        // Not hosted, no tunnel headers, and either no peer info or a loopback peer → local.
        assert!(!compute_is_remote(false, &HeaderMap::new(), None));
        assert!(!compute_is_remote(false, &HeaderMap::new(), peer("127.0.0.1:54321")));
        assert!(!compute_is_remote(false, &HeaderMap::new(), peer("[::1]:54321")));
    }

    #[test]
    fn tunnel_headers_are_remote() {
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        assert!(compute_is_remote(false, &h, None));
        let mut h = HeaderMap::new();
        h.insert("cf-ray", "abc123".parse().unwrap());
        assert!(compute_is_remote(false, &h, None));
    }

    /// A permaura.com token is remote on a loopback peer with no forwarder header, and a local
    /// session bearer there stays local.
    #[test]
    fn a_permaura_com_token_is_remote_over_loopback() {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::AUTHORIZATION, "Bearer eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln".parse().unwrap());
        assert!(compute_is_remote(false, &h, peer("127.0.0.1:54321")));
        assert!(compute_is_remote(false, &h, None));
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::AUTHORIZATION, "Bearer demo-codex-cli-token".parse().unwrap());
        assert!(!compute_is_remote(false, &h, peer("127.0.0.1:54321")));
    }

    #[test]
    fn non_loopback_peer_is_remote() {
        // The peer-check fix: a BYO / non-Cloudflare public gateway stamps no cf-* header, so without
        // the peer check an off-host caller read as loopback and defeated the guard.
        assert!(compute_is_remote(false, &HeaderMap::new(), peer("203.0.113.7:44300")));
        assert!(compute_is_remote(false, &HeaderMap::new(), peer("192.168.1.20:9000")));
    }

    #[test]
    fn a_web_page_is_remote_over_loopback() {
        for origin in [
            "https://permaura.com",
            "https://www.permaura.com",
            "http://localhost:3102",
            "http://localhost:1420",
            "https://attacker.example",
            "null",
            "TAURI://LOCALHOST",
            "",
        ] {
            let mut h = HeaderMap::new();
            h.insert("origin", origin.parse().unwrap());
            assert!(compute_is_remote(false, &h, None), "{origin:?} must read as remote");
            assert!(compute_is_remote(false, &h, peer("127.0.0.1:54321")), "{origin:?} from 127.0.0.1");
        }
        // One page origin among several is enough.
        let mut h = HeaderMap::new();
        h.append("origin", "tauri://localhost".parse().unwrap());
        h.append("origin", "https://permaura.com".parse().unwrap());
        assert!(compute_is_remote(false, &h, None));
    }

    #[test]
    fn the_desktop_webview_keeps_loopback() {
        let mut h = HeaderMap::new();
        h.insert("origin", "tauri://localhost".parse().unwrap());
        assert!(!compute_is_remote(false, &h, peer("127.0.0.1:54321")));
        // The Windows webview's origin is an ordinary http host elsewhere, so it is only exempt there.
        let mut h = HeaderMap::new();
        h.insert("origin", "http://tauri.localhost".parse().unwrap());
        assert_eq!(compute_is_remote(false, &h, peer("127.0.0.1:54321")), !cfg!(windows));
        // The exemption never outranks a tunnel, a forwarder or an off-host peer.
        let mut h = HeaderMap::new();
        h.insert("origin", "tauri://localhost".parse().unwrap());
        h.insert("cf-ray", "abc123".parse().unwrap());
        assert!(compute_is_remote(false, &h, None));
        let mut h = HeaderMap::new();
        h.insert("origin", "tauri://localhost".parse().unwrap());
        assert!(compute_is_remote(false, &h, peer("192.168.1.20:9000")));
        assert!(compute_is_remote(true, &h, None));
    }

    #[test]
    fn reject_if_remote_maps_the_flag() {
        assert!(reject_if_remote(true).is_err());
        assert!(reject_if_remote(false).is_ok());
    }

    #[test]
    fn forwarding_headers_close_the_operator_plane() {
        // A bring-your-own HTTP tunnel (ngrok, Tailscale Funnel) or reverse proxy connects from
        // loopback but stamps standard forwarding headers; each alone must classify as remote.
        // The loopback peer (`None`) is the point: the header is the only signal available.
        for (name, value) in [
            ("x-forwarded-for", "203.0.113.7"),
            ("x-real-ip", "203.0.113.7"),
            ("forwarded", "for=203.0.113.7;proto=https"),
        ] {
            let mut h = HeaderMap::new();
            h.insert(name, value.parse().unwrap());
            assert!(compute_is_remote(false, &h, None), "{name} must read as remote");
        }
    }

    /// A seeded state with the hosted flag forced, so a test can exercise Mode C without touching
    /// the process environment (`PERMAURA_HOSTED` is read once per construction and shared by every
    /// test in this binary).
    fn state_with_hosted(hosted: bool) -> AppState {
        let mut state = AppState::in_memory_seeded();
        state.hosted = hosted;
        state
    }

    /// Headers carrying the seeded operator bearer, plus any extras.
    fn operator_headers(extra: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", crate::seed::DEMO_TOKEN).parse().unwrap(),
        );
        for (name, value) in extra {
            h.insert(*name, value.parse().unwrap());
        }
        h
    }

    /// The seeded operator session, resolved the way a handler resolves it, so `pairing_authority`
    /// gets the real thing rather than a hand-built `Session`.
    fn operator_session(state: &AppState) -> Session {
        operator_authed(state, &operator_headers(&[])).expect("the seeded demo token is an operator")
    }

    #[test]
    fn pairing_authority_is_loopback_when_not_remote() {
        // Modes A and B reach the positional anchor before any of the hosted machinery is consulted:
        // no ticket and no Resource Server needed.
        let state = state_with_hosted(false);
        let op = operator_session(&state);
        let auth = pairing_authority(
            &state,
            &op,
            false,
            &HeaderMap::new(),
            crate::oauth::TicketPurpose::ApproverPair,
            crate::oauth::TicketBinding::None,
        )
        .expect("a loopback caller is authorised by position");
        assert!(matches!(auth, PairingAuthority::Loopback));
    }

    #[test]
    fn pairing_authority_refuses_a_tunnelled_caller_holding_a_ticket() {
        // Mode B has a host, so the positional anchor is available and strictly stronger. The
        // identity substitute is NOT offered there, whatever the caller presents.
        let state = state_with_hosted(false);
        let op = operator_session(&state);
        let headers = operator_headers(&[(PAIRING_TICKET_HEADER, "a.plausible.ticket")]);
        // `let Err(..) else` rather than `expect_err`, which would need `PairingAuthority: Debug`,
        // and a derived Debug would print an unspent ticket id into whatever captured the panic.
        let Err(err) = pairing_authority(
            &state,
            &op,
            true,
            &headers,
            crate::oauth::TicketPurpose::ApproverPair,
            crate::oauth::TicketBinding::None,
        ) else {
            panic!("a tunnelled caller must not reach the keyring");
        };
        assert!(
            matches!(err, GatewayError::Denied(_)),
            "a tunnelled caller is refused outright, not asked to step up: {err}"
        );
    }

    #[test]
    fn hosted_pairing_without_a_ticket_asks_for_a_step_up() {
        // 401, never 403: 403 tells a client it may never do this and ends the interaction, while the
        // whole point of a step-up is that the console CAN proceed after re-authenticating.
        let state = state_with_hosted(true);
        let op = operator_session(&state);
        let Err(err) = pairing_authority(
            &state,
            &op,
            true,
            &operator_headers(&[]),
            crate::oauth::TicketPurpose::ApproverPair,
            crate::oauth::TicketBinding::None,
        ) else {
            panic!("a hosted caller with no ticket must be refused");
        };
        assert!(
            matches!(err, GatewayError::StepUpRequired(_)),
            "a missing ticket must ask for re-authentication, not deny outright: {err}"
        );
    }

    #[test]
    fn a_revocation_takes_a_step_up_everywhere_but_the_gateways_own_machine() {
        let self_run = state_with_hosted(false);
        let op = operator_session(&self_run);
        let Ok(None) = revocation_step_up(&self_run, &op, false, &HeaderMap::new(), "device:a") else {
            panic!("at the gateway's own machine the bearer is enough");
        };
        let Err(err) = revocation_step_up(&self_run, &op, true, &operator_headers(&[]), "device:a") else {
            panic!("a remote revocation must not pass on the bearer");
        };
        assert!(matches!(err, GatewayError::Denied(_)), "with no authorization server there is no step-up to ask for: {err}");

        let hosted = state_with_hosted(true);
        let op = operator_session(&hosted);
        let Err(err) = revocation_step_up(&hosted, &op, true, &operator_headers(&[]), "device:a") else {
            panic!("a hosted revocation must not pass on the bearer");
        };
        assert!(matches!(&err, GatewayError::StepUpRequired(m) if m.contains("'approver-revoke'")), "{err}");
    }

    /// The audit record must name the human, not just the worker. `auth_time` and `amr` say a
    /// re-authentication happened; on a team account several people can produce one, so without an
    /// actor the record cannot answer the only question the owner's notification email raises.
    #[test]
    fn the_audit_detail_names_the_actor_who_stepped_up() {
        let authority = PairingAuthority::HostedOwner {
            jti: "tkt_1".into(),
            auth_time: 1_700_000_000,
            amr: vec!["pwd".into()],
            actor_sub: Some("user_priya".into()),
            actor_name: Some("Priya Raman".into()),
            actor_role: None,
            actor_is_owner: false,
            remove_alone: false,
        };
        let detail = authority.audit_detail();
        assert_eq!(detail["actor_sub"], json!("user_priya"));
        assert_eq!(detail["actor_name"], json!("Priya Raman"));
    }

    /// The emptying-revocation guard reads the `act_role` value, not its presence, so its standing does not rest on the verifier's filter alone.
    #[test]
    fn an_emptying_revocation_reads_the_role_value_not_its_presence() {
        let state = state_with_hosted(true);
        let member = |role: Option<&str>| PairingAuthority::HostedOwner {
            jti: "tkt_role".into(),
            auth_time: 1_700_000_000,
            amr: vec!["pwd".into()],
            actor_sub: Some("user_member".into()),
            actor_name: None,
            actor_role: role.map(Into::into),
            actor_is_owner: false,
            remove_alone: false,
        };
        for role in [None, Some("member"), Some("superadmin"), Some("owner,admin"), Some("")] {
            let err = refuse_emptying_unless_manager(&state, Some(&member(role)), "device:owner-phone").unwrap_err();
            assert!(matches!(err, GatewayError::Denied(_)), "{role:?}: {err:?}");
        }
        for role in ["owner", "admin"] {
            assert!(refuse_emptying_unless_manager(&state, Some(&member(Some(role))), "device:owner-phone").is_ok(), "{role}");
        }
    }

    /// An AS that named nobody writes an explicit null. An omitted key would be read as the owner by
    /// anyone who knows `sub` is pinned to them, which is exactly the wrong inference.
    #[test]
    fn an_unnamed_actor_is_recorded_as_null_not_omitted() {
        let authority = PairingAuthority::HostedOwner {
            jti: "tkt_1".into(),
            auth_time: 1_700_000_000,
            amr: vec!["pwd".into()],
            actor_sub: None,
            actor_name: None,
            actor_role: None,
            actor_is_owner: false,
            remove_alone: false,
        };
        let detail = authority.audit_detail();
        assert!(detail.contains_key("actor_sub"), "the key is always present on a hosted record");
        assert_eq!(detail["actor_sub"], serde_json::Value::Null);
        // Loopback has no actor claim to make: a human is standing at the machine.
        assert!(PairingAuthority::Loopback.audit_detail().is_empty());
    }

    /// The placement rule must be decidable without a credential, because that is what lets a handler
    /// answer a Mode B caller 403 before it ever looks at the bearer.
    #[test]
    fn the_placement_rule_refuses_a_tunnelled_caller_with_no_credential_at_all() {
        let tunnelled = state_with_hosted(false);
        let Err(err) = pairing_placement_allows(&tunnelled, true) else {
            panic!("a tunnelled caller must be refused on placement alone");
        };
        assert!(matches!(err, GatewayError::Denied(_)), "loopback-only is a 403, not a 401: {err}");
        assert!(err.to_string().contains("loopback-only"), "{err}");
        pairing_placement_allows(&tunnelled, false).expect("a loopback caller passes on placement");
        pairing_placement_allows(&state_with_hosted(true), true)
            .expect("a hosted worker is the one placement the substitute exists for");
    }
}

// ---- Connector OAuth: the bring-your-own-app authorization dance ----------------------

/// Body for `POST /v1/connections/:id/oauth/start`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartOAuthReq {
    /// The client id of the OAuth app the operator registered with the provider.
    pub client_id: String,
    /// Its client secret. Held in memory for the few minutes the dance takes, then sealed with the
    /// tokens: the gateway is a confidential client, so it needs this to refresh forever after.
    pub client_secret: String,
    /// The redirect URI, which must match the one registered with the provider **exactly**.
    /// Required rather than inferred: a mismatch is the single most common OAuth failure, and the
    /// operator has already had to type this string into the provider's console.
    pub redirect_uri: String,
    /// Override the connector's default scopes. Omit to request what the manifest declares.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

/// Validate the operator-supplied redirect URI. Loopback may be plaintext (there is no network hop
/// to intercept, and it is what a desktop gateway uses); anything else must be https, or the
/// authorization code would cross the network in the clear. Judged on the URL as a browser parses it,
/// since that is where the provider's redirect delivers the code, and returned as given, since the
/// provider compares it with the registered one byte for byte.
fn validate_redirect_uri(raw: &str) -> Result<String, GatewayError> {
    let uri = raw.trim();
    if uri.contains(['\r', '\n', ' ']) {
        return Err(GatewayError::BadRequest("redirect_uri must not contain whitespace".into()));
    }
    let parsed = reqwest::Url::parse(uri)
        .map_err(|_| GatewayError::BadRequest("redirect_uri must be an absolute http(s) URL".into()))?;
    if !uri.get(..parsed.scheme().len() + 3).is_some_and(|p| p.eq_ignore_ascii_case(&format!("{}://", parsed.scheme()))) {
        return Err(GatewayError::BadRequest("redirect_uri must be an absolute http(s) URL".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(GatewayError::BadRequest("redirect_uri must not carry a user name or password".into()));
    }
    match parsed.scheme() {
        "https" => {}
        "http" => {
            if !crate::release::is_loopback_http_url(uri) {
                return Err(GatewayError::BadRequest(
                    "redirect_uri must use https, unless it is a loopback address".into(),
                ));
            }
        }
        _ => return Err(GatewayError::BadRequest("redirect_uri must be an absolute http(s) URL".into())),
    }
    Ok(uri.to_string())
}

/// `POST /v1/connections/:id/oauth/start`: begin the bring-your-own-app OAuth dance for a
/// connection. Returns the provider URL for the operator to open in a browser. Operator-only.
///
/// Refused over the broker when a device is enrolled: completing this seals a credential, which is a
/// change of the upstream identity the connection acts as, and that mutation class is held for a
/// device signature. The callback arrives as an unauthenticated browser redirect and cannot
/// carry an approval, so rather than open a hole around the credential hold, the dance must be
/// started from the gateway's own host.
pub async fn start_connector_oauth(
    State(state): State<AppState>,
    Extension(RemoteFlag(remote)): Extension<RemoteFlag>,
    headers: HeaderMap,
    Path(id): Path<String>,
    JsonBody(req): JsonBody<StartOAuthReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), GatewayError> {
    let op = operator_authed(&state, &headers)?;
    if remote && state.service.any_device_enrolled() {
        return Err(GatewayError::Denied(
            "connecting over OAuth seals a credential, so it must be started from the gateway's own \
             host while a device is enrolled for approvals"
                .into(),
        ));
    }
    let store = state.service.store();
    let connection = store
        .get_connection(&id)?
        .ok_or_else(|| GatewayError::NotFound(format!("connection '{id}'")))?;
    crate::secret_inventory::refuse_staging_secret_id("the secret bound by connection", &connection.secret_id)?;
    // A first credential adds a secret row, so the refusal comes before the browser dance rather than at its end.
    if store.get_secret(&connection.secret_id)?.is_none() {
        state.service.refuse_if_over_allowance(crate::allowances::Allowance::Secrets, Some(&op))?;
    }

    // The connector's OAuth endpoints come from its catalog manifest, never from the caller, so a
    // request cannot point the dance at an attacker's authorization server.
    if let Some(why) = state.service.connection_revocation(&connection)? {
        return Err(GatewayError::Conflict(format!(
            "connector '{}' is revoked ({why}), so its OAuth endpoints are not used",
            connection.connector
        )));
    }
    // The token endpoint is sent the client secret and the code, so the endpoints come only from the entry this connection was made from: the compiled preset for one built from the gateway's own code or discovered from the operator's source, and an installed manifest only while it is still the version and key the connection recorded.
    let installed = match &connection.made_from {
        Some(permaura_core::CatalogOrigin::BuiltIn | permaura_core::CatalogOrigin::Discovered) => None,
        Some(permaura_core::CatalogOrigin::Installed { version, key_id }) => {
            let current = store.get_connector_manifest(&connection.connector)?;
            let signed_by = |m: &crate::manifest::InstalledManifest| match &m.provenance {
                crate::manifest::Provenance::Signed { key_id } => Some(key_id.clone()),
                crate::manifest::Provenance::User => None,
            };
            if !current.as_ref().is_some_and(|m| m.version == *version && signed_by(m) == *key_id) {
                return Err(GatewayError::Conflict(format!(
                    "connection '{}' was made from version {version} of '{}', which is no longer the version installed, so its OAuth endpoints are not taken from another. Make the connection again from the installed version.",
                    connection.id, connection.connector
                )));
            }
            current
        }
        None => store.get_connector_manifest(&connection.connector)?,
    };
    if installed.is_some() {
        if let Some(why) = state.service.connector_revocation(&connection.connector)? {
            return Err(GatewayError::Conflict(format!(
                "connector '{}' is revoked ({why}), so its OAuth endpoints are not used",
                connection.connector
            )));
        }
    }
    let preset = match &installed {
        Some(m) => Some(m.manifest.clone()),
        None => crate::presets::catalog().get(&connection.connector).cloned(),
    }
    .ok_or_else(|| {
        GatewayError::BadRequest(format!(
            "connector '{}' is not in this gateway's catalog, so its OAuth endpoints are unknown",
            connection.connector
        ))
    })?;
    let oauth = preset.oauth.as_ref().ok_or_else(|| {
        GatewayError::BadRequest(format!("connector '{}' does not support OAuth", preset.id))
    })?;
    // An installed manifest's endpoints are read live here, so they are held to the hosts its install named: the token endpoint is sent the client secret and the code.
    if let Some(installed) = &installed {
        let named = installed.named_hosts();
        for (what, url) in [("authorization", &oauth.authorize_url), ("token", &oauth.token_url)] {
            let host = crate::connectors::shown_host(url);
            if !host.as_ref().is_some_and(|h| named.contains(h)) {
                return Err(GatewayError::Denied(format!(
                    "connector '{}' sends its OAuth {what} requests to {}, which its install did not name (it named {}), so no client secret is sent there. Install the connector again so the change names that host.",
                    preset.id,
                    host.as_deref().unwrap_or("an address that names no host"),
                    if named.is_empty() { "no host".to_string() } else { named.join(", ") },
                )));
            }
        }
    }

    let client_id = req.client_id.trim().to_string();
    let client_secret = {
        let given = zeroize::Zeroizing::new(req.client_secret);
        permaura_core::SecretString::copied(given.trim())
    };
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(GatewayError::BadRequest("client_id and client_secret are required".into()));
    }
    let redirect_uri = validate_redirect_uri(&req.redirect_uri)?;
    let scopes = req.scopes.unwrap_or_else(|| oauth.scopes.clone());

    let state_token = crate::oauth_connect::random_token();
    let (verifier, challenge) = if oauth.pkce {
        let v = permaura_core::SecretString::new(crate::oauth_connect::random_token());
        let c = crate::oauth_connect::s256_challenge(v.expose());
        (Some(v), Some(c))
    } else {
        (None, None)
    };

    let url = crate::oauth_connect::authorize_url(
        &oauth.authorize_url,
        &client_id,
        &redirect_uri,
        &scopes,
        &state_token,
        challenge.as_deref(),
        &oauth.authorize_params,
    );
    let binding = crate::oauth_connect::PendingBinding::capture(&state.service, &connection, &op, remote)?;

    state.oauth_pending.insert(
        state_token.clone(),
        crate::oauth_connect::PendingAuth {
            connection_id: id.clone(),
            provider: preset.id.clone(),
            client_id,
            client_secret,
            redirect_uri,
            token_url: oauth.token_url.clone(),
            code_verifier: verifier,
            scopes,
            created_ms: now_ms(),
            binding,
            token_auth: oauth.token_auth,
        },
        now_ms(),
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "connection_id": id,
            "authorize_url": url,
            "expires_in_ms": crate::oauth_connect::PENDING_TTL_MS,
            "pkce": oauth.pkce,
        })),
    ))
}

/// Query string on the provider's redirect back to `GET /oauth/callback`.
#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    /// The authorization code, on success.
    #[serde(default)]
    pub code: Option<String>,
    /// The `state` minted by `start`, the only thing authenticating this request.
    #[serde(default)]
    pub state: Option<String>,
    /// The provider's error code, when the user declined or the request was malformed.
    #[serde(default)]
    pub error: Option<String>,
    /// The provider's human-readable error detail.
    #[serde(default)]
    pub error_description: Option<String>,
}

/// The most of a provider's error text the callback page shows.
const CALLBACK_DETAIL_MAX_CHARS: usize = 300;

/// A minimal self-contained result page. The browser tab is a dead end either way (the console is
/// where the connection lives), so this only has to tell the operator what happened.
fn callback_page(title: &str, detail: &str) -> axum::response::Html<String> {
    // Escaped because `detail` can carry a provider-supplied error string.
    let esc = |s: &str| {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    };
    axum::response::Html(format!(
        "<!doctype html><meta charset=utf-8><title>{t}</title>\
         <style>body{{font:16px/1.5 system-ui,sans-serif;margin:4rem auto;max-width:34rem;padding:0 1rem}}\
         h1{{font-size:1.25rem}}p{{color:#444}}</style>\
         <h1>{t}</h1><p>{d}</p><p>You can close this tab.</p>",
        t = esc(title),
        d = esc(detail)
    ))
}

/// Why a credential an OAuth dance wrote stands: the browser redirect that completed it carries no bearer, so its record names the session that started the dance.
const OAUTH_CALLBACK_WRITE: &str = "an OAuth authorization started by this session completed in the browser";

/// The credential write's record for a completed OAuth dance. Ids, the provider and who started it; never a token, the code, `state` or the client secret.
fn audit_oauth_credential_write(
    state: &AppState,
    pending: &crate::oauth_connect::PendingAuth,
) -> Result<(), GatewayError> {
    let binding = &pending.binding;
    audit_vault(state, &binding.initiator, SECRET_WRITE_ACTION, "allow", json!({
        "reason": OAUTH_CALLBACK_WRITE,
        "secret_id": binding.secret_id,
        "connection_id": pending.connection_id,
        "provider": pending.provider,
        "remote": binding.remote,
    }))
}

/// The page for an authorization refused because what it was started against has changed.
fn stale_callback_page(why: crate::oauth_connect::Stale) -> axum::response::Html<String> {
    callback_page(
        "This authorization is out of date",
        &format!("{} Start connecting again from the console.", why.explain()),
    )
}

/// `GET /oauth/callback`: the provider's redirect. Exchanges the authorization code for tokens and
/// seals them as the connection's credential.
///
/// Unauthenticated by necessity: this is a plain browser navigation. Its authentication is the
/// `state` parameter, which is 32 CSPRNG bytes, single-use, expiring, and only ever minted by an
/// operator-authed `start`, so an attacker cannot forge one, and cannot replay one they observe.
///
/// `state` proves who started the dance, not that the connection is still the one they started it
/// against, so the write goes ahead only while its [`crate::oauth_connect::PendingBinding`] holds:
/// asked before the code is exchanged, and again inside the unit of work that writes, under the
/// control-plane lock, since the exchange is an await another write can land in. The write goes
/// through the audited credential-write path, so it and its record stand or fall together.
pub async fn connector_oauth_callback(
    State(state): State<AppState>,
    Query(q): Query<OAuthCallbackQuery>,
) -> axum::response::Html<String> {
    if let Some(err) = q.error {
        // The provider's words are shown only for a dance this gateway started and has not finished, which the refusal also ends; anyone can send an owner a link to this page on the gateway's own hostname.
        let live = q.state.as_deref().and_then(|st| state.oauth_pending.take(st, now_ms())).is_some();
        if !live {
            return callback_page(
                "Authorization not completed",
                "The provider did not complete an authorization this gateway is waiting for. If you were connecting a service, start again from the console.",
            );
        }
        let detail: String = q.error_description.unwrap_or(err).chars().take(CALLBACK_DETAIL_MAX_CHARS).collect();
        return callback_page("Authorization declined", &detail);
    }
    let (Some(code), Some(state_token)) = (q.code, q.state) else {
        return callback_page("Missing parameters", "The provider's redirect carried no code or state.");
    };
    let Some(pending) = state.oauth_pending.take(&state_token, now_ms()) else {
        // Unknown, already used, or expired: all indistinguishable to the caller on purpose.
        return callback_page(
            "This authorization has expired",
            "Start connecting again from the console. A link can only be used once, within ten minutes.",
        );
    };

    let store = state.service.store();
    let connection = match store.get_connection(&pending.connection_id) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return callback_page(
                "Connection not found",
                "It was removed while you were authorizing. Create it again and retry.",
            )
        }
        Err(e) => return callback_page("Something went wrong", &e.to_string()),
    };
    match pending.binding.stale(&state.service, store.as_ref(), &pending.connection_id) {
        Ok(None) => {}
        Ok(Some(why)) => return stale_callback_page(why),
        Err(e) => return callback_page("Something went wrong", &e.to_string()),
    }

    if let Err(e) = crate::secret_inventory::refuse_staging_secret_id("the secret bound by connection", &pending.binding.secret_id) {
        return callback_page("Could not store the credential", &e.to_string());
    }
    let cred = match crate::oauth_connect::exchange_code(
        state.service.http().as_ref(),
        &pending,
        &code,
        now_ms(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return callback_page("Could not complete the exchange", &e.to_string()),
    };

    let json = match crate::oauth_connect::to_sealed_json(&cred) {
        Ok(j) => j,
        Err(e) => return callback_page("Something went wrong", &e.to_string()),
    };
    let sealed = match seal(Cipher::Aes256Gcm, vault_passphrase(), json.as_bytes()) {
        Ok(s) => s,
        Err(e) => return callback_page("Could not seal the credential", &e.to_string()),
    };
    drop(json);
    drop(cred);
    permaura_core::secret::clear_stack();

    let _cp = state.service.control_plane_mutex().lock().await;
    let binding = &pending.binding;
    let metadata = store
        .get_secret(&binding.secret_id)
        .ok()
        .flatten()
        .map(|s| s.metadata)
        .unwrap_or_default();
    let mut record = Some(SecretRecord { id: binding.secret_id.clone(), sealed, metadata });
    let mut stale = None;
    let written = store.change_with_record(&mut || {
        let Some(record) = record.take() else { return Ok(()) };
        let stale = &mut stale;
        let still_bound = |store: &dyn Store| match binding.stale(&state.service, store, &pending.connection_id)? {
            None => Ok(()),
            Some(why) => {
                *stale = Some(why);
                Err(GatewayError::Conflict(why.explain().into()))
            }
        };
        publish_secret_with_record_if(&state, store.as_ref(), record, &binding.initiator, still_bound, || {
            audit_oauth_credential_write(&state, &pending)
        })?;
        Ok(())
    });
    if let Some(why) = stale {
        return stale_callback_page(why);
    }
    if let Err(e) = written {
        return callback_page("Could not store the credential", &e.to_string());
    }

    callback_page(
        "Connected",
        &format!(
            "{} is connected. Your gateway holds the refresh token and will keep this working on its \
             own. Nothing was sent to permaura.com.",
            connection.name
        ),
    )
}

// ── Restore reconciliation: the review list and lifting the hold ───────────────────────────────
//
// Five control-plane mutations. Every one of them is permitted while held, because reconciliation
// IS a sequence of control-plane mutations and refusing them would leave a restored tenant with no
// way out of its own hold; none is gated by the audit ceiling or by admission control, because a
// restored snapshot may already be above the ceiling and telling an owner to slow down while they
// are trying to make their workspace usable again is the wrong instruction. All are audited.

/// The confirmation authority for a restored workspace: the OAuth operator subject.
///
/// **Not a session, and not a device.** Every session was deleted by the invalidation and every
/// device is itself awaiting review, so nothing inside the restored database can authorise a
/// confirmation, which is the point. A permaura.com-issued token whose `sub` equals
/// `PERMAURA_OWNER_SUB` is a fact that lives entirely outside the tenant database, so a promoted
/// snapshot cannot restore it, rewrite it or forge it.
///
/// A session bearer is refused even when one exists, rather than being allowed as a convenience on
/// a gateway that happens to have one: the property worth having is that the authority is outside
/// the database, and an alternative path inside it would be the whole of the argument undone.
///
/// A gateway with no OAuth configuration has no authority of this kind; a self-run gateway also
/// has no hold bucket and so never reconciles, and the refusal says both rather than reading as a
/// bug.
fn restoration_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::oauth::VerifiedClaims, GatewayError> {
    let token = bearer(headers)?;
    let Some(oauth) = state.service.oauth() else {
        return Err(GatewayError::Denied(
            "this gateway has no Authorization Server bound, so it has no reconciliation authority: only a permaura.com operator token whose subject is PERMAURA_OWNER_SUB can confirm restored authority, and a gateway with no hold bucket never reconciles in the first place".into(),
        ));
    };
    if token.matches('.').count() != 2 {
        return Err(GatewayError::Denied(
            "reconciliation needs a permaura.com operator token; a gateway session bearer cannot confirm restored authority, because every session in a restored database is one a restore rolled back".into(),
        ));
    }
    let claims = oauth
        .verify(&token, crate::store::now_ms() / 1000)
        .map_err(|reason| GatewayError::Unauthorized(format!("invalid token: {reason}")))?;
    if !claims.is_operator() {
        return Err(GatewayError::Denied(
            "reconciliation needs an operator-scoped permaura.com token".into(),
        ));
    }
    Ok(claims)
}

/// The reconciliation, or the refusal that there is none.
fn open_reconciliation(
    state: &AppState,
) -> Result<crate::reconcile::ReconciliationRecord, GatewayError> {
    state.service.reconciliation()?.ok_or_else(|| {
        GatewayError::NotFound(
            "this gateway is not reconciling a restore: nothing has been restored into it, or the record has not been written yet".into(),
        )
    })
}

/// What the review routes answer with.
fn reconciliation_body(
    state: &AppState,
    record: &crate::reconcile::ReconciliationRecord,
) -> serde_json::Value {
    json!({
        "hold_id": record.hold_id,
        "checkpoint_id": record.checkpoint_id,
        "state": record.health_snapshot()["state"],
        "opened_at": record.opened_at,
        "closed_at": record.closed_at,
        "closed_by": record.closed_by,
        "unreviewed": record.unreviewed(),
        "items": record.items,
        // What this restore could not establish, in full: a missing retained floor means the
        // checkpoint job is not stamping one, and the console is the only place an owner would
        // learn it.
        "notes": record.notes,
        "replay_floor_ms": record.replay_floor_ms,
        "replay_floor_source": record.replay_floor_source,
        "approval_floor": record.approval_floor,
        "gap_events": record.gap_events,
        // A restored snapshot may already be above the hot-audit ceiling, which was never a property
        // of the bytes. Surfaced here so an owner meets it while reconciling rather than as a 429 the
        // moment the hold is lifted.
        "audit_pressure": state
            .service
            .audit_ceiling()
            .health_snapshot(state.service.store().audit_len().unwrap_or(0)),
    })
}

/// Handler for `GET /v1/recovery/reconciliation`: the list, and what the restore could not establish.
pub async fn list_reconciliation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, GatewayError> {
    restoration_operator(&state, &headers)?;
    let record = open_reconciliation(&state)?;
    Ok(Json(reconciliation_body(&state, &record)))
}

/// Body for confirming or removing one item.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItemReq {
    /// `device`, `grant`, `connection`, `secret` or `agent`.
    pub kind: String,
    /// The item's id.
    pub id: String,
}

/// Find the item a request names, refusing a kind this build does not know.
fn locate<'a>(
    record: &'a mut crate::reconcile::ReconciliationRecord,
    req: &ReviewItemReq,
) -> Result<&'a mut crate::reconcile::ReviewItem, GatewayError> {
    let kind = crate::reconcile::ReviewKind::parse(&req.kind).ok_or_else(|| {
        GatewayError::BadRequest(format!(
            "'{}' is not a reviewable kind; expected device, grant, connection, secret or agent",
            req.kind
        ))
    })?;
    record
        .items
        .iter_mut()
        .find(|i| i.kind == kind && i.id == req.id)
        .ok_or_else(|| {
            GatewayError::NotFound(format!("no {} '{}' in the reconciliation list", req.kind, req.id))
        })
}

/// Handler for `POST /v1/recovery/reconciliation/confirm`: this one may act again.
pub async fn confirm_reconciliation_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ReviewItemReq>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let operator = restoration_operator(&state, &headers)?.sub;
    let mut record = open_reconciliation(&state)?;
    let item = locate(&mut record, &req)?;
    item.status = crate::reconcile::ReviewStatus::Confirmed;
    item.decided_at = Some(crate::store::now_ms());
    crate::reconcile::save(state.service.store().as_ref(), &record)?;
    crate::reconcile::append_review_action(
        state.service.store().as_ref(),
        "recovery.confirm",
        &operator,
        json!({ "kind": req.kind, "id": req.id, "hold_id": record.hold_id }),
    )?;
    Ok(Json(reconciliation_body(&state, &record)))
}

/// Handler for `POST /v1/recovery/reconciliation/remove`: delete the restored thing rather than
/// trust it.
///
/// The underlying object goes first and the item is marked only if it did, so a record saying
/// `removed` is never the only thing standing between a restored credential and an agent. A device
/// is revoked rather than deleted, which is what the keyring can express and what every other
/// revocation surface already does.
pub async fn remove_reconciliation_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ReviewItemReq>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let claims = restoration_operator(&state, &headers)?;
    let mut record = open_reconciliation(&state)?;
    let kind = { locate(&mut record, &req)?.kind };
    let store = state.service.store();
    match kind {
        crate::reconcile::ReviewKind::Device => {
            // Removing the last trusted device empties the keyring, a decision kept for the owner; the web proxy mints this token only for the owner, and a token naming any other actor is refused here as well.
            let _cp = state.service.control_plane_mutex().lock().await;
            let someone_else = claims.actor.as_ref().is_some_and(|a| a.sub != claims.sub);
            if someone_else && state.service.revoking_would_empty_keyring(&req.id) {
                return Err(GatewayError::Denied(
                    "removing this restored device would leave this gateway with no trusted approver, \
                     and only the gateway owner's own sign-in can do that"
                        .into(),
                ));
            }
            state.service.revoke_approver_key(&req.id)?
        }
        crate::reconcile::ReviewKind::Grant => {
            store.delete_grant(&req.id)?;
        }
        crate::reconcile::ReviewKind::Connection => {
            store.delete_connection(&req.id)?;
            state.service.note_connection_removed(&req.id);
        }
        crate::reconcile::ReviewKind::Secret => {
            store.delete_secret(&req.id)?;
            store.delete_secret_custody(&req.id)?;
            state.service.note_credential_change(&req.id);
            state.service.forget_rotations_of_deleted_secrets();
        }
        // The whole removal, not just the row: an OAuth client's token outlives its agent, so without the
        // tombstone its next call registers it again, and a grant still naming it hands it back its reach.
        crate::reconcile::ReviewKind::Agent => {
            let delete = crate::policy_guard::Mutation::AgentDelete { agent_id: req.id.clone() };
            match apply_mutation(store.as_ref(), &state.service, &delete) {
                Ok(_) | Err(GatewayError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    let item = locate(&mut record, &req)?;
    item.status = crate::reconcile::ReviewStatus::Removed;
    item.decided_at = Some(crate::store::now_ms());
    crate::reconcile::save(store.as_ref(), &record)?;
    crate::reconcile::append_review_action(
        store.as_ref(),
        "recovery.remove",
        &claims.sub,
        json!({ "kind": req.kind, "id": req.id, "hold_id": record.hold_id }),
    )?;
    Ok(Json(reconciliation_body(&state, &record)))
}

/// Handler for `POST /v1/recovery/reconciliation/confirm-all`.
///
/// Its own route and its own audit action rather than N confirmations, because "the owner looked at
/// every one of these" and "the owner accepted all of these at once" are different statements and
/// only one of them is true here. An auditor reading the chain has to be able to tell them apart.
pub async fn confirm_all_reconciliation(
    State(state): State<AppState>,
    headers: HeaderMap,
    _: NoBody,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let operator = restoration_operator(&state, &headers)?.sub;
    let mut record = open_reconciliation(&state)?;
    let now = crate::store::now_ms();
    let confirmed: Vec<crate::reconcile::ReviewItem> = record
        .items
        .iter()
        .filter(|i| i.is_unreviewed())
        .cloned()
        .collect();
    for item in record.items.iter_mut().filter(|i| i.is_unreviewed()) {
        item.status = crate::reconcile::ReviewStatus::Confirmed;
        item.decided_at = Some(now);
    }
    crate::reconcile::save(state.service.store().as_ref(), &record)?;
    crate::reconcile::append_review_action(
        state.service.store().as_ref(),
        "recovery.confirm_all",
        &operator,
        json!({
            "hold_id": record.hold_id,
            "confirmed": confirmed.len(),
            "ids": crate::reconcile::ids(&confirmed),
        }),
    )?;
    Ok(Json(reconciliation_body(&state, &record)))
}

/// Handler for `POST /v1/recovery/reconciliation/close`: record `recovery.reconciled`.
///
/// Refuses while any item is unreviewed, which is the rule that nothing restored acts until the owner confirms it, in its enforceable form, and
/// while the record is still at `Opened`: there "nothing unreviewed" means the invalidation and the list
/// never happened, and a closed record is resumed by every later boot rather than invalidated.
///
/// **The gateway never writes the hold object.** The runtime holds read access to that prefix and
/// nothing else, and that is exactly what stops a compromised runtime from clearing its own hold, so
/// the response says the restoration authority may now clear the hold in both layers rather than
/// claiming to have done it.
pub async fn close_reconciliation(
    State(state): State<AppState>,
    headers: HeaderMap,
    _: NoBody,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let operator = restoration_operator(&state, &headers)?.sub;
    let mut record = open_reconciliation(&state)?;
    if matches!(record.stage, crate::reconcile::Stage::Opened) {
        return Err(GatewayError::Conflict(
            "this restore has not finished invalidating the restored sessions, approvals and enrolment codes, so there is no review list to close yet; the gateway retries it, and Close is available once the list appears".into(),
        ));
    }
    let outstanding = record.unreviewed();
    if outstanding > 0 {
        return Err(GatewayError::Denied(format!(
            "{outstanding} restored items are still awaiting review; confirm or remove each one before closing the reconciliation"
        )));
    }
    if !matches!(record.stage, crate::reconcile::Stage::Closed) {
        record.stage = crate::reconcile::Stage::Closed;
        record.closed_at = Some(crate::store::now_ms());
        record.closed_by = Some(operator);
        crate::reconcile::save(state.service.store().as_ref(), &record)?;
        crate::reconcile::append_reconciled(state.service.store().as_ref(), &record)?;
    }
    let mut body = reconciliation_body(&state, &record);
    if let Some(map) = body.as_object_mut() {
        map.insert(
            "hold".into(),
            json!({
                "cleared": false,
                "next": "the restoration authority may now clear the hold in both layers: the state.json object and PERMAURA_EXECUTION_HOLD on the service. This gateway holds read access to the hold object and nothing else, which is what stops a compromised runtime from clearing its own hold.",
            }),
        );
    }
    Ok(Json(body))
}

#[cfg(test)]
#[path = "approval_race_tests.rs"]
mod approval_race_tests;

#[cfg(test)]
mod approval_listing_tests {
    use super::*;
    use tower::ServiceExt;

    /// The listing written row by row around each result is byte for byte the `ApprovalListing` serde_json wrote, with the same declared length.
    #[tokio::test]
    async fn the_streamed_listing_is_the_serialized_listing() {
        let state = AppState::in_memory_seeded();
        let store = state.service.store();
        for (id, status, result) in [("appr_a", "approved", r#"{"rows":[{"id":1,"note":"x\"y"}]}"#), ("appr_b", "pending", "null")] {
            let row = format!(
                r#"{{"id":"{id}","session_id":"sess_demo","capability":"github.pull_requests.create","resource":"github_acme","message":"Approve?","status":"{status}","grant_id":null,"policy_id":null,"params":{{"title":"t"}},"result":{result},"result_status":null,"created_at":1,"expires_at":null,"risk":"high","action_description":"Create pull requests","required_tier":"approve","required_signatures":1,"signatures":[]}}"#
            );
            store.put_approval(serde_json::from_str(&row).unwrap()).unwrap();
        }
        let audience = state.service.served_approval_audience();
        let rows = store.list_approvals(None).unwrap();
        assert_eq!(rows.len(), 2);
        let expected = serde_json::to_vec(&ApprovalListing {
            approvals: rows.iter().map(|a| approval_json(&state, a, audience.as_deref(), false)).collect(),
        })
        .unwrap();

        let app = crate::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
        let request = Request::builder()
            .uri("/v1/approvals")
            .header("authorization", format!("Bearer {}", crate::seed::DEMO_TOKEN))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "application/json");
        assert_eq!(resp.headers()["content-length"], expected.len().to_string());
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&body), String::from_utf8_lossy(&expected));
    }
}

#[cfg(test)]
mod ssh_target_patch_tests {
    use super::*;
    use crate::policy_guard::{ConnPatch, Mutation, SshPatch};

    /// A held SSH target patch is applied on its approval, which can be long after the handler measured it, so the write asks the service's capability-bytes ceiling again.
    #[test]
    fn a_held_ssh_target_patch_asks_the_ceiling_when_it_is_applied() {
        let state = AppState::in_memory_seeded();
        let store = state.service.store().clone();
        let held = store.capability_bytes().unwrap();
        let tight = crate::service::EnforcementService::new(store.clone(), std::sync::Arc::new(crate::connectors::MockHttpClient::new()))
            .with_memory_budget(crate::memory::MemoryBudget::from_config(&crate::limits::LimitsConfig {
                capability_bytes: held + 1024,
                ..crate::limits::LimitsConfig::default()
            }));
        let patch = Mutation::ConnectionPatch {
            connection_id: "ssh_prod".into(),
            patch: ConnPatch {
                ssh: Some(SshPatch { host_key_sha256: Some("k".repeat(16 * 1024)), ..SshPatch::default() }),
                ..ConnPatch::default()
            },
        };

        let err = apply_mutation(store.as_ref(), &tight, &patch).expect_err("the rewritten rows pass the ceiling");
        assert!(matches!(err, GatewayError::TooLarge(_)), "{err}");
        assert_eq!(store.capability_bytes().unwrap(), held, "nothing was written");

        apply_mutation(store.as_ref(), state.service.as_ref(), &patch).expect("the default ceiling has room");
        assert!(store.capability_bytes().unwrap() > held);
    }
}

#[cfg(test)]
mod pairing_person_tests {
    use super::*;

    fn hosted(actor: Option<&str>) -> PairingAuthority {
        PairingAuthority::HostedOwner {
            jti: "jti_x".into(),
            auth_time: 0,
            amr: vec![],
            actor_sub: actor.map(str::to_string),
            actor_name: None,
            actor_role: None,
            actor_is_owner: true,
            remove_alone: false,
        }
    }

    fn naming(person: Option<&str>) -> PairApproverKeyReq {
        PairApproverKeyReq {
            approver_id: "phone_x".into(),
            approver_pubkey: "k".into(),
            issued_at: 0,
            sig: "s".into(),
            person: person.map(str::to_string),
        }
    }

    /// A hosted worker binds the key to the ticket's actor, so a body naming someone else was dropped; it is refused instead.
    #[test]
    fn a_hosted_pairing_refuses_a_person_the_ticket_does_not_name() {
        assert!(pairing_person(&hosted(Some("user_a")), &naming(Some("user_b"))).is_err());
        assert!(pairing_person(&hosted(None), &naming(Some("user_b"))).is_err());
        assert_eq!(pairing_person(&hosted(Some("user_a")), &naming(Some("user_a"))).unwrap().as_deref(), Some("user_a"));
        assert_eq!(pairing_person(&hosted(Some("user_a")), &naming(None)).unwrap().as_deref(), Some("user_a"));
        assert_eq!(pairing_person(&PairingAuthority::Loopback, &naming(Some("user_b"))).unwrap().as_deref(), Some("user_b"));
    }
}

#[cfg(test)]
mod redirect_uri_tests {
    use super::validate_redirect_uri;

    /// The loopback exemption is decided on the host a browser and the provider would send the code to, so a userinfo form naming another host is refused and the bracketed IPv6 loopback is let through.
    #[test]
    fn the_loopback_exemption_is_judged_on_the_parsed_host() {
        for refused in [
            "http://127.0.0.1:7376@evil.example/oauth/callback",
            "http://localhost:80@evil.example/oauth/callback",
            "http://localhost@evil.example/",
            "http://evil.example/oauth/callback",
            "http://127.0.0.1.evil.example/oauth/callback",
            "https://127.0.0.1:7376@evil.example/oauth/callback",
            "ftp://127.0.0.1/oauth/callback",
            "http:/127.0.0.1/oauth/callback",
            "http://127.0.0.1/oauth/callback with space",
        ] {
            assert!(validate_redirect_uri(refused).is_err(), "{refused} must be refused");
        }
        for allowed in [
            "http://127.0.0.1:7376/oauth/callback",
            "http://localhost:7376/oauth/callback",
            "http://[::1]:7376/oauth/callback",
            "https://gw.example.com/oauth/callback",
        ] {
            assert_eq!(validate_redirect_uri(allowed).unwrap(), allowed, "{allowed} must be accepted as given");
        }
    }
}

#[cfg(test)]
mod vouched_after_import_tests {
    use super::*;
    use crate::policy_guard::Mutation;
    use permaura_core::{Action, RiskTier};

    /// A vault restored before its Permaura-signed manifest is installed holds that manifest's POST reads to their shape (Create, High), because the bundle carries no manifest. Installing the signed manifest returns each capability that is exactly one of its lines to the posture it vouches for, and leaves alone what is not.
    #[test]
    fn installing_the_signed_manifest_returns_raised_lines_to_their_vouched_posture() {
        let state = AppState::in_memory_seeded();
        let store = state.service.store().clone();
        let manifest = json!({
            "id": "acme-signed", "name": "Acme", "vertical": "data", "base_url": "https://api.acme.example",
            "capabilities": [
                { "id": "files.search", "method": "POST", "path": "/files/search", "body_params": ["query"], "action": "search", "risk": "medium", "disabled": false },
                { "id": "files.upload", "method": "POST", "path": "/files", "body_params": ["name"] }
            ]
        });
        let mut connection = store.get_connection("github_acme").unwrap().unwrap();
        connection.id = "acme".into();
        connection.connector = "acme-signed".into();
        connection.capabilities = vec!["acme.files.search".into(), "acme.files.upload".into(), "acme.files.elsewhere".into()];
        connection.secret_id = "sec_acme".into();
        let template = store.get_capability("github.pull_requests.list").unwrap().unwrap();
        let record = |id: &str, base: &str, path: &str, posture: (Action, RiskTier, bool)| {
            let mut c = template.clone();
            c.id = id.into();
            c.resource = "acme".into();
            c.secret_id = "sec_acme".into();
            (c.action, c.risk, c.requires_approval) = posture;
            c.http = Some(crate::connectors::HttpSpec { method: crate::connectors::HttpMethod::Post, base_url: base.into(), path: path.into(), ..Default::default() });
            crate::vault_bundle::CapabilityRecord::from(&c)
        };
        let payload = crate::vault_bundle::BundlePayload {
            connections: vec![connection],
            policies: vec![],
            grants: vec![],
            capabilities: vec![
                record("acme.files.search", "https://api.acme.example", "/files/search", (Action::Search, RiskTier::Medium, false)),
                record("acme.files.upload", "https://api.acme.example", "/files", (Action::Create, RiskTier::High, false)),
                record("acme.files.elsewhere", "https://collector.example", "/files/search", (Action::Search, RiskTier::Medium, false)),
            ],
            secrets: vec![],
            agents: vec![],
            excluded: Default::default(),
        };
        crate::vault_bundle::apply(store.as_ref(), payload, &crate::vault_bundle::ImportOptions::default(), |_, _, _| Ok(())).unwrap();
        let posture = |id: &str| {
            let c = store.get_capability(id).unwrap().unwrap();
            (c.action, c.risk, c.requires_approval)
        };
        assert_eq!(posture("acme.files.search"), (Action::Create, RiskTier::High, false), "no manifest here vouches for it yet");

        let install = Mutation::ConnectorInstall {
            manifest,
            version: 1,
            provenance: crate::manifest::Provenance::Signed { key_id: "pmconn-dev".into() },
        };
        let out = apply_mutation(store.as_ref(), state.service.as_ref(), &install).unwrap();
        assert_eq!(posture("acme.files.search"), (Action::Search, RiskTier::Medium, false), "the signed line vouches for its read: {out}");
        assert_eq!(out["restored"], json!(["acme.files.search"]), "{out}");
        assert_eq!(posture("acme.files.upload"), (Action::Create, RiskTier::High, false), "a write stays what it was");
        assert_eq!(posture("acme.files.elsewhere"), (Action::Create, RiskTier::High, false), "another host is no vouched line");
    }
}

#[cfg(test)]
mod revoked_connector_tests {
    use super::*;
    use crate::manifest::{revocation_preimage, InstalledManifest, Provenance, Revocation, RevocationList};
    use crate::policy_guard::Mutation;
    use ed25519_dalek::Signer as _;

    /// The seeded estate with a Permaura-signed `github` v3 installed under `key_id`, its `github_acme` connection made from it, and the service checking a list that revokes `int-revoked`.
    fn estate(key_id: &str) -> AppState {
        let state = AppState::in_memory_seeded();
        state
            .service
            .store()
            .put_connector_manifest(InstalledManifest {
                manifest: crate::presets::catalog().get("github").unwrap().clone(),
                version: 3,
                provenance: Provenance::Signed { key_id: key_id.into() },
                installed_at: 0,
                endpoint_hosts: Vec::new(),
            })
            .unwrap();
        let root = ed25519_dalek::SigningKey::from_bytes(&[62; 32]);
        let mut list = RevocationList {
            revoked_key_ids: vec!["int-revoked".into()],
            revoked_manifests: Vec::new(),
            issued_at: 1,
            serial: 1,
            root_key_id: "root-test".into(),
            root_sig: String::new(),
        };
        use base64::Engine as _;
        list.root_sig = base64::engine::general_purpose::STANDARD.encode(root.sign(&revocation_preimage(&list)).to_bytes());
        state.with_revocation(Revocation::verified(&list, &[("root-test".to_string(), root.verifying_key())]).unwrap())
    }

    /// A newer manifest under the same id would lift the revocation from connections still holding the revoked version's capabilities, so it waits until they are gone, applied at once or confirmed from a hold alike.
    #[test]
    fn a_revoked_connector_is_not_replaced_while_connections_made_from_it_exist() {
        let state = estate("int-revoked");
        let store = state.service.store();
        let replace = Mutation::ConnectorInstall {
            manifest: serde_json::to_value(crate::presets::catalog().get("github").unwrap()).unwrap(),
            version: 4,
            provenance: Provenance::Signed { key_id: "int-current".into() },
        };
        let err = apply_mutation(store.as_ref(), state.service.as_ref(), &replace).unwrap_err();
        assert!(matches!(&err, GatewayError::Conflict(why) if why.contains("github_acme")), "{err:?}");
        assert_eq!(store.get_connector_manifest("github").unwrap().unwrap().version, 3);

        assert!(store.delete_connection("github_acme").unwrap());
        apply_mutation(store.as_ref(), state.service.as_ref(), &replace).expect("with nothing made from it left, a newer version installs");
        assert_eq!(state.service.connector_revocation("github").unwrap(), None, "and the version now installed is not revoked");
    }

    /// With its origin recorded, a connection made from a revoked version stays refused after a newer version replaces it, so that connection does not hold the replacement back, and one made from the newer version runs.
    #[test]
    fn a_connection_made_from_a_revoked_version_stays_refused_after_a_newer_one_replaces_it() {
        let state = estate("int-revoked");
        let store = state.service.store();
        assert!(store.delete_connection("github_acme").unwrap(), "the seeded connection records no origin");
        let made = |id: &str, version: u32, key: &str| {
            let mut c = store.get_connection("braintree_production").unwrap().unwrap();
            c.id = id.into();
            c.connector = "github".into();
            c.made_from = Some(permaura_core::CatalogOrigin::Installed { version, key_id: Some(key.into()) });
            store.put_connection(c.clone()).unwrap();
            c
        };
        let old = made("gh_v3", 3, "int-revoked");
        assert!(state.service.connection_revocation(&old).unwrap().is_some());

        let replace = Mutation::ConnectorInstall {
            manifest: serde_json::to_value(crate::presets::catalog().get("github").unwrap()).unwrap(),
            version: 4,
            provenance: Provenance::Signed { key_id: "int-current".into() },
        };
        apply_mutation(store.as_ref(), state.service.as_ref(), &replace).expect("a connection that records its origin does not block the replacement");
        assert!(state.service.connection_revocation(&old).unwrap().is_some(), "and the replacement does not revive the revoked copy");
        let new = made("gh_v4", 4, "int-current");
        assert_eq!(state.service.connection_revocation(&new).unwrap(), None);
        let built_in = permaura_core::Connection { made_from: Some(permaura_core::CatalogOrigin::BuiltIn), ..new };
        assert_eq!(state.service.connection_revocation(&built_in).unwrap(), None);
    }

    /// A connection stored before origins were recorded reads back with none, and a recorded one round-trips.
    #[test]
    fn a_connection_reads_back_its_origin_and_an_older_record_has_none() {
        let mut c = AppState::in_memory_seeded().service.store().get_connection("github_acme").unwrap().unwrap();
        let mut old = serde_json::to_value(&c).unwrap();
        old.as_object_mut().unwrap().remove("made_from");
        assert_eq!(serde_json::from_value::<permaura_core::Connection>(old).unwrap().made_from, None);
        c.made_from = Some(permaura_core::CatalogOrigin::Installed { version: 7, key_id: Some("int-a".into()) });
        let text = serde_json::to_string(&c).unwrap();
        assert!(text.contains(r#""made_from":{"kind":"installed","version":7,"key_id":"int-a"}"#), "{text}");
        assert_eq!(serde_json::from_str::<permaura_core::Connection>(&text).unwrap(), c);
    }

    #[test]
    fn an_agent_is_not_shown_the_capabilities_of_a_revoked_connector() {
        let cap = |state: &AppState| {
            state.service.store().list_capabilities().unwrap().into_iter().find(|c| c.id == "github.pull_requests.list").unwrap()
        };
        let clean = estate("int-current");
        assert!(reachable_by_agent(&clean.service, "codex-cli", &cap(&clean)).unwrap(), "a granted agent sees an unrevoked connector");
        let revoked = estate("int-revoked");
        assert!(!reachable_by_agent(&revoked.service, "codex-cli", &cap(&revoked)).unwrap());
    }
}
