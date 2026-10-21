//! A held call runs on the authority of the session that made it. Once that session is
//! revoked, expired or gone, a later approval must not release the call by any route, and the hold
//! has to end in a terminal state that says why instead of sitting claimed and pending.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use permaura_core::{ExecutionLocation, GrantAgent, GrantAgents};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::relay::handle_approval_result;
use permaura_gateway::service::InvokeOutcome;
use permaura_gateway::store::{Agent, Session, SessionRole, AGENT_SESSION_TTL_MS};
use permaura_gateway::{build_router, AppState};
use permaura_relay::{approval_display_full_digest_of, approval_result_preimage_v3, sign, ApprovalResult, RelayOutcome};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const CAP: &str = "vercel.deployments.create";
const SESSION_ENDED: &str = "session_ended";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct Estate {
    state: AppState,
    http: MockHttpClient,
    app: axum::Router,
    op: String,
}

async fn estate() -> Estate {
    common::isolate_from_the_real_install();
    let http = MockHttpClient::new();
    let state = AppState::in_memory_seeded_with_http(Arc::new(http.clone()));
    let op = common::operator_token(state.clone()).await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    Estate { state, http, app, op }
}

async fn call(app: &axum::Router, method: &str, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if !token.is_empty() {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn session_row(id: &str, agent_id: &str, token: &str) -> Session {
    let now = now_ms();
    Session {
        class: Default::default(),
        opened_by: None,
        id: id.into(),
        agent_id: agent_id.into(),
        user_id: None,
        device_id: None,
        token: token.into(),
        role: SessionRole::Agent,
        created_at: now,
        revoked: false,
        expires_at: Some(now + AGENT_SESSION_TTL_MS),
        last_used_at: None,
        actor: None,
    }
}

/// A separate Agent-role session for the approved demo agent, the shape an enrolled agent has.
fn agent(e: &Estate, id: &str) -> String {
    let token = format!("tok_{id}");
    e.state.service.store().put_session(session_row(id, "codex-cli", &token)).unwrap();
    token
}

/// The agent's held deployment, made through the REST invoke route.
async fn hold(e: &Estate, token: &str) -> String {
    let (status, body) = call(
        &e.app,
        "POST",
        "/v1/invoke",
        token,
        json!({ "capability": CAP, "params": { "name": "synthetic", "target": "production" } }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "the deployment is held for a human: {body}");
    assert!(e.http.requests().is_empty(), "nothing runs while it is held");
    body["approval_id"].as_str().expect("a held call names its approval").to_string()
}

async fn revoke(e: &Estate, session_id: &str) {
    let (status, body) = call(&e.app, "POST", &format!("/v1/sessions/{session_id}/revoke"), &e.op, Value::Null).await;
    assert_eq!(status, StatusCode::OK, "the operator's revocation succeeds: {body}");
}

async fn bearer_decides(e: &Estate, approval_id: &str, approve: bool) -> (StatusCode, Value) {
    call(&e.app, "POST", "/v1/approvals", &e.op, json!({ "approval_id": approval_id, "approve": approve })).await
}

/// A paired device's v3 signature over the approval exactly as the gateway serves it.
async fn signed(e: &Estate, approval_id: &str, approver: &str, sk: &SigningKey, approve: bool) -> ApprovalResult {
    let (_, appr) = call(&e.app, "GET", &format!("/v1/approvals/{approval_id}"), &e.op, Value::Null).await;
    let request_hash = appr["request_hash"].as_str().expect("request_hash is served").to_string();
    let job_id = appr["job_id"].as_str().expect("job_id is served").to_string();
    let audience = appr["approval_audience"].as_str().expect("the audience is served").to_string();
    let shown = approval_display_full_digest_of(&appr).expect("the full rendering is served");
    let decided_at = now_ms();
    let preimage =
        approval_result_preimage_v3(&audience, &job_id, approval_id, approve, &request_hash, &shown, approver, decided_at);
    ApprovalResult {
        job_id,
        approval_id: approval_id.into(),
        approve,
        request_hash,
        approver: approver.into(),
        decided_at,
        approver_pubkey: Some(STANDARD.encode(sk.verifying_key().to_bytes())),
        audience: Some(audience),
        display_digest: Some(shown),
        device_sig: sign(sk, &preimage),
    }
}

fn paired_device(e: &Estate, approver: &str, seed: u8) -> SigningKey {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    assert!(e.state.service.trust_approver_key(approver, &STANDARD.encode(sk.verifying_key().to_bytes())));
    sk
}

async fn device_decides_over_rest(e: &Estate, result: &ApprovalResult) -> (StatusCode, Value) {
    let body = json!({
        "approval_id": result.approval_id,
        "approve": result.approve,
        "approver": result.approver,
        "request_hash": result.request_hash,
        "decided_at": result.decided_at,
        "job_id": result.job_id,
        "approver_pubkey": result.approver_pubkey,
        "audience": result.audience,
        "display_digest": result.display_digest,
        "device_sig": result.device_sig,
    });
    call(&e.app, "POST", "/v1/approvals", &e.op, body).await
}

/// Every audit decision recorded against this approval, in order.
fn chain(e: &Estate, approval_id: &str) -> Vec<(String, Value)> {
    e.state
        .service
        .store()
        .audit_events(None)
        .unwrap()
        .into_iter()
        .filter(|ev| ev.payload.summary.get("approval_id").and_then(Value::as_str) == Some(approval_id))
        .map(|ev| (ev.payload.decision.clone(), ev.payload.summary.clone()))
        .collect()
}

/// The protection: no upstream request, a terminal row that says the gateway ended it and why, and a
/// chain that records the refusal with no execution attempt. A second approval changes nothing.
async fn assert_refused_and_settled(e: &Estate, approval_id: &str, why: &str) {
    assert!(
        e.http.requests().is_empty(),
        "a held call whose session no longer stands behind it reached the upstream: {:?}",
        e.http.requests().iter().map(|r| r.url.clone()).collect::<Vec<_>>()
    );
    let row = e.state.service.store().get_approval(approval_id).unwrap().expect("the hold is still recorded");
    assert_eq!(row.status, "denied", "the hold is settled, not left pending or approved");
    assert_eq!(row.resolution_reason.as_deref(), Some(SESSION_ENDED), "the row says the gateway ended it");
    assert!(row.result.is_none());

    let events = chain(e, approval_id);
    let decisions: Vec<&str> = events.iter().map(|(d, _)| d.as_str()).collect();
    assert_eq!(decisions, ["requires_approval", "denied"], "refused before any attempt: {events:?}");
    let (_, terminal) = events.last().unwrap();
    let reason = terminal["reason"].as_str().unwrap_or_default();
    assert!(reason.contains(why), "the chain says why ({why}): {terminal}");
    assert_eq!(terminal["human_decision"], "approved", "a human said yes and the gateway refused");

    let (status, again) = bearer_decides(e, approval_id, true).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["status"], "denied", "the terminal row is stable");
    assert!(e.http.requests().is_empty(), "a second approval still runs nothing");
    assert_eq!(chain(e, approval_id).len(), 2, "and writes nothing");
}

/// A distinct operator revokes the agent's session over REST, the bearer stops
/// authenticating, and the operator then approves the old hold with a bearer.
#[tokio::test]
async fn bearer_approval_after_the_session_is_revoked_is_refused_and_settled() {
    let e = estate().await;
    let token = agent(&e, "sess_held_agent");
    let approval_id = hold(&e, &token).await;
    revoke(&e, "sess_held_agent").await;
    assert!(e.state.service.authenticate(&token).is_err(), "the revocation took effect");

    let (status, answer) = bearer_decides(&e, &approval_id, true).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_ne!(answer["status"], "approved", "a revoked session's queued deployment executed: {answer}");
    assert_eq!(answer["status"], "denied", "{answer}");
    assert_eq!(answer["resolution_reason"], SESSION_ENDED, "{answer}");
    assert!(answer["result"].is_null(), "{answer}");
    assert_refused_and_settled(&e, &approval_id, "revoked").await;
}

/// The paired control: the same fixture with the session left alone executes, so the refusal above
/// is the revocation and not the fixture.
#[tokio::test]
async fn bearer_approval_with_the_session_live_still_executes() {
    let e = estate().await;
    let token = agent(&e, "sess_held_agent");
    let approval_id = hold(&e, &token).await;

    let (status, answer) = bearer_decides(&e, &approval_id, true).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "approved", "{answer}");
    assert!(answer["resolution_reason"].is_null(), "{answer}");
    let sent = e.http.requests();
    assert_eq!(sent.len(), 1, "exactly one upstream request");
    assert_eq!(sent[0].host().as_deref(), Some("api.vercel.com"));
    let decisions: Vec<String> = chain(&e, &approval_id).into_iter().map(|(d, _)| d).collect();
    assert_eq!(decisions, ["requires_approval", "attempt", "approved"]);
}

/// A device signature verifies and is still not authority the session no longer has.
#[tokio::test]
async fn device_signed_approval_after_the_session_is_revoked_is_refused() {
    let e = estate().await;
    let sk = paired_device(&e, "device:approver", 31);
    let token = agent(&e, "sess_held_agent");
    let approval_id = hold(&e, &token).await;
    revoke(&e, "sess_held_agent").await;

    let result = signed(&e, &approval_id, "device:approver", &sk, true).await;
    let (status, answer) = device_decides_over_rest(&e, &result).await;
    assert_eq!(status, StatusCode::OK, "the signature itself is valid: {answer}");
    assert_eq!(answer["status"], "denied", "{answer}");
    assert_eq!(answer["resolution_reason"], SESSION_ENDED, "{answer}");
    assert_refused_and_settled(&e, &approval_id, "revoked").await;
}

/// The device-signed control: the same signature on a live session's hold executes.
#[tokio::test]
async fn device_signed_approval_with_the_session_live_still_executes() {
    let e = estate().await;
    let sk = paired_device(&e, "device:approver", 31);
    let token = agent(&e, "sess_held_agent");
    let approval_id = hold(&e, &token).await;

    let result = signed(&e, &approval_id, "device:approver", &sk, true).await;
    let (status, answer) = device_decides_over_rest(&e, &result).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "approved", "{answer}");
    assert_eq!(e.http.requests().len(), 1);
}

/// The relay transport: a hold made under a relayed identity, its row revoked, then a signed approval
/// delivered through the relay's own entry point.
#[tokio::test]
async fn relay_delivered_approval_after_the_session_is_revoked_is_refused() {
    let e = estate().await;
    let sk = paired_device(&e, "device:approver", 31);
    let relayed = session_row("relay:cp_held", "codex-cli", "tok_never_presented");
    e.state.service.store().put_session(relayed.clone()).unwrap();
    let outcome = e
        .state
        .service
        .invoke(&relayed, CAP, &json!({ "name": "synthetic", "target": "production" }), None, ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::RequiresApproval { approval, .. } = outcome else { panic!("the deployment is held") };
    assert!(e.state.service.store().revoke_session("relay:cp_held").unwrap());

    let result = signed(&e, &approval.id, "device:approver", &sk, true).await;
    let keyring = e.state.service.approver_keyring_snapshot();
    let terminal = handle_approval_result(&e.state.service, &keyring, result).await.expect("a terminal outcome for the job");
    let RelayOutcome::Denied { decision } = &terminal.outcome else {
        panic!("the relayed job ends denied, not allowed: {}", serde_json::to_value(&terminal).unwrap());
    };
    assert!(decision.reason.contains(SESSION_ENDED), "the job says the gateway refused it, not the approver: {}", decision.reason);
    assert_refused_and_settled(&e, &approval.id, "revoked").await;
}

/// The relay control: the same delivery for a live relayed identity executes.
#[tokio::test]
async fn relay_delivered_approval_with_the_session_live_still_executes() {
    let e = estate().await;
    let sk = paired_device(&e, "device:approver", 31);
    let relayed = session_row("relay:cp_held", "codex-cli", "tok_never_presented");
    e.state.service.store().put_session(relayed.clone()).unwrap();
    let outcome = e
        .state
        .service
        .invoke(&relayed, CAP, &json!({ "name": "synthetic", "target": "production" }), None, ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::RequiresApproval { approval, .. } = outcome else { panic!("the deployment is held") };

    let result = signed(&e, &approval.id, "device:approver", &sk, true).await;
    let keyring = e.state.service.approver_keyring_snapshot();
    let terminal = handle_approval_result(&e.state.service, &keyring, result).await.expect("a terminal outcome");
    assert!(matches!(terminal.outcome, RelayOutcome::Allowed { .. }));
    assert_eq!(e.http.requests().len(), 1);
}

/// An agent revoking its own session over MCP ends its holds the same way the operator's REST
/// revocation does: both write the one revoked bit.
#[tokio::test]
async fn mcp_self_revocation_also_ends_the_hold() {
    let e = estate().await;
    let token = agent(&e, "sess_held_agent");
    let approval_id = hold(&e, &token).await;
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "permaura_revoke_session", "arguments": {} },
    });
    let (_, out) = call(&e.app, "POST", "/mcp", &token, body).await;
    assert_eq!(out["result"]["structuredContent"]["revoked"], true, "{out}");

    let (_, answer) = bearer_decides(&e, &approval_id, true).await;
    assert_eq!(answer["status"], "denied", "{answer}");
    assert_refused_and_settled(&e, &approval_id, "revoked").await;
}

/// Expiry ends a session's authority as surely as revocation: the bearer is refused with "session
/// has expired", so its queued calls are too.
#[tokio::test]
async fn an_expired_sessions_hold_is_refused() {
    let e = estate().await;
    let token = agent(&e, "sess_held_agent");
    let approval_id = hold(&e, &token).await;
    let mut row = e.state.service.store().get_session("sess_held_agent").unwrap().unwrap();
    row.expires_at = Some(now_ms() - 1);
    e.state.service.store().put_session(row).unwrap();
    assert!(e.state.service.authenticate(&token).is_err(), "the bearer has expired");

    let (_, answer) = bearer_decides(&e, &approval_id, true).await;
    assert_eq!(answer["status"], "denied", "{answer}");
    assert_refused_and_settled(&e, &approval_id, "expired").await;
}

/// The sweep deletes a revoked row a week after its last use, so the row can be gone by the time
/// anyone answers. The hold must still end, on an approval and on a denial, rather than spend its
/// claim on a lookup error and stay pending for ever.
#[tokio::test]
async fn a_hold_whose_session_row_is_gone_is_settled_not_stranded() {
    let e = estate().await;
    let token = agent(&e, "sess_held_agent");
    let approved = hold(&e, &token).await;
    let denied = hold(&e, &token).await;
    revoke(&e, "sess_held_agent").await;
    assert!(e.state.service.store().delete_session("sess_held_agent").unwrap());

    let (status, answer) = bearer_decides(&e, &approved, true).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "denied", "{answer}");
    assert_refused_and_settled(&e, &approved, "no longer exists").await;

    let (status, answer) = bearer_decides(&e, &denied, false).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "denied", "{answer}");
    assert!(answer["resolution_reason"].is_null(), "a human's denial names no gateway reason: {answer}");
    let events = chain(&e, &denied);
    let decisions: Vec<&str> = events.iter().map(|(d, _)| d.as_str()).collect();
    assert_eq!(decisions, ["requires_approval", "denied"], "{events:?}");
    assert_eq!(events[1].1["reason"], "denied by human approver");
    assert!(e.http.requests().is_empty());
}

/// An OAuth agent's row is never presented and its stored expiry is never extended: the client's JWT
/// is the credential. A lapsed expiry on that row is therefore not a lapsed session, and a hold made
/// by an agent still calling in must still run. Its revocation (the owner's tombstone) still counts.
#[tokio::test]
async fn an_oauth_agents_row_expiry_does_not_end_its_holds_but_its_revocation_does() {
    let e = estate().await;
    let store = e.state.service.store();
    store.put_agent(Agent::approved("oauth:held-client", "OAuth client", now_ms())).unwrap();
    let mut grant = store.get_grant("gr_vercel_acme").unwrap().unwrap();
    let GrantAgents::Agents(members) = &mut grant.agents else { panic!("the Vercel grant names its agents") };
    members.push(GrantAgent::new("oauth:held-client"));
    assert!(store.update_grant(grant).unwrap());
    let mut row = session_row("sess_oauth:held-client", "oauth:held-client", "tok_never_presented");
    row.expires_at = Some(now_ms() - 1);
    store.put_session(row.clone()).unwrap();

    let held = |svc: AppState, row: Session| async move {
        let outcome = svc
            .service
            .invoke(&row, CAP, &json!({ "name": "synthetic", "target": "production" }), None, ExecutionLocation::LocalOnly)
            .await
            .unwrap();
        let InvokeOutcome::RequiresApproval { approval, .. } = outcome else { panic!("the deployment is held") };
        approval.id
    };

    let live = held(e.state.clone(), row.clone()).await;
    let (_, answer) = bearer_decides(&e, &live, true).await;
    assert_eq!(answer["status"], "approved", "{answer}");
    assert_eq!(e.http.requests().len(), 1);

    let tombstoned = held(e.state.clone(), row).await;
    assert!(store.revoke_session("sess_oauth:held-client").unwrap());
    let (_, answer) = bearer_decides(&e, &tombstoned, true).await;
    assert_eq!(answer["status"], "denied", "{answer}");
    assert_eq!(answer["resolution_reason"], SESSION_ENDED, "{answer}");
    assert_eq!(e.http.requests().len(), 1, "the tombstoned agent's hold ran nothing");
}

/// Deleting a connection deletes its capability rows, so a hold made through it has no capability
/// left to load. It must end on an approval and on a denial, rather than spend its claim on a lookup
/// error and stay pending for ever. The session is live here: the reason is the capability's, and
/// the row carries no session reason.
#[tokio::test]
async fn a_hold_whose_connection_was_deleted_is_settled_not_stranded() {
    let e = estate().await;
    let token = agent(&e, "sess_held_agent");
    let approved = hold(&e, &token).await;
    let denied = hold(&e, &token).await;
    let (status, body) = call(&e.app, "DELETE", "/v1/connections/vercel_acme", &e.op, Value::Null).await;
    assert_eq!(status, StatusCode::OK, "the connection is deleted outright: {body}");
    assert!(e.state.service.store().get_capability(CAP).unwrap().is_none(), "and its capabilities with it");

    let (status, answer) = bearer_decides(&e, &approved, true).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "denied", "{answer}");
    assert!(answer["resolution_reason"].is_null(), "{answer}");
    let events = chain(&e, &approved);
    let decisions: Vec<&str> = events.iter().map(|(d, _)| d.as_str()).collect();
    assert_eq!(decisions, ["requires_approval", "denied"], "{events:?}");
    assert!(events[1].1["reason"].as_str().unwrap_or_default().contains("capability does not exist"), "{events:?}");
    assert_eq!(events[1].1["human_decision"], "approved");
    let (_, again) = bearer_decides(&e, &approved, true).await;
    assert_eq!(again["status"], "denied", "the terminal row is stable: {again}");

    let (status, answer) = bearer_decides(&e, &denied, false).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "denied", "{answer}");
    let events = chain(&e, &denied);
    assert_eq!(events.last().unwrap().1["reason"], "denied by human approver", "{events:?}");
    assert!(e.http.requests().is_empty());
}
