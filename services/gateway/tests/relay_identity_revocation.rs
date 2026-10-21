//! A relayed identity revoked on the gateway stays revoked: the next relayed invoke from the same
//! control-plane session is refused the way a revoked bearer is, and does not write its row back
//! unrevoked, so a call it had held stays refused too.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{ExecutionLocation, Principal};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::relay::{handle_invoke, relayed_session_id};
use permaura_gateway::store::AGENT_SESSION_TTL_MS;
use permaura_gateway::{build_router, AppState};
use permaura_relay::{request_hash, InvokeOrigin, InvokeRequest, InvokeResult, RelayOutcome, SessionCtx};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const ORG: &str = "org_revocation";
const CP_SESSION: &str = "cp_revocation";
const SEARCH: &str = "braintree.transactions.search";
const DEPLOY: &str = "vercel.deployments.create";

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

/// The demo estate with the two seeded secrets the relayed calls use allowed off the host, since a
/// relayed call is remote whatever its frame says.
async fn estate() -> Estate {
    common::isolate_from_the_real_install();
    let http = MockHttpClient::new();
    let state = AppState::in_memory_seeded_with_http(Arc::new(http.clone()));
    let store = state.service.store();
    for id in ["sec_braintree_prod", "sec_vercel"] {
        let mut secret = store.get_secret(id).unwrap().expect("a seeded secret");
        secret.metadata.allowed_execution_locations.push(ExecutionLocation::RemoteAllowed);
        store.put_secret(secret).unwrap();
    }
    let op = common::operator_token(state.clone()).await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    Estate { state, http, app, op }
}

async fn call(app: &axum::Router, method: &str, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    let resp = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn relayed(e: &Estate, job_id: &str, capability: &str, params: Value) -> InvokeResult {
    let req = InvokeRequest {
        job_id: job_id.into(),
        session_ctx: SessionCtx {
            cp_session_id: CP_SESSION.into(),
            org_id: ORG.into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: capability.into(),
        params: params.clone(),
        request_hash: request_hash(capability, &params),
        reason: None,
        execution_location: ExecutionLocation::LocalOnly,
        deadline_ms: 9_999_999_999_999,
    };
    handle_invoke(&e.state.service, ORG, req).await
}

async fn search(e: &Estate, job_id: &str) -> InvokeResult {
    relayed(e, job_id, SEARCH, json!({ "status": "failed", "date": "2026-10-13" })).await
}

/// The operator's revocation of the relayed identity, through the same route as any other session.
async fn revoke(e: &Estate) {
    let id = relayed_session_id(CP_SESSION);
    let (status, body) = call(&e.app, "POST", &format!("/v1/sessions/{id}/revoke"), &e.op, Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn row_is_revoked(e: &Estate) -> bool {
    e.state
        .service
        .store()
        .get_session(&relayed_session_id(CP_SESSION))
        .unwrap()
        .expect("the relayed identity's row is still there")
        .revoked
}

fn refusal(result: &InvokeResult) -> String {
    match &result.outcome {
        RelayOutcome::Denied { decision } => decision.reason.clone(),
        other => panic!("the relayed invoke ran: {}", serde_json::to_value(other).unwrap()),
    }
}

#[tokio::test]
async fn a_revoked_relayed_identity_is_refused_and_stays_revoked() {
    let e = estate().await;
    assert!(matches!(search(&e, "job_1").await.outcome, RelayOutcome::Allowed { .. }), "baseline: the identity works");
    assert_eq!(e.http.requests().len(), 1);
    revoke(&e).await;

    let refused = search(&e, "job_2").await;
    assert_eq!(refusal(&refused), "session has been revoked", "the refusal a revoked bearer gets");
    assert!(row_is_revoked(&e), "the relayed invoke must not write the row back unrevoked");
    assert_eq!(e.http.requests().len(), 1, "nothing reached the upstream");

    let again = search(&e, "job_3").await;
    assert_eq!(refusal(&again), "session has been revoked", "and it stays refused");
    assert!(row_is_revoked(&e));
}

#[tokio::test]
async fn a_hold_under_a_revoked_relayed_identity_stays_refused_after_another_relayed_invoke() {
    let e = estate().await;
    let held = relayed(&e, "job_deploy", DEPLOY, json!({ "name": "synthetic", "target": "production" })).await;
    let RelayOutcome::RequiresApproval { approval_id, .. } = held.outcome else {
        panic!("the relayed deployment is held: {}", serde_json::to_value(&held).unwrap());
    };
    revoke(&e).await;
    let _ = search(&e, "job_after").await;
    assert!(row_is_revoked(&e), "the relayed invoke after the revocation left it standing");

    let (status, answer) =
        call(&e.app, "POST", "/v1/approvals", &e.op, json!({ "approval_id": approval_id, "approve": true })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "denied", "the held deployment stays refused: {answer}");
    assert_eq!(answer["resolution_reason"], "session_ended", "{answer}");
    assert!(e.http.requests().is_empty(), "neither the search nor the deployment reached the upstream");
}

/// The control: an identity nobody revoked keeps working, and its row is refreshed on every relayed
/// invoke exactly as before.
#[tokio::test]
async fn an_unrevoked_relayed_identity_is_refreshed_as_before() {
    let e = estate().await;
    assert!(matches!(search(&e, "job_1").await.outcome, RelayOutcome::Allowed { .. }));
    let store = e.state.service.store();
    let id = relayed_session_id(CP_SESSION);
    let mut row = store.get_session(&id).unwrap().expect("the relayed identity has a row");
    let first_token = row.token.clone();
    row.expires_at = Some(now_ms() + 1_000);
    store.put_session(row).unwrap();

    assert!(matches!(search(&e, "job_2").await.outcome, RelayOutcome::Allowed { .. }));
    let row = store.get_session(&id).unwrap().unwrap();
    assert!(!row.revoked);
    assert!(
        row.expires_at.unwrap_or_default() > now_ms() + AGENT_SESSION_TTL_MS - 60_000,
        "the expiry is pushed out again: {:?}",
        row.expires_at
    );
    assert_ne!(row.token, first_token, "the row is rewritten, with a fresh token nobody holds");
    assert_eq!(e.http.requests().len(), 2);
}

/// A refresh is the same admission, not a later one: a call the identity held before another relayed
/// invoke rewrote its row still runs when a human approves it.
#[tokio::test]
async fn a_hold_under_a_live_relayed_identity_still_runs_after_a_refresh() {
    let e = estate().await;
    let held = relayed(&e, "job_deploy", DEPLOY, json!({ "name": "synthetic", "target": "production" })).await;
    let RelayOutcome::RequiresApproval { approval_id, .. } = held.outcome else {
        panic!("the relayed deployment is held: {}", serde_json::to_value(&held).unwrap());
    };
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert!(matches!(search(&e, "job_after").await.outcome, RelayOutcome::Allowed { .. }), "the refresh");

    let (status, answer) =
        call(&e.app, "POST", "/v1/approvals", &e.op, json!({ "approval_id": approval_id, "approve": true })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "approved", "the held deployment runs: {answer}");
    assert_eq!(e.http.requests().len(), 2, "the search and the deployment reached the upstream");
}
