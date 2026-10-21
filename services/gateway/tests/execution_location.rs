//! A local-only credential never executes remotely, and whether a call is remote is the gateway's own
//! knowledge: a hosted worker, a relayed job, a forwarded or off-host request. The `execution_location`
//! a caller sends can only make the call stricter. It is outside `request_hash`, so trusting it let a
//! relayed or hosted call skip the custody gate by saying `local_only`, which is also the default.
//!
//! Every credential here is the synthetic demo seed.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{ExecutionLocation, Principal};
use permaura_gateway::relay::handle_invoke;
use permaura_gateway::{build_router, seed, AppState};
use permaura_relay::{request_hash, InvokeOrigin, InvokeRequest, RelayOutcome, SessionCtx};
use tower::ServiceExt;

mod common;

const CAPABILITY: &str = "braintree.transactions.search";
const SECRET: &str = "sec_braintree_prod";

fn params() -> serde_json::Value {
    serde_json::json!({ "status": "failed", "date": "2026-06-21" })
}

fn set_locations(state: &AppState, locations: Vec<ExecutionLocation>) {
    let store = state.service.store();
    let mut secret = store.get_secret(SECRET).unwrap().expect("the seeded secret");
    secret.metadata.allowed_execution_locations = locations;
    store.put_secret(secret).unwrap();
}

fn relayed(location: ExecutionLocation) -> InvokeRequest {
    InvokeRequest {
        job_id: "job_loc".into(),
        session_ctx: SessionCtx {
            cp_session_id: "cp_sess_loc".into(),
            org_id: "org_x".into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: CAPABILITY.into(),
        params: params(),
        request_hash: request_hash(CAPABILITY, &params()),
        reason: Some("relayed search".into()),
        execution_location: location,
        deadline_ms: 9_999_999_999_999,
    }
}

async fn send(state: &AppState, uri: &str, forwarded: bool, body: serde_json::Value) -> (StatusCode, String) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    if forwarded {
        builder = builder.header("x-forwarded-for", "203.0.113.9");
    }
    let resp = app.oneshot(builder.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn invoke_body() -> serde_json::Value {
    serde_json::json!({ "capability": CAPABILITY, "params": params(), "execution_location": "local_only" })
}

fn mcp_body() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "permaura_invoke", "arguments": { "capability": CAPABILITY, "params": params() } }
    })
}

#[tokio::test]
async fn a_relayed_invoke_saying_local_only_cannot_use_a_local_only_secret() {
    let state = common::seeded();
    for location in [ExecutionLocation::LocalOnly, ExecutionLocation::RemoteAllowed] {
        let result = handle_invoke(&state.service, "org_x", relayed(location)).await;
        match result.outcome {
            RelayOutcome::Denied { decision } => {
                assert!(decision.reason.contains("local-only"), "{location:?}: {}", decision.reason)
            }
            other => panic!("a relayed call is remote whatever its frame says ({location:?}): {other:?}"),
        }
    }
    set_locations(&state, vec![ExecutionLocation::LocalOnly, ExecutionLocation::RemoteAllowed]);
    let result = handle_invoke(&state.service, "org_x", relayed(ExecutionLocation::LocalOnly)).await;
    assert!(matches!(result.outcome, RelayOutcome::Allowed { .. }), "a secret that allows remote use still runs");
}

#[tokio::test]
async fn a_forwarded_or_hosted_call_saying_local_only_cannot_use_a_local_only_secret() {
    let state = common::seeded();
    let (status, body) = send(&state, "/v1/invoke", true, invoke_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a forwarded REST call is remote: {body}");
    assert!(body.contains("local-only"), "{body}");
    let (_, body) = send(&state, "/mcp", true, mcp_body()).await;
    assert!(body.contains("local-only"), "a forwarded MCP call is remote: {body}");

    let mut hosted = common::seeded();
    hosted.hosted = true;
    let (status, body) = send(&hosted, "/v1/invoke", false, invoke_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a hosted worker is remote: {body}");
    assert!(body.contains("local-only"), "{body}");

    let (status, body) = send(&state, "/v1/invoke", false, invoke_body()).await;
    assert_eq!(status, StatusCode::OK, "a loopback call on a self-run gateway is local: {body}");
}

/// A credential added through the console records no locations at all, and that is every credential
/// on a hosted worker. Read as local-only, the rule above would refuse all of them.
#[tokio::test]
async fn a_secret_that_records_no_locations_still_runs_remotely() {
    let mut state = common::seeded();
    set_locations(&state, Vec::new());
    state.hosted = true;
    let (status, body) = send(&state, "/v1/invoke", false, invoke_body()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let result = handle_invoke(&state.service, "org_x", relayed(ExecutionLocation::LocalOnly)).await;
    assert!(matches!(result.outcome, RelayOutcome::Allowed { .. }), "{:?}", result.outcome);
}
