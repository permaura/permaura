//! A session opened through `POST /v1/sessions` stands only while the bearer that opened it does: revoking or expiring the opener ends every session it opened, and every one those opened, at their next request, whichever way the opener ended and whenever the child was opened.
//!
//! Every token here is synthetic.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

async fn send(state: &AppState, bearer: &str, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "127.0.0.1:7376")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn open(state: &AppState, opener: &str) -> String {
    let (status, body) = send(state, opener, "POST", "/v1/sessions", json!({ "agent_id": "codex-cli" })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["token"].as_str().expect("a session token").to_string()
}

fn id_of(state: &AppState, token: &str) -> String {
    state.service.store().session_by_token(token).unwrap().expect("a stored session").id
}

async fn works(state: &AppState, token: &str) -> bool {
    send(state, token, "GET", "/v1/grants", Value::Null).await.0 == StatusCode::OK
}

fn gateway() -> (AppState, String) {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let operator_token = seed::clean_bootstrap(state.service.store().as_ref()).expect("an operator token");
    (state, operator_token)
}

#[tokio::test]
async fn revoking_a_session_ends_what_it_opened() {
    let (state, operator_token) = gateway();
    let child = open(&state, &operator_token).await;
    let grandchild = open(&state, &child).await;
    let sibling = open(&state, &operator_token).await;
    assert!(works(&state, &child).await && works(&state, &grandchild).await && works(&state, &sibling).await);

    let (status, body) = send(&state, &sibling, "POST", &format!("/v1/sessions/{}/revoke", id_of(&state, &child)), Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!works(&state, &child).await, "the revoked session stops");
    assert!(!works(&state, &grandchild).await, "and so does the one it opened");
    assert!(works(&state, &sibling).await, "a session its opener opened beside it is untouched");
    assert!(works(&state, &operator_token).await, "and so is the opener");
    assert!(!state.service.bearer_is_live(&grandchild), "admission control agrees");
}

#[tokio::test]
async fn revoking_the_operator_token_ends_every_session_opened_from_it() {
    let (state, operator_token) = gateway();
    let child = open(&state, &operator_token).await;
    let grandchild = open(&state, &child).await;
    let other = permaura_gateway::mint_console_session(state.service.store().as_ref()).expect("another operator bearer");
    let (status, body) =
        send(&state, &other, "POST", &format!("/v1/sessions/{}/revoke", id_of(&state, &operator_token)), Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!works(&state, &child).await, "a session the revoked token opened stops");
    assert!(!works(&state, &grandchild).await, "and one opened from that");
}

/// The rotation's race: a session opened, or written, after the retirement read the session list still ends when its opener does, because the opener is read at every request rather than walked once.
#[tokio::test]
async fn a_session_ends_when_its_opener_expires_after_it_was_opened() {
    let (state, operator_token) = gateway();
    let child = open(&state, &operator_token).await;
    let store = state.service.store();
    let past = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64 - 1_000;
    assert!(store.expire_session_by(&id_of(&state, &operator_token), past).unwrap());
    assert!(!works(&state, &child).await, "the child does not outlive its opener's expiry");
}

/// A call a child held before its opener was revoked does not run when it is approved: the opener stands behind the call as it stood behind the session.
#[tokio::test]
async fn a_held_call_of_a_session_whose_opener_was_revoked_does_not_run() {
    let (state, operator_token) = gateway();
    let child = open(&state, &operator_token).await;
    let (status, held) = send(
        &state,
        &child,
        "POST",
        "/v1/invoke",
        json!({ "capability": "vercel.deployments.create", "params": { "name": "synthetic", "target": "production" } }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "the deployment is held: {held}");

    let other = seed::DEMO_TOKEN;
    let (status, body) = send(&state, other, "POST", &format!("/v1/sessions/{}/revoke", id_of(&state, &operator_token)), Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, answer) = send(&state, other, "POST", "/v1/approvals", json!({ "approval_id": held["approval_id"], "approve": true })).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["status"], "denied", "the held call does not outlive its session's opener: {answer}");
    assert_eq!(answer["resolution_reason"], "session_ended", "{answer}");
}
