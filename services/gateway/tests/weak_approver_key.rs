//! A small-order key cannot be paired, so no one gets the key under which one fixed 64-byte value verifies as every approval.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use permaura_gateway::{build_router, seed};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

/// The identity point, and the 64 bytes `R = identity, s = 0` that a non-strict verify accepts under it for any message.
fn identity_forgery() -> (String, String) {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut forged = [0u8; 64];
    forged[0] = 1;
    (STANDARD.encode(identity), STANDARD.encode(forged))
}

async fn pair(app: &axum::Router, approver_id: &str, pubkey: &str, sig: &str) -> (StatusCode, Value) {
    let body = json!({
        "approver_id": approver_id, "approver_pubkey": pubkey,
        "issued_at": permaura_gateway::service::now_ms(), "sig": sig,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/approver-keys/pair")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_small_order_key_is_never_paired_or_trusted() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (weak, forged) = identity_forgery();

    let (status, body) = pair(&app, "device:weak", &weak, &forged).await;
    assert!(status.is_client_error(), "the forged possession proof must be refused, got {status}: {body}");
    assert!(state.service.approver_keyring_snapshot().trusted_key("device:weak").is_none());

    let noncanonical_identity = STANDARD.encode({
        let mut y = [0xffu8; 32];
        y[0] = 0xee;
        y[31] = 0x7f;
        y
    });
    let (status, body) = pair(&app, "device:respelled", &noncanonical_identity, &forged).await;
    assert!(status.is_client_error(), "nor under a second spelling of the same point, got {status}: {body}");

    assert!(
        !state.service.trust_approver_key_for("device:direct", &weak, None).unwrap_or(false),
        "and the keyring will not hold one however it is offered"
    );
    assert!(state.service.approver_keyring_snapshot().trusted_key("device:direct").is_none());
}
