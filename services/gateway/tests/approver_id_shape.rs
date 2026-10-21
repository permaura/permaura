//! A pairing may only create an approver id permaura.com can address as one URL path segment, so every key it trusts can be revoked from the console.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use permaura_gateway::{build_router, seed};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

async fn pair(app: &axum::Router, approver_id: &str, seed_byte: u8) -> (StatusCode, Value) {
    let sk = SigningKey::from_bytes(&[seed_byte; 32]);
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = permaura_gateway::service::now_ms();
    let preimage = permaura_relay::approver_pairing_preimage(approver_id, &pubkey, issued_at);
    let body = json!({
        "approver_id": approver_id, "approver_pubkey": pubkey, "issued_at": issued_at,
        "sig": permaura_relay::sign(&sk, &preimage),
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
async fn a_pairing_under_an_id_the_console_cannot_address_is_refused() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let long = "d".repeat(129);
    for (i, bad) in ["device:a/b", "..", ".", "device:a\\b", "device:\u{1b}[2J", long.as_str()].into_iter().enumerate() {
        let (status, body) = pair(&app, bad, 40 + i as u8).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}: {body}");
        assert!(state.service.approver_keyring_snapshot().trusted_key(bad).is_none(), "{bad:?} was trusted");
    }
    let (status, body) = pair(&app, "device:3f9a0c1b2d4e", 60).await;
    assert_eq!(status, StatusCode::OK, "an ordinary id still pairs: {body}");
}

async fn revoke(app: &axum::Router, uri: &str) -> StatusCode {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

/// `pair`, `enroll` and `push-token` are static routes beside the two revoke routes that take an approver id, so a key under one of them could be paired and never revoked; each is refused, and an id beside them still pairs and revokes by both routes.
#[tokio::test]
async fn a_pairing_under_a_static_sibling_of_a_revoke_route_is_refused() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    for (i, reserved) in ["pair", "enroll", "push-token"].into_iter().enumerate() {
        let (status, body) = pair(&app, reserved, 70 + i as u8).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{reserved}: {body}");
        assert!(state.service.approver_keyring_snapshot().trusted_key(reserved).is_none(), "{reserved} was trusted");
    }
    // The static route answers a DELETE meant for a key under its name.
    assert_eq!(revoke(&app, "/v1/approver-keys/pair").await, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(revoke(&app, "/v1/devices/enroll").await, StatusCode::METHOD_NOT_ALLOWED);
    let (status, body) = pair(&app, "pairing", 80).await;
    assert_eq!(status, StatusCode::OK, "an id beside a static segment pairs: {body}");
    let trust = |id: &str, seed_byte: u8| {
        let pubkey = STANDARD.encode(SigningKey::from_bytes(&[seed_byte; 32]).verifying_key().to_bytes());
        assert!(state.service.trust_approver_key_for(id, &pubkey, None).unwrap(), "{id}");
    };
    // Kept trusted throughout, so neither revoke below would empty the keyring.
    trust("device:anchor", 79);
    trust("enrolled", 81);
    assert!(revoke(&app, "/v1/approver-keys/pairing").await.is_success());
    assert!(state.service.approver_keyring_snapshot().trusted_key("pairing").is_none(), "revoked by its approver-keys route");
    assert!(revoke(&app, "/v1/devices/enrolled").await.is_success());
    assert!(state.service.approver_keyring_snapshot().trusted_key("enrolled").is_none(), "revoked by its devices route");
}
