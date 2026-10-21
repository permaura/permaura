//! A key provisioned through `PERMAURA_APPROVER_KEYS` stays revoked once an operator revokes it: through the store refresh, through a restart, until the variable names a different key. The keys are generated here.
//!
//! One test in this binary on purpose: the variable is process-wide and this test changes it.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::{build_router, seed};
use tower::ServiceExt;

const PHONE: &str = "device:env-phone";
const WATCH: &str = "device:env-watch";

fn pubkey(seed: u8) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.to_bytes())
}

fn provision(phone: u8, watch: u8) {
    std::env::set_var("PERMAURA_APPROVER_KEYS", format!("{PHONE}|{},{WATCH}|{}", pubkey(phone), pubkey(watch)));
}

#[tokio::test]
async fn a_revoked_environment_key_stays_revoked_until_the_variable_changes() {
    common::isolate_from_the_real_install();
    provision(71, 72);
    let state = common::seeded();
    assert_eq!(state.service.trusted_approver_key(PHONE), Some(pubkey(71)), "the variable provisions the key");

    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/approver-keys/{PHONE}"))
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK, "another key remains, so the revocation applies: {body}");
    assert_eq!(body["trusted"], false);

    state.service.refresh_keyring_now();
    assert_eq!(state.service.trusted_approver_key(PHONE), None, "the refresh read the variable and trusted the key again");
    assert_eq!(state.service.trusted_approver_key(WATCH), Some(pubkey(72)), "the other provisioned key is untouched");

    let store = state.service.store().clone();
    let restarted = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()));
    assert_eq!(restarted.trusted_approver_key(PHONE), None, "a restart trusted the key again");

    assert_eq!(body["source"], "environment", "the revoke says where the key came from: {body}");
    assert!(body["note"].as_str().is_some_and(|n| n.contains("PERMAURA_APPROVER_KEYS")), "{body}");

    provision(73, 72);
    let rotated = EnforcementService::new(store, Arc::new(MockHttpClient::new()));
    assert_eq!(rotated.trusted_approver_key(PHONE), Some(pubkey(73)), "a different key under the same id is trusted");
    assert_eq!(rotated.trusted_approver_key(WATCH), Some(pubkey(72)));
}
