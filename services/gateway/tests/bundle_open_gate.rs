//! One bundle key derivation at a time. Each open costs 256 MiB of Argon2 memory and a hosted worker
//! has 512 MiB, so two at once, on top of the process itself, can end the worker and every call in
//! flight on it. A preview needs no approval, which makes it the cheap way to ask for one.
//!
//! Its own test binary, because the gate is process-wide and the other vault tests open bundles too.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

const PASSPHRASE: &str = "correct horse battery staple";

async fn preview(state: AppState, bundle: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let token = common::operator_token(state.clone()).await;
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    let body = serde_json::json!({ "bundle": bundle, "passphrase": PASSPHRASE });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/vault/import/preview")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

fn small_bundle() -> serde_json::Value {
    serde_json::to_value(
        permaura_core::seal_bundle(
            PASSPHRASE.as_bytes(),
            serde_json::json!({ "connections": [], "policies": [], "grants": [], "capabilities": [], "secrets": [] }),
            1_754_500_000_000,
            permaura_core::BundleSource::default(),
        )
        .unwrap(),
    )
    .unwrap()
}

/// Before the gate, three concurrent previews derived at once, which is 768 MiB on a 512 MiB worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_open_waits_while_another_derivation_runs() {
    let state = common::seeded();
    let bundle = small_bundle();
    let running = permaura_gateway::vault_bundle::BUNDLE_KDF.acquire().await.unwrap();
    let call = tokio::spawn(preview(state.clone(), bundle));
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    assert!(!call.is_finished(), "the open must wait for the derivation already running");
    drop(running);
    let (status, body) = call.await.unwrap();
    assert_eq!(status, StatusCode::OK, "and run once it is done: {body}");
}
