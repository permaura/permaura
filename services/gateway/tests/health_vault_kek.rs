//! `vault_kek` must report `real` when a real passphrase was injected.
//!
//! This is the case where a live hosted worker sealed customer secrets under the passphrase printed
//! in `service.rs`. The crypto was right and the key was wrong, and no protocol test can see that:
//! only an assertion about the running process's boot state can.
//!
//! Its own test binary on purpose. The KEK resolves once per process into a `OnceLock`, so a test
//! that sets the environment has to be the only thing in the binary that can reach it; sharing a
//! binary with the other health tests would make the answer depend on which thread got there first.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn an_injected_passphrase_reports_real() {
    // Set before any state is built: building it resolves the KEK. A file, because the inline
    // variable is no longer a hand-over route at all.
    let kek = std::env::temp_dir().join("permaura-health-vault-kek");
    std::fs::write(&kek, "a-real-per-install-secret").expect("write the KEK file");
    std::env::set_var("PERMAURA_VAULT_PASSPHRASE_FILE", &kek);

    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["vault_kek"], "real");
    // And it never echoes the passphrase itself.
    let doc = serde_json::to_string(&json).unwrap();
    assert!(!doc.contains("a-real-per-install-secret"), "leaked the KEK: {doc}");
}
