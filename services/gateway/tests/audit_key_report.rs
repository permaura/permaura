//! The audit chain's public key on every authenticated surface a control plane reads.
//!
//! A store writer can re-sign a rewritten history under a key of their own, and every check inside the
//! gateway then passes, because every check uses the store's key. The control plane pins the key it
//! first saw this gateway report and compares each later report against that pin, so what matters here
//! is that the report is always the key the store actually signs with: after the key in the store is
//! replaced, the gateway reports the replacement, and the pin holder sees a different key.
#![cfg(feature = "sqlite")]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, AppState};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

async fn get(state: AppState, path: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().uri(path);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

/// What the report must say for `key`, computed here independently of the gateway's own helper.
fn expected(key: &[u8; 32]) -> (String, String) {
    let b64 = base64::engine::general_purpose::STANDARD.encode(key);
    let fp: String = Sha256::digest(key).iter().map(|b| format!("{b:02x}")).collect();
    (b64, fp)
}

fn assert_reports(body: &serde_json::Value, key: &[u8; 32], surface: &str) {
    let (b64, fp) = expected(key);
    let reported = &body["audit_key"];
    assert_eq!(reported["algorithm"], "ed25519", "{surface}: {body}");
    assert_eq!(reported["public_key"], b64.as_str(), "{surface} must report the key the store signs with");
    assert_eq!(reported["fingerprint"], fp.as_str(), "{surface} must report the full SHA-256 of that key");
}

#[tokio::test]
async fn every_authenticated_surface_reports_the_key_the_chain_is_signed_with() {
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    let key = state.service.store().audit_verifying_key().unwrap();

    for path in ["/health", "/v1/broker", "/v1/audit-events?limit=5"] {
        let (status, body) = get(state.clone(), path, Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_reports(&body, &key, path);
    }
}

#[tokio::test]
async fn a_stranger_is_not_told_the_key() {
    let state = common::seeded();
    let (status, body) = get(state, "/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("audit_key").is_none(), "unauthenticated /health stays two fields: {body}");
}

fn state_over(store: std::sync::Arc<dyn Store>) -> AppState {
    let http = std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    AppState::new(permaura_gateway::service::EnforcementService::new(store, http))
}

/// The key substitution, on the hosted store layout (key in `gateway_meta`): something with write access to
/// the store and none to its custody replaces the signing key. The gateway has nothing to compare
/// against and opens it, so the report is the only place the substitution can show, and it must show
/// the NEW key rather than one remembered from before.
#[tokio::test]
async fn a_replaced_store_key_is_the_key_reported() {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!("permaura-audit-key-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db");
    let _ = std::fs::remove_file(&path);
    let path = path.to_string_lossy().to_string();

    let original = {
        let store = SqliteStore::open_with_custody(&path, None).expect("a fresh hosted-shape store opens");
        store.audit_verifying_key().unwrap()
    };

    let forged_seed = [0x42u8; 32];
    let forged = ed25519_dalek::SigningKey::from_bytes(&forged_seed).verifying_key().to_bytes();
    assert_ne!(original, forged);
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let replaced = conn
            .execute(
                "UPDATE gateway_meta SET value = ?1 WHERE key = 'audit_signing_key'",
                [base64::engine::general_purpose::STANDARD.encode(forged_seed)],
            )
            .unwrap();
        assert_eq!(replaced, 1, "the fixture has to have replaced the key row it means to");
    }

    let store: std::sync::Arc<dyn Store> =
        std::sync::Arc::new(SqliteStore::open_with_custody(&path, None).expect("the rewritten store still opens"));
    let state = state_over(store);
    let token = common::operator_token(state.clone()).await;
    for path in ["/health", "/v1/broker", "/v1/audit-events"] {
        let (status, body) = get(state.clone(), path, Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_reports(&body, &forged, path);
        let (_, original_fp) = expected(&original);
        assert_ne!(body["audit_key"]["fingerprint"], original_fp.as_str(), "{path}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
