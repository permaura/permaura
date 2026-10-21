//! A Permaura-signed manifest that replaced a built-in preset and is later revoked refuses only the connections made from it: one made earlier from the built-in keeps running, and removing the revoked manifest drops the id back to the built-in.
//!
//! Every key, credential and upstream here is synthetic; the root is a throwaway seed, never a pinned one.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::manifest::{revocation_preimage, InstalledManifest, Provenance, Revocation, RevocationList};
use permaura_gateway::service::InvokeOutcome;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, presets, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const KEY: &str = "pmconn-int-test";

fn revoking(key: &str) -> Revocation {
    let root = SigningKey::from_bytes(&[63; 32]);
    let mut list = RevocationList {
        revoked_key_ids: vec![key.to_string()],
        revoked_manifests: Vec::new(),
        issued_at: 1,
        serial: 1,
        root_key_id: "root-test".into(),
        root_sig: String::new(),
    };
    use base64::Engine as _;
    list.root_sig = base64::engine::general_purpose::STANDARD.encode(root.sign(&revocation_preimage(&list)).to_bytes());
    Revocation::verified(&list, &[("root-test".to_string(), root.verifying_key())]).unwrap()
}

async fn send(state: &AppState, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri).header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    let body = match body {
        Some(b) => {
            request = request.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Why a call on `connection` was refused, or `None` when it ran or waits for a human.
async fn refusal(state: &AppState, connection: &str) -> Option<String> {
    let session = state.service.store().get_session("sess_demo").unwrap().unwrap();
    let cap = format!("{connection}.repos.read");
    match state.service.invoke(&session, &cap, &json!({ "owner": "o", "repo": "r" }), Some("synthetic"), ExecutionLocation::LocalOnly).await.unwrap() {
        InvokeOutcome::Denied { decision } => Some(decision.reason),
        _ => None,
    }
}

#[tokio::test]
async fn revoking_a_manifest_that_replaced_a_built_in_spares_what_the_built_in_made() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = MockHttpClient::with_response(HttpResponse::json(200, json!({ "ok": true })));
    let state = AppState::from_parts(store.clone(), Arc::new(http));

    let (status, body) = send(&state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": "github", "name": "built in", "id": "gh_builtin" }))).await;
    assert_eq!(status, StatusCode::CREATED, "made from the built-in preset: {body}");
    store
        .put_connector_manifest(InstalledManifest {
            manifest: presets::catalog().get("github").unwrap().clone(),
            version: 3,
            provenance: Provenance::Signed { key_id: KEY.into() },
            installed_at: 0,
            endpoint_hosts: Vec::new(),
        })
        .unwrap();
    let (status, body) = send(&state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": "github", "name": "signed", "id": "gh_signed" }))).await;
    assert_eq!(status, StatusCode::CREATED, "made from the signed manifest that replaced it: {body}");
    // The demo connection was seeded by hand, so nothing says what it was made from: it is refused, as before.
    assert!(store.delete_connection("github_acme").unwrap());

    let state = state.with_revocation(revoking(KEY));
    let builtin = refusal(&state, "gh_builtin").await;
    assert!(!builtin.as_deref().unwrap_or_default().contains("revoked"), "the built-in's connection is not the revoked manifest's: {builtin:?}");
    let signed = refusal(&state, "gh_signed").await;
    assert!(signed.as_deref().is_some_and(|why| why.contains("revoked")), "the revoked manifest's own connection is refused: {signed:?}");

    let (status, body) = send(&state, "DELETE", "/v1/connectors/github", None).await;
    assert_eq!(status, StatusCode::OK, "removing it falls back to the built-in: {body}");
    let builtin = refusal(&state, "gh_builtin").await;
    assert!(!builtin.as_deref().unwrap_or_default().contains("revoked"), "{builtin:?}");
    let signed = refusal(&state, "gh_signed").await;
    assert!(signed.as_deref().is_some_and(|why| why.contains("revoked")), "and removal does not revive the revoked manifest's copies: {signed:?}");
}

async fn oauth_start(state: &AppState, connection: &str) -> (StatusCode, Value) {
    let body = json!({ "client_id": "synthetic-client", "client_secret": "synthetic-secret", "redirect_uri": "http://127.0.0.1:7376/oauth/callback" });
    send(state, "POST", &format!("/v1/connections/{connection}/oauth/start"), Some(body)).await
}

/// A connection made from the built-in preset keeps the built-in's OAuth endpoints after a manifest naming others is installed over its id and revoked, and one made from that manifest uses none.
#[tokio::test]
async fn a_connection_made_from_the_built_in_keeps_its_oauth_endpoints() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let state = AppState::from_parts(store.clone(), Arc::new(MockHttpClient::new()));
    let (status, body) = send(&state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": "github", "name": "built in", "id": "gh_builtin" }))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let mut replacement = presets::catalog().get("github").unwrap().clone();
    replacement.oauth.as_mut().unwrap().authorize_url = "https://login.replacement.example/authorize".into();
    store
        .put_connector_manifest(InstalledManifest { manifest: replacement, version: 3, provenance: Provenance::Signed { key_id: KEY.into() }, installed_at: 0, endpoint_hosts: Vec::new() })
        .unwrap();
    let (status, body) = send(&state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": "github", "name": "signed", "id": "gh_signed" }))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let state = state.with_revocation(revoking(KEY));

    let (status, body) = oauth_start(&state, "gh_builtin").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["authorize_url"].as_str().unwrap().starts_with("https://github.com/login/oauth/authorize"), "the built-in's endpoint: {body}");
    let (status, body) = oauth_start(&state, "gh_signed").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("revoked"), "{body}");
}
