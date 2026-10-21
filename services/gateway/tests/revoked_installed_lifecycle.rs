//! A Permaura-signed connector installed before the gateway booted, checked against the revocation list it booted under: a revoked one runs nothing, makes no new connection, is marked in the listings, and cannot be removed while connections made from it would run again without it.
//!
//! Every key, credential and upstream here is synthetic; the root is a throwaway seed, never a pinned one.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::manifest::{
    revocation_preimage, InstalledManifest, Provenance, Revocation, RevocationList, RevokedManifest,
};
use permaura_gateway::service::InvokeOutcome;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, presets, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const KEY: &str = "pmconn-int-test";

fn root() -> SigningKey {
    SigningKey::from_bytes(&[61; 32])
}

/// A list signed by the throwaway root, verified the way the gateway verifies one at boot.
fn revocation(keys: &[&str], manifests: &[(&str, u32)]) -> Revocation {
    let mut list = RevocationList {
        revoked_key_ids: keys.iter().map(|k| k.to_string()).collect(),
        revoked_manifests: manifests.iter().map(|(id, v)| RevokedManifest { id: id.to_string(), up_to_version: *v }).collect(),
        issued_at: 1,
        serial: 1,
        root_key_id: "root-test".into(),
        root_sig: String::new(),
    };
    use base64::Engine as _;
    list.root_sig = base64::engine::general_purpose::STANDARD.encode(root().sign(&revocation_preimage(&list)).to_bytes());
    Revocation::verified(&list, &[("root-test".to_string(), root().verifying_key())]).expect("the throwaway root signed it")
}

/// The demo estate, with a Permaura-signed `github` manifest at version 3 installed over the bundled preset its `github_acme` connection was made from.
fn estate(revoked: Revocation) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    store
        .put_connector_manifest(InstalledManifest {
            manifest: presets::catalog().get("github").unwrap().clone(),
            version: 3,
            provenance: Provenance::Signed { key_id: KEY.into() },
            installed_at: 0,
            endpoint_hosts: Vec::new(),
        })
        .unwrap();
    let http = MockHttpClient::with_response(HttpResponse::json(200, json!({ "ok": true })));
    AppState::from_parts(store, Arc::new(http)).with_revocation(revoked)
}

async fn list_pull_requests(state: &AppState) -> InvokeOutcome {
    let session = state.service.store().get_session("sess_demo").unwrap().unwrap();
    state
        .service
        .invoke(&session, "github.pull_requests.list", &json!({ "owner": "o", "repo": "r" }), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap()
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

#[tokio::test]
async fn a_revoked_key_or_version_stops_every_call_on_connections_made_from_it() {
    for (arm, revoked) in [("its key", revocation(&[KEY], &[])), ("its version", revocation(&[], &[("github", 3)]))] {
        let InvokeOutcome::Denied { decision } = list_pull_requests(&estate(revoked)).await else {
            panic!("{arm}: an installed connector the list revokes must not run")
        };
        assert!(decision.reason.contains("revoked") && decision.reason.contains("github"), "{arm}: {}", decision.reason);
    }
    for (arm, unrelated) in [
        ("nothing", Revocation::empty()),
        ("another key", revocation(&["pmconn-int-other"], &[])),
        ("an older version only", revocation(&[], &[("github", 2)])),
    ] {
        assert!(matches!(list_pull_requests(&estate(unrelated)).await, InvokeOutcome::Allowed { .. }), "{arm} revokes nothing installed here");
    }
}

#[tokio::test]
async fn a_held_call_approved_after_a_restart_under_a_list_that_revokes_its_connector_is_denied() {
    let state = estate(Revocation::empty());
    let session = state.service.store().get_session("sess_demo").unwrap().unwrap();
    let held = state
        .service
        .invoke(&session, "github.pull_requests.create", &json!({ "owner": "o", "repo": "r", "title": "t", "head": "h", "base": "b" }), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::RequiresApproval { approval, .. } = held else { panic!("a high-risk call is held") };
    let state = state.with_revocation(revocation(&[KEY], &[]));
    let resolved = state.service.resolve_approval(&approval.id, true, "bearer", Some("operator")).await.unwrap();
    assert_ne!(resolved.status, "approved", "the re-check at approval refuses a revoked connector");
}

#[tokio::test]
async fn no_connection_is_made_from_a_revoked_connector_and_the_listings_say_so() {
    let state = estate(revocation(&[KEY], &[]));
    let (status, body) = send(&state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": "github", "name": "another" }))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (_, installed) = send(&state, "GET", "/v1/connectors/installed", None).await;
    let github = installed["connectors"].as_array().unwrap().iter().find(|c| c["id"] == "github").unwrap();
    assert!(github["revoked"].as_str().is_some_and(|why| why.contains(KEY)), "{github}");
    let (_, presets) = send(&state, "GET", "/v1/presets", None).await;
    let github = presets["presets"].as_array().unwrap().iter().find(|p| p["id"] == "github").unwrap();
    assert!(github["revoked"].is_string(), "{github}");

    let clean = estate(Revocation::empty());
    let (_, installed) = send(&clean, "GET", "/v1/connectors/installed", None).await;
    assert!(installed["connectors"][0]["revoked"].is_null(), "{installed}");
}

#[tokio::test]
async fn a_revoked_connector_is_not_removed_while_connections_made_from_it_would_run_again() {
    let state = estate(revocation(&[KEY], &[]));
    let (status, body) = send(&state, "DELETE", "/v1/connectors/github", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("github_acme"), "the refusal names the connection to remove first: {body}");
    assert!(state.service.store().get_connector_manifest("github").unwrap().is_some());

    let (status, body) = send(&state, "DELETE", "/v1/connections/github_acme", None).await;
    assert!(status.is_success(), "{body}");
    let (status, body) = send(&state, "DELETE", "/v1/connectors/github", None).await;
    assert_eq!(status, StatusCode::OK, "with nothing made from it left, it can go: {body}");
}
