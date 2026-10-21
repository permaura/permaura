//! What a connection was made from decides what revocation refuses and where its OAuth dance goes: endpoints come only from the catalog entry it was made from, and every creation path records that entry.
//!
//! Every key, credential, host and upstream here is synthetic; the root is a throwaway seed, never a pinned one.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use permaura_core::CatalogOrigin;
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::manifest::{revocation_preimage, InstalledManifest, Provenance, Revocation, RevocationList};
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, presets, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

fn revoking(keys: &[&str]) -> Revocation {
    let root = SigningKey::from_bytes(&[64; 32]);
    let mut list = RevocationList {
        revoked_key_ids: keys.iter().map(|k| k.to_string()).collect(),
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

fn gateway() -> (Arc<dyn Store>, AppState, Arc<MockHttpClient>) {
    common::isolate_from_the_real_install();
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::in_memory_seeded_with_http(http.clone());
    (state.service.store().clone(), state, http)
}

/// `github` at `version` signed with `key` (unsigned when `None`), its OAuth endpoints moved to `host` when one is given, and the install naming that host.
fn install(store: &Arc<dyn Store>, version: u32, key: Option<&str>, host: Option<&str>) {
    let mut manifest = presets::catalog().get("github").unwrap().clone();
    let mut endpoint_hosts = manifest.endpoint_hosts();
    if let Some(host) = host {
        let oauth = manifest.oauth.as_mut().unwrap();
        oauth.authorize_url = format!("https://{host}/authorize");
        oauth.token_url = format!("https://{host}/token");
        endpoint_hosts.push(host.to_string());
    }
    let provenance = match key {
        Some(k) => Provenance::Signed { key_id: k.into() },
        None => Provenance::User,
    };
    store.put_connector_manifest(InstalledManifest { manifest, version, provenance, installed_at: 0, endpoint_hosts }).unwrap();
}

async fn from_preset(state: &AppState, id: &str) {
    let (status, body) = send(state, "POST", "/v1/connections/from-preset", Some(json!({ "preset_id": "github", "name": id, "id": id }))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn oauth_start(state: &AppState, connection: &str) -> (StatusCode, Value) {
    let body = json!({ "client_id": "synthetic-client", "client_secret": "synthetic-secret", "redirect_uri": "http://127.0.0.1:7376/oauth/callback" });
    send(state, "POST", &format!("/v1/connections/{connection}/oauth/start"), Some(body)).await
}

/// A connection made from v4 is never sent through the endpoints of a v5 installed over it since, revoked or not, signed v4 or unsigned.
#[tokio::test]
async fn oauth_endpoints_come_only_from_the_entry_a_connection_was_made_from() {
    for (arm, v4_key, revoked) in [
        ("signed v4, v5's key revoked", Some("int-b"), vec!["int-c"]),
        ("unsigned v4, v5's key revoked", None, vec!["int-c"]),
        ("signed v4, nothing revoked", Some("int-b"), vec![]),
    ] {
        let (store, state, _) = gateway();
        install(&store, 4, v4_key, None);
        from_preset(&state, "gh_v4").await;
        install(&store, 5, Some("int-c"), Some("login.replacement.example"));
        let state = state.with_revocation(revoking(&revoked));
        let (status, body) = oauth_start(&state, "gh_v4").await;
        assert_eq!(status, StatusCode::CONFLICT, "{arm}: {body}");
        assert!(!body.to_string().contains("login.replacement.example/authorize"), "{arm}: {body}");
    }

    let (store, state, _) = gateway();
    install(&store, 5, Some("int-c"), Some("login.replacement.example"));
    from_preset(&state, "gh_v5").await;
    let (status, body) = oauth_start(&state, "gh_v5").await;
    assert_eq!(status, StatusCode::OK, "a connection made from the installed version takes its endpoints: {body}");
    assert!(body["authorize_url"].as_str().unwrap().starts_with("https://login.replacement.example/authorize"), "{body}");
    let state = state.with_revocation(revoking(&["int-c"]));
    assert_eq!(oauth_start(&state, "gh_v5").await.0, StatusCode::CONFLICT, "and none once that version is revoked");
}

/// A connection built from the gateway's own code, or discovered from the operator's own source, records that, so revoking a manifest later installed under its connector id refuses none of them and does not hold the manifest's removal.
#[tokio::test]
async fn every_creation_path_records_its_origin() {
    const FORUM: &str = include_str!("fixtures/wordpress/forum-index.json");
    let (store, state, http) = gateway();
    assert!(store.delete_connection("github_acme").unwrap(), "the seeded connection records no origin");
    let (status, body) = send(&state, "POST", "/v1/connections", Some(json!({ "connector": "github", "name": "Built", "id": "gh_family" }))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let spec = json!({
        "openapi": "3.0.3",
        "info": { "title": "Items", "version": "1" },
        "servers": [{ "url": "https://api.example.com/v1" }],
        "paths": { "/items": { "get": { "operationId": "getItems", "summary": "List items" } } },
    });
    let (status, body) = send(&state, "POST", "/v1/connections/import-openapi", Some(json!({ "name": "items", "id": "items", "spec": spec.to_string() }))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    http.push_response(HttpResponse::json(200, serde_json::from_str(FORUM).unwrap()));
    let (status, body) = send(
        &state,
        "POST",
        "/v1/connections/import-wordpress",
        Some(json!({
            "name": "Support",
            "url": "https://eventsmanagerpro.com/support",
            "namespaces": ["bbpress/v1"],
            "digest": permaura_gateway::wordpress::digest(&serde_json::from_str(FORUM).unwrap(), Some(&["bbpress/v1".to_string()])),
        })),
    )
    .await;
    assert!(status.is_success(), "{body}");

    let made = |id: &str| store.get_connection(id).unwrap().unwrap();
    assert_eq!(made("gh_family").made_from, Some(CatalogOrigin::BuiltIn), "built from the gateway's own code");
    for id in ["items", "wordpress_support"] {
        assert!(made(id).made_from.is_some(), "{id} records what it was made from");
    }

    install(&store, 3, Some("int-x"), None);
    let state = state.with_revocation(revoking(&["int-x"]));
    for id in ["gh_family", "items", "wordpress_support"] {
        assert_eq!(state.service.connection_revocation(&made(id)).unwrap(), None, "{id} is not the revoked manifest's");
    }
    let (status, body) = send(&state, "DELETE", "/v1/connectors/github", None).await;
    assert_eq!(status, StatusCode::OK, "nothing under the id waits on the revoked manifest: {body}");
}
