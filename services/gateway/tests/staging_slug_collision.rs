//! An ordinary connection whose derived credential slot starts like the prefix gateway 1.3.46 parked credential
//! changes under.
//!
//! The console names an OpenAPI connection after its host, so `staging.api.example.com` becomes
//! `staging_api_example_com` with the slot `sec_staging_api_example_com`. Staged rows are now minted under
//! `sec:staging:`, a marker no derived slot can hold, and every staging refusal keys on that marker alone, so that
//! connection, and one in the exact shape 1.3.46 minted, is created, its credential rotates, the export carries it
//! and the gateway's own export imports.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::MockHttpClient;
use common::build_router;
use permaura_gateway::AppState;
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const PASSPHRASE: &str = "correct horse battery staple";
const VALUE: &str = "acme_staging_key_271828";

/// What the console's "connect your own API" step names a connection for `https://staging.api.example.com`:
/// `suggestConnectionName` (web `lib/connectors/discovery.ts:122`) gives `staging-api-example-com`, sent as `name`
/// with no `id` (web `components/console/connect-own-step.tsx:503`), and core slugs it with `_`.
const CONSOLE_NAME: &str = "staging-api-example-com";
const CONNECTION: &str = "staging_api_example_com";
const SLOT: &str = "sec_staging_api_example_com";

const STAGING_API: &str = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Acme staging", "version": "1" },
  "servers": [{ "url": "https://staging.api.example.com/v1" }],
  "components": { "securitySchemes": { "key": { "type": "apiKey", "in": "header", "name": "X-Api-Key" } } },
  "security": [{ "key": [] }],
  "paths": { "/orders": { "get": { "operationId": "listOrders" } } }
}"#;

async fn call(state: &AppState, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    call_as(state, OPERATOR_TOKEN, method, uri, body).await
}

async fn call_as(state: &AppState, token: &str, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let req = match body {
        Some(b) => builder.header("content-type", "application/json").body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// The connection the console makes for a staging host, with its credential set, from the gateway's own host.
async fn staging_connection(state: &AppState) {
    named_connection(state, CONSOLE_NAME, CONNECTION, SLOT).await;
}

async fn named_connection(state: &AppState, name: &str, connection: &str, slot: &str) {
    let (status, body) =
        call(state, "POST", "/v1/connections/import-openapi", Some(json!({ "name": name, "spec": STAGING_API }))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["connection_id"], connection, "the console's name slugs to an id whose slot is {slot}");
    let (status, body) =
        call(state, "POST", &format!("/v1/connections/{connection}/credential"), Some(json!({ "value": VALUE }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(state.service.store().get_secret(slot).unwrap().is_some(), "the live credential is stored under {slot}");
}

const OPERATOR_TOKEN: &str = "test-operator-bearer";

/// A fresh gateway with nothing in it but an operator session, as `tests/vault_portability.rs` builds one.
fn empty_gateway() -> AppState {
    use permaura_gateway::store::memory::MemoryStore;
    use permaura_gateway::store::{Session, SessionRole, Store};
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    store
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_operator".into(),
            agent_id: "operator".into(),
            user_id: Some("user_test".into()),
            device_id: None,
            token: OPERATOR_TOKEN.into(),
            role: SessionRole::Operator,
            created_at: 0,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
    AppState::from_parts(store, Arc::new(MockHttpClient::new()))
}

async fn export(state: &AppState) -> (Value, Value) {
    let (status, bundle) = call(state, "POST", "/v1/vault/export", Some(json!({ "passphrase": PASSPHRASE }))).await;
    assert_eq!(status, StatusCode::OK, "{bundle}");
    let parsed: permaura_core::VaultBundle = serde_json::from_value(bundle.clone()).expect("a bundle");
    // This test reads the payload's shape, so it opts a tree in for itself; nothing in the gateway can.
    #[derive(serde::Deserialize)]
    #[serde(transparent)]
    struct Tree(Value);
    impl permaura_core::TypedPayload for Tree {}
    let payload: Tree = permaura_core::open_bundle(&parsed, PASSPHRASE.as_bytes()).expect("opens").payload().expect("a payload");
    (bundle, payload.0)
}

#[tokio::test]
async fn the_console_default_name_for_a_staging_host_keeps_an_ordinary_credential() {
    let state = empty_gateway();
    staging_connection(&state).await;

    // An ordinary live credential: the generic secret routes treat it like any other.
    let (status, body) = call(&state, "POST", &format!("/v1/secrets/{SLOT}/rotate"), Some(json!({ "value": "rotated" }))).await;
    assert_eq!(status, StatusCode::OK, "rotating a connection's own live credential: {body}");

    // And a vault export carries it, or at least names it as missing.
    let ids = permaura_gateway::vault_bundle::enumerate_secret_ids(state.service.store().as_ref()).unwrap();
    let (_bundle, payload) = export(&state).await;
    let exported_connection = payload["connections"].as_array().unwrap().iter().any(|c| c["id"] == CONNECTION);
    let exported_secret = payload["secrets"].as_array().unwrap().iter().any(|s| s["id"] == SLOT);
    assert!(exported_connection, "the connection travels");
    assert!(
        exported_secret && ids.contains(SLOT),
        "the connection's live credential is left out of the bundle and out of the inventory, with nothing said"
    );
}

#[tokio::test]
async fn the_bundle_our_own_export_produced_for_it_imports() {
    let source = empty_gateway();
    staging_connection(&source).await;
    let (bundle, _payload) = export(&source).await;

    let destination = empty_gateway();
    let (status, body) = call_as(
        &destination,
        OPERATOR_TOKEN,
        "POST",
        "/v1/vault/import",
        Some(json!({ "bundle": bundle, "passphrase": PASSPHRASE, "on_conflict": "skip" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the gateway's own export of an ordinary connection imports: {body}");
    assert!(destination.service.store().get_connection(CONNECTION).unwrap().is_some());
}

/// A connection named in the exact shape gateway 1.3.46 gave a parked change (`staging_` and 32 lowercase hex) is ordinary too: nothing reserves it, its credential rotates and travels, and the bundle imports.
#[tokio::test]
async fn a_connection_in_the_shape_1_3_46_parked_changes_under_is_ordinary_too() {
    let hex = "0123456789abcdef0123456789abcdef";
    let (name, connection, slot) = (format!("staging-{hex}"), format!("staging_{hex}"), format!("sec_staging_{hex}"));
    let source = empty_gateway();
    named_connection(&source, &name, &connection, &slot).await;
    let (status, body) = call(&source, "POST", &format!("/v1/secrets/{slot}/rotate"), Some(json!({ "value": "rotated" }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(&source, "POST", &format!("/v1/connections/{connection}/credential"), Some(json!({ "value": VALUE }))).await;
    assert_eq!(status, StatusCode::OK, "setting it again: {body}");
    let (bundle, payload) = export(&source).await;
    assert!(payload["secrets"].as_array().unwrap().iter().any(|s| s["id"] == slot.as_str()), "the credential travels");

    let destination = empty_gateway();
    let (status, body) = call(
        &destination,
        "POST",
        "/v1/vault/import",
        Some(json!({ "bundle": bundle, "passphrase": PASSPHRASE, "on_conflict": "skip" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(destination.service.store().get_connection(&connection).unwrap().is_some());
    assert!(destination.service.store().get_secret(&slot).unwrap().is_some());
}
