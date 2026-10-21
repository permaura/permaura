//! `POST /v1/connections/import-openapi` end to end through the real router, with a mock upstream: the
//! fetch and probe stay on the bound host, the servers a document names are held to it, a dry run
//! persists nothing, and a created connection records its source with its writes disabled.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{AuthScheme, HttpResponse, MockHttpClient};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

fn rig() -> (Arc<MockHttpClient>, AppState) {
    common::isolate_from_the_real_install();
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::in_memory_seeded_with_http(http.clone());
    (http, state)
}

async fn import(state: &AppState, body: Value) -> (StatusCode, Value) {
    post(state, "/v1/connections/import-openapi", body).await
}

async fn post(state: &AppState, uri: &str, body: Value) -> (StatusCode, Value) {
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn not_found() -> HttpResponse {
    HttpResponse { status: 404, text: Some("not found".into()), ..HttpResponse::default() }
}

fn document(text: &str) -> HttpResponse {
    HttpResponse { status: 200, text: Some(text.into()), ..HttpResponse::default() }
}

fn requested(http: &MockHttpClient) -> Vec<String> {
    http.requests().iter().map(|r| r.url.clone()).collect()
}

const PETS: &str = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Pets", "version": "1" },
  "servers": [{ "url": "https://api.example.com/v1" }],
  "components": { "securitySchemes": { "key": { "type": "apiKey", "in": "header", "name": "X-Pets-Key" } } },
  "security": [{ "key": [] }],
  "paths": {
    "/pets": {
      "get": { "operationId": "listPets", "parameters": [{ "name": "X-Request-Id", "in": "header" }] },
      "post": { "operationId": "createPet", "requestBody": { "content": { "application/json": { "schema": { "properties": { "name": {} } } } } } }
    }
  }
}"#;

#[tokio::test]
async fn probing_finds_the_document_on_the_bound_host_and_nowhere_else() {
    let (http, state) = rig();
    for _ in 0..5 {
        http.push_response(not_found());
    }
    http.push_response(document(PETS));

    let (status, body) = import(&state, json!({ "name": "Pets", "url": "https://api.example.com/v1", "dry_run": true })).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let expected: Vec<String> = [
        "/v1/openapi.json",
        "/v1/openapi.yaml",
        "/v1/swagger.json",
        "/v1/v3/api-docs",
        "/v1/.well-known/openapi.json",
        "/openapi.json",
    ]
    .iter()
    .map(|p| format!("https://api.example.com{p}"))
    .collect();
    assert_eq!(requested(&http), expected, "under the bound path first, then the origin root, in order");
    assert!(http.requests().iter().all(|r| r.host().as_deref() == Some("api.example.com")));

    assert_eq!(body["spec_url"], "https://api.example.com/openapi.json");
    assert_eq!(body["base_url"], "https://api.example.com/v1");
    assert_eq!(body["auth"], json!({ "scheme": "api_key_header", "header": "X-Pets-Key" }));
    assert_eq!(body["digest"].as_str().map(str::len), Some(64));
    let caps = body["capabilities"].as_array().unwrap();
    let create = caps.iter().find(|c| c["id"] == "pets.createPet").expect("createPet previewed");
    assert_eq!(create["method"], "POST");
    assert_eq!(create["path"], "/pets");
    assert_eq!(create["disabled"], true, "a write lands disabled");
    let list = caps.iter().find(|c| c["id"] == "pets.listPets").unwrap();
    assert_eq!(list["disabled"], false);
    assert!(body.get("connection_id").is_none());
    assert!(state.service.store().get_connection("pets").unwrap().is_none(), "a dry run persists nothing");
}

#[tokio::test]
async fn a_spec_url_on_another_host_is_refused_without_a_request() {
    let (http, state) = rig();
    let (status, body) = import(
        &state,
        json!({ "name": "Pets", "url": "https://api.example.com", "spec_url": "https://evil.example.net/openapi.json", "dry_run": true }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("not the bound host"), "{body}");
    assert!(http.requests().is_empty());
}

#[tokio::test]
async fn a_server_on_another_host_is_never_pinned() {
    let (http, state) = rig();
    http.push_response(document(&PETS.replace("https://api.example.com/v1", "https://api.attacker.net/v1")));
    let (status, body) =
        import(&state, json!({ "name": "Pets", "spec_url": "https://api.example.com/openapi.json", "dry_run": true })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("not the bound host api.example.com"), "{body}");
    assert_eq!(requested(&http), vec!["https://api.example.com/openapi.json"]);
}

#[tokio::test]
async fn a_yaml_document_fetched_by_url_is_imported_with_its_source() {
    let (http, state) = rig();
    let yaml = "openapi: 3.0.3
info: { title: Pets, version: '1' }
servers:
  - url: /api
components:
  securitySchemes:
    basic: { type: http, scheme: basic }
paths:
  /pets/{id}:
    parameters:
      - { name: id, in: path, required: true }
    get:
      operationId: getPet
      responses:
        200: { description: ok }
    delete:
      operationId: deletePet
      responses:
        204: { description: gone }
";
    http.push_response(document(yaml));
    let (status, body) = import(
        &state,
        json!({ "name": "Pet Store", "id": "petstore", "url": "https://www.example.com", "spec_url": "https://example.com/specs/openapi.yaml",
                "digest": permaura_gateway::openapi::digest(yaml.as_bytes()) }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["connection_id"], "petstore");
    assert_eq!(body["base_url"], "https://example.com/api", "the relative server resolves against the spec URL");
    assert_eq!(body["auth"], json!({ "scheme": "basic", "key_as_username": false }));
    assert_eq!(body["digest"], permaura_gateway::openapi::digest(yaml.as_bytes()));

    let store = state.service.store();
    let conn = store.get_connection("petstore").unwrap().expect("created");
    assert_eq!(conn.connector, "openapi");
    assert_eq!(conn.disabled_capabilities, vec!["petstore.deletePet".to_string()]);
    let source = conn.source.expect("the source is recorded for a later re-sync");
    assert_eq!(source.kind, permaura_core::SourceKind::Openapi);
    assert_eq!(source.url, "https://example.com/specs/openapi.yaml");
    assert_eq!(source.digest.as_deref(), body["digest"].as_str());
    assert!(source.synced_at > 0);

    let get = store.get_capability("petstore.getPet").unwrap().expect("stored");
    let spec = get.http.expect("an http capability");
    assert_eq!(spec.base_url, "https://example.com/api");
    assert_eq!(spec.path_params, vec!["id".to_string()], "the path-level parameter reaches the operation");
    assert_eq!(spec.auth, AuthScheme::Basic { key_as_username: false });
}

fn two_servers() -> String {
    PETS.replace(
        r#""servers": [{ "url": "https://api.example.com/v1" }]"#,
        r#""servers": [{ "url": "https://sandbox.example.com/v1" }, { "url": "https://api.example.com/v1" }]"#,
    )
}

#[tokio::test]
async fn several_servers_are_offered_on_a_dry_run_and_refused_on_a_create() {
    let (_http, state) = rig();
    let spec = two_servers();

    let (status, body) = import(&state, json!({ "name": "Pets", "spec": spec, "dry_run": true })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["base_url"], Value::Null);
    assert_eq!(body["servers"], json!(["https://sandbox.example.com/v1", "https://api.example.com/v1"]));
    assert_eq!(body["spec_url"], Value::Null, "a pasted document has no URL");
    assert!(body["capabilities"].as_array().is_some_and(|c| c.len() == 2), "still previewed: {body}");

    let (status, body) = import(&state, json!({ "name": "Pets", "spec": spec })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["servers"], json!(["https://sandbox.example.com/v1", "https://api.example.com/v1"]));
    assert!(body["error"].as_str().unwrap().contains("base_url"), "{body}");
    assert!(state.service.store().get_connection("pets").unwrap().is_none());

    let (status, body) =
        import(&state, json!({ "name": "Pets", "spec": spec, "base_url": "https://api.example.com/v1" })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let cap = state.service.store().get_capability("pets.listPets").unwrap().unwrap();
    let spec = cap.http.unwrap();
    assert_eq!(spec.base_url, "https://api.example.com/v1");
    assert_eq!(spec.header_params, vec!["X-Request-Id".to_string()]);
    let source = state.service.store().get_connection("pets").unwrap().unwrap().source.unwrap();
    assert_eq!(source.url, "", "a pasted document records no URL");
}

#[tokio::test]
async fn the_operators_auth_override_is_pinned_and_reported() {
    let (_http, state) = rig();
    let (status, body) = import(
        &state,
        json!({ "name": "Pets", "spec": PETS, "auth": { "scheme": "api_key_query", "param": "key" } }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["auth"], json!({ "scheme": "api_key_query", "param": "key" }));
    let cap = state.service.store().get_capability("pets.createPet").unwrap().unwrap();
    assert_eq!(cap.http.unwrap().auth, AuthScheme::ApiKeyQuery { param: "key".into() });
}

#[tokio::test]
async fn a_changed_document_is_refused_against_the_reviewed_digest() {
    let (_http, state) = rig();
    let (status, body) =
        import(&state, json!({ "name": "Pets", "spec": PETS, "digest": "0".repeat(64) })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["digest"], permaura_gateway::openapi::digest(PETS.as_bytes()));
    assert!(state.service.store().get_connection("pets").unwrap().is_none());

    let reviewed = permaura_gateway::openapi::digest(PETS.as_bytes());
    let (status, _) = import(&state, json!({ "name": "Pets", "spec": PETS, "digest": reviewed })).await;
    assert_eq!(status, StatusCode::CREATED);
}

/// A document read from the bound host can change between the dry run and the create, so a create from a URL is stored only against the digest the operator reviewed; a pasted document is the document itself.
#[tokio::test]
async fn a_fetched_document_is_created_only_against_the_digest_reviewed() {
    let (http, state) = rig();
    http.push_response(document(PETS));
    let (status, body) =
        import(&state, json!({ "name": "Pets", "url": "https://api.example.com/v1", "spec_url": "https://api.example.com/openapi.json" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("digest"), "{body}");
    assert!(state.service.store().get_connection("pets").unwrap().is_none(), "nothing nobody reviewed is stored");

    http.push_response(document(PETS));
    let reviewed = permaura_gateway::openapi::digest(PETS.as_bytes());
    let (status, body) = import(
        &state,
        json!({ "name": "Pets", "url": "https://api.example.com/v1", "spec_url": "https://api.example.com/openapi.json", "digest": reviewed }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn the_request_must_name_exactly_one_source() {
    let (http, state) = rig();
    let (status, body) = import(&state, json!({ "name": "Pets", "spec": PETS, "url": "https://api.example.com" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("not both"), "{body}");
    let (status, _) = import(&state, json!({ "name": "Pets" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = import(&state, json!({ "name": "Pets", "id": "bad.id", "spec": PETS })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("id 'bad.id'"), "{body}");
    assert!(http.requests().is_empty());
}

#[tokio::test]
async fn nothing_found_says_where_it_looked() {
    let (http, state) = rig();
    for _ in 0..5 {
        http.push_response(not_found());
    }
    let (status, body) = import(&state, json!({ "name": "Pets", "url": "https://api.example.com", "dry_run": true })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error = body["error"].as_str().unwrap();
    assert!(error.contains("no OpenAPI 3 document found on api.example.com"), "{error}");
    assert!(error.contains("https://api.example.com/.well-known/openapi.json (404)"), "{error}");
    assert_eq!(http.requests().len(), 5);
}

/// An ElevenLabs-shaped API: the key goes up as an `xi-api-key` header and `/user` hands it back.
const VOICES: &str = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Voices", "version": "1" },
  "servers": [{ "url": "https://api.voices.example/v1" }],
  "components": { "securitySchemes": { "key": { "type": "apiKey", "in": "header", "name": "xi-api-key" } } },
  "security": [{ "key": [] }],
  "paths": { "/user": { "get": { "operationId": "getUser" } } }
}"#;

/// Import `spec` as `id`, seal `credential` on it, let the demo agent read `getUser`, and return what
/// that read hands the agent when the upstream answers with `answer`.
async fn read_through_an_import(spec: &str, id: &str, credential: &str, answer: Value) -> Value {
    let (http, state) = rig();
    let (status, body) = import(&state, json!({ "name": id, "id": id, "spec": spec })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = post(&state, &format!("/v1/connections/{id}/credential"), json!({ "value": credential })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post(
        &state,
        "/v1/policies",
        json!({ "id": format!("pol_{id}"), "connection_id": id, "name": "Read", "allow": ["getUser"] }),
    )
    .await;
    assert!(status.is_success(), "{body}");
    let (status, body) = post(
        &state,
        "/v1/grants",
        json!({ "grant_id": format!("gr_{id}"), "name": "Read", "policy_ids": [format!("pol_{id}")], "agents": ["codex-cli"] }),
    )
    .await;
    assert!(status.is_success(), "{body}");

    http.push_response(HttpResponse::json(200, answer));
    let (status, body) = post(&state, "/v1/invoke", json!({ "capability": format!("{id}.getUser"), "params": {} })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["result"].clone()
}

#[tokio::test]
async fn the_imported_key_header_is_redacted_by_name_in_both_spellings() {
    // A credential too short to scrub by value, and a different key under the hyphenated name: only the
    // name can catch either.
    let result = read_through_an_import(
        VOICES,
        "voices",
        "k7Qz2",
        json!({ "xi_api_key": "k7Qz2", "xi-api-key": "another_key_entirely", "subscription": { "tier": "free" } }),
    )
    .await;
    assert_eq!(result["xi_api_key"], permaura_core::REDACTED, "{result}");
    assert_eq!(result["xi-api-key"], permaura_core::REDACTED, "{result}");
    assert_eq!(result["subscription"]["tier"], "free");
}

#[tokio::test]
async fn the_imported_key_query_parameter_is_redacted_by_name() {
    let spec = VOICES.replace(r#""in": "header", "name": "xi-api-key""#, r#""in": "query", "name": "appid""#);
    let result = read_through_an_import(
        &spec,
        "weather",
        "k7Qz2",
        json!({ "request": { "appid": "k7Qz2" }, "city": "Andorra la Vella" }),
    )
    .await;
    assert_eq!(result["request"]["appid"], permaura_core::REDACTED, "{result}");
    assert_eq!(result["city"], "Andorra la Vella");
}

const ACCOUNTS: &str = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Accounts", "version": "1" },
  "servers": [{ "url": "https://api.example.com" }],
  "components": { "securitySchemes": { "key": { "type": "apiKey", "in": "header", "name": "X-Accounts-Key" } } },
  "security": [{ "key": [] }],
  "paths": { "{account}/items": { "get": { "operationId": "listItems", "parameters": [{ "name": "account", "in": "path", "required": true }] } } }
}"#;

/// Import ACCOUNTS as `accounts`, seal a credential, and let the demo agent read `listItems`.
async fn accounts_rig() -> (Arc<MockHttpClient>, AppState) {
    let (http, state) = rig();
    let (status, body) = import(&state, json!({ "name": "Accounts", "id": "accounts", "spec": ACCOUNTS })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = post(&state, "/v1/connections/accounts/credential", json!({ "value": "synthetic-accounts-key" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post(
        &state,
        "/v1/policies",
        json!({ "id": "pol_accounts", "connection_id": "accounts", "name": "Read", "allow": ["listItems"] }),
    )
    .await;
    assert!(status.is_success(), "{body}");
    let (status, body) = post(
        &state,
        "/v1/grants",
        json!({ "grant_id": "gr_accounts", "name": "Read", "policy_ids": ["pol_accounts"], "agents": ["codex-cli"] }),
    )
    .await;
    assert!(status.is_success(), "{body}");
    (http, state)
}

/// A document's path key without its leading slash is pinned under the base, so an ordinary call works and a path parameter can only ever name a path on the base's host.
#[tokio::test]
async fn a_path_key_without_a_leading_slash_stays_under_the_base() {
    let (http, state) = accounts_rig().await;
    let cap = state.service.store().get_capability("accounts.listItems").unwrap().expect("imported");
    assert_eq!(cap.http.as_ref().unwrap().path, "/{account}/items");
    for (account, sent) in [
        ("acme", "https://api.example.com/acme/items"),
        (".evil.example", "https://api.example.com/.evil.example/items"),
    ] {
        let (status, body) =
            post(&state, "/v1/invoke", json!({ "capability": "accounts.listItems", "params": { "account": account } })).await;
        assert_eq!(status, StatusCode::OK, "{account}: {body}");
        let request = http.last_request().expect("sent");
        assert_eq!(request.url, sent);
        assert_eq!(request.host().as_deref(), Some("api.example.com"));
    }
}

/// A stored path without its leading slash (a manifest, a bundle, or an import from before the fix) cannot let a path parameter choose the host the credential goes to. The final host, scheme and port must be the pinned base's, and the call is refused before policy with nothing sent.
#[tokio::test]
async fn a_stored_path_that_would_move_the_host_is_refused_before_the_credential_leaves() {
    let (http, state) = accounts_rig().await;
    let store = state.service.store();
    let mut cap = store.get_capability("accounts.listItems").unwrap().expect("imported");
    cap.http.as_mut().unwrap().path = "{account}/items".into();
    store.put_capability(cap).unwrap();
    let before = http.requests().len();
    for account in [".evil.example", "@evil.example", ":8443"] {
        let (status, body) =
            post(&state, "/v1/invoke", json!({ "capability": "accounts.listItems", "params": { "account": account } })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{account}: {body}");
        assert!(body["decision"]["reason"].as_str().unwrap().contains("pinned"), "{account}: {body}");
    }
    assert_eq!(http.requests().len(), before, "nothing reaches any host");
    let last = store.audit_events(Some(1)).unwrap().pop().expect("audited");
    assert_eq!(last.payload.decision, "deny");
    assert_eq!(last.payload.summary["request_refused"], "pinned_host");
}
