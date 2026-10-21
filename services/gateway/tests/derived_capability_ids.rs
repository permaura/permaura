//! A cap of 128 bytes on every capability id refused the whole import or re-sync that carried a longer one, which earlier builds accepted: FastAPI's default operationId alone passes 128 bytes on a four-level path. The 128-byte cap stays on what an API call names when it creates or renames a connection. A capability id an import or re-sync derives from an operation is capped at 512 bytes, and one past it is left out with a warning, the same on a dry run; a re-sync caps only the ids it adds.
//!
//! The label half: the console's WordPress connect sends the site's own name as the label, which its user cannot edit and its review's dry run does not send, so refusing one past 128 bytes failed the connect after the review passed. An import cuts its label to 128 bytes at a character boundary instead, as earlier builds took it whole.
//!
//! Every credential and host here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{Connection, ConnectionSource, SourceKind};
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

/// The operationId FastAPI generates by default: the function name, the path with every non-word character as `_`, and the method.
const FASTAPI_OPERATION: &str = "list_deployment_logs_api_v1_organizations__organization_id__projects__project_id__environments__environment_id__deployments__deployment_id__logs_get";
const FASTAPI_PATH: &str = "/api/v1/organizations/{organization_id}/projects/{project_id}/environments/{environment_id}/deployments/{deployment_id}/logs";
const SPEC_URL: &str = "https://api.example.com/openapi.json";
const FORUM: &str = include_str!("fixtures/wordpress/forum-index.json");
const SITE: &str = "https://eventsmanagerpro.com/support";
/// A plausible Japanese business title, 45 characters and 135 bytes.
const LONG_SITE_NAME: &str = "東京都千代田区の税理士事務所｜相続税・法人税・確定申告・会社設立のご相談は山田税理士法人へ";

fn rig() -> (Arc<MockHttpClient>, AppState) {
    common::isolate_from_the_real_install();
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::in_memory_seeded_with_http(http.clone());
    (http, state)
}

/// An OpenAPI document with a GET for each `(path, operationId, summary)`, its path parameters declared.
fn spec(operations: &[(&str, &str, &str)]) -> String {
    let paths: serde_json::Map<String, Value> = operations
        .iter()
        .map(|(path, operation_id, summary)| {
            let parameters: Vec<Value> = path
                .split('/')
                .filter_map(|segment| segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
                .map(|name| json!({ "name": name, "in": "path", "required": true }))
                .collect();
            (path.to_string(), json!({ "get": { "operationId": operation_id, "summary": summary, "parameters": parameters } }))
        })
        .collect();
    json!({
        "openapi": "3.0.3",
        "info": { "title": "Internal", "version": "1" },
        "servers": [{ "url": "https://api.example.com/v1" }],
        "paths": paths,
    })
    .to_string()
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

async fn import(state: &AppState, id: &str, spec: &str, dry_run: bool) -> (StatusCode, Value) {
    post(state, "/v1/connections/import-openapi", json!({ "name": id, "id": id, "spec": spec, "dry_run": dry_run })).await
}

fn ids(body: &Value, key: &str) -> Vec<String> {
    let mut ids: Vec<String> = body[key].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().to_string()).collect();
    ids.sort();
    ids
}

fn warns_of_the_cap(body: &Value) -> bool {
    body["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("512"))
}

#[tokio::test]
async fn fastapis_default_operation_id_imports_on_a_dry_run_and_for_real() {
    let (_, state) = rig();
    let doc = spec(&[(FASTAPI_PATH, FASTAPI_OPERATION, "List deployment logs")]);
    let id = format!("internal.{FASTAPI_OPERATION}");
    assert!(id.len() > 128, "{}", id.len());
    for dry_run in [true, false] {
        let (status, body) = import(&state, "internal", &doc, dry_run).await;
        assert_eq!(status, if dry_run { StatusCode::OK } else { StatusCode::CREATED }, "dry run {dry_run}: {body}");
        assert_eq!(ids(&body, "capabilities"), vec![id.clone()], "dry run {dry_run}");
        assert!(!warns_of_the_cap(&body), "dry run {dry_run}: {body}");
    }
    let store = state.service.store();
    assert_eq!(store.get_connection("internal").unwrap().expect("created").capabilities, vec![id.clone()]);
    assert!(store.get_capability(&id).unwrap().is_some());
}

#[tokio::test]
async fn an_operation_whose_capability_id_passes_512_bytes_is_left_out_and_the_rest_import() {
    let (_, state) = rig();
    let long = "o".repeat(600);
    let doc = spec(&[("/items", "listItems", "List items"), ("/long", &long, "Long"), ("/other", "getOther", "Get other")]);
    let kept = vec!["long_ops.getOther".to_string(), "long_ops.listItems".to_string()];
    for dry_run in [true, false] {
        let (status, body) = import(&state, "long_ops", &doc, dry_run).await;
        assert_eq!(status, if dry_run { StatusCode::OK } else { StatusCode::CREATED }, "dry run {dry_run}: {body}");
        assert_eq!(ids(&body, "capabilities"), kept, "dry run {dry_run}");
        assert!(warns_of_the_cap(&body), "the report says what was left out, dry run {dry_run}: {body}");
        assert!(body.to_string().len() < 8 * 1024, "the warning does not echo the whole id");
    }
    let store = state.service.store();
    let mut stored = store.get_connection("long_ops").unwrap().expect("created").capabilities;
    stored.sort();
    assert_eq!(stored, kept);
    assert!(store.get_capability(&format!("long_ops.{long}")).unwrap().is_none());
}

/// A connection 1.3.51 imported with an id past 128 bytes, so every capability id it has is too.
fn a_1351_connection(state: &AppState, id: &str, doc: &str) {
    let derived = permaura_gateway::openapi::derive(
        doc.as_bytes(),
        &permaura_gateway::openapi::DeriveOptions {
            connection_id: id.to_string(),
            secret_id: format!("sec_{id}"),
            spec_url: Some(SPEC_URL.to_string()),
            bound_host: Some("api.example.com".to_string()),
            base_url: None,
            auth: None,
        },
    )
    .unwrap();
    let store = state.service.store();
    let mut capabilities: Vec<String> = derived.capabilities.iter().map(|c| c.id.clone()).collect();
    capabilities.sort();
    for cap in derived.capabilities {
        store.put_capability(cap).unwrap();
    }
    store
        .put_connection(Connection {
            id: id.to_string(),
            connector: "openapi".into(),
            name: "Internal".into(),
            label: "Internal".into(),
            secret_id: format!("sec_{id}"),
            capabilities,
            disabled_capabilities: derived.disabled_capabilities,
            disabled: false,
            allowed_hosts: Vec::new(),
            created_at: 1,
            redact_fields: Vec::new(),
            source: Some(ConnectionSource {
                kind: SourceKind::Openapi,
                url: SPEC_URL.into(),
                rest_root: None,
                namespaces: Vec::new(),
                abilities: false,
                digest: Some(permaura_gateway::openapi::digest(doc.as_bytes())),
                synced_at: 1,
            }),
            made_from: None,
        })
        .unwrap();
}

#[tokio::test]
async fn a_1351_connection_with_a_long_id_re_syncs_and_only_an_added_id_is_capped() {
    let (http, state) = rig();
    let id = format!("internal_{}", "c".repeat(140));
    a_1351_connection(&state, &id, &spec(&[("/a", "listA", "List A"), ("/b", "getB", "Get B")]));
    let long = "o".repeat(600);
    let changed = spec(&[("/a", "listA", "List every A"), ("/b", "getB", "Get B"), ("/c", "getC", "Get C"), ("/long", &long, "Long")]);
    for dry_run in [true, false] {
        http.push_response(HttpResponse { status: 200, text: Some(changed.clone()), ..HttpResponse::default() });
        let (status, body) = post(&state, &format!("/v1/connections/{id}/resync"), json!({ "dry_run": dry_run })).await;
        assert_eq!(status, StatusCode::OK, "dry run {dry_run}: {}", body.to_string().chars().take(400).collect::<String>());
        assert_eq!(ids(&body, "changed"), vec![format!("{id}.listA")], "dry run {dry_run}");
        assert_eq!(ids(&body, "added"), vec![format!("{id}.getC")], "dry run {dry_run}");
        assert!(warns_of_the_cap(&body), "the added operation past 512 bytes is reported, dry run {dry_run}: {body}");
    }
    let store = state.service.store();
    assert_eq!(store.get_capability(&format!("{id}.listA")).unwrap().unwrap().description, "List every A");
    assert!(store.get_capability(&format!("{id}.getC")).unwrap().is_some());
    assert!(store.get_capability(&format!("{id}.{long}")).unwrap().is_none());
}

/// `label` as an import stores it: at most 128 bytes, a prefix of what was sent, cut between characters.
fn assert_cut_label(stored: &str, sent: &str) {
    assert!(stored.len() <= 128, "{} bytes", stored.len());
    assert!(stored.len() > 128 - 4, "cut at the last character boundary, {} bytes", stored.len());
    assert!(sent.starts_with(stored), "{stored}");
}

#[tokio::test]
async fn the_consoles_wordpress_connect_with_a_long_site_name_imports_what_its_review_passed() {
    let (http, state) = rig();
    assert_eq!(LONG_SITE_NAME.len(), 135);
    let mut index: Value = serde_json::from_str(FORUM).unwrap();
    index["name"] = json!(LONG_SITE_NAME);
    http.push_response(HttpResponse::json(200, index.clone()));
    let (status, found) = post(&state, "/v1/connections/discover", json!({ "url": SITE })).await;
    assert_eq!(status, StatusCode::OK, "{found}");
    let site_name = found["name"].as_str().expect("the site's name").trim().to_string();
    assert_eq!(site_name, LONG_SITE_NAME);

    // The console's review sends no label; its connect sends the site's name as one.
    http.push_response(HttpResponse::json(200, index.clone()));
    let (status, review) =
        post(&state, "/v1/connections/import-wordpress", json!({ "name": "support", "url": SITE, "namespaces": ["bbpress/v1"], "dry_run": true })).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    http.push_response(HttpResponse::json(200, index));
    let (status, created) = post(
        &state,
        "/v1/connections/import-wordpress",
        json!({ "name": "support", "label": site_name, "url": SITE, "namespaces": ["bbpress/v1"], "digest": review["digest"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["connection_id"].as_str().unwrap();
    let connection = state.service.store().get_connection(id).unwrap().expect("created");
    assert_cut_label(&connection.label, LONG_SITE_NAME);
}

#[tokio::test]
async fn an_openapi_import_cuts_a_long_label_and_still_refuses_a_long_name() {
    let (_, state) = rig();
    let doc = spec(&[("/items", "listItems", "List items")]);
    let body = |name: &str, dry_run: bool| json!({ "name": name, "id": "labelled", "label": LONG_SITE_NAME, "spec": doc, "dry_run": dry_run });
    for dry_run in [true, false] {
        let (status, answer) = post(&state, "/v1/connections/import-openapi", body("labelled", dry_run)).await;
        assert_eq!(status, if dry_run { StatusCode::OK } else { StatusCode::CREATED }, "dry run {dry_run}: {answer}");
    }
    let connection = state.service.store().get_connection("labelled").unwrap().expect("created");
    assert_cut_label(&connection.label, LONG_SITE_NAME);

    // A name is the caller's own and every hold that names the connection carries it, so it is still refused, before anything is read.
    let (status, refused) = post(&state, "/v1/connections/import-openapi", json!({ "name": "n".repeat(129), "id": "named", "spec": doc, "dry_run": true })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(refused.to_string().contains("connection name is 129 bytes"), "{refused}");
}
