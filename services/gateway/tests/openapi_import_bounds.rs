//! An OpenAPI import wrote one capability row per operation with no count or byte bound, and a hosted plan sets no connection ceiling, so five or six large imports pushed the store past what a 512 MiB worker can snapshot. One import is bounded in operations, and every import in the bytes all capabilities may take together; both are refused before anything is written, on a dry run too.
//!
//! Every credential and host here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

fn gateway(config: LimitsConfig) -> AppState {
    common::isolate_from_the_real_install();
    AppState::in_memory_seeded_with_http(Arc::new(MockHttpClient::new())).with_limits(Arc::new(Limits::new(config)))
}

/// An OpenAPI document with `operations` GET operations, each summarised in `summary_bytes` bytes.
fn spec(operations: usize, summary_bytes: usize) -> String {
    let paths: serde_json::Map<String, Value> = (0..operations)
        .map(|i| (format!("/items{i}"), json!({ "get": { "operationId": format!("getItem{i}"), "summary": "s".repeat(summary_bytes) } })))
        .collect();
    json!({
        "openapi": "3.0.3",
        "info": { "title": "Items", "version": "1" },
        "servers": [{ "url": "https://api.example.com/v1" }],
        "paths": paths,
    })
    .to_string()
}

async fn import(state: &AppState, id: &str, spec: String, dry_run: bool) -> (StatusCode, Value) {
    let body = json!({ "name": id, "id": id, "spec": spec, "dry_run": dry_run });
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/connections/import-openapi")
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

#[tokio::test]
async fn an_import_with_more_operations_than_one_import_takes_is_refused() {
    let state = gateway(LimitsConfig { openapi_operations: 50, ..LimitsConfig::default() });
    for dry_run in [true, false] {
        let (status, body) = import(&state, "items", spec(51, 16), dry_run).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "dry run {dry_run}: {body}");
        assert!(body["error"].as_str().unwrap().contains("51 operations"), "{body}");
    }
    assert!(state.service.store().get_connection("items").unwrap().is_none(), "nothing was written");
    let (status, body) = import(&state, "items", spec(50, 16), false).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn an_import_that_would_take_the_capabilities_past_their_ceiling_is_refused() {
    let held = gateway(LimitsConfig::default()).service.store().capability_bytes().unwrap();
    let state = gateway(LimitsConfig { capability_bytes: held + 64 * 1024, ..LimitsConfig::default() });
    let (status, body) = import(&state, "small", spec(20, 64), false).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let after = state.service.store().capability_bytes().unwrap();
    eprintln!("20 small operations took {} bytes as capabilities", after - held);

    for dry_run in [true, false] {
        let (status, body) = import(&state, "large", spec(100, 1024), dry_run).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "dry run {dry_run}: {body}");
        assert!(body["error"].as_str().unwrap().contains("ceiling"), "{body}");
    }
    assert!(state.service.store().get_connection("large").unwrap().is_none(), "nothing was written");
    assert_eq!(state.service.store().capability_bytes().unwrap(), after);
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

/// The ceiling is the gateway's, not only an import's: a connection, a preset and a WordPress site write capability rows too, and each is refused once the rows would pass it, with nothing written.
#[tokio::test]
async fn every_path_that_writes_capabilities_is_held_to_the_ceiling() {
    const FORUM: &str = include_str!("fixtures/wordpress/forum-index.json");
    let http = Arc::new(MockHttpClient::new());
    common::isolate_from_the_real_install();
    let probe = AppState::in_memory_seeded_with_http(http.clone());
    let held = probe.service.store().capability_bytes().unwrap();
    let state = AppState::in_memory_seeded_with_http(http.clone())
        .with_limits(Arc::new(Limits::new(LimitsConfig { capability_bytes: held, ..LimitsConfig::default() })));
    http.push_response(permaura_gateway::connectors::HttpResponse::json(200, serde_json::from_str(FORUM).unwrap()));
    for (uri, body) in [
        ("/v1/connections", json!({ "connector": "github", "name": "Second GitHub", "id": "github_second" })),
        ("/v1/connections/from-preset", json!({ "preset_id": "stripe", "name": "Stripe", "id": "stripe_second" })),
        (
            "/v1/connections/import-wordpress",
            json!({ "name": "Support", "url": "https://eventsmanagerpro.com/support", "namespaces": ["bbpress/v1"],
                    "digest": permaura_gateway::wordpress::digest(&serde_json::from_str(FORUM).unwrap(), Some(&["bbpress/v1".to_string()])) }),
        ),
    ] {
        let (status, answer) = post(&state, uri, body).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{uri}: {answer}");
        assert!(answer["error"].as_str().unwrap().contains("ceiling"), "{uri}: {answer}");
    }
    for id in ["github_second", "stripe_second", "wordpress_support"] {
        assert!(state.service.store().get_connection(id).unwrap().is_none(), "{id} was not written");
    }
    assert_eq!(state.service.store().capability_bytes().unwrap(), held);
}

/// The ceiling refuses growth only: a gateway already past it (its ceiling lowered, or a restore) can still re-sync a site that has not changed, which writes nothing.
#[tokio::test]
async fn a_re_sync_that_writes_nothing_is_not_refused_past_the_ceiling() {
    const FORUM: &str = include_str!("fixtures/wordpress/forum-index.json");
    let http = Arc::new(MockHttpClient::new());
    common::isolate_from_the_real_install();
    let state = AppState::in_memory_seeded_with_http(http.clone());
    http.push_response(permaura_gateway::connectors::HttpResponse::json(200, serde_json::from_str(FORUM).unwrap()));
    let digest = permaura_gateway::wordpress::digest(&serde_json::from_str(FORUM).unwrap(), Some(&["bbpress/v1".to_string()]));
    let (status, answer) = post(
        &state,
        "/v1/connections/import-wordpress",
        json!({ "name": "Support", "url": "https://eventsmanagerpro.com/support", "namespaces": ["bbpress/v1"], "digest": digest }),
    )
    .await;
    assert!(status.is_success(), "{answer}");
    let held = state.service.store().capability_bytes().unwrap();
    let past = state.clone().with_limits(Arc::new(Limits::new(LimitsConfig { capability_bytes: held - 1, ..LimitsConfig::default() })));
    http.push_response(permaura_gateway::connectors::HttpResponse::json(200, serde_json::from_str(FORUM).unwrap()));
    let (status, answer) = post(&past, "/v1/connections/wordpress_support/resync", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(answer["added"].as_array().unwrap().is_empty() && answer["changed"].as_array().unwrap().is_empty(), "{answer}");
    assert_eq!(state.service.store().capability_bytes().unwrap(), held);
}

/// The SQLite store sums its stored rows in SQL; that is the figure every other store computes from its capabilities.
#[test]
fn the_sqlite_store_counts_the_bytes_its_capability_rows_take() {
    use permaura_gateway::store::Store as _;
    let store = permaura_gateway::store::sqlite::SqliteStore::open_in_memory().unwrap();
    seed::seed(&store).expect("the demo estate seeds");
    let computed: u64 = store.list_capabilities().unwrap().iter().map(permaura_gateway::store::capability_row_bytes).sum();
    assert!(computed > 0);
    assert_eq!(store.capability_bytes().unwrap(), computed);
}
