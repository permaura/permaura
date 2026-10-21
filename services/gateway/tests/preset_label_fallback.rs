//! A connection made from an installed manifest without a label takes the manifest's label cut to 128 bytes, since the console and the phone send none and their user cannot edit it; a label the caller sends is still refused past 128 bytes.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const LONG: &str = "東京都千代田区の税理士事務所｜相続税・法人税・確定申告・会社設立のご相談は山田税理士法人へ";

async fn send(state: &AppState, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn manifest(id: &str, name: &str, label: Option<&str>) -> Value {
    let mut m = json!({
        "id": id, "name": name, "vertical": "devtools", "base_url": "https://api.acme-tools.example",
        "capabilities": [ { "id": "items.list", "method": "GET", "path": "/items", "description": "List items" } ]
    });
    if let Some(l) = label {
        m["label"] = json!(l);
    }
    m
}

async fn install(state: &AppState, m: Value) {
    let (status, body) = send(state, "POST", "/v1/connectors/install", json!({ "manifest": m, "version": 1 })).await;
    assert!(status.is_success(), "install: {status} {body}");
}

#[tokio::test]
async fn a_manifest_label_past_128_bytes_is_cut_when_the_caller_sends_none() {
    let state = common::seeded();
    assert!(LONG.len() > 128);
    install(&state, manifest("acme-tools", "Acme", Some(LONG))).await;
    let (status, body) = send(&state, "POST", "/v1/connections/from-preset", json!({ "preset_id": "acme-tools", "name": "acme" })).await;
    assert!(status.is_success(), "{status} {body}");
    let id = body["connection_id"].as_str().unwrap().to_string();
    let (_, list) = send(&state, "GET", "/v1/connections", Value::Null).await;
    let rows = list["connections"].as_array().or_else(|| list.as_array()).cloned().unwrap_or_default();
    let row = rows.iter().find(|c| c["id"] == id.as_str()).unwrap_or_else(|| panic!("{id} not listed in {list}"));
    let label = row["label"].as_str().unwrap_or_default();
    assert!(!label.is_empty() && label.len() <= 128 && LONG.starts_with(label), "label {label:?}");

    install(&state, manifest("acme-two", LONG, None)).await;
    let (status, body) = send(&state, "POST", "/v1/connections/from-preset", json!({ "preset_id": "acme-two", "name": "acme2" })).await;
    assert!(status.is_success(), "a long manifest name with no label: {status} {body}");
}

#[tokio::test]
async fn a_label_the_caller_sends_past_128_bytes_is_still_refused() {
    let state = common::seeded();
    install(&state, manifest("acme-three", "Acme", None)).await;
    let (status, _) = send(&state, "POST", "/v1/connections/from-preset", json!({ "preset_id": "acme-three", "name": "acme3", "label": LONG })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
