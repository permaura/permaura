//! A member's management write that applies at once is recorded in the resident chain, and a member chooses how large it is (a deny list of one valid action id thousands of times), so a few hundred writes could fill a hosted worker. The applied event keeps a change past a small size as its length and digest.
//!
//! Every credential here is synthetic.

use axum::body::Body;
use axum::http::Request;
use permaura_gateway::{build_router, seed};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

#[tokio::test]
async fn an_applied_change_past_a_small_size_is_recorded_as_its_length_and_digest() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let deny = vec!["transactions.refund"; 4_000];
    let policy = json!({ "id": "p_large", "connection_id": "braintree_production", "name": "large", "deny": deny });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/policies")
        .header("host", "127.0.0.1:7376")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(policy.to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let body: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap_or(Value::Null);
    assert!(status.is_success(), "{status}: {body}");
    assert!(state.service.store().get_policy("p_large").unwrap().is_some(), "the change applied at once");

    let events = state.service.store().audit_events(None).unwrap();
    let applied = events
        .iter()
        .rev()
        .find(|e| e.payload.action == "permaura.policy.write" && e.payload.summary["method"] == "applied")
        .expect("the applied change is in the chain");
    let summary = serde_json::to_string(&applied.payload.summary).unwrap();
    assert!(summary.len() < 4 * 1024, "the applied event keeps {} bytes of summary", summary.len());
    let mutation = &applied.payload.summary["mutation"];
    assert!(mutation["bytes"].as_u64().unwrap() > 64 * 1024, "{mutation}");
    assert_eq!(mutation["sha256"].as_str().map(str::len), Some(64), "{mutation}");
}
