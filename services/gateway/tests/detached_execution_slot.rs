//! An execution that outlives its caller keeps the execution slot it was admitted under until it has finished.
//! The execution runs in a task of its own so a caller who hangs up cancels nothing, and before this the slot went with the caller's request: an agent could hang up on call after call against an upstream that drips its answer, and every one of those executions ran outside the slot count, with its response bytes outside every budget.
//!
//! Every credential and upstream here is synthetic.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse};
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use tokio::sync::Semaphore;
use tower::ServiceExt;

mod common;

/// An upstream that answers only when the test releases it, and counts the calls that reached it.
struct HeldUpstream {
    reached: AtomicUsize,
    release: Semaphore,
}

#[async_trait]
impl HttpClient for HeldUpstream {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        self.reached.fetch_add(1, Ordering::SeqCst);
        self.release.acquire().await?.forget();
        Ok(HttpResponse::json(200, serde_json::json!({ "pulls": [] })))
    }
}

fn invoke() -> Request<Body> {
    post("/v1/invoke", serde_json::json!({ "capability": "github.pull_requests.list", "params": { "owner": "synthetic", "repo": "synthetic" } }))
}

fn mcp_call() -> Request<Body> {
    post(
        "/mcp",
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "github.pull_requests.list", "arguments": { "owner": "synthetic", "repo": "synthetic" } } }),
    )
}

fn post(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn an_execution_whose_caller_hung_up_keeps_its_slot_until_it_finishes() {
    for call in [invoke as fn() -> Request<Body>, mcp_call] {
        hang_up_then_call_again(call).await;
    }
}

async fn hang_up_then_call_again(call: fn() -> Request<Body>) {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let upstream = Arc::new(HeldUpstream { reached: AtomicUsize::new(0), release: Semaphore::new(0) });
    let limits = Arc::new(Limits::new(LimitsConfig {
        max_inflight: 1,
        queue_depth: 0,
        queue_wait: Duration::from_millis(50),
        rate_per_min: 60_000,
        rate_burst: 1_000,
        ..LimitsConfig::default()
    }));
    let state = AppState::new(EnforcementService::new(store, upstream.clone())).with_limits(limits.clone());
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    // The first call reaches the upstream, and its caller hangs up while the upstream holds its answer.
    let caller = tokio::spawn(app.clone().oneshot(call()));
    until("the first call to reach the upstream", || upstream.reached.load(Ordering::SeqCst) == 1).await;
    caller.abort();
    let _ = caller.await;
    assert_eq!(limits.available_execution_slots(), 0, "the detached execution still holds the only slot");

    // So the next call is shed at admission instead of starting a second execution beside it.
    let shed = tokio::time::timeout(Duration::from_secs(5), app.clone().oneshot(call()))
        .await
        .expect("a call with no slot is shed, not parked")
        .unwrap();
    assert_eq!(shed.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(upstream.reached.load(Ordering::SeqCst), 1, "no second execution started");

    // Once the detached execution finishes, its slot is free again.
    upstream.release.add_permits(1);
    until("the detached execution to finish", || limits.available_execution_slots() == 1).await;
    upstream.release.add_permits(1);
    let ran = tokio::time::timeout(Duration::from_secs(5), app.oneshot(call())).await.expect("the call ran").unwrap();
    assert_eq!(ran.status(), StatusCode::OK);
    assert_eq!(upstream.reached.load(Ordering::SeqCst), 2);
}
