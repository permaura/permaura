//! The reads outside admission control do work bounded by what they return, not by how many
//! events the hot audit window holds.
//!
//! Grant usage cloned the whole resident chain on every request, `/v1/audit-events` with no `limit`
//! returned a copy of all of it, and every authenticated `/health` and audit page re-verified every
//! event under the store lock. None of those routes passes execution admission, so a session could
//! repeat them until a 512 MiB worker had no memory and no free request slot left for a revocation.
//!
//! Measured as bytes allocated on the request's own thread, on a current-thread runtime so the whole
//! handler runs there, against windows of two sizes: what does not grow with the window is the
//! property, and an absolute number would only be a guess about the allocator.
#![cfg(feature = "sqlite")]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::AuditPayload;
use permaura_gateway::store::{GrantCharge, Store};
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

struct CountingAllocator;

thread_local! {
    static ALLOCATED: Cell<u64> = const { Cell::new(0) };
}

fn count(bytes: usize) {
    let _ = ALLOCATED.try_with(|a| a.set(a.get() + bytes as u64));
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size);
        System.realloc(ptr, layout, new_size)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Growth allowed between the small window and the large one. Far below one copy of the large
/// window (several thousand events of a few hundred bytes each), and far above the noise of a
/// response that does not depend on it.
const SLACK: u64 = 64 * 1024;

fn state(tag: &str) -> AppState {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!("permaura-bounded-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db");
    let _ = std::fs::remove_file(&path);
    let store: std::sync::Arc<dyn Store> = std::sync::Arc::new(
        permaura_gateway::store::sqlite::SqliteStore::open(&path.to_string_lossy()).expect("store opens"),
    );
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    AppState::new(permaura_gateway::service::EnforcementService::new(store, http))
}

/// Append `n` charged executions of `grant_id`, as the engine records them.
fn charge(state: &AppState, grant_id: &str, n: usize) {
    let store = state.service.store();
    for i in 0..n {
        let mut payload = AuditPayload::new("generic_http.request", "bounded", "allow");
        payload.agent_id = Some(if i % 2 == 0 { "codex-cli" } else { "claude-code" }.into());
        payload.summary = serde_json::json!({ "grant_id": grant_id, "padding": "x".repeat(200) });
        store.append_audit_charged(payload, Some(GrantCharge::new(grant_id))).unwrap();
    }
}

/// Bytes allocated on this thread while the router answers one GET, and the answer.
async fn measured_get(state: &AppState, uri: &str) -> (u64, StatusCode, serde_json::Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::empty())
        .unwrap();
    let before = ALLOCATED.with(Cell::get);
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let allocated = ALLOCATED.with(Cell::get) - before;
    (allocated, status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

fn first_grant(state: &AppState) -> String {
    state.service.store().list_grants().unwrap().first().expect("the seed has a grant").grant_id.clone()
}

#[tokio::test(flavor = "current_thread")]
async fn grant_usage_does_not_grow_with_the_audit_window() {
    let state = state("usage");
    let grant_id = first_grant(&state);
    let uri = format!("/v1/grants/{grant_id}/usage?window=month");
    charge(&state, &grant_id, 200);
    let (small, status, usage) = measured_get(&state, &uri).await;
    assert_eq!(status, StatusCode::OK, "{usage}");
    assert_eq!(usage["overall_used"], 200);

    charge(&state, &grant_id, 4800);
    let (large, status, usage) = measured_get(&state, &uri).await;
    assert_eq!(status, StatusCode::OK, "{usage}");
    assert_eq!(usage["overall_used"], 5000, "the counter still counts every charge");
    let series: u64 = usage["series"].as_array().unwrap().iter().map(|b| b["count"].as_u64().unwrap()).sum();
    assert_eq!(series, 5000, "and the series is every charge in the window, from the same counter");
    assert!(
        large < small + SLACK,
        "a request against 5000 events allocated {large} bytes, against 200 it allocated {small}: the work grows with the window"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_audit_page_is_capped_and_a_repeated_verification_is_free() {
    let state = state("audit");
    let grant_id = first_grant(&state);
    charge(&state, &grant_id, 3000);

    let (_, status, page) = measured_get(&state, "/v1/audit-events").await;
    assert_eq!(status, StatusCode::OK);
    let returned = page["events"].as_array().unwrap().len();
    assert_eq!(returned, permaura_gateway::rest::AUDIT_PAGE_MAX, "no limit means the cap, not the window");
    assert_eq!(page["limit"], permaura_gateway::rest::AUDIT_PAGE_MAX);
    assert_eq!(page["window_only"], true, "and the answer says it is short of what was asked");
    assert_eq!(page["chain_intact"], true);

    // The first authenticated health check proves the window; the next one has nothing new to prove.
    let (_, status, health) = measured_get(&state, "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["audit_chain_intact"], true, "{health}");
    let (again, _, health) = measured_get(&state, "/health").await;
    assert_eq!(health["audit_chain_intact"], true);
    charge(&state, &grant_id, 3000);
    let (after_more, _, health) = measured_get(&state, "/health").await;
    assert_eq!(health["audit_chain_intact"], true);
    let (settled, _, _) = measured_get(&state, "/health").await;
    assert!(
        settled < again + SLACK,
        "a health check over 6000 proven events allocated {settled} bytes, over 3000 it allocated {again}: verification is redone every time"
    );
    assert!(after_more > settled, "the events appended since were checked once ({after_more} then {settled})");
}
