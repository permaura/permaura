//! An approved held call runs outside the execution slots, as on 1.3.52, so it reserves a slot's byte buffers in the JSON pool beside its params, and the pool bounds how many run at once. Two approved while the worker is otherwise idle run side by side, as they did before any bound; one approved while agent calls hold every slot runs, and takes no slot from them; one the pool has no room for waits up to the pool wait and is then refused, still pending, for the approver to give again.
//!
//! Every credential and upstream here is synthetic.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{AuthScheme, HttpMethod, HttpSpec, ReqwestClient, DEFAULT_HTTP_MAX_RESPONSE_BYTES};
use permaura_gateway::error::GatewayError;
use permaura_gateway::limits::{LimitKey, Limits, LimitsConfig, DEFAULT_BODY_EXEC_BYTES, VIEW_FREE_TENTHS};
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tower::ServiceExt;

mod common;

const HELD: &str = "github.pull_requests.create";

/// An upstream that tells the test when a request has arrived and answers only once the test releases it.
async fn upstream(arrived: mpsc::UnboundedSender<()>, release: Arc<Semaphore>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let (arrived, release) = (arrived.clone(), release.clone());
            tokio::spawn(async move {
                let mut head = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut head).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&head[..n]),
                    }
                }
                let _ = arrived.send(());
                let _permit = release.acquire().await;
                let body = br#"{"number":1}"#;
                let status = format!(
                    "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(status.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

async fn hold(state: &AppState, title: &str) -> String {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let params = json!({ "title": title });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(json!({ "capability": HELD, "params": params }).to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    body["approval_id"].as_str().unwrap().to_string()
}

/// The seeded estate with the held capability posting to `base_url`, on the memory budget `config` describes.
fn state(base_url: String, config: &LimitsConfig) -> (AppState, Arc<dyn Store>) {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let mut cap = store.get_capability(HELD).unwrap().expect("the seeded capability");
    cap.http = Some(HttpSpec { method: HttpMethod::Post, base_url, path: "/v1/pulls".to_string(), body_params: vec!["title".to_string()], auth: AuthScheme::Bearer, ..HttpSpec::default() });
    store.put_capability(cap).unwrap();
    common::file_as_imported(store.as_ref(), HELD);
    let http = Arc::new(ReqwestClient::loopback_for_tests(Duration::from_secs(60)).with_response_cap(DEFAULT_HTTP_MAX_RESPONSE_BYTES));
    (AppState::new(EnforcementService::new(store.clone(), http).with_memory_budget(MemoryBudget::from_config(config))).with_limits(Arc::new(Limits::new(config.clone()))), store)
}

#[tokio::test]
async fn two_approved_calls_run_side_by_side_on_an_idle_hosted_worker() {
    let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let config = LimitsConfig { json_pool_wait: Duration::from_millis(300), ..LimitsConfig::defaults_for(true) };
    let (state, _store) = state(upstream(arrived_tx, release.clone()).await, &config);
    let pool = state.service.memory().pool().clone();

    let first = hold(&state, "first").await;
    let second = hold(&state, "second").await;
    let approve = |id: String| {
        let service = state.service.clone();
        tokio::spawn(async move { service.resolve_approval(&id, true, "bearer", Some("operator")).await })
    };
    let running = approve(first);
    tokio::time::timeout(Duration::from_secs(10), arrived.recv()).await.expect("the first approved call reached its upstream");
    let beside = approve(second);
    tokio::time::timeout(Duration::from_secs(10), arrived.recv()).await.expect("the second approved call reached its upstream while the first was still running");
    let held = pool.max_bytes() - pool.available_bytes();
    let response = DEFAULT_HTTP_MAX_RESPONSE_BYTES;
    let share = DEFAULT_BODY_EXEC_BYTES as u64 + response + response * VIEW_FREE_TENTHS / 10;
    assert!(held >= 2 * share, "each running approval holds an execution slot's share of the pool: {held} bytes");
    assert_eq!(state.limits.available_execution_slots(), config.max_inflight, "and none of the execution slots");

    release.add_permits(16);
    for call in [running, beside] {
        assert_eq!(call.await.unwrap().expect("the approval ran").status, "approved");
    }
    assert_eq!(pool.available_bytes(), pool.max_bytes(), "both gave their room back");
    assert_eq!(state.limits.available_execution_slots(), config.max_inflight, "and their slots");
}

/// 1.3.52 ran an approval while agent calls held every execution slot, and an approval holds none of them, so agent calls are admitted beside it as they were.
#[tokio::test]
async fn an_approval_runs_while_agent_calls_hold_every_execution_slot_and_takes_none() {
    let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let config = LimitsConfig { max_inflight: 1, queue_depth: 1, queue_wait: Duration::from_millis(300), ..LimitsConfig::defaults_for(true) };
    let (state, _store) = state(upstream(arrived_tx, release.clone()).await, &config);

    let first = hold(&state, "first").await;
    let agent = state.limits.admit(&LimitKey::session("an agent call")).await.expect("the one slot");
    let running = {
        let service = state.service.clone();
        tokio::spawn(async move { service.resolve_approval(&first, true, "bearer", Some("operator")).await })
    };
    tokio::time::timeout(Duration::from_secs(10), arrived.recv()).await.expect("the approved call reached its upstream while an agent call held the only slot");
    drop(agent);
    assert_eq!(state.limits.available_execution_slots(), 1, "the running approval holds no slot");
    let beside = tokio::time::timeout(Duration::from_secs(5), state.limits.admit(&LimitKey::session("another agent call"))).await.expect("answered");
    assert!(beside.is_ok(), "an agent call is admitted at once while the approval runs");
    drop(beside);

    release.add_permits(16);
    assert_eq!(running.await.unwrap().expect("the approval ran").status, "approved");
}

#[tokio::test]
async fn an_approval_the_pool_has_no_room_for_waits_and_is_then_refused_still_pending() {
    let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    // Room for one approved call's execution and its params, not two.
    let config = LimitsConfig {
        json_pool_bytes: 30 * 1024 * 1024,
        json_pool_wait: Duration::from_millis(300),
        ..LimitsConfig::defaults_for(true)
    };
    let (state, store) = state(upstream(arrived_tx, release.clone()).await, &config);

    let first = hold(&state, "first").await;
    let second = hold(&state, "second").await;

    let running = {
        let service = state.service.clone();
        let first = first.clone();
        tokio::spawn(async move { service.resolve_approval(&first, true, "bearer", Some("operator")).await })
    };
    tokio::time::timeout(Duration::from_secs(10), arrived.recv()).await.expect("the first approved call reached its upstream");

    let refused = tokio::time::timeout(Duration::from_secs(5), state.service.resolve_approval(&second, true, "bearer", Some("operator")))
        .await
        .expect("the second approval was answered while the first was still running");
    match refused {
        Err(GatewayError::TooManyRequests { reason, .. }) => assert_eq!(reason, "memory"),
        other => panic!("expected a 429 while the first approved call holds the pool, got {other:?}"),
    }
    assert_eq!(store.get_approval(&second).unwrap().unwrap().status, "pending", "nothing was claimed");
    assert!(arrived.try_recv().is_err(), "the second call never reached its upstream");

    release.add_permits(16);
    let done = running.await.unwrap().expect("the first approval ran");
    assert_eq!(done.status, "approved");
    let again = state.service.resolve_approval(&second, true, "bearer", Some("operator")).await.expect("given again, it runs");
    assert_eq!(again.status, "approved");
}
