//! Measured: approving a held call holds its result as the row it is stored in and the row read back to answer the approver, never a copy kept beside the row, and the answer is written around the stored result's own bytes.
//! Before, the settled row was cloned into the store write while the original stayed alive, and the approver's answer cloned the result again and serialized it into one more buffer.
//!
//! A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak. Every credential and upstream here is synthetic.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures_util::StreamExt;
use permaura_gateway::connectors::{AuthScheme, HttpMethod, HttpSpec, ReqwestClient, DEFAULT_HTTP_MAX_RESPONSE_BYTES};
use permaura_gateway::limits::LimitsConfig;
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

mod common;
mod metered_alloc;

use metered_alloc::{peak_growth, MIB};

/// High risk, so the seeded policy holds it for a human.
const HELD: &str = "github.pull_requests.create";

/// Low risk: it runs at once, which measures what an execution of the same answer holds.
const RUNS: &str = "github.pull_requests.list";

async fn upstream(body: Arc<Vec<u8>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut head).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&head[..n]),
                    }
                }
                let status = format!(
                    "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(status.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    (status, axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec())
}

/// Send `request` and read the answer as a stream, keeping only its length and its first bytes, so the measurement is of the gateway and not of this client.
async fn send_streamed(state: &AppState, request: Request<Body>) -> (StatusCode, usize, Vec<u8>) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let mut stream = resp.into_body().into_data_stream();
    let (mut len, mut head) = (0, Vec::new());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        if head.len() < 512 {
            head.extend_from_slice(&chunk[..chunk.len().min(512 - head.len())]);
        }
        len += chunk.len();
    }
    (status, len, head)
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn approving_a_held_call_keeps_its_result_once_beside_its_row() {
    common::isolate_from_the_real_install();
    let result = Arc::new(format!(r#"{{"blob":"{}"}}"#, "r".repeat(4 * MIB)).into_bytes());
    let base_url = upstream(result.clone()).await;

    let dir = std::env::temp_dir().join(format!("approval-resolution-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(dir.join("gateway.db").to_str().unwrap()).unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    for (id, method) in [(HELD, HttpMethod::Post), (RUNS, HttpMethod::Get)] {
        let mut cap = store.get_capability(id).unwrap().expect("the seeded capability");
        cap.http = Some(HttpSpec { method, base_url: base_url.clone(), path: "/v1/pulls".to_string(), body_params: vec!["title".to_string()], auth: AuthScheme::Bearer, ..HttpSpec::default() });
        store.put_capability(cap).unwrap();
        common::file_as_imported(store.as_ref(), id);
    }
    let http = Arc::new(ReqwestClient::loopback_for_tests(Duration::from_secs(60)).with_response_cap(DEFAULT_HTTP_MAX_RESPONSE_BYTES));
    let budget = MemoryBudget::from_config(&LimitsConfig::defaults_for(true));
    let state = AppState::new(EnforcementService::new(store, http).with_memory_budget(budget));

    let params = json!({ "title": "t" });
    let (status, held) = send(&state, post("/v1/invoke", json!({ "capability": HELD, "params": params }))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&held));
    let held: Value = serde_json::from_slice(&held).unwrap();
    let id = held["approval_id"].as_str().expect("the hold names its approval").to_string();

    let run = || post("/v1/invoke", json!({ "capability": RUNS, "params": {} }));
    // Once to warm what a first call sets up for good, then measured.
    assert_eq!(send_streamed(&state, run()).await.0, StatusCode::OK);
    let ((status, _, _), executing) = peak_growth(send_streamed(&state, run())).await;
    assert_eq!(status, StatusCode::OK);

    let ((status, len, head), peak) = peak_growth(send_streamed(&state, post("/v1/approvals", json!({ "approval_id": id, "approve": true })))).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&head));
    assert!(len > 4 * MIB, "the approver is answered with the whole result: {len} bytes");
    let row = state.service.store().get_approval(&id).unwrap().unwrap();
    assert_eq!(row.status, "approved");
    assert_eq!(row.result.unwrap().to_value_unbounded()["blob"].as_str().map(str::len), Some(4 * MIB), "and it is stored whole");
    // After the execution (the response and its view), storing the result holds the row and its text, then the text and SQLite's copy, then the row read back: about twice the result, which the execution already held.
    assert!(peak < executing + 3 * MIB, "approving held {} MiB, where executing the same call held {} MiB", peak / MIB, executing / MIB);

    // Asked again, the resolved row is the answer: read once and written around its result's own bytes.
    let ((status, again, _), answering) = peak_growth(send_streamed(&state, post("/v1/approvals", json!({ "approval_id": id, "approve": true })))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again, len);
    assert!(answering < 2 * 4 * MIB + 2 * MIB, "answering with a 4 MiB result held {} MiB", answering / MIB);
    eprintln!(
        "measured: executing a call whose answer is 4 MiB {} MiB; approving the held call {} MiB; answering with the resolved row {} MiB",
        executing / MIB,
        peak / MIB,
        answering / MIB
    );
    let _ = std::fs::remove_dir_all(&dir);
}
