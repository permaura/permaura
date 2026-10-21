//! Measured: what one execution holds outside the JSON pool is its response and one redacted view of it, written once at its length, and storing a held call's result never writes a cut longer than a stored result keeps.
//! The view of a body of `1e15`s is 3.8 times the body (serde_json writes each as `1000000000000000.0`), so a view grown by doubling its buffer held the body, the old buffer and the doubled one at once: 7 times the body, where the hosted arithmetic counts 4.8.
//!
//! A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak. Growing reallocations are counted as copies, as the hosted worker's allocator may make them. Every credential and upstream here is synthetic.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures_util::StreamExt;
use permaura_gateway::connectors::{AuthScheme, HttpMethod, HttpSpec, ReqwestClient, DEFAULT_HTTP_MAX_RESPONSE_BYTES};
use permaura_gateway::limits::LimitsConfig;
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{PendingApproval, Store, MAX_STORED_RESULT_BYTES, MAX_STORED_RESULT_DEPTH};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

mod common;
mod metered_alloc;

use metered_alloc::{peak_growth, peak_growth_sync, MIB};

const CAPABILITY: &str = "github.pull_requests.list";

/// `[1e15,1e15,...]` as large as fits under `cap`: its view is 3.8 times its size.
fn numbers(cap: usize) -> Vec<u8> {
    let mut body = b"[".to_vec();
    while body.len() + 6 < cap {
        body.extend_from_slice(b"1e15,");
    }
    body.pop();
    body.push(b']');
    body
}

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
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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

fn state_pointing_at(base_url: &str) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let mut cap = store.get_capability(CAPABILITY).unwrap().expect("the seeded capability");
    cap.http = Some(HttpSpec {
        method: HttpMethod::Get,
        base_url: base_url.to_string(),
        path: "/v1/items".to_string(),
        auth: AuthScheme::Bearer,
        ..HttpSpec::default()
    });
    store.put_capability(cap).unwrap();
    common::file_as_imported(store.as_ref(), CAPABILITY);
    let http = Arc::new(ReqwestClient::loopback_for_tests(Duration::from_secs(60)).with_response_cap(DEFAULT_HTTP_MAX_RESPONSE_BYTES));
    let budget = MemoryBudget::from_config(&LimitsConfig::defaults_for(true));
    AppState::new(EnforcementService::new(store, http).with_memory_budget(budget))
}

/// Post an invoke and read the answer as a stream, keeping only its length, so the measurement is of the gateway and not of this client.
async fn invoke_streamed(state: &AppState) -> (StatusCode, usize) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let body = json!({ "capability": CAPABILITY, "params": {} }).to_string();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let mut stream = resp.into_body().into_data_stream();
    let mut len = 0;
    while let Some(chunk) = stream.next().await {
        len += chunk.unwrap().len();
    }
    (status, len)
}

/// An approved held call whose result nests past the stored depth with many small containers there, each of which the cut would write as a marker many times its size.
fn approved_with_a_wide_deep_result(result_bytes: usize) -> PendingApproval {
    let siblings = (result_bytes - 2 * MAX_STORED_RESULT_DEPTH) / 3;
    let result = format!("{}{}{}", "[".repeat(MAX_STORED_RESULT_DEPTH), vec!["[]"; siblings].join(","), "]".repeat(MAX_STORED_RESULT_DEPTH));
    let row = format!(
        r#"{{"id":"appr_wide","session_id":"sess_demo","capability":"{CAPABILITY}","resource":"github_acme","message":"Approve?","status":"approved","grant_id":null,"policy_id":null,"params":{{}},"result":{result},"result_status":200,"created_at":1,"expires_at":null,"risk":"low","action_description":"List pull requests","required_tier":"approve","required_signatures":1,"signatures":[]}}"#
    );
    serde_json::from_str(&row).unwrap()
}

#[tokio::test]
async fn an_execution_holds_its_response_and_one_view_and_a_stored_cut_stays_within_its_bound() {
    metered_alloc::count_realloc_as_copy(true);
    let r = DEFAULT_HTTP_MAX_RESPONSE_BYTES as usize;
    let body = Arc::new(numbers(r));
    let state = state_pointing_at(&upstream(body.clone()).await);
    let accounted = r + 38 * r / 10;

    let ((status, len), one) = peak_growth(invoke_streamed(&state)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(len * 10 > body.len() * 37, "the whole 3.8x view reached the agent: {len} bytes");
    assert!(one < accounted + 3 * MIB, "one call held {} MiB; the arithmetic counts {} MiB for R and its view", one / MIB, accounted / MIB);

    let (answers, eight) = peak_growth(async {
        let calls: Vec<_> = (0..8)
            .map(|_| {
                let state = state.clone();
                tokio::spawn(async move { invoke_streamed(&state).await })
            })
            .collect();
        let mut out = Vec::new();
        for call in calls {
            out.push(call.await.unwrap());
        }
        out
    })
    .await;
    for (status, _) in &answers {
        assert_eq!(*status, StatusCode::OK);
    }
    assert!(eight < 8 * (accounted + 3 * MIB), "eight calls held {} MiB together", eight / MIB);

    // A 4 MiB result whose cut would be about 60 MiB: measured, found over the bound, and stored as the size marker without being written.
    let store = MemoryStore::new();
    let row = approved_with_a_wide_deep_result(4 * MIB);
    let (stored, cut) = peak_growth_sync(|| store.put_approval(row));
    stored.unwrap();
    let kept = store.get_approval("appr_wide").unwrap().unwrap().result.unwrap().to_value_unbounded();
    assert!(kept["bytes"].as_u64().unwrap() > MAX_STORED_RESULT_BYTES as u64, "{kept}");
    assert!(cut < 2 * MIB, "storing the row held {} MiB", cut / MIB);
    eprintln!("measured: one call {} MiB (R + 3.8 R = {} MiB); eight in parallel {} MiB; storing a result whose cut is over the bound {} MiB", one / MIB, accounted / MIB, eight / MIB, cut / MIB);
}
