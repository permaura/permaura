//! Measured: an upstream body of the costliest shape, at the 5 MiB response cap, reaches the agent without the gateway ever building a tree of it, over REST and MCP, alone and eight at a time.
//! The same body parsed into a `serde_json::Value`, which is what the gateway did before, is measured beside it as the control.
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
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

mod common;
mod metered_alloc;

use metered_alloc::{peak_growth, peak_growth_sync, MIB};

const CAPABILITY: &str = "github.pull_requests.list";

/// `[{"a":1},...]` as large as fits under `cap`: about 85 bytes of tree for every byte.
fn one_key_objects(cap: usize) -> Vec<u8> {
    let mut body = b"[".to_vec();
    while body.len() + 9 < cap {
        body.extend_from_slice(b"{\"a\":1},");
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

/// Post `body` and read the answer as a stream, keeping only its length and its first bytes, so the measurement is of the gateway and not of this client.
async fn post_streamed(state: &AppState, uri: &str, body: String) -> (StatusCode, usize, String) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let mut stream = resp.into_body().into_data_stream();
    let mut len = 0;
    let mut head = String::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        if head.len() < 200 {
            head.push_str(&String::from_utf8_lossy(&chunk[..chunk.len().min(200)]));
        }
        len += chunk.len();
    }
    (status, len, head)
}

fn invoke_body() -> String {
    json!({ "capability": CAPABILITY, "params": {} }).to_string()
}

fn mcp_body() -> String {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": CAPABILITY, "arguments": {} } })
        .to_string()
}

#[tokio::test]
async fn a_five_mib_body_of_one_key_objects_reaches_the_agent_as_bytes() {
    let body = Arc::new(one_key_objects(DEFAULT_HTTP_MAX_RESPONSE_BYTES as usize));
    let state = state_pointing_at(&upstream(body.clone()).await);

    // The control: what the gateway built from this body before.
    let (tree, control) = peak_growth_sync(|| serde_json::from_slice::<serde_json::Value>(&body).unwrap());
    drop(tree);
    assert!(control > 300 * MIB, "the tree the body used to become: {} MiB", control / MIB);

    let ((status, len, head), rest) = peak_growth(post_streamed(&state, "/v1/invoke", invoke_body())).await;
    assert_eq!(status, StatusCode::OK, "{head}");
    assert!(len > body.len(), "the whole document reached the agent: {len} bytes");
    assert!(rest < 48 * MIB, "REST held {} MiB for a {} MiB body (the tree was {} MiB)", rest / MIB, body.len() / MIB, control / MIB);

    let ((status, len, head), mcp) = peak_growth(post_streamed(&state, "/mcp", mcp_body())).await;
    assert_eq!(status, StatusCode::OK, "{head}");
    assert!(head.starts_with(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"#), "{head}");
    assert!(len > 2 * body.len(), "the text block and structuredContent both carry it: {len} bytes");
    assert!(mcp < 48 * MIB, "MCP held {} MiB for a {} MiB body", mcp / MIB, body.len() / MIB);

    // Eight at once, as the hosted execution slots allow: bytes, never trees.
    let (answers, eight) = peak_growth(async {
        let calls: Vec<_> = (0..8)
            .map(|i| {
                let state = state.clone();
                tokio::spawn(async move {
                    if i % 2 == 0 {
                        post_streamed(&state, "/v1/invoke", invoke_body()).await
                    } else {
                        post_streamed(&state, "/mcp", mcp_body()).await
                    }
                })
            })
            .collect();
        let mut out = Vec::new();
        for call in calls {
            out.push(call.await.unwrap());
        }
        out
    })
    .await;
    for (status, len, head) in &answers {
        assert_eq!(*status, StatusCode::OK, "{head}");
        assert!(*len > body.len());
    }
    assert!(eight < 8 * 48 * MIB, "eight calls held {} MiB together", eight / MIB);
    eprintln!(
        "measured: control tree {} MiB; REST {} MiB; MCP {} MiB; eight in parallel {} MiB",
        control / MIB,
        rest / MIB,
        mcp / MIB,
        eight / MIB
    );
}
