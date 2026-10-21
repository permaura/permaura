//! Measured: an agent's params become a tree only under the worker's JSON memory budget, on a hosted worker's numbers.
//! A body that can never fit is refused before it is parsed; eight costly bodies at once wait their turn instead of all being built; serde_json's raw-value key builds an ordinary member; and the room a call's params take is given back when the execution is done with them, not when its caller hangs up.
//!
//! A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak. Every credential and upstream here is synthetic.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{AuthScheme, HttpMethod, HttpSpec, ReqwestClient};
use permaura_gateway::limits::LimitsConfig;
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tower::ServiceExt;

mod common;
mod metered_alloc;

use metered_alloc::{peak_growth, peak_growth_sync, MIB};

const CAPABILITY: &str = "github.pull_requests.list";

fn one_key_objects(cap: usize) -> String {
    filled(cap, "{\"a\":1}")
}

fn filled(cap: usize, row: &str) -> String {
    let mut body = String::from("[");
    while body.len() + row.len() + 2 < cap {
        body.push_str(row);
        body.push(',');
    }
    body.pop();
    body.push(']');
    body
}

/// Answers every request with `{"ok":true}` once it can take a permit from `gate`, after `delay`.
async fn upstream(gate: Arc<Semaphore>, delay: Duration) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let gate = gate.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _permit = gate.acquire().await;
                tokio::time::sleep(delay).await;
                let body = b"{\"ok\":true}";
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

fn state(base_url: &str, config: &LimitsConfig) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let mut cap = store.get_capability(CAPABILITY).unwrap().expect("the seeded capability");
    // The params these calls send are ones the capability declares: an undeclared one is refused before it runs.
    cap.http = Some(HttpSpec {
        method: HttpMethod::Get,
        base_url: base_url.to_string(),
        path: "/v1/items".to_string(),
        body_params: vec!["rows".to_string(), "x".to_string()],
        auth: AuthScheme::Bearer,
        ..HttpSpec::default()
    });
    store.put_capability(cap).unwrap();
    common::file_as_imported(store.as_ref(), CAPABILITY);
    let http = Arc::new(ReqwestClient::loopback_for_tests(Duration::from_secs(60)));
    AppState::new(EnforcementService::new(store, http).with_memory_budget(MemoryBudget::from_config(config)))
}

async fn post(state: &AppState, body: String) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A `/v1/invoke` body carrying `rows` (JSON text) as one of the params.
fn invoke_with(rows: &str) -> String {
    format!(r#"{{"capability":"{CAPABILITY}","params":{{"rows":{rows}}}}}"#)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn params_become_a_tree_only_within_the_memory_budget() {
    let hosted = LimitsConfig::defaults_for(true);
    let open = Arc::new(Semaphore::new(Semaphore::MAX_PERMITS));

    // 1. Two MiB of objects nested in objects is over the one ceiling on an agent call's unpacked size: refused before a tree.
    let gw = state(&upstream(open.clone(), Duration::ZERO).await, &hosted);
    let body = invoke_with(&filled(2 * MIB - 200, "{\"a\":{\"a\":1}}"));
    let (tree, control) = peak_growth_sync(|| serde_json::from_str::<Value>(&body).unwrap());
    drop(tree);
    let ((status, answer), refused) = peak_growth(post(&gw, body.clone())).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{answer}");
    assert!(answer["error"].as_str().unwrap_or_default().contains("once unpacked"), "{answer}");
    assert!(refused < 16 * MIB, "a refused body held {} MiB (its tree is {} MiB)", refused / MIB, control / MIB);
    assert_eq!(gw.service.memory().pool().available_bytes(), gw.service.memory().pool().max_bytes());

    // 2. Eight costly bodies at once: each reserves its estimate and the body written from it, so they take turns and the trees held together stay inside the pool. Before, all eight were built at once.
    let gw = state(&upstream(open.clone(), Duration::from_millis(300)).await, &hosted);
    let medium = invoke_with(&one_key_objects(600 * 1024));
    let (one, one_tree) = peak_growth_sync(|| serde_json::from_str::<Value>(&medium).unwrap());
    drop(one);
    let (answers, eight) = peak_growth(async {
        let calls: Vec<_> = (0..8)
            .map(|_| {
                let (gw, body) = (gw.clone(), medium.clone());
                tokio::spawn(async move { post(&gw, body).await })
            })
            .collect();
        let mut out = Vec::new();
        for call in calls {
            out.push(call.await.unwrap());
        }
        out
    })
    .await;
    for (status, answer) in &answers {
        assert_eq!(*status, StatusCode::OK, "every call waited its turn and ran: {answer}");
    }
    let pool = hosted.json_pool_bytes as usize;
    assert!(8 * one_tree > pool, "eight such trees at once ({} MiB) would not fit the pool", 8 * one_tree / MIB);
    assert!(eight < pool + 32 * MIB, "eight calls held {} MiB; the pool is {} MiB", eight / MIB, pool / MIB);
    assert_eq!(gw.service.memory().pool().available_bytes(), gw.service.memory().pool().max_bytes());

    // 3. With no time to wait, the calls the pool has no room for are shed with a retryable 429.
    let impatient = LimitsConfig { json_pool_wait: Duration::from_millis(50), ..hosted.clone() };
    let gw = state(&upstream(open.clone(), Duration::from_millis(300)).await, &impatient);
    let calls: Vec<_> = (0..4)
        .map(|_| {
            let (gw, body) = (gw.clone(), medium.clone());
            tokio::spawn(async move { post(&gw, body).await })
        })
        .collect();
    let mut shed = 0;
    for call in calls {
        let (status, answer) = call.await.unwrap();
        match status {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => {
                assert_eq!(answer["reason"], "memory", "{answer}");
                shed += 1;
            }
            other => panic!("unexpected {other}: {answer}"),
        }
    }
    assert!(shed > 0, "a call with no room and no wait is told to retry");

    // 4. serde_json's raw-value key is an ordinary member: the string under it stays a string.
    let gw = state(&upstream(open.clone(), Duration::ZERO).await, &hosted);
    let inner = one_key_objects(MIB);
    let raw = format!(
        r#"{{"capability":"{CAPABILITY}","params":{{"x":{{"$serde_json::private::RawValue":{}}}}}}}"#,
        serde_json::to_string(&inner).unwrap()
    );
    let (tricked, trick_control) = peak_growth_sync(|| serde_json::from_str::<Value>(&raw).unwrap());
    drop(tricked);
    let ((status, answer), raw_peak) = peak_growth(post(&gw, raw)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(raw_peak < 24 * MIB, "the raw-value body held {} MiB; Value's own reading built {} MiB", raw_peak / MIB, trick_control / MIB);

    // 5. The caller hangs up mid-call; the execution keeps its params and their room until it is done with them, then gives the room back.
    let closed = Arc::new(Semaphore::new(0));
    let gw = state(&upstream(closed.clone(), Duration::ZERO).await, &hosted);
    let pool = gw.service.memory().pool().clone();
    let caller = tokio::spawn({
        let (gw, body) = (gw.clone(), medium.clone());
        async move { post(&gw, body).await }
    });
    let charged = async {
        while pool.available_bytes() == pool.max_bytes() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), charged).await.expect("the call reserved its params");
    tokio::time::sleep(Duration::from_millis(200)).await;
    caller.abort();
    let _ = caller.await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let held = pool.max_bytes() - pool.available_bytes();
    let (_, room) = permaura_gateway::memory::params_room(medium.as_bytes());
    assert!(held >= room, "the running execution still holds its params' room: {} of {} MiB", held / MIB as u64, room / MIB as u64);
    closed.add_permits(1);
    let released = async {
        while pool.available_bytes() < pool.max_bytes() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), released).await.expect("the room comes back when the execution ends");

    eprintln!(
        "measured: 2 MiB one-key tree {} MiB, refused at {} MiB; one 600 KiB tree {} MiB, eight at once held {} MiB; raw-value body {} MiB (Value's reading {} MiB)",
        control / MIB,
        refused / MIB,
        one_tree / MIB,
        eight / MIB,
        raw_peak / MIB,
        trick_control / MIB
    );
}
