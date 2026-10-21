//! An execution route's response holds its execution slot until it has been sent, so a caller that reads slowly spends slots rather than the worker's memory, one that stops reading gives its slot back at the delivery deadline, and one making steady progress at the minimum rate gets all of a response up to 15 MiB, past which the deadline stops growing at its 120 s cap.
//!
//! Over a real listener and raw sockets, because what is under test is hyper holding a body its client has not read, which an in-process `oneshot` never does.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Request;
use axum::response::IntoResponse;
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::delivery::{delivery_deadline, HoldWhileSending, DELIVERY_MIN_RATE};
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::{build_router, seed, AppState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tower::ServiceExt;

mod common;

/// An upstream answer of `rows` rows of about 114 bytes each in the view. A view has to be well over the 0.7 to 0.9 MB a loopback connection and hyper's write buffer take in between them for hyper to be left holding it while the client reads nothing.
fn large_answer(rows: usize) -> HttpResponse {
    let rows: Vec<serde_json::Value> = (0..rows)
        .map(|i| serde_json::json!({ "id": format!("txn_{i:08}"), "status": "failed", "note": "n".repeat(64) }))
        .collect();
    HttpResponse { status: 200, body: serde_json::json!({ "transactions": rows }), headers: Vec::new(), text: None, memory: Default::default() }
}

/// One execution slot and no queue, so a second call while the slot is held is refused at once.
async fn serve(delivery_timeout: Option<Duration>, rows: usize) -> (SocketAddr, Arc<Limits>) {
    common::isolate_from_the_real_install();
    let http = MockHttpClient::new();
    for _ in 0..3 {
        http.push_response(large_answer(rows));
    }
    let limits = Arc::new(Limits::new(LimitsConfig {
        max_inflight: 1,
        queue_depth: 0,
        queue_wait: Duration::from_millis(100),
        rate_per_min: 60_000,
        rate_burst: 1_000,
        delivery_timeout,
        ..LimitsConfig::default()
    }));
    let state: AppState = AppState::in_memory_seeded_with_http(Arc::new(http)).with_limits(limits.clone());
    // A small send buffer, inherited by every accepted connection, so less of an unread body disappears into the kernel.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(16 * 1024).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(64).unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state, addr);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    (addr, limits)
}

/// A call's head, parsed, and the open socket with whatever of the body arrived alongside the head.
struct Answer {
    status: u16,
    content_length: usize,
    head: String,
    body: Vec<u8>,
    stream: TcpStream,
}

/// Send one invoke and read only as far as the end of the response head, over a socket whose receive buffer is small so the kernel takes in as little of the body as it can.
async fn invoke(addr: SocketAddr) -> Answer {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(16 * 1024).unwrap();
    let mut stream = socket.connect(addr).await.unwrap();
    let body = serde_json::json!({ "capability": "braintree.transactions.search", "params": { "status": "failed" } }).to_string();
    let request = format!(
        "POST /v1/invoke HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        seed::DEMO_TOKEN,
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    let end = loop {
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut chunk)).await.expect("a head").unwrap();
        assert!(n > 0, "the connection ended before a head: {}", String::from_utf8_lossy(&received));
        received.extend_from_slice(&chunk[..n]);
        if let Some(at) = received.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&received[..end]).into_owned();
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status");
    let content_length = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()))
        .expect("a Content-Length, as before the body was wrapped");
    Answer { status, content_length, head, body: received[end..].to_vec(), stream }
}

/// Read until the body is whole or the connection ends.
async fn read_rest(answer: &mut Answer) {
    let mut chunk = vec![0u8; 256 * 1024];
    while answer.body.len() < answer.content_length {
        match tokio::time::timeout(Duration::from_secs(30), answer.stream.read(&mut chunk)).await.expect("the connection made progress") {
            Ok(0) | Err(_) => break,
            Ok(n) => answer.body.extend_from_slice(&chunk[..n]),
        }
    }
}

async fn until_free(limits: &Limits, within: Duration) -> bool {
    tokio::time::timeout(within, async {
        while limits.available_execution_slots() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn a_response_holds_its_slot_until_it_has_been_read() {
    let (addr, limits) = serve(Some(Duration::from_secs(60)), 150_000).await;

    let mut first = invoke(addr).await;
    assert_eq!(first.status, 200, "{}", first.head);
    assert!(first.content_length > 8 * 1024 * 1024, "a view of several MiB: {} bytes", first.content_length);
    // Long enough for hyper to have filled every buffer it can while the client reads nothing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(limits.available_execution_slots(), 0, "the slot is held while the body is undelivered");

    let second = invoke(addr).await;
    assert_eq!(second.status, 429, "a second call is refused while the first body is unread: {}", second.head);

    read_rest(&mut first).await;
    assert_eq!(first.body.len(), first.content_length, "the first body arrives whole");
    let view: serde_json::Value = serde_json::from_slice(&first.body).expect("and well-formed");
    assert!(view.to_string().contains("txn_00149999"), "with the upstream's last row in it");
    assert!(until_free(&limits, Duration::from_secs(5)).await, "the slot is free once the body has been read");

    let mut third = invoke(addr).await;
    assert_eq!(third.status, 200, "a third call is admitted: {}", third.head);
    read_rest(&mut third).await;
    assert_eq!(third.body.len(), third.content_length);
}

#[tokio::test]
async fn a_reader_that_stalls_gives_its_slot_back_at_the_delivery_deadline() {
    let floor = Duration::from_millis(300);
    // About 1.25 MB: enough to stall over loopback, small enough that its deadline at the minimum rate is under 10 s.
    let (addr, limits) = serve(Some(floor), 11_000).await;

    let started = Instant::now();
    let mut stalled = invoke(addr).await;
    assert_eq!(stalled.status, 200, "{}", stalled.head);
    let deadline = delivery_deadline(floor, Some(stalled.content_length as u64));
    assert!(deadline < Duration::from_secs(10), "{deadline:?}");
    assert_eq!(limits.available_execution_slots(), 0, "held while the body is unread");
    assert!(until_free(&limits, deadline + Duration::from_secs(10)).await, "the deadline gives the slot back with the client doing nothing");
    assert!(started.elapsed() >= deadline, "and not before the deadline its length set: {:?} of {deadline:?}", started.elapsed());

    let mut next = invoke(addr).await;
    assert_eq!(next.status, 200, "the next call is admitted: {}", next.head);
    read_rest(&mut next).await;
    assert_eq!(next.body.len(), next.content_length, "and its body arrives whole");

    // The stalled client finds a short body and a closed connection, never a well-formed document cut short.
    read_rest(&mut stalled).await;
    assert!(
        stalled.body.len() < stalled.content_length,
        "{} of {} bytes: the connection was cut rather than the body ended early",
        stalled.body.len(),
        stalled.content_length
    );
}

/// The floor is 1 s and the client takes about 3 s, reading at about ten times the minimum rate: a deadline fixed at the floor cut a reader like this one, so a slow link could lose an answer whose call had already run.
#[tokio::test]
async fn a_reader_making_steady_progress_gets_the_whole_body_past_the_floor() {
    let floor = Duration::from_secs(1);
    let (addr, limits) = serve(Some(floor), 32_000).await;

    let started = Instant::now();
    let mut paced = invoke(addr).await;
    assert_eq!(paced.status, 200, "{}", paced.head);
    let deadline = delivery_deadline(floor, Some(paced.content_length as u64));
    assert!(deadline > Duration::from_secs(20), "about 3.6 MB at 128 KiB/s: {deadline:?}");

    // 64 KiB every 50 ms, about 1.2 MiB/s.
    let mut chunk = vec![0u8; 64 * 1024];
    while paced.body.len() < paced.content_length {
        let mut taken = 0;
        while taken < chunk.len() && paced.body.len() < paced.content_length {
            let want = (chunk.len() - taken).min(paced.content_length - paced.body.len());
            match tokio::time::timeout(Duration::from_secs(10), paced.stream.read(&mut chunk[..want])).await.expect("progress") {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    paced.body.extend_from_slice(&chunk[..n]);
                    taken += n;
                }
            }
        }
        if taken == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let took = started.elapsed();
    assert_eq!(paced.body.len(), paced.content_length, "the whole body arrived, after {took:?}");
    assert!(took >= 2 * floor, "the transfer outlasted the floor: {took:?}");
    assert!((paced.content_length as f64 / took.as_secs_f64()) > 4.0 * DELIVERY_MIN_RATE as f64, "at well above the minimum rate");
    let view: serde_json::Value = serde_json::from_slice(&paced.body).expect("well-formed");
    assert!(view.to_string().contains("txn_00031999"), "with the upstream's last row in it");
    assert!(until_free(&limits, Duration::from_secs(5)).await);
}

/// The hook another per-call charge reaches the response through: a guard a handler attaches is taken off the response by the execution middleware and held with the slot until the body has been read.
#[tokio::test]
async fn a_guard_a_handler_attaches_is_held_with_the_slot_until_the_body_is_read() {
    let state = common::seeded().with_limits(Arc::new(Limits::new(LimitsConfig {
        max_inflight: 1,
        queue_depth: 0,
        rate_per_min: 60_000,
        rate_burst: 1_000,
        ..LimitsConfig::default()
    })));
    let limits = state.limits.clone();
    let charges = Arc::new(Semaphore::new(1));
    let handler_charges = charges.clone();
    let app = axum::Router::new()
        .route(
            "/v1/invoke",
            axum::routing::post(move || {
                let charges = handler_charges.clone();
                async move {
                    let mut response = axum::Json(serde_json::json!({ "pad": "p".repeat(512 * 1024) })).into_response();
                    HoldWhileSending::attach(&mut response, charges.try_acquire_owned().expect("a free charge"));
                    response
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(state, permaura_gateway::limits::admit_execution));
    let request = Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert!(response.extensions().get::<HoldWhileSending>().is_none(), "the middleware took the guards off the response");
    assert_eq!(charges.available_permits(), 0, "the handler's charge is held while the body is unread");
    assert_eq!(limits.available_execution_slots(), 0, "and so is the slot");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(body.len() > 512 * 1024);
    assert_eq!(charges.available_permits(), 1, "both are released once the body has been read");
    assert_eq!(limits.available_execution_slots(), 1);
}
