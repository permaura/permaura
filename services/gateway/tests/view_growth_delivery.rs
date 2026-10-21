//! The room a view longer than its slot's share takes in the view-growth budget is held with the response until the response has been sent, on `/v1/invoke` and on `/mcp`, and given back when the body has been read, when the client hangs up and at the delivery deadline; a relayed invoke holds it only until its result has been framed. Released when the handler returned, the budget bounded executions while up to every slot's growth sat unsent in hyper.
//!
//! A binary of its own, because it lowers the process-wide response cap (read once) so a view past its slot's share is about a megabyte rather than 13 MiB, and a stalled reader's deadline is seconds rather than the 120 s cap. Over a real listener and raw sockets, because what is under test is hyper holding a body its client has not read.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use permaura_core::{ExecutionLocation, Principal};
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::delivery::delivery_deadline;
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::relay::handle_invoke;
use permaura_gateway::{build_router, seed, AppState};
use permaura_relay::{request_hash, InvokeOrigin, InvokeRequest, RelayOutcome, SessionCtx};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod common;

const RESPONSE_CAP: u64 = 320 * 1024;
const CAPABILITY: &str = "braintree.transactions.search";
const SECRET: &str = "sec_braintree_prod";

fn setup() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| std::env::set_var("PERMAURA_HTTP_MAX_RESPONSE_BYTES", RESPONSE_CAP.to_string()));
    common::isolate_from_the_real_install();
    assert_eq!(permaura_gateway::connectors::http_max_response_bytes(), RESPONSE_CAP, "nothing read the cap before it was lowered");
}

/// `[1e15,...]` just under the response cap: serde_json writes each number as `1000000000000000.0`, so the view is about 3.8 times the body, past the 2.6 times its slot holds.
fn exponent_numbers() -> String {
    let mut text = String::from("[");
    while (text.len() + 6) as u64 <= RESPONSE_CAP {
        text.push_str("1e15,");
    }
    text.pop();
    text.push(']');
    text
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Invoke,
    Mcp,
}

struct Served {
    addr: SocketAddr,
    state: AppState,
    limits: Arc<Limits>,
}

impl Served {
    fn growth_free(&self) -> bool {
        let growth = self.state.service.memory().view_growth();
        growth.available_bytes() == growth.max_bytes()
    }

    async fn until_growth_free(&self, within: Duration) -> bool {
        tokio::time::timeout(within, async {
            while !self.growth_free() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    }
}

async fn serve(delivery_timeout: Duration) -> Served {
    setup();
    let http = MockHttpClient::new();
    http.push_response(HttpResponse { status: 200, body: serde_json::Value::Null, text: Some(exponent_numbers()), headers: Vec::new(), memory: Default::default() });
    let limits = Arc::new(Limits::new(LimitsConfig {
        max_inflight: 1,
        queue_depth: 0,
        queue_wait: Duration::from_millis(100),
        rate_per_min: 60_000,
        rate_burst: 1_000,
        delivery_timeout: Some(delivery_timeout),
        ..LimitsConfig::default()
    }));
    let state: AppState = AppState::in_memory_seeded_with_http(Arc::new(http)).with_limits(limits.clone());
    // A small send buffer, inherited by every accepted connection, so less of an unread body disappears into the kernel.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(16 * 1024).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(64).unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state.clone(), addr);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    Served { addr, state, limits }
}

struct Answer {
    status: u16,
    content_length: usize,
    head: String,
    body: Vec<u8>,
    stream: TcpStream,
}

/// Call the capability over `route` and read only as far as the end of the response head, over a socket whose receive buffer is small so the kernel takes in as little of the body as it can.
async fn call(addr: SocketAddr, route: Route) -> Answer {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(16 * 1024).unwrap();
    let mut stream = socket.connect(addr).await.unwrap();
    let (path, body) = match route {
        Route::Invoke => ("/v1/invoke", serde_json::json!({ "capability": CAPABILITY, "params": { "status": "failed" } })),
        Route::Mcp => (
            "/mcp",
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": CAPABILITY, "arguments": { "status": "failed" } } }),
        ),
    };
    let body = body.to_string();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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
        .expect("a Content-Length");
    Answer { status, content_length, head, body: received[end..].to_vec(), stream }
}

async fn read_rest(answer: &mut Answer) {
    let mut chunk = vec![0u8; 256 * 1024];
    while answer.body.len() < answer.content_length {
        match tokio::time::timeout(Duration::from_secs(30), answer.stream.read(&mut chunk)).await.expect("the connection made progress") {
            Ok(0) | Err(_) => break,
            Ok(n) => answer.body.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A call whose long view is charged to the growth budget and whose body is still unread, so hyper is left holding the rest of it.
async fn unread(served: &Served, route: Route) -> Answer {
    assert!(served.growth_free(), "nothing is charged before the call");
    let answer = call(served.addr, route).await;
    assert_eq!(answer.status, 200, "{}", answer.head);
    assert!(answer.content_length as u64 > RESPONSE_CAP * 26 / 10, "a view past its slot's share: {} bytes", answer.content_length);
    // Long enough for hyper to have filled every buffer it can while the client reads nothing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!served.growth_free(), "{route:?}: the view's growth room is held while the body is unread");
    assert_eq!(served.limits.available_execution_slots(), 0, "and so is the slot");
    answer
}

async fn released_once_read(route: Route) {
    let served = serve(Duration::from_secs(60)).await;
    let mut answer = unread(&served, route).await;
    read_rest(&mut answer).await;
    assert_eq!(answer.body.len(), answer.content_length, "the body arrives whole");
    serde_json::from_slice::<serde_json::Value>(&answer.body).expect("and well-formed");
    assert!(served.until_growth_free(Duration::from_secs(5)).await, "{route:?}: the growth room is given back once the body has been read");
}

async fn released_on_hang_up(route: Route) {
    let floor = Duration::from_secs(60);
    let served = serve(floor).await;
    let answer = unread(&served, route).await;
    let hung_up = Instant::now();
    drop(answer);
    assert!(served.until_growth_free(Duration::from_secs(10)).await, "{route:?}: a client that hung up gives the growth room back");
    assert!(hung_up.elapsed() < floor, "with the hang-up, not the deadline");
}

async fn released_at_the_deadline(route: Route) {
    let floor = Duration::from_millis(300);
    let served = serve(floor).await;
    let started = Instant::now();
    let mut answer = unread(&served, route).await;
    let deadline = delivery_deadline(floor, Some(answer.content_length as u64));
    assert!(deadline < Duration::from_secs(25), "{deadline:?}");
    assert!(served.until_growth_free(deadline + Duration::from_secs(10)).await, "{route:?}: the deadline gives the growth room back with the client doing nothing");
    assert!(started.elapsed() >= deadline, "and not before the deadline its length set: {:?} of {deadline:?}", started.elapsed());
    read_rest(&mut answer).await;
    assert!(answer.body.len() < answer.content_length, "the stalled client gets a short body: {} of {}", answer.body.len(), answer.content_length);
}

#[tokio::test]
async fn invoke_holds_the_growth_room_until_the_body_has_been_read() {
    released_once_read(Route::Invoke).await;
}

#[tokio::test]
async fn mcp_holds_the_growth_room_until_the_body_has_been_read() {
    released_once_read(Route::Mcp).await;
}

#[tokio::test]
async fn invoke_gives_the_growth_room_back_when_the_client_hangs_up() {
    released_on_hang_up(Route::Invoke).await;
}

#[tokio::test]
async fn mcp_gives_the_growth_room_back_when_the_client_hangs_up() {
    released_on_hang_up(Route::Mcp).await;
}

#[tokio::test]
async fn invoke_gives_the_growth_room_back_at_the_delivery_deadline() {
    released_at_the_deadline(Route::Invoke).await;
}

#[tokio::test]
async fn mcp_gives_the_growth_room_back_at_the_delivery_deadline() {
    released_at_the_deadline(Route::Mcp).await;
}

#[tokio::test]
async fn a_relayed_invoke_gives_the_growth_room_back_once_its_result_has_been_framed() {
    let served = serve(Duration::from_secs(60)).await;
    let store = served.state.service.store();
    let mut secret = store.get_secret(SECRET).unwrap().expect("the seeded secret");
    secret.metadata.allowed_execution_locations = vec![ExecutionLocation::RemoteAllowed];
    store.put_secret(secret).unwrap();
    let params = serde_json::json!({ "status": "failed" });
    let req = InvokeRequest {
        job_id: "job_growth".into(),
        session_ctx: SessionCtx {
            cp_session_id: "cp_sess_growth".into(),
            org_id: "org_x".into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: CAPABILITY.into(),
        request_hash: request_hash(CAPABILITY, &params),
        params,
        reason: Some("relayed search".into()),
        execution_location: ExecutionLocation::RemoteAllowed,
        deadline_ms: 9_999_999_999_999,
    };
    assert!(served.growth_free(), "nothing is charged before the call");
    let reply = handle_invoke(&served.state.service, "org_x", req).await;
    let RelayOutcome::Allowed { result, .. } = reply.outcome else { panic!("the relayed call runs: {:?}", reply.outcome) };
    let framed = serde_json::to_string(&result).unwrap().len() as u64;
    assert!(framed > RESPONSE_CAP * 26 / 10, "a view past its slot's share, so it took growth room: {framed} bytes");
    assert!(served.growth_free(), "given back with the result framed, before the reply is sent over the relay");
}
