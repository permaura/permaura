//! Reading an agent's GraphQL documents asks the memory pool for nothing beyond the room the call's params already hold, so reading them never makes a call wait for room while it holds some: not at its gate, not when it is explained, and not when a human approves it. Something other than its documents can still make a call wait while it holds its params' room: a Vercel capability's response projection reserves its tree with the pool wait (`EnforcementService::projected`, as in gateway 1.3.52), and vercel.deployments.create forwards its params as its body, so that call can carry a document too. The brackets the reader keeps fit in the room the params reserve for the body written from them. The aliases of redacted fields a response is redacted under take room from the pool only past a fixed allowance, and only when it is there at once; with none the call still runs and its whole response is redacted.
//!
//! Every credential and upstream here is synthetic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{graphql, AuthScheme, HttpMethod, HttpResponse, HttpSpec, MemoryPool, MockHttpClient, MAX_RESPONSE_ALIASES};
use permaura_gateway::limits::LimitsConfig;
use permaura_gateway::memory::{held_room, params_room, AgentParams, MemoryBudget};
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const MIB: u64 = 1024 * 1024;

/// What fits in the 2 MiB execution body beside the rest of the call.
const DOC: usize = 2 * MIB as usize - 256;

/// Low risk and a list, so it runs at once and its request check reads the document.
const RUNS: &str = "github.pull_requests.list";

/// High risk, so the seeded policy holds it for a human.
const HELD: &str = "github.pull_requests.create";

/// A service over the seeded estate, its two GitHub capabilities forwarding `query`, which is held as GraphQL when it reads as one, and answered by `http`.
fn service(http: MockHttpClient, config: &LimitsConfig) -> EnforcementService {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    for id in [RUNS, HELD] {
        let mut cap = store.get_capability(id).unwrap().expect("the seeded capability");
        cap.http = Some(HttpSpec {
            method: HttpMethod::Post,
            base_url: "https://api.probe.test".to_string(),
            path: "/v1/search".to_string(),
            body_params: vec!["query".to_string()],
            auth: AuthScheme::Bearer,
            ..HttpSpec::default()
        });
        store.put_capability(cap).unwrap();
        common::file_as_imported(store.as_ref(), id);
    }
    EnforcementService::new(store, Arc::new(http)).with_memory_budget(MemoryBudget::from_config(config))
}

fn params(document: &str) -> Value {
    json!({ "query": document })
}

/// `{ a: secret b: secret ... }` with `count` distinct aliases of a field every call redacts.
fn aliases_of_secret(count: usize) -> String {
    let mut doc = String::from("{");
    for n in 0..count {
        doc.push_str(&format!("a{n}: secret "));
    }
    doc.push('}');
    doc
}

/// The room the pool hands out for `bytes`: whole KiB.
fn room(bytes: u64) -> u64 {
    bytes.div_ceil(1024) * 1024
}

/// Everything in `pool` but `leave` bytes, held until the charge is dropped.
async fn hog(pool: &MemoryPool, leave: u64) -> permaura_gateway::connectors::MemoryCharge {
    pool.reserve(pool.max_bytes() - leave, Duration::ZERO).await.expect("an idle pool")
}

async fn post(state: &AppState, uri: &str, body: String) -> (StatusCode, Value) {
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
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A larger reservation queues for the room a call already holds, then a call whose capability has no response projection is invoked: reading its document must not make it wait behind the reservation for more, which would leave both stalled for the whole pool wait. A call whose documents alias a few redacted fields is redacted under them as it always was; nothing here needs room from the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reading_a_document_never_makes_a_call_wait_behind_a_reservation_for_the_room_it_holds() {
    let wait = Duration::from_millis(1500);
    let config = LimitsConfig { json_pool_wait: wait, ..LimitsConfig::defaults_for(true) };
    let http = MockHttpClient::new();
    let svc = service(http.clone(), &config);
    let pool = svc.memory().pool().clone();
    let max = pool.max_bytes();
    let session = svc.store().get_session("sess_demo").unwrap().unwrap();

    for (shape, document) in [
        ("an ordinary query", "query Viewer { viewer { id } }".to_string()),
        ("a search term", "red shoes".to_string()),
        ("an alias of a redacted field", "{ s: secret id }".to_string()),
        ("'a:b ' x 64 Ki", "a:b ".repeat(64 * 1024)),
        ("brackets 64 Ki deep", format!("query {{ a {}", "{".repeat(64 * 1024))),
    ] {
        http.push_response(HttpResponse::json(200, json!({ "s": "a synthetic secret", "id": 1 })));
        let charge = pool.reserve(4 * MIB, Duration::ZERO).await.unwrap();
        let call = AgentParams::charged(params(&document), charge);
        let larger = tokio::spawn({
            let pool = pool.clone();
            async move { pool.reserve(max - 2 * MIB, wait).await.is_ok() }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        let outcome = svc.invoke_admitted(&session, RUNS, call, None, ExecutionLocation::LocalOnly).await;
        let took = started.elapsed();
        assert!(larger.await.unwrap(), "{shape}: the larger reservation got its room once the call was done");
        assert!(took < wait / 2, "{shape}: the call ran in {took:?}, not behind the reservation");
        let result = match outcome {
            Ok(InvokeOutcome::Allowed { result, .. }) => result,
            Ok(_) => panic!("{shape}: not allowed"),
            Err(e) => panic!("{shape}: {e}"),
        };
        let result = result.to_value_unbounded();
        let expected = if document.contains("s: secret") { "[redacted]" } else { "a synthetic secret" };
        assert_eq!(result, json!({ "s": expected, "id": 1 }), "{shape}");
        assert_eq!(pool.available_bytes(), max, "{shape}: all of it given back");
    }
}

/// The reader keeps no more than its stack of open brackets, which fits in the room the params reserve for the body written from them: nothing is written while it reads. So a call, its explanation and its approval need no other room, and with none to spare they still run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_its_explanation_and_its_approval_need_only_their_params_room() {
    let config = LimitsConfig { json_pool_wait: Duration::from_millis(100), ..LimitsConfig::defaults_for(true) };
    let http = MockHttpClient::new();
    let gw = AppState::new(service(http.clone(), &config));
    let pool = gw.service.memory().pool().clone();
    let max = pool.max_bytes();

    for (shape, document) in [
        ("'{' x 2 MiB", "{".repeat(DOC)),
        ("brackets 2 MiB deep", format!("query {{ a {}", "{".repeat(DOC - 12))),
        ("'a:b ' x 512 Ki", "a:b ".repeat(DOC / 4)),
        ("'{a:b a:b ...}'", format!("{{{}}}", "a:b ".repeat(DOC / 4 - 1))),
        ("an ordinary query", "query Viewer { viewer { id name s: secret } }".to_string()),
        ("an empty one", String::new()),
    ] {
        let body = json!({ "capability": RUNS, "params": params(&document) }).to_string();
        let (tree, reserved) = params_room(body.as_bytes());
        assert!(graphql::read_bytes(&document) <= reserved - tree, "{shape}: the stack fits in the room for the body written from the params");

        let held = hog(&pool, room(reserved)).await;
        let (status, answer) = post(&gw, "/v1/invoke", body).await;
        drop(held);
        assert_eq!(status, StatusCode::OK, "{shape}: {answer}");

        let explain = json!({ "capability": RUNS, "params": params(&document), "explain_only": true }).to_string();
        let held = hog(&pool, room(params_room(explain.as_bytes()).1)).await;
        let (status, answer) = post(&gw, "/v1/invoke", explain).await;
        drop(held);
        assert_eq!(status, StatusCode::OK, "{shape}: {answer}");
        assert_eq!(answer["decision"]["decision"], "allow", "{shape}: {answer}");
        assert_eq!(pool.available_bytes(), max, "{shape}");
    }

    let document = format!("{{{}}}", "a:b ".repeat(64 * 1024));
    let (status, answer) = post(&gw, "/v1/invoke", json!({ "capability": HELD, "params": params(&document) }).to_string()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");
    let id = answer["approval_id"].as_str().expect("the hold names its approval").to_string();
    let row = gw.service.store().get_approval(&id).unwrap().unwrap();
    let held = hog(&pool, room(held_room(row.params.get().as_bytes()) + gw.service.memory().resolution_bytes())).await;
    let sent = http.requests().len();
    let (status, answer) = post(&gw, "/v1/approvals", json!({ "approval_id": id, "approve": true }).to_string()).await;
    drop(held);
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(gw.service.store().get_approval(&id).unwrap().unwrap().status, "approved");
    assert_eq!(http.requests().len(), sent + 1);
    assert_eq!(pool.available_bytes(), max);
}

/// Aliases past the uncharged allowance take room from the pool while the response is read, and only when it is there at once. With none the call is not refused: it runs, and its whole response is redacted. Past the most aliases kept, the same, whatever room there is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aliases_the_pool_has_no_room_for_redact_the_whole_response() {
    let config = LimitsConfig { json_pool_wait: Duration::from_millis(100), ..LimitsConfig::defaults_for(true) };
    let http = MockHttpClient::new();
    let svc = service(http.clone(), &config);
    let pool = svc.memory().pool().clone();
    let max = pool.max_bytes();
    let session = svc.store().get_session("sess_demo").unwrap().unwrap();
    let answer = json!({ "a0": "a synthetic secret", "a1": "another", "id": 1 });
    let charged = 4 * MIB;

    let invoke = |document: String| {
        let (svc, pool, session, http, answer) = (svc.clone(), pool.clone(), session.clone(), http.clone(), answer.clone());
        async move {
            http.push_response(HttpResponse::json(200, answer));
            let charge = pool.reserve(charged, Duration::ZERO).await.unwrap();
            let sent = http.requests().len();
            let outcome = svc.invoke_admitted(&session, RUNS, AgentParams::charged(params(&document), charge), None, ExecutionLocation::LocalOnly).await;
            assert_eq!(http.requests().len(), sent + 1, "the call ran");
            match outcome {
                Ok(InvokeOutcome::Allowed { result, status, .. }) => {
                    assert_eq!(status, 200);
                    result.to_value_unbounded()
                }
                Ok(_) => panic!("not allowed"),
                Err(e) => panic!("{e}"),
            }
        }
    };

    let many = aliases_of_secret(MAX_RESPONSE_ALIASES as usize / 2);
    assert_eq!(invoke(many.clone()).await, json!({ "a0": "[redacted]", "a1": "[redacted]", "id": 1 }), "with room, each alias is redacted");
    let held = hog(&pool, charged).await;
    assert_eq!(invoke(many).await, json!("[redacted]"), "with no room the whole response is");
    assert_eq!(invoke(aliases_of_secret(2)).await, json!({ "a0": "[redacted]", "a1": "[redacted]", "id": 1 }), "a few aliases need no room");
    drop(held);
    assert_eq!(invoke(aliases_of_secret(MAX_RESPONSE_ALIASES as usize + 1)).await, json!("[redacted]"), "past the most kept");
    assert_eq!(invoke(aliases_of_secret(MAX_RESPONSE_ALIASES as usize)).await["a1"], "[redacted]");
    assert_eq!(pool.available_bytes(), max);
}
