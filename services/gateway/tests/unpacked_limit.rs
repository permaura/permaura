//! Every agent call's params get one ceiling on their unpacked size, the gateway's estimate of their tree, whether or not the call needs approval. It is the JSON pool less 64 MiB, 128 MiB on hosted defaults and 448 MiB on self-run ones, and it replaced the 1.3.52 hold ceiling, under which some params ran unheld and were refused held.
//!
//! Every credential here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::json_budget::estimate;
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::memory::{held_room, MemoryBudget};
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const MIB: u64 = 1024 * 1024;
/// High risk, so the seeded policy holds it for a human.
const HELD: &str = "github.pull_requests.create";
/// Low risk, so the seeded policy runs it at once. It takes the same params as [`HELD`].
const UNHELD: &str = "github.pull_requests.list";

fn gateway(config: &LimitsConfig) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let service = EnforcementService::new(store, Arc::new(MockHttpClient::new())).with_memory_budget(MemoryBudget::from_config(config));
    AppState::new(service).with_limits(Arc::new(Limits::new(config.clone())))
}

async fn send(state: &AppState, body: String) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A `/v1/invoke` body for `capability` whose params carry `rows` copies of `row` as a list.
fn body(capability: &str, row: &str, rows: usize) -> String {
    let mut list = String::with_capacity(rows * (row.len() + 1) + 2);
    list.push('[');
    for i in 0..rows {
        if i > 0 {
            list.push(',');
        }
        list.push_str(row);
    }
    list.push(']');
    format!(r#"{{"capability":"{capability}","params":{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","extra":{list}}}}}"#)
}

/// The most rows of `row` whose body estimates at or under `limit` and fits `max_body` bytes.
fn rows_under(row: &str, limit: u64, max_body: usize) -> usize {
    let (mut low, mut high) = (0usize, max_body / (row.len() + 1));
    while low < high {
        let mid = (low + high).div_ceil(2);
        let text = body(HELD, row, mid);
        if text.len() <= max_body && estimate(text.as_bytes()) <= limit {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}

fn cut(v: &Value) -> String {
    v.to_string().chars().take(300).collect()
}

fn pending(state: &AppState) -> usize {
    state.service.store().list_approvals(Some("pending")).unwrap().len()
}

fn audit_len(state: &AppState) -> usize {
    state.service.store().audit_events(None).unwrap().len()
}

/// The same params, sent to a call the policy runs at once and to one it holds, are admitted both ways and the held one is approved.
async fn admitted_both_ways(state: &AppState, row: &str, rows: usize, what: &str) {
    let id = admitted_both_ways_and_held(state, body(UNHELD, row, rows), body(HELD, row, rows), what).await;
    let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(approved.status, "approved", "{what}");
}

/// The unheld body runs and the held one is held; the hold's id.
async fn admitted_both_ways_and_held(state: &AppState, unheld: String, held: String, what: &str) -> String {
    let (status, ran) = send(state, unheld).await;
    assert_eq!(status, StatusCode::OK, "{what}, unheld: {}", cut(&ran));
    let (status, answer) = send(state, held).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{what}, held: {}", cut(&answer));
    answer["approval_id"].as_str().unwrap().to_string()
}

/// Approving the held call `id` runs it when its tree and the room for its text as stored ([`held_room`]) fit the pool, beside an execution's buffers or, when those could never fit beside them, under an execution slot, and writes its params back into its row as they were held. Otherwise it is refused with a 413 telling the approver to deny it, the call stays pending, and a denial lands. Either way the room and the slot are given back. Whether it ran.
async fn approve_or_deny(state: &AppState, config: &LimitsConfig, id: &str, what: &str) -> bool {
    let row = state.service.store().get_approval(id).unwrap().unwrap();
    let fits = held_room(row.params.get().as_bytes()) <= config.json_pool_bytes;
    match state.service.resolve_approval(id, true, "bearer", Some("operator")).await {
        Ok(approved) => {
            assert!(fits, "{what}: approved past the pool");
            assert_eq!(approved.status, "approved", "{what}");
            assert!(approved.params.get() == row.params.get(), "{what}: the row keeps the params it was held with");
        }
        Err(error) => {
            let error = error.to_string();
            assert!(!fits, "{what}: refused though it fits: {error}");
            assert!(error.contains("can never run here") && error.contains("deny it"), "{what}: {error}");
            assert_eq!(state.service.store().get_approval(id).unwrap().unwrap().status, "pending", "{what}");
            let denied = state.service.resolve_approval(id, false, "bearer", Some("operator")).await.unwrap();
            assert_eq!(denied.status, "denied", "{what}");
        }
    }
    let pool = state.service.memory().pool();
    assert_eq!(pool.available_bytes(), pool.max_bytes(), "{what}: the approval gave its room back");
    assert_eq!(state.limits.available_execution_slots(), config.max_inflight, "{what}: and its slot");
    fits
}

/// The same params are refused both ways with a 413 that names their size and the ceiling, and nothing is written.
async fn refused_both_ways(state: &AppState, row: &str, rows: usize, what: &str) {
    let (pending_before, audit_before) = (pending(state), audit_len(state));
    let size = estimate(body(HELD, row, rows).as_bytes());
    for capability in [UNHELD, HELD] {
        let (status, answer) = send(state, body(capability, row, rows)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{what}, {capability}: {}", cut(&answer));
        let error = answer["error"].as_str().unwrap_or_default();
        assert!(error.contains(&state.service.memory().unpacked_limit().to_string()), "names the ceiling: {error}");
        let named = estimate(body(capability, row, rows).as_bytes());
        assert!(error.contains(&named.to_string()), "names the call's size, {named}: {error}");
        assert!(named.abs_diff(size) < 64, "{capability} and {HELD} bodies estimate alike");
        assert!(error.contains("split it into smaller calls"), "tells the agent what to do: {error}");
    }
    assert_eq!((pending(state), audit_len(state)), (pending_before, audit_before), "{what}: nothing was written");
}

/// On hosted and self-run defaults and with each knob moved, a body just under the ceiling is admitted held and unheld, and one just over it (where the body limit lets a body reach it) is refused both ways. Only the pool moves the ceiling, and on a pool under 128 MiB it is half the pool, never nothing. The held call is approved and runs under every knob: its params reserve no more than they reserved unheld, and its execution's buffers are reserved beside them or, on the 32 and 16 MiB pools where they could never fit beside them, are in an execution slot.
#[tokio::test]
async fn held_and_unheld_calls_are_admitted_or_refused_alike_under_every_knob() {
    let hosted = LimitsConfig::defaults_for(true);
    let configs = [
        ("hosted defaults", hosted.clone(), 128 * MIB),
        ("self-run defaults", LimitsConfig::defaults_for(false), 448 * MIB),
        ("a hosted pool lowered to 128 MiB", LimitsConfig { json_pool_bytes: 128 * MIB, ..hosted.clone() }, 64 * MIB),
        ("a hosted pool lowered to 96 MiB", LimitsConfig { json_pool_bytes: 96 * MIB, ..hosted.clone() }, 48 * MIB),
        ("a hosted pool lowered to 32 MiB", LimitsConfig { json_pool_bytes: 32 * MIB, ..hosted.clone() }, 16 * MIB),
        ("a hosted pool at its 16 MiB floor", LimitsConfig { json_pool_bytes: 16 * MIB, ..hosted.clone() }, 8 * MIB),
        ("a hosted body limit raised to 16 MiB", LimitsConfig { body_exec_bytes: 16 * MIB as usize, ..hosted.clone() }, 128 * MIB),
        ("a hosted body limit raised to 40 MiB", LimitsConfig { body_exec_bytes: 40 * MIB as usize, ..hosted.clone() }, 128 * MIB),
    ];
    let one_letter = r#"{"a":1}"#;
    for (what, config, ceiling) in configs {
        let state = gateway(&config);
        assert_eq!(state.service.memory().unpacked_limit(), ceiling, "{what}");
        let max_body = config.body_exec_bytes;
        let under = rows_under(one_letter, ceiling, max_body);
        assert!(under > 0);
        let reached = estimate(body(HELD, one_letter, under + 1).as_bytes()) > ceiling && body(HELD, one_letter, under + 1).len() <= max_body;
        eprintln!("{what}: ceiling {} MiB; {} rows of {one_letter} estimate {} bytes", ceiling / MIB, under, estimate(body(HELD, one_letter, under).as_bytes()));
        let what_under = format!("{what}, just under the ceiling");
        let id = admitted_both_ways_and_held(&state, body(UNHELD, one_letter, under), body(HELD, one_letter, under), &what_under).await;
        assert!(approve_or_deny(&state, &config, &id, &what_under).await, "{what}: a call at the ceiling that ran unheld is approved");
        if reached {
            refused_both_ways(&state, one_letter, under + 1, &format!("{what}, one row over the ceiling")).await;
        } else {
            assert_eq!(what, "self-run defaults", "only the self-run ceiling is out of a 2 MiB body's reach");
        }
    }
}

/// Only the pool moves the one ceiling, and a small pool keeps half of itself, so calls 1.3.52 ran are not refused for a raised body limit or a small pool: with a hosted body limit of 32 MiB a 20 MiB string param (a base64 file) runs and is held and approved, and so does a 30 MiB one, which reserves 165 MiB unheld and which approving reserves 30 + 30 + 2 x 30 MiB for, with the execution's 50 MiB beside it, where four copies of its text would have passed the pool; with one of 40 MiB, where the clamp this replaced put the ceiling at nothing, a small call runs and is held and approved; on a pool at its 16 MiB floor a small call runs and is held and approved; and on a 32 MiB pool a list of 20,000 id rows (under 256 KiB, over the 8 MiB the clamp left as a tree) runs.
#[tokio::test]
async fn calls_are_not_refused_for_a_raised_body_limit_or_a_small_pool() {
    let hosted = LimitsConfig::defaults_for(true);
    let string = |capability: &str, bytes: usize| format!(r#"{{"capability":"{capability}","params":{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","extra":"{}"}}}}"#, "A".repeat(bytes));
    let config = LimitsConfig { body_exec_bytes: 32 * MIB as usize, ..hosted.clone() };
    let state = gateway(&config);
    let id = admitted_both_ways_and_held(&state, string(UNHELD, 20 * MIB as usize), string(HELD, 20 * MIB as usize), "a 32 MiB body limit, 20 MiB of string").await;
    assert!(approve_or_deny(&state, &config, &id, "a 32 MiB body limit, 20 MiB of string").await);
    let base64 = |capability: &str| format!(r#"{{"capability":"{capability}","params":{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","extra":"{}"}}}}"#, "QUJD+/09".repeat(30 * MIB as usize / 8));
    let (_, unheld) = permaura_gateway::memory::params_room(base64(UNHELD).as_bytes());
    assert!(unheld > 160 * MIB && unheld < 170 * MIB, "{unheld}");
    let id = admitted_both_ways_and_held(&state, base64(UNHELD), base64(HELD), "a 32 MiB body limit, 30 MiB of base64").await;
    assert!(approve_or_deny(&state, &config, &id, "a 32 MiB body limit, 30 MiB of base64").await, "a 30 MiB base64 param that ran unheld is approved");

    for (what, config) in [
        ("a 40 MiB body limit", LimitsConfig { body_exec_bytes: 40 * MIB as usize, ..hosted.clone() }),
        ("a 16 MiB pool", LimitsConfig { json_pool_bytes: 16 * MIB, ..hosted.clone() }),
    ] {
        let state = gateway(&config);
        let id = admitted_both_ways_and_held(&state, string(UNHELD, 1024), string(HELD, 1024), what).await;
        assert!(approve_or_deny(&state, &config, &id, what).await, "{what}");
    }

    let state = gateway(&LimitsConfig { json_pool_bytes: 32 * MIB, ..hosted.clone() });
    let ids = body(UNHELD, r#"{"id":1}"#, 0).replace("[]", &format!("[{}]", (0..20_000).map(|i| format!(r#"{{"id":{i}}}"#)).collect::<Vec<_>>().join(",")));
    let tree = estimate(ids.as_bytes());
    assert!(ids.len() < 256 * 1024 && tree > 8 * MIB && tree <= state.service.memory().unpacked_limit(), "{} bytes, {tree} as a tree", ids.len());
    let (status, answer) = send(&state, ids).await;
    assert_eq!(status, StatusCode::OK, "{}", cut(&answer));
}

/// A call under the one ceiling passes it and still meets the pool, as on 1.3.52: on a pool at its 16 MiB floor, whose ceiling is 8 MiB, a body near 2 MiB with a tree under 8 MiB reserves its tree and room for the body written from it, more than the pool, so it is refused by the pool's 413 held and unheld, never by the ceiling's, and nothing is written.
#[tokio::test]
async fn a_call_under_the_ceiling_can_still_be_refused_by_the_pool() {
    let state = gateway(&LimitsConfig { json_pool_bytes: 16 * MIB, ..LimitsConfig::defaults_for(true) });
    let ceiling = state.service.memory().unpacked_limit();
    assert_eq!(ceiling, 8 * MIB);
    let make = |capability: &str| {
        let rows = vec![r#"{"a":1}"#; 8_000].join(",");
        format!(r#"{{"capability":"{capability}","params":{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","note":"{}","extra":[{rows}]}}}}"#, "A".repeat(1_960_000))
    };
    let (tree, room) = permaura_gateway::memory::params_room(make(HELD).as_bytes());
    assert!(tree <= ceiling && room > 16 * MIB, "a {tree}-byte tree reserving {room} bytes");
    let (pending_before, audit_before) = (pending(&state), audit_len(&state));
    for capability in [UNHELD, HELD] {
        let (status, answer) = send(&state, make(capability)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{capability}: {}", cut(&answer));
        let error = answer["error"].as_str().unwrap_or_default();
        assert!(error.contains("budget for the documents its calls hold") && !error.contains("once unpacked"), "{capability}: the pool's refusal, not the ceiling's: {error}");
    }
    assert_eq!((pending(&state), audit_len(&state)), (pending_before, audit_before), "nothing was written");
}

/// 2 MiB of `{"x":1,"y":2}` rows, the costliest realistic shape measured at the body limit, is under the hosted ceiling and is admitted held and unheld.
#[tokio::test]
async fn two_mib_of_point_rows_is_admitted_held_and_unheld_on_hosted_defaults() {
    let state = gateway(&LimitsConfig::defaults_for(true));
    let row = r#"{"x":1,"y":2}"#;
    let rows = (2 * MIB as usize - 200) / (row.len() + 1);
    let size = estimate(body(HELD, row, rows).as_bytes());
    eprintln!("2 MiB of {row}: {} bytes ({} MiB) as a tree", size, size / MIB);
    assert!(size > 100 * MIB && size < 128 * MIB, "{size}");
    admitted_both_ways(&state, row, rows, "2 MiB of {x, y} rows").await;
}

/// A near-2 MiB document of one-letter-key objects, about 180 MiB as a tree, is over the hosted ceiling, and it is refused held and unheld with nothing written. Before, it ran unheld and was refused held. It is not the only near-2 MiB shape over it: one-key rows over a short value are too (`{"qty":5}` 146 MiB, `{"id":n}` 161 MiB for one-digit ids down to 135 MiB for three, `{"tag":"a"}` 129 MiB), as the doc on `DEFAULT_HOSTED_JSON_POOL_BYTES` states and its unit test measures.
#[tokio::test]
async fn a_near_two_mib_document_of_one_letter_key_objects_is_refused_held_and_unheld() {
    let state = gateway(&LimitsConfig::defaults_for(true));
    let row = r#"{"a":1}"#;
    let rows = (2 * MIB as usize - 200) / (row.len() + 1);
    let size = estimate(body(HELD, row, rows).as_bytes());
    eprintln!("2 MiB of {row}: {} bytes ({} MiB) as a tree", size, size / MIB);
    assert!(size > 170 * MIB, "{size}");
    refused_both_ways(&state, row, rows, "2 MiB of {a: 1} rows").await;
}

/// An agent's URL is held and signed in the form the gateway sends it, which can be longer than the agent wrote it (a space becomes `%20`). The ceiling counts that URL at its new length, before the policy decides whether to hold the call, so the tree a held row renders and approves from is never over it. The same call with a URL that does not grow passes the ceiling and is answered by the policy.
#[tokio::test]
async fn an_agent_url_the_gateway_writes_longer_is_counted_at_its_new_length() {
    let state = gateway(&LimitsConfig { json_pool_bytes: 64 * MIB, ..LimitsConfig::defaults_for(true) });
    state
        .service
        .store()
        .put_connection(permaura_core::Connection {
            id: "generic_http".into(),
            connector: "generic_http".into(),
            name: "Generic HTTP".into(),
            label: "Generic HTTP".into(),
            secret_id: "sec_github_acme".into(),
            capabilities: vec!["http.request".into()],
            disabled_capabilities: vec![],
            disabled: false,
            allowed_hosts: vec!["api.example.com".into()],
            created_at: 1,
            redact_fields: Vec::new(),
            source: None,
            made_from: None,
        })
        .unwrap();
    let ceiling = state.service.memory().unpacked_limit();
    assert_eq!(ceiling, 32 * MIB);
    let make = |path: &str, rows: usize| {
        let url = format!("https://api.example.com/{}x", path.repeat(MIB as usize));
        let list = vec![r#"{"a":1}"#; rows].join(",");
        format!(r#"{{"capability":"http.request","params":{{"method":"GET","url":{},"extra":[{list}]}}}}"#, serde_json::to_string(&url).unwrap())
    };
    let (mut low, mut high) = (0usize, 1_000_000usize);
    while low < high {
        let mid = (low + high).div_ceil(2);
        if estimate(make("a", mid).as_bytes()) <= ceiling - MIB {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    let (spaced, plain) = (make(" ", low), make("a", low));
    assert!(estimate(spaced.as_bytes()) <= ceiling && estimate(plain.as_bytes()) <= ceiling, "both are under the ceiling as sent");
    let (status, answer) = send(&state, plain).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "past the ceiling, the policy answers: {}", cut(&answer));
    let before = audit_len(&state);
    let (status, answer) = send(&state, spaced).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "a 1 MiB path of spaces is 3 MiB as sent on: {}", cut(&answer));
    assert_eq!(audit_len(&state), before, "nothing was written");
}

async fn mcp(state: &AppState, id: Value, tool: &str, arguments: &str) -> (StatusCode, Value) {
    let body = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#);
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// On `/mcp` a call over the ceiling is a tool error, as every other refusal of a tool call is: a JSON-RPC error carrying the request's id, whose message names the call's size and the limit and tells the agent to split the call. Held or not, and nothing is written.
#[tokio::test]
async fn on_mcp_a_call_over_the_ceiling_is_a_tool_error_that_says_to_split_it() {
    let state = gateway(&LimitsConfig::defaults_for(true));
    let (pending_before, audit_before) = (pending(&state), audit_len(&state));
    let rows = (2 * MIB as usize - 400) / 8;
    let arguments = format!(r#"{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","extra":[{}]}}"#, vec![r#"{"a":1}"#; rows].join(","));
    for (id, tool) in [(json!(7), UNHELD), (json!("call-8"), HELD)] {
        let (status, answer) = mcp(&state, id.clone(), tool, &arguments).await;
        assert_eq!(status, StatusCode::OK, "{tool}: {}", cut(&answer));
        assert_eq!(answer["id"], id, "{}", cut(&answer));
        assert_eq!(answer["error"]["code"], -32000, "{}", cut(&answer));
        let message = answer["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("once unpacked") && message.contains("split it into smaller calls"), "{message}");
        assert!(message.contains(&state.service.memory().unpacked_limit().to_string()), "names the ceiling: {message}");
    }
    assert_eq!((pending(&state), audit_len(&state)), (pending_before, audit_before), "nothing was written");

    // An id too long to be one is answered as null rather than echoed.
    let long = Value::String("i".repeat(1024));
    let (_, answer) = mcp(&state, long, UNHELD, &arguments).await;
    assert_eq!(answer["id"], Value::Null);

    // Under the ceiling the same tool runs.
    let (status, answer) = mcp(&state, json!(9), UNHELD, r#"{"owner":"synthetic","repo":"synthetic"}"#).await;
    assert_eq!(status, StatusCode::OK);
    assert!(answer.get("result").is_some(), "{}", cut(&answer));
}

/// The ceiling is for agent calls: an `/mcp` request with another method whose body is over it is read and answered as on 1.3.52, here a `tools/list` carrying 1.9 MiB of `{"a":1}` (about 170 MiB as a tree), which the pool still holds.
#[tokio::test]
async fn on_mcp_a_request_that_is_not_a_tool_call_is_not_held_to_the_ceiling() {
    let state = gateway(&LimitsConfig::defaults_for(true));
    let rows = (19 * MIB as usize / 10) / 8;
    let body = format!(r#"{{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{{"extra":[{}]}}}}"#, vec![r#"{"a":1}"#; rows].join(","));
    let (tree, room) = permaura_gateway::memory::params_room(body.as_bytes());
    assert!(tree > state.service.memory().unpacked_limit() && room <= state.service.memory().pool().max_bytes(), "{tree} {room}");
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let answer: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(answer["id"], 3);
    assert!(answer["result"]["tools"].as_array().is_some_and(|tools| !tools.is_empty()), "{}", cut(&answer));
}

/// A `/v1/invoke` body for `capability` whose params carry a list of `1e15`, as long as fits in `bytes`.
fn exponents(capability: &str, bytes: usize) -> String {
    let mut body = format!(r#"{{"capability":"{capability}","params":{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","extra":[1e15"#);
    while body.len() + 8 < bytes {
        body.push_str(",1e15");
    }
    body.push_str("]}}");
    body
}

/// Held text serde_json writes longer than it was sent is charged at its stored length, never refused for being longer, and the one ceiling is the only size test a call meets before the policy decides whether to hold it. With a hosted body limit raised to 8 MiB, 8 MiB of `1e15` (a 96 MiB tree written as 30 MiB) runs unheld, as on 1.3.52, and is held, where 1.3.52 refused it held; it is approved and runs, reserving its tree, the 30 MiB of text the request is written from and an execution's 26 MiB, where four copies of that text beside them would have passed the pool. Its row keeps the text it was held with. 4 MiB of them (written as 15 MiB) is admitted both ways and approved. On a 64 MiB pool, 2 MiB of them (a 24 MiB tree, under the 32 MiB ceiling) runs unheld, as on 1.3.52.
#[tokio::test]
async fn text_written_past_the_body_limit_is_held_at_its_stored_length_and_charged_when_approved() {
    let config = LimitsConfig { body_exec_bytes: 8 * MIB as usize, ..LimitsConfig::defaults_for(true) };
    let state = gateway(&config);
    assert_eq!(state.service.memory().unpacked_limit(), 128 * MIB);
    let long = exponents(HELD, 8 * MIB as usize - 1024);
    assert!(estimate(long.as_bytes()) < 128 * MIB, "under the ceiling as a tree");
    let id = admitted_both_ways_and_held(&state, exponents(UNHELD, 8 * MIB as usize - 1024), long, "8 MiB of 1e15").await;
    let row = state.service.store().get_approval(&id).unwrap().unwrap();
    assert!(row.params.len() > 28 * MIB as usize, "kept at its stored length, {} bytes", row.params.len());
    assert!(approve_or_deny(&state, &config, &id, "8 MiB of 1e15").await, "8 MiB of 1e15 that ran unheld is approved");

    let id = admitted_both_ways_and_held(&state, exponents(UNHELD, 4 * MIB as usize), exponents(HELD, 4 * MIB as usize), "4 MiB of 1e15").await;
    let row = state.service.store().get_approval(&id).unwrap().unwrap();
    assert!(row.params.len() > 3 * 4 * MIB as usize, "kept at its stored length, {} bytes", row.params.len());
    assert!(approve_or_deny(&state, &config, &id, "4 MiB of 1e15").await);

    let config = LimitsConfig { json_pool_bytes: 64 * MIB, ..LimitsConfig::defaults_for(true) };
    let state = gateway(&config);
    let two = exponents(UNHELD, 2 * MIB as usize - 1024);
    let tree = estimate(two.as_bytes());
    assert!(tree > 20 * MIB && tree < state.service.memory().unpacked_limit(), "{tree}");
    let (status, answer) = send(&state, two).await;
    assert_eq!(status, StatusCode::OK, "{}", cut(&answer));
}

/// Answers like [`MockHttpClient`], but holds every POST (the held call's create) until `gate` has a permit, and counts the POSTs it has been sent.
struct HoldsCreates {
    gate: Arc<tokio::sync::Semaphore>,
    sent: Arc<std::sync::atomic::AtomicUsize>,
    inner: MockHttpClient,
}

#[async_trait::async_trait]
impl permaura_gateway::connectors::HttpClient for HoldsCreates {
    async fn send(&self, request: permaura_gateway::connectors::HttpRequest) -> anyhow::Result<permaura_gateway::connectors::HttpResponse> {
        if request.method == permaura_gateway::connectors::HttpMethod::Post {
            self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _permit = self.gate.acquire().await?;
        }
        self.inner.send(request).await
    }
}

async fn get(state: &AppState, uri: &str) -> (StatusCode, Value) {
    let request = Request::builder().uri(uri).header("authorization", format!("Bearer {}", seed::DEMO_TOKEN)).body(Body::empty()).unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Approving the largest held call reserved the whole hosted pool (164 + 4 x 2 + 20 MiB at the 1.3.52 hold ceiling), so every agent call waited out the pool wait and was refused 429 "memory" for as long as the approved call ran, and an approver's listing or read of that call queued for the pool ahead of them. At the one ceiling, approving a call just under it reserves its tree, room for its text and an execution's buffers, about 128 + 2.5 + 20 MiB, as on 1.3.52 outside the execution slots, and leaves about 41 MiB for ordinary calls, which run meanwhile without a 429; and a listing or read of a call whose approval is running renders it only if the pool has room at once, never queueing for it, so the row is served unrendered while it runs. So does the check of a device's approve of it, a retried tap or another device's signature, and a second approve of it waits for no room, each answered at once with the pool's 429; the second approve's end leaves the call in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approving_the_largest_call_leaves_room_for_ordinary_agent_calls() {
    common::isolate_from_the_real_install();
    let config = LimitsConfig { json_pool_wait: std::time::Duration::from_secs(5), ..LimitsConfig::defaults_for(true) };
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let client = HoldsCreates { gate: gate.clone(), sent: sent.clone(), inner: MockHttpClient::new() };
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let service = EnforcementService::new(store, Arc::new(client)).with_memory_budget(MemoryBudget::from_config(&config));
    let state = AppState::new(service).with_limits(Arc::new(Limits::new(config.clone())));

    let ceiling = state.service.memory().unpacked_limit();
    let row = r#"{"a":1}"#;
    let rows = rows_under(row, ceiling, config.body_exec_bytes);
    let (status, answer) = send(&state, body(HELD, row, rows)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", cut(&answer));
    let id = answer["approval_id"].as_str().unwrap().to_string();

    let approving = tokio::spawn({
        let (state, id) = (state.clone(), id.clone());
        async move { state.service.resolve_approval(&id, true, "bearer", Some("operator")).await }
    });
    let started = async {
        while sent.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(60), started).await.expect("the approved call reached its upstream");
    let pool = state.service.memory().pool().clone();
    let reserved = pool.max_bytes() - pool.available_bytes();
    eprintln!("approving a {}-byte call reserves {} MiB of the {} MiB pool", estimate(body(HELD, row, rows).as_bytes()), reserved / MIB, pool.max_bytes() / MIB);
    let room = held_room(state.service.store().get_approval(&id).unwrap().unwrap().params.get().as_bytes()) + state.service.memory().resolution_bytes();
    assert!(reserved >= room && reserved < room + 1024 && reserved <= 157 * MIB, "its tree, room for its text and an execution's 20 MiB: {reserved}");
    assert!(pool.available_bytes() >= 35 * MIB, "{}", pool.available_bytes());
    assert_eq!(state.limits.available_execution_slots(), config.max_inflight, "it takes no execution slot");

    // Ordinary agent calls run meanwhile, each answered without a 429: a list of a quarter of a MiB of ids reserves about 15 MiB, which the 1.3.52 approval of its largest call, at 164 + 4 x 2 + 20 MiB, left no room for.
    let ordinary = body(UNHELD, r#"{"id":100000}"#, 256 * 1024 / 14);
    let (_, room) = permaura_gateway::memory::params_room(ordinary.as_bytes());
    assert!(room > 8 * MIB && room < 36 * MIB, "{room}");
    for _ in 0..4 {
        let (status, answer) = send(&state, ordinary.clone()).await;
        assert_eq!(status, StatusCode::OK, "an ordinary call while the largest is approved: {}", cut(&answer));
    }
    // A second approve of the call being approved, and the check of a device's approve of it, answer at once rather than queueing for the pool behind its approval's reservation, ahead of agent calls.
    let at_once = std::time::Duration::from_secs(1);
    let again = tokio::time::timeout(at_once, state.service.resolve_approval(&id, true, "bearer", Some("operator"))).await.expect("a second approve answered at once");
    match again {
        Err(permaura_gateway::error::GatewayError::TooManyRequests { reason, .. }) => assert_eq!(reason, "memory"),
        Err(other) => panic!("a second approve while the first runs: {other}"),
        Ok(row) => panic!("a second approve ran: {}", row.status),
    }
    let tap: permaura_relay::ApprovalResult = serde_json::from_value(json!({
        "job_id": id, "approval_id": id, "approve": true, "request_hash": "h", "approver": "device:phone", "decided_at": 1,
        "display_digest": "d", "device_sig": "s",
    }))
    .unwrap();
    let checked = tokio::time::timeout(at_once, state.service.display_room_for_signed(&tap)).await.expect("a device's approve checked at once");
    assert!(matches!(&checked, Err(permaura_gateway::error::GatewayError::TooManyRequests { reason, .. }) if reason == "memory"), "{:?}", checked.err());
    assert!(state.service.executions().in_flight_approvals().contains(&id), "the second approve's end left the first in flight");
    // An approver's listing and read of the call being approved answer at once, without its rendering, rather than queueing for the pool ahead of agent calls.
    let (status, listed) = get(&state, "/v1/approvals?status=pending").await;
    assert_eq!(status, StatusCode::OK, "{}", cut(&listed));
    let mine = listed["approvals"].as_array().unwrap().iter().find(|a| a["id"] == id.as_str()).cloned().unwrap();
    assert_eq!(mine["params_rendered"], false, "{}", cut(&mine));
    let (status, read) = get(&state, &format!("/v1/approvals/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{}", cut(&read));
    assert_eq!(read["params_rendered"], false);
    let (status, answer) = send(&state, body(UNHELD, r#"{"id":1}"#, 20)).await;
    assert_eq!(status, StatusCode::OK, "{}", cut(&answer));

    gate.add_permits(1);
    let approved = approving.await.unwrap().unwrap();
    assert_eq!(approved.status, "approved");
    assert_eq!(pool.available_bytes(), pool.max_bytes(), "the approval gave its room back");
    assert_eq!(state.limits.available_execution_slots(), config.max_inflight, "and its slot");
}

/// An approved held call runs outside the execution slots, as on 1.3.52, with an execution's buffers reserved in the pool beside its params, so an approve while agent calls hold every slot runs. Only a call whose params and those buffers could never fit the pool together takes a slot, here 5 MiB of string on a 32 MiB pool with an 8 MiB body limit, whose execution's share is 16 MiB beside 20 MiB of params; it ran unheld, and approving it runs it under a slot. With one slot and no queue, its approve while an agent call holds the slot is the 429 an agent call gets, nothing is claimed, and the approval stays pending; once the slot is free the same approve runs. A denial needs no slot.
#[tokio::test]
async fn only_an_approval_that_could_never_fit_beside_an_executions_buffers_takes_an_execution_slot() {
    let config = LimitsConfig {
        json_pool_bytes: 32 * MIB,
        body_exec_bytes: 8 * MIB as usize,
        max_inflight: 1,
        queue_depth: 0,
        queue_wait: std::time::Duration::from_millis(50),
        ..LimitsConfig::defaults_for(true)
    };
    let state = gateway(&config);
    let held = |capability: &str, title: &str, extra: usize| format!(r#"{{"capability":"{capability}","params":{{"owner":"synthetic","repo":"synthetic","title":"{title}","head":"h","base":"b","extra":"{}"}}}}"#, "A".repeat(extra));
    let (status, answer) = send(&state, held(HELD, "small", 0)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", cut(&answer));
    let small = answer["approval_id"].as_str().unwrap().to_string();
    let large = admitted_both_ways_and_held(&state, held(UNHELD, "large", 5 * MIB as usize), held(HELD, "large", 5 * MIB as usize), "5 MiB of string").await;
    let (status, answer) = send(&state, held(HELD, "denied", 0)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", cut(&answer));
    let other = answer["approval_id"].as_str().unwrap().to_string();
    let memory = state.service.memory();
    assert!(memory.held_fits_beside_buffers(state.service.store().get_approval(&small).unwrap().unwrap().params.get().as_bytes()));
    let text = state.service.store().get_approval(&large).unwrap().unwrap().params;
    assert!(!memory.held_fits_beside_buffers(text.get().as_bytes()) && held_room(text.get().as_bytes()) <= config.json_pool_bytes, "{}", held_room(text.get().as_bytes()));

    let busy = state.limits.admit(&permaura_gateway::limits::LimitKey::session("an agent call")).await.expect("the one slot");
    assert_eq!(state.service.resolve_approval(&small, true, "bearer", Some("operator")).await.unwrap().status, "approved", "an approve that fits beside an execution's buffers needs no slot");
    let refused = state.service.resolve_approval(&large, true, "bearer", Some("operator")).await.unwrap_err();
    assert!(matches!(refused, permaura_gateway::error::GatewayError::TooManyRequests { .. }), "{refused}");
    assert_eq!(state.service.store().get_approval(&large).unwrap().unwrap().status, "pending", "nothing was claimed");
    assert_eq!(state.service.resolve_approval(&other, false, "bearer", Some("operator")).await.unwrap().status, "denied", "a denial needs no slot");
    drop(busy);

    assert!(approve_or_deny(&state, &config, &large, "5 MiB of string on a 32 MiB pool").await, "once the slot is free it runs");
}

/// An agent polls its approved call's result through `permaura_get_approval_status`, which reads the row without its params: the status, the upstream status and the result are what the row keeps, for a call whose params serde_json wrote longer than they were sent.
#[tokio::test]
async fn the_agent_reads_its_approved_calls_result_without_its_params() {
    let state = gateway(&LimitsConfig::defaults_for(true));
    let (status, answer) = send(&state, exponents(HELD, 64 * 1024)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", cut(&answer));
    let id = answer["approval_id"].as_str().unwrap().to_string();
    let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(approved.status, "approved");
    let (status, answer) = mcp(&state, json!(6), "permaura_get_approval_status", &format!(r#"{{"approval_id":"{id}"}}"#)).await;
    assert_eq!(status, StatusCode::OK);
    let text = answer["result"]["content"][0]["text"].as_str().unwrap_or_default();
    let read: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    assert_eq!(read["status"], "approved", "{}", cut(&answer));
    assert_eq!(read["approval_id"], id.as_str());
    assert_eq!(read["upstream_status"], json!(approved.result_status));
    assert_eq!(read["result"], serde_json::from_str::<Value>(approved.result.as_ref().unwrap().get()).unwrap());
    assert!(read.get("params").is_none());
}

/// Each agent call's unpacked-size estimate is recorded as one number, `unpacked_bytes`, on the audit event it writes first, a run's attempt, a hold or a denial, so the ceiling can be checked against real traffic; nothing of the params is recorded with it.
#[tokio::test]
async fn each_call_records_its_unpacked_size_and_none_of_its_params() {
    let state = gateway(&LimitsConfig::defaults_for(true));
    state
        .service
        .store()
        .put_connection(permaura_core::Connection {
            id: "generic_http".into(),
            connector: "generic_http".into(),
            name: "Generic HTTP".into(),
            label: "Generic HTTP".into(),
            secret_id: "sec_github_acme".into(),
            capabilities: vec!["http.request".into()],
            disabled_capabilities: vec![],
            disabled: false,
            allowed_hosts: vec!["api.example.com".into()],
            created_at: 1,
            redact_fields: Vec::new(),
            source: None,
            made_from: None,
        })
        .unwrap();
    let marker = "synthetic-param-7f3a";
    let calls = [
        (UNHELD, "attempt", format!(r#"{{"capability":"{UNHELD}","params":{{"owner":"synthetic","repo":"{marker}","rows":[1,2,3]}}}}"#)),
        (HELD, "requires_approval", format!(r#"{{"capability":"{HELD}","params":{{"owner":"synthetic","repo":"synthetic","title":"{marker}","head":"h","base":"b"}}}}"#)),
        ("http.request", "deny", format!(r#"{{"capability":"http.request","params":{{"method":"GET","url":"https://api.example.com/{marker}"}}}}"#)),
    ];
    for (capability, decision, body) in calls {
        let before = audit_len(&state);
        let sent = estimate(body.as_bytes());
        let (status, answer) = send(&state, body).await;
        assert!(status.is_success() || status == StatusCode::FORBIDDEN, "{capability}: {status} {}", cut(&answer));
        let events = state.service.store().audit_events(None).unwrap();
        let first = &events[before];
        assert_eq!(first.payload.decision, decision, "{capability}");
        assert_eq!(first.payload.summary["unpacked_bytes"], json!(sent), "{capability}: {}", first.payload.summary);
        assert!(!serde_json::to_string(&events[before..].iter().map(|e| &e.payload.summary).collect::<Vec<_>>()).unwrap().contains(marker), "{capability}: no params recorded");
    }
}

/// Params from the relay come as a tree no body limit bounded, and meet the same one ceiling as every other agent call and nothing else before the policy decides whether to hold them. At hosted defaults 40 MiB of string, a 40 MiB tree under the 128 MiB ceiling, runs unheld, as on 1.3.52, and is held and approved, reserving 40 + 40 + 2 x 40 MiB and an execution's 20 MiB, where 1.3.52 refused it held. Approving params no body bounded can still pass the pool: on a 64 MiB pool, whose ceiling is 32 MiB, 20 MiB of string runs unheld and is held, and approving it would take 20 + 20 + 2 x 20 MiB, more than the pool even under an execution slot, so its approval is refused and it can be denied; 4 MiB of it is approved. Over the ceiling it is refused alike, with nothing written.
#[tokio::test]
async fn relayed_params_meet_the_one_ceiling_and_are_charged_when_approved() {
    use permaura_core::ExecutionLocation;
    use permaura_gateway::service::InvokeOutcome;
    let params = |bytes: usize| json!({ "owner": "synthetic", "repo": "synthetic", "title": "t", "head": "h", "base": "b", "extra": "A".repeat(bytes) });
    let run_and_hold = |state: AppState, bytes: usize| async move {
        let session = state.service.store().get_session("sess_demo").unwrap().expect("the demo session");
        let ran = state.service.invoke(&session, UNHELD, &params(bytes), None, ExecutionLocation::LocalOnly).await.unwrap();
        assert!(matches!(ran, InvokeOutcome::Allowed { .. }), "{bytes} bytes of relayed string runs unheld");
        let held = state.service.invoke(&session, HELD, &params(bytes), None, ExecutionLocation::LocalOnly).await.unwrap();
        let InvokeOutcome::RequiresApproval { approval, .. } = held else { panic!("held") };
        approval.id
    };
    let hosted = LimitsConfig::defaults_for(true);
    let state = gateway(&hosted);
    let id = run_and_hold(state.clone(), 40 * MIB as usize).await;
    assert!(approve_or_deny(&state, &hosted, &id, "40 MiB of relayed string").await);

    let small = LimitsConfig { json_pool_bytes: 64 * MIB, ..hosted.clone() };
    let small_state = gateway(&small);
    let id = run_and_hold(small_state.clone(), 20 * MIB as usize).await;
    assert!(!approve_or_deny(&small_state, &small, &id, "20 MiB of relayed string on a 64 MiB pool").await, "approving it cannot fit the pool");
    let id = run_and_hold(small_state.clone(), 4 * MIB as usize).await;
    assert!(approve_or_deny(&small_state, &small, &id, "4 MiB of relayed string on a 64 MiB pool").await);

    let session = state.service.store().get_session("sess_demo").unwrap().expect("the demo session");
    let dense = json!({ "owner": "synthetic", "repo": "synthetic", "extra": vec![json!({ "a": 1 }); 2 * MIB as usize / 7] });
    let (pending_before, audit_before) = (pending(&state), audit_len(&state));
    for capability in [UNHELD, HELD] {
        let refused = state.service.invoke(&session, capability, &dense, None, ExecutionLocation::LocalOnly).await;
        let Err(error) = refused else { panic!("{capability}: over the ceiling") };
        assert!(error.to_string().contains("once unpacked") && error.to_string().contains("split it into smaller calls"), "{capability}: {error}");
    }
    assert_eq!((pending(&state), audit_len(&state)), (pending_before, audit_before), "nothing was written");
}
