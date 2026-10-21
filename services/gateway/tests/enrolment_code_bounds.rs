//! `POST /v1/agents/enroll` stored a row per call with an unbounded label, no ceiling and no sweep, and a used code was never deleted, so a member could fill a hosted worker's store in a few hundred requests and the restored store crashed it again. The label is bounded, the codes waiting to be redeemed are capped, and minting one sweeps every code past its expiry.
//!
//! Every credential here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{EnrolmentCode, Store};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

async fn enroll(state: &AppState, body: Value) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method("POST")
        .uri("/v1/agents/enroll")
        .header("host", "127.0.0.1:7376")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn rows(path: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row("SELECT count(*) FROM enrolment_codes", [], |r| r.get(0)).unwrap()
}

#[tokio::test]
async fn enrolment_codes_are_bounded_in_label_count_and_lifetime() {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!("enrolment-codes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(path.to_str().unwrap()).unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let limits = Arc::new(Limits::new(LimitsConfig { live_enrolment_codes: 3, ..LimitsConfig::default() }));
    let state = AppState::new(permaura_gateway::service::EnforcementService::new(store.clone(), Arc::new(permaura_gateway::connectors::MockHttpClient::new()))).with_limits(limits);

    let (status, body) = enroll(&state, json!({ "label": "x".repeat(201) })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an over-long label is refused: {body}");
    assert_eq!(rows(&path), 0, "and nothing is stored");

    // Spent and expired: nothing can redeem either, and the next mint takes them with it.
    for (code, used) in [("ENRL-OLD0-0000-0000-0000", false), ("ENRL-OLD1-0000-0000-0000", true)] {
        store.put_enrolment_code(EnrolmentCode { code: code.into(), label: None, created_at: 1, expires_at: 2, used }).unwrap();
    }
    assert_eq!(rows(&path), 2);

    for i in 0..3 {
        let (status, body) = enroll(&state, json!({ "label": format!("agent {i}") })).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    assert_eq!(rows(&path), 3, "the expired codes were swept when the first was minted");

    let (status, body) = enroll(&state, json!({ "label": "one too many" })).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(rows(&path), 3, "a refused mint stores nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Both stores count only codes that can still be redeemed, and refuse at the ceiling without writing.
#[test]
fn every_store_caps_the_codes_waiting_to_be_redeemed() {
    let stores: Vec<(&str, Box<dyn Store>)> = vec![
        ("memory", Box::new(permaura_gateway::store::memory::MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open_in_memory().unwrap())),
    ];
    for (kind, store) in stores {
        let code = |n: usize, expires_at: i64, used: bool| EnrolmentCode { code: format!("ENRL-{n:04}-0000-0000-0000"), label: None, created_at: 1, expires_at, used };
        store.put_enrolment_code(code(0, 5, false)).unwrap();
        store.put_enrolment_code(code(1, 50, true)).unwrap();
        store.mint_enrolment_code(code(2, 50, false), 10, 2).unwrap();
        store.mint_enrolment_code(code(3, 50, false), 10, 2).unwrap();
        assert!(store.mint_enrolment_code(code(4, 50, false), 10, 2).is_err(), "{kind}: two are waiting");
        assert!(!store.enrolment_code_redeemable("ENRL-0004-0000-0000-0000", 10).unwrap(), "{kind}: the refused one was not stored");
        assert!(store.enrolment_code_redeemable("ENRL-0003-0000-0000-0000", 10).unwrap(), "{kind}");
        assert!(store.mint_enrolment_code(code(5, 100, false), 60, 2).is_ok(), "{kind}: once the two expire there is room again");
    }
}

async fn mcp_enroll(state: &AppState, arguments: Value) -> Value {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "permaura_enroll", "arguments": arguments } });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "127.0.0.1:7376")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Alongside the label bound: an agent redeeming a code over MCP names itself, and the agents table keeps its `name` and `agent_id` for good, so both are held to the label's 200 characters, refused before the code is spent.
#[tokio::test]
async fn an_agent_enrolling_over_mcp_names_itself_within_the_label_bound() {
    common::isolate_from_the_real_install();
    let state = AppState::in_memory_seeded_with_http(Arc::new(permaura_gateway::connectors::MockHttpClient::new()));
    let (status, minted) = enroll(&state, json!({ "label": "a new agent" })).await;
    assert_eq!(status, StatusCode::CREATED, "{minted}");
    let code = minted["code"].as_str().unwrap().to_string();

    for (field, value) in [("name", "n".repeat(201)), ("agent_id", "a".repeat(201))] {
        let answer = mcp_enroll(&state, json!({ "code": code, field: value })).await;
        assert_eq!(answer["error"]["code"], -32602, "{field}: {answer}");
        assert!(answer["error"]["message"].as_str().unwrap().contains("200 characters"), "{answer}");
    }
    assert!(state.service.store().list_agents().unwrap().iter().all(|a| a.name.chars().count() <= 200 && a.id.chars().count() <= 200));

    let answer = mcp_enroll(&state, json!({ "code": code, "name": "n".repeat(200), "agent_id": "bounded-agent" })).await;
    assert!(answer["error"].is_null(), "the code was not spent by the refusals: {answer}");
    assert_eq!(state.service.store().get_agent("bounded-agent").unwrap().unwrap().name, "n".repeat(200));
}

/// A redeemed code is the agent's bearer for its whole sliding life and is stored as an unsalted digest, so it carries the 128 bits every other bearer does, not 64: an offline search of a store copy must be out of reach, not merely costly.
#[tokio::test]
async fn an_enrolment_code_carries_128_random_bits() {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..3 {
        let (status, body) = enroll(&state, json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let code = body["code"].as_str().expect("a code").to_string();
        let digits: String = code.strip_prefix("ENRL-").expect("the code's prefix").chars().filter(|c| *c != '-').collect();
        assert_eq!(digits.len(), 32, "32 hex digits, 128 bits: {code}");
        assert!(digits.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()), "{code}");
        assert!(seen.insert(code));
    }
}

/// A session whose bearer is an enrolment code an older gateway minted (64 bits, four groups or fewer) no longer slides when used: it keeps the expiry it had, so it ends at most one TTL after its last use before the upgrade and its agent enrols again with a 128-bit code. A current code's session slides as before.
#[test]
fn a_pre_upgrade_short_code_bearer_stops_sliding() {
    use permaura_gateway::store::{Session, SessionRole};
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let store = state.service.store();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let soon = now + 60_000;
    let session = |id: &str, token: &str| Session {
        class: Default::default(),
        opened_by: None,
        id: id.into(),
        agent_id: "codex-cli".into(),
        user_id: None,
        device_id: None,
        token: token.into(),
        role: SessionRole::Agent,
        created_at: now - 1_000,
        revoked: false,
        expires_at: Some(soon),
        last_used_at: None,
        actor: None,
    };
    let short = "ENRL-AB12-CD34-EF56-0789";
    let short_remote = "pgc_ENRL-AB12-CD34-EF56-0788";
    let long = "ENRL-AB12-CD34-EF56-0789-AB12-CD34-EF56-0789";
    for (id, token) in [("sess_short", short), ("sess_short_remote", short_remote), ("sess_long", long)] {
        store.put_session(session(id, token)).unwrap();
        state.service.authenticate(token).expect("a live session authenticates");
    }
    let expiry = |id: &str| store.get_session(id).unwrap().unwrap().expires_at.unwrap();
    assert_eq!(expiry("sess_short"), soon, "a 64-bit code bearer keeps its expiry");
    assert_eq!(expiry("sess_short_remote"), soon, "with the console prefix too");
    assert!(expiry("sess_long") > soon, "a 128-bit code bearer slides as before");
}
