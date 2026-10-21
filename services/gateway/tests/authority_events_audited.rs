//! Every change of who may act is in the audit chain: a session opened or revoked, over REST or MCP,
//! an enrolment code minted, and an enrolment redeemed into an agent and its bearer.
//!
//! These wrote no event, so an owner reading the chain after an incident could not see that
//! extra operator authority had been issued or taken away. The bearer and the code themselves are
//! never in the record. Every credential here is synthetic.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

async fn send(app: &axum::Router, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn send_anon(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn events(state: &AppState) -> Vec<permaura_core::AuditEvent> {
    state.service.store().audit_events(None).unwrap()
}

fn recorded(state: &AppState, action: &str, resource: &str) -> permaura_core::AuditEvent {
    events(state)
        .into_iter()
        .rev()
        .find(|e| e.payload.action == action && e.payload.resource == resource)
        .unwrap_or_else(|| panic!("no {action} event for {resource} in the chain"))
}

fn never_in_the_chain(state: &AppState, secret: &str) {
    let chain = serde_json::to_string(&events(state)).unwrap();
    assert!(!chain.contains(secret), "a bearer or code was written into the audit chain");
}

#[tokio::test]
async fn a_session_opened_and_revoked_over_rest_is_recorded_with_who_did_it() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    let (status, opened) = send(&app, "/v1/sessions", &operator, json!({ "agent_id": "codex-cli" })).await;
    assert_eq!(status, StatusCode::CREATED, "{opened}");
    let id = opened["session_id"].as_str().unwrap().to_string();
    let token = opened["token"].as_str().unwrap().to_string();
    let open = recorded(&state, "permaura.session.open", &id);
    assert_eq!(open.payload.decision, "allow");
    assert_eq!(open.payload.session_id.as_deref(), Some("sess_test_operator"), "the opener is on the event");
    assert_eq!(open.payload.summary["agent_id"], "codex-cli", "{}", open.payload.summary);
    assert_eq!(open.payload.summary["role"], "operator", "{}", open.payload.summary);

    let (status, body) = send(&app, &format!("/v1/sessions/{id}/revoke"), &operator, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let revoke = recorded(&state, "permaura.session.revoke", &id);
    assert_eq!(revoke.payload.session_id.as_deref(), Some("sess_test_operator"));
    never_in_the_chain(&state, &token);
}

#[tokio::test]
async fn an_agent_revoking_its_own_session_over_mcp_is_recorded() {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "permaura_revoke_session", "arguments": {} },
    });
    let (status, body) = send(&app, "/mcp", permaura_gateway::seed::DEMO_TOKEN, call).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    let revoke = recorded(&state, "permaura.session.revoke", "sess_demo");
    assert_eq!(revoke.payload.session_id.as_deref(), Some("sess_demo"), "the caller is on the event");
    assert_eq!(revoke.payload.summary["via"], "mcp", "{}", revoke.payload.summary);
}

#[tokio::test]
async fn an_enrolment_code_minted_and_redeemed_is_recorded_without_the_code() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    let (status, minted) = send(&app, "/v1/agents/enroll", &operator, json!({ "label": "Review bot" })).await;
    assert_eq!(status, StatusCode::CREATED, "{minted}");
    let code = minted["code"].as_str().unwrap().to_string();
    let mint = recorded(&state, "permaura.enrolment_code.mint", "enrolment-code");
    assert_eq!(mint.payload.session_id.as_deref(), Some("sess_test_operator"));
    assert_eq!(mint.payload.summary["label"], "Review bot", "{}", mint.payload.summary);
    assert_eq!(mint.payload.summary["expires_at"], minted["expires_at"], "{}", mint.payload.summary);

    let list = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let (status, body) = send(&app, "/mcp", &code, list).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let agent = state
        .service
        .store()
        .list_agents()
        .unwrap()
        .into_iter()
        .find(|a| a.name == "Review bot")
        .expect("the code became an agent");
    let enrolled = recorded(&state, "permaura.agent.enroll", &agent.id);
    assert!(enrolled.payload.summary["session_id"].as_str().is_some_and(|s| s.starts_with("sess_")), "{}", enrolled.payload.summary);
    never_in_the_chain(&state, &code);
}

/// The open names the user and device the new session carries, and the mint and the redemption share the code's non-secret times, so the two can be joined.
#[tokio::test]
async fn the_events_carry_what_joins_them() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (status, opened) = send(
        &app,
        "/v1/sessions",
        &operator,
        json!({ "agent_id": "codex-cli", "user_id": "user_synthetic", "device_id": "device:synthetic" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{opened}");
    let open = recorded(&state, "permaura.session.open", opened["session_id"].as_str().unwrap());
    assert_eq!(open.payload.summary["user_id"], "user_synthetic", "{}", open.payload.summary);
    assert_eq!(open.payload.summary["device_id"], "device:synthetic", "{}", open.payload.summary);

    let (_, minted) = send(&app, "/v1/agents/enroll", &operator, json!({ "label": "Joined" })).await;
    let code = minted["code"].as_str().unwrap().to_string();
    let mint = recorded(&state, "permaura.enrolment_code.mint", "enrolment-code");
    send(&app, "/mcp", &code, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })).await;
    let agent = state.service.store().list_agents().unwrap().into_iter().find(|a| a.name == "Joined").unwrap();
    let enrolled = recorded(&state, "permaura.agent.enroll", &agent.id);
    for key in ["code_created_at", "code_expires_at"] {
        assert!(mint.payload.summary[key].is_i64(), "the mint carries {key}: {}", mint.payload.summary);
        assert_eq!(mint.payload.summary[key], enrolled.payload.summary[key], "{key} joins the two");
    }
}

/// An agent that enrols through the MCP `permaura_enroll` tool is recorded like one that presents its code as a bearer.
#[tokio::test]
async fn an_agent_enrolling_through_the_mcp_tool_is_recorded() {
    let state = common::seeded();
    let operator = common::operator_token(state.clone()).await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_, minted) = send(&app, "/v1/agents/enroll", &operator, json!({ "label": "Tool enrolled" })).await;
    let code = minted["code"].as_str().unwrap().to_string();
    let call = json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": { "name": "permaura_enroll", "arguments": { "code": code, "agent_id": "tool-enrolled" } },
    });
    let (status, body) = send_anon(&app, "/mcp", call).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    let enrolled = recorded(&state, "permaura.agent.enroll", "tool-enrolled");
    assert_eq!(enrolled.payload.summary["via"], "mcp_tool", "{}", enrolled.payload.summary);
    let token = body.to_string();
    let bearer = token.split("tok_").nth(1).map(|t| format!("tok_{}", &t[..32])).expect("a bearer came back");
    never_in_the_chain(&state, &bearer);
    never_in_the_chain(&state, &code);
}

/// A redemption whose record cannot be written grants no bearer: the record is written first, so the session is never put.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redemption_whose_record_fails_grants_no_bearer() {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!("permaura-enrol-record-{}-{}", std::process::id(), permaura_gateway::service::short_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db");
    let store = permaura_gateway::store::sqlite::SqliteStore::open(path.to_str().unwrap()).unwrap();
    permaura_gateway::seed::seed(&store).unwrap();
    let state = AppState::from_parts(std::sync::Arc::new(store), std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new()));
    let operator = common::operator_token(state.clone()).await;
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (_, minted) = send(&app, "/v1/agents/enroll", &operator, json!({ "label": "Unrecorded" })).await;
    let code = minted["code"].as_str().unwrap().to_string();

    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;")
        .unwrap();
    send(&app, "/mcp", &code, json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/list" })).await;
    conn.execute_batch("DROP TRIGGER refuse;").unwrap();
    assert!(
        state.service.store().session_by_token(&code).unwrap().is_none(),
        "no session row stands for a redemption that was never recorded"
    );
}
