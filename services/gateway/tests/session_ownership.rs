//! A session, and the result of a call it had held, belong to the agent that holds it. An agent
//! must not list other sessions, revoke them, or read another agent's approval result.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::store::{Session, SessionRole};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

async fn call(app: &axum::Router, method: &str, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if !token.is_empty() {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn mcp_tool(app: &axum::Router, token: &str, name: &str, arguments: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": arguments } });
    call(app, "POST", "/mcp", token, body).await.1
}

fn router(state: AppState) -> axum::Router {
    build_router(state, "127.0.0.1:7376".parse().unwrap())
}

/// An agent-role session for `agent_id`, written straight to the store.
fn agent_session(state: &AppState, id: &str, agent_id: &str) -> String {
    let token = format!("tok_{id}");
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: id.into(),
            agent_id: agent_id.into(),
            user_id: None,
            device_id: None,
            token: token.clone(),
            role: SessionRole::Agent,
            created_at: 0,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
    token
}

/// GET /v1/sessions hands out the ids `permaura_revoke_session` takes, so it is operator-only.
#[tokio::test]
async fn an_agent_cannot_list_sessions() {
    let state = common::seeded();
    let agent = agent_session(&state, "sess_agent_a", "codex-cli");
    let app = router(state);
    let (s, _) = call(&app, "GET", "/v1/sessions", &agent, Value::Null).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, body) = call(&app, "GET", "/v1/sessions", seed::DEMO_TOKEN, Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body["sessions"].as_array().unwrap().iter().any(|r| r["id"] == "sess_agent_a"));
}

/// An agent revokes only its own agent's sessions; the operator's and another agent's survive.
#[tokio::test]
async fn an_agent_cannot_revoke_someone_elses_session() {
    let state = common::seeded();
    let agent = agent_session(&state, "sess_agent_a", "codex-cli");
    let _sibling = agent_session(&state, "sess_agent_a2", "codex-cli");
    let other = agent_session(&state, "sess_agent_b", "other-agent");
    let app = router(state.clone());

    for target in ["sess_demo", "sess_agent_b"] {
        let out = mcp_tool(&app, &agent, "permaura_revoke_session", json!({ "session_id": target })).await;
        assert!(out.get("error").is_some(), "revoking {target} must be refused: {out}");
    }
    let (s, _) = call(&app, "GET", "/v1/sessions", seed::DEMO_TOKEN, Value::Null).await;
    assert_eq!(s, StatusCode::OK, "the operator session still authenticates");
    let (s, _) = call(&app, "GET", "/v1/broker", &other, Value::Null).await;
    assert_eq!(s, StatusCode::OK, "the other agent's session still authenticates");

    let out = mcp_tool(&app, "", "permaura_revoke_session", json!({ "session_id": "sess_demo" })).await;
    assert!(out.get("error").is_some(), "an unauthenticated revoke must be refused: {out}");

    let out = mcp_tool(&app, &agent, "permaura_revoke_session", json!({ "session_id": "sess_agent_a2" })).await;
    assert_eq!(out["result"]["structuredContent"]["revoked"], true, "a sibling session of the same agent: {out}");
    let out = mcp_tool(&app, &agent, "permaura_revoke_session", json!({})).await;
    assert!(out.get("error").is_none(), "an agent may revoke its own session: {out}");
    let (s, _) = call(&app, "GET", "/v1/broker", &agent, Value::Null).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// An approval's redacted result belongs to the agent whose call was held.
#[tokio::test]
async fn an_agent_cannot_read_another_agents_approval() {
    let state = common::seeded();
    let agent = agent_session(&state, "sess_agent_a", "codex-cli");
    let other = agent_session(&state, "sess_agent_b", "other-agent");
    let store = state.service.store();
    store
        .put_approval(permaura_gateway::store::PendingApproval {
            id: "appr_owned".into(),
            session_id: "sess_agent_a".into(),
            capability: "github.issues.create".into(),
            resource: "github".into(),
            message: "held".into(),
            status: "approved".into(),
            grant_id: None,
            policy_id: None,
            params: json!({}).into(),
            result: Some(json!({ "private": "redacted output of agent a" }).into()),
            result_status: Some(200),
            resolution_reason: None,
            created_at: 0,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
    let app = router(state);

    let out = mcp_tool(&app, &other, "permaura_get_approval_status", json!({ "approval_id": "appr_owned" })).await;
    assert!(out.get("error").is_some(), "{out}");
    assert!(!out.to_string().contains("redacted output of agent a"));
    let out = mcp_tool(&app, "", "permaura_get_approval_status", json!({ "approval_id": "appr_owned" })).await;
    assert!(out.get("error").is_some(), "{out}");
    let out = mcp_tool(&app, &agent, "permaura_get_approval_status", json!({ "approval_id": "appr_owned" })).await;
    assert!(out.to_string().contains("redacted output of agent a"), "{out}");
}
