//! The bearer permaura.com holds sealed for a loopback-only gateway is a console session, and a console session is remote wherever it is presented.
//!
//! permaura.com's Cloudflare account can push the managed tunnel's connector a configuration that points it at a `tcp://` service, or route private-network traffic through it to the gateway's port, and the connector carries either until the gateway's guard stops it about a second later: long enough to deliver a request from loopback with no `Origin` and no forwarder header. Carrying a bearer it holds, that request must not be the owner at the keyboard: no first device trusted on its say-so, no vault for an unpaired gateway, and every loosening edit held for the paired device. The bearers this machine's own clients use (`operator.token`, which the CLI and the desktop supervisor read, and a session `POST /v1/sessions` opens) keep loopback authority.
//!
//! Every key, token and host here is synthetic.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use permaura_gateway::store::{Agent, AgentStatus};
use common::build_router;
use permaura_gateway::{seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

/// One request through the real router with no peer address (loopback), no `Origin` and no forwarder header.
async fn send(state: &AppState, bearer: &str, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "127.0.0.1:7376")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A loopback-only self-run gateway, the console bearer it would seal, and the `operator.token` value it would publish.
fn gateway() -> (AppState, String, String) {
    let state = common::seeded();
    let store = state.service.store();
    let console = permaura_gateway::mint_console_session(store.as_ref()).expect("a console session");
    let operator_token = seed::clean_bootstrap(store.as_ref()).expect("an operator token");
    assert!(console.starts_with(permaura_gateway::CONSOLE_TOKEN_PREFIX), "{console}");
    assert!(!operator_token.starts_with(permaura_gateway::CONSOLE_TOKEN_PREFIX), "{operator_token}");
    (state, console, operator_token)
}

/// What the desktop app's webview and other local clients open with the operator token.
async fn opened_session(state: &AppState, operator_token: &str) -> String {
    let (status, body) = send(state, operator_token, "POST", "/v1/sessions", json!({ "agent_id": "codex-cli" })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().expect("a session token").to_string();
    assert!(!token.starts_with(permaura_gateway::CONSOLE_TOKEN_PREFIX), "{token}");
    token
}

fn pair_body(approver_id: &str, seed: u8) -> Value {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = now_ms();
    let preimage = permaura_relay::approver_pairing_preimage(approver_id, &pubkey, issued_at);
    json!({ "approver_id": approver_id, "approver_pubkey": pubkey, "issued_at": issued_at, "sig": permaura_relay::sign(&sk, &preimage) })
}

fn pair_a_device(state: &AppState) {
    let sk = SigningKey::from_bytes(&[71; 32]);
    assert!(state.service.trust_approver_key("device:owner", &STANDARD.encode(sk.verifying_key().to_bytes())));
}

fn widening_policy(id: &str) -> Value {
    json!({ "id": id, "connection_id": "generic_http", "name": id, "allow": ["request"] })
}

fn has_policy(state: &AppState, id: &str) -> bool {
    state.service.store().list_policies().unwrap().iter().any(|p| p.id == id)
}

fn pending_agent(state: &AppState, id: &str) {
    let mut agent = Agent::approved(id, id, now_ms());
    agent.status = AgentStatus::Pending;
    state.service.store().put_agent(agent).unwrap();
}

fn agent_status(state: &AppState, id: &str) -> AgentStatus {
    state.service.store().get_agent(id).unwrap().expect("the agent").status
}

#[tokio::test]
async fn an_unpaired_gateway_refuses_the_console_session_its_vault() {
    let (state, console, operator_token) = gateway();
    assert!(!state.service.any_device_trusted());
    let export = json!({ "passphrase": "correct horse battery staple" });
    let (status, body) = send(&state, &console, "POST", "/v1/vault/export", export.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("no device is paired to confirm it"), "{body}");

    let (status, body) = send(&state, &operator_token, "POST", "/v1/vault/export", export).await;
    assert_eq!(status, StatusCode::OK, "operator.token on loopback still exports: {body}");
}

#[tokio::test]
async fn the_console_session_cannot_anchor_the_first_device_or_open_sessions() {
    let (state, console, _) = gateway();
    let (status, body) = send(&state, &console, "POST", "/v1/approver-keys/pair", pair_body("device:sealed", 72)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("loopback-only"), "{body}");
    assert!(body.get("recovery_codes").is_none(), "{body}");
    assert!(!state.service.any_device_trusted(), "nothing trusted on a sealed bearer's say-so");

    let (status, body) = send(&state, &console, "POST", "/v1/sessions", json!({ "agent_id": "codex-cli" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn a_paired_gateway_holds_the_console_sessions_edits_and_agent_approvals() {
    let (state, console, _) = gateway();
    pair_a_device(&state);

    let (status, body) = send(&state, &console, "POST", "/v1/policies", widening_policy("p_sealed")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "requires_approval", "{body}");
    assert_eq!(body["required_tier"], "device_signed", "{body}");
    assert!(!has_policy(&state, "p_sealed"), "nothing applied before the device signed");

    pending_agent(&state, "agt_sealed");
    let (status, body) = send(&state, &console, "POST", "/v1/agents/agt_sealed/approve", json!({})).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(agent_status(&state, "agt_sealed"), AgentStatus::Pending, "the agent waits for the device");
}

/// The blast radius: only a console session's prefix moves. The CLI's `operator.token` (and the desktop supervisor, which reads the same file) and a session opened from it keep loopback authority.
#[tokio::test]
async fn the_operator_token_and_sessions_opened_from_it_stay_local() {
    let (state, _, operator_token) = gateway();
    let webview = opened_session(&state, &operator_token).await;

    let (status, body) = send(&state, &operator_token, "POST", "/v1/approver-keys/pair", pair_body("device:first", 73)).await;
    assert_eq!(status, StatusCode::OK, "operator.token anchors the first device over loopback: {body}");

    for (who, bearer) in [("operator.token", operator_token.as_str()), ("an opened session", webview.as_str())] {
        let id = format!("p_{}", who.len());
        let (status, body) = send(&state, bearer, "POST", "/v1/policies", widening_policy(&id)).await;
        assert_eq!(status, StatusCode::CREATED, "{who} applies a loosening edit at once: {body}");
        assert!(has_policy(&state, &id), "{who}");

        let agent = format!("agt_{}", who.len());
        pending_agent(&state, &agent);
        let (status, body) = send(&state, bearer, "POST", &format!("/v1/agents/{agent}/approve"), json!({})).await;
        assert_eq!(status, StatusCode::OK, "{who} approves an agent at once: {body}");
        assert_eq!(agent_status(&state, &agent), AgentStatus::Approved, "{who}");
    }
}

// ── An enrolment code carries the remoteness of the request that minted it ─────────────────

/// [`send`] with extra headers.
async fn send_with(state: &AppState, bearer: &str, uri: &str, body: Value, extra: &[(&str, &str)]) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "127.0.0.1:7376")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"));
    for (name, value) in extra {
        req = req.header(*name, *value);
    }
    let resp = app.oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn invoke() -> Value {
    json!({ "capability": "braintree.transactions.search", "params": { "status": "failed", "date": "2026-06-21" } })
}

/// Mint a code with `minter` (plus `extra` headers), redeem it, approve and grant the agent with the local operator token, and return the agent's bearer.
async fn enrolled_agent(state: &AppState, minter: &str, extra: &[(&str, &str)], operator_token: &str) -> String {
    let (status, body) = send_with(state, minter, "/v1/agents/enroll", json!({ "label": "opr99" }), extra).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let code = body["code"].as_str().expect("a code").to_string();
    send(state, &code, "POST", "/v1/invoke", invoke()).await;
    let agent = state.service.store().session_by_token(&code).unwrap().expect("the session the code opened").agent_id;
    let (status, body) = send(state, operator_token, "POST", &format!("/v1/agents/{agent}/approve"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let grant = json!({ "name": format!("g_{agent}"), "policy_ids": ["pol_braintree_readonly"], "agents": [agent] });
    let (status, body) = send(state, operator_token, "POST", "/v1/grants", grant).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    code
}

/// On an unpaired gateway a console session minted a code, and the agent bearer it became was local on loopback, so the agent used a local-only credential that refuses the same call classed remote. A code a console session or a forwarded request mints now carries the console prefix, and the agent's calls are remote on every transport.
#[tokio::test]
async fn an_agent_enrolled_on_a_code_a_remote_request_minted_stays_remote() {
    let (state, console, operator_token) = gateway();
    for (minter, extra) in [(console.as_str(), &[][..]), (operator_token.as_str(), &[("x-forwarded-for", "203.0.113.9")][..])] {
        let code = enrolled_agent(&state, minter, extra, &operator_token).await;
        assert!(code.starts_with(permaura_gateway::CONSOLE_TOKEN_PREFIX), "{code}");
        let (status, body) = send(&state, &code, "POST", "/v1/invoke", invoke()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "over loopback with no header the call is still remote: {body}");
        assert!(body.to_string().contains("local-only"), "{body}");
    }
}

/// The control: a code minted at the gateway's own host is unchanged, and its agent keeps loopback authority.
#[tokio::test]
async fn an_agent_enrolled_on_a_code_minted_locally_is_unchanged() {
    let (state, _, operator_token) = gateway();
    let code = enrolled_agent(&state, &operator_token, &[], &operator_token).await;
    assert!(code.starts_with("ENRL-"), "{code}");
    let (status, body) = send(&state, &code, "POST", "/v1/invoke", invoke()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The same agent, enrolled through the `permaura_enroll` MCP tool instead of presenting the code as its bearer: a code a remote request minted becomes a bearer that is remote on every transport there too, and a locally minted one still becomes a local `tok_`.
#[tokio::test]
async fn the_mcp_enroll_tool_keeps_a_remote_code_remote() {
    let (state, console, operator_token) = gateway();
    for (minter, extra, remote) in [
        (console.as_str(), &[][..], true),
        (operator_token.as_str(), &[("x-forwarded-for", "203.0.113.9")][..], true),
        (operator_token.as_str(), &[][..], false),
    ] {
        let (status, body) = send_with(&state, minter, "/v1/agents/enroll", json!({ "label": "opr99-mcp" }), extra).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let code = body["code"].as_str().expect("a code").to_string();
        let agent = format!("mcp-{}", permaura_gateway::service::short_id());
        let call = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "permaura_enroll",
            "arguments": { "code": code, "agent_id": agent, "name": "MCP agent" } } });
        let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
        let req = Request::builder().method("POST").uri("/mcp").header("content-type", "application/json").body(Body::from(call.to_string())).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let enrolled: Value = serde_json::from_slice(&bytes).unwrap();
        let token = enrolled["result"]["structuredContent"]["token"].as_str().expect("an agent bearer").to_string();
        assert_eq!(token.starts_with(permaura_gateway::CONSOLE_TOKEN_PREFIX), remote, "{code} became {token}");

        let (status, body) = send(&state, &operator_token, "POST", &format!("/v1/agents/{agent}/approve"), json!({})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let grant = json!({ "name": format!("g_{agent}"), "policy_ids": ["pol_braintree_readonly"], "agents": [agent] });
        let (status, body) = send(&state, &operator_token, "POST", "/v1/grants", grant).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = send(&state, &token, "POST", "/v1/invoke", invoke()).await;
        if remote {
            assert_eq!(status, StatusCode::FORBIDDEN, "over loopback with no header the call is still remote: {body}");
            assert!(body.to_string().contains("local-only"), "{body}");
        } else {
            assert_eq!(status, StatusCode::OK, "a locally minted code keeps loopback authority: {body}");
        }
    }
}
