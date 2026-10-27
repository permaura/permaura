//! An agent an enrolment code enrols is named after the MCP client that redeemed it, from `initialize`'s `params.clientInfo`, unless the operator labeled the code; every one of them used to read "Enrolled agent".

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::allowances::{Allowances, AllowancesConfig};
use crate::connectors::{MockCommandRunner, MockHttpClient};
use crate::oauth::{OAuthRs, RsConfig};
use crate::service::{now_ms, EnforcementService, AGENT_ENROLL_ACTION, AGENT_NAMED_BY_CLIENT_ACTION, DEFAULT_ENROLLED_AGENT_NAME};
use crate::store::memory::MemoryStore;
use crate::store::{Agent, AgentStatus, EnrolmentCode, Session, SessionRole, Store};
use crate::AppState;

const CODE: &str = "ENRL-0A1B-2C3D-4E5F-6A7B-8C9D-0E1F-2A3B-4C5D";
const PUBLIC_URL: &str = "https://g-client-name.permaura.test";

fn self_run() -> AppState {
    AppState::from_parts(Arc::new(MemoryStore::new()), Arc::new(MockHttpClient::new()))
}

/// A gateway with a public URL, whose gate authenticates every `/mcp` request before its body is read, but lets a live code through to be redeemed once it is. It has fetched no signing keys, which a code bearer never needs.
fn resource_server() -> AppState {
    resource_server_with(None)
}

/// A self-run gateway that may enrol no more agents.
fn self_run_with_no_agent_room() -> AppState {
    AppState::new(EnforcementService::new(Arc::new(MemoryStore::new()), Arc::new(MockHttpClient::new())).with_allowances(no_agent_room()))
}

fn no_agent_room() -> Arc<Allowances> {
    Arc::new(Allowances::new(AllowancesConfig { agents: Some(0), ..Default::default() }).with_log_interval(std::time::Duration::ZERO))
}

fn resource_server_with(allowances: Option<Arc<Allowances>>) -> AppState {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let oauth = Arc::new(OAuthRs::new(RsConfig {
        public_url: PUBLIC_URL.into(),
        mcp_resource: format!("{PUBLIC_URL}/mcp"),
        public_url_aliases: Vec::new(),
        issuer: "https://permaura.test/api/auth".into(),
        jwks_uri: "https://permaura.test/api/auth/jwks".into(),
        owner_sub: Some("user_owner".into()),
    }));
    let backend = crate::backend::build_backend(store.clone());
    let service = EnforcementService::from_components(store, Arc::new(MockHttpClient::new()), Arc::new(MockCommandRunner::new()), backend, Some(oauth));
    AppState::new(match allowances {
        Some(allowances) => service.with_allowances(allowances),
        None => service,
    })
}

fn mint(state: &AppState, code: &str, label: Option<&str>) {
    let now = now_ms();
    state
        .service
        .store()
        .put_enrolment_code(EnrolmentCode {
            code: code.into(),
            label: label.map(String::from),
            created_at: now,
            expires_at: now + 15 * 60 * 1000,
            used: false,
        })
        .unwrap();
}

async fn post_mcp(state: &AppState, bearer: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut request = Request::builder().method("POST").uri("/mcp").header("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let resp = crate::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn initialize(state: &AppState, bearer: Option<&str>, client_info: Option<Value>) -> (StatusCode, Value) {
    let mut params = json!({ "protocolVersion": "2025-06-18", "capabilities": {} });
    if let Some(info) = client_info {
        params["clientInfo"] = info;
    }
    post_mcp(state, bearer, json!({ "jsonrpc": "2.0", "id": 7, "method": "initialize", "params": params })).await
}

fn claude_code() -> Option<Value> {
    Some(json!({ "name": "claude-code", "version": "2.0.0" }))
}

/// The agent the code's session belongs to.
fn enrolled(state: &AppState, code: &str) -> Agent {
    let session = state.service.store().session_by_token(code).unwrap().expect("the code opened a session");
    assert_eq!(session.role, SessionRole::Agent);
    state.service.store().get_agent(&session.agent_id).unwrap().expect("and enrolled its agent")
}

/// The audit records `action` holds for `agent_id`, oldest first.
fn records(state: &AppState, action: &str, agent_id: &str) -> Vec<Value> {
    let events = state.service.store().audit_events(None).unwrap();
    events.into_iter().filter(|e| e.payload.action == action && e.payload.resource == agent_id).map(|e| e.payload.summary).collect()
}

/// What `initialize` answers a caller that names no client and holds no bearer, which nothing here may change.
async fn plain_initialize_result() -> Value {
    let (status, body) = initialize(&self_run(), None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["serverInfo"]["name"], "permaura-gateway", "{body}");
    body["result"].clone()
}

#[tokio::test]
async fn a_code_with_no_label_names_its_agent_after_the_client_that_redeems_it_at_initialize() {
    let state = self_run();
    mint(&state, CODE, None);
    let (status, body) = initialize(&state, Some(CODE), claude_code()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], 7);
    assert_eq!(body["result"], plain_initialize_result().await, "naming the agent changes nothing in the answer");
    let agent = enrolled(&state, CODE);
    assert_eq!(agent.name, "Claude Code");
    assert!(agent.id.starts_with("claude-code-"), "the id follows the name: {}", agent.id);
    assert_eq!(agent.status, AgentStatus::Pending, "a name approves nothing");
    let enroll = records(&state, AGENT_ENROLL_ACTION, &agent.id);
    assert_eq!(enroll.len(), 1, "{enroll:?}");
    assert_eq!(enroll[0]["client"], "Claude Code", "the client's claim is on the record: {}", enroll[0]);
    assert!(records(&state, AGENT_NAMED_BY_CLIENT_ACTION, &agent.id).is_empty(), "it was named as it enrolled, not renamed");
}

#[tokio::test]
async fn the_operators_label_wins_over_the_name_the_client_gives_itself() {
    for (mode, state) in [("self-run", self_run()), ("resource server", resource_server())] {
        mint(&state, CODE, Some("ci-bot"));
        let (status, body) = initialize(&state, Some(CODE), claude_code()).await;
        assert_eq!(status, StatusCode::OK, "{mode}: {body}");
        let agent = enrolled(&state, CODE);
        assert_eq!(agent.name, "ci-bot", "{mode}");
        assert!(agent.id.starts_with("ci-bot-"), "{mode}: {}", agent.id);
        let enroll = records(&state, AGENT_ENROLL_ACTION, &agent.id);
        assert_eq!((enroll[0]["label"].as_str(), enroll[0]["client"].as_str()), (Some("ci-bot"), Some("Claude Code")), "{mode}: the claim is recorded even where the label won");
    }
}

#[tokio::test]
async fn initialize_answers_as_before_with_no_bearer_or_one_that_names_nothing() {
    let plain = plain_initialize_result().await;
    let state = self_run();
    mint(&state, "ENRL-SPNT-0000-0000-0000", None);
    state.service.store().consume_enrolment_code("ENRL-SPNT-0000-0000-0000", now_ms()).unwrap();
    for bearer in [None, Some("garbage"), Some("tok_nobody_holds_this"), Some("ENRL-FFFF-FFFF-FFFF-FFFF"), Some("pgc_ENRL-0000-0000-0000-0000"), Some("ENRL-SPNT-0000-0000-0000")] {
        for client in [None, claude_code()] {
            let (status, body) = initialize(&state, bearer, client.clone()).await;
            assert_eq!(status, StatusCode::OK, "{bearer:?}, {client:?}: {body}");
            assert_eq!(body["result"], plain, "{bearer:?}, {client:?}");
            assert_eq!(body["id"], 7, "{bearer:?}, {client:?}");
        }
    }
    assert!(state.service.store().list_agents().unwrap().is_empty(), "nothing was enrolled");
}

#[tokio::test]
async fn an_initialize_naming_no_client_leaves_the_code_to_the_next_call_as_before() {
    let state = self_run();
    mint(&state, CODE, None);
    for info in [None, Some(json!({ "name": "\u{200B}\u{202E}", "version": "1" }))] {
        let (status, body) = initialize(&state, Some(CODE), info).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert!(state.service.store().enrolment_code_redeemable(CODE, now_ms()).unwrap(), "the code is not redeemed");
    assert!(state.service.store().list_agents().unwrap().is_empty());
}

/// A client that called anything else first redeemed the code under the default name; its `initialize` names it then, without moving its id.
#[tokio::test]
async fn an_agent_the_code_already_enrolled_under_the_default_name_is_renamed_at_initialize() {
    let state = self_run();
    mint(&state, CODE, None);
    let (status, body) = post_mcp(&state, Some(CODE), json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = enrolled(&state, CODE);
    assert_eq!(before.name, DEFAULT_ENROLLED_AGENT_NAME);
    assert!(before.id.starts_with("agent-"), "{}", before.id);

    let (status, body) = initialize(&state, Some(CODE), Some(json!({ "name": "my-ci-bot", "version": "0.1" }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = enrolled(&state, CODE);
    assert_eq!(after.name, "My Ci Bot");
    assert_eq!((after.id.as_str(), after.status, after.enrolled_at), (before.id.as_str(), AgentStatus::Pending, before.enrolled_at), "only the name moves");

    let enroll = records(&state, AGENT_ENROLL_ACTION, &after.id);
    assert!(enroll[0].get("client").is_none(), "tools/list named no client: {}", enroll[0]);
    let named = records(&state, AGENT_NAMED_BY_CLIENT_ACTION, &after.id);
    assert_eq!(named.len(), 1, "the rename is recorded: {named:?}");
    assert_eq!((named[0]["name"].as_str(), named[0]["previous_name"].as_str()), (Some("My Ci Bot"), Some(DEFAULT_ENROLLED_AGENT_NAME)), "{}", named[0]);
    assert!(named[0]["session_id"].as_str().is_some_and(|s| s.starts_with("sess_")), "{}", named[0]);

    let _ = initialize(&state, Some(CODE), claude_code()).await;
    assert_eq!(enrolled(&state, CODE).name, "My Ci Bot", "a name once given is not taken by the next initialize");
    assert_eq!(records(&state, AGENT_NAMED_BY_CLIENT_ACTION, &after.id).len(), 1, "and a rename that did not happen is not recorded");
}

/// The resource server's gate lets a live code through unredeemed, so the agent is enrolled under its client's name, and the pending notice its redemption announces carries that name.
#[tokio::test]
async fn behind_the_resource_server_gate_a_live_code_enrols_its_agent_under_its_clients_name() {
    let state = resource_server();
    mint(&state, CODE, None);
    let (status, body) = initialize(&state, Some(CODE), Some(json!({ "name": "cursor-vscode", "version": "1.7" }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"]["serverInfo"]["name"], "permaura-gateway", "{body}");
    let agent = enrolled(&state, CODE);
    assert_eq!(agent.name, "Cursor");
    assert!(agent.id.starts_with("cursor-"), "enrolled under the name, not renamed after: {}", agent.id);
    assert_eq!(agent.status, AgentStatus::Pending);
    assert_eq!(records(&state, AGENT_ENROLL_ACTION, &agent.id)[0]["client"], "Cursor");
    assert!(records(&state, AGENT_NAMED_BY_CLIENT_ACTION, &agent.id).is_empty());

    // The gate refuses what it refused before.
    for bearer in [None, Some("garbage")] {
        let (status, body) = initialize(&state, bearer, claude_code()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{bearer:?}: {body}");
    }
    assert_eq!(state.service.store().list_agents().unwrap().len(), 1, "and enrolled nobody");
}

/// Behind the gate, a code another request already redeemed under the default name is authenticated by the gate as before, and renamed at `initialize`.
#[tokio::test]
async fn behind_the_resource_server_gate_an_agent_enrolled_by_an_earlier_request_is_renamed_at_initialize() {
    let state = resource_server();
    mint(&state, CODE, None);
    let (status, body) = post_mcp(&state, Some(CODE), json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = enrolled(&state, CODE);
    assert_eq!(before.name, DEFAULT_ENROLLED_AGENT_NAME);
    let (status, body) = initialize(&state, Some(CODE), claude_code()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = enrolled(&state, CODE);
    assert_eq!((after.id.as_str(), after.name.as_str()), (before.id.as_str(), "Claude Code"));
    assert_eq!(records(&state, AGENT_NAMED_BY_CLIENT_ACTION, &after.id).len(), 1);
}

/// A paused gateway redeems nothing. Self-run, `initialize` is answered as before and the unspent code waits for the resume; behind the gate it is refused as the gate refused it before.
#[tokio::test]
async fn a_gateway_with_agents_paused_redeems_nothing_and_answers_initialize_as_before() {
    let plain = plain_initialize_result().await;
    for (mode, state) in [("self-run", self_run()), ("resource server", resource_server())] {
        state.service.pause_agents_for_this_run();
        mint(&state, CODE, None);
        let (status, body) = initialize(&state, Some(CODE), claude_code()).await;
        if mode == "self-run" {
            assert_eq!(status, StatusCode::OK, "{mode}: {body}");
            assert_eq!(body["result"], plain, "{mode}: {body}");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "{mode}: the gate's answer to a paused code, as before: {body}");
        }
        assert!(state.service.store().enrolment_code_redeemable(CODE, now_ms()).unwrap(), "{mode}: the code is not redeemed");
        assert!(state.service.store().list_agents().unwrap().is_empty(), "{mode}");
    }
}

/// An enrolled agent reconnecting while agents are paused still initializes: naming only looks its session up, and its calls meet the pause as they did before.
#[tokio::test]
async fn an_enrolled_agent_reconnecting_while_agents_are_paused_still_initializes() {
    let plain = plain_initialize_result().await;
    let state = self_run();
    mint(&state, CODE, None);
    let (status, body) = post_mcp(&state, Some(CODE), json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session = state.service.store().session_by_token(CODE).unwrap().unwrap();
    state.service.pause_agents_for_this_run();
    let (status, body) = initialize(&state, Some(CODE), claude_code()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["result"], plain, "{body}");
    assert_eq!(state.service.store().session_by_token(CODE).unwrap().unwrap().last_used_at, session.last_used_at, "the lookup touched nothing");
}

/// THE MISLEADING 401. With the agent allowance full the redemption is refused after the code is spent; `initialize` used to answer normally and the client's next call heard only that it held no session (self-run) or was sent to sign in (behind the gate).
#[tokio::test]
async fn a_full_agent_allowance_is_the_answer_to_initialize() {
    for (mode, state) in [("self-run", self_run_with_no_agent_room()), ("resource server", resource_server_with(Some(no_agent_room())))] {
        mint(&state, CODE, None);
        let (status, body) = initialize(&state, Some(CODE), claude_code()).await;
        assert_eq!(status, StatusCode::OK, "{mode}: a JSON-RPC error, not a sign-in challenge: {body}");
        assert_eq!(body["id"], 7, "{mode}: {body}");
        assert!(body.get("result").is_none(), "{mode}: {body}");
        assert_eq!(body["error"]["code"], -32000, "{mode}: {body}");
        assert!(body["error"]["message"].as_str().is_some_and(|m| m.starts_with("allowance exceeded:")), "{mode}: {body}");
        assert!(state.service.store().list_agents().unwrap().is_empty(), "{mode}: nobody was enrolled");
    }
}

/// A body naming no client, with the allowance full, is refused the same way behind the gate, whatever its method.
#[tokio::test]
async fn behind_the_gate_a_full_agent_allowance_is_the_answer_to_any_first_call() {
    let state = resource_server_with(Some(no_agent_room()));
    mint(&state, CODE, None);
    let (status, body) = post_mcp(&state, Some(CODE), json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], 3, "{body}");
    assert!(body["error"]["message"].as_str().is_some_and(|m| m.starts_with("allowance exceeded:")), "{body}");
}

fn agent_session(agent_id: &str, role: SessionRole) -> Session {
    Session {
        class: Default::default(),
        opened_by: None,
        id: format!("sess_{agent_id}"),
        agent_id: agent_id.into(),
        user_id: None,
        device_id: None,
        token: format!("tok_{agent_id}"),
        role,
        created_at: 0,
        revoked: false,
        expires_at: None,
        last_used_at: None,
        actor: None,
    }
}

#[test]
fn only_a_pending_agent_still_carrying_the_default_name_is_renamed() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()));
    let agent = |id: &str, name: &str, status: AgentStatus| Agent { id: id.into(), name: name.into(), status, enrolled_at: 11 };
    store.put_agent(agent("agent-pending", DEFAULT_ENROLLED_AGENT_NAME, AgentStatus::Pending)).unwrap();
    store.put_agent(agent("agent-approved", DEFAULT_ENROLLED_AGENT_NAME, AgentStatus::Approved)).unwrap();
    store.put_agent(agent("ci-bot-1", "ci-bot", AgentStatus::Pending)).unwrap();
    store.put_agent(agent("agent-renamed", "Enrolled agent 2", AgentStatus::Pending)).unwrap();

    let rename = |id: &str, role: SessionRole| service.name_enrolled_agent_from_client(&agent_session(id, role), "Claude Code").unwrap();
    assert!(rename("agent-pending", SessionRole::Agent));
    assert_eq!(store.get_agent("agent-pending").unwrap(), Some(agent("agent-pending", "Claude Code", AgentStatus::Pending)), "only the name moves");
    assert!(!rename("agent-pending", SessionRole::Agent), "and only once");

    assert!(!rename("agent-approved", SessionRole::Agent), "an approved agent keeps its name");
    assert!(!rename("ci-bot-1", SessionRole::Agent), "a name the operator chose stays");
    assert!(!rename("agent-renamed", SessionRole::Agent), "so does any other name");
    assert!(!rename("agent-nobody", SessionRole::Agent), "an agent that is gone is not brought back");
    store.put_agent(agent("agent-operator", DEFAULT_ENROLLED_AGENT_NAME, AgentStatus::Pending)).unwrap();
    assert!(!rename("agent-operator", SessionRole::Operator), "an operator session names no agent");
    assert_eq!(store.get_agent("agent-approved").unwrap().unwrap().name, DEFAULT_ENROLLED_AGENT_NAME);
    assert_eq!(store.get_agent("agent-approved").unwrap().unwrap().status, AgentStatus::Approved);
    assert_eq!(store.get_agent("ci-bot-1").unwrap().unwrap().name, "ci-bot");
    assert!(store.get_agent("agent-nobody").unwrap().is_none());
    assert_eq!(store.get_agent("agent-operator").unwrap().unwrap().name, DEFAULT_ENROLLED_AGENT_NAME);
}
