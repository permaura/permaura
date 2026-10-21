//! What an agent session may read about the estate.
//!
//! An agent is told about itself and about what its own grants reach, nothing more: not the other
//! agents on the gateway, not a connection no grant points it at, and not the policies on a reachable
//! connection that some other agent's grant activates. A Pending agent reaches nothing at all, so it
//! sees only itself. The operator still sees everything.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{Grant, GrantAgent, GrantAgents, GrantPeriod, Policy};
use permaura_gateway::store::{Agent, AgentStatus, Session, SessionRole};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::Value;
use tower::ServiceExt;

mod common;

const SCOPED: &str = "tok-scoped-agent";
const WAITING: &str = "tok-waiting-agent";

fn agent_session(id: &str, agent_id: &str, token: &str) -> Session {
    Session {
        class: Default::default(),
        opened_by: None,
        id: id.into(),
        agent_id: agent_id.into(),
        user_id: None,
        device_id: None,
        token: token.into(),
        role: SessionRole::Agent,
        created_at: permaura_gateway::service::now_ms(),
        revoked: false,
        expires_at: None,
        last_used_at: None,
        actor: None,
    }
}

fn estate() -> AppState {
    let state = common::seeded();
    let store = state.service.store();
    let now = permaura_gateway::service::now_ms();
    store.put_agent(Agent::approved("agt_scoped", "Scoped agent", now)).unwrap();
    store
        .put_agent(Agent { id: "agt_waiting".into(), name: "Waiting agent".into(), status: AgentStatus::Pending, enrolled_at: now })
        .unwrap();
    store.put_session(agent_session("sess_scoped", "agt_scoped", SCOPED)).unwrap();
    store.put_session(agent_session("sess_waiting", "agt_waiting", WAITING)).unwrap();
    // A second policy on the same connection that only the seeded agent's grant would ever carry.
    store
        .put_policy(Policy {
            id: "pol_github_admin".into(),
            connection_id: "github_acme".into(),
            name: "Repository admin".into(),
            allow: vec!["repos.delete".into()],
            deny: vec![],
            requires_approval: vec![],
            notify: vec![],
            device_signed: vec![],
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        })
        .unwrap();
    store
        .put_grant(Grant {
            grant_id: "gr_scoped".into(),
            name: "Scoped pull requests".into(),
            enabled: true,
            is_default: false,
            policy_ids: vec!["pol_github_prs".into()],
            agents: GrantAgents::Agents(vec![GrantAgent::new("agt_scoped"), GrantAgent::new("agt_waiting")]),
            period: GrantPeriod::Total,
            overall_limit: None,
            default_per_agent_limit: None,
            expires_at: None,
        })
        .unwrap();
    state
}

async fn get(state: &AppState, uri: &str, token: &str) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let req = Request::builder().uri(uri).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn ids(body: &Value, list: &str, key: &str) -> Vec<String> {
    let mut out: Vec<String> = body[list]
        .as_array()
        .unwrap_or_else(|| panic!("{list} in {body}"))
        .iter()
        .map(|v| v[key].as_str().unwrap().to_string())
        .collect();
    out.sort();
    out
}

#[tokio::test]
async fn an_agent_lists_only_itself() {
    let state = estate();
    let (status, body) = get(&state, "/v1/agents", SCOPED).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body, "agents", "id"), vec!["agt_scoped"]);

    let (status, body) = get(&state, "/v1/agents", WAITING).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body, "agents", "id"), vec!["agt_waiting"]);
    assert_eq!(body["agents"][0]["status"], "pending", "{body}");

    let (_, body) = get(&state, "/v1/agents", seed::DEMO_TOKEN).await;
    let all = ids(&body, "agents", "id");
    for id in ["agt_scoped", "agt_waiting", "codex-cli"] {
        assert!(all.contains(&id.to_string()), "the operator sees every agent: {all:?}");
    }
}

#[tokio::test]
async fn an_agent_sees_a_connection_its_grant_reaches_and_only_its_own_policies_on_it() {
    let state = estate();
    let (status, body) = get(&state, "/v1/connections/github_acme", SCOPED).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body, "policies", "id"), vec!["pol_github_prs"], "not the admin policy: {body}");

    let (status, body) = get(&state, "/v1/connections/braintree_production", SCOPED).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no grant of its reaches this one: {body}");

    let (status, body) = get(&state, "/v1/connections/github_acme", seed::DEMO_TOKEN).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body, "policies", "id"), vec!["pol_github_admin", "pol_github_prs"], "{body}");
}

#[tokio::test]
async fn a_pending_agent_sees_no_connection_even_one_its_grant_names() {
    let state = estate();
    for id in ["github_acme", "braintree_production"] {
        let (status, body) = get(&state, &format!("/v1/connections/{id}"), WAITING).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{id}: {body}");
    }
}

/// A paused grant reaches nothing, so it shows nothing either.
#[tokio::test]
async fn a_disabled_grant_does_not_reveal_its_connection() {
    let state = estate();
    let store = state.service.store();
    let mut g = store.get_grant("gr_scoped").unwrap().unwrap();
    g.enabled = false;
    store.update_grant(g).unwrap();
    let (status, body) = get(&state, "/v1/connections/github_acme", SCOPED).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}
