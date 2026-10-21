//! A held grant or policy edit carries the whole row it was asked against, so confirming it after a later tightening must not undo that tightening.
//!
//! The hold's params carry a digest of the live row (and, for a policy edit that sets membership, of the grants that hold it), the device signs over it, and the apply refuses with a recorded conflict when the row has moved since.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{GrantAgent, GrantAgents};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::json;
use tower::ServiceExt;

mod common;

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    remote: bool,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder =
        Request::builder().method(method).uri(uri).header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    if remote {
        builder = builder.header("cf-ray", "abc123");
    }
    let req = match body {
        Some(b) => builder.header("content-type", "application/json").body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn gateway_with_device(seed_byte: u8) -> (axum::Router, AppState, ed25519_dalek::SigningKey) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key_for("device:approver", &pubkey, Some("user_approver")).unwrap());
    (app, state, sk)
}

async fn device_sign(
    app: &axum::Router,
    approval_id: &str,
    sk: &ed25519_dalek::SigningKey,
) -> (StatusCode, serde_json::Value) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use permaura_relay::{approval_display_full_digest_of, approval_result_preimage_v3, sign};
    let approver = "device:approver";
    let (_s, appr) = send(app, "GET", &format!("/v1/approvals/{approval_id}"), false, None).await;
    let request_hash = appr["request_hash"].as_str().unwrap().to_string();
    let job_id = appr["job_id"].as_str().unwrap().to_string();
    let audience = appr["approval_audience"].as_str().expect("audience").to_string();
    let shown = approval_display_full_digest_of(&appr).expect("full rendering");
    let decided_at = now_ms();
    let preimage =
        approval_result_preimage_v3(&audience, &job_id, approval_id, true, &request_hash, &shown, approver, decided_at);
    let device_sig = sign(sk, &preimage);
    send(
        app,
        "POST",
        "/v1/approvals",
        false,
        Some(json!({
            "approval_id": approval_id, "approve": true, "approver": approver,
            "request_hash": request_hash, "decided_at": decided_at, "job_id": job_id,
            "approver_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
            "audience": audience, "display_digest": shown, "device_sig": device_sig,
        })),
    )
    .await
}

fn refusals_naming(state: &AppState, id: &str) -> usize {
    state
        .service
        .store()
        .audit_events_from(0, 100_000)
        .unwrap()
        .iter()
        .filter(|e| {
            e.payload.action == "permaura.policy.write" && e.payload.decision == "deny" && e.payload.summary["id"] == id
        })
        .count()
}

const GRANT: &str = "gr_github_prs";
const POLICY: &str = "pol_github_prs";

/// The grant at a per-agent limit of 100 for `codex-cli`.
fn limit_codex_at_100(state: &AppState) {
    let store = state.service.store();
    let mut g = store.get_grant(GRANT).unwrap().unwrap();
    g.agents = GrantAgents::Agents(vec![GrantAgent { agent_id: "codex-cli".into(), per_agent_limit: Some(100) }]);
    assert!(store.update_grant(g).unwrap());
}

async fn hold_limit_raise(app: &axum::Router) -> String {
    let (s, body) = send(
        app,
        "PUT",
        &format!("/v1/grants/{GRANT}"),
        true,
        Some(json!({
            "name": "GitHub pull requests",
            "policy_ids": [POLICY],
            "agents": [{ "agent_id": "codex-cli", "per_agent_limit": 150 }],
        })),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "raising a limit over the broker is held: {body}");
    body["approval_id"].as_str().unwrap().to_string()
}

fn per_agent_limit(state: &AppState) -> Option<u64> {
    match state.service.store().get_grant(GRANT).unwrap().unwrap().agents {
        GrantAgents::Agents(members) => members[0].per_agent_limit,
        GrantAgents::AllAgents => None,
    }
}

/// The grant case: a limit raise is held, the owner then pauses the grant, and the raise is confirmed later.
#[tokio::test]
async fn a_held_grant_edit_confirmed_after_a_pause_does_not_re_enable_the_grant() {
    let (app, state, sk) = gateway_with_device(61);
    limit_codex_at_100(&state);
    let approval_id = hold_limit_raise(&app).await;

    let (ps, pbody) = send(&app, "PATCH", &format!("/v1/grants/{GRANT}"), true, Some(json!({ "enabled": false }))).await;
    assert_eq!(ps, StatusCode::OK, "a pause tightens and applies at once: {pbody}");

    let (s, body) = device_sign(&app, &approval_id, &sk).await;
    assert_eq!(s, StatusCode::CONFLICT, "a stale held edit is refused: {body}");
    let grant = state.service.store().get_grant(GRANT).unwrap().unwrap();
    assert!(!grant.enabled, "the pause made after the hold stands");
    assert_eq!(per_agent_limit(&state), Some(100), "nothing from the stale edit landed");
    assert_eq!(refusals_naming(&state, GRANT), 1, "the refusal is recorded");
}

/// The same hold, confirmed with nothing changed in between, still applies.
#[tokio::test]
async fn a_held_grant_edit_confirmed_against_an_unchanged_row_applies() {
    let (app, state, sk) = gateway_with_device(62);
    limit_codex_at_100(&state);
    let approval_id = hold_limit_raise(&app).await;
    let held = state.service.store().get_approval(&approval_id).unwrap().unwrap();
    let base = permaura_core::json_stream::string_at(&held.params, "/base_sha256");
    assert_eq!(base.as_deref().map(str::len), Some(64), "the hold binds the row it was asked against");

    let (s, body) = device_sign(&app, &approval_id, &sk).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(per_agent_limit(&state), Some(150));
}

/// A hold an earlier build made carries no digest, so nothing shows the row is the one it was asked against.
#[tokio::test]
async fn a_held_grant_edit_without_a_digest_is_refused() {
    let (app, state, sk) = gateway_with_device(63);
    limit_codex_at_100(&state);
    let approval_id = hold_limit_raise(&app).await;
    let store = state.service.store();
    let mut held = store.get_approval(&approval_id).unwrap().unwrap();
    let mut params = held.params.to_value_unbounded();
    params.as_object_mut().unwrap().remove("base_sha256");
    held.params = params.into();
    store.put_approval(held).unwrap();

    let (s, body) = device_sign(&app, &approval_id, &sk).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert_eq!(per_agent_limit(&state), Some(100));
    assert_eq!(refusals_naming(&state, GRANT), 1);
}

fn policy_body(requires_approval: &[&str], device_signed: &[&str]) -> serde_json::Value {
    json!({
        "connection_id": "github_acme",
        "name": "Pull requests",
        "allow": ["pull_requests.list", "pull_requests.create"],
        "requires_approval": requires_approval,
        "device_signed": device_signed,
        "grant_ids": [GRANT],
    })
}

/// The policy case: an edit is held, the owner then raises an action to `device_signed`, and the edit is confirmed later.
#[tokio::test]
async fn a_held_policy_edit_confirmed_after_a_raise_does_not_lower_the_action_again() {
    let (app, state, sk) = gateway_with_device(64);
    let store = state.service.store();
    let mut p = store.get_policy(POLICY).unwrap().unwrap();
    p.requires_approval = vec!["pull_requests.create".into()];
    store.put_policy(p).unwrap();

    let (hs, hbody) = send(&app, "PUT", &format!("/v1/policies/{POLICY}"), true, Some(policy_body(&[], &[]))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "dropping an approval rung over the broker is held: {hbody}");
    let approval_id = hbody["approval_id"].as_str().unwrap().to_string();

    // The owner at the host, so the raise applies at once.
    let (rs, rbody) = send(
        &app,
        "PUT",
        &format!("/v1/policies/{POLICY}"),
        false,
        Some(policy_body(&["pull_requests.create"], &["pull_requests.create"])),
    )
    .await;
    assert_eq!(rs, StatusCode::OK, "{rbody}");

    let (s, body) = device_sign(&app, &approval_id, &sk).await;
    assert_eq!(s, StatusCode::CONFLICT, "a stale held edit is refused: {body}");
    let policy = store.get_policy(POLICY).unwrap().unwrap();
    assert_eq!(policy.device_signed, vec!["pull_requests.create".to_string()], "the raise made after the hold stands");
    assert_eq!(refusals_naming(&state, POLICY), 1, "the refusal is recorded");
}

/// A policy edit that sets membership is stale once a grant holding the policy drops it.
#[tokio::test]
async fn a_held_policy_edit_confirmed_after_its_grant_dropped_it_does_not_rebind_it() {
    let (app, state, sk) = gateway_with_device(65);
    let store = state.service.store();
    let mut p = store.get_policy(POLICY).unwrap().unwrap();
    p.requires_approval = vec!["pull_requests.create".into()];
    store.put_policy(p).unwrap();

    let (hs, hbody) = send(&app, "PUT", &format!("/v1/policies/{POLICY}"), true, Some(policy_body(&[], &[]))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "{hbody}");
    let approval_id = hbody["approval_id"].as_str().unwrap().to_string();

    let mut g = store.get_grant(GRANT).unwrap().unwrap();
    g.policy_ids.clear();
    assert!(store.update_grant(g).unwrap());

    let (s, body) = device_sign(&app, &approval_id, &sk).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(store.get_grant(GRANT).unwrap().unwrap().policy_ids.is_empty(), "the grant does not hold the policy again");
    assert_eq!(store.get_policy(POLICY).unwrap().unwrap().requires_approval, vec!["pull_requests.create".to_string()]);
}

/// The agent case: creating an approved agent is held, the agent then enrols as pending, and the stale hold is confirmed.
#[tokio::test]
async fn a_held_agent_upsert_confirmed_after_the_agent_changed_does_not_approve_it() {
    use permaura_gateway::store::{Agent, AgentStatus};
    let (app, state, sk) = gateway_with_device(66);
    let (hs, hbody) = send(&app, "PUT", "/v1/agents/agt_late", true, Some(json!({ "name": "Late agent" }))).await;
    assert_eq!(hs, StatusCode::ACCEPTED, "creating an approved agent over the broker is held: {hbody}");
    let approval_id = hbody["approval_id"].as_str().unwrap().to_string();

    let store = state.service.store();
    store
        .put_agent(Agent { id: "agt_late".into(), name: "Late agent".into(), status: AgentStatus::Pending, enrolled_at: now_ms() })
        .unwrap();

    let (s, body) = device_sign(&app, &approval_id, &sk).await;
    assert_eq!(s, StatusCode::CONFLICT, "a stale held agent upsert is refused: {body}");
    assert_eq!(store.get_agent("agt_late").unwrap().unwrap().status, AgentStatus::Pending, "the agent was not approved");
    assert_eq!(refusals_naming(&state, "agt_late"), 1, "the refusal is recorded");
}

/// Narrowing an all-agents grant to one agent while raising that agent's ceiling is a budget loosening, so over the broker it waits for the device.
#[tokio::test]
async fn narrowing_an_all_agents_grant_with_a_raised_member_override_is_held() {
    let (app, state, _sk) = gateway_with_device(9);
    let store = state.service.store();
    let mut g = store.get_grant(GRANT).unwrap().unwrap();
    g.agents = GrantAgents::AllAgents;
    g.default_per_agent_limit = Some(5);
    assert!(store.update_grant(g).unwrap());
    let (s, body) = send(&app, "PUT", &format!("/v1/grants/{GRANT}"), true, Some(json!({
        "name": "GitHub pull requests",
        "policy_ids": [POLICY],
        "default_per_agent_limit": 5,
        "agents": [{ "agent_id": "codex-cli", "per_agent_limit": 1_000_000 }],
    }))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "raising one agent's budget over the broker is held: {body}");
    let stored = store.get_grant(GRANT).unwrap().unwrap();
    assert!(matches!(stored.agents, GrantAgents::AllAgents), "the held edit did not apply");
}

/// Bringing forward the expiry of the grant that holds a call on a device, beside a grant that permits it at auto, changes nothing yet and drops the call to auto once the new expiry passes, so over the broker it waits for the device.
#[tokio::test]
async fn ending_the_strict_grant_sooner_beside_a_lax_one_is_held() {
    let (app, state, _sk) = gateway_with_device(10);
    let store = state.service.store();
    let policy = |id: &str, allow: &[&str], device_signed: &[&str]| permaura_core::Policy {
        id: id.into(),
        connection_id: "generic_http".into(),
        name: id.into(),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        device_signed: device_signed.iter().map(|s| s.to_string()).collect(),
        device_signed_quorum: 1,
        ..Default::default()
    };
    let grant = |id: &str, policy: &str| permaura_core::Grant {
        grant_id: id.into(),
        name: id.into(),
        enabled: true,
        is_default: false,
        policy_ids: vec![policy.into()],
        agents: GrantAgents::AllAgents,
        period: permaura_core::GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    };
    store.put_policy(policy("pol_strict", &[], &["request"])).unwrap();
    store.put_policy(policy("pol_lax", &["request"], &[])).unwrap();
    store.put_grant(grant("gr_strict", "pol_strict")).unwrap();
    store.put_grant(grant("gr_lax", "pol_lax")).unwrap();
    let soon = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (s, body) = send(&app, "PUT", "/v1/grants/gr_strict", true, Some(json!({
        "name": "gr_strict",
        "policy_ids": ["pol_strict"],
        "all_agents": true,
        "expires_at": soon,
    }))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "ending the device rule sooner over the broker is held: {body}");
    assert_eq!(store.get_grant("gr_strict").unwrap().unwrap().expires_at, None, "the held edit did not apply");
}
