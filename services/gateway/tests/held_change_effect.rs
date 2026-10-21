//! A held policy or grant change applies only while it lowers nothing beyond what it lowered when it was held. The
//! gateway keeps what it loosened beside the hold and compares at the confirm, so a change whose effect another change
//! unmasked in between is retired and asked for again, however many signatures it carries.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{Grant, GrantAgents, GrantPeriod, Policy};
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
        builder = builder.header("cf-ray", "8f00000000000000-SIN");
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

/// The owner's device, the only one paired.
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

/// The device's v3 signature over the approval as served now, the confirm permaura.com relays.
fn signed_confirm(served: &serde_json::Value, approval_id: &str, sk: &ed25519_dalek::SigningKey) -> serde_json::Value {
    signed_confirm_as(served, approval_id, "device:approver", sk)
}

/// [`signed_confirm`] from the device `approver`.
fn signed_confirm_as(served: &serde_json::Value, approval_id: &str, approver: &str, sk: &ed25519_dalek::SigningKey) -> serde_json::Value {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use permaura_relay::{approval_display_full_digest_of, approval_result_preimage_v3, sign};
    let request_hash = served["request_hash"].as_str().unwrap().to_string();
    let job_id = served["job_id"].as_str().unwrap().to_string();
    let audience = served["approval_audience"].as_str().expect("audience").to_string();
    let shown = approval_display_full_digest_of(served).expect("full rendering");
    let decided_at = now_ms();
    let preimage =
        approval_result_preimage_v3(&audience, &job_id, approval_id, true, &request_hash, &shown, approver, decided_at);
    json!({
        "approval_id": approval_id, "approve": true, "approver": approver,
        "request_hash": request_hash, "decided_at": decided_at, "job_id": job_id,
        "approver_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
        "audience": audience, "display_digest": shown, "device_sig": sign(sk, &preimage),
    })
}

fn refunds(id: &str, allow: &[&str], device_signed: &[&str]) -> Policy {
    Policy {
        id: id.into(),
        connection_id: "generic_http".into(),
        name: id.into(),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        device_signed: device_signed.iter().map(|s| s.to_string()).collect(),
        device_signed_quorum: 1,
        ..Policy::default()
    }
}

fn everyone(id: &str, policy: &str, enabled: bool) -> Grant {
    Grant {
        grant_id: id.into(),
        name: id.into(),
        enabled,
        is_default: false,
        policy_ids: vec![policy.into()],
        agents: GrantAgents::AllAgents,
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    }
}

fn switch(id: &str, policy: &str, enabled: bool) -> serde_json::Value {
    json!({ "name": id, "policy_ids": [policy], "all_agents": true, "enabled": enabled })
}

/// Refunds take one device through `g_strict`, beside a switched-off `g_lax` that would run them at auto.
fn estate(state: &AppState) {
    let store = state.service.store();
    store.put_policy(refunds("pol_strict", &[], &["request"])).unwrap();
    store.put_policy(refunds("pol_lax", &["request"], &[])).unwrap();
    store.put_grant(everyone("g_strict", "pol_strict", true)).unwrap();
    store.put_grant(everyone("g_lax", "pol_lax", false)).unwrap();
}

fn enabled(state: &AppState, id: &str) -> bool {
    state.service.store().get_grant(id).unwrap().unwrap().enabled
}

/// The owner's device signs "switch on g_lax", held at one signature because `g_strict` masks it. A relay that holds
/// the confirm sends "switch off g_strict", a tightening while `g_lax` is off, so it applies at once; then it delivers
/// the confirm. Applied, refunds would run at auto, lowered by a change no device saw lower them.
#[tokio::test]
async fn a_confirm_held_back_until_another_change_unmasks_it_is_retired() {
    let (app, state, sk) = gateway_with_device(31);
    estate(&state);

    let (status, held) = send(&app, "PUT", "/v1/grants/g_lax", true, Some(switch("g_lax", "pol_lax", true))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "switching on the lax grant from off the host is held: {held}");
    assert_eq!(held["required_signatures"], 1, "at one signature, since the strict grant masks it: {held}");
    let approval_id = held["approval_id"].as_str().unwrap().to_string();
    let (_, served) = send(&app, "GET", &format!("/v1/approvals/{approval_id}"), false, None).await;
    let confirm = signed_confirm(&served, &approval_id, &sk);

    let (status, body) = send(&app, "PUT", "/v1/grants/g_strict", true, Some(switch("g_strict", "pol_strict", false))).await;
    assert_eq!(status, StatusCode::OK, "switching off the strict grant leaves refunds denied, a tightening: {body}");

    let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(confirm)).await;
    assert_eq!(status, StatusCode::CONFLICT, "the confirm delivered afterwards does not apply: {body}");
    assert!(!enabled(&state, "g_lax"), "the lax grant stays off, so refunds stay denied");
    let row = state.service.store().get_approval(&approval_id).unwrap().unwrap();
    assert_eq!(row.status, "denied", "the hold is retired: {row:?}");
    assert_eq!(row.resolution_reason.as_deref(), Some("effect_widened"));
}

/// The control: the strict grant was already off when "switch on g_lax" was asked for, so the device signed a change
/// that took refunds from denied to auto, and that is what it does.
#[tokio::test]
async fn a_change_that_lowers_what_it_lowered_when_held_applies() {
    let (app, state, sk) = gateway_with_device(32);
    estate(&state);

    let (status, body) = send(&app, "PUT", "/v1/grants/g_strict", true, Some(switch("g_strict", "pol_strict", false))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, held) = send(&app, "PUT", "/v1/grants/g_lax", true, Some(switch("g_lax", "pol_lax", true))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let approval_id = held["approval_id"].as_str().unwrap().to_string();
    let (_, served) = send(&app, "GET", &format!("/v1/approvals/{approval_id}"), false, None).await;

    let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(signed_confirm(&served, &approval_id, &sk))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(enabled(&state, "g_lax"), "the change it was asked for applied");
    assert_eq!(state.service.store().get_approval(&approval_id).unwrap().unwrap().status, "approved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirm_reloads_the_pending_row_after_waiting_for_the_control_plane() {
    let (app, state, _) = gateway_with_device(33);
    estate(&state);
    let (_, held) = send(&app, "PUT", "/v1/grants/g_lax", true, Some(switch("g_lax", "pol_lax", true))).await;
    let id = held["approval_id"].as_str().unwrap().to_string();
    let lock = state.service.control_plane_mutex().lock().await;
    let service = state.service.clone();
    let waiting_id = id.clone();
    let task = tokio::spawn(async move { service.resolve_approval(&waiting_id, true, "device_signed", Some("device:approver")).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!task.is_finished(), "confirmation waits for the control-plane lock");
    let mut row = state.service.store().get_approval(&id).unwrap().unwrap();
    row.expires_at = Some(now_ms() - 1);
    state.service.store().put_approval(row).unwrap();
    drop(lock);
    assert!(task.await.unwrap().is_err(), "a hold that expired while waiting cannot apply");
    assert!(!enabled(&state, "g_lax"));
}

/// An estate too large to work a change out on within the classification budget: `n` all-agents grants of a two-person
/// rule, each ending at its own moment, and one grant naming `n` agents.
fn estate_past_the_budget(state: &AppState, n: usize) {
    use permaura_core::GrantAgent;
    let store = state.service.store();
    store.put_policy(Policy { device_signed_quorum: 2, ..refunds("pol_two", &[], &["request"]) }).unwrap();
    let now = time::OffsetDateTime::now_utc();
    for i in 0..n {
        store.put_grant(Grant { expires_at: Some(now + time::Duration::minutes(10 + i as i64)), ..everyone(&format!("g_{i}"), "pol_two", true) }).unwrap();
    }
    let named = GrantAgents::Agents((0..n).map(|i| GrantAgent::new(format!("agent-{i}"))).collect());
    store.put_grant(Grant { agents: named, ..everyone("g_named", "pol_two", true) }).unwrap();
}

/// A change whose effect cannot be worked out within the classification budget is held at the most people any rule on
/// the connection it touches asks for, and that many signatures apply it. It was retired at every confirm, so on an
/// estate past the budget no grant could be paused from off the host.
#[tokio::test]
async fn a_change_past_the_classification_budget_applies_on_the_most_people() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use permaura_gateway::policy_guard::{held_effect, GuardContext, HeldEffect, Mutation};
    let (app, state, sk) = gateway_with_device(36);
    let second = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
    assert!(state.service.trust_approver_key_for("device:second", &STANDARD.encode(second.verifying_key().to_bytes()), Some("user_second")).unwrap());
    estate_past_the_budget(&state, 500);
    let store = state.service.store();
    let (policies, grants) = (store.list_policies().unwrap(), store.list_grants().unwrap());
    let paused = Grant { enabled: false, ..store.get_grant("g_0").unwrap().unwrap() };
    let ctx = GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
    assert!(matches!(held_effect(&Mutation::GrantUpsert { grant: paused }, &ctx, &[]), HeldEffect::PastBudget), "setup: past the budget");

    let (status, held) = send(&app, "PATCH", "/v1/grants/g_0", true, Some(json!({ "enabled": false }))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "pausing a grant it cannot work out is held: {held}");
    assert_eq!(held["required_signatures"], 2, "at the two people the rule on its connection asks for: {held}");
    let approval_id = held["approval_id"].as_str().unwrap().to_string();

    let (_, served) = send(&app, "GET", &format!("/v1/approvals/{approval_id}"), false, None).await;
    let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(signed_confirm(&served, &approval_id, &sk))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "one person is not enough: {body}");
    assert!(enabled(&state, "g_0"));
    let (_, served) = send(&app, "GET", &format!("/v1/approvals/{approval_id}"), false, None).await;
    let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(signed_confirm_as(&served, &approval_id, "device:second", &second))).await;
    assert_eq!(status, StatusCode::OK, "the second person applies it: {body}");
    assert!(!enabled(&state, "g_0"), "the grant is paused");
    assert_eq!(store.get_approval(&approval_id).unwrap().unwrap().status, "approved");
}

fn estate_with_large_site(state: &AppState, agents: usize) {
    use permaura_core::GrantAgent;
    estate(state);
    let store = state.service.store();
    store.put_policy(Policy {
        id: "pol_site".into(), connection_id: "site".into(), name: "Site".into(),
        allow: (0..1500).map(|i| format!("route_{i}")).collect(), ..Policy::default()
    }).unwrap();
    let mut lax = store.get_grant("g_lax").unwrap().unwrap();
    lax.policy_ids.push("pol_site".into());
    store.put_grant(lax).unwrap();
    let now = time::OffsetDateTime::now_utc();
    for i in 0..agents {
        store.put_grant(Grant {
            agents: GrantAgents::Agents(vec![GrantAgent::new(format!("agent-{i}"))]),
            expires_at: Some(now + time::Duration::minutes(10 + i as i64)),
            ..everyone(&format!("g_site_{i}"), "pol_site", true)
        }).unwrap();
    }
}

fn lax_effect(state: &AppState) -> permaura_gateway::policy_guard::HeldEffect {
    use permaura_gateway::policy_guard::{held_effect, GuardContext, Mutation};
    let store = state.service.store();
    let (policies, grants) = (store.list_policies().unwrap(), store.list_grants().unwrap());
    let change = Grant { enabled: true, ..store.get_grant("g_lax").unwrap().unwrap() };
    held_effect(&Mutation::GrantUpsert { grant: change }, &GuardContext {
        policies: &policies, grants: &grants, connections: &[], agents: &[],
    }, &[])
}

async fn hold_lax(app: &axum::Router) -> (String, serde_json::Value) {
    let mut change = switch("g_lax", "pol_lax", true);
    change["policy_ids"] = json!(["pol_lax", "pol_site"]);
    let (status, held) = send(app, "PUT", "/v1/grants/g_lax", true, Some(change)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["required_signatures"], 1, "{held}");
    let id = held["approval_id"].as_str().unwrap().to_string();
    let (status, served) = send(app, "GET", &format!("/v1/approvals/{id}"), false, None).await;
    assert_eq!(status, StatusCode::OK, "{served}");
    (id, served)
}

async fn unmask_lax(app: &axum::Router) {
    let (status, body) = send(app, "PUT", "/v1/grants/g_strict", true, Some(switch("g_strict", "pol_strict", false))).await;
    assert_eq!(status, StatusCode::OK, "the narrow tightening remains under budget and applies unheld: {body}");
}

async fn assert_confirm_retired(app: &axum::Router, state: &AppState, id: &str, confirm: serde_json::Value) {
    let (status, body) = send(app, "POST", "/v1/approvals", false, Some(confirm)).await;
    assert_eq!(status, StatusCode::CONFLICT, "a changed or unrecorded estate cannot authorize an unknown effect: {body}");
    assert!(body["error"].as_str().unwrap().contains("ask for it again"), "{body}");
    assert!(!enabled(state, "g_lax"));
    let row = state.service.store().get_approval(id).unwrap().unwrap();
    assert_eq!(row.status, "denied", "the hold is retired, not left pending");
    assert_eq!(row.resolution_reason.as_deref(), Some("effect_widened"));
}

#[tokio::test]
async fn an_over_budget_hold_is_retired_after_an_unheld_change_unmasks_it() {
    use permaura_gateway::policy_guard::HeldEffect;
    let (app, state, sk) = gateway_with_device(38);
    estate_with_large_site(&state, 40);
    assert!(matches!(lax_effect(&state), HeldEffect::PastBudget), "the broad held change exceeds the budget");
    let (id, served) = hold_lax(&app).await;
    let confirm = signed_confirm(&served, &id, &sk);
    unmask_lax(&app).await;
    assert_confirm_retired(&app, &state, &id, confirm).await;
}

#[tokio::test]
async fn a_known_hold_is_retired_when_unheld_changes_push_its_confirm_over_budget() {
    use permaura_gateway::policy_guard::HeldEffect;
    let (app, state, sk) = gateway_with_device(39);
    estate_with_large_site(&state, 20);
    assert!(matches!(lax_effect(&state), HeldEffect::Lowers(_)), "the hold starts within budget");
    let (id, served) = hold_lax(&app).await;
    let confirm = signed_confirm(&served, &id, &sk);
    unmask_lax(&app).await;
    let (status, body) = send(&app, "POST", "/v1/policies", true, Some(json!({
        "id": "pol_padding", "connection_id": "generic_http", "name": "Unbound denials",
        "deny": vec!["request"; 9000],
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "an unbound deny policy applies unheld: {body}");
    assert!(matches!(lax_effect(&state), HeldEffect::PastBudget), "only the confirm exceeds the budget");
    assert_confirm_retired(&app, &state, &id, confirm).await;
}

#[tokio::test]
async fn a_hold_without_an_estate_digest_is_retired_even_when_the_estate_is_unchanged() {
    for (agents, missing_record) in [(0, false), (40, false), (0, true)] {
        let (app, state, sk) = gateway_with_device(40);
        estate_with_large_site(&state, agents);
        let (id, served) = hold_lax(&app).await;
        let store = state.service.store();
        let key = format!("{}{}", permaura_gateway::store::HELD_EFFECT_META_PREFIX, id);
        let text = store.get_meta(&key).unwrap().unwrap();
        let record: serde_json::Value = serde_json::from_str(&text).unwrap();
        let legacy = record.get("effect").unwrap_or(&record);
        store.put_meta(&key, &if missing_record { String::new() } else { legacy.to_string() }).unwrap();
        assert_confirm_retired(&app, &state, &id, signed_confirm(&served, &id, &sk)).await;
    }
}
