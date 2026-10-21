//! A held change's quorum is worked out on the blocking pool, as its classification is, so a gateway on one runtime
//! thread keeps answering while an estate whose grants each end at their own moment is resolved for it.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{Grant, GrantAgent, GrantAgents, GrantPeriod, Policy};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower::ServiceExt;

mod common;

/// How many all-agents grants end at their own moment, and how many agents a grant names: resolving every agent at
/// every moment then takes about a million visits, inside the classification budget, so the work is done in full.
const N: usize = 64;

fn grant(id: &str, agents: GrantAgents, expires_at: Option<time::OffsetDateTime>) -> Grant {
    Grant {
        grant_id: id.into(),
        name: id.into(),
        enabled: true,
        is_default: false,
        policy_ids: vec!["pol_two_person".into()],
        agents,
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at,
    }
}

fn large_estate(state: &AppState) {
    let store = state.service.store();
    store
        .put_policy(Policy {
            id: "pol_two_person".into(),
            connection_id: "generic_http".into(),
            name: "Two people".into(),
            device_signed: vec!["request".into()],
            device_signed_quorum: 2,
            ..Policy::default()
        })
        .unwrap();
    let now = time::OffsetDateTime::now_utc();
    for i in 0..N {
        let ends = now + time::Duration::minutes(10 + i as i64);
        store.put_grant(grant(&format!("gr_{i}"), GrantAgents::AllAgents, Some(ends))).unwrap();
    }
    let named = (0..N).map(|i| GrantAgent::new(format!("agent-{i}"))).collect();
    store.put_grant(grant("gr_named", GrantAgents::Agents(named), None)).unwrap();
}

async fn put_remote(app: &axum::Router, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("cf-ray", "8f00000000000000-SIN")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

/// That `what`, from `from` to `to`, left the runtime free for most of it: the longest stretch with no tick from the
/// task beside it is under a third of the time it took.
fn left_the_runtime_answering(ticks: &Mutex<Vec<Instant>>, from: Instant, to: Instant, what: &str) {
    let mut points = vec![from];
    points.extend(ticks.lock().unwrap().iter().copied().filter(|t| *t > from && *t < to));
    points.push(to);
    let longest = points.windows(2).map(|w| w[1] - w[0]).max().unwrap_or_default();
    let took = to - from;
    assert!(took >= Duration::from_millis(100), "setup: {what} took {took:?}, too little to show anything");
    assert!(longest * 3 < took, "{what} took {took:?} and held the only runtime thread for {longest:?} of it");
}

#[test]
fn holding_and_confirming_a_change_leave_a_single_threaded_runtime_answering() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        use base64::Engine as _;
        common::isolate_from_the_real_install();
        let state = common::seeded();
        let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
        let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let pubkey = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        assert!(state.service.trust_approver_key_for("device:approver", &pubkey, Some("user_approver")).unwrap());
        large_estate(&state);

        let ticks = Arc::new(Mutex::new(Vec::new()));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    ticks.lock().unwrap().push(Instant::now());
                }
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Keeping one of the grants past its end is a loosening, so over the broker it is held.
        let started = Instant::now();
        let (status, body) = put_remote(&app, "/v1/grants/gr_0", json!({
            "name": "gr_0",
            "policy_ids": ["pol_two_person"],
            "all_agents": true,
        }))
        .await;
        let done = Instant::now();
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        left_the_runtime_answering(&ticks, started, done, "holding the change");

        let approval_id = body["approval_id"].as_str().expect("a held change names its approval").to_string();
        let started = Instant::now();
        let resolved = state.service.resolve_approval(&approval_id, true, "device_signed", Some("device:approver")).await;
        let done = Instant::now();
        let resolved = resolved.expect("the held change is confirmed");
        assert_eq!(resolved.status, "approved");
        left_the_runtime_answering(&ticks, started, done, "confirming it");
        assert_eq!(state.service.store().get_grant("gr_0").unwrap().unwrap().expires_at, None, "and it applied");
        ticker.abort();
    });
}
