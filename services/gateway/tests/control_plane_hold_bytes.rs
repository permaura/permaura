//! A held control-plane change stored its params with no byte check, and the held-params ceiling counted only agent holds, so a member could fill a hosted worker's store with held changes up to the pending count. Control-plane holds now have a byte budget of their own, the same size as the agents' one, and a hold past it is refused with nothing written.
//!
//! Every credential here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::error::GatewayError;
use permaura_gateway::limits::LimitsConfig;
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::policy_guard::Mutation;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{Agent, Store};
use permaura_gateway::{build_router, seed, AppState};

mod common;

#[tokio::test]
async fn control_plane_holds_are_refused_past_their_byte_budget() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    // No body for a change to arrive in keeps the budget's floor, one change and the rest of its row, at 64 KiB, under the 96 KiB asked for.
    let config = LimitsConfig { held_total_bytes: 96 * 1024, body_default_bytes: 0, body_bulk_bytes: 0, ..LimitsConfig::defaults_for(true) };
    let budget = MemoryBudget::from_config(&config);
    assert_eq!(budget.control_plane_held_total_bytes(), 96 * 1024);
    let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())).with_memory_budget(budget);
    let mutation = |i: usize| Mutation::AgentUpsert { agent: Agent::approved(format!("agent-{i}"), format!("{i} {}", "n".repeat(16 * 1024)), 1) };
    let row = service.control_plane_hold_bytes("permaura.policy.write", &mutation(0), "Create an agent?", None).unwrap();
    let mut held = 0;
    let refused = loop {
        match service.hold_mutation_approval("permaura.policy.write", &mutation(held), "Create an agent?", None) {
            Ok(_) => held += 1,
            Err(e) => break e,
        }
        assert!(held < 16, "the budget never refused a hold");
    };
    assert_eq!(held as u64, 96 * 1024 / row, "{held} holds of {row} bytes fit 96 KiB");
    match refused {
        GatewayError::TooManyRequests { reason, .. } => assert_eq!(reason, "held_params"),
        other => panic!("expected a 429, got {other:?}"),
    }
    assert_eq!(store.list_approvals(Some("pending")).unwrap().len(), held, "the refused hold wrote nothing");
    assert!(store.pending_control_plane_hold_bytes().unwrap() <= 96 * 1024);
    assert_eq!(store.pending_hold_bytes().unwrap(), 0, "and the agents' budget is untouched");
}

async fn install(state: &AppState, body: String) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/connectors/install")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .header("cf-ray", "abc123")
        .body(Body::from(body))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A change's row is its mutation as serde_json writes it, every default field included, so a change can take about four times the body it arrived in, past its budget's floor of that body and 64 KiB; one alone in the queue is held whatever it takes. The docs on `DEFAULT_HOSTED_HELD_TOTAL_BYTES` and `memory::control_plane_held_total_bytes` state this bound and it is pinned here, not tightened: earlier builds had no budget and held this change.
#[tokio::test]
async fn a_change_alone_in_the_queue_may_pass_its_budget_by_what_it_writes_past_its_body() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let budget = MemoryBudget::from_config(&LimitsConfig::defaults_for(true));
    let ceiling = budget.control_plane_held_total_bytes();
    assert_eq!(ceiling, 16 * 1024 * 1024, "hosted defaults: the bulk body and 64 KiB are under the 16 MiB asked for");
    let state = AppState::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())).with_memory_budget(budget));
    let device = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let key = STANDARD.encode(device.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key_for("device:approver", &key, Some("user_approver")).unwrap());

    // The shortest capability lines a manifest takes, up to just under the 8 MiB bulk body.
    let mut capabilities = Vec::new();
    let mut written = 0;
    while written < 8 * 1024 * 1024 - 64 * 1024 {
        let line = json!({ "id": format!("a{}", capabilities.len()), "method": "GET", "path": "/" });
        written += line.to_string().len() + 1;
        capabilities.push(line);
    }
    let manifest = |id: &str, capabilities: &[Value]| {
        json!({ "manifest": { "id": id, "name": "Acme", "vertical": "devtools", "base_url": "https://api.acme-tools.example", "capabilities": capabilities }, "version": 1 })
            .to_string()
    };
    let body = manifest("acme-tools", &capabilities);
    let (status, held) = install(&state, body.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", held.to_string().chars().take(300).collect::<String>());
    let stored = store.pending_control_plane_hold_bytes().unwrap();
    assert!(stored > 2 * ceiling, "{stored} bytes held alone against a {ceiling}-byte budget");
    assert!(stored > 4 * body.len() as u64, "{stored} bytes from a {}-byte body", body.len());

    // With it waiting, the next change is refused until it is resolved, writing nothing.
    let (status, refused) = install(&state, manifest("other-tools", &capabilities[..1])).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{refused}");
    assert_eq!(refused["reason"], "held_params", "{refused}");
    assert_eq!(store.list_approvals(Some("pending")).unwrap().len(), 1);
}
