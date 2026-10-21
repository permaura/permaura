//! Measured: when a held credential change fails after its row was staged, the gateway asks whether a pending hold names that staged row, and before it holds a change it asks whether the same change is already held. Both used to list every pending approval to answer, reading every held call's params as text, the whole-queue read that was taken out of the listings; both now read only the held changes.
//!
//! A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak. Every credential here is synthetic.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::limits::LimitsConfig;
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::policy_guard::Mutation;
use permaura_gateway::secret_inventory::is_staging_secret_id;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{Agent, PendingApproval, Store};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::Value;
use tower::ServiceExt;

mod common;
mod metered_alloc;

use metered_alloc::{peak_growth, MIB};

fn one_key_objects(cap: usize) -> String {
    let mut body = String::from("[");
    while body.len() + 9 < cap {
        body.push_str("{\"a\":1},");
    }
    body.pop();
    body.push(']');
    body
}

/// A pending agent hold whose params are 2 MiB, as a gateway before the hold budget could store it.
fn legacy_row(id: &str, params: &str) -> String {
    format!(
        r#"{{"id":"{id}","session_id":"sess_demo","capability":"github.pull_requests.create","resource":"github_acme","message":"Approve?","status":"pending","grant_id":"gr_github_prs","policy_id":"pol_github_prs","params":{{"rows":{params}}},"result":null,"result_status":null,"created_at":1,"expires_at":null,"risk":"high","action_description":"Create pull requests","required_tier":"approve","required_signatures":1,"signatures":[]}}"#
    )
}

/// A gateway with a paired device and `held` agent holds of 2 MiB waiting, whose held-change budget a change already waiting fills, so a credential hold is refused after its row is staged.
fn gateway(name: &str, held: usize) -> (AppState, Arc<dyn Store>, PathBuf) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let dir = std::env::temp_dir().join(format!("staged-row-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(dir.join("gateway.db").to_str().unwrap()).unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let params = one_key_objects(2 * MIB);
    for i in 0..held {
        store.put_approval(serde_json::from_str::<PendingApproval>(&legacy_row(&format!("appr_legacy_{i}"), &params)).unwrap()).unwrap();
    }
    // No body for a change to arrive in keeps the budget at its 64 KiB floor, which the change below fills alone.
    let config = LimitsConfig { held_total_bytes: 64, body_default_bytes: 0, body_bulk_bytes: 0, ..LimitsConfig::defaults_for(true) };
    let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())).with_memory_budget(MemoryBudget::from_config(&config));
    let state = AppState::new(service);
    let waiting = Mutation::AgentUpsert { agent: Agent::approved("agent-large", "n".repeat(64 * 1024), 1) };
    state.service.hold_mutation_approval("permaura.policy.write", &waiting, "Create an agent?", None).expect("alone in the queue, it is held");
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    assert!(state.service.trust_approver_key_for("device:approver", &STANDARD.encode(key.verifying_key().to_bytes()), Some("user_approver")).unwrap());
    (state, store, dir)
}

async fn credential(state: &AppState) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/connections/braintree_production/credential")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .header("cf-ray", "abc123")
        .body(Body::from(serde_json::json!({ "value": "synthetic-credential" }).to_string()))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_failed_credential_hold_reads_no_held_call() {
    common::isolate_from_the_real_install();
    // Sealing the credential derives a key with a memory-hard function, so the measure is what twelve held calls add to the same request on an empty queue.
    let (empty, _, empty_dir) = gateway("empty", 0);
    let (full, full_store, full_dir) = gateway("full", 12);
    let ((status, body), baseline) = peak_growth(credential(&empty)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let ((status, body), peak) = peak_growth(credential(&full)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(!full_store.list_secret_ids().unwrap().iter().any(|id| is_staging_secret_id(id)), "the staged row was removed, since no hold names it");
    assert!(peak < baseline + 2 * MIB, "beside twelve 2 MiB held calls the request held {} MiB, {} MiB on an empty queue", peak / MIB, baseline / MIB);
    eprintln!("measured: a failed credential hold held {} MiB beside twelve 2 MiB held calls, {} MiB on an empty queue", peak / MIB, baseline / MIB);
    let _ = std::fs::remove_dir_all(&empty_dir);
    let _ = std::fs::remove_dir_all(&full_dir);
}
