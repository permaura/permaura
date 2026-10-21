//! A held-params budget below one hold refused, with a 429 on an empty queue that no retry could clear, a call the same gateway ran unheld: a hosted worker whose body limit an operator raised past 16 MiB, or a gateway whose held total an operator set below its body limit. Each budget is floored at a body's length of params (for a change, the largest body a change arrives in) and 64 KiB for the rest of its row, and a hold alone in its queue is admitted whatever its row takes, so a single hold is never refused on an empty queue.
//!
//! One test in a binary of its own, because the variables are process-wide and every other binary's tests run in parallel with each other. Every credential here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::policy_guard::Mutation;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{Agent, Store};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const VARS: [&str; 2] = ["PERMAURA_LIMIT_BODY_EXEC_BYTES", "PERMAURA_LIMIT_HELD_TOTAL_BYTES"];
const MIB: usize = 1024 * 1024;
/// High risk, so the seeded policy holds it for a human.
const HELD: &str = "github.pull_requests.create";
/// Low risk, so the seeded policy runs it at once. It takes the same params as [`HELD`].
const UNHELD: &str = "github.pull_requests.list";

fn gateway(config: &LimitsConfig) -> AppState {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let service = EnforcementService::new(store, Arc::new(MockHttpClient::new())).with_memory_budget(MemoryBudget::from_config(config));
    AppState::new(service).with_limits(Arc::new(Limits::new(config.clone())))
}

async fn invoke(state: &AppState, capability: &str, params: &Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(json!({ "capability": capability, "params": params }).to_string()))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn pr(extra: &str) -> Value {
    json!({ "owner": "synthetic", "repo": "synthetic", "title": "t", "head": "h", "base": "b", "extra": extra })
}

fn cut(v: &Value) -> String {
    v.to_string().chars().take(300).collect()
}

/// `params` run unheld, and are held on an empty queue and approved.
async fn run_unheld_then_held_and_approved(state: &AppState, params: &Value, what: &str) {
    let (status, ran) = invoke(state, UNHELD, params).await;
    assert_eq!(status, StatusCode::OK, "{what}, unheld: {}", cut(&ran));
    assert!(state.service.store().list_approvals(Some("pending")).unwrap().is_empty(), "the queue is empty");
    let (status, answer) = invoke(state, HELD, params).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{what}, held: {}", cut(&answer));
    let id = answer["approval_id"].as_str().unwrap().to_string();
    let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(approved.status, "approved", "{what}");
}

#[tokio::test]
async fn a_single_hold_the_gateway_admits_unheld_fits_an_empty_queue() {
    common::isolate_from_the_real_install();
    for var in VARS {
        std::env::remove_var(var);
    }

    // A hosted worker with a 24 MiB body limit takes holds of up to 24 MiB of params, past its 16 MiB of held rows.
    std::env::set_var("PERMAURA_LIMIT_BODY_EXEC_BYTES", (24 * MIB).to_string());
    let config = LimitsConfig::from_env_for(true);
    assert_eq!(config.body_exec_bytes, 24 * MIB);
    let state = gateway(&config);
    assert!(state.service.memory().held_total_bytes() > 24 * MIB as u64, "{}", state.service.memory().held_total_bytes());
    run_unheld_then_held_and_approved(&state, &pr(&"A".repeat(17 * MIB)), "hosted, 24 MiB body limit, a 17 MiB string").await;
    std::env::remove_var("PERMAURA_LIMIT_BODY_EXEC_BYTES");

    // A self-run gateway whose operator set 1 MiB of held rows, below the 2 MiB body.
    std::env::set_var("PERMAURA_LIMIT_HELD_TOTAL_BYTES", MIB.to_string());
    let config = LimitsConfig::from_env_for(false);
    assert!(config.held_total_bytes > 2 * MIB as u64, "{}", config.held_total_bytes);
    let state = gateway(&config);
    run_unheld_then_held_and_approved(&state, &pr(&"A".repeat(3 * MIB / 2)), "self-run, 1 MiB held total, a 1.5 MiB string").await;

    // A held change gets the same floor, for one of the largest bodies a change arrives in.
    let mutation = Mutation::AgentUpsert { agent: Agent::approved("agent-large", "n".repeat(3 * MIB / 2), 1) };
    assert!(state.service.control_plane_hold_bytes("permaura.policy.write", &mutation, "Create an agent?", None).unwrap() > MIB as u64);
    state
        .service
        .hold_mutation_approval("permaura.policy.write", &mutation, "Create an agent?", None)
        .expect("a single change larger than the operator's 1 MiB is held on an empty queue");

    for var in VARS {
        std::env::remove_var(var);
    }
}
