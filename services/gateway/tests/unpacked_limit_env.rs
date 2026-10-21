//! The one ceiling on an agent call's unpacked size under the knobs only the environment sets: a raised response cap, which grows an execution's buffers, and so what approving a call reserves beside its params, and leaves the ceiling where it is, a call whose params and those buffers could never fit the pool together running under an execution slot; and the removed hold-tree knob, which moves nothing and is warned about once when the gateway starts.
//!
//! One test in a binary of its own, because the response cap is read once per process. Every credential here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::json_budget::estimate;
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::memory::{held_room, resolution_bytes, MemoryBudget};
use permaura_gateway::store::PendingApproval;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::Value;
use tower::ServiceExt;

mod common;

const MIB: u64 = 1024 * 1024;
const HELD: &str = "github.pull_requests.create";
const UNHELD: &str = "github.pull_requests.list";

/// The `/v1/invoke` body for `capability` whose params carry `rows` `{x, y}` points.
fn body(capability: &str, rows: usize) -> String {
    let list = vec![r#"{"x":1,"y":2}"#; rows].join(",");
    format!(r#"{{"capability":"{capability}","params":{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","extra":[{list}]}}}}"#)
}

async fn send(state: &AppState, capability: &str, rows: usize) -> (StatusCode, Value) {
    let body = body(capability, rows);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// The held call's id, after asserting the unheld one ran.
async fn admitted_both_ways(state: &AppState, rows: usize) -> String {
    let (status, answer) = send(state, UNHELD, rows).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, answer) = send(state, HELD, rows).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");
    answer["approval_id"].as_str().unwrap().to_string()
}

fn approval(state: &AppState, id: &str) -> PendingApproval {
    state.service.store().get_approval(id).unwrap().unwrap()
}

#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_raised_response_cap_leaves_the_one_ceiling_where_it_is_and_the_hold_tree_knob_is_gone() {
    common::isolate_from_the_real_install();
    let captured = Captured::default();
    let sink = captured.clone();
    let _logs = tracing::subscriber::set_default(tracing_subscriber::fmt().with_ansi(false).with_writer(move || sink.clone()).finish());
    std::env::set_var("PERMAURA_HTTP_MAX_RESPONSE_BYTES", (24 * MIB).to_string());
    std::env::set_var("PERMAURA_LIMIT_HOLD_TREE_BYTES", (32 * MIB).to_string());
    let config = LimitsConfig::from_env_for(true);
    assert_eq!(config.unpacked_limit(), 128 * MIB, "the hosted pool less 64 MiB, whatever the response cap; the 32 MiB hold-tree setting moves nothing");
    // An execution slot's B + R + 2.6 R is 88.4 MiB with a 24 MiB response cap. 1.3.52 reserved that in the pool beside a held call's tree and four copies of its text when it was approved, and put its hold ceiling at what was left, about 95.6 MiB. Approving a call still reserves it beside the call's params where the two can fit the pool together, and otherwise runs the call under an execution slot, so the pool holds only its params.
    let execution = resolution_bytes(&config);
    assert!(execution > 88 * MIB && execution < 89 * MIB, "{execution}");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let service = EnforcementService::new(store, Arc::new(MockHttpClient::new())).with_memory_budget(MemoryBudget::from_config(&config));
    let state = AppState::new(service).with_limits(Arc::new(Limits::new(config.clone())));
    assert_eq!(state.service.memory().unpacked_limit(), 128 * MIB);
    // The removed knob is named once, when the gateway's limits are first read, so an operator who set it learns it no longer bounds anything.
    let _again = AppState::new(EnforcementService::new(Arc::new(SqliteStore::open_in_memory().unwrap()), Arc::new(MockHttpClient::new())));
    let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert_eq!(logged.matches("PERMAURA_LIMIT_HOLD_TREE_BYTES is set").count(), 1, "{logged}");
    assert!(logged.contains("PERMAURA_LIMIT_JSON_POOL_BYTES"), "it says what replaced it: {logged}");

    // 2 MiB of `{x, y}` points, a 112.6 MiB call, ran unheld and was refused held on 1.3.52 here, and its params and an execution's 88.4 MiB could never fit the pool together. It is admitted both ways, as every call under the ceiling is, and approved under an execution slot, its params reserving about 117 MiB.
    let over = (2 * MIB as usize - 200) / 14;
    let tree = estimate(body(HELD, over).as_bytes());
    assert!(tree > 112 * MIB && tree < 113 * MIB, "{tree}");
    let id = admitted_both_ways(&state, over).await;
    let room = held_room(approval(&state, &id).params.get().as_bytes());
    assert!(room < 118 * MIB, "{room}");
    assert!(!state.service.memory().held_fits_beside_buffers(approval(&state, &id).params.get().as_bytes()));
    let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(approved.status, "approved");
    let pool = state.service.memory().pool();
    assert_eq!(pool.available_bytes(), pool.max_bytes());
    assert_eq!(state.limits.available_execution_slots(), config.max_inflight);

    // 1.5 MiB of them, an 81.4 MiB call, is admitted both ways, and the held one is approved with an execution's 88.4 MiB beside its params, as on 1.3.52.
    let under = (3 * MIB as usize / 2) / 14;
    let tree = estimate(body(HELD, under).as_bytes());
    assert!(tree > 81 * MIB && tree < 82 * MIB, "{tree}");
    let id = admitted_both_ways(&state, under).await;
    assert!(state.service.memory().held_fits_beside_buffers(approval(&state, &id).params.get().as_bytes()));
    let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(approved.status, "approved");

    std::env::remove_var("PERMAURA_HTTP_MAX_RESPONSE_BYTES");
    std::env::remove_var("PERMAURA_LIMIT_HOLD_TREE_BYTES");
}
