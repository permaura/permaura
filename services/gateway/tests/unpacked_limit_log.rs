//! The line a refusal by the one ceiling on an agent call's unpacked size writes.
//!
//! One test in a binary of its own: it captures through a thread-local subscriber, and with no global one set a callsite's interest is cached from whichever thread reaches it first, so a parallel test in the same binary that tripped the refusal first would leave the warning switched off for this one. Every credential here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::json_budget::estimate;
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const MIB: u64 = 1024 * 1024;
/// Low risk, so the seeded policy runs it at once.
const UNHELD: &str = "github.pull_requests.list";

fn gateway(config: &LimitsConfig) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let service = EnforcementService::new(store, Arc::new(MockHttpClient::new())).with_memory_budget(MemoryBudget::from_config(config));
    AppState::new(service).with_limits(Arc::new(Limits::new(config.clone())))
}

async fn post(state: &AppState, uri: &str, body: String) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A `/v1/invoke` body for `capability` whose params carry `rows` copies of `row` as a list.
fn body(capability: &str, row: &str, rows: usize) -> String {
    format!(r#"{{"capability":"{capability}","params":{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","extra":[{}]}}}}"#, vec![row; rows].join(","))
}

/// The most rows of `row` whose body estimates at or under `limit`.
fn rows_under(row: &str, limit: u64) -> usize {
    let (mut low, mut high) = (0usize, 2 * MIB as usize / (row.len() + 1));
    while low < high {
        let mid = (low + high).div_ceil(2);
        if estimate(body(UNHELD, row, mid).as_bytes()) <= limit {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}

fn cut(v: &Value) -> String {
    v.to_string().chars().take(300).collect()
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

impl Captured {
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap().lines().filter(|line| line.contains(permaura_gateway::memory::UNPACKED_REFUSAL_LOG_MESSAGE)).map(str::to_string).collect()
    }
}

/// A refusal by the one ceiling writes one log line with the call's estimated unpacked size, the limit and where it was refused, and nothing of its params: on `/v1/invoke` and `/mcp` before the body is parsed, and in the service for a relayed call. A body the ceiling does not refuse, an `/mcp` request that is not a tool call, writes none.
#[tokio::test]
async fn a_refusal_by_the_ceiling_writes_one_line_with_its_size_limit_and_route() {
    let captured = Captured::default();
    let sink = captured.clone();
    let _logs = tracing::subscriber::set_default(tracing_subscriber::fmt().with_ansi(false).with_writer(move || sink.clone()).finish());
    let state = gateway(&LimitsConfig { json_pool_bytes: 32 * MIB, ..LimitsConfig::defaults_for(true) });
    let ceiling = state.service.memory().unpacked_limit();
    let marker = "synthetic-param-41c9";
    let row = r#"{"a":1}"#;
    let rows = rows_under(row, ceiling) + 1;
    let over = body(UNHELD, row, rows).replace(r#""title":"t""#, &format!(r#""title":"{marker}""#));
    let size = estimate(over.as_bytes());
    assert!(size > ceiling);

    let (status, answer) = post(&state, "/v1/invoke", over).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{}", cut(&answer));
    let lines = captured.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains(&format!("unpacked_bytes={size}")) && lines[0].contains(&format!("limit={ceiling}")) && lines[0].contains("route=/v1/invoke"), "{}", lines[0]);

    let arguments = format!(r#"{{"owner":"synthetic","repo":"synthetic","title":"{marker}","extra":[{}]}}"#, vec![row; rows].join(","));
    let call = format!(r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"{UNHELD}","arguments":{arguments}}}}}"#);
    let (_, answer) = post(&state, "/mcp", call).await;
    assert_eq!(answer["error"]["code"], -32000, "{}", cut(&answer));
    let lines = captured.lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[1].contains("route=/mcp") && lines[1].contains(&format!("limit={ceiling}")), "{}", lines[1]);

    let listing = format!(r#"{{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{{"extra":[{}]}}}}"#, vec![row; rows].join(","));
    let (status, _) = post(&state, "/mcp", listing).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(captured.lines().len(), 2, "a request the ceiling does not refuse writes no line");

    let session = state.service.store().get_session("sess_demo").unwrap().expect("the demo session");
    let relayed = json!({ "owner": "synthetic", "repo": "synthetic", "title": marker, "extra": vec![json!({ "a": 1 }); rows + 100] });
    let refused = state.service.invoke(&session, UNHELD, &relayed, None, permaura_core::ExecutionLocation::LocalOnly).await;
    assert!(refused.is_err());
    let lines = captured.lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[2].contains("route=service"), "{}", lines[2]);
    let all = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(!all.contains(marker), "no params are logged");
}
