//! One approved call whose upstream answers with JSON nested 127 levels deep (inside serde_json's limit) used to store an approval row nested one level deeper, which the store wrote and could never read back. From then on the approval queue, every control-plane hold, interrupted-call settlement and restore reconciliation failed, because each of them lists the approvals table.
//!
//! Over SQLite, because the in-memory store never serializes a row and so cannot show it.
#![cfg(feature = "sqlite")]

use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use std::sync::Arc;

mod common;

fn nested(depth: usize) -> serde_json::Value {
    (0..depth).fold(serde_json::json!("leaf"), |inner, _| serde_json::json!([inner]))
}

#[tokio::test]
async fn an_approved_call_with_a_127_deep_answer_leaves_the_approvals_table_readable() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let upstream = HttpResponse { status: 200, body: nested(127), headers: Vec::new(), text: None, memory: Default::default() };
    let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::with_response(upstream)));
    let session = store.get_session("sess_demo").unwrap().unwrap();
    let params = serde_json::json!({ "name": "acme-web", "target": "production" });
    let held = service
        .invoke(&session, "vercel.deployments.create", &params, Some("deploy"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::RequiresApproval { approval, .. } = held else { panic!("a High-risk call holds") };

    let resolved = service.resolve_approval(&approval.id, true, "bearer", Some("operator")).await;
    let listed = store.list_approvals(None);
    let row = store.get_approval(&approval.id);
    let resolved = resolved.expect("the approved call settles");
    assert_eq!(resolved.status, "approved");
    let listed = listed.expect("the approvals table still lists after the deep answer was stored");
    assert!(listed.iter().any(|a| a.id == approval.id), "the settled row is listed");
    let row = row.expect("the settled row reads back").expect("and is there");
    assert!(row.result.is_some(), "with its result kept, cut short where it was too deep");
}
