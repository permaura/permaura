//! What an agent sends can reach a deny event's reason (the egress gate echoes a URL it cannot parse), and the chain keeps every event resident on a hosted worker, so a few dozen 2 MiB URLs used to take a 512 MiB worker down for good. An event keeps each such string cut, with its length and digest.
//!
//! Every credential and host here is synthetic.

use std::sync::Arc;

use permaura_core::{Connection, ExecutionLocation};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::seed;
use serde_json::json;

mod common;

#[tokio::test]
async fn a_deny_event_keeps_a_long_echoed_url_cut_with_its_length_and_digest() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    // The seeded generic HTTP capability, on a connection with an allowlist, so its URL reaches the egress gate.
    store
        .put_connection(Connection {
            id: "generic_http".into(),
            connector: "generic_http".into(),
            name: "Generic HTTP".into(),
            label: "Generic HTTP".into(),
            secret_id: "sec_github_acme".into(),
            capabilities: vec!["http.request".into()],
            disabled_capabilities: vec![],
            disabled: false,
            allowed_hosts: vec!["api.example.com".into()],
            created_at: 1,
            redact_fields: Vec::new(),
            source: None,
            made_from: None,
        })
        .unwrap();
    let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()));
    let session = store.get_session("sess_demo").unwrap().expect("the demo session");
    let url = format!("not a url {}", "x".repeat(2 * 1024 * 1024));
    let outcome = service
        .invoke(&session, "http.request", &json!({ "method": "GET", "url": url }), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("the call is answered");
    assert!(matches!(outcome, InvokeOutcome::Denied { .. }), "an unparseable URL is denied");

    let events = store.audit_events(Some(1)).unwrap();
    let event = events.last().expect("the denial is recorded");
    assert_eq!(event.payload.decision, "deny");
    let summary = serde_json::to_string(&event.payload.summary).unwrap();
    assert!(summary.len() < 4 * 1024, "the deny event keeps {} bytes of summary", summary.len());
    let reason = event.payload.summary["reason"].as_str().unwrap();
    assert!(reason.starts_with("Request URL refused"), "{reason}");
    assert!(reason.contains("cut from") && reason.contains("sha256"), "{reason}");
}
