//! "Pause all agents" and the new-agent approval gate survive a hosted cold start.
//!
//! Both lived only in memory, so a fleet roll, a crash or a stale exit lifted them with no device signature while the console said every action stays denied until resumed. They are `gateway_meta` rows now, carried in the snapshot like everything else.
#![cfg(feature = "sqlite")]

use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::objectstore::MemoryObjectStore;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use permaura_gateway::store::Store;
use std::sync::Arc;

mod common;

fn instance(objects: &Arc<MemoryObjectStore>, tag: &str) -> EnforcementService {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!("broker-switches-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store: Arc<dyn Store> = Arc::new(
        PersistedSqliteStore::open(dir.join("gateway.db").to_str().unwrap(), objects.clone(), DEFAULT_OBJECT, None)
            .expect("the store opens from the bucket"),
    );
    EnforcementService::new(store, Arc::new(MockHttpClient::new()))
}

#[test]
fn a_cold_start_restores_the_pause_and_the_gate_from_the_bucket() {
    let objects = Arc::new(MemoryObjectStore::new());
    let first = instance(&objects, "first");
    first.set_paused(true).expect("the pause is saved");
    first.set_require_agent_approval(true).expect("the gate is saved");
    drop(first);

    let next = instance(&objects, "next");
    assert!(next.is_paused(), "a cold start must not lift the pause");
    assert!(next.require_agent_approval(), "nor the new-agent gate");

    next.set_paused(false).expect("the resume is saved");
    drop(next);
    let after = instance(&objects, "after");
    assert!(!after.is_paused(), "a resume is restored as faithfully as a pause");
    assert!(after.require_agent_approval());
}

/// `PERMAURA_REQUIRE_AGENT_APPROVAL` engages the gate for one run and is not written down, so a deployment that stops setting it does not keep a gate nobody asked the store for.
#[test]
fn the_gate_engaged_from_the_environment_lasts_one_run() {
    let objects = Arc::new(MemoryObjectStore::new());
    let first = instance(&objects, "env-first");
    first.require_agent_approval_for_this_run();
    assert!(first.require_agent_approval());
    drop(first);
    assert!(!instance(&objects, "env-next").require_agent_approval());
}
