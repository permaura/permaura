//! Measured: admitting a held control-plane change read the length of its row by writing the whole row out, a full copy of the held mutation beside the row about to be stored. The length is now counted as the row is written, holding nothing.
//!
//! A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak. Every credential here is synthetic.

use std::sync::Arc;

use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::limits::LimitsConfig;
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::policy_guard::Mutation;
use permaura_gateway::seed;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{Agent, Store};

mod common;
mod metered_alloc;

use metered_alloc::{peak_growth_sync, MIB};

#[tokio::test]
async fn a_held_change_is_admitted_without_a_copy_of_its_row() {
    common::isolate_from_the_real_install();
    metered_alloc::count_realloc_as_copy(true);
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let config = LimitsConfig { held_total_bytes: 64 * MIB as u64, ..LimitsConfig::defaults_for(true) };
    let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())).with_memory_budget(MemoryBudget::from_config(&config));
    let mutation = Mutation::AgentUpsert { agent: Agent::approved("agent-large", "n".repeat(4 * MIB), 1) };
    let row = serde_json::to_string(&mutation).unwrap().len();
    let (held, peak) = peak_growth_sync(|| service.hold_mutation_approval("permaura.policy.write", &mutation, "Create an agent?", None));
    held.expect("the change is held");
    eprintln!("measured: holding a {} MiB change held {} MiB", row / MIB, peak / MIB);
    // The change as a tree, its text, the row and the store's copy of it are four; writing the row out to measure it was a fifth.
    assert!(peak < 4 * row + row / 2, "holding a {} MiB change held {} MiB", row / MIB, peak / MIB);
}
