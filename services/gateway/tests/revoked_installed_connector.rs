//! A Permaura-signed connector installed before the gateway booted stops running when the revocation list it boots under cannot be verified, not only a new install of it.
//!
//! The only binary that sets `PERMAURA_PMCONN_REVOCATION`, so it holds this one test. Every credential and upstream here is synthetic.

use std::sync::Arc;

use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::manifest::{InstalledManifest, Provenance};
use permaura_gateway::service::InvokeOutcome;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::{presets, seed, AppState};

mod common;

fn shadow_github(store: &Arc<dyn Store>, provenance: Provenance) {
    store
        .put_connector_manifest(InstalledManifest {
            manifest: presets::catalog().get("github").unwrap().clone(),
            version: 1,
            provenance,
            installed_at: 0,
            endpoint_hosts: Vec::new(),
        })
        .unwrap();
}

#[tokio::test]
async fn a_signed_connector_installed_before_an_unverifiable_list_stops_running() {
    common::isolate_from_the_real_install();
    std::env::set_var("PERMAURA_PMCONN_REVOCATION", "{ not a revocation list");
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let session = store.get_session("sess_demo").unwrap().expect("the demo session is seeded");
    let params = serde_json::json!({ "owner": "synthetic", "repo": "synthetic" });
    let call = |state: AppState| {
        let (session, params) = (session.clone(), params.clone());
        async move {
            state
                .service
                .invoke(&session, "github.pull_requests.list", &params, Some("synthetic"), ExecutionLocation::LocalOnly)
                .await
                .unwrap()
        }
    };
    let http = || Arc::new(MockHttpClient::with_response(HttpResponse::json(200, serde_json::json!({ "ok": true }))));

    shadow_github(&store, Provenance::Signed { key_id: "pmconn-int-2026b".into() });
    let state = AppState::from_parts(store.clone(), http());
    let InvokeOutcome::Denied { decision } = call(state).await else {
        panic!("a signed connector must not run under a list that does not verify")
    };
    assert!(decision.reason.contains("revoked"), "the refusal says why: {}", decision.reason);

    shadow_github(&store, Provenance::User);
    let state = AppState::from_parts(store.clone(), http());
    assert!(matches!(call(state).await, InvokeOutcome::Allowed { .. }), "the operator's own unsigned manifest still runs");
}
