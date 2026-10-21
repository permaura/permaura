//! The effective redaction set a connector result gets before it reaches an agent: the gateway
//! defaults, the connection's own list, its catalog manifest's list and the lists of every policy
//! that permitted the call, unioned, on the immediate path and on a held call approved later.
//!
//! Every credential and upstream here is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{ExecutionLocation, REDACTED};
use permaura_gateway::connectors::{HttpResponse, MockHttpClient};
use permaura_gateway::manifest::{InstalledManifest, Provenance};
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{Session, Store};
use permaura_gateway::{build_router, presets, seed};
use tower::ServiceExt;

mod common;

/// What the synthetic upstream answers: one key for every source, plus look-alikes that must survive.
fn upstream_body() -> serde_json::Value {
    serde_json::json!({
        "authorization": "Bearer synthetic-live-token",
        "client_secret": "cs_synthetic",
        "email": "someone@example.test",
        "phone": "+1 555 0100",
        "card": { "number": "4242424242424242", "brand": "visa" },
        "number": 42,
        "title": "keep me",
        "items": [ { "email": "other@example.test", "number": 7 } ]
    })
}

fn seeded() -> (Arc<dyn Store>, EnforcementService, Session) {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let session = store.get_session("sess_demo").unwrap().expect("the demo session is seeded");
    let http = MockHttpClient::with_response(HttpResponse::json(200, upstream_body()));
    let service = EnforcementService::new(store.clone(), Arc::new(http));
    (store, service, session)
}

/// Give each of the three configurable sources one distinct entry on the seeded GitHub connection:
/// the connection redacts `phone`, an installed manifest shadowing the bundled `github` preset
/// redacts `card.number`, and the policy that permits the calls redacts `email`.
fn configure_sources(store: &Arc<dyn Store>, connection: &[&str], manifest: &[&str], policy: &[&str]) {
    let strings = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut conn = store.get_connection("github_acme").unwrap().unwrap();
    conn.redact_fields = strings(connection);
    store.put_connection(conn).unwrap();

    let mut shadow = presets::catalog().get("github").unwrap().clone();
    shadow.redact_fields = strings(manifest);
    store
        .put_connector_manifest(InstalledManifest {
            manifest: shadow,
            version: 1,
            provenance: Provenance::User,
            installed_at: 0,
            endpoint_hosts: Vec::new(),
        })
        .unwrap();

    let mut pol = store.get_policy("pol_github_prs").unwrap().unwrap();
    pol.redact_fields = strings(policy);
    store.put_policy(pol).unwrap();
}

fn params() -> serde_json::Value {
    serde_json::json!({ "owner": "synthetic", "repo": "synthetic", "title": "t", "head": "h", "base": "b" })
}

fn assert_union_applied(result: &serde_json::Value) {
    assert_eq!(result["authorization"], REDACTED, "a default");
    assert_eq!(result["client_secret"], REDACTED, "a default");
    assert_eq!(result["phone"], REDACTED, "the connection's own list");
    assert_eq!(result["card"]["number"], REDACTED, "the manifest's list, scoped to card");
    assert_eq!(result["email"], REDACTED, "the permitting policy's list");
    assert_eq!(result["items"][0]["email"], REDACTED);
    assert_eq!(result["number"], 42, "a bare number outside card is not a card number");
    assert_eq!(result["items"][0]["number"], 7);
    assert_eq!(result["card"]["brand"], "visa");
    assert_eq!(result["title"], "keep me");
}

#[tokio::test]
async fn an_allowed_call_gets_the_union_of_every_source() {
    let (store, service, session) = seeded();
    configure_sources(&store, &["phone"], &["card.number"], &["email"]);

    let outcome = service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::Allowed { result, .. } = outcome else { panic!("expected an allowed call") };
    let result = result.to_value_unbounded();
    assert_union_applied(&result);
}

#[tokio::test]
async fn a_held_call_approved_later_gets_the_same_effective_set() {
    let (store, service, session) = seeded();
    configure_sources(&store, &["phone"], &["card.number"], &["email"]);

    // High risk, so the engine holds it for a human even though the policy allows it.
    let outcome = service
        .invoke(&session, "github.pull_requests.create", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::RequiresApproval { approval, .. } = outcome else { panic!("expected a held call") };

    let resolved = service.resolve_approval(&approval.id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(resolved.status, "approved");
    assert_union_applied(&resolved.result.as_ref().expect("the approved call stores its result").to_value_unbounded());
}

#[tokio::test]
async fn a_held_call_takes_the_redaction_in_force_when_it_is_approved() {
    // The set is resolved from the approval-time gates, like the rest of the re-check, so a redaction
    // added while the call waited applies to the result it produces.
    let (store, service, session) = seeded();
    let outcome = service
        .invoke(&session, "github.pull_requests.create", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::RequiresApproval { approval, .. } = outcome else { panic!("expected a held call") };
    configure_sources(&store, &[], &[], &["email"]);

    let resolved = service.resolve_approval(&approval.id, true, "bearer", Some("operator")).await.unwrap();
    let result = resolved.result.unwrap().to_value_unbounded();
    assert_eq!(result["email"], REDACTED);
    assert_eq!(result["phone"], "+1 555 0100", "nothing redacts phone in this configuration");
}

#[tokio::test]
async fn no_manifest_connection_or_policy_input_can_un_redact_a_default() {
    let (store, service, session) = seeded();
    let hostile = ["-authorization", "!client_secret", "authorization:false", "*", "", "~secret"];
    configure_sources(&store, &hostile, &hostile, &hostile);

    let outcome = service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::Allowed { result, .. } = outcome else { panic!("expected an allowed call") };
    let result = result.to_value_unbounded();
    assert_eq!(result["authorization"], REDACTED);
    assert_eq!(result["client_secret"], REDACTED);
    assert_eq!(result["title"], "keep me", "and nothing turned into a redact-everything wildcard");
}

#[tokio::test]
async fn a_connection_made_before_the_fix_still_gets_its_bundled_manifest_list() {
    // A stored connection with no list of its own (every connection created before from-preset
    // copied one) is covered by the per-call catalog lookup, with no migration.
    let (store, service, session) = seeded();
    let mut conn = store.get_connection("github_acme").unwrap().unwrap();
    conn.connector = "stripe".into();
    assert!(conn.redact_fields.is_empty());
    store.put_connection(conn).unwrap();

    let outcome = service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::Allowed { result, .. } = outcome else { panic!("expected an allowed call") };
    let result = result.to_value_unbounded();
    assert_eq!(result["email"], REDACTED, "stripe's manifest redacts email");
    assert_eq!(result["phone"], REDACTED, "and phone");
    assert_eq!(result["card"]["number"], REDACTED, "and the card number");
    assert_eq!(result["number"], 42, "but not every field called number");
}

#[tokio::test]
async fn from_preset_copies_the_manifest_list_onto_the_connection() {
    let state = common::seeded();
    let store = state.service.store().clone();
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/connections/from-preset")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(
                    serde_json::json!({ "preset_id": "stripe", "name": "Books", "id": "books" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let expected = presets::catalog().get("stripe").unwrap().redact_fields.clone();
    assert!(!expected.is_empty());
    assert_eq!(store.get_connection("books").unwrap().unwrap().redact_fields, expected);
}
