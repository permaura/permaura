//! Restore reconciliation, driven through the real router.
//!
//! Through `build_router` and a real `AppState` rather than against `reconcile.rs` directly,
//! because what is worth proving is where the enforcement sits: which callers are refused after the
//! hold is lifted, which route can confirm, and what has and has not happened to the store by the
//! time each answer is returned.
//!
//! The hold objects and retained records these tests read are the fixtures in `fixtures/hold/`,
//! written by the hosted scripts rather than by hand. See that directory's README.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectStore};
use permaura_gateway::reconcile::{self, ReviewKind, Stage};
use permaura_gateway::restore::{hold_metadata, hold_object, retained_object, ExecutionHold};
use permaura_gateway::service::EnforcementService;
use permaura_core::{GrantAgent, GrantAgents};
use permaura_gateway::store::{
    memory::MemoryStore, AgentStatus, PendingApproval, Session, SessionRole, Store, APPROVAL_FLOOR_META,
};
use permaura_gateway::{build_router, seed, AppState};

mod common;

/// The tenant every fixture names.
const TENANT: &str = "acme";

/// The hold id `state-held.json` carries.
const HOLD_ID: &str = "hold_20260920T142200Z";

/// The account this worker is provisioned for (`PERMAURA_OWNER_SUB`), and the only subject whose
/// token can confirm restored authority.
const OWNER_SUB: &str = "sam";

const PUBLIC_URL: &str = "https://g-restore.permaura.test";
const AS_ISSUER: &str = "https://permaura.test/api/auth";
const AS_KID: &str = "as-restore-k1";

// ── fixtures, as the hosted scripts wrote them ───────────────────────────────────────

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hold")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// A bucket holding one `state.json` and, optionally, one `retained.json`.
///
/// The retained record goes in first and the hold is pinned to the generation it landed at, as
/// restore-tenant.sh pins the one it read: the fixtures carry the generation a real bucket assigned,
/// which this one never will.
fn bucket(state: &str, retained: Option<&str>) -> Arc<MemoryObjectStore> {
    let objects = Arc::new(MemoryObjectStore::new());
    let mut document: Value = serde_json::from_slice(&fixture(state)).expect("a hold fixture");
    if let Some(retained) = retained {
        let stored = objects
            .put_if_generation(&retained_object(TENANT), &fixture(retained), 0, &hold_metadata())
            .expect("write the retained record");
        let permaura_gateway::objectstore::PutOutcome::Stored(generation) = stored else {
            panic!("the retained record was not stored: {stored:?}")
        };
        if document["retained_ref"]["generation"].is_string() {
            document["retained_ref"]["generation"] = json!(generation.to_string());
        }
    }
    objects
        .put_if_generation(&hold_object(TENANT), &serde_json::to_vec(&document).unwrap(), 0, &hold_metadata())
        .expect("write the hold object");
    objects
}

fn hold(objects: Arc<MemoryObjectStore>) -> Arc<ExecutionHold> {
    Arc::new(
        ExecutionHold::open(None, objects, TENANT, Duration::from_secs(600))
            .expect("the hold object reads"),
    )
}

// ── the worker under test ────────────────────────────────────────────────────────────

/// A hosted worker with a fake Authorization Server behind it, so the confirmation authority is
/// exercised for real rather than stubbed.
///
/// The environment is process-global and the suite runs in parallel, so every value is the same for
/// every test here and is set once before any `AppState` exists. The hold itself is never set
/// through the environment, for the same reason: `common::seeded_with_hold` takes one the test
/// built.
fn oauth_environment() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        common::isolate_from_the_real_install();
        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": AS_KID,
                "use": "sig",
                "alg": "EdDSA",
                "x": URL_SAFE_NO_PAD.encode(as_signing_key().verifying_key().to_bytes()),
            }]
        })
        .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local JWKS listener");
        let port = listener.local_addr().expect("JWKS listener address").port();
        std::thread::spawn(move || serve_jwks(listener, jwks));
        std::env::set_var("PERMAURA_PUBLIC_URL", PUBLIC_URL);
        std::env::set_var("PERMAURA_AS_ISSUER", AS_ISSUER);
        std::env::set_var("PERMAURA_AS_JWKS", format!("http://127.0.0.1:{port}/jwks"));
        std::env::set_var("PERMAURA_OWNER_SUB", OWNER_SUB);
    });
}

fn as_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[37u8; 32])
}

/// Answer every connection with the same JWKS document.
fn serve_jwks(listener: TcpListener, body: String) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut scratch = [0u8; 2048];
        let _ = stream.read(&mut scratch);
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }
}

fn mint(claims: Value) -> String {
    let header = json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" });
    let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = as_signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix milliseconds. `store::now_ms` is crate-private, so this binary keeps its own.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A console-minted operator token for the bound owner: the confirmation authority.
fn operator_jwt() -> String {
    mint(json!({
        "iss": AS_ISSUER,
        "sub": OWNER_SUB,
        "aud": format!("{PUBLIC_URL}/mcp"),
        "exp": now_secs() + 600,
        "scope": "permaura:operator",
    }))
}

/// A token for somebody who is not this gateway's bound owner.
fn stranger_jwt() -> String {
    mint(json!({
        "iss": AS_ISSUER,
        "sub": "user_someone_else",
        "aud": format!("{PUBLIC_URL}/mcp"),
        "exp": now_secs() + 600,
        "scope": "permaura:operator",
    }))
}

/// A seeded worker over `store`, with the hold and the OAuth resource server wired, its JWKS
/// already fetched.
async fn worker(store: Arc<dyn Store>, hold: Arc<ExecutionHold>) -> AppState {
    worker_with_http(store, hold, Arc::new(permaura_gateway::connectors::MockHttpClient::new())).await
}

/// [`worker`] over an HTTP seam the test keeps.
async fn worker_with_http(
    store: Arc<dyn Store>,
    hold: Arc<ExecutionHold>,
    http: Arc<permaura_gateway::connectors::MockHttpClient>,
) -> AppState {
    oauth_environment();
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let oauth = permaura_gateway::oauth::RsConfig::from_env()
        .map(|cfg| Arc::new(permaura_gateway::oauth::OAuthRs::new(cfg)))
        .expect("PERMAURA_PUBLIC_URL makes this gateway a resource server");
    oauth.refresh().await;
    let backend = permaura_gateway::backend::build_backend(store.clone());
    let service = EnforcementService::from_components(
        store,
        http,
        Arc::new(permaura_gateway::connectors::MockCommandRunner::new()),
        backend,
        Some(oauth),
    )
    .with_execution_hold(hold);
    AppState::new(service)
}

/// The same worker, over the in-memory store, already reconciled once at boot.
async fn restored_worker() -> AppState {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store, hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    reconcile::run_at_boot(&state.service).expect("the restore reconciles");
    state
}

fn app(state: &AppState) -> axum::Router {
    build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn request(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Lift the hold the way the restoration authority does: replace the object with the open one the
/// provisioner writes, and let the recheck interval elapse.
fn lift(objects: &MemoryObjectStore) {
    let current = objects.head(&hold_object(TENANT)).unwrap().unwrap_or(0);
    objects
        .put_if_generation(&hold_object(TENANT), &fixture("state-open.json"), current, &hold_metadata())
        .expect("the restoration authority clears the hold");
}

// ── the trigger ──────────────────────────────────────────────────────────────────────

/// The four guards, read off the objects the hosted scripts actually write.
#[tokio::test]
async fn an_ordinary_cold_start_never_reconciles() {
    // A gateway with no hold bucket at all: every self-hosted install, and every hosted worker
    // provisioned before the backup project existed.
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), Arc::new(ExecutionHold::env_only(None))).await;
    assert!(reconcile::run_at_boot(&state.service).unwrap().is_none());
    assert!(state.service.reconciliation().unwrap().is_none(), "no record was written");

    // A provisioned worker: the explicit open object, which carries no checkpoint id.
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store, hold(bucket("state-open.json", Some("retained-numbers.json")))).await;
    assert!(state.service.execution_hold().unwrap().restore_trigger().is_none());
    assert!(reconcile::run_at_boot(&state.service).unwrap().is_none());
    assert!(state.service.reconciliation().unwrap().is_none());

    // Layer 1 alone holds the worker without a restore ever having happened.
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store, Arc::new(ExecutionHold::env_only(Some("hold_manual".into())))).await;
    assert!(reconcile::run_at_boot(&state.service).unwrap().is_none());
}

/// A restored worker scales to zero and cold-starts repeatedly; the invalidation runs once.
#[tokio::test]
async fn a_second_cold_start_of_a_restored_worker_does_not_reconcile_twice() {
    let objects = bucket("state-held.json", Some("retained-floors.json"));
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(objects.clone())).await;
    let first = reconcile::run_at_boot(&state.service).unwrap().expect("the restore reconciles");
    assert_eq!(first.stage, Stage::Reviewing);
    let recovery_after_first = recovery_actions(store.as_ref());

    // A session opened after the restore, by somebody the owner let in. A second reconciliation
    // would delete it, which is how this test can tell a resume from a re-run.
    store
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_after".into(),
            agent_id: "operator".into(),
            user_id: None,
            device_id: None,
            token: "tok_after".into(),
            role: SessionRole::Operator,
            created_at: 0,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();

    // The second cold start, same hold id, and the object has moved on to `reconciling`.
    let state2 = worker(store.clone(), hold(bucket("state-reconciling.json", Some("retained-floors.json")))).await;
    let second = reconcile::run_at_boot(&state2.service).unwrap().expect("the same reconciliation");
    assert_eq!(second.hold_id, first.hold_id);
    assert_eq!(second.opened_at, first.opened_at, "the same record, resumed");
    assert!(
        store.get_session("sess_after").unwrap().is_some(),
        "the session opened after the restore survives, so nothing was invalidated a second time"
    );
    assert_eq!(
        recovery_actions(store.as_ref()),
        recovery_after_first,
        "and no second set of recovery events was appended"
    );
}

// ── the invalidation ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_restore_invalidates_every_session_and_denies_every_pending_approval() {
    let before = now_ms();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    // `seed::seed` seals the demo estate's credentials, so it resolves the vault KEK: it is a pin
    // site in its own right, and here it runs BEFORE `worker()`, which is where the rest of this
    // file gets its pin. Without it the test mints a KEK into the developer's own home.
    common::isolate_from_the_real_install();
    seed::seed(store.as_ref()).expect("seed");
    for id in ["sess_a", "sess_b"] {
        store
            .put_session(Session {
                class: Default::default(),
                opened_by: None,
                id: id.into(),
                agent_id: "codex-cli".into(),
                user_id: None,
                device_id: None,
                token: format!("tok-{id}"),
                role: SessionRole::Operator,
                created_at: 0,
                revoked: false,
                expires_at: None,
                last_used_at: None,
                actor: None,
            })
            .unwrap();
    }
    store
        .put_approval(PendingApproval {
            id: "appr_held".into(),
            session_id: "sess_a".into(),
            capability: "braintree.transactions.refund".into(),
            resource: "braintree_production".into(),
            message: "Refund?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: json!({ "amount": 100 }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: 0,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
    store
        .put_enrolment_code(permaura_gateway::store::EnrolmentCode {
            code: "ENRL-LIVE".into(),
            label: None,
            created_at: 0,
            expires_at: i64::MAX,
            used: false,
        })
        .unwrap();

    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");

    assert!(store.list_sessions().unwrap().is_empty(), "every session is deleted, not revoked");
    let approval = store.get_approval("appr_held").unwrap().expect("the row is still there");
    assert_eq!(approval.status, "denied");
    assert_eq!(approval.resolution_reason.as_deref(), Some(reconcile::DENIED_BY_RESTORE));
    assert!(
        store.consume_enrolment_code("ENRL-LIVE", 1).unwrap().is_none(),
        "the unconsumed enrolment code is gone"
    );
    // `max(restored, retained, the instant this reconciliation ran)`. The retained floor is read and
    // ranked (the floor is never below it), but the restore instant dominates it, because every
    // one-time token alive at that instant was issued against a claims ledger this restore rolled
    // back.
    let floor = record.replay_floor_ms.expect("a restore always sets a floor");
    assert!(floor >= 1_758_376_682_117, "never below the retained floor: {floor}");
    assert!(floor >= before, "and never below the instant the restore reconciled: {floor} < {before}");
    assert_eq!(record.replay_floor_source.as_deref(), Some("restore_time"));
    assert_eq!(record.approval_floor.as_deref(), Some("device_signed"));

    // And it is terminal: a held call denied by the restore cannot be approved back into life,
    // whatever a client still holding its approval id tries.
    let resolved = state
        .service
        .resolve_approval("appr_held", true, "bearer", None)
        .await
        .expect("a resolved approval answers rather than erroring");
    assert_eq!(resolved.status, "denied", "still denied");
    assert!(resolved.result.is_none(), "and nothing ran");
}

/// The same run against the store that actually ships, so the invalidation's transaction, the epoch
/// fork and the re-signed boundary are exercised on SQLite rather than on a passthrough.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_restore_reconciles_on_the_store_that_actually_ships() {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!(
        "permaura-reconcile-sqlite-{}-{}",
        std::process::id(),
        now_secs()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db").to_string_lossy().to_string();
    let store: Arc<dyn Store> =
        Arc::new(permaura_gateway::store::sqlite::SqliteStore::open(&path).expect("opens"));
    assert_eq!(store.audit_epoch().unwrap(), Some(0));

    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    assert_eq!(record.epoch_target, Some(1));
    assert_eq!(store.audit_epoch().unwrap(), Some(1), "the chain forked");
    assert_eq!(
        recovery_event(store.as_ref(), "recovery.restored")["summary"]["epoch"],
        json!(1)
    );
    assert!(record.items.iter().any(|i| i.kind == ReviewKind::Grant));
    assert_eq!(store.verify_audit().unwrap(), None, "and the chain still verifies");
    drop(state);
    drop(store);

    // The signing-order trap, end to end: a boundary naming a non-zero epoch must verify under the
    // key the next open resolves, or the store refuses to open at all.
    let reopened = permaura_gateway::store::sqlite::SqliteStore::open(&path)
        .expect("a forked store still opens, which only happens when its boundary verifies");
    assert_eq!(reopened.audit_epoch().unwrap(), Some(1));
    assert_eq!(reopened.verify_audit().unwrap(), None);
    assert!(
        reconcile::load(&reopened).unwrap().is_some(),
        "and the record survived the restart, so the second cold start resumes"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// `retained-nulls.json` is what every checkpoint written today looks like. The replay floor is set
/// anyway, from the instant the restore reconciled, and the record says that is where it came from.
/// The approval floor is still never invented, because a floor nobody stamped is not a floor.
#[tokio::test]
async fn a_retained_record_with_no_floors_still_floors_the_one_time_ledger() {
    let before = now_ms();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-nulls.json")))).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");

    let floor = record.replay_floor_ms.expect("a restore always sets a floor");
    assert!(floor >= before, "the floor is the instant the restore reconciled: {floor} < {before}");
    assert_eq!(record.replay_floor_source.as_deref(), Some("restore_time"));
    assert_eq!(
        permaura_gateway::restore::replay_floor(store.as_ref()).unwrap(),
        Some(floor),
        "and it was written to the store, not only to the record"
    );
    assert!(
        record.notes.iter().any(|n| n.contains("no replay floor")),
        "the owner is still told the checkpoint job stamped none: {:?}",
        record.notes
    );
    assert!(
        record.notes.iter().any(|n| n.contains("no approval floor")),
        "and about the approval floor too: {:?}",
        record.notes
    );
    // `retained-nulls.json` also carries no head seq, so the gap cannot be computed and must not be
    // reported as zero.
    assert_eq!(record.gap_events, None);
    let restored = recovery_event(store.as_ref(), "recovery.restored");
    assert_eq!(restored["summary"]["gap_events"], json!("unknown"));
    assert_eq!(restored["summary"]["abandoned_head_seq"], Value::Null);
}

/// The string `none` and `null` are different nothings and the chain keeps them apart.
#[tokio::test]
async fn the_two_kinds_of_nothing_reach_the_chain_as_different_values() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-none.json")))).await;
    reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    let restored = recovery_event(store.as_ref(), "recovery.restored");
    assert_eq!(
        restored["summary"]["abandoned_head_seq"],
        json!("none"),
        "a gateway looked and there was nothing there"
    );
    assert_eq!(restored["summary"]["gap_events"], json!("unknown"));
}

/// The fork record: the abandoned head, the restored head and a correct gap.
#[tokio::test]
async fn the_restored_chain_records_the_fork_and_the_gap() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    // Before `seed::seed`, for the reason given at the first of these.
    common::isolate_from_the_real_install();
    seed::seed(store.as_ref()).expect("seed");
    // Three events in the restored window, so the head is seq 2 and the gap is 100987 - 2.
    for i in 0..3 {
        store
            .append_audit(permaura_core::AuditPayload::new(format!("a{i}"), "r", "allow"))
            .unwrap();
    }
    let objects = bucket("state-held.json", Some("retained-floors.json"));
    let pinned = objects.head(&retained_object(TENANT)).unwrap().expect("a retained record").to_string();
    let state = worker(store.clone(), hold(objects)).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");

    let restored = recovery_event(store.as_ref(), "recovery.restored");
    assert_eq!(restored["summary"]["restored_head_seq"], json!(2));
    assert_eq!(restored["summary"]["abandoned_head_seq"], json!(100_987));
    assert_eq!(restored["summary"]["abandoned_epoch"], json!(0));
    assert_eq!(restored["summary"]["gap_events"], json!(100_985));
    assert_eq!(record.gap_events, Some(100_985));
    assert_eq!(restored["summary"]["checkpoint_id"], json!("cp_acme_20260920T140000Z_g4711"));
    assert_eq!(
        restored["summary"]["source_generation"],
        json!(pinned),
        "the retained generation the restore was planned against, not whatever a later checkpoint left"
    );
    assert_eq!(restored["summary"]["retained_generation"], json!(pinned), "and it is the one that was read");
    assert_eq!(restored["summary"]["retained_chosen"], json!("pinned"));

    // The four recovery audit events, in order, and none of them before the fork record.
    let actions = recovery_actions(store.as_ref());
    assert_eq!(
        actions,
        vec!["recovery.restored", "recovery.invalidated", "recovery.needs_review"],
        "and the close is not among them until the owner closes it"
    );
}

/// Floors are a maximum. A restore can raise them and can never lower them.
#[tokio::test]
async fn a_restore_raises_the_approval_floor_and_never_lowers_it() {
    // Restored snapshot: device_signed. Retained record: device_signed. Nothing moves.
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    store.put_meta(APPROVAL_FLOOR_META, "device_signed").unwrap();
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    assert_eq!(record.approval_floor.as_deref(), Some("device_signed"));
    assert_eq!(store.get_meta(APPROVAL_FLOOR_META).unwrap().as_deref(), Some("device_signed"));

    // Restored snapshot: nothing. Retained record: device_signed. The floor is raised.
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    assert_eq!(
        store.get_meta(APPROVAL_FLOOR_META).unwrap().as_deref(),
        Some("device_signed"),
        "a floor its owner raised after the checkpoint is preserved"
    );

    // Restored snapshot: device_signed. Retained record: nothing at all. It stays device_signed.
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    store.put_meta(APPROVAL_FLOOR_META, "device_signed").unwrap();
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-nulls.json")))).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    assert_eq!(record.approval_floor.as_deref(), Some("device_signed"), "never lowered");
    assert_eq!(store.get_meta(APPROVAL_FLOOR_META).unwrap().as_deref(), Some("device_signed"));
}

/// The replay floor kills every pre-restore one-time token, whatever the rolled-back ledger says.
#[tokio::test]
async fn a_pre_restore_step_up_ticket_is_refused_after_the_replay_floor_moves() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");

    let floor = record.replay_floor_ms.expect("a restore always sets a floor");
    // The ledger is empty, because a restore rolled it back: the claim itself would succeed.
    assert!(store.claim_once("step-up", "jti-pre-restore", i64::MAX).unwrap());
    let refused = permaura_gateway::restore::refuse_if_replayed_across_a_restore(
        store.as_ref(),
        floor,
        "step-up ticket",
    )
    .expect_err("a ticket issued AT the floor is one nobody can vouch for");
    assert!(matches!(refused, GatewayError::Unauthorized(_)), "{refused}");
    assert!(permaura_gateway::restore::refuse_if_replayed_across_a_restore(
        store.as_ref(),
        floor + 1,
        "step-up ticket",
    )
    .is_ok());
}

// ── needs_review, enforced beside the hold ───────────────────────────────────────────

/// The load-bearing one: a grant that came back with the snapshot cannot execute, and that survives
/// the hold being lifted.
#[tokio::test]
async fn a_grant_with_no_journal_entry_lands_in_needs_review_and_cannot_execute() {
    let objects = bucket("state-held.json", Some("retained-floors.json"));
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(objects.clone())).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    assert!(
        record.items.iter().any(|i| i.kind == ReviewKind::Grant),
        "the seeded estate's grants are all in the list"
    );

    lift(&objects);
    tokio::time::sleep(Duration::from_millis(5)).await;
    // The hold's recheck interval is ten minutes here, so the lift is applied directly rather than
    // waited for: what this test is about is what happens once nothing is held.
    let unheld = worker(store.clone(), hold(bucket("state-open.json", None))).await;
    assert!(unheld.service.refuse_if_held().is_ok(), "nothing is held any more");

    let session = agent_session(store.as_ref());
    let outcome = unheld
        .service
        .invoke(
            &session,
            "braintree.transactions.search",
            &json!({ "status": "failed" }),
            None,
            permaura_core::ExecutionLocation::LocalOnly,
        )
        .await
        .expect("the call is answered, not errored");
    let reason = denial_reason(&outcome);
    assert!(
        reason.contains("restored snapshot") && reason.contains("has not confirmed"),
        "denied for the right reason: {reason}"
    );
}

/// Every kind in the list blocks, not just the one that happens to be checked first.
#[tokio::test]
async fn every_kind_of_restored_authority_is_refused_until_it_is_confirmed() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    for kind in [
        ReviewKind::Grant,
        ReviewKind::Connection,
        ReviewKind::Secret,
        ReviewKind::Agent,
    ] {
        assert!(
            record.items.iter().any(|i| i.kind == kind),
            "the seeded estate has at least one {kind:?} and it is in the list"
        );
    }

    let unheld = worker(store.clone(), hold(bucket("state-open.json", None))).await;
    let session = agent_session(store.as_ref());
    // Confirm one kind at a time and watch the denial reason move down the gates, which is what
    // proves each gate is wired rather than one gate catching everything.
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..4 {
        let outcome = unheld
            .service
            .invoke(
                &session,
                "braintree.transactions.search",
                &json!({ "status": "failed" }),
                None,
                permaura_core::ExecutionLocation::LocalOnly,
            )
            .await
            .expect("answered");
        let reason = denial_reason(&outcome);
        assert!(reason.contains("restored snapshot"), "{reason}");
        let kind = ["connection", "agent", "secret", "grant"]
            .iter()
            .find(|k| reason.contains(&format!("The {k} '")))
            .unwrap_or_else(|| panic!("the denial names a kind: {reason}"))
            .to_string();
        assert!(!seen.contains(&kind), "each gate refuses once: {kind} twice");
        seen.push(kind.clone());
        // Confirm every item of that kind and go round again.
        let mut record = unheld.service.reconciliation().unwrap().unwrap();
        let want = ReviewKind::parse(&kind).unwrap();
        for item in record.items.iter_mut().filter(|i| i.kind == want) {
            item.status = permaura_gateway::reconcile::ReviewStatus::Confirmed;
        }
        reconcile::save(store.as_ref(), &record).unwrap();
    }
    assert_eq!(seen.len(), 4, "four gates: {seen:?}");
}

/// A bearer that was revoked after the checkpoint comes back valid in the snapshot. It must never
/// authenticate again, and no confirmation brings it back: sessions are deleted rather than listed.
#[tokio::test]
async fn a_bearer_revoked_after_the_checkpoint_still_fails_after_the_restore() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    // Before `seed::seed`, for the reason given at the first of these.
    common::isolate_from_the_real_install();
    seed::seed(store.as_ref()).expect("seed");
    let token = "tok_revoked_after_the_checkpoint";
    store
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_stale".into(),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: token.into(),
            role: SessionRole::Operator,
            created_at: 0,
            // Unrevoked, because the generation that revoked it was the one thrown away.
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
    let objects = bucket("state-held.json", Some("retained-floors.json"));
    let state = worker(store.clone(), hold(objects)).await;
    assert!(state.service.authenticate(token).is_ok(), "before reconciliation it works");
    reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    assert!(state.service.authenticate(token).is_err(), "and after it does not");

    // And it is still gone once nothing is held and every item has been confirmed.
    let unheld = worker(store.clone(), hold(bucket("state-open.json", None))).await;
    let app = app(&unheld);
    let resp = app
        .oneshot(request("POST", "/v1/recovery/reconciliation/confirm-all", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        unheld.service.authenticate(token).is_err(),
        "confirming the list never brings a deleted session back"
    );
    assert!(
        store.get_session("sess_stale").unwrap().is_none(),
        "the row itself is gone, so there is nothing left to un-revoke"
    );
}

/// A device that came back with the snapshot cannot approve, and it cannot confirm itself either.
#[tokio::test]
async fn a_restored_approver_device_can_neither_approve_nor_confirm() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key("device:restored-phone", &pubkey), "the key pairs");
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    assert!(
        record.items.iter().any(|i| i.kind == ReviewKind::Device && i.id == "device:restored-phone"),
        "the paired device is in the list: {:?}",
        record.items
    );

    let keyring = state.service.approver_keyring_snapshot();
    let outcome = state.service.verify_signed_approval(
        &keyring,
        &permaura_relay::ApprovalResult {
            job_id: "job_1".into(),
            approval_id: "appr_1".into(),
            approve: true,
            request_hash: "deadbeef".into(),
            approver: "device:restored-phone".into(),
            decided_at: now_secs() * 1000,
            approver_pubkey: None,
            audience: None,
            display_digest: None,
            device_sig: String::new(),
        },
    );
    match outcome {
        permaura_gateway::service::SignedApprovalOutcome::Refused(why) => assert!(
            why.contains("restored snapshot"),
            "refused for being unreviewed rather than for a bad signature: {why}"
        ),
        _ => panic!("a device awaiting review must not approve"),
    }

    // And nothing a device holds is a confirmation authority: the routes take an OAuth operator
    // token and there is no device path into them at all.
    let resp = app(&state)
        .oneshot(request("GET", "/v1/recovery/reconciliation", &pubkey, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "a device key is not a bearer, let alone an authority");
}

// ── the routes ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn only_the_bound_owners_operator_token_can_drive_a_reconciliation() {
    let state = restored_worker().await;
    // A gateway session bearer, which is what a restored database would hand back.
    let session_token = common::operator_token(state.clone()).await;
    for (token, what) in [
        (session_token.as_str(), "a gateway session bearer"),
        ("", "nothing at all"),
    ] {
        let resp = app(&state)
            .oneshot(request("GET", "/v1/recovery/reconciliation", token, json!({})))
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "{what} must not reach the reconciliation: {}",
            resp.status()
        );
    }
    let resp = app(&state)
        .oneshot(request("GET", "/v1/recovery/reconciliation", &stranger_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "another account's operator token");

    let resp = app(&state)
        .oneshot(request("GET", "/v1/recovery/reconciliation", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["hold_id"], json!(HOLD_ID));
    assert!(body["unreviewed"].as_u64().unwrap() > 0);
    assert!(body["audit_pressure"]["ceiling"].is_number(), "the ceiling travels with the list");
}

/// The reconciliation routes answer while the tenant is held, which is the only reason they are
/// usable at all: reconciliation is the thing a held tenant is being asked to do.
#[tokio::test]
async fn the_reconciliation_routes_answer_while_execution_is_held() {
    let state = restored_worker().await;
    assert!(state.service.refuse_if_held().is_err(), "the tenant is held");
    let resp = app(&state)
        .oneshot(request("GET", "/v1/recovery/reconciliation", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// At the hot-audit ceiling every new execution is refused, and reconciliation is not an execution.
#[tokio::test]
async fn reconciliation_mutations_succeed_at_the_audit_ceiling() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    oauth_environment();
    seed::seed(store.as_ref()).expect("seed");
    let oauth = permaura_gateway::oauth::RsConfig::from_env()
        .map(|cfg| Arc::new(permaura_gateway::oauth::OAuthRs::new(cfg)))
        .expect("resource server");
    oauth.refresh().await;
    let backend = permaura_gateway::backend::build_backend(store.clone());
    let service = EnforcementService::from_components(
        store.clone(),
        Arc::new(permaura_gateway::connectors::MockHttpClient::new()),
        Arc::new(permaura_gateway::connectors::MockCommandRunner::new()),
        backend,
        Some(oauth),
    )
    .with_execution_hold(hold(bucket("state-held.json", Some("retained-floors.json"))))
    // A ceiling of one, so the seeded chain is already above it.
    .with_audit_ceiling(Arc::new(permaura_gateway::audit_ceiling::AuditCeiling::new(
        permaura_gateway::audit_ceiling::AuditCeilingConfig {
            soft: 1,
            ceiling: 1,
            ..Default::default()
        },
    )));
    let state = AppState::new(service);
    reconcile::run_at_boot(&state.service).expect("a restore reconciles above the ceiling too");
    assert!(state.service.refuse_if_audit_full().is_err(), "the ceiling is reached");

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/confirm-all", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "the ceiling never gates reconciliation");
}

#[tokio::test]
async fn close_refuses_while_anything_is_outstanding_and_records_reconciled_when_nothing_is() {
    let state = restored_worker().await;
    let store = state.service.store().clone();
    let token = operator_jwt();

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/close", &token, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert!(
        body["error"].as_str().unwrap_or_default().contains("awaiting review"),
        "{body}"
    );
    assert!(
        !recovery_actions(store.as_ref()).contains(&"recovery.reconciled".to_string()),
        "and nothing was recorded"
    );

    // Confirm one by hand, remove one, then accept the rest at once.
    let record = state.service.reconciliation().unwrap().unwrap();
    let a_grant = record.items.iter().find(|i| i.kind == ReviewKind::Grant).unwrap().clone();
    let a_secret = record.items.iter().find(|i| i.kind == ReviewKind::Secret).unwrap().clone();
    let resp = app(&state)
        .oneshot(request(
            "POST",
            "/v1/recovery/reconciliation/confirm",
            &token,
            json!({ "kind": "grant", "id": a_grant.id }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app(&state)
        .oneshot(request(
            "POST",
            "/v1/recovery/reconciliation/remove",
            &token,
            json!({ "kind": "secret", "id": a_secret.id }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        store.get_secret(&a_secret.id).unwrap().is_none(),
        "removing an item deletes the thing, not just the row about it"
    );

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/confirm-all", &token, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["unreviewed"], json!(0));

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/close", &token, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["state"], json!("closed"));
    assert_eq!(body["hold"]["cleared"], json!(false), "the gateway never writes the hold object");
    assert!(body["hold"]["next"].as_str().unwrap().contains("restoration authority"));

    // Confirm-all is audited AS confirm-all, not as N confirmations.
    let actions = recovery_actions(store.as_ref());
    assert_eq!(actions.iter().filter(|a| *a == "recovery.confirm_all").count(), 1);
    assert_eq!(actions.iter().filter(|a| *a == "recovery.confirm").count(), 1);
    assert_eq!(actions.iter().filter(|a| *a == "recovery.remove").count(), 1);
    assert_eq!(actions.iter().filter(|a| *a == "recovery.reconciled").count(), 1);

    let reconciled = recovery_event(store.as_ref(), "recovery.reconciled");
    assert_eq!(reconciled["summary"]["hold_id"], json!(HOLD_ID));
    assert_eq!(reconciled["summary"]["reviewed_by"], json!(OWNER_SUB));
    assert_eq!(reconciled["summary"]["removed"], json!(1));
}

/// The reconciliation side of emptying the keyring: removing a restored device revokes its key, so when
/// it is the last trusted approver the removal empties the keyring. Only the owner's own token may do
/// that; one naming a different member as the actor is refused, and the device stays trusted.
#[tokio::test]
async fn removing_the_last_restored_device_takes_the_owners_own_token() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes());
    assert!(state.service.trust_approver_key("device:restored-phone", &pubkey), "the key pairs");
    reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");

    let members = mint(json!({
        "iss": AS_ISSUER,
        "sub": OWNER_SUB,
        "aud": format!("{PUBLIC_URL}/mcp"),
        "exp": now_secs() + 600,
        "scope": "permaura:operator",
        "act_sub": "user_priya",
    }));
    let remove = json!({ "kind": "device", "id": "device:restored-phone" });
    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/remove", &members, remove.clone()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{}", body_json(resp).await);
    assert!(state.service.approver_key_trusted("device:restored-phone"), "the refused removal did not land");

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/remove", &operator_jwt(), remove))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!state.service.approver_key_trusted("device:restored-phone"));
}

/// `/health` says which state a reconciliation is in and names nothing restored.
#[tokio::test]
async fn health_reports_the_reconciliation_and_nothing_sensitive() {
    let state = restored_worker().await;
    let token = common::operator_token(state.clone()).await;
    let resp = app(&state)
        .oneshot(request("GET", "/health", &token, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let block = &body["reconciliation"];
    assert_eq!(block["state"], json!("reviewing"));
    assert_eq!(block["hold_id"], json!(HOLD_ID));
    assert!(block["unreviewed"].as_u64().unwrap() > 0);
    let rendered = block.to_string();
    for id in ["braintree", "grant_", "sec_"] {
        assert!(!rendered.contains(id), "no restored id belongs in /health: {rendered}");
    }
    assert!(body["audit_pressure"]["ceiling"].is_number());
}

/// A gateway that has never been restored reports `null`, which must not read as "reconciled".
#[tokio::test]
async fn health_reports_null_on_a_gateway_that_has_never_been_restored() {
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    let resp = app(&state)
        .oneshot(request("GET", "/health", &token, json!({})))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["reconciliation"], Value::Null);
}

/// A self-hosted gateway has no Authorization Server, so it has no confirmation authority. It also
/// has no hold bucket and never reconciles, and the refusal says both.
#[tokio::test]
async fn a_self_hosted_gateway_is_told_why_it_has_no_reconciliation_authority() {
    // Built explicitly rather than through `common::seeded()`: `PERMAURA_PUBLIC_URL` is
    // process-wide and this binary sets it, so the only honest way to model a gateway with no
    // Authorization Server is to assemble one without.
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    seed::seed(store.as_ref()).expect("seed");
    let state = AppState::new(EnforcementService::new(
        store,
        Arc::new(permaura_gateway::connectors::MockHttpClient::new()),
    ));
    assert!(state.service.oauth().is_none(), "a self-hosted gateway is no resource server");
    let resp = app(&state)
        .oneshot(request("GET", "/v1/recovery/reconciliation", "anything", json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    let message = body["error"].as_str().unwrap_or_default();
    assert!(message.contains("PERMAURA_OWNER_SUB"), "{message}");
    assert!(message.contains("never reconciles"), "{message}");
}

// ── helpers ──────────────────────────────────────────────────────────────────────────

/// An agent session for the seeded estate, opened after the restore so the invalidation is not what
/// refuses the call.
fn agent_session(store: &dyn Store) -> Session {
    let session = Session {
        class: Default::default(),
        opened_by: None,
        id: "sess_after_restore".into(),
        agent_id: "codex-cli".into(),
        user_id: None,
        device_id: None,
        token: "tok_after_restore".into(),
        role: SessionRole::Agent,
        created_at: 0,
        revoked: false,
        expires_at: None,
        last_used_at: None,
        actor: None,
    };
    store.put_session(session.clone()).unwrap();
    session
}

fn denial_reason(outcome: &permaura_gateway::service::InvokeOutcome) -> String {
    match outcome {
        permaura_gateway::service::InvokeOutcome::Denied { decision } => decision.reason.clone(),
        _ => panic!("expected a denial"),
    }
}

/// Every `recovery.*` action in the chain, in order.
fn recovery_actions(store: &dyn Store) -> Vec<String> {
    store
        .audit_events(None)
        .unwrap()
        .into_iter()
        .map(|e| e.payload.action)
        .filter(|a| a.starts_with("recovery."))
        .collect()
}

/// The newest event with this action, as JSON.
fn recovery_event(store: &dyn Store, action: &str) -> Value {
    let event = store
        .audit_events(None)
        .unwrap()
        .into_iter()
        .rev()
        .find(|e| e.payload.action == action)
        .unwrap_or_else(|| panic!("no {action} in the chain"));
    serde_json::to_value(event.payload).unwrap()
}

/// Proof the fixtures are the shapes this build reads, rather than something a test wrote to suit
/// itself: every one of them parses, and each derives the trigger decision the gateway acts on.
#[test]
fn every_hosted_fixture_parses_and_derives_the_right_trigger() {
    let cases: &[(&str, Option<&str>)] = &[
        ("state-open.json", None),
        ("state-held.json", Some("held")),
        ("state-reconciling.json", Some("reconciling")),
        // The document that lifts a hold, written by the same `hold_open_patch` over
        // `state-reconciling.json`. `hold_merge` merges, so this is the one that would carry a stale
        // `checkpoint_id` if the patch did not null it, and the trigger check below is what proves a
        // lifted worker does not reconcile again.
        ("state-lifted.json", None),
    ];
    for (name, expected) in cases {
        let objects = Arc::new(MemoryObjectStore::new());
        objects
            .put_if_generation(&hold_object(TENANT), &fixture(name), 0, &BTreeMap::new())
            .unwrap();
        let hold = ExecutionHold::open(None, objects, TENANT, Duration::from_secs(600))
            .unwrap_or_else(|e| panic!("{name} must parse: {e}"));
        match expected {
            Some(state) => {
                let trigger = hold.restore_trigger().unwrap_or_else(|| panic!("{name} triggers"));
                assert_eq!(trigger.state, *state);
                assert_eq!(trigger.hold_id, HOLD_ID);
                assert_eq!(trigger.checkpoint_id, "cp_acme_20260920T140000Z_g4711");
                assert_eq!(
                    trigger.retained_ref.as_ref().and_then(|r| r.object.clone()).as_deref(),
                    Some("holds/acme/retained.json"),
                    "{name} names the account the restore was planned against"
                );
                assert!(hold.refuse_if_held().is_err(), "{name} refuses execution");
            }
            None => {
                assert!(hold.restore_trigger().is_none(), "{name} is not a restore");
                assert!(hold.refuse_if_held().is_ok(), "{name} permits execution");
            }
        }
    }

    // And the lifted document stops naming the restore, so a human reading the object during the
    // next incident does not see a checkpoint id beside `state: "open"`.
    let lifted: Value = serde_json::from_slice(&fixture("state-lifted.json")).unwrap();
    assert_eq!(lifted["state"], json!("open"));
    assert_eq!(lifted["hold_id"], Value::Null);
    assert_eq!(lifted["checkpoint_id"], Value::Null);
    assert_eq!(lifted["retained_ref"], Value::Null);

    // The retained records, and the three nothings their fields carry.
    let numbers: Value = serde_json::from_slice(&fixture("retained-numbers.json")).unwrap();
    let block = numbers.get("retained");
    assert_eq!(
        reconcile::retained_i64(block, "pre_restore_audit_head_seq"),
        reconcile::Retained::Known(100_987)
    );
    let nulls: Value = serde_json::from_slice(&fixture("retained-nulls.json")).unwrap();
    assert_eq!(
        reconcile::retained_i64(nulls.get("retained"), "pre_restore_audit_head_seq"),
        reconcile::Retained::Unstamped
    );
    let none: Value = serde_json::from_slice(&fixture("retained-none.json")).unwrap();
    assert_eq!(
        reconcile::retained_i64(none.get("retained"), "pre_restore_audit_head_seq"),
        reconcile::Retained::Nothing
    );
    let floors: Value = serde_json::from_slice(&fixture("retained-floors.json")).unwrap();
    assert_eq!(
        reconcile::retained_i64(floors.get("retained"), "replay_floor_ms"),
        reconcile::Retained::Known(1_758_376_682_117),
        "the shape the hosted follow-up will write"
    );
    assert_eq!(
        reconcile::retained_str(floors.get("retained"), "approval_floor"),
        reconcile::Retained::Known("device_signed".into())
    );
}

/// With an archive configured, the restore's epoch is claimed in the archive bucket rather than read
/// out of the restored database: another restore of the same checkpoint already holding epoch 1 moves
/// this one to epoch 2, and the fork is recorded in the boundary's signed lineage under this hold.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_restore_claims_its_epoch_in_the_archive_and_records_its_lineage() {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!(
        "permaura-reconcile-claim-{}-{}",
        std::process::id(),
        now_secs()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db").to_string_lossy().to_string();
    let store: Arc<dyn Store> =
        Arc::new(permaura_gateway::store::sqlite::SqliteStore::open(&path).expect("opens"));
    let archive = Arc::new(permaura_gateway::archive::AuditArchive::with_limits(
        Arc::new(MemoryObjectStore::new()),
        TENANT,
        "audit",
        4,
        2,
    ));
    let parent = store.audit_boundary().unwrap().unwrap();
    assert_eq!(archive.claim_epoch(&parent, "hold_another_restore").unwrap(), 1);

    oauth_environment();
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let service = EnforcementService::new(store.clone(), http)
        .with_execution_hold(hold(bucket("state-held.json", Some("retained-floors.json"))))
        .with_audit_archive(archive.clone());
    let record = reconcile::run_at_boot(&service).unwrap().expect("reconciles");

    assert_eq!(record.epoch_target, Some(2), "epoch 1 belongs to the other restore");
    let boundary = store.audit_boundary().unwrap().unwrap();
    assert_eq!(boundary.epoch, 2);
    let fork = boundary.lineage.last().expect("the fork is in the lineage");
    assert_eq!((fork.epoch, fork.parent_epoch, fork.restore_id.as_str()), (2, 0, HOLD_ID));
    assert_eq!(
        archive.claim_epoch(&parent, HOLD_ID).unwrap(),
        2,
        "a cold start that lost the reconciliation record claims the same epoch again"
    );
    drop(service);
    drop(store);
    let reopened = permaura_gateway::store::sqlite::SqliteStore::open(&path)
        .expect("a boundary with a signed lineage verifies on the next open");
    assert_eq!(reopened.audit_boundary().unwrap().unwrap().lineage.len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// An archive bucket that can be switched off, for a claim outage at boot.
#[cfg(feature = "sqlite")]
struct Switchable {
    inner: MemoryObjectStore,
    down: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "sqlite")]
impl Switchable {
    fn check(&self) -> Result<(), GatewayError> {
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(GatewayError::Internal("synthetic: the archive bucket is unreachable".into()));
        }
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
impl ObjectStore for Switchable {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        self.check()?;
        self.inner.head(name)
    }
    fn head_full(&self, name: &str) -> Result<Option<permaura_gateway::objectstore::ObjectHead>, GatewayError> {
        self.check()?;
        self.inner.head_full(name)
    }
    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        self.check()?;
        self.inner.has_history(name)
    }
    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        self.check()?;
        self.inner.get(name, generation)
    }
    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<permaura_gateway::objectstore::PutOutcome, GatewayError> {
        self.check()?;
        self.inner.put_if_generation(name, bytes, expected, metadata)
    }
    fn describe(&self) -> String {
        "switchable".into()
    }
}

/// The unclaimed-epoch fork, at its source: a restore whose epoch cannot be claimed used to fork into `parent + 1`
/// anyway, which another restore may own. It now records, forks and appends nothing, and stays held;
/// once the bucket answers the same boot path claims a free epoch and reconciles.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_restore_that_cannot_claim_its_epoch_changes_nothing_until_it_can() {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!(
        "permaura-reconcile-outage-{}-{}",
        std::process::id(),
        now_secs()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.db").to_string_lossy().to_string();
    let store: Arc<dyn Store> =
        Arc::new(permaura_gateway::store::sqlite::SqliteStore::open(&path).expect("opens"));
    let objects = Arc::new(Switchable {
        inner: MemoryObjectStore::new(),
        down: std::sync::atomic::AtomicBool::new(false),
    });
    let archive = Arc::new(permaura_gateway::archive::AuditArchive::with_limits(
        objects.clone(),
        TENANT,
        "audit",
        4,
        2,
    ));
    let parent = store.audit_boundary().unwrap().unwrap();
    assert_eq!(archive.claim_epoch(&parent, "hold_another_restore").unwrap(), 1);

    oauth_environment();
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let service = EnforcementService::new(store.clone(), http)
        .with_execution_hold(hold(bucket("state-held.json", Some("retained-floors.json"))))
        .with_audit_archive(archive.clone());
    let events = store.audit_len().unwrap();

    objects.down.store(true, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..2 {
        let err = reconcile::run_at_boot(&service).unwrap_err();
        assert!(err.to_string().contains("could not claim an audit epoch"), "{err}");
        assert_eq!(store.audit_boundary().unwrap().unwrap(), parent, "not forked");
        assert!(reconcile::load(store.as_ref()).unwrap().is_none(), "nothing recorded");
        assert_eq!(store.audit_len().unwrap(), events, "and nothing appended");
        assert!(
            service.execution_hold().and_then(|h| h.restore_trigger()).is_some(),
            "the tenant is still held by the restore"
        );
    }

    objects.down.store(false, std::sync::atomic::Ordering::SeqCst);
    let record = reconcile::run_at_boot(&service).unwrap().expect("reconciles once the claim can be made");
    assert_eq!(record.epoch_target, Some(2));
    let boundary = store.audit_boundary().unwrap().unwrap();
    assert_eq!(boundary.epoch, 2);
    assert_eq!(boundary.lineage.last().map(|f| f.restore_id.as_str()), Some(HOLD_ID));
    drop(service);
    drop(store);
    std::fs::remove_dir_all(&dir).ok();
}

// ── revocations survive a restore ────────────────────────────────────────────────────

/// A token for an OAuth agent the AS minted for `azp`. Its consent outlives every revocation, so on
/// this gateway the revoked `sess_oauth:` row is the only record that the owner stopped it.
fn oauth_client(azp: &str) -> String {
    mint(json!({
        "iss": AS_ISSUER,
        "sub": OWNER_SUB,
        "aud": format!("{PUBLIC_URL}/mcp"),
        "azp": azp,
        "iat": now_secs(),
        "exp": now_secs() + 600,
        "scope": "openid mcp offline_access",
    }))
}

fn agent_status(store: &dyn Store, id: &str) -> Option<AgentStatus> {
    store.get_agent(id).unwrap().map(|a| a.status)
}

/// A client revoked before the checkpoint authenticated again once the restore
/// deleted its tombstone and the owner confirmed its agent.
#[tokio::test]
async fn a_revoked_oauth_client_stays_revoked_across_a_restore() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let client = || oauth_client("client-revoked");
    state.service.authenticate(&client()).expect("the client connects");
    let resp = app(&state)
        .oneshot(request("POST", "/v1/sessions/sess_oauth:client-revoked/revoke", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert!(resp.status().is_success(), "revoke status {}", resp.status());
    assert!(state.service.authenticate(&client()).is_err(), "precondition: the revocation holds");

    reconcile::run_at_boot(&state.service).expect("the restore reconciles");
    let resp = app(&state)
        .oneshot(request(
            "POST",
            "/v1/recovery/reconciliation/confirm",
            &operator_jwt(),
            json!({ "kind": "agent", "id": "oauth:client-revoked" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(state.service.authenticate(&client()).is_err(), "a client its owner revoked is back after the restore");
}

/// An agent removed before the checkpoint is absent from the review list, so only its tombstone can
/// stop its client registering again Approved under the Default grant once the hold lifts.
#[tokio::test]
async fn an_oauth_agent_removed_before_the_checkpoint_does_not_return_approved() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    state.service.authenticate(&oauth_client("client-removed")).expect("the client connects");
    let resp = app(&state)
        .oneshot(request("DELETE", "/v1/agents/oauth:client-removed", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "the owner removes the agent");
    assert_eq!(agent_status(store.as_ref(), "oauth:client-removed"), None);

    reconcile::run_at_boot(&state.service).expect("the restore reconciles");
    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/confirm-all", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = state.service.authenticate(&oauth_client("client-removed"));
    assert_eq!(
        agent_status(store.as_ref(), "oauth:client-removed"),
        Some(AgentStatus::Pending),
        "a removed agent comes back only through a fresh decision"
    );
}

/// The reconciliation's own "remove" is a removal: the tombstone is written and the grants that
/// named the agent stop naming it, so neither the next call nor a confirmed grant brings it back.
#[tokio::test]
async fn an_agent_removed_during_review_stays_removed() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    state.service.authenticate(&oauth_client("client-dropped")).expect("the client connects");
    let mut grant = store
        .list_grants()
        .unwrap()
        .into_iter()
        .find(|g| !g.is_default)
        .expect("the seeded estate has a grant to copy");
    grant.grant_id = "gr_client_dropped".into();
    grant.agents = GrantAgents::Agents(vec![GrantAgent::new("oauth:client-dropped")]);
    store.put_grant(grant).unwrap();
    let mut shared = store
        .list_grants()
        .unwrap()
        .into_iter()
        .find(|g| !g.is_default && g.grant_id != "gr_client_dropped")
        .expect("a second grant to share");
    shared.grant_id = "gr_shared".into();
    shared.agents = GrantAgents::Agents(vec![GrantAgent::new("oauth:client-dropped"), GrantAgent::new("codex-cli")]);
    store.put_grant(shared).unwrap();

    reconcile::run_at_boot(&state.service).expect("the restore reconciles");
    let resp = app(&state)
        .oneshot(request(
            "POST",
            "/v1/recovery/reconciliation/remove",
            &operator_jwt(),
            json!({ "kind": "agent", "id": "oauth:client-dropped" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/confirm-all", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(
        store.get_grant("gr_client_dropped").unwrap().is_none(),
        "a grant that named only the removed agent is gone"
    );
    let shared = store.get_grant("gr_shared").unwrap().expect("a grant naming others stays");
    assert!(!shared.targets("oauth:client-dropped"), "and no longer names it");
    assert!(shared.targets("codex-cli"));
    let tombstone = store.get_session("sess_oauth:client-dropped").unwrap().expect("a tombstone");
    assert!(tombstone.revoked);

    let _ = state.service.authenticate(&oauth_client("client-dropped"));
    assert_eq!(
        agent_status(store.as_ref(), "oauth:client-dropped"),
        Some(AgentStatus::Pending),
        "the removed agent's client comes back only through a fresh decision"
    );
}

/// Every live session goes, on both stores, and so does a revoked bearer session (nothing can present
/// it any more); the revoked OAuth and relayed rows stay, by the same rule the session sweep keeps them.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_restore_deletes_every_live_session_and_keeps_the_revocation_tombstones() {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!(
        "permaura-reconcile-tombstones-{}-{}",
        std::process::id(),
        now_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let sqlite: Arc<dyn Store> = Arc::new(
        permaura_gateway::store::sqlite::SqliteStore::open(&dir.join("gateway.db").to_string_lossy())
            .expect("opens"),
    );
    for store in [Arc::new(MemoryStore::new()) as Arc<dyn Store>, sqlite] {
        let row = |id: &str, revoked: bool| Session {
            class: Default::default(),
            opened_by: None,
            id: id.into(),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: format!("tok-{id}"),
            role: SessionRole::Agent,
            created_at: 0,
            revoked,
            expires_at: None,
            last_used_at: None,
            actor: None,
        };
        seed::seed(store.as_ref()).expect("seed");
        for (id, revoked) in [
            ("sess_live", false),
            ("sess_revoked_bearer", true),
            ("sess_oauth:client-live", false),
            ("sess_oauth:client-revoked", true),
            ("relay:cp_live", false),
            ("relay:cp_revoked", true),
        ] {
            store.put_session(row(id, revoked)).unwrap();
        }
        let before = store.list_sessions().unwrap().len();

        let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
        reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");

        let mut kept: Vec<String> = store.list_sessions().unwrap().into_iter().map(|s| s.id).collect();
        kept.sort();
        assert_eq!(kept, vec!["relay:cp_revoked".to_string(), "sess_oauth:client-revoked".to_string()], "{}", store.kind());
        assert!(store.list_sessions().unwrap().iter().all(|s| s.revoked));
        assert_eq!(
            recovery_event(store.as_ref(), "recovery.invalidated")["summary"]["sessions_deleted"],
            json!(before - 2),
            "{}",
            store.kind()
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

// ── closing needs a finished invalidation ────────────────────────────────────────────

/// The record exactly as `run_at_boot` saves it before the fork and the invalidation, and as it is
/// left when either then fails (an epoch claim, an append, a snapshot upload), with no items yet.
fn record_at(stage: Stage) -> reconcile::ReconciliationRecord {
    reconcile::ReconciliationRecord {
        version: reconcile::RECONCILIATION_VERSION,
        hold_id: HOLD_ID.into(),
        checkpoint_id: "cp_acme_20260920T140000Z_g4711".into(),
        stage,
        epoch_target: None,
        opened_at: now_ms(),
        closed_at: None,
        closed_by: None,
        items: Vec::new(),
        notes: Vec::new(),
        replay_floor_ms: None,
        replay_floor_source: None,
        approval_floor: None,
        gap_events: None,
    }
}

/// A record stuck at Opened has nothing unreviewed only because nothing was listed. Closing it would
/// append `recovery.reconciled`, the key the hold lift waits for, and every later boot would resume
/// a closed record, so the restored sessions, approvals and enrolment codes would never be invalidated.
#[tokio::test]
async fn a_reconciliation_whose_invalidation_never_finished_cannot_be_closed() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    let stale = Session {
        class: Default::default(),
        opened_by: None,
        id: "sess_restored".into(),
        agent_id: "codex-cli".into(),
        user_id: None,
        device_id: None,
        token: "tok_restored".into(),
        role: SessionRole::Operator,
        created_at: 0,
        revoked: false,
        expires_at: None,
        last_used_at: None,
        actor: None,
    };
    store.put_session(stale).unwrap();
    reconcile::save(store.as_ref(), &record_at(Stage::Opened)).unwrap();

    let resp = app(&state)
        .oneshot(request("GET", "/v1/recovery/reconciliation", &operator_jwt(), Value::Null))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["unreviewed"], json!(0), "precondition: nothing is listed, so nothing is unreviewed");

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/close", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert!(body["error"].as_str().unwrap_or_default().contains("invalidat"), "{body}");
    assert_eq!(state.service.reconciliation().unwrap().unwrap().stage, Stage::Opened, "still open");
    assert!(
        !recovery_actions(store.as_ref()).contains(&"recovery.reconciled".to_string()),
        "and nothing the hold lift reads was recorded"
    );

    // The retry the refusal is waiting for still runs, and only then can the owner close.
    reconcile::run_at_boot(&state.service).unwrap().expect("the invalidation runs again from the top");
    assert!(store.get_session("sess_restored").unwrap().is_none(), "the restored session is gone");
    assert_eq!(state.service.reconciliation().unwrap().unwrap().stage, Stage::Reviewing);
}

/// The other side: a record that reached Reviewing closes once nothing is unreviewed, even when the
/// restore listed nothing at all.
#[tokio::test]
async fn a_reviewing_reconciliation_with_nothing_unreviewed_closes() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let state = worker(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json")))).await;
    reconcile::save(store.as_ref(), &record_at(Stage::Reviewing)).unwrap();

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/close", &operator_jwt(), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["state"], json!("closed"));
    assert_eq!(state.service.reconciliation().unwrap().unwrap().stage, Stage::Closed);
    assert_eq!(
        recovery_actions(store.as_ref()).iter().filter(|a| *a == "recovery.reconciled").count(),
        1
    );
}

// ── reconciliation reads the retained generation the hold pins ───────────────────────

/// A holds bucket that keeps every version of every object, as the real holds bucket does
/// (noncurrent versions retained), so the generation a hold pins is still readable after a later
/// write.
#[derive(Default)]
struct VersionedHolds {
    versions: std::sync::Mutex<std::collections::HashMap<String, Vec<(u64, Vec<u8>, BTreeMap<String, String>)>>>,
    next: std::sync::Mutex<u64>,
}

impl VersionedHolds {
    fn put(&self, name: &str, bytes: &[u8]) -> u64 {
        let current = self.head(name).unwrap().unwrap_or(0);
        match self.put_if_generation(name, bytes, current, &hold_metadata()).unwrap() {
            permaura_gateway::objectstore::PutOutcome::Stored(g) => g,
            other => panic!("{other:?}"),
        }
    }
}

impl ObjectStore for VersionedHolds {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        Ok(self.versions.lock().unwrap().get(name).and_then(|v| v.last()).map(|(g, _, _)| *g))
    }
    fn head_full(&self, name: &str) -> Result<Option<permaura_gateway::objectstore::ObjectHead>, GatewayError> {
        Ok(self.versions.lock().unwrap().get(name).and_then(|v| v.last()).map(|(g, b, m)| {
            permaura_gateway::objectstore::ObjectHead { generation: *g, metadata: m.clone(), size: b.len() as u64, crc32c: String::new() }
        }))
    }
    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        Ok(self.versions.lock().unwrap().get(name).is_some_and(|v| !v.is_empty()))
    }
    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        self.versions
            .lock()
            .unwrap()
            .get(name)
            .and_then(|v| v.iter().find(|(g, _, _)| *g == generation))
            .map(|(_, b, _)| b.clone())
            .ok_or_else(|| GatewayError::NotFound(format!("{name} has no generation {generation}")))
    }
    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<permaura_gateway::objectstore::PutOutcome, GatewayError> {
        let live = self.head(name)?.unwrap_or(0);
        if live != expected {
            return Ok(permaura_gateway::objectstore::PutOutcome::Conflict);
        }
        let mut next = self.next.lock().unwrap();
        *next = if *next == 0 { 1_760_400_000_000_000 } else { *next + 1_000 };
        let g = *next;
        self.versions.lock().unwrap().entry(name.to_string()).or_default().push((g, bytes.to_vec(), metadata.clone()));
        Ok(permaura_gateway::objectstore::PutOutcome::Stored(g))
    }
    fn describe(&self) -> String {
        "versioned-holds".into()
    }
}

/// How the hold written by restore-tenant.sh names the retained record it was planned against.
#[derive(Clone, Copy)]
enum Pin {
    /// `retained_ref.generation` is the generation retained.json was at (G1).
    Planned,
    /// `retained_ref.generation` is null: the restore could not read one.
    Nothing,
    /// A generation the bucket does not hold.
    Missing,
    /// `0`: restore-tenant.sh could read no retained record when it planned the restore.
    NoneAtPlanning,
}

/// The restore as restore-tenant.sh plans it: retained.json at G1 (`device_signed`, abandoned head
/// 100987, the `retained-floors.json` fixture), and a hold naming it per `pin`. With
/// `checkpoint_after_promotion`, the next checkpoint-job pass then rewrites retained.json (G2) from
/// the promoted snapshot's stamps.
fn pinned_holds(pin: Pin, checkpoint_after_promotion: bool) -> (Arc<VersionedHolds>, u64, Option<u64>) {
    let holds = Arc::new(VersionedHolds::default());
    let g1 = holds.put(&retained_object(TENANT), &fixture("retained-floors.json"));
    let mut state: Value = serde_json::from_slice(&fixture("state-held.json")).unwrap();
    state["retained_ref"]["generation"] = match pin {
        Pin::Planned => json!(g1.to_string()),
        Pin::Nothing => Value::Null,
        Pin::Missing => json!("42"),
        Pin::NoneAtPlanning => json!("0"),
    };
    holds.put(&hold_object(TENANT), serde_json::to_vec_pretty(&state).unwrap().as_slice());
    let g2 = checkpoint_after_promotion.then(|| {
        let promoted = json!({
            "hold_version": 1,
            "tenant": TENANT,
            "retained": {
                "approval_floor": "approve",
                "pre_restore_audit_epoch": 0,
                "pre_restore_audit_head_seq": 2,
                "pre_restore_audit_head_hash": Value::Null,
                "pre_restore_commit_seq": 1,
                "refreshed_at": "2026-09-21T03:17:05Z",
                "replay_floor_ms": 1_758_376_682_117i64,
                "revocation_journal_head": Value::Null,
            }
        });
        holds.put(&retained_object(TENANT), serde_json::to_vec_pretty(&promoted).unwrap().as_slice())
    });
    (holds, g1, g2)
}

/// The promoted snapshot: floor `approve`, three audit events (head seq 2), then the restored
/// worker's first reconciliation.
async fn reconcile_pinned(pin: Pin, checkpoint_after_promotion: bool) -> (reconcile::ReconciliationRecord, Option<String>, Value, u64, Option<u64>) {
    let (holds, g1, g2) = pinned_holds(pin, checkpoint_after_promotion);
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    common::isolate_from_the_real_install();
    seed::seed(store.as_ref()).expect("seed");
    for i in 0..3 {
        store.append_audit(permaura_core::AuditPayload::new(format!("a{i}"), "r", "allow")).unwrap();
    }
    store.put_meta(APPROVAL_FLOOR_META, "approve").unwrap();
    let hold = Arc::new(ExecutionHold::open(None, holds.clone(), TENANT, Duration::from_secs(600)).expect("the hold reads"));
    let state = worker(store.clone(), hold).await;
    let record = reconcile::run_at_boot(&state.service).unwrap().expect("reconciles");
    let floor = store.get_meta(APPROVAL_FLOOR_META).unwrap();
    let restored = recovery_event(store.as_ref(), "recovery.restored");
    (record, floor, restored, g1, g2)
}

/// A checkpoint pass between the promotion and the first reconciliation must not
/// change what reconciliation concludes, because the hold pins G1.
#[tokio::test]
async fn reconciliation_reads_the_retained_generation_the_hold_pins() {
    let (record, floor, restored, g1, g2) = reconcile_pinned(Pin::Planned, true).await;
    assert_ne!(Some(g1), g2);
    assert_eq!(
        (record.approval_floor.as_deref(), floor.as_deref(), record.gap_events),
        (Some("device_signed"), Some("device_signed"), Some(100_985)),
        "reconciliation used the retained record at G2, not the G1 its hold pins"
    );
    assert_eq!(restored["summary"]["source_generation"], json!(g1.to_string()));
    assert_eq!(restored["summary"]["retained_generation"], json!(g1.to_string()), "the chain names the generation actually read");
    assert_eq!(restored["summary"]["retained_chosen"], json!("pinned"));
    assert_eq!(restored["summary"]["gap_events"], json!(100_985));
}

/// The control: the same restore with no checkpoint pass in between.
#[tokio::test]
async fn without_a_later_checkpoint_the_pinned_record_is_honoured() {
    let (record, floor, restored, g1, _) = reconcile_pinned(Pin::Planned, false).await;
    assert_eq!(
        (record.approval_floor.as_deref(), floor.as_deref(), record.gap_events),
        (Some("device_signed"), Some("device_signed"), Some(100_985))
    );
    assert_eq!(restored["summary"]["retained_generation"], json!(g1.to_string()));
    assert_eq!(restored["summary"]["retained_chosen"], json!("pinned"));
}

/// A hold that pins nothing is the one case that reads the newest version, and the chain and the
/// notes say that is what happened.
#[tokio::test]
async fn a_hold_that_pins_no_generation_reads_the_newest_and_says_so() {
    let (record, _, restored, _, g2) = reconcile_pinned(Pin::Nothing, true).await;
    let g2 = g2.expect("rewritten");
    assert_eq!(restored["summary"]["retained_generation"], json!(g2.to_string()));
    assert_eq!(restored["summary"]["retained_chosen"], json!("newest"));
    assert_eq!(record.approval_floor.as_deref(), Some("approve"), "the newest says approve, and a floor is never lowered or invented");
    assert!(
        record.notes.iter().any(|n| n.contains("pins no generation")),
        "the owner is told the newest was read: {:?}",
        record.notes
    );
}

/// A pinned generation the bucket cannot produce is never replaced by the newest, which can only have
/// been written after the restore was planned: the restore goes ahead with no retained record, and
/// says so rather than reporting a gap of zero. The floor that record carried is unknown, so it is
/// raised rather than left at whatever the promoted snapshot held.
#[tokio::test]
async fn a_pinned_generation_that_cannot_be_read_is_not_replaced_by_the_newest() {
    let (record, floor, restored, _, _) = reconcile_pinned(Pin::Missing, false).await;
    assert_eq!(restored["summary"]["retained_generation"], Value::Null);
    assert_eq!(restored["summary"]["retained_chosen"], json!("pinned"));
    assert_eq!(restored["summary"]["gap_events"], json!("unknown"));
    assert_eq!(record.gap_events, None);
    assert_eq!(floor.as_deref(), Some("device_signed"), "an unreadable record's floor is unknown, so the restore raises rather than keeps the snapshot's approve");
    assert!(
        record.notes.iter().any(|n| n.contains("generation 42")),
        "the owner is told which generation could not be read: {:?}",
        record.notes
    );
}

/// The pin names a generation that is gone while a later checkpoint wrote a newer version reading `approve`. The newer one is not read, the owner's `device_signed` from the planned record is not lost, and no note says the floor was never stamped.
#[tokio::test]
async fn an_unreadable_pinned_generation_keeps_the_device_signed_raise() {
    let (record, floor, restored, _, g2) = reconcile_pinned(Pin::Missing, true).await;
    assert!(g2.is_some());
    assert_eq!(restored["summary"]["retained_generation"], Value::Null, "the later checkpoint is not read: {restored}");
    assert_ne!(record.gap_events, Some(0));
    assert_eq!(record.approval_floor.as_deref(), Some("device_signed"), "{:?}", record.notes);
    assert_eq!(floor.as_deref(), Some("device_signed"));
    assert!(record.notes.iter().any(|n| n.contains("could not be read")), "{:?}", record.notes);
    assert!(
        record.notes.iter().any(|n| n.contains("approval floor") && n.contains("unknown") && n.contains("raised")),
        "the floor note says the record was unreadable and the floor was raised: {:?}",
        record.notes
    );
    assert!(
        !record.notes.iter().any(|n| n.contains("no gateway ever stamped")),
        "an unreadable record is not an unstamped one: {:?}",
        record.notes
    );
}

/// The control: a restore planned with no retained record at all keeps the snapshot's floor, since there was nothing to raise to.
#[tokio::test]
async fn a_restore_planned_with_no_record_does_not_raise_the_floor() {
    let (_, floor, _, _, _) = reconcile_pinned(Pin::NoneAtPlanning, false).await;
    assert_eq!(floor.as_deref(), Some("approve"));
}

/// A restore planned when no retained record could be read pins `0`, and a record that appeared since
/// (a checkpoint's rewrite from the promoted snapshot) is not taken as the account it was planned against.
#[tokio::test]
async fn a_restore_planned_with_no_retained_record_does_not_adopt_one_written_since() {
    let (record, floor, restored, _, _) = reconcile_pinned(Pin::NoneAtPlanning, true).await;
    assert_eq!(restored["summary"]["retained_generation"], Value::Null);
    assert_eq!(restored["summary"]["retained_chosen"], json!("pinned"));
    assert_eq!(restored["summary"]["gap_events"], json!("unknown"), "never a gap of zero read off the promoted state");
    assert_eq!(floor.as_deref(), Some("approve"));
    assert!(
        record.notes.iter().any(|n| n.contains("could read no")),
        "the owner is told the restore had no retained record: {:?}",
        record.notes
    );
}

/// Bind a connector OAuth dance to `connection_id` as `start` would and return its `state`; `start` itself
/// is a session-authed route a restored worker has no session for.
fn start_dance(state: &AppState, connection_id: &str) -> String {
    let connection = state.service.store().get_connection(connection_id).unwrap().expect("the connection");
    let initiator = Session { id: "sess_dance".into(), role: SessionRole::Operator, ..agent_session(state.service.store().as_ref()) };
    let binding = permaura_gateway::oauth_connect::PendingBinding::capture(&state.service, &connection, &initiator, false).unwrap();
    let token = permaura_gateway::oauth_connect::random_token();
    state.oauth_pending.insert(
        token.clone(),
        permaura_gateway::oauth_connect::PendingAuth {
            connection_id: connection_id.into(),
            provider: connection.connector.clone(),
            client_id: "synthetic-client".into(),
            client_secret: "synthetic-client-secret".into(),
            redirect_uri: "http://127.0.0.1:7376/oauth/callback".into(),
            token_url: "https://provider.permaura.test/token".into(),
            code_verifier: None,
            scopes: vec![],
            created_ms: now_ms(),
            binding,
        },
        now_ms(),
    );
    token
}

async fn complete_dance(state: &AppState, token: &str) -> String {
    let resp = app(state)
        .oneshot(Request::builder().uri(format!("/oauth/callback?code=synthetic-code&state={token}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}

/// A restored connection removed in review is removed for an OAuth dance outstanding against it too: its
/// callback is refused even once the exported connection is imported again with its creation stamp.
#[tokio::test]
async fn a_dance_outstanding_across_a_reconciliation_removal_and_reimport_is_refused() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let http = Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let state = worker_with_http(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json"))), http.clone()).await;
    reconcile::run_at_boot(&state.service).expect("the restore reconciles");
    let record = state.service.reconciliation().unwrap().unwrap();
    let id = record.items.iter().find(|i| i.kind == ReviewKind::Connection).expect("a restored connection").id.clone();
    let exported = store.get_connection(&id).unwrap().unwrap();
    let before = store.get_secret(&exported.secret_id).unwrap().map(|s| s.sealed);
    http.push_response(permaura_gateway::connectors::HttpResponse::json(
        200,
        json!({ "access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600 }),
    ));
    let dance = start_dance(&state, &id);

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/remove", &operator_jwt(), json!({ "kind": "connection", "id": id })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(store.get_connection(&id).unwrap().is_none());
    let bundle = permaura_gateway::vault_bundle::BundlePayload { connections: vec![exported.clone()], ..Default::default() };
    permaura_gateway::vault_bundle::apply(store.as_ref(), bundle, &Default::default(), |_, _, _| Ok(())).unwrap();
    assert_eq!(store.get_connection(&id).unwrap().unwrap().created_at, exported.created_at);

    let page = complete_dance(&state, &dance).await;
    assert!(page.contains("This authorization is out of date"), "{page}");
    assert_eq!(store.get_secret(&exported.secret_id).unwrap().map(|s| s.sealed), before, "nothing was written");
    assert!(http.requests().is_empty(), "the code is not exchanged");
}

/// A same-app OAuth bundle sealed for `connector`.
fn sealed_oauth_bundle(connector: &str, access: &str) -> permaura_core::SealedSecret {
    let cred = permaura_gateway::oauth_credential::OAuthCredential {
        layer: permaura_gateway::oauth_credential::OAuthLayer::ByoApp,
        provider: connector.into(),
        access_token: access.into(),
        refresh_token: Some("synthetic-refresh".into()),
        expires_at: 0,
        scopes: vec![],
        token_url: "https://provider.permaura.test/token".into(),
        client_id: Some("synthetic-client".into()),
        client_secret: Some("synthetic-client-secret".into()),
    };
    let json = permaura_gateway::oauth_connect::to_sealed_json(&cred).unwrap();
    permaura_core::seal(permaura_core::Cipher::Aes256Gcm, permaura_gateway::service::vault_passphrase(), json.as_bytes()).unwrap()
}

/// A restored secret removed in review is a deliberate change to its slot, so a dance outstanding against
/// it is refused even when a bundle for the same app, which the contents comparison admits as a refresh,
/// is in the slot again by the callback.
#[tokio::test]
async fn a_dance_outstanding_across_a_reconciliation_secret_removal_is_refused() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let http = Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let state = worker_with_http(store.clone(), hold(bucket("state-held.json", Some("retained-floors.json"))), http.clone()).await;
    reconcile::run_at_boot(&state.service).expect("the restore reconciles");
    let record = state.service.reconciliation().unwrap().unwrap();
    let connection = store
        .list_connections()
        .unwrap()
        .into_iter()
        .find(|c| record.items.iter().any(|i| i.kind == ReviewKind::Secret && i.id == c.secret_id))
        .expect("a restored connection whose secret is in the list");
    let mut secret = store.get_secret(&connection.secret_id).unwrap().expect("the restored secret");
    secret.sealed = sealed_oauth_bundle(&connection.connector, "synthetic-restored-access");
    store.put_secret(secret.clone()).unwrap();
    http.push_response(permaura_gateway::connectors::HttpResponse::json(
        200,
        json!({ "access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600 }),
    ));
    let dance = start_dance(&state, &connection.id);

    let resp = app(&state)
        .oneshot(request("POST", "/v1/recovery/reconciliation/remove", &operator_jwt(), json!({ "kind": "secret", "id": connection.secret_id })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(store.get_secret(&connection.secret_id).unwrap().is_none());
    let again = permaura_core::SecretRecord { sealed: sealed_oauth_bundle(&connection.connector, "synthetic-later-access"), ..secret };
    store.put_secret(again.clone()).unwrap();

    let page = complete_dance(&state, &dance).await;
    assert!(page.contains("This authorization is out of date"), "{page}");
    assert_eq!(store.get_secret(&connection.secret_id).unwrap().map(|s| s.sealed), Some(again.sealed), "nothing was written");
    assert!(http.requests().is_empty());
}
