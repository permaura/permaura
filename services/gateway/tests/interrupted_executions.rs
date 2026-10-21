//! An approved held call whose gateway stops while it runs is settled on the next boot.
//!
//! On Windows, quitting the desktop app killed the bundled gateway six seconds into an approved
//! call. On relaunch the approval read `pending`, its claim was spent, the chain held an `attempt`
//! and nothing after it, and every approve answered "already claimed". Nothing ever settled it.
//!
//! Each test leaves a store exactly as a dead process leaves it and boots a new service over it.
//! Every credential and transport here is synthetic.
#![cfg(feature = "sqlite")]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse};
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectStore};
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{Session, Store, APPROVAL_UNRESOLVED};

/// An upstream that takes the request and never answers: the process running it is about to die.
#[derive(Default)]
struct Hangs {
    sent: AtomicUsize,
    entered: tokio::sync::Notify,
}

#[async_trait]
impl HttpClient for Hangs {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        std::future::pending::<()>().await;
        unreachable!()
    }
}

/// The upstream the next process is given. Anything that reaches it is a call run a second time.
#[derive(Default)]
struct MustNotRun {
    sent: AtomicUsize,
}

#[async_trait]
impl HttpClient for MustNotRun {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        Ok(HttpResponse::json(201, serde_json::json!({ "number": 8 })))
    }
}

fn temp_db(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("permaura-interrupted-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("gateway.db")
}

/// What a SIGKILL leaves: the file as it stands right now, copied for the next process to open. A copy
/// rather than the same file, because the dying process's store is still held in this test by the task
/// its call hangs in, and a store is opened by one process at a time.
fn what_a_kill_leaves(first: &SqliteStore, path: &str) -> String {
    let dir = std::path::Path::new(path).parent().unwrap().join("next");
    std::fs::create_dir_all(&dir).unwrap();
    let next = dir.join("gateway.db");
    first.snapshot_to(&next).expect("a consistent copy of the store");
    std::fs::copy(format!("{path}.auditkey"), format!("{}.auditkey", next.display())).expect("the audit key goes with it");
    next.to_string_lossy().to_string()
}

fn demo_session(store: &dyn Store) -> Session {
    store.get_session("sess_demo").unwrap().expect("the demo session is seeded")
}

/// Hold a High-risk call and hand back its approval id.
async fn hold(service: &EnforcementService, session: &Session) -> String {
    let held = service
        .invoke(
            session,
            "github.pull_requests.create",
            &serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }),
            Some("synthetic"),
            ExecutionLocation::LocalOnly,
        )
        .await
        .expect("a High-risk capability holds rather than erroring");
    match held {
        InvokeOutcome::RequiresApproval { approval, .. } => approval.id,
        _ => panic!("a High-risk capability must be escalated to a human"),
    }
}

/// Approve on `service`, whose upstream hangs, and return once the call has left the gateway: the
/// claim is spent and the `attempt` is committed, which is the moment the desktop quit landed.
async fn approve_until_it_is_running(service: EnforcementService, http: &Hangs, approval_id: &str) {
    let id = approval_id.to_string();
    tokio::spawn(async move {
        let _ = service.resolve_approval(&id, true, "bearer", Some("operator:synthetic")).await;
    });
    tokio::time::timeout(Duration::from_secs(10), http.entered.notified())
        .await
        .expect("the approved call reached the upstream");
}

/// `(decision, summary)` of every event naming `approval_id`, in chain order.
fn events_naming(store: &dyn Store, approval_id: &str) -> Vec<(String, serde_json::Value)> {
    store
        .audit_events(None)
        .unwrap()
        .into_iter()
        .filter(|e| e.payload.summary.get("approval_id").and_then(|v| v.as_str()) == Some(approval_id))
        .map(|e| (e.payload.decision.clone(), e.payload.summary.clone()))
        .collect()
}

fn decisions(events: &[(String, serde_json::Value)]) -> Vec<&str> {
    events.iter().map(|(d, _)| d.as_str()).collect()
}

/// The terminal event an interrupted execution is closed with, and the row it leaves.
fn assert_settled_as_interrupted(store: &dyn Store, approval_id: &str) {
    let row = store.get_approval(approval_id).unwrap().unwrap();
    assert_eq!(row.status, APPROVAL_UNRESOLVED, "the row is answered, and not as a denial");
    assert!(row.result.is_none(), "there is no result to claim");
    let events = events_naming(store, approval_id);
    assert_eq!(
        decisions(&events),
        ["requires_approval", "attempt", "error"],
        "the hold, the one fence, then exactly one terminal event: {events:?}"
    );
    let (_, terminal) = &events[2];
    assert_eq!(terminal["outcome"], "unknown", "the call may have landed: {terminal}");
    assert_eq!(terminal["error_kind"], "interrupted", "{terminal}");
    assert_eq!(terminal["ok"], false);
    let (_, attempt) = &events[1];
    for key in ["method", "approver", "grant_id", "policy_id"] {
        assert_eq!(terminal[key], attempt[key], "{key} is carried from the attempt: {terminal}");
    }
    assert!(store.verify_audit().is_ok(), "the chain still verifies");
}

/// The same failure on a self-run gateway's SQLite store: the process dies mid-call and the next one
/// settles the approval as unresolved, outcome unknown, without running anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approval_interrupted_mid_call_is_settled_as_unresolved_on_the_next_boot_and_never_rerun() {
    common::isolate_from_the_real_install();
    let path = temp_db("sqlite");
    let path = path.to_string_lossy().to_string();

    let held = Arc::new(SqliteStore::open(&path).unwrap());
    let first: Arc<dyn Store> = held.clone();
    permaura_gateway::seed::seed(first.as_ref()).unwrap();
    let hangs = Arc::new(Hangs::default());
    let running = EnforcementService::new(first.clone(), hangs.clone());
    let approval_id = hold(&running, &demo_session(first.as_ref())).await;
    approve_until_it_is_running(running, &hangs, &approval_id).await;

    // What a SIGKILL leaves: the file as it stands right now. The first process never runs again.
    let after: Arc<dyn Store> = Arc::new(SqliteStore::open(&what_a_kill_leaves(&held, &path)).unwrap());
    assert_eq!(after.get_approval(&approval_id).unwrap().unwrap().status, "pending");
    assert_eq!(decisions(&events_naming(after.as_ref(), &approval_id)), ["requires_approval", "attempt"]);
    let next_upstream = Arc::new(MustNotRun::default());
    let next = EnforcementService::new(after.clone(), next_upstream.clone());

    // Before the settlement this is exactly the stuck state the desktop quit left.
    let refused = next.resolve_approval(&approval_id, true, "bearer", Some("operator:synthetic")).await;
    assert!(
        matches!(&refused, Err(e) if e.to_string().contains("already claimed")),
        "{refused:?}"
    );

    let report = next.settle_interrupted_approvals(Duration::ZERO, u64::MAX).unwrap();
    assert_eq!(report.interrupted, vec![approval_id.clone()], "{report:?}");
    assert!(report.reconciled.is_empty() && report.deferred == 0, "{report:?}");
    assert_settled_as_interrupted(after.as_ref(), &approval_id);

    // Approving again reads the settled approval back and runs nothing.
    let again = next.resolve_approval(&approval_id, true, "bearer", Some("operator:synthetic")).await.unwrap();
    assert_eq!(again.status, APPROVAL_UNRESOLVED);
    assert_eq!(next_upstream.sent.load(Ordering::SeqCst), 0, "the held call is never run again");
    assert_eq!(hangs.sent.load(Ordering::SeqCst), 1, "it was sent exactly once, by the process that died");

    // A second pass, as the next boot after this one would make, changes nothing.
    let again = next.settle_interrupted_approvals(Duration::ZERO, u64::MAX).unwrap();
    assert_eq!(again, Default::default());
    assert_eq!(events_naming(after.as_ref(), &approval_id).len(), 3);
}

/// A hosted worker: the instance is replaced mid-call, the next one restores the snapshot from the
/// bucket, and the settlement it writes is what the bucket holds afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hosted_instance_replaced_mid_call_is_settled_from_the_restored_snapshot() {
    common::isolate_from_the_real_install();
    let objects: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
    let open = |tag: &str, stale: Arc<AtomicBool>| -> PersistedSqliteStore {
        PersistedSqliteStore::open(&temp_db(tag).to_string_lossy(), objects.clone(), DEFAULT_OBJECT, None)
            .unwrap()
            .with_on_stale(Box::new(move |_| stale.store(true, Ordering::SeqCst)))
    };

    let replaced_was_told = Arc::new(AtomicBool::new(false));
    let replaced: Arc<dyn Store> = Arc::new(open("replaced", replaced_was_told.clone()));
    permaura_gateway::seed::seed(replaced.as_ref()).unwrap();
    let hangs = Arc::new(Hangs::default());
    let running = EnforcementService::new(replaced.clone(), hangs.clone());
    let approval_id = hold(&running, &demo_session(replaced.as_ref())).await;
    approve_until_it_is_running(running, &hangs, &approval_id).await;

    // The replacement restores what the bucket holds: the attempt went up before the call went out.
    let next_was_told = Arc::new(AtomicBool::new(false));
    let restored: Arc<dyn Store> = Arc::new(open("restored", next_was_told.clone()));
    assert_eq!(decisions(&events_naming(restored.as_ref(), &approval_id)), ["requires_approval", "attempt"]);
    let next_upstream = Arc::new(MustNotRun::default());
    let next = EnforcementService::new(restored.clone(), next_upstream.clone());

    // An attempt younger than the bound may still be running on the instance being replaced, so it waits.
    let early = next.settle_interrupted_approvals(Duration::from_secs(3600), u64::MAX).unwrap();
    assert_eq!(early.deferred, 1, "{early:?}");
    assert!(early.retry_in.is_some_and(|d| d > Duration::from_secs(3000)), "{early:?}");
    assert_eq!(restored.get_approval(&approval_id).unwrap().unwrap().status, "pending");
    assert_eq!(events_naming(restored.as_ref(), &approval_id).len(), 2, "nothing is written while it waits");

    let report = next.settle_interrupted_approvals(Duration::ZERO, u64::MAX).unwrap();
    assert_eq!(report.interrupted, vec![approval_id.clone()], "{report:?}");
    assert!(!next_was_told.load(Ordering::SeqCst), "the restored instance owns the store");
    assert_eq!(next_upstream.sent.load(Ordering::SeqCst), 0);

    // Durable, not just local: a third instance restoring from the bucket reads the settlement.
    let third: Arc<dyn Store> = Arc::new(open("third", Arc::new(AtomicBool::new(false))));
    assert_settled_as_interrupted(third.as_ref(), &approval_id);
}

/// A process whose runtime was torn down mid-call (the drain window ran out, then the process exited)
/// records the terminal event from the execution's own guard but never writes the row. The next boot
/// makes the row say what the chain says and appends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_left_pending_behind_a_recorded_ending_is_brought_into_line_with_the_chain() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let hangs = Arc::new(Hangs::default());
    let approval_id = {
        let service = EnforcementService::new(store.clone(), hangs.clone());
        hold(&service, &demo_session(store.as_ref())).await
    };

    // The dying process: its own runtime, shut down while the call is in flight.
    {
        let store = store.clone();
        let hangs = hangs.clone();
        let approval_id = approval_id.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            runtime.block_on(async {
                let service = EnforcementService::new(store, hangs.clone());
                approve_until_it_is_running(service, &hangs, &approval_id).await;
            });
            drop(runtime);
        })
        .join()
        .unwrap();
    }
    let events = events_naming(store.as_ref(), &approval_id);
    assert_eq!(decisions(&events), ["requires_approval", "attempt", "error"], "{events:?}");
    assert_eq!(events[2].1["error_kind"], "abandoned", "the execution's guard wrote this one: {:?}", events[2]);
    assert_eq!(store.get_approval(&approval_id).unwrap().unwrap().status, "pending", "and nothing wrote the row");

    let next = EnforcementService::new(store.clone(), Arc::new(MustNotRun::default()));
    let report = next.settle_interrupted_approvals(Duration::ZERO, u64::MAX).unwrap();
    assert_eq!(report.reconciled, vec![approval_id.clone()], "{report:?}");
    assert!(report.interrupted.is_empty(), "{report:?}");
    assert_eq!(store.get_approval(&approval_id).unwrap().unwrap().status, APPROVAL_UNRESOLVED);
    assert_eq!(events_naming(store.as_ref(), &approval_id).len(), 3, "the chain already said how it ended");
}

/// An approval this process is resolving right now has an `attempt` and no ending because it has not
/// ended. The settlement must leave it to finish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_execution_this_process_is_still_running_is_never_settled() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let hangs = Arc::new(Hangs::default());
    let service = EnforcementService::new(store.clone(), hangs.clone());
    let approval_id = hold(&service, &demo_session(store.as_ref())).await;
    // The chain's length when this process began serving, which is what `permaura start` reads.
    let recorded_before = store.audit_events(Some(1)).unwrap().last().map_or(0, |e| e.seq + 1);
    approve_until_it_is_running(service.clone(), &hangs, &approval_id).await;

    let report = service.settle_interrupted_approvals(Duration::ZERO, u64::MAX).unwrap();
    assert_eq!(report, Default::default(), "it is running here");
    // The boundary protects it without the in-flight set: its `attempt` was recorded after it.
    let unaware = EnforcementService::new(store.clone(), Arc::new(MustNotRun::default()));
    let report = unaware.settle_interrupted_approvals(Duration::ZERO, recorded_before).unwrap();
    assert_eq!(report, Default::default(), "recorded by this process, so not one an earlier process owed");
    assert_eq!(store.get_approval(&approval_id).unwrap().unwrap().status, "pending");
    assert_eq!(decisions(&events_naming(store.as_ref(), &approval_id)), ["requires_approval", "attempt"]);
}

/// A gateway that has begun to drain refuses an approve before it spends the claim, so the approval
/// is still pending and the next process can run it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approve_a_draining_gateway_refuses_is_still_pending_for_the_next_process() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let draining_upstream = Arc::new(MustNotRun::default());
    let draining = EnforcementService::new(store.clone(), draining_upstream.clone());
    let approval_id = hold(&draining, &demo_session(store.as_ref())).await;
    draining.begin_drain();

    let refused = draining.resolve_approval(&approval_id, true, "bearer", Some("operator:synthetic")).await;
    match refused {
        Err(permaura_gateway::error::GatewayError::TooManyRequests { reason, retry_after_secs, .. }) => {
            assert_eq!(reason, permaura_gateway::drain::DRAINING_REASON);
            assert!(retry_after_secs > 0);
        }
        other => panic!("a draining gateway refuses the approve: {other:?}"),
    }
    let invoked = draining
        .invoke(
            &demo_session(store.as_ref()),
            "github.pull_requests.list",
            &serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }),
            Some("synthetic"),
            ExecutionLocation::LocalOnly,
        )
        .await;
    assert!(matches!(invoked, Err(permaura_gateway::error::GatewayError::TooManyRequests { .. })), "{:?}", invoked.err());
    assert_eq!(draining_upstream.sent.load(Ordering::SeqCst), 0);
    assert_eq!(store.get_approval(&approval_id).unwrap().unwrap().status, "pending");
    assert_eq!(decisions(&events_naming(store.as_ref(), &approval_id)), ["requires_approval"]);

    let next_upstream = Arc::new(MustNotRun::default());
    let next = EnforcementService::new(store.clone(), next_upstream.clone());
    let approved = next.resolve_approval(&approval_id, true, "bearer", Some("operator:synthetic")).await.unwrap();
    assert_eq!(approved.status, "approved");
    assert_eq!(next_upstream.sent.load(Ordering::SeqCst), 1);
}

/// A plain call whose process dies after sending it and before recording its answer leaves its `attempt` alone in the chain; the next boot closes it as interrupted and charges it to its grant, so a crash cannot hand budget back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_a_dying_process_cut_off_is_closed_and_charged_on_the_next_boot() {
    common::isolate_from_the_real_install();
    let path = temp_db("invoke");
    let path = path.to_string_lossy().to_string();

    let held = Arc::new(SqliteStore::open(&path).unwrap());
    let first: Arc<dyn Store> = held.clone();
    permaura_gateway::seed::seed(first.as_ref()).unwrap();
    let hangs = Arc::new(Hangs::default());
    let running = EnforcementService::new(first.clone(), hangs.clone());
    let session = demo_session(first.as_ref());
    tokio::spawn(async move {
        let _ = running
            .invoke(&session, "github.pull_requests.list", &serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }), None, ExecutionLocation::LocalOnly)
            .await;
    });
    tokio::time::timeout(Duration::from_secs(10), hangs.entered.notified()).await.expect("the call reached the upstream");

    let after: Arc<dyn Store> = Arc::new(SqliteStore::open(&what_a_kill_leaves(&held, &path)).unwrap());
    let attempt = after.audit_events(None).unwrap().into_iter().rev().find(|e| e.payload.decision == "attempt").expect("the fence");
    let execution_id = attempt.payload.summary["execution_id"].as_str().expect("an invoke's attempt names its execution").to_string();
    let grant_id = attempt.payload.summary["grant_id"].as_str().expect("the call ran on a grant").to_string();
    let windows = [permaura_gateway::store::GrantWindow { grant_id: &grant_id, since_ms: i64::MIN }];
    let spent_before = after.read_grant_usage(&windows).unwrap().total(&grant_id);
    let next = EnforcementService::new(after.clone(), Arc::new(MustNotRun::default()));

    let own = next.settle_interrupted_invokes(Duration::ZERO, attempt.seq).unwrap();
    assert!(own.invokes.is_empty(), "an attempt this process recorded is its own to close: {own:?}");
    let early = next.settle_interrupted_invokes(Duration::from_secs(3600), u64::MAX).unwrap();
    assert_eq!((early.invokes.len(), early.deferred), (0, 1), "too recent to be another process's: {early:?}");

    let report = next.settle_interrupted_invokes(Duration::ZERO, u64::MAX).unwrap();
    assert_eq!(report.invokes, vec![execution_id.clone()], "{report:?}");
    let closing: Vec<_> = after
        .audit_events(None)
        .unwrap()
        .into_iter()
        .filter(|e| e.payload.summary["execution_id"] == execution_id.as_str())
        .collect();
    assert_eq!(closing.iter().map(|e| e.payload.decision.as_str()).collect::<Vec<_>>(), ["attempt", "error"]);
    let terminal = &closing[1].payload.summary;
    assert_eq!(terminal["outcome"], "unknown", "{terminal}");
    assert_eq!(terminal["error_kind"], "interrupted", "{terminal}");
    assert_eq!(terminal["grant_id"], grant_id.as_str(), "{terminal}");
    assert_eq!(after.read_grant_usage(&windows).unwrap().total(&grant_id), spent_before + 1, "the cut-off call is charged");
    assert_eq!(
        after.count_grant_usage(&windows).unwrap().total(&grant_id),
        after.read_grant_usage(&windows).unwrap().total(&grant_id),
        "and a scan of the chain agrees with the counter"
    );
    assert!(after.verify_audit().is_ok());

    let again = next.settle_interrupted_invokes(Duration::ZERO, u64::MAX).unwrap();
    assert_eq!(again, Default::default(), "a second boot changes nothing");
    assert_eq!(hangs.sent.load(Ordering::SeqCst), 1, "it was sent exactly once, by the process that died");
}

async fn post(app: &axum::Router, uri: &str, body: serde_json::Value) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", permaura_gateway::seed::DEMO_TOKEN))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

/// A connection with a credential, a read policy and a `max_calls` total grant for the seeded agent on a SQLite store at `path`, whose one call the upstream takes and never answers: the process running it is about to die. Returns the capability, the grant, the upstream, and the path of what the process's death leaves ([`what_a_kill_leaves`]).
async fn one_call_cut_off(path: &str, max_calls: u64) -> (String, String, Arc<Hangs>, String) {
    let held = Arc::new(SqliteStore::open(path).unwrap());
    let store: Arc<dyn Store> = held.clone();
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let hangs = Arc::new(Hangs::default());
    let state = permaura_gateway::AppState::from_parts(store, hangs.clone());
    let app = permaura_gateway::build_router(state, "127.0.0.1:7376".parse().unwrap());
    let (_s, conn) = post(&app, "/v1/connections", serde_json::json!({ "connector": "github", "name": "Budget GitHub" })).await;
    let connection_id = conn["connection_id"].as_str().unwrap().to_string();
    let (s, _) = post(&app, &format!("/v1/connections/{connection_id}/credential"), serde_json::json!({ "value": "ghp_budget_0123456789" })).await;
    assert!(s.is_success(), "{s}");
    let (_s, pol) =
        post(&app, "/v1/policies", serde_json::json!({ "connection_id": connection_id, "name": "ro", "allow": ["pull_requests.list"] })).await;
    let (s, grant) = post(
        &app,
        "/v1/grants",
        serde_json::json!({ "policy_id": pol["policy_id"], "target_agent": "codex-cli", "max_calls": max_calls, "period": "total" }),
    )
    .await;
    assert_eq!(s, axum::http::StatusCode::CREATED, "{grant}");
    let capability = format!("{connection_id}.pull_requests.list");
    let call = serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } });
    tokio::spawn(async move {
        let _ = post(&app, "/v1/invoke", call).await;
    });
    tokio::time::timeout(Duration::from_secs(10), hangs.entered.notified()).await.expect("the call reached the upstream");
    let left = what_a_kill_leaves(&held, path);
    (capability, grant["grant_id"].as_str().unwrap().to_string(), hangs, left)
}

/// The next process over what the last one left, with an upstream that counts what reaches it, booted as `permaura start` boots it up to the point it serves: the audit head read and the unfinished calls' budget held.
fn next_boot(path: &str) -> (permaura_gateway::AppState, axum::Router, Arc<MustNotRun>, u64) {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(path).unwrap());
    let upstream = Arc::new(MustNotRun::default());
    let state = permaura_gateway::AppState::from_parts(store.clone(), upstream.clone());
    let recorded_before = store.audit_events(Some(1)).unwrap().last().map_or(0, |e| e.seq + 1);
    assert_eq!(state.service.carry_interrupted_budget(recorded_before).unwrap(), 1, "one call was left unfinished");
    let app = permaura_gateway::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    (state, app, upstream, recorded_before)
}

/// Across a restart: a `max_calls: 1` grant's one call is sent and the process dies before recording it. The reservation died with the process and the settlement that charges the attempt waits ten seconds after boot, so a retry in that window read nothing spent and reached the upstream a second time. The next boot now holds that call's budget before it serves, and the settlement turns the hold into the charge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_a_crash_cut_off_holds_its_budget_from_the_next_boot_until_it_is_charged() {
    common::isolate_from_the_real_install();
    let path = temp_db("budget-across-restart").to_string_lossy().to_string();
    let (capability, grant_id, hangs, left) = one_call_cut_off(&path, 1).await;
    let (state, app, upstream, recorded_before) = next_boot(&left);
    let call = serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } });

    let (s, body) = post(&app, "/v1/invoke", call.clone()).await;
    assert_ne!(s, axum::http::StatusCode::OK, "{body}");
    assert_eq!(upstream.sent.load(Ordering::SeqCst), 0, "a retry inside the settlement window reached the upstream past max_calls");

    let report = state.service.settle_interrupted_invokes(Duration::ZERO, recorded_before).unwrap();
    assert_eq!(report.invokes.len(), 1, "{report:?}");
    state.service.release_settled_budget(recorded_before).unwrap();
    let store = state.service.store();
    let windows = [permaura_gateway::store::GrantWindow { grant_id: &grant_id, since_ms: i64::MIN }];
    assert_eq!(store.read_grant_usage(&windows).unwrap().total(&grant_id), 1, "the cut-off call is the one charge");
    assert_eq!(store.count_grant_usage(&windows).unwrap().total(&grant_id), 1, "and the chain agrees");

    let (s, body) = post(&app, "/v1/invoke", call).await;
    assert_ne!(s, axum::http::StatusCode::OK, "{body}");
    assert_eq!(upstream.sent.load(Ordering::SeqCst), 0);
    assert_eq!(hangs.sent.load(Ordering::SeqCst), 1, "the grant's one call was the one the dead process sent");
}

/// The hold is handed back once the charge is in, so a settled call is counted once and not twice: on a `max_calls: 2` grant the next call still runs after the settlement, and the one after it does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settled_call_is_counted_once_and_its_hold_given_back() {
    common::isolate_from_the_real_install();
    let path = temp_db("budget-released").to_string_lossy().to_string();
    let (capability, grant_id, _hangs, left) = one_call_cut_off(&path, 2).await;
    let (state, app, upstream, recorded_before) = next_boot(&left);
    let call = serde_json::json!({ "capability": capability, "params": { "repo": "synthetic/app" } });

    state.service.settle_interrupted_invokes(Duration::ZERO, recorded_before).unwrap();
    state.service.release_settled_budget(recorded_before).unwrap();
    let (s, body) = post(&app, "/v1/invoke", call.clone()).await;
    assert_eq!(s, axum::http::StatusCode::OK, "the second of two calls runs: {body}");
    let (s, body) = post(&app, "/v1/invoke", call).await;
    assert_ne!(s, axum::http::StatusCode::OK, "{body}");
    assert_eq!(upstream.sent.load(Ordering::SeqCst), 1);
    let windows = [permaura_gateway::store::GrantWindow { grant_id: &grant_id, since_ms: i64::MIN }];
    assert_eq!(state.service.store().read_grant_usage(&windows).unwrap().total(&grant_id), 2);
}
