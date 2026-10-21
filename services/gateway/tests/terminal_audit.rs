//! Every pre-execution `"attempt"` is followed by exactly one terminal event.
//!
//! Hosted recovery and the archive design both read the chain
//! on that assumption. It once held only when the execution returned a result: an
//! upstream failure, the execution ceiling, an oversize response or a dropped request left the
//! `"attempt"` standing alone, so a reader could not tell a call that never finished from one that
//! was never recorded.
//!
//! Every credential and transport here is synthetic.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use permaura_core::ExecutionLocation;
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse};
use permaura_gateway::error::GatewayError;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::{Session, Store};

mod common;

/// An upstream that takes the request and then loses it. The gateway cannot know whether the far
/// side acted on it, which is the whole case the terminal event exists to state honestly.
struct LosesTheAnswer {
    sent: AtomicUsize,
}

#[async_trait]
impl HttpClient for LosesTheAnswer {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("synthetic transport failure after the request was sent")
    }
}

/// An upstream that answers, eventually. Long enough that a caller with a short patience gives up
/// first, short enough that a test can wait for it.
struct SlowUpstream {
    delay: Duration,
    answered: AtomicUsize,
}

#[async_trait]
impl HttpClient for SlowUpstream {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        tokio::time::sleep(self.delay).await;
        self.answered.fetch_add(1, Ordering::SeqCst);
        Ok(HttpResponse::json(200, serde_json::json!({ "pulls": [] })))
    }
}

/// The seeded estate, an agent session, and whatever HTTP client the test wants behind it.
fn seeded(http: Arc<dyn HttpClient>) -> (Arc<dyn Store>, EnforcementService, Session) {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).expect("the demo estate seeds");
    let session = store.get_session("sess_demo").unwrap().expect("the demo session is seeded");
    let service = EnforcementService::new(store.clone(), http);
    (store, service, session)
}

fn params() -> serde_json::Value {
    serde_json::json!({ "owner": "synthetic", "repo": "synthetic" })
}

/// `(attempt events, terminal events)` for the whole chain. A terminal event is an `"allow"` or an
/// `"error"`; the decisions that never reach the fence (`deny`, `requires_approval`) are neither.
fn chain(store: &Arc<dyn Store>) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let events = store.audit_events(None).unwrap();
    let pick = |wanted: &[&str]| -> Vec<serde_json::Value> {
        events
            .iter()
            .filter(|e| wanted.contains(&e.payload.decision.as_str()))
            .map(|e| {
                let mut v = e.payload.summary.clone();
                v["decision"] = serde_json::Value::String(e.payload.decision.clone());
                v
            })
            .collect()
    };
    (pick(&["attempt"]), pick(&["allow", "error"]))
}

/// A request that was sent and whose answer never arrived leaves the upstream effect genuinely
/// unresolved. Saying "failed" would be a claim about somebody else's ledger that this gateway
/// cannot support.
#[tokio::test]
async fn an_upstream_that_loses_the_answer_records_the_outcome_as_unknown() {
    let http = Arc::new(LosesTheAnswer { sent: AtomicUsize::new(0) });
    let (store, service, session) = seeded(http.clone());

    let result = service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await;
    assert!(matches!(result, Err(GatewayError::Internal(_))), "{:?}", result.err());

    assert_eq!(http.sent.load(Ordering::SeqCst), 1, "the request did leave the gateway");
    let (attempts, terminals) = chain(&store);
    assert_eq!(attempts.len(), 1, "one execution was fenced");
    assert_eq!(terminals.len(), 1, "and exactly one terminal event follows it");
    assert_eq!(terminals[0]["decision"], "error");
    assert_eq!(terminals[0]["outcome"], "unknown");
    assert_eq!(terminals[0]["error_kind"], "internal");
}

/// The other half of the same honesty: when the refusal happened above every transport, the effect
/// certainly did not happen and the chain may say so. A credential that has been deleted is the
/// realistic shape of it.
#[tokio::test]
async fn a_refusal_above_every_transport_records_that_the_effect_did_not_happen() {
    let http = Arc::new(LosesTheAnswer { sent: AtomicUsize::new(0) });
    let (store, service, session) = seeded(http.clone());
    assert!(store.delete_secret("sec_github_acme").unwrap(), "the seeded credential existed");

    let result = service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await;
    assert!(matches!(result, Err(GatewayError::NotFound(_))), "{:?}", result.err());

    assert_eq!(http.sent.load(Ordering::SeqCst), 0, "nothing was sent");
    let (attempts, terminals) = chain(&store);
    assert_eq!(attempts.len(), 1);
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0]["decision"], "error");
    assert_eq!(terminals[0]["outcome"], "refused");
    assert_eq!(terminals[0]["error_kind"], "not_found");
}

/// The cancellation case, and the reason the execution runs in a task of its own.
///
/// The inbound request timeout and a client hanging up both drop the handler's future at an await
/// point. Dropping it must not leave an `"attempt"` with nothing beside it, and must not abandon a
/// request that had already been sent: the call finishes and the chain records what it actually did.
#[tokio::test]
async fn a_caller_that_gives_up_does_not_cancel_the_execution_or_its_record() {
    let http = Arc::new(SlowUpstream {
        delay: Duration::from_millis(300),
        answered: AtomicUsize::new(0),
    });
    let (store, service, session) = seeded(http.clone());

    let gave_up = tokio::time::timeout(
        Duration::from_millis(30),
        service.invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly),
    )
    .await;
    assert!(gave_up.is_err(), "the caller must have given up before the upstream answered");

    let (attempts, terminals) = chain(&store);
    assert_eq!(attempts.len(), 1, "the fence is already in the chain");
    assert!(terminals.is_empty(), "and the execution is still running");

    // Drive the runtime past the upstream's delay. The task was spawned, not awaited, so this is the
    // only thing standing between the dropped request and its record.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(http.answered.load(Ordering::SeqCst), 1, "the execution ran to completion");
    let (attempts, terminals) = chain(&store);
    assert_eq!(attempts.len(), 1);
    assert_eq!(terminals.len(), 1, "exactly one terminal event, written after the caller left");
    assert_eq!(terminals[0]["decision"], "allow");
    assert_eq!(terminals[0]["status"], 200);
}

/// The success path is what every other test in the suite already asserts, so it is here only to
/// pin the pairing: one `"attempt"`, one `"allow"`, and nothing extra from the task boundary.
#[tokio::test]
async fn a_successful_execution_still_records_exactly_one_allow() {
    let http = Arc::new(SlowUpstream {
        delay: Duration::from_millis(1),
        answered: AtomicUsize::new(0),
    });
    let (store, service, session) = seeded(http.clone());

    service
        .invoke(&session, "github.pull_requests.list", &params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .expect("the upstream answers");

    let (attempts, terminals) = chain(&store);
    assert_eq!(attempts.len(), 1);
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0]["decision"], "allow");
    assert_eq!(terminals[0]["status"], 200);
}

// ── resolve_approval: the same rule on the path a human releases ──────────────────────────────────
//
// The same gap on the path a human releases: `resolve_approval` claims durably, executes,
// and appends `"approved"`. When the execution errored the claim was spent, the upstream may well
// have landed, the approval stayed `pending` and the chain said nothing at all. That is the one
// state an auditor cannot tell apart from a call that was never made, on the one path where a human
// had just said yes.

/// Every terminal event on a held call: an `"approved"` or an `"error"` carrying an approval id.
fn resolutions(store: &Arc<dyn Store>) -> Vec<serde_json::Value> {
    store
        .audit_events(None)
        .unwrap()
        .iter()
        .filter(|e| matches!(e.payload.decision.as_str(), "approved" | "error"))
        .filter(|e| e.payload.summary.get("approval_id").is_some())
        .map(|e| {
            let mut v = e.payload.summary.clone();
            v["decision"] = serde_json::Value::String(e.payload.decision.clone());
            v
        })
        .collect()
}

/// Hold a High-risk call the way the enforcement loop does, and hand back its approval id.
async fn a_held_call(service: &EnforcementService, session: &Session) -> String {
    let held = service
        .invoke(
            session,
            "github.pull_requests.create",
            &params(),
            Some("synthetic"),
            ExecutionLocation::LocalOnly,
        )
        .await
        .expect("a High-risk capability holds rather than erroring");
    match held {
        permaura_gateway::service::InvokeOutcome::RequiresApproval { approval, .. } => approval.id,
        _ => panic!("a High-risk capability must be escalated to a human"),
    }
}

/// The gap this commit closes. A human approves, the held call is executed, the transport loses the
/// answer: the claim is spent and the upstream may have landed, so the chain must say so.
#[tokio::test]
async fn a_held_call_whose_execution_fails_still_records_its_terminal_event() {
    let http = Arc::new(LosesTheAnswer { sent: AtomicUsize::new(0) });
    let (store, service, session) = seeded(http.clone());
    let approval_id = a_held_call(&service, &session).await;

    let err = service
        .resolve_approval(&approval_id, true, "device_signed", Some("apprv_phone"))
        .await
        .expect_err("the transport lost the answer");
    assert!(matches!(err, GatewayError::Internal(_)), "{err:?}");
    assert_eq!(http.sent.load(Ordering::SeqCst), 1, "the request did leave the gateway");

    let terminals = resolutions(&store);
    assert_eq!(terminals.len(), 1, "exactly one terminal event, and there used to be none");
    assert_eq!(terminals[0]["decision"], "error");
    assert_eq!(terminals[0]["approval_id"], approval_id.as_str());
    // Unknown, not refused: something was sent. This is the whole point of the event.
    assert_eq!(terminals[0]["outcome"], "unknown");
    assert_eq!(terminals[0]["error_kind"], "internal");
    // The error's own text is never recorded, on this path as on `invoke`'s.
    assert!(
        terminals[0].get("error").is_none() && terminals[0].get("message").is_none(),
        "the error text must not reach the chain: {}",
        terminals[0]
    );
    // How it was released survives onto the failure event, not only onto the success one.
    assert_eq!(terminals[0]["method"], "device_signed");
    assert_eq!(terminals[0]["approver"], "apprv_phone");
    // The text goes beside the chain instead, where it can be purged.
    assert_eq!(terminals[0]["diagnostic"], true);
    assert_eq!(terminals[0]["ok"], false);
    let kept = store.call_diagnostics(0).unwrap();
    assert_eq!(kept.len(), 1);
    assert!(kept[0].message.contains("synthetic transport failure"), "{}", kept[0].message);
}

/// The state a failed resolution leaves behind, and why it is that one.
///
/// Not `pending`: a question that has in fact been answered would sit on an operator's dashboard
/// forever and the control plane would go on waiting for it. Not `denied`: a denial claims nothing
/// ran, and something may have. Not `approved`: there is no result. And it must not be re-executable
/// by a second approve, which is enforced twice over.
#[tokio::test]
async fn a_failed_resolution_is_terminal_and_cannot_be_approved_again() {
    let http = Arc::new(LosesTheAnswer { sent: AtomicUsize::new(0) });
    let (store, service, session) = seeded(http.clone());
    let approval_id = a_held_call(&service, &session).await;

    service
        .resolve_approval(&approval_id, true, "bearer", None)
        .await
        .expect_err("the transport lost the answer");

    let row = store.get_approval(&approval_id).unwrap().expect("the approval is still there");
    assert_eq!(row.status, permaura_gateway::store::APPROVAL_UNRESOLVED);
    assert!(row.result.is_none(), "there is no result to report");
    assert_eq!(
        store.list_approvals(Some("pending")).unwrap().len(),
        0,
        "and it no longer occupies the human's queue"
    );

    // A second approve returns the row unchanged and runs nothing: `status != \"pending\"` is the
    // first gate, and the spent `claim_once` row is the second, which holds even if this status
    // were edited back by hand outside the gateway.
    let again = service
        .resolve_approval(&approval_id, true, "bearer", None)
        .await
        .expect("a resolved approval reads back rather than erroring");
    assert_eq!(again.status, permaura_gateway::store::APPROVAL_UNRESOLVED);
    assert_eq!(http.sent.load(Ordering::SeqCst), 1, "the upstream was reached exactly once");
    assert_eq!(resolutions(&store).len(), 1, "and exactly one terminal event exists");

    // The store will not write a settled row back to `pending` either, so the edit takes a hand
    // outside the gateway, where the spent claim (pinned in `approval_race_tests`) still refuses it.
    let mut forced = row.clone();
    forced.status = "pending".into();
    let kept = store.put_approval(forced).expect_err("a settled approval keeps its status");
    assert!(matches!(kept, GatewayError::Conflict(_)), "{kept:?}");
    let again = service
        .resolve_approval(&approval_id, true, "bearer", None)
        .await
        .expect("a resolved approval reads back rather than erroring");
    assert_eq!(again.status, permaura_gateway::store::APPROVAL_UNRESOLVED);
    assert_eq!(http.sent.load(Ordering::SeqCst), 1, "still exactly once");
}

/// The cancellation half, for the same reason `invoke` has one: an approver's phone losing the
/// network drops this future at an await point, and the call it released has already been sent.
#[tokio::test]
async fn an_approver_that_gives_up_does_not_cancel_the_held_call_or_its_record() {
    let http = Arc::new(SlowUpstream {
        delay: Duration::from_millis(300),
        answered: AtomicUsize::new(0),
    });
    let (store, service, session) = seeded(http.clone());
    let approval_id = a_held_call(&service, &session).await;

    let gave_up = tokio::time::timeout(
        Duration::from_millis(30),
        service.resolve_approval(&approval_id, true, "bearer", None),
    )
    .await;
    assert!(gave_up.is_err(), "the approver must have given up before the upstream answered");
    assert!(resolutions(&store).is_empty(), "the execution is still running");

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(http.answered.load(Ordering::SeqCst), 1, "the held call ran to completion");
    let terminals = resolutions(&store);
    assert_eq!(terminals.len(), 1, "one terminal event, written after the approver left");
    assert_eq!(terminals[0]["decision"], "approved");
    assert_eq!(terminals[0]["status"], 200);
}

/// The success path, unchanged. It is here to pin that moving the `"approved"` event inside
/// `TerminalEvent` did not move the event: same decision, same keys, same values.
#[tokio::test]
async fn an_approved_held_call_records_the_same_approved_event_it_always_did() {
    let http = Arc::new(SlowUpstream { delay: Duration::from_millis(1), answered: AtomicUsize::new(0) });
    let (store, service, session) = seeded(http.clone());
    let approval_id = a_held_call(&service, &session).await;

    let resolved = service
        .resolve_approval(&approval_id, true, "device_signed", Some("apprv_phone"))
        .await
        .expect("the upstream answers");
    assert_eq!(resolved.status, "approved");

    let terminals = resolutions(&store);
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0]["decision"], "approved");
    assert_eq!(terminals[0]["approval_id"], approval_id.as_str());
    assert_eq!(terminals[0]["status"], 200);
    assert_eq!(terminals[0]["method"], "device_signed");
    assert_eq!(terminals[0]["approver"], "apprv_phone");
    assert!(terminals[0].get("grant_id").is_some(), "the charged grant is still named");
    assert!(terminals[0].get("result_summary").is_some(), "and the redacted summary is still there");
    assert!(terminals[0].get("outcome").is_none(), "a successful resolution claims no outcome");
}

/// An upstream that holds every request until the test lets it answer, so a test can hang up on a
/// call that is provably mid-flight rather than racing a sleep.
#[derive(Default)]
struct GatedUpstream {
    sent: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl HttpClient for GatedUpstream {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(HttpResponse::json(201, serde_json::json!({ "number": 7 })))
    }
}

fn approve_request(approval_id: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/v1/approvals")
        .header("authorization", format!("Bearer {}", permaura_gateway::seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({ "approval_id": approval_id, "approve": true }).to_string(),
        ))
        .unwrap()
}

/// `(seq, decision)` of every event in the chain that names `approval_id`.
fn events_naming(store: &Arc<dyn Store>, approval_id: &str) -> Vec<(u64, String)> {
    store
        .audit_events(None)
        .unwrap()
        .iter()
        .filter(|e| e.payload.summary.get("approval_id").and_then(|v| v.as_str()) == Some(approval_id))
        .map(|e| (e.seq, e.payload.decision.clone()))
        .collect()
}

/// Over the REST route the desktop uses. The desktop gave up on its approve after 1.5 s while
/// the held call was still running upstream. The call finished and its `approved` event was written,
/// but the row was settled by the request that had gone away, so it stayed `pending` with its claim
/// spent and every later approve answered "already claimed".
#[tokio::test]
async fn an_approver_that_hangs_up_mid_call_still_leaves_the_approval_resolved() {
    use tower::ServiceExt;

    let http = Arc::new(GatedUpstream::default());
    let (store, service, session) = seeded(http.clone());
    let approval_id = a_held_call(&service, &session).await;
    let app = permaura_gateway::build_router(
        permaura_gateway::AppState::new(service),
        "127.0.0.1:7376".parse().unwrap(),
    );

    // The client hangs up the moment the upstream has the request: `select!` drops the losing branch,
    // which is what hyper does to a handler whose connection closed.
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            answered = app.clone().oneshot(approve_request(&approval_id)) => {
                panic!("the resolve answered before the upstream did: {:?}", answered.map(|r| r.status()))
            }
            _ = http.entered.notified() => {}
        }
    })
    .await
    .expect("the held call reached the upstream");
    assert_eq!(http.sent.load(Ordering::SeqCst), 1);
    assert_eq!(store.get_approval(&approval_id).unwrap().unwrap().status, "pending", "still running");

    http.release.notify_one();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let row = loop {
        let row = store.get_approval(&approval_id).unwrap().unwrap();
        if row.status != "pending" {
            break row;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the approval was left claimed and pending after its call finished"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(row.status, "approved");
    assert_eq!(row.result_status, Some(201));
    assert!(row.result.is_some(), "the agent can collect the result its call produced");

    let events = events_naming(&store, &approval_id);
    let decisions: Vec<&str> = events.iter().map(|(_, d)| d.as_str()).collect();
    assert_eq!(
        decisions,
        ["requires_approval", "attempt", "approved"],
        "the hold, one fence, then one terminal event: {events:?}"
    );
    assert!(events[1].0 < events[2].0);

    // The approver comes back: the resolved approval reads back, nothing runs a second time.
    let again = app.oneshot(approve_request(&approval_id)).await.unwrap();
    assert_eq!(again.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(again.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["status"], "approved", "{body}");
    assert_eq!(http.sent.load(Ordering::SeqCst), 1, "the held call ran exactly once");
    assert_eq!(events_naming(&store, &approval_id).len(), 3, "and the chain gained nothing");
}
