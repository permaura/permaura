use super::*;
use crate::connectors::MockHttpClient;
use crate::manifest::InstalledManifest;
use crate::store::{memory::MemoryStore, SecretCustody};
use permaura_core::{AuditEvent, AuditPayload};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

macro_rules! delegate {
    ($( fn $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty; )*) => {
        $( fn $name(&self, $( $arg : $ty ),*) -> $ret { self.inner.$name($( $arg ),*) } )*
    };
}

struct RacingStore {
    inner: MemoryStore,
    readers: Barrier,
    snapshots: AtomicUsize,
    fail_resolved_write: AtomicBool,
    /// When set, the next read of a resolved row fails, as a quarantined store's would after the row was written.
    fail_resolved_read: AtomicBool,
    revoke_on_attempt: Mutex<Option<String>>,
    /// When set, each read of the held-params total waits (up to a second) after reading for a second reader, so two holds both read it before either writes its row unless something orders them.
    hold_rendezvous: AtomicBool,
    hold_readers: AtomicUsize,
}
impl RacingStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            readers: Barrier::new(2),
            snapshots: AtomicUsize::new(0),
            fail_resolved_write: AtomicBool::new(false),
            fail_resolved_read: AtomicBool::new(false),
            revoke_on_attempt: Mutex::new(None),
            hold_rendezvous: AtomicBool::new(false),
            hold_readers: AtomicUsize::new(0),
        }
    }
}
impl Store for RacingStore {
    fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError> {
        f(self)
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn put_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        if approval.status == "approved" && self.fail_resolved_write.swap(false, Ordering::SeqCst) {
            return Err(GatewayError::Internal(
                "synthetic failure after upstream execution".into(),
            ));
        }
        self.inner.put_approval(approval)
    }
    fn append_audit_charged(
        &self,
        payload: AuditPayload,
        charge: Option<crate::store::GrantCharge>,
    ) -> Result<AuditEvent, GatewayError> {
        let revoke = payload.decision == "attempt"
            && payload.session_id.is_some()
            && payload.session_id == *self.revoke_on_attempt.lock().unwrap();
        let event = self.inner.append_audit_charged(payload, charge)?;
        if revoke {
            self.inner.revoke_session(event.payload.session_id.as_deref().unwrap_or_default())?;
        }
        Ok(event)
    }
    fn pending_hold_bytes(&self) -> Result<u64, GatewayError> {
        let total = self.inner.pending_hold_bytes()?;
        if self.hold_rendezvous.load(Ordering::SeqCst) {
            self.hold_readers.fetch_add(1, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while self.hold_readers.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        Ok(total)
    }
    fn get_approval(&self, id: &str) -> Result<Option<PendingApproval>, GatewayError> {
        let snapshot = self.inner.get_approval(id)?;
        if snapshot.as_ref().is_some_and(|a| a.status != "pending") && self.fail_resolved_read.swap(false, Ordering::SeqCst) {
            return Err(GatewayError::Internal("synthetic failure reading the resolved row".into()));
        }
        // Both requests have read the unspent approval before either is allowed to write it.
        if self.snapshots.fetch_add(1, Ordering::SeqCst) < 2 {
            self.readers.wait();
        }
        Ok(snapshot)
    }
    delegate! {
        fn insert_approval(approval: PendingApproval) -> Result<(), GatewayError>;
        fn get_meta(key: &str) -> Result<Option<String>, GatewayError>;
        fn put_meta(key: &str, value: &str) -> Result<(), GatewayError>;
        fn put_agent(agent: Agent) -> Result<(), GatewayError>;
        fn get_agent(id: &str) -> Result<Option<Agent>, GatewayError>;
        fn list_agents() -> Result<Vec<Agent>, GatewayError>;
        fn delete_agent(id: &str) -> Result<bool, GatewayError>;
        fn put_session(session: Session) -> Result<(), GatewayError>;
        fn insert_session(session: Session) -> Result<bool, GatewayError>;
        fn touch_session(id: &str, token: &str, now: i64, extend_expiry_to: Option<i64>) -> Result<bool, GatewayError>;
        fn session_by_token(token: &str) -> Result<Option<Session>, GatewayError>;
        fn get_session(id: &str) -> Result<Option<Session>, GatewayError>;
        fn list_sessions() -> Result<Vec<Session>, GatewayError>;
        fn revoke_session(id: &str) -> Result<bool, GatewayError>;
        fn expire_session_by(id: &str, at: i64) -> Result<bool, GatewayError>;
        fn delete_live_sessions() -> Result<u64, GatewayError>;
        fn delete_session(id: &str) -> Result<bool, GatewayError>;
        fn delete_session_if(id: &str, dead: &dyn Fn(&Session) -> bool) -> Result<bool, GatewayError>;
        fn put_connection(connection: Connection) -> Result<(), GatewayError>;
        fn get_connection(id: &str) -> Result<Option<Connection>, GatewayError>;
        fn list_connections() -> Result<Vec<Connection>, GatewayError>;
        fn delete_connection(id: &str) -> Result<bool, GatewayError>;
        fn put_policy(policy: Policy) -> Result<(), GatewayError>;
        fn get_policy(id: &str) -> Result<Option<Policy>, GatewayError>;
        fn list_policies() -> Result<Vec<Policy>, GatewayError>;
        fn policies_for_connection(connection_id: &str) -> Result<Vec<Policy>, GatewayError>;
        fn delete_policy(id: &str) -> Result<bool, GatewayError>;
        fn put_grant(grant: Grant) -> Result<(), GatewayError>;
        fn get_grant(grant_id: &str) -> Result<Option<Grant>, GatewayError>;
        fn list_grants() -> Result<Vec<Grant>, GatewayError>;
        fn update_grant(grant: Grant) -> Result<bool, GatewayError>;
        fn delete_grant(grant_id: &str) -> Result<bool, GatewayError>;
        fn put_enrolment_code(code: EnrolmentCode) -> Result<(), GatewayError>;
        fn mint_enrolment_code(code: EnrolmentCode, now_ms: i64, live_max: usize) -> Result<(), GatewayError>;
        fn consume_enrolment_code(code: &str, now_ms: i64) -> Result<Option<EnrolmentCode>, GatewayError>;
        fn enrolment_code_redeemable(code: &str, now_ms: i64) -> Result<bool, GatewayError>;
        fn delete_unconsumed_enrolment_codes() -> Result<u64, GatewayError>;
        fn put_secret(record: SecretRecord) -> Result<(), GatewayError>;
        fn put_secret_if_unchanged(id: &str, expected: &permaura_core::SealedSecret, sealed: permaura_core::SealedSecret) -> Result<bool, GatewayError>;
        fn get_secret(id: &str) -> Result<Option<SecretRecord>, GatewayError>;
        fn list_secret_ids() -> Result<Vec<String>, GatewayError>;
        fn delete_secret(id: &str) -> Result<bool, GatewayError>;
        fn put_secret_custody(custody: SecretCustody) -> Result<(), GatewayError>;
        fn get_secret_custody(secret_id: &str) -> Result<Option<SecretCustody>, GatewayError>;
        fn list_secret_custody() -> Result<Vec<SecretCustody>, GatewayError>;
        fn delete_secret_custody(secret_id: &str) -> Result<bool, GatewayError>;
        fn put_capability(cap: Capability) -> Result<(), GatewayError>;
        fn get_capability(id: &str) -> Result<Option<Capability>, GatewayError>;
        fn list_capabilities() -> Result<Vec<Capability>, GatewayError>;
        fn delete_capability(id: &str) -> Result<bool, GatewayError>;
        fn set_approval_status(id: &str, status: &str) -> Result<Option<PendingApproval>, GatewayError>;
        fn list_approvals(status: Option<&str>) -> Result<Vec<PendingApproval>, GatewayError>;
        fn put_connector_manifest(manifest: InstalledManifest) -> Result<(), GatewayError>;
        fn get_connector_manifest(id: &str) -> Result<Option<InstalledManifest>, GatewayError>;
        fn list_connector_manifests() -> Result<Vec<InstalledManifest>, GatewayError>;
        fn delete_connector_manifest(id: &str) -> Result<bool, GatewayError>;
        fn claim_once(scope: &str, jti: &str, expires_at_ms: i64) -> Result<bool, GatewayError>;
        fn audit_events(limit: Option<usize>) -> Result<Vec<AuditEvent>, GatewayError>;
        fn audit_len() -> Result<u64, GatewayError>;
        fn put_call_diagnostic(diagnostic: crate::store::CallDiagnostic) -> Result<(), GatewayError>;
        fn call_diagnostics(from_seq: u64) -> Result<Vec<crate::store::CallDiagnostic>, GatewayError>;
        fn purge_call_diagnostics() -> Result<u64, GatewayError>;
        fn audit_events_from(from_seq: u64, limit: usize) -> Result<Vec<AuditEvent>, GatewayError>;
        fn prune_audit_to(end_seq: u64, base_hash: &str, segment_head: &str) -> Result<u64, GatewayError>;
        fn seal_audit_segment(draft: permaura_core::audit::AuditSegmentDraft) -> Result<permaura_core::audit::AuditSegment, GatewayError>;
        fn seal_audit_index(index: permaura_core::audit::AuditArchiveIndex, written_at: &str) -> Result<permaura_core::audit::AuditArchiveIndex, GatewayError>;
        fn audit_verifying_key() -> Result<[u8; 32], GatewayError>;
        fn count_grant_usage(windows: &[crate::store::GrantWindow<'_>]) -> Result<crate::store::GrantUsageCounts, GatewayError>;
        fn read_grant_usage(windows: &[crate::store::GrantWindow<'_>]) -> Result<crate::store::GrantUsageCounts, GatewayError>;
        fn grant_usage_series(grant_id: &str, since_ms: i64, bucket_ms: i64, buckets: usize) -> Result<Vec<u64>, GatewayError>;
        fn rebuild_grant_usage(archived: &mut dyn Iterator<Item = Result<AuditEvent, GatewayError>>) -> Result<u64, GatewayError>;
        fn verify_audit() -> Result<Option<u64>, GatewayError>;
        fn audit_boundary() -> Result<Option<permaura_core::audit::AuditBoundary>, GatewayError>;
        fn fork_audit_epoch(epoch: u64, restore_id: &str) -> Result<bool, GatewayError>;
    }
}

#[tokio::test]
async fn concurrent_exports_cannot_spend_one_device_approval_twice() {
    let store = Arc::new(RacingStore::new());
    let state = AppState::from_parts(store.clone(), Arc::new(MockHttpClient::new()));
    let (mut approval, secret) = state
        .service
        .hold_vault_export_approval(VAULT_EXPORT_CAP, "Export", None)
        .unwrap();
    approval.status = "approved".into();
    store.put_approval(approval.clone()).unwrap();
    let first_state = state.clone();
    let second_state = state.clone();
    let first_id = approval.id.clone();
    let second_id = approval.id.clone();
    let second_secret = secret.clone();
    let first = std::thread::spawn(move || consume_export_approval(&first_state, &first_id, Some(&secret)));
    let second = std::thread::spawn(move || consume_export_approval(&second_state, &second_id, Some(&second_secret)));
    let wins = [first.join().unwrap(), second.join().unwrap()]
        .into_iter()
        .filter(Result::is_ok)
        .count();
    assert_eq!(
        wins, 1,
        "one signed approval must authorise exactly one export even across concurrent readers"
    );
}

async fn held_write(store: &Arc<RacingStore>, http: &Arc<MockHttpClient>) -> (AppState, String) {
    crate::seed::seed(store.as_ref()).unwrap();
    let state = AppState::from_parts(store.clone(), http.clone());
    let session = store.get_session("sess_demo").unwrap().unwrap();
    let outcome = state
        .service
        .invoke(
            &session,
            "github.pull_requests.create",
            &json!({ "repo": "example/synthetic", "title": "Test" }),
            None,
            ExecutionLocation::LocalOnly,
        )
        .await
        .unwrap();
    let crate::service::InvokeOutcome::RequiresApproval { approval, .. } = outcome else {
        panic!("synthetic write must be held");
    };
    assert!(http.requests().is_empty());
    (state, approval.id)
}

#[tokio::test]
async fn concurrent_approval_resolutions_execute_the_held_action_once() {
    let store = Arc::new(RacingStore::new());
    let http = Arc::new(MockHttpClient::new());
    let (state, approval_id) = held_write(&store, &http).await;
    // A second service instance shares only the store: a process-local lock cannot pass this test.
    let other = AppState::from_parts(store.clone(), http.clone());
    let first_state = state.clone();
    let first_id = approval_id.clone();
    let second_id = approval_id.clone();
    let first = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(
                first_state
                    .service
                    .resolve_approval(&first_id, true, "bearer", None),
            )
    });
    let second = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(
                other
                    .service
                    .resolve_approval(&second_id, true, "bearer", None),
            )
    });
    let wins = [first.join().unwrap(), second.join().unwrap()]
        .into_iter()
        .filter(Result::is_ok)
        .count();
    assert_eq!(wins, 1);
    assert_eq!(
        http.requests().len(),
        1,
        "one held action must not make two upstream writes"
    );
    let replay = state
        .service
        .resolve_approval(&approval_id, true, "bearer", None)
        .await
        .unwrap();
    assert_eq!(replay.status, "approved");
    assert_eq!(http.requests().len(), 1);
}

#[tokio::test]
async fn a_failed_result_save_cannot_make_a_completed_action_retryable() {
    let store = Arc::new(RacingStore::new());
    // This is a sequential failure/retry test, with no concurrent readers to wait for.
    store.snapshots.store(2, Ordering::SeqCst);
    let http = Arc::new(MockHttpClient::new());
    let (state, approval_id) = held_write(&store, &http).await;
    store.fail_resolved_write.store(true, Ordering::SeqCst);
    assert!(state
        .service
        .resolve_approval(&approval_id, true, "bearer", None)
        .await
        .is_err());
    assert_eq!(
        http.requests().len(),
        1,
        "the upstream effect happened before saving failed"
    );
    assert_eq!(
        store
            .inner
            .get_approval(&approval_id)
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
    let retry = state
        .service
        .resolve_approval(&approval_id, true, "bearer", None)
        .await
        .unwrap_err();
    assert!(retry.to_string().contains("already claimed"));
    assert_eq!(
        http.requests().len(),
        1,
        "an uncertain result must never execute again"
    );
}

/// The approver is answered from the row read back after it is settled, and when that read fails the call has still run and its row is still resolved. The error says so, and approving again answers with the row.
#[tokio::test]
async fn an_answer_that_cannot_be_read_back_says_the_decision_was_recorded() {
    let store = Arc::new(RacingStore::new());
    store.snapshots.store(2, Ordering::SeqCst);
    let http = Arc::new(MockHttpClient::new());
    let (state, approval_id) = held_write(&store, &http).await;
    store.fail_resolved_read.store(true, Ordering::SeqCst);
    let error = state.service.resolve_approval(&approval_id, true, "bearer", None).await.unwrap_err().to_string();
    assert!(error.contains("was recorded as approved") && error.contains("no longer pending"), "{error}");
    assert_eq!(http.requests().len(), 1, "the call ran");
    let again = state.service.resolve_approval(&approval_id, true, "bearer", None).await.unwrap();
    assert_eq!(again.status, "approved");
    assert!(again.result.is_some(), "approving again answers with the stored result");
    assert_eq!(http.requests().len(), 1, "and runs nothing");
}

/// A held deployment from an Agent-role session of the approved demo agent, and that session.
async fn held_deployment(store: &Arc<RacingStore>, http: &Arc<MockHttpClient>) -> (AppState, String, String) {
    store.snapshots.store(2, Ordering::SeqCst);
    crate::seed::seed(store.as_ref()).unwrap();
    let mut agent = store.get_session("sess_demo").unwrap().unwrap();
    agent.id = "sess_window_agent".into();
    agent.token = "tok_window_agent".into();
    agent.role = crate::store::SessionRole::Agent;
    store.put_session(agent.clone()).unwrap();
    let state = AppState::from_parts(store.clone(), http.clone());
    let outcome = state
        .service
        .invoke(
            &agent,
            "vercel.deployments.create",
            &json!({ "name": "synthetic", "target": "production" }),
            None,
            ExecutionLocation::LocalOnly,
        )
        .await
        .unwrap();
    let crate::service::InvokeOutcome::RequiresApproval { approval, .. } = outcome else {
        panic!("the deployment must be held");
    };
    assert!(http.requests().is_empty());
    (state, approval.id, agent.id)
}

fn decisions_for(store: &RacingStore, approval_id: &str) -> Vec<(String, serde_json::Value)> {
    store
        .inner
        .audit_events(None)
        .unwrap()
        .into_iter()
        .filter(|e| e.payload.summary.get("approval_id").and_then(|v| v.as_str()) == Some(approval_id))
        .map(|e| (e.payload.decision.clone(), e.payload.summary.clone()))
        .collect()
}

/// The later window: the approval-time recheck read the session before the attempt was
/// recorded, and the revocation lands while that append is in progress (on a hosted store it is an
/// upload). Nothing has been sent, so the call must still be stopped and its attempt closed.
#[tokio::test]
async fn a_revocation_landing_while_the_attempt_is_recorded_stops_the_held_call() {
    let store = Arc::new(RacingStore::new());
    let http = Arc::new(MockHttpClient::new());
    let (state, approval_id, session_id) = held_deployment(&store, &http).await;
    *store.revoke_on_attempt.lock().unwrap() = Some(session_id.clone());

    let resolved = state.service.resolve_approval(&approval_id, true, "bearer", None).await.unwrap();

    assert!(store.inner.get_session(&session_id).unwrap().unwrap().revoked, "the revocation landed mid-resolution");
    assert!(http.requests().is_empty(), "a call whose session was revoked before it was sent reached the upstream");
    assert_eq!(resolved.status, "denied");
    assert_eq!(resolved.resolution_reason.as_deref(), Some("session_ended"));
    let row = store.inner.get_approval(&approval_id).unwrap().unwrap();
    assert_eq!(row.status, "denied", "the row is settled with the same verdict");
    let events = decisions_for(&store, &approval_id);
    let decisions: Vec<&str> = events.iter().map(|(d, _)| d.as_str()).collect();
    assert_eq!(decisions, ["requires_approval", "attempt", "denied"], "the attempt is closed by one terminal event");
    let terminal = &events[2].1;
    assert!(terminal["reason"].as_str().unwrap_or_default().contains("revoked"), "{terminal}");
    assert_eq!(terminal["human_decision"], "approved");
    assert_eq!(terminal["approver"], serde_json::Value::Null);
}

/// The control for the test above: the same harness, nothing revoked, and the call runs once.
#[tokio::test]
async fn the_same_harness_with_nothing_revoked_runs_the_held_call() {
    let store = Arc::new(RacingStore::new());
    let http = Arc::new(MockHttpClient::new());
    let (state, approval_id, _) = held_deployment(&store, &http).await;

    let resolved = state.service.resolve_approval(&approval_id, true, "bearer", None).await.unwrap();

    assert_eq!(resolved.status, "approved");
    assert_eq!(http.requests().len(), 1);
    let decisions: Vec<String> = decisions_for(&store, &approval_id).into_iter().map(|(d, _)| d).collect();
    assert_eq!(decisions, ["requires_approval", "attempt", "approved"]);
}

/// Two agent holds that each fit the held-params ceiling, but not together, are never both admitted, however their budget checks interleave: the check and the row's write are one step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_holds_cannot_both_pass_the_held_params_ceiling() {
    let store = Arc::new(RacingStore::new());
    crate::seed::seed(store.as_ref()).unwrap();
    let http = Arc::new(MockHttpClient::new());
    // A 100 KiB body keeps the budget's floor, one hold's text and the rest of its row, under two of these holds.
    let config = crate::limits::LimitsConfig { held_total_bytes: 160 * 1024, body_exec_bytes: 100 * 1024, ..crate::limits::LimitsConfig::default() };
    let budget = crate::memory::MemoryBudget::from_config(&config);
    let ceiling = budget.held_total_bytes();
    let state = AppState::new(crate::service::EnforcementService::new(store.clone(), http.clone()).with_memory_budget(budget));
    let session = store.get_session("sess_demo").unwrap().unwrap();
    store.hold_rendezvous.store(true, Ordering::SeqCst);

    let hold = |title: &'static str| {
        let state = state.clone();
        let session = session.clone();
        tokio::spawn(async move {
            let params = json!({ "repo": "example/synthetic", "title": title, "body": "x".repeat(96 * 1024) });
            state.service.invoke(&session, "github.pull_requests.create", &params, None, ExecutionLocation::LocalOnly).await
        })
    };
    let (first, second) = (hold("first"), hold("second"));
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    let held = outcomes.iter().filter(|o| matches!(o, Ok(crate::service::InvokeOutcome::RequiresApproval { .. }))).count();
    let refused = outcomes
        .iter()
        .filter(|o| matches!(o, Err(GatewayError::TooManyRequests { reason, .. }) if reason == "held_params"))
        .count();
    assert_eq!((held, refused), (1, 1), "one hold fits the ceiling and the other is refused");
    assert!(store.inner.pending_hold_bytes().unwrap() <= ceiling, "the held rows stay under the ceiling");
    assert!(http.requests().is_empty());
}
