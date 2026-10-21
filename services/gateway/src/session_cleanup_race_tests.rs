//! The session cleanup judges a row as it stands when the delete lands, not as its earlier snapshot
//! read it. The schedule: the cleanup lists an expired, unrevoked relay row,
//! the owner revokes it, and the cleanup must not then delete the tombstone, or the next relayed
//! invoke recreates the identity unrevoked and reaches the upstream. Run against each real store.

use crate::connectors::{Capability, MockHttpClient};
use crate::error::GatewayError;
use crate::manifest::InstalledManifest;
use crate::store::*;
use crate::AppState;
use permaura_core::{AuditEvent, AuditPayload, Connection, ExecutionLocation, Grant, Policy, Principal, SecretRecord};
use permaura_relay::{request_hash, InvokeOrigin, InvokeRequest, RelayOutcome, SessionCtx};
use serde_json::json;
use std::sync::{Arc, Mutex};

macro_rules! delegate {
    ($( fn $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty; )*) => {
        $( fn $name(&self, $( $arg : $ty ),*) -> $ret { self.inner.$name($( $arg ),*) } )*
    };
}

/// A real store whose `list_sessions` lets the owner's revocation land just after the snapshot it
/// hands the cleanup was read.
struct SnapshotRaceStore {
    inner: Arc<dyn Store>,
    revoke_after_list: Mutex<Option<String>>,
}

impl Store for SnapshotRaceStore {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError> {
        self.inner.run_atomically(f)
    }
    fn list_sessions(&self) -> Result<Vec<Session>, GatewayError> {
        let snapshot = self.inner.list_sessions()?;
        if let Some(id) = self.revoke_after_list.lock().unwrap().take() {
            assert!(self.inner.revoke_session(&id)?);
            assert!(self.inner.get_session(&id)?.unwrap().revoked);
        }
        Ok(snapshot)
    }
    delegate! {
        fn put_approval(approval: PendingApproval) -> Result<(), GatewayError>;
        fn insert_approval(approval: PendingApproval) -> Result<(), GatewayError>;
        fn get_approval(id: &str) -> Result<Option<PendingApproval>, GatewayError>;
        fn append_audit_charged(payload: AuditPayload, charge: Option<crate::store::GrantCharge>) -> Result<AuditEvent, GatewayError>;
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

fn sqlite() -> Arc<dyn Store> {
    Arc::new(crate::store::sqlite::SqliteStore::open_in_memory().unwrap())
}

fn memory() -> Arc<dyn Store> {
    Arc::new(crate::store::memory::MemoryStore::new())
}

/// The hosted store: SQLite carried to an object store, here an in-memory bucket.
fn hosted(tag: &str) -> Arc<dyn Store> {
    struct XorKms;
    #[async_trait::async_trait]
    impl crate::backend::KmsClient for XorKms {
        async fn decrypt(&self, _key_id: &str, ct: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, GatewayError> {
            Ok(zeroize::Zeroizing::new(ct.iter().map(|b| b ^ 0x5A).collect()))
        }
        async fn encrypt(&self, _key_id: &str, pt: &[u8]) -> Result<Vec<u8>, GatewayError> {
            Ok(pt.iter().map(|b| b ^ 0x5A).collect())
        }
    }
    let dir = std::env::temp_dir().join(format!("permaura-cleanup-race-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let wrap = crate::backend::AuditKeyWrap { kms: Arc::new(XorKms), key_id: "test-cmk".into(), adopt_plaintext: false };
    Arc::new(
        crate::store::persisted::PersistedSqliteStore::open(
            &dir.join("gateway.db").to_string_lossy(),
            Arc::new(crate::objectstore::MemoryObjectStore::new()),
            crate::store::persisted::DEFAULT_OBJECT,
            Some(wrap),
        )
        .unwrap(),
    )
}

fn long_ago() -> i64 {
    crate::service::now_ms() - DEAD_SESSION_GRACE_MS - 60_000
}

/// That schedule against `inner`, with the revocation before the cleanup's snapshot or after it.
async fn relay_tombstone_survives_cleanup(inner: Arc<dyn Store>, revoke_before: bool) {
    crate::seed::seed(inner.as_ref()).unwrap();
    let mut secret = inner.get_secret("sec_braintree_prod").unwrap().unwrap();
    secret.metadata.allowed_execution_locations.push(ExecutionLocation::RemoteAllowed);
    inner.put_secret(secret).unwrap();
    let store = Arc::new(SnapshotRaceStore { inner: inner.clone(), revoke_after_list: Mutex::new(None) });
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::from_parts(store.clone(), http.clone());
    let cap = "braintree.transactions.search";
    let params = json!({ "status": "failed" });
    let request = || InvokeRequest {
        job_id: "job_cleanup_race".into(),
        session_ctx: SessionCtx {
            cp_session_id: "cp_cleanup_race".into(),
            org_id: "org_cleanup_race".into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: cap.into(),
        params: params.clone(),
        request_hash: request_hash(cap, &params),
        reason: None,
        execution_location: ExecutionLocation::LocalOnly,
        deadline_ms: i64::MAX,
    };
    let first = crate::relay::handle_invoke(&state.service, "org_cleanup_race", request()).await;
    assert!(matches!(first.outcome, RelayOutcome::Allowed { .. }), "the identity is established");
    let id = crate::relay::relayed_session_id("cp_cleanup_race");
    let mut row = inner.get_session(&id).unwrap().unwrap();
    row.expires_at = Some(long_ago());
    inner.put_session(row).unwrap();
    if revoke_before {
        assert!(inner.revoke_session(&id).unwrap());
    } else {
        *store.revoke_after_list.lock().unwrap() = Some(id.clone());
    }

    crate::prune_dead_sessions(store.as_ref(), false);

    assert!(store.revoke_after_list.lock().unwrap().is_none(), "the revocation was injected");
    assert!(inner.get_session(&id).unwrap().is_some(), "the cleanup deleted a revoked relay identity's tombstone");
    let result = crate::relay::handle_invoke(&state.service, "org_cleanup_race", request()).await;
    assert!(
        matches!(result.outcome, RelayOutcome::Denied { ref decision } if decision.reason == "session has been revoked"),
        "revocation must survive session cleanup: {:?}",
        result.outcome
    );
    assert!(inner.get_session(&id).unwrap().unwrap().revoked, "the retained revocation must remain set");
    assert_eq!(http.requests().len(), 1, "only the call made before the revocation reached the upstream");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_after_the_cleanup_snapshot_survives_on_sqlite() {
    relay_tombstone_survives_cleanup(sqlite(), false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_before_the_cleanup_snapshot_survives_on_sqlite() {
    relay_tombstone_survives_cleanup(sqlite(), true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_after_the_cleanup_snapshot_survives_on_the_hosted_store() {
    relay_tombstone_survives_cleanup(hosted("after"), false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_after_the_cleanup_snapshot_survives_in_memory() {
    relay_tombstone_survives_cleanup(memory(), false).await;
}

fn row(id: &str, agent_id: &str, role: SessionRole, expires_at: Option<i64>, revoked: bool) -> Session {
    Session {
        class: Default::default(),
        opened_by: None,
        id: id.into(),
        agent_id: agent_id.into(),
        user_id: None,
        device_id: None,
        token: format!("tok_{id}"),
        role,
        created_at: long_ago(),
        revoked,
        expires_at,
        last_used_at: None,
        actor: None,
    }
}

/// The controls: ordinary dead rows still go, on each store, and a revoked OAuth tombstone stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_dead_rows_are_still_pruned_and_tombstones_kept() {
    for (name, inner) in [("sqlite", sqlite()), ("memory", memory()), ("hosted", hosted("controls"))] {
        let store = SnapshotRaceStore { inner: inner.clone(), revoke_after_list: Mutex::new(None) };
        inner.put_session(row("sess_expired", "operator", SessionRole::Operator, Some(long_ago()), false)).unwrap();
        inner.put_session(row("relay:cp_lapsed", "codex-cli", SessionRole::Agent, Some(long_ago()), false)).unwrap();
        inner.put_session(row("sess_revoked", "operator", SessionRole::Operator, Some(i64::MAX), true)).unwrap();
        inner.put_session(row("sess_oauth:client-gone", "oauth:client-gone", SessionRole::Agent, Some(long_ago()), true)).unwrap();
        inner.put_session(row("relay:cp_revoked", "codex-cli", SessionRole::Agent, Some(long_ago()), true)).unwrap();
        inner.put_session(row("sess_live", "operator", SessionRole::Operator, Some(i64::MAX), false)).unwrap();

        crate::prune_dead_sessions(&store, false);

        let left: Vec<String> = inner.list_sessions().unwrap().into_iter().map(|s| s.id).collect();
        for gone in ["sess_expired", "relay:cp_lapsed", "sess_revoked"] {
            assert!(!left.iter().any(|id| id == gone), "{name}: {gone} is ordinary weight and goes: {left:?}");
        }
        for kept in ["sess_oauth:client-gone", "relay:cp_revoked", "sess_live"] {
            assert!(left.iter().any(|id| id == kept), "{name}: {kept} must survive: {left:?}");
        }
    }
}

/// The idle sweep deletes an OAuth row that has no expiry and has gone unused for 30 days. An owner's
/// revocation landing after the sweep read it turns it into a tombstone, which must then stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oauth_row_revoked_after_the_idle_sweep_snapshot_is_kept() {
    for (name, inner) in [("sqlite", sqlite()), ("memory", memory()), ("hosted", hosted("idle"))] {
        let store = SnapshotRaceStore { inner: inner.clone(), revoke_after_list: Mutex::new(None) };
        let idle = |id: &str| Session {
            created_at: crate::service::now_ms() - AGENT_SESSION_TTL_MS - 60_000,
            ..row(id, "oauth:client", SessionRole::Agent, None, false)
        };
        inner.put_session(idle("sess_oauth:client")).unwrap();
        inner.put_session(idle("sess_oauth:other")).unwrap();
        *store.revoke_after_list.lock().unwrap() = Some("sess_oauth:client".into());

        crate::sweep_idle_agent_sessions(&store, false);

        let kept = inner.get_session("sess_oauth:client").unwrap();
        assert!(kept.is_some_and(|s| s.revoked), "{name}: the revoked OAuth row is a tombstone and stays");
        assert!(inner.get_session("sess_oauth:other").unwrap().is_none(), "{name}: an idle row nobody revoked still goes");
    }
}

/// The atomicity itself, on each store: a revocation issued while `delete_session_if` is judging the
/// row cannot land until the judgement and the delete are both done. The judge here starts that
/// revocation on another thread and sees it still waiting before it answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_judgement_and_the_delete_exclude_a_concurrent_revocation() {
    for (name, store) in [("sqlite", sqlite()), ("memory", memory()), ("hosted", hosted("exclusion"))] {
        store.put_session(row("relay:cp_judged", "codex-cli", SessionRole::Agent, Some(long_ago()), false)).unwrap();
        let revoker: Mutex<Option<std::thread::JoinHandle<Result<bool, GatewayError>>>> = Mutex::new(None);
        let landed_inside = Mutex::new(None);
        let deleted = store
            .delete_session_if("relay:cp_judged", &|current| {
                let (tx, rx) = std::sync::mpsc::channel();
                let other = store.clone();
                *revoker.lock().unwrap() = Some(std::thread::spawn(move || {
                    let out = other.revoke_session("relay:cp_judged");
                    let _ = tx.send(());
                    out
                }));
                *landed_inside.lock().unwrap() = Some(rx.recv_timeout(std::time::Duration::from_millis(300)).is_ok());
                !current.revoked
            })
            .unwrap();
        assert_eq!(*landed_inside.lock().unwrap(), Some(false), "{name}: a revocation landed between the judgement and the delete");
        assert!(deleted, "{name}: the row was judged unrevoked and deleted");
        let revoked = revoker.lock().unwrap().take().unwrap().join().unwrap().unwrap();
        assert!(!revoked, "{name}: the revocation ran after the delete and found no row");
    }
}
