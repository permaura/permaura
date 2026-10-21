//! A held control-plane change is re-checked, claimed and applied under the control-plane lock that an unheld change is classified and applied under, so neither can land between the other's check and its apply.

use super::*;
use crate::connectors::MockHttpClient;
use crate::policy_guard::{GuardContext, Mutation};
use crate::store::memory::MemoryStore;
use permaura_core::{Grant, GrantAgents, GrantPeriod, Policy};

fn refunds(id: &str, allow: &[&str], device_signed: &[&str], quorum: u8) -> Policy {
    Policy {
        id: id.into(),
        connection_id: "stripe".into(),
        name: id.into(),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        device_signed: device_signed.iter().map(|s| s.to_string()).collect(),
        device_signed_quorum: quorum,
        ..Policy::default()
    }
}

fn everyone(id: &str, policy: &str, enabled: bool) -> Grant {
    Grant {
        grant_id: id.into(),
        name: id.into(),
        enabled,
        is_default: false,
        policy_ids: vec![policy.into()],
        agents: GrantAgents::AllAgents,
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    }
}

/// Refunds take two devices through `g_strict`; `g_lax` would run them at auto and is switched off. Enabling `g_lax`
/// is held at one signature, since the two-device rule stays in force beside it. Disabling `g_strict` leaves refunds
/// denied, a tightening applied at once. Either order alone is caught, but a confirm that lands between the unheld
/// change's check and its apply would leave refunds at auto on one signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_change_is_rechecked_and_applied_under_the_control_plane_lock() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    store.put_policy(refunds("p_strict", &[], &["refunds.create"], 2)).unwrap();
    store.put_policy(refunds("p_lax", &["refunds.create"], &[], 1)).unwrap();
    store.put_grant(everyone("g_strict", "p_strict", true)).unwrap();
    store.put_grant(everyone("g_lax", "p_lax", false)).unwrap();
    let svc = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));

    use base64::Engine as _;
    let phone_key = base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[40; 32]).verifying_key().to_bytes());
    assert!(svc.trust_approver_key_for("device:phone", &phone_key, Some("person-phone")).unwrap());

    let enable_lax = Mutation::GrantUpsert { grant: everyone("g_lax", "p_lax", true) };
    let held = svc.hold_change_approval(crate::rest::POLICY_WRITE_CAP, &enable_lax, "test", None).await.unwrap();
    assert_eq!(held.required_signatures, 1, "setup: enabling the lax grant alone lowers nothing");

    // The unheld change in flight: classified on the estate before the held one lands, holding the lock until it applies.
    let in_flight = svc.control_plane_mutex().lock().await;
    let disable_strict = Mutation::GrantUpsert { grant: everyone("g_strict", "p_strict", false) };
    let (policies, grants) = (store.list_policies().unwrap(), store.list_grants().unwrap());
    let ctx = GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
    assert!(crate::policy_guard::is_strictly_tightening(&disable_strict, &ctx), "setup: it leaves refunds denied");

    let confirm = {
        let (svc, id) = (svc.clone(), held.id.clone());
        tokio::spawn(async move { svc.resolve_approval(&id, true, "device_signed", Some("device:phone")).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!confirm.is_finished(), "the confirm waits for the unheld change to finish");
    assert!(!store.get_grant("g_lax").unwrap().unwrap().enabled, "and has applied nothing meanwhile");

    crate::rest::apply_mutation(store.as_ref(), &svc, &disable_strict).unwrap();
    drop(in_flight);
    let outcome = confirm.await.unwrap();
    assert!(outcome.is_err(), "re-checked on the estate the unheld change left, it now takes refunds below their two-device mark: {outcome:?}");
    assert!(!store.get_grant("g_lax").unwrap().unwrap().enabled, "so the lax grant stays off");
    assert_eq!(store.get_approval(&held.id).unwrap().unwrap().required_signatures, 2, "and the hold now asks for both devices");

    // Even signed by both people, it would lower refunds further than when it was held, so it is retired, not applied.
    let key = |n: u8| base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes());
    for (id, n, person) in [("device:a", 41, "person-a"), ("device:b", 42, "person-b")] {
        assert!(svc.trust_approver_key_for(id, &key(n), Some(person)).unwrap());
    }
    let mut row = store.get_approval(&held.id).unwrap().unwrap();
    row.signatures = [("device:a", 41), ("device:b", 42)]
        .into_iter()
        .map(|(id, n)| crate::store::CollectedSignature { approver: id.into(), key_fp: key_fingerprint(&key(n)), decided_at: 0 })
        .collect();
    store.put_approval(row).unwrap();
    let outcome = svc.resolve_approval(&held.id, true, "device_signed", Some("device:b")).await;
    assert!(matches!(outcome, Err(GatewayError::Conflict(_))), "{outcome:?}");
    assert!(!store.get_grant("g_lax").unwrap().unwrap().enabled, "the lax grant stays off");
    let row = store.get_approval(&held.id).unwrap().unwrap();
    assert_eq!((row.status.as_str(), row.resolution_reason.as_deref()), ("denied", Some(DENIED_EFFECT_WIDENED)));
}

use crate::manifest::InstalledManifest;
use crate::store::{SecretCustody, EnrolmentCode};
use permaura_core::{Connection, SecretRecord};
use permaura_core::{AuditEvent, AuditPayload};
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};
macro_rules! delegate {
    ($( fn $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty; )*) => {
        $( fn $name(&self, $( $arg : $ty ),*) -> $ret { self.inner.$name($( $arg ),*) } )*
    };
}


struct LockStore {
    inner: MemoryStore,
    lock: Mutex<Option<Arc<tokio::sync::Mutex<()>>>>,
    claims: AtomicUsize,
    writes: AtomicUsize,
}
impl LockStore {
    fn assert_locked(&self, counter: &AtomicUsize) {
        if let Some(lock) = self.lock.lock().unwrap().as_ref() {
            assert!(lock.try_lock().is_err(), "the control-plane lock must cover the claim and write");
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }
}
impl Store for LockStore {
    fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError> { f(self) }
    fn kind(&self) -> &'static str { self.inner.kind() }
    fn put_approval(&self, row: PendingApproval) -> Result<(), GatewayError> { self.inner.put_approval(row) }
    fn get_approval(&self, id: &str) -> Result<Option<PendingApproval>, GatewayError> { self.inner.get_approval(id) }
    fn append_audit_charged(&self, payload: AuditPayload, charge: Option<crate::store::GrantCharge>) -> Result<AuditEvent, GatewayError> { self.inner.append_audit_charged(payload, charge) }
    fn put_grant(&self, grant: Grant) -> Result<(), GatewayError> { self.assert_locked(&self.writes); self.inner.put_grant(grant) }
    fn update_grant(&self, grant: Grant) -> Result<bool, GatewayError> { self.assert_locked(&self.writes); self.inner.update_grant(grant) }
    fn claim_once(&self, scope: &str, jti: &str, expires_at_ms: i64) -> Result<bool, GatewayError> {
        if scope == "approval-resolution" { self.assert_locked(&self.claims); }
        self.inner.claim_once(scope, jti, expires_at_ms)
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
        fn get_grant(grant_id: &str) -> Result<Option<Grant>, GatewayError>;
        fn list_grants() -> Result<Vec<Grant>, GatewayError>;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lock_covers_the_durable_claim_and_grant_write() {
    let store = Arc::new(LockStore { inner: MemoryStore::new(), lock: Mutex::new(None), claims: AtomicUsize::new(0), writes: AtomicUsize::new(0) });
    let svc = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()));
    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[61;32]).verifying_key().to_bytes());
    svc.trust_approver_key_for("device:phone", &key, Some("person")).unwrap();
    let m = Mutation::GrantUpsert { grant: everyone("added", "p", true) };
    store.put_policy(refunds("p", &["refunds.create"], &[], 1)).unwrap();
    let held = svc.hold_change_approval(crate::rest::POLICY_WRITE_CAP, &m, "test", None).await.unwrap();
    *store.lock.lock().unwrap() = Some(svc.control_plane_lock.clone());
    let resolved = svc.resolve_approval(&held.id, true, "device_signed", Some("device:phone")).await.unwrap();
    assert_eq!(resolved.status, "approved");
    assert_eq!(store.claims.load(Ordering::SeqCst), 1);
    assert!(store.writes.load(Ordering::SeqCst) > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_waiting_confirm_refreshes_trust_status_and_collected_signatures() {
    for change in ["revoked", "resolved", "signature"] {
        let store = Arc::new(MemoryStore::new());
        let svc = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[62;32]).verifying_key().to_bytes());
        svc.trust_approver_key_for("device:phone", &key, Some("person")).unwrap();
        let m = Mutation::GrantUpsert { grant: everyone("added", "p", true) };
        store.put_policy(refunds("p", &["refunds.create"], &[], 1)).unwrap();
        let held = svc.hold_change_approval(crate::rest::POLICY_WRITE_CAP, &m, "test", None).await.unwrap();
        let guard = svc.control_plane_mutex().lock().await;
        let task = { let svc = svc.clone(); let id = held.id.clone(); tokio::spawn(async move { svc.resolve_approval(&id, true, "device_signed", Some("device:phone")).await }) };
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert!(!task.is_finished());
        let mut row = store.get_approval(&held.id).unwrap().unwrap();
        match change {
            "revoked" => svc.revoke_approver_key("device:phone").unwrap(),
            "resolved" => { row.status = "denied".into(); store.put_approval(row).unwrap(); },
            _ => { row.signatures.push(crate::store::CollectedSignature { approver: "device:phone".into(), key_fp: key_fingerprint(&key), decided_at: 0 }); store.put_approval(row).unwrap(); },
        }
        drop(guard);
        let answer = task.await.unwrap();
        match change {
            "revoked" => { assert!(answer.is_err()); assert!(store.get_grant("added").unwrap().is_none()); },
            "resolved" => { assert_eq!(answer.unwrap().status, "denied"); assert!(store.get_grant("added").unwrap().is_none()); },
            _ => assert_eq!(answer.unwrap().signatures.len(), 1),
        }
    }
}

#[tokio::test]
async fn canceled_classification_keeps_its_worker_permit_until_work_ends() {
    let svc = Arc::new(EnforcementService::new(Arc::new(MemoryStore::new()), Arc::new(MockHttpClient::new())));
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let task = { let svc = svc.clone(); tokio::spawn(async move { svc.classify(move || { let _ = entered.send(()); released.recv().unwrap(); }).await }) };
    ready.await.unwrap();
    task.abort();
    let _ = task.await;
    let next = { let svc = svc.clone(); tokio::spawn(async move { svc.classify(|| 42).await }) };
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let stacked = next.is_finished();
    release.send(()).unwrap();
    assert_eq!(next.await.unwrap().unwrap(), 42);
    assert!(!stacked, "a canceled request must not admit another worker while its classifier runs");
}

#[tokio::test]
async fn destructive_confirmations_prepare_their_marks_before_the_store_write() {
    for mutation in [Mutation::AgentDelete { agent_id: "a".into() }, Mutation::ConnectionDelete { connection_id: "stripe".into() }] {
        let store = Arc::new(MemoryStore::new());
        store.put_policy(refunds("p", &[], &["refunds.create"], 2)).unwrap();
        store.put_grant(everyone("g", "p", true)).unwrap();
        let svc = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()));
        assert!(svc.in_force_cache.lock().unwrap().is_empty());
        svc.held_change_bar(&mutation, true, None).await.unwrap();
        let digest = estate_digest(&store.list_policies().unwrap(), &store.list_grants().unwrap());
        assert!(svc.in_force_cache.lock().unwrap().iter().any(|(key, _)| key == &digest), "the apply must not resolve this estate inline");
    }
}

#[test]
fn an_estate_digest_is_order_independent_and_invalidates_on_a_field_change() {
    let p = vec![refunds("p", &[], &["refunds.create"], 2), refunds("q", &["refunds.create"], &[], 1)];
    let g = vec![everyone("a", "p", true), everyone("b", "q", true)];
    let first = estate_digest(&p, &g);
    let mut reversed_p = p.clone(); reversed_p.reverse();
    let mut reversed_g = g.clone(); reversed_g.reverse();
    assert_eq!(first, estate_digest(&reversed_p, &reversed_g));
    reversed_g[0].enabled = false;
    assert_ne!(first, estate_digest(&p, &reversed_g));
    reversed_p[0].device_signed_quorum = 3;
    assert_ne!(first, estate_digest(&reversed_p, &g));
}
