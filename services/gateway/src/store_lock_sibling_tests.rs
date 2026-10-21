//! The siblings of a `std::sync::Mutex` held across a hosted store upload, on one runtime worker: every lock the signature and keyring paths take beside `serial`, and the budget book around `AuditUsage::measure`. Four of the six fail when `locked_store_section` and the `invoke` budget-book site are put back to the released shape (a plain `lock()` outside a store unit); the two upload-overlap keyring tests pass either way, see their notes.
//!
//! Every test builds its own one-worker multi-thread runtime and shuts it down in the background, so a wedge fails the assertion instead of hanging the suite. Bucket calls, once armed, answer only through a runtime timer (or an external release), as GcsObjectStore answers only through the I/O driver: if no worker is free to drive the timer, nothing answers until the release.

use super::*;
use crate::connectors::MockHttpClient;
use crate::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use crate::store::persisted::PersistedSqliteStore;
use crate::store::{PendingApproval, Session, SessionRole};
use base64::Engine as _;
use permaura_relay::{approval_result_preimage, request_hash, sign};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::Duration;

const CAP: &str = "braintree.transactions.search";

struct Stall {
    inner: MemoryObjectStore,
    stall_put: AtomicBool,
    stall_head: AtomicBool,
    started: std::sync::Mutex<std::sync::mpsc::Sender<&'static str>>,
    release: tokio::sync::watch::Sender<bool>,
    waits_started: AtomicU64,
    waits_finished: AtomicU64,
}

impl Stall {
    fn new() -> (Arc<Self>, std::sync::mpsc::Receiver<&'static str>) {
        let (tx, rx) = std::sync::mpsc::channel();
        (
            Arc::new(Stall {
                inner: MemoryObjectStore::new(),
                stall_put: AtomicBool::new(false),
                stall_head: AtomicBool::new(false),
                started: std::sync::Mutex::new(tx),
                release: tokio::sync::watch::channel(false).0,
                waits_started: AtomicU64::new(0),
                waits_finished: AtomicU64::new(0),
            }),
            rx,
        )
    }

    fn wait(&self, what: &'static str) {
        self.waits_started.fetch_add(1, Ordering::SeqCst);
        let _ = self.started.lock().unwrap().send(what);
        let mut released = self.release.subscribe();
        crate::store::bridge::block_on(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                _ = released.wait_for(|r| *r) => {}
            }
        });
        self.waits_finished.fetch_add(1, Ordering::SeqCst);
    }

    fn counts(&self) -> (u64, u64) {
        (self.waits_started.load(Ordering::SeqCst), self.waits_finished.load(Ordering::SeqCst))
    }
}

impl ObjectStore for Stall {
    fn head(&self, n: &str) -> Result<Option<u64>, GatewayError> {
        if self.stall_head.load(Ordering::SeqCst) {
            self.wait("head");
        }
        self.inner.head(n)
    }
    fn head_full(&self, n: &str) -> Result<Option<ObjectHead>, GatewayError> {
        if self.stall_head.load(Ordering::SeqCst) {
            self.wait("head");
        }
        self.inner.head_full(n)
    }
    fn has_history(&self, n: &str) -> Result<bool, GatewayError> {
        self.inner.has_history(n)
    }
    fn get(&self, n: &str, g: u64) -> Result<Vec<u8>, GatewayError> {
        self.inner.get(n, g)
    }
    fn put_if_generation(
        &self,
        n: &str,
        b: &[u8],
        e: u64,
        m: &std::collections::BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        if self.stall_put.load(Ordering::SeqCst) {
            self.wait("put");
        }
        self.inner.put_if_generation(n, b, e, m)
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

fn one_worker() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap()
}

fn store_over(objects: Arc<Stall>, window: Duration) -> Arc<dyn Store> {
    let dir = std::env::temp_dir().join(format!("store-lock-siblings-{}", short_id()));
    std::fs::create_dir_all(&dir).unwrap();
    Arc::new(
        PersistedSqliteStore::open(dir.join("gw.db").to_str().unwrap(), objects, "store.db", None)
            .unwrap()
            .with_fresh_read_window(window)
            .with_on_stale(Box::new(|_| {})),
    )
}

fn pending(id: &str, tier: &str, sigs: u8) -> PendingApproval {
    PendingApproval {
        id: id.into(),
        session_id: "sess_2p".into(),
        requested_by: None,
        capability: CAP.into(),
        resource: "braintree_production".into(),
        message: "m".into(),
        status: "pending".into(),
        grant_id: None,
        policy_id: None,
        params: serde_json::json!({ "status": "failed" }).into(),
        result: None,
        result_status: None,
        resolution_reason: None,
        created_at: now_ms(),
        expires_at: None,
        risk: None,
        action_description: None,
        intent: None,
        required_tier: tier.into(),
        required_signatures: sigs,
        signatures: Vec::new(),
    }
}

fn signed(sk: &ed25519_dalek::SigningKey, approver: &str, id: &str) -> ApprovalResult {
    let hash = request_hash(CAP, &serde_json::json!({ "status": "failed" }));
    let at = now_ms();
    let pre = approval_result_preimage(id, id, true, &hash, approver, at);
    ApprovalResult {
        job_id: id.into(),
        approval_id: id.into(),
        approve: true,
        request_hash: hash,
        approver: approver.into(),
        decided_at: at,
        approver_pubkey: None,
        audience: None,
        display_digest: None,
        device_sig: sign(sk, &pre),
    }
}

fn b64(sk: &ed25519_dalek::SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
}

fn put_session(store: &dyn Store) {
    store
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_2p".into(),
            agent_id: "codex-cli".into(),
            user_id: Some("sam".into()),
            device_id: None,
            token: String::new(),
            role: SessionRole::Operator,
            created_at: now_ms(),
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
}

fn outcome_name(o: &SignedApprovalOutcome) -> String {
    match o {
        SignedApprovalOutcome::Verified => "Verified".into(),
        SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => {
            format!("AwaitingSignatures {collected}/{required}")
        }
        SignedApprovalOutcome::AlreadyResolved(_) => "AlreadyResolved".into(),
        SignedApprovalOutcome::Refused(why) => format!("Refused({why})"),
    }
}

fn collect(rx: &std::sync::mpsc::Receiver<String>, want: usize, within: Duration) -> Vec<String> {
    let deadline = std::time::Instant::now() + within;
    let mut answered = Vec::new();
    while answered.len() < want {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(who) => answered.push(who),
            Err(_) => break,
        }
    }
    answered
}

fn canary(rt: &tokio::runtime::Runtime, done: std::sync::mpsc::Sender<String>) {
    std::thread::sleep(Duration::from_millis(50));
    rt.spawn(async move {
        let _ = done.send("canary".to_string());
    });
}

/// v2_signers_lock: Bob's first v2 signature is noted while Alice's note is still uploading.
#[test]
fn v2_signers_lock_a_second_signer_during_the_first_upload_does_not_wedge_one_worker() {
    let rt = one_worker();
    let _g = rt.enter();
    let (objects, started) = Stall::new();
    let store = store_over(objects.clone(), Duration::ZERO);
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    objects.stall_put.store(true, Ordering::SeqCst);
    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (s, d) = (service.clone(), done.clone());
    rt.spawn(async move {
        s.note_v2_signer("device:alice");
        let _ = d.send("alice noted".into());
    });
    started.recv_timeout(Duration::from_secs(10)).expect("alice's signer record upload started");
    let (s, d) = (service.clone(), done.clone());
    rt.spawn(async move {
        s.note_v2_signer("device:bob");
        let _ = d.send("bob noted".into());
    });
    canary(&rt, done);
    let answered = collect(&finished, 3, Duration::from_secs(5));
    let lock_held = service.v2_signers_lock.try_lock().is_err();
    objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("v2_signers_lock: answered={answered:?} after_release={after:?} lock_held_at_5s={lock_held} waits={:?}", objects.counts());
    rt.shutdown_background();
    assert_eq!(answered.len(), 3, "wedged: only {answered:?} answered within 5 s");
    let rec = store.get_meta(crate::store::DEVICE_SIG_V2_APPROVERS_META).unwrap().unwrap_or_default();
    assert!(rec.contains("device:alice") && rec.contains("device:bob"), "both signers recorded: {rec}");
}

/// refuse_short_of: raising one approval's tier uploads under the old shape while holding signature_lock; Bob signs another approval meanwhile.
#[test]
fn refuse_short_of_raising_a_row_while_another_signature_arrives_does_not_wedge_one_worker() {
    let rt = one_worker();
    let _g = rt.enter();
    let (objects, started) = Stall::new();
    let store = store_over(objects.clone(), Duration::ZERO);
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    service.set_accept_v1_device_signatures(true);
    service.set_require_display_bound_approvals(false);
    put_session(store.as_ref());
    store.put_approval(pending("appr_short", "approve", 1)).unwrap();
    store.put_approval(pending("appr_x", "device_signed", 2)).unwrap();
    let alice = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let bob = ed25519_dalek::SigningKey::from_bytes(&[22; 32]);
    let mut ring = ApproverKeyring::new();
    assert!(ring.add_for("device:alice", b64(&alice), Some("person-a".into())));
    assert!(ring.add_for("device:bob", b64(&bob), Some("person-b".into())));
    objects.stall_put.store(true, Ordering::SeqCst);

    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (s, st, d) = (service.clone(), store.clone(), done.clone());
    rt.spawn(async move {
        let row = st.get_approval("appr_short").unwrap().unwrap();
        let r = s.refuse_short_of(&row, "approve", Rung::DeviceSigned, 2);
        let _ = d.send(format!("refuse_short_of denied={}", matches!(r, Err(GatewayError::Denied(_)))));
    });
    started.recv_timeout(Duration::from_secs(10)).expect("the raised row's upload started");
    let (s, ring2, d, res) = (service.clone(), ring.clone(), done.clone(), signed(&bob, "device:bob", "appr_x"));
    rt.spawn(async move {
        let o = s.verify_signed_approval(&ring2, &res);
        let _ = d.send(format!("bob: {}", outcome_name(&o)));
    });
    canary(&rt, done);
    let answered = collect(&finished, 3, Duration::from_secs(5));
    let lock_held = service.signature_lock.try_lock().is_err();
    objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("refuse_short_of: answered={answered:?} after_release={after:?} signature_lock_held_at_5s={lock_held} waits={:?}", objects.counts());
    rt.shutdown_background();
    assert_eq!(answered.len(), 3, "wedged: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"refuse_short_of denied=true".to_string()), "{answered:?}");
    assert!(answered.contains(&"bob: AwaitingSignatures 1/2".to_string()), "{answered:?}");
    let row = store.get_approval("appr_short").unwrap().unwrap();
    assert_eq!((row.required_tier.as_str(), row.required_signatures), ("device_signed", 2), "the row was raised");
}

fn pairing(id: &str, sk: &ed25519_dalek::SigningKey) -> crate::policy_guard::Mutation {
    crate::policy_guard::Mutation::ApproverKeyTrust { approver_id: id.into(), approver_pubkey: b64(sk), person: None, replaces: None }
}

/// keyring_write_lock: a device-signed pairing (rest::apply_mutation, inside a transaction) is uploading, and a console revocation arrives.
///
/// Does not catch a return to the released lock shape: `PersistedSqliteStore::persist` donates on its own `state` lock, so an upload overlap never wedged here. The keyring cases that do are the fresh-read stall in `keyring_lock_order_with_serial_holds_on_one_worker_with_a_timer_driven_bucket_check` and `store_lock_tests::a_revocation_overlapping_a_pairing_upload_does_not_wedge_one_worker`, whose pairing writes the keyring outside a transaction.
#[test]
fn keyring_a_console_revocation_during_a_device_signed_pairings_upload_does_not_wedge_one_worker() {
    let rt = one_worker();
    let _g = rt.enter();
    let (objects, started) = Stall::new();
    let store = store_over(objects.clone(), Duration::ZERO);
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    let alice = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let carol = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
    assert!(service.trust_approver_key_durable("device:alice", &b64(&alice)).unwrap());
    objects.stall_put.store(true, Ordering::SeqCst);
    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (s, st, d, m) = (service.clone(), store.clone(), done.clone(), pairing("device:carol", &carol));
    rt.spawn(async move {
        let r = crate::rest::apply_mutation(st.as_ref(), &s, &m).map(|_| ());
        let _ = d.send(format!("pairing: {r:?}"));
    });
    started.recv_timeout(Duration::from_secs(10)).expect("the pairing's upload started");
    let (s, d) = (service.clone(), done.clone());
    rt.spawn(async move {
        let r = s.revoke_approver_key("device:alice");
        let _ = d.send(format!("revocation: {r:?}"));
    });
    canary(&rt, done);
    let answered = collect(&finished, 3, Duration::from_secs(5));
    objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("keyring pairing-then-revocation: answered={answered:?} after_release={after:?} waits={:?}", objects.counts());
    rt.shutdown_background();
    assert_eq!(answered.len(), 3, "wedged: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"pairing: Ok(())".to_string()), "{answered:?}");
    assert!(answered.contains(&"revocation: Ok(())".to_string()), "{answered:?}");
    service.refresh_keyring_now();
    assert!(service.approver_key_trusted("device:carol") && !service.approver_key_trusted("device:alice"));
}

/// keyring_write_lock, the other order: the console revocation is uploading when the device-signed pairing lands. Like the test above, it passes on the released lock shape too.
#[test]
fn keyring_a_device_signed_pairing_during_a_revocations_upload_does_not_wedge_one_worker() {
    let rt = one_worker();
    let _g = rt.enter();
    let (objects, started) = Stall::new();
    let store = store_over(objects.clone(), Duration::ZERO);
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    let alice = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let carol = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
    assert!(service.trust_approver_key_durable("device:alice", &b64(&alice)).unwrap());
    objects.stall_put.store(true, Ordering::SeqCst);
    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (s, d) = (service.clone(), done.clone());
    rt.spawn(async move {
        let r = s.revoke_approver_key("device:alice");
        let _ = d.send(format!("revocation: {r:?}"));
    });
    started.recv_timeout(Duration::from_secs(10)).expect("the revocation's upload started");
    let (s, st, d, m) = (service.clone(), store.clone(), done.clone(), pairing("device:carol", &carol));
    rt.spawn(async move {
        let r = crate::rest::apply_mutation(st.as_ref(), &s, &m).map(|_| ());
        let _ = d.send(format!("pairing: {r:?}"));
    });
    canary(&rt, done);
    let answered = collect(&finished, 3, Duration::from_secs(5));
    objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("keyring revocation-then-pairing: answered={answered:?} after_release={after:?} waits={:?}", objects.counts());
    rt.shutdown_background();
    assert_eq!(answered.len(), 3, "wedged: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"pairing: Ok(())".to_string()), "{answered:?}");
    assert!(answered.contains(&"revocation: Ok(())".to_string()), "{answered:?}");
    service.refresh_keyring_now();
    assert!(service.approver_key_trusted("device:carol") && !service.approver_key_trusted("device:alice"));
}

/// The lock-order inversion on one worker with tasks: the revocation is stopped at its first fresh-read bucket check (timer-driven), and the device-signed pairing takes serial and the keyring lock meanwhile. With the release's order (keyring lock, then serial) this closes a cycle.
#[test]
fn keyring_lock_order_with_serial_holds_on_one_worker_with_a_timer_driven_bucket_check() {
    let rt = one_worker();
    let _g = rt.enter();
    let (objects, started) = Stall::new();
    let store = store_over(objects.clone(), Duration::from_secs(600));
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    let alice = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let carol = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
    assert!(service.trust_approver_key_durable("device:alice", &b64(&alice)).unwrap());
    std::thread::sleep(crate::store::persisted::FRESH_READ_INTERVAL + Duration::from_millis(100));
    objects.stall_head.store(true, Ordering::SeqCst);
    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (s, d) = (service.clone(), done.clone());
    rt.spawn(async move {
        let r = s.revoke_approver_key("device:alice");
        let _ = d.send(format!("revocation: {r:?}"));
    });
    let first = started.recv_timeout(Duration::from_secs(10)).expect("the revocation reached the bucket");
    let (s, st, d, m) = (service.clone(), store.clone(), done.clone(), pairing("device:carol", &carol));
    rt.spawn(async move {
        let r = crate::rest::apply_mutation(st.as_ref(), &s, &m).map(|_| ());
        let _ = d.send(format!("pairing: {r:?}"));
    });
    canary(&rt, done);
    let answered = collect(&finished, 3, Duration::from_secs(5));
    objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("keyring lock order: first_stall={first} answered={answered:?} after_release={after:?} waits={:?}", objects.counts());
    rt.shutdown_background();
    assert_eq!(answered.len(), 3, "wedged or deadlocked: only {answered:?} answered within 5 s");
    service.refresh_keyring_now();
    assert!(service.approver_key_trusted("device:carol") && !service.approver_key_trusted("device:alice"));
}

/// budget_book around AuditUsage::measure: the holder runs the product's section (lock_donating the book, then measure, whose read_grant_usage makes the fresh-read bucket check), and a real invoke waits for the book.
#[test]
fn budget_book_a_call_waiting_while_measure_waits_on_the_bucket_does_not_wedge_one_worker() {
    let rt = one_worker();
    let _g = rt.enter();
    let (objects, started) = Stall::new();
    let store = store_over(objects.clone(), Duration::from_secs(600));
    crate::seed::seed(store.as_ref()).unwrap();
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    let grants = store.list_grants().unwrap();
    let session = store.get_session("sess_demo").unwrap().expect("the seeded demo session");
    std::thread::sleep(crate::store::persisted::FRESH_READ_INTERVAL + Duration::from_millis(100));
    objects.stall_head.store(true, Ordering::SeqCst);

    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (s, d) = (service.clone(), done.clone());
    rt.spawn(async move {
        let book = crate::store::bridge::lock_donating(&s.budget_book).unwrap_or_else(|e| e.into_inner());
        let usage = AuditUsage::measure(s.store.as_ref(), &grants, now_ms()).map(|u| u.with_reserved(&book));
        drop(book);
        let _ = d.send(format!("holder measured: {}", usage.is_ok()));
    });
    let first = started.recv_timeout(Duration::from_secs(10)).expect("measure's read reached the bucket under the book");
    let (s, d) = (service.clone(), done.clone());
    rt.spawn(async move {
        let params = serde_json::json!({ "owner": "synthetic", "repo": "synthetic" });
        let out = s
            .invoke(&session, "github.pull_requests.create", &params, Some("synthetic"), ExecutionLocation::LocalOnly)
            .await;
        let _ = d.send(format!("invoke answered: {}", out.is_ok()));
    });
    canary(&rt, done);
    let answered = collect(&finished, 3, Duration::from_secs(5));
    let book_held = service.budget_book.try_lock().is_err();
    objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("budget_book: first_stall={first} answered={answered:?} after_release={after:?} book_held_at_5s={book_held} waits={:?}", objects.counts());
    rt.shutdown_background();
    assert_eq!(answered.len(), 3, "wedged: only {answered:?} answered within 5 s");
}
