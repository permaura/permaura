//! A service-level `std::sync::Mutex` held across a hosted store upload, on one runtime worker.
//!
//! The first four tests are the original reproduction, kept as they first ran. Modelled on `store::persisted::tests::a_read_inside_a_transaction_on_a_fresh_instance_does_not_wedge_one_worker`.

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

/// Uploads, once armed, answer only after a runtime timer, as GcsObjectStore's PUT answers only through the I/O driver.
struct HeldPut {
    inner: MemoryObjectStore,
    armed: AtomicBool,
    started: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    release: tokio::sync::watch::Sender<bool>,
    puts_started: AtomicU64,
    puts_finished: AtomicU64,
}

impl HeldPut {
    fn new(started: std::sync::mpsc::Sender<()>) -> Self {
        HeldPut {
            inner: MemoryObjectStore::new(),
            armed: AtomicBool::new(false),
            started: std::sync::Mutex::new(Some(started)),
            release: tokio::sync::watch::channel(false).0,
            puts_started: AtomicU64::new(0),
            puts_finished: AtomicU64::new(0),
        }
    }
}

impl ObjectStore for HeldPut {
    fn head(&self, n: &str) -> Result<Option<u64>, GatewayError> {
        self.inner.head(n)
    }
    fn head_full(&self, n: &str) -> Result<Option<ObjectHead>, GatewayError> {
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
        if self.armed.load(Ordering::SeqCst) {
            self.puts_started.fetch_add(1, Ordering::SeqCst);
            if let Some(tx) = self.started.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let mut released = self.release.subscribe();
            crate::store::bridge::block_on(async move {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                    _ = released.wait_for(|r| *r) => {}
                }
            });
            self.puts_finished.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.put_if_generation(n, b, e, m)
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

fn pending(id: &str) -> PendingApproval {
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
        required_tier: "device_signed".into(),
        required_signatures: 2,
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

fn b64_public(sk: &ed25519_dalek::SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
}

struct Rig {
    objects: Arc<HeldPut>,
    store: Arc<dyn Store>,
    service: Arc<EnforcementService>,
    ring: ApproverKeyring,
    alice: ed25519_dalek::SigningKey,
    bob: ed25519_dalek::SigningKey,
    started_rx: std::sync::mpsc::Receiver<()>,
}

impl Rig {
    fn arm(&self) {
        self.objects.armed.store(true, Ordering::SeqCst);
    }

    fn signers(&self, id: &str) -> Vec<String> {
        self.store
            .get_approval(id)
            .unwrap()
            .expect("the approval is still there")
            .signatures
            .into_iter()
            .map(|s| s.approver)
            .collect()
    }
}

/// The rig, armed: every upload from here on waits for a runtime timer.
fn rig(tag: &str) -> Rig {
    let r = unarmed_rig(tag);
    r.arm();
    r
}

fn unarmed_rig(tag: &str) -> Rig {
    let dir = std::env::temp_dir().join(format!("store-lock-rig-{tag}-{}", short_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let objects = Arc::new(HeldPut::new(started_tx));
    let store: Arc<dyn Store> = Arc::new(
        PersistedSqliteStore::open(dir.join("gw.db").to_str().unwrap(), objects.clone(), "store.db", None)
            .unwrap()
            .with_fresh_read_window(Duration::ZERO)
            .with_on_stale(Box::new(|_| {})),
    );
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    service.set_accept_v1_device_signatures(true);
    service.set_require_display_bound_approvals(false);
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
    store.put_approval(pending("appr_x")).unwrap();
    store.put_approval(pending("appr_y")).unwrap();
    let alice = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let bob = ed25519_dalek::SigningKey::from_bytes(&[22; 32]);
    let mut ring = ApproverKeyring::new();
    assert!(ring.add_for("device:alice", b64_public(&alice), Some("person-a".into())));
    assert!(ring.add_for("device:bob", b64_public(&bob), Some("person-b".into())));
    Rig { objects, store, service, ring, alice, bob, started_rx }
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

/// Collect up to `want` answers until `deadline`.
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

/// Sign `id` as `who` on a spawned task, reporting the outcome on `done`.
fn spawn_signature(r: &Rig, who: &str, sk: &ed25519_dalek::SigningKey, id: &str, done: &std::sync::mpsc::Sender<String>) {
    let (s, ring, d, res, label) =
        (r.service.clone(), r.ring.clone(), done.clone(), signed(sk, &format!("device:{who}"), id), who.to_string());
    tokio::spawn(async move {
        let o = s.verify_signed_approval(&ring, &res);
        let _ = d.send(format!("{label}: {}", outcome_name(&o)));
    });
}

/// A third task with no store or lock work at all: if it never runs, no worker is polling anything.
fn spawn_canary(done: std::sync::mpsc::Sender<String>) {
    std::thread::sleep(Duration::from_millis(50));
    tokio::spawn(async move {
        let _ = done.send("canary".to_string());
    });
}

/// The wedge itself: Bob's signature arrives while Alice's upload is in flight under `signature_lock`.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_second_signature_while_the_first_uploads_does_not_wedge_one_worker() {
    let r = rig("wedge");
    let (done, finished) = std::sync::mpsc::channel::<String>();
    let bob_polled = Arc::new(AtomicBool::new(false));

    spawn_signature(&r, "alice", &r.alice, "appr_x", &done);
    r.started_rx.recv_timeout(Duration::from_secs(10)).expect("alice's upload started");
    let (s, ring, d, res, polled) =
        (r.service.clone(), r.ring.clone(), done.clone(), signed(&r.bob, "device:bob", "appr_y"), bob_polled.clone());
    tokio::spawn(async move {
        polled.store(true, Ordering::SeqCst);
        let o = s.verify_signed_approval(&ring, &res);
        let _ = d.send(format!("bob: {}", outcome_name(&o)));
    });
    spawn_canary(done);

    let answered = collect(&finished, 3, Duration::from_secs(5));
    let lock_held = r.service.signature_lock.try_lock().is_err();
    eprintln!(
        "store-lock wedge: answered={answered:?} bob_polled={} signature_lock_held={lock_held} puts_started={} puts_finished={}",
        bob_polled.load(Ordering::SeqCst),
        r.objects.puts_started.load(Ordering::SeqCst),
        r.objects.puts_finished.load(Ordering::SeqCst),
    );
    r.objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("store-lock wedge: after release, answered={after:?}");
    assert_eq!(answered.len(), 3, "the worker wedged: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"alice: AwaitingSignatures 1/2".to_string()), "{answered:?}");
    assert!(answered.contains(&"bob: AwaitingSignatures 1/2".to_string()), "{answered:?}");
    assert_eq!(r.signers("appr_x"), vec!["device:alice"], "alice's signature is recorded");
    assert_eq!(r.signers("appr_y"), vec!["device:bob"], "bob's signature is recorded");
}

/// Control: the same harness with Bob's signature arriving only after Alice's has answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn control_a_second_signature_after_the_first_has_answered_completes_on_one_worker() {
    let r = rig("control");
    let (done, finished) = std::sync::mpsc::channel::<String>();
    spawn_signature(&r, "alice", &r.alice, "appr_x", &done);
    r.started_rx.recv_timeout(Duration::from_secs(10)).expect("alice's upload started");
    let first = collect(&finished, 1, Duration::from_secs(5));
    assert_eq!(first.len(), 1, "alice alone did not answer: the harness itself wedges");
    spawn_signature(&r, "bob", &r.bob, "appr_y", &done);
    let second = collect(&finished, 1, Duration::from_secs(5));
    r.objects.release.send_replace(true);
    eprintln!(
        "store-lock control: first={first:?} second={second:?} puts_started={} puts_finished={}",
        r.objects.puts_started.load(Ordering::SeqCst),
        r.objects.puts_finished.load(Ordering::SeqCst),
    );
    assert_eq!(second.len(), 1, "bob after alice did not answer");
    assert!(first[0].starts_with("alice: AwaitingSignatures 1/2"), "{first:?}");
    assert!(second[0].starts_with("bob: AwaitingSignatures 1/2"), "{second:?}");
}

/// Control: during Alice's upload, Bob's pre-lock work (steps 1 to 9 are reads) answers, so the store is not what parks the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn control_reads_during_the_upload_answer() {
    let r = rig("reads");
    let (done, finished) = std::sync::mpsc::channel::<String>();
    spawn_signature(&r, "alice", &r.alice, "appr_x", &done);
    r.started_rx.recv_timeout(Duration::from_secs(10)).expect("alice's upload started");
    let (s, d) = (r.service.clone(), done);
    tokio::spawn(async move {
        let _ = s.reconciliation();
        let _ = s.device_signature_version_refusal("device:bob", None);
        let p = s.store.get_approval("appr_y").unwrap().unwrap();
        let _ = s.store.get_session(&p.session_id);
        let _ = d.send("reads".to_string());
    });
    let answered = collect(&finished, 2, Duration::from_secs(5));
    r.objects.release.send_replace(true);
    eprintln!("store-lock reads control: answered={answered:?}");
    assert_eq!(answered.len(), 2, "reads wedged too: {answered:?}");
}

/// `signature_lock` is free while a signature uploads: a task that takes only the lock during Alice's upload answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_signature_lock_is_not_held_while_a_signature_uploads() {
    let r = rig("lock-only");
    let (done, finished) = std::sync::mpsc::channel::<String>();
    spawn_signature(&r, "alice", &r.alice, "appr_x", &done);
    r.started_rx.recv_timeout(Duration::from_secs(10)).expect("alice's upload started");
    let (s, d) = (r.service.clone(), done);
    tokio::spawn(async move {
        let _g = s.signature_lock.lock().unwrap();
        let _ = d.send("lock-only".to_string());
    });
    let answered = collect(&finished, 2, Duration::from_secs(5));
    r.objects.release.send_replace(true);
    let after = collect(&finished, 2 - answered.len(), Duration::from_secs(10));
    eprintln!("store-lock lock-only: answered={answered:?} after release={after:?}");
    assert_eq!(answered.len(), 2, "taking signature_lock alone wedged the worker: {answered:?}");
}

/// The re-tap: the phone gave up on Alice's first delivery while its upload stalled, and the identical signature arrives again.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_redelivered_identical_signature_during_the_upload_answers_and_counts_once() {
    let r = rig("redelivered");
    let (done, finished) = std::sync::mpsc::channel::<String>();
    let first = signed(&r.alice, "device:alice", "appr_x");
    let again = first.clone();
    let (s, ring, d) = (r.service.clone(), r.ring.clone(), done.clone());
    tokio::spawn(async move {
        let o = s.verify_signed_approval(&ring, &first);
        let _ = d.send(format!("first: {}", outcome_name(&o)));
    });
    r.started_rx.recv_timeout(Duration::from_secs(10)).expect("alice's upload started");
    let (s, ring, d) = (r.service.clone(), r.ring.clone(), done.clone());
    tokio::spawn(async move {
        let o = s.verify_signed_approval(&ring, &again);
        let _ = d.send(format!("again: {}", outcome_name(&o)));
    });
    spawn_canary(done);

    let answered = collect(&finished, 3, Duration::from_secs(5));
    r.objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("store-lock redelivered: answered={answered:?} after release={after:?}");
    assert_eq!(answered.len(), 3, "the worker wedged: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"first: AwaitingSignatures 1/2".to_string()), "{answered:?}");
    assert!(answered.contains(&"again: AwaitingSignatures 1/2".to_string()), "{answered:?}");
    assert_eq!(r.signers("appr_x"), vec!["device:alice"], "the re-delivered signature is counted once");
}

/// The two-person rule: Bob signs the approval Alice's signature is still uploading for.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_second_person_signing_during_the_first_upload_completes_the_quorum() {
    let r = rig("two-person");
    let (done, finished) = std::sync::mpsc::channel::<String>();
    spawn_signature(&r, "alice", &r.alice, "appr_x", &done);
    r.started_rx.recv_timeout(Duration::from_secs(10)).expect("alice's upload started");
    spawn_signature(&r, "bob", &r.bob, "appr_x", &done);
    spawn_canary(done);

    let answered = collect(&finished, 3, Duration::from_secs(5));
    r.objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("store-lock two-person: answered={answered:?} after release={after:?}");
    assert_eq!(answered.len(), 3, "the worker wedged: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"alice: AwaitingSignatures 1/2".to_string()), "{answered:?}");
    assert!(answered.contains(&"bob: Verified".to_string()), "exactly the second signer completes it: {answered:?}");
    assert_eq!(r.signers("appr_x"), vec!["device:alice", "device:bob"], "both signatures are recorded");
}

/// A console revocation arriving while a pairing's keyring write uploads.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_revocation_overlapping_a_pairing_upload_does_not_wedge_one_worker() {
    let r = unarmed_rig("keyring");
    assert!(r.service.trust_approver_key_durable("device:alice", &b64_public(&r.alice)).unwrap());
    r.arm();
    let carol = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (s, d, key) = (r.service.clone(), done.clone(), b64_public(&carol));
    tokio::spawn(async move {
        let paired = s.trust_approver_key_durable("device:carol", &key);
        let _ = d.send(format!("pairing: {paired:?}"));
    });
    r.started_rx.recv_timeout(Duration::from_secs(10)).expect("the pairing's upload started");
    let (s, d) = (r.service.clone(), done.clone());
    tokio::spawn(async move {
        let revoked = s.revoke_approver_key("device:alice");
        let _ = d.send(format!("revocation: {revoked:?}"));
    });
    spawn_canary(done);

    let answered = collect(&finished, 3, Duration::from_secs(5));
    r.objects.release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("store-lock keyring: answered={answered:?} after release={after:?}");
    assert_eq!(answered.len(), 3, "the worker wedged: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"pairing: Ok(true)".to_string()), "{answered:?}");
    assert!(answered.contains(&"revocation: Ok(())".to_string()), "{answered:?}");
    r.service.refresh_keyring_now();
    assert!(r.service.approver_key_trusted("device:carol"), "the pairing is in the store");
    assert!(!r.service.approver_key_trusted("device:alice"), "and so is the revocation");
}

/// `budget_book`: a call that reaches the policy engine while another holds the book across a read that only a runtime worker can answer (the fresh-read window's generation check).
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_call_waiting_for_the_budget_book_does_not_wedge_one_worker() {
    let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
    crate::seed::seed(store.as_ref()).unwrap();
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (holding, held) = std::sync::mpsc::channel::<()>();
    let release = tokio::sync::watch::channel(false).0;
    let (book, d, mut released) = (service.budget_book.clone(), done.clone(), release.subscribe());
    tokio::spawn(async move {
        let _book = book.lock().unwrap();
        let _ = holding.send(());
        crate::store::bridge::block_on(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                _ = released.wait_for(|r| *r) => {}
            }
        });
        let _ = d.send("holder".to_string());
    });
    held.recv_timeout(Duration::from_secs(10)).expect("the holder took the book");
    let (s, d) = (service.clone(), done.clone());
    tokio::spawn(async move {
        let session = s.store.get_session("sess_demo").unwrap().unwrap();
        let params = serde_json::json!({ "owner": "synthetic", "repo": "synthetic" });
        let out = s
            .invoke(&session, "github.pull_requests.create", &params, Some("synthetic"), ExecutionLocation::LocalOnly)
            .await;
        let _ = d.send(format!("invoke answered: {}", out.is_ok()));
    });
    spawn_canary(done);

    let answered = collect(&finished, 3, Duration::from_secs(5));
    release.send_replace(true);
    let after = collect(&finished, 3 - answered.len(), Duration::from_secs(10));
    eprintln!("budget_book: answered={answered:?} after release={after:?}");
    assert_eq!(answered.len(), 3, "the worker wedged: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"invoke answered: true".to_string()), "{answered:?}");
}

/// Generation checks that, once armed, report that they started and then wait for the test to release them, so a caller can be stopped at its first bucket read holding whatever it has taken by then.
struct GatedHead {
    inner: MemoryObjectStore,
    armed: AtomicBool,
    entered: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    open: (std::sync::Mutex<bool>, std::sync::Condvar),
}

impl GatedHead {
    fn new(entered: std::sync::mpsc::Sender<()>) -> Self {
        GatedHead {
            inner: MemoryObjectStore::new(),
            armed: AtomicBool::new(false),
            entered: std::sync::Mutex::new(Some(entered)),
            open: (std::sync::Mutex::new(false), std::sync::Condvar::new()),
        }
    }

    fn gate(&self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        if let Some(tx) = self.entered.lock().unwrap().take() {
            let _ = tx.send(());
        }
        let (lock, opened) = &self.open;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = opened.wait(open).unwrap();
        }
    }

    fn release(&self) {
        *self.open.0.lock().unwrap() = true;
        self.open.1.notify_all();
    }
}

impl ObjectStore for GatedHead {
    fn head(&self, n: &str) -> Result<Option<u64>, GatewayError> {
        self.gate();
        self.inner.head(n)
    }
    fn head_full(&self, n: &str) -> Result<Option<ObjectHead>, GatewayError> {
        self.gate();
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
        self.inner.put_if_generation(n, b, e, m)
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

/// A console revocation, made outside any transaction, against a device-signed pairing applied inside one (`rest::apply_mutation`).
/// They took `serial` and `keyring_write_lock` in opposite orders: the revocation held the keyring lock while its first store read asked the bucket, the pairing took `serial` and waited for the keyring lock, and the revocation's read then waited for `serial` for ever.
/// Plain threads rather than tasks, because the cycle is between two locks and needs no runtime to close, and a deadlocked runtime could not be dropped.
#[test]
fn a_revocation_and_a_pairing_applied_in_a_transaction_do_not_deadlock() {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let handle = runtime.handle().clone();
    let dir = std::env::temp_dir().join(format!("revocation-pairing-{}", short_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let objects = Arc::new(GatedHead::new(entered_tx));
    let store: Arc<dyn Store> = Arc::new(
        PersistedSqliteStore::open(dir.join("gw.db").to_str().unwrap(), objects.clone(), "store.db", None)
            .unwrap()
            .with_fresh_read_window(Duration::from_secs(600))
            .with_on_stale(Box::new(|_| {})),
    );
    let service = {
        let _runtime = handle.enter();
        Arc::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())))
    };
    let alice = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let carol = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
    assert!(service.trust_approver_key_durable("device:alice", &b64_public(&alice)).unwrap());
    // Past the fresh-read throttle, so the revocation's first store read asks the bucket.
    std::thread::sleep(crate::store::persisted::FRESH_READ_INTERVAL + Duration::from_millis(100));
    objects.armed.store(true, Ordering::SeqCst);

    let (done, finished) = std::sync::mpsc::channel::<String>();
    let (s, d, h) = (service.clone(), done.clone(), handle.clone());
    std::thread::spawn(move || {
        let _runtime = h.enter();
        let revoked = s.revoke_approver_key("device:alice");
        let _ = d.send(format!("revocation: {revoked:?}"));
    });
    entered.recv_timeout(Duration::from_secs(10)).expect("the revocation's first store read reached the bucket");
    let (s, st, d, h, key) = (service.clone(), store.clone(), done, handle.clone(), b64_public(&carol));
    std::thread::spawn(move || {
        let _runtime = h.enter();
        let pairing = crate::policy_guard::Mutation::ApproverKeyTrust {
            approver_id: "device:carol".into(),
            approver_pubkey: key,
            person: None,
            replaces: None,
        };
        let applied = crate::rest::apply_mutation(st.as_ref(), &s, &pairing).map(|_| ());
        let _ = d.send(format!("pairing: {applied:?}"));
    });
    std::thread::sleep(Duration::from_millis(200));
    objects.release();

    let answered = collect(&finished, 2, Duration::from_secs(5));
    eprintln!("lock-order inversion: answered={answered:?}");
    runtime.shutdown_background();
    assert_eq!(answered.len(), 2, "deadlocked: only {answered:?} answered within 5 s");
    assert!(answered.contains(&"revocation: Ok(())".to_string()), "{answered:?}");
    assert!(answered.contains(&"pairing: Ok(())".to_string()), "{answered:?}");
    service.refresh_keyring_now();
    assert!(service.approver_key_trusted("device:carol"), "the pairing landed");
    assert!(!service.approver_key_trusted("device:alice"), "and so did the revocation");
}
