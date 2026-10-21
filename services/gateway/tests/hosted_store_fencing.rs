//! Regressions for the three defects the 8 September 2026 review reproduced on gateway 1.3.15.
//! Each test is that review's probe with its assertion inverted, so the probe that proved the defect
//! is the test that proves the fix. Every credential, transport and KMS here is synthetic.
//!
//! The last two tests are the other cases that review asked for before it would call the fence
//! proven: a long revision overlap, where the instance that lost the store has not been told yet,
//! and a crash between a local commit and its upload.
#![cfg(feature = "sqlite")]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use permaura_core::ExecutionLocation;
use permaura_gateway::backend::{AuditKeyWrap, KmsClient};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use permaura_gateway::store::{Agent, Store};

struct FakeKms;
#[async_trait]
impl KmsClient for FakeKms {
    async fn decrypt(&self, _: &str, b: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, GatewayError> {
        Ok(zeroize::Zeroizing::new(b.iter().map(|x| x ^ 0x5a).collect()))
    }
    async fn encrypt(&self, _: &str, b: &[u8]) -> Result<Vec<u8>, GatewayError> {
        Ok(b.iter().map(|x| x ^ 0x5a).collect())
    }
}

fn dir(tag: &str) -> PathBuf {
    // A counter as well as the clock. Two tests share the tag `self-race`, cargo runs them in
    // parallel threads of one process, and `subsec_nanos` can hand both the same number: they then
    // open one database and one `store.db.snap`, and whichever persists second reads a staging file
    // the first has already removed. That is a collision between two tests, not a race either of
    // them is about.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("permaura-fencing-{}-{tag}-{nanos}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn open(tag: &str, objects: Arc<dyn ObjectStore>) -> PersistedSqliteStore {
    open_at(&dir(tag).join("store.db"), objects)
}

/// The same, at a path the caller keeps, so a test can reopen the file a dead process left behind.
fn open_at(path: &Path, objects: Arc<dyn ObjectStore>) -> PersistedSqliteStore {
    common::isolate_from_the_real_install();
    PersistedSqliteStore::open(
        &path.to_string_lossy(),
        objects,
        DEFAULT_OBJECT,
        Some(AuditKeyWrap { kms: Arc::new(FakeKms), key_id: "synthetic".into(), adopt_plaintext: false }),
    )
    .unwrap()
    .with_carry_floor(Duration::ZERO)
}

fn invoke_params() -> serde_json::Value {
    serde_json::json!({ "owner": "synthetic", "repo": "synthetic" })
}

/// An instance past its fresh-read window, holding a store another instance has since
/// moved on, must not use a credential. The attempt record it appends before executing forces an
/// upload, the upload meets the 412, and the instance exits with no upstream request made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_instance_makes_no_upstream_request() {
    let objects = Arc::new(MemoryObjectStore::new());
    let exited = Arc::new(AtomicBool::new(false));
    let mark = exited.clone();
    // A zero window is exactly the path an instance takes once its default 60 seconds have passed.
    let stale = Arc::new(
        open("stale", objects.clone())
            .with_fresh_read_window(Duration::ZERO)
            .with_on_stale(Box::new(move |_| mark.store(true, Ordering::SeqCst))),
    );
    permaura_gateway::seed::seed(stale.as_ref()).unwrap();
    let session = stale.get_session("sess_demo").unwrap().unwrap();
    let http = Arc::new(MockHttpClient::new());
    let service = EnforcementService::new(stale.clone(), http.clone());

    let winner = open("winner", objects.clone());
    let mut connection = winner.get_connection("github_acme").unwrap().unwrap();
    connection.disabled = true;
    winner.put_connection(connection).unwrap();

    let result = service
        .invoke(
            &session,
            "github.pull_requests.list",
            &invoke_params(),
            Some("synthetic stale-permission test"),
            ExecutionLocation::LocalOnly,
        )
        .await;
    assert_eq!(http.requests().len(), 0, "a durably disabled connection was never used");
    assert!(matches!(result, Err(GatewayError::StoreUnavailable(_))), "{:?}", result.as_ref().err());
    assert!(exited.load(Ordering::SeqCst), "the stale instance took the exit");
    assert_eq!(winner.audit_events(None).unwrap().len(), 0, "the winner's history is untouched");
}

/// Blocks inside `head` at a chosen moment so a test can order an upload around it.
struct HeldHead {
    inner: MemoryObjectStore,
    armed: AtomicBool,
    /// Hold before asking (the bucket answers after the upload) or after (it answered before).
    hold_before: bool,
    entered: mpsc::SyncSender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
}
impl HeldHead {
    fn hold(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.send(()).unwrap();
            self.resume.lock().unwrap().recv().unwrap();
        }
    }
}
impl ObjectStore for HeldHead {
    fn head(&self, n: &str) -> Result<Option<u64>, GatewayError> {
        if self.hold_before {
            self.hold();
            self.inner.head(n)
        } else {
            let answer = self.inner.head(n);
            self.hold();
            answer
        }
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
        g: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        self.inner.put_if_generation(n, b, g, metadata)
    }
    fn describe(&self) -> String {
        "synthetic-held-head".into()
    }
}

/// Both interleavings. A fresh instance's read check must never mistake this instance's
/// own concurrent upload for another owner, whether the bucket answered before or after it.
async fn own_upload_is_not_another_owner(hold_before: bool) {
    let (tx_enter, rx_enter) = mpsc::sync_channel(1);
    let (tx_resume, rx_resume) = mpsc::sync_channel(1);
    let objects = Arc::new(HeldHead {
        inner: MemoryObjectStore::new(),
        armed: AtomicBool::new(false),
        hold_before,
        entered: tx_enter,
        resume: Mutex::new(rx_resume),
    });
    let exited = Arc::new(AtomicBool::new(false));
    let mark = exited.clone();
    let store =
        Arc::new(open("self-race", objects.clone()).with_on_stale(Box::new(move |_| mark.store(true, Ordering::SeqCst))));
    store.put_agent(Agent::approved("a", "A", 0)).unwrap();

    objects.armed.store(true, Ordering::SeqCst);
    let reader = store.clone();
    let read = std::thread::spawn(move || reader.list_agents());
    rx_enter.recv_timeout(Duration::from_secs(10)).unwrap();
    // While the read is held inside `head`, this instance uploads a new generation.
    let writer = store.clone();
    let write = std::thread::spawn(move || writer.put_agent(Agent::approved("b", "B", 0)));
    if hold_before {
        // The write cannot finish while the read holds nothing, so it lands first; let it.
        write.join().unwrap().unwrap();
        tx_resume.send(()).unwrap();
    } else {
        tx_resume.send(()).unwrap();
        write.join().unwrap().unwrap();
    }
    let result = read.join().unwrap();

    assert_eq!(store.generation(), objects.inner.head(DEFAULT_OBJECT).unwrap().unwrap());
    assert!(result.is_ok(), "the check accepted its own new generation: {result:?}");
    assert!(!exited.load(Ordering::SeqCst), "no stale exit for a generation this instance moved itself");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_instance_does_not_exit_when_the_bucket_answers_after_its_own_upload() {
    own_upload_is_not_another_owner(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_instance_does_not_exit_when_the_bucket_answered_before_its_own_upload() {
    own_upload_is_not_another_owner(false).await;
}

/// And the case the check exists for still fires: the bucket genuinely ahead of this instance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_instance_still_exits_when_another_instance_has_written() {
    let objects = Arc::new(MemoryObjectStore::new());
    let a = open("owner-a", objects.clone());
    a.put_agent(Agent::approved("first", "A", 0)).unwrap();
    let exited = Arc::new(AtomicBool::new(false));
    let mark = exited.clone();
    let b = open("owner-b", objects.clone()).with_on_stale(Box::new(move |_| mark.store(true, Ordering::SeqCst)));
    assert_eq!(b.list_agents().unwrap().len(), 1);
    a.put_agent(Agent::approved("second", "A", 0)).unwrap();
    std::thread::sleep(permaura_gateway::store::persisted::FRESH_READ_INTERVAL);
    assert!(matches!(b.list_agents(), Err(GatewayError::StoreUnavailable(_))));
    assert!(exited.load(Ordering::SeqCst));
}

struct FailWrites {
    inner: MemoryObjectStore,
    fail: AtomicBool,
}
impl ObjectStore for FailWrites {
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
        g: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(GatewayError::Internal("synthetic storage outage".into()))
        } else {
            self.inner.put_if_generation(n, b, g, metadata)
        }
    }
    fn describe(&self) -> String {
        "synthetic-unavailable-writes".into()
    }
}

/// A write whose upload fails is the one write allowed to stand locally; nothing else
/// is. While the store is dirty it refuses every further write and every execution, says so, and
/// carries the limbo commit before the first write it accepts once storage is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dirty_store_refuses_execution_and_new_writes_until_it_has_carried_the_limbo_commit() {
    let objects = Arc::new(FailWrites { inner: MemoryObjectStore::new(), fail: AtomicBool::new(false) });
    let store = Arc::new(open("outage", objects.clone()).with_fresh_read_window(Duration::ZERO));
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let session = store.get_session("sess_demo").unwrap().unwrap();
    let mut connection = store.get_connection("github_acme").unwrap().unwrap();
    connection.disabled = true;
    store.put_connection(connection.clone()).unwrap();
    let durable = open("outage-durable", objects.clone());
    assert!(store.degraded().is_none());

    objects.fail.store(true, Ordering::SeqCst);
    connection.disabled = false;
    assert!(matches!(store.put_connection(connection), Err(GatewayError::StoreUnavailable(_))));
    assert!(durable.get_connection("github_acme").unwrap().unwrap().disabled, "the bucket still says disabled");
    // The one write in limbo: locally applied, reported failed, carried later. Documented, not hidden.
    assert!(!store.get_connection("github_acme").unwrap().unwrap().disabled);
    let degraded = store.degraded().expect("the store says it is degraded");
    assert!(degraded.contains("storage unavailable"), "{degraded}");

    // No second write joins the limbo: refused, and not applied.
    assert!(matches!(store.put_agent(Agent::approved("second", "S", 0)), Err(GatewayError::StoreUnavailable(_))));
    assert!(store.get_agent("second").unwrap().is_none(), "a refused write is not applied locally");

    // No execution either: the attempt record cannot be made durable, so the credential is not used.
    let http = Arc::new(MockHttpClient::new());
    let service = EnforcementService::new(store.clone(), http.clone());
    let result = service
        .invoke(
            &session,
            "github.pull_requests.list",
            &invoke_params(),
            Some("synthetic upload-outage test"),
            ExecutionLocation::LocalOnly,
        )
        .await;
    assert_eq!(http.requests().len(), 0, "nothing executed while durability could not be established");
    assert!(matches!(result, Err(GatewayError::StoreUnavailable(_))), "{:?}", result.as_ref().err());
    assert_eq!(durable.audit_events(None).unwrap().len(), 0);

    // Storage returns. The first accepted write carries the limbo commit ahead of itself.
    objects.fail.store(false, Ordering::SeqCst);
    store.put_agent(Agent::approved("after", "A", 0)).unwrap();
    assert!(store.degraded().is_none());
    let carried = open("outage-after", objects.clone());
    assert!(!carried.get_connection("github_acme").unwrap().unwrap().disabled, "the limbo commit was carried");
    assert!(carried.get_agent("after").unwrap().is_some());
    assert!(carried.get_agent("second").unwrap().is_none(), "the refused write never existed");
}

/// The attempt record is what makes the fence: every allowed execution leaves one before the
/// upstream call and the outcome after it, in that order, on the durable copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_allowed_execution_records_its_attempt_before_its_outcome() {
    let objects = Arc::new(MemoryObjectStore::new());
    let store = Arc::new(open("attempt", objects.clone()));
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let session = store.get_session("sess_demo").unwrap().unwrap();
    let http = Arc::new(MockHttpClient::new());
    let service = EnforcementService::new(store.clone(), http.clone());
    let before = objects.head(DEFAULT_OBJECT).unwrap().unwrap();
    service
        .invoke(&session, "github.pull_requests.list", &invoke_params(), Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    assert_eq!(http.requests().len(), 1);
    let durable = open("attempt-durable", objects.clone());
    let decisions: Vec<String> = durable
        .audit_events(None)
        .unwrap()
        .iter()
        .map(|e| e.payload.decision.clone())
        .collect();
    assert_eq!(decisions, vec!["attempt".to_string(), "allow".to_string()]);
    assert!(objects.head(DEFAULT_OBJECT).unwrap().unwrap() >= before + 2, "two uploads: the fence and the outcome");
}

/// A bucket whose metadata keeps answering with the generation this instance already agrees with.
///
/// That is what a long overlap looks like from inside the revision being replaced: the freshness
/// poll tells it nothing, because the answer it has is the answer it keeps getting. Conditional
/// writes still reach the real object, so the only thing that can catch the takeover is the fence.
/// `head_full` stays truthful because it is read only to prove ownership of an upload that went
/// unanswered, which is not what happens here.
struct PinnedMetadata {
    inner: Arc<MemoryObjectStore>,
    pinned: AtomicU64,
}

impl PinnedMetadata {
    fn pin(&self, generation: u64) {
        self.pinned.store(generation, Ordering::SeqCst);
    }
}

impl ObjectStore for PinnedMetadata {
    fn head(&self, n: &str) -> Result<Option<u64>, GatewayError> {
        match self.pinned.load(Ordering::SeqCst) {
            0 => self.inner.head(n),
            pinned => Ok(Some(pinned)),
        }
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
        g: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        self.inner.put_if_generation(n, b, g, metadata)
    }
    fn describe(&self) -> String {
        "synthetic-overlapping-revision".into()
    }
}

/// Long overlap, and revocation ordering inside it. Cloud Run keeps the revision being replaced
/// serving while the new one starts, and a request can outlive the sixty-second freshness window in
/// either direction, so the instance that lost the store may not be told for a while. The fence must
/// not depend on that timer: the attempt record every execution publishes before it uses a
/// credential meets the 412 by itself, and the connection the winning instance revoked is never
/// used even though this instance still reads it as enabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_overlapping_instance_makes_no_upstream_request_before_the_window_tells_it() {
    let inner = Arc::new(MemoryObjectStore::new());
    let objects = Arc::new(PinnedMetadata { inner: inner.clone(), pinned: AtomicU64::new(0) });
    let exited = Arc::new(AtomicBool::new(false));
    let mark = exited.clone();
    // The shipped window, not zero: this instance believes it is current, and is, until the write below.
    let overlapping = Arc::new(
        open("overlap", objects.clone()).with_on_stale(Box::new(move |_| mark.store(true, Ordering::SeqCst))),
    );
    permaura_gateway::seed::seed(overlapping.as_ref()).unwrap();
    let session = overlapping.get_session("sess_demo").unwrap().unwrap();
    let http = Arc::new(MockHttpClient::new());
    let service = EnforcementService::new(overlapping.clone(), http.clone());

    // It executes while it genuinely is current, which is what makes the second call a regression
    // rather than a store that never worked at all.
    service
        .invoke(&session, "github.pull_requests.list", &invoke_params(), Some("synthetic in-window call"), ExecutionLocation::LocalOnly)
        .await
        .expect("the current instance executes");
    assert_eq!(http.requests().len(), 1);
    objects.pin(overlapping.generation());

    // The revision that replaced it takes the store and revokes the connection.
    let winner = open("overlap-winner", inner.clone());
    let mut connection = winner.get_connection("github_acme").unwrap().unwrap();
    connection.disabled = true;
    winner.put_connection(connection).unwrap();
    let durable = winner.audit_events(None).unwrap().len();
    assert_eq!(durable, 2, "the winner restored the attempt and the outcome of the call that was allowed");

    // Nothing has told the overlapping instance, and it still reads the connection as enabled: the
    // decision it is about to make is made on state another instance has moved on from.
    assert!(!overlapping.get_connection("github_acme").unwrap().unwrap().disabled);
    let result = service
        .invoke(&session, "github.pull_requests.list", &invoke_params(), Some("synthetic overlap call"), ExecutionLocation::LocalOnly)
        .await;

    assert_eq!(http.requests().len(), 1, "the revoked connection was never used");
    assert!(matches!(result, Err(GatewayError::StoreUnavailable(_))), "{:?}", result.as_ref().err());
    assert!(exited.load(Ordering::SeqCst), "the overlapping instance took the exit");
    assert_eq!(winner.audit_events(None).unwrap().len(), durable, "and left nothing in the winner's history");
}

/// A crash between a local commit and its upload. Nothing acknowledged that commit, so it is not
/// durable, and the instance that comes back must present the bucket's store and not the file the
/// dead process left on disk: a write that exists on one instance's disk and nowhere else is the
/// one state a hosted worker may never serve. The write-ahead log is the way it would come back,
/// and a staging copy the crash stranded is the way the next upload would fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commit_that_never_reached_the_bucket_does_not_survive_a_crash() {
    let objects = Arc::new(FailWrites { inner: MemoryObjectStore::new(), fail: AtomicBool::new(false) });
    let path = dir("crash").join("store.db");
    {
        let store = open_at(&path, objects.clone());
        store.put_agent(Agent::approved("acknowledged", "A", 0)).unwrap();
        objects.fail.store(true, Ordering::SeqCst);
        assert!(matches!(store.put_agent(Agent::approved("limbo", "L", 0)), Err(GatewayError::StoreUnavailable(_))));
        assert!(store.get_agent("limbo").unwrap().is_some(), "the limbo commit stands on this instance");
        assert!(store.degraded().is_some(), "which is why the instance says it is degraded");
        // The process dies here. Nothing carries the limbo commit and nothing tidies up after it.
    }
    std::fs::write(format!("{}-wal", path.display()), b"a write-ahead log the crash left behind").unwrap();
    std::fs::write(format!("{}.snap", path.display()), b"a staging copy the crash left behind").unwrap();
    objects.fail.store(false, Ordering::SeqCst);
    let uploads = objects.inner.put_count();

    let rebooted = open_at(&path, objects.clone());
    assert!(rebooted.get_agent("acknowledged").unwrap().is_some(), "what the bucket acknowledged came back");
    assert!(rebooted.get_agent("limbo").unwrap().is_none(), "what it never acknowledged did not");
    assert!(!Path::new(&format!("{}-wal", path.display())).exists(), "and no stranded log can replay it back");
    assert!(rebooted.degraded().is_none(), "the store that came back is clean, not carrying a commit nobody has");
    assert_eq!(rebooted.generation(), objects.inner.head(DEFAULT_OBJECT).unwrap().unwrap());
    assert_eq!(objects.inner.put_count(), uploads, "and a boot that only restored uploaded nothing");

    // The stranded staging copy is not the next upload's problem either.
    rebooted.put_agent(Agent::approved("after", "B", 0)).unwrap();
    let carried = open("crash-after", objects.clone());
    assert!(carried.get_agent("after").unwrap().is_some(), "the first write after the crash is durable");
    assert!(carried.get_agent("limbo").unwrap().is_none(), "and did not carry a commit the crash lost");
}
