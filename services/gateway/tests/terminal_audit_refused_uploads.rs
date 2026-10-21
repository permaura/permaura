//! No execution is left without its terminal audit event because snapshot uploads are being
//! refused.
//!
//! A speed test on 7 October 2026 logged 13 executions whose terminal event "could not be
//! appended" while Cloud Storage answered 429 on `store.db`. The mechanism: one execution's fence
//! upload landed, then another request's upload was refused and left the store holding a local commit
//! it had not carried, and the first execution's terminal append, like every write, tried to carry
//! that commit first and gave up before recording anything. These reproduce it on a persisted store
//! over an object store the test can make refuse, and every credential and transport is synthetic.
#![cfg(feature = "sqlite")]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use permaura_core::ExecutionLocation;
use permaura_gateway::backend::{AuditKeyWrap, KmsClient};
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse};
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use permaura_gateway::store::{Session, Store};

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

/// A bucket that refuses uploads the way Cloud Storage does under a per-object write rate: when told
/// to, or every other upload while throttled. Reads always answer.
///
/// The throttle counts uploads rather than timing them. It used to refuse a write closer than 150 ms to
/// the last accepted one, and on a runner slow enough that consecutive uploads were already that far
/// apart it refused nothing, so the test that depends on it failed for want of a refusal.
struct Refusing {
    inner: MemoryObjectStore,
    refuse: AtomicBool,
    throttled: AtomicBool,
    uploads: AtomicU64,
    refused: AtomicU64,
}

impl Refusing {
    fn new() -> Self {
        Refusing {
            inner: MemoryObjectStore::new(),
            refuse: AtomicBool::new(false),
            throttled: AtomicBool::new(false),
            uploads: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }
}

impl ObjectStore for Refusing {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        self.inner.head(name)
    }
    fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        self.inner.head_full(name)
    }
    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        self.inner.has_history(name)
    }
    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        self.inner.get(name, generation)
    }
    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        // The real client retries a 429 three times with a growing wait; this does the same, scaled
        // down. A throttled upload is refused through every retry, as one that keeps landing inside
        // the per-object window would be.
        let throttled = self.throttled.load(Ordering::SeqCst) && self.uploads.fetch_add(1, Ordering::SeqCst) % 2 == 0;
        for wait_ms in [0u64, 5, 20, 80] {
            std::thread::sleep(Duration::from_millis(wait_ms));
            if self.refuse.load(Ordering::SeqCst) || throttled {
                continue;
            }
            return self.inner.put_if_generation(name, bytes, expected, metadata);
        }
        self.refused.fetch_add(1, Ordering::SeqCst);
        Err(GatewayError::Internal(format!("object store put gs://test/{name} returned 429")))
    }
    fn describe(&self) -> String {
        "gs://test".into()
    }
}

fn dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "permaura-refused-upload-{}-{tag}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn open(tag: &str, objects: Arc<dyn ObjectStore>) -> Arc<PersistedSqliteStore> {
    common::isolate_from_the_real_install();
    Arc::new(
        PersistedSqliteStore::open(
            &dir(tag).join("store.db").to_string_lossy(),
            objects,
            DEFAULT_OBJECT,
            Some(AuditKeyWrap { kms: Arc::new(FakeKms), key_id: "synthetic".into(), adopt_plaintext: false }),
        )
        .unwrap()
        .with_fresh_read_window(Duration::ZERO)
        .with_carry_floor(Duration::ZERO),
    )
}

/// What the bucket holds, read the way a replacement instance would: by restoring it.
fn durable_chain(objects: Arc<dyn ObjectStore>) -> Vec<String> {
    decisions(&open("restored", objects).audit_events(None).unwrap())
}

fn decisions(events: &[permaura_core::AuditEvent]) -> Vec<String> {
    events
        .iter()
        .filter(|e| e.payload.action == CAPABILITY)
        .map(|e| e.payload.decision.clone())
        .collect()
}

const CAPABILITY: &str = "github.pull_requests.list";

fn params() -> serde_json::Value {
    serde_json::json!({ "owner": "synthetic", "repo": "synthetic" })
}

/// Every `"attempt"` followed by exactly one terminal event, in order.
fn every_attempt_is_closed(chain: &[String]) -> bool {
    let mut open = 0i64;
    for decision in chain {
        match decision.as_str() {
            "attempt" => open += 1,
            "allow" | "error" | "approved" => {
                open -= 1;
                if open < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    open == 0
}

/// An upstream that, while the call is in flight, has the bucket start refusing and has another
/// request's write fail against it: the moment the speed test caught, with an execution already past its fence
/// and the store left holding a commit it could not carry.
struct RefusalArrivesMidCall {
    objects: Arc<Refusing>,
    store: OnceLock<Arc<dyn Store>>,
    sent: AtomicUsize,
}

#[async_trait]
impl HttpClient for RefusalArrivesMidCall {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        self.objects.refuse.store(true, Ordering::SeqCst);
        let other = self.store.get().expect("store wired").put_meta("another-request", "refused");
        assert!(other.is_err(), "the other request's write meets the refusal");
        Ok(HttpResponse::json(200, serde_json::json!({ "pulls": [] })))
    }
}

fn seeded_service(
    store: Arc<PersistedSqliteStore>,
    http: Arc<dyn HttpClient>,
) -> (EnforcementService, Session) {
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let session = store.get_session("sess_demo").unwrap().unwrap();
    let store: Arc<dyn Store> = store;
    (EnforcementService::new(store, http), session)
}

/// The speed test's mechanism, step by step. The terminal event is recorded on the instance even though an
/// earlier commit is still waiting, a new execution is refused before its upstream call while the
/// bucket refuses, and once the bucket answers again the event is in what it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_upload_never_costs_an_execution_its_terminal_event() {
    let objects = Arc::new(Refusing::new());
    let store = open("mid-call", objects.clone());
    let http = Arc::new(RefusalArrivesMidCall {
        objects: objects.clone(),
        store: OnceLock::new(),
        sent: AtomicUsize::new(0),
    });
    let _ = http.store.set(store.clone());
    let (service, session) = seeded_service(store.clone(), http.clone());

    let result = service
        .invoke(&session, CAPABILITY, &params(), Some("refused upload"), ExecutionLocation::LocalOnly)
        .await;
    assert_eq!(http.sent.load(Ordering::SeqCst), 1, "the call went upstream");
    assert!(
        matches!(&result, Err(GatewayError::StoreUnavailable(m)) if m.contains("recorded on this instance")),
        "the result is withheld until its record is durable, and the error says the record exists: {:?}",
        result.as_ref().err()
    );
    assert_eq!(
        decisions(&store.audit_events(None).unwrap()),
        ["attempt", "allow"],
        "the terminal event is recorded even though another commit was waiting to be carried"
    );
    assert_eq!(durable_chain(objects.clone()), ["attempt"], "and it is not durable yet");

    // While the bucket refuses, the next execution is refused at its fence: nothing goes upstream.
    let next = service
        .invoke(&session, CAPABILITY, &params(), Some("refused upload next"), ExecutionLocation::LocalOnly)
        .await;
    assert!(matches!(next, Err(GatewayError::StoreUnavailable(_))), "{:?}", next.err());
    assert_eq!(http.sent.load(Ordering::SeqCst), 1, "no upstream call without a durable attempt");

    objects.refuse.store(false, Ordering::SeqCst);
    assert!(store.carry_pending().unwrap(), "the waiting commit is carried");
    assert_eq!(durable_chain(objects.clone()), ["attempt", "allow"]);
    assert!(store.degraded().is_none());
}

/// Nothing else needs to write for the waiting event to become durable: the carrier takes it as
/// soon as the bucket answers again, so an instance that goes quiet after a burst of 429s does not
/// hold its terminal events only in memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_carrier_makes_a_waiting_terminal_event_durable_without_another_write() {
    let objects = Arc::new(Refusing::new());
    let store = open("carrier", objects.clone());
    let http = Arc::new(RefusalArrivesMidCall {
        objects: objects.clone(),
        store: OnceLock::new(),
        sent: AtomicUsize::new(0),
    });
    let _ = http.store.set(store.clone());
    let (service, session) = seeded_service(store.clone(), http.clone());
    let _ = service
        .invoke(&session, CAPABILITY, &params(), Some("refused upload"), ExecutionLocation::LocalOnly)
        .await;
    assert_eq!(durable_chain(objects.clone()), ["attempt"]);

    let carrier = permaura_gateway::spawn_store_carrier(store.clone(), Duration::from_millis(20));
    objects.refuse.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    while store.degraded().is_some() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    carrier.abort();
    assert_eq!(durable_chain(objects), ["attempt", "allow"]);
}

/// An upstream that takes a little while, so concurrent executions overlap their uploads.
struct Slow;
#[async_trait]
impl HttpClient for Slow {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        tokio::time::sleep(Duration::from_millis(15)).await;
        Ok(HttpResponse::json(200, serde_json::json!({ "pulls": [] })))
    }
}

/// Many executions at once against a bucket that refuses every other upload through all its retries,
/// which is the per-object write rate in miniature. Some executions are refused at their fence
/// and some results are withheld, but every attempt is closed by exactly one terminal event, on the
/// instance at once and in the bucket once it has carried them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_induced_429s_every_attempt_keeps_its_terminal_event() {
    let objects = Arc::new(Refusing::new());
    let store = open("induced", objects.clone());
    let (service, session) = seeded_service(store.clone(), Arc::new(Slow));
    let service = Arc::new(service);
    // Seeding writes many times in a row, so the throttle starts after it.
    objects.throttled.store(true, Ordering::SeqCst);

    let mut handles = Vec::new();
    for round in 0..8 {
        for i in 0..6 {
            let (service, session) = (service.clone(), session.clone());
            handles.push(tokio::spawn(async move {
                let reason = format!("r{round}-{i}");
                service.invoke(&session, CAPABILITY, &params(), Some(&reason), ExecutionLocation::LocalOnly).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (mut ran, mut withheld) = (0, 0);
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => ran += 1,
            Err(GatewayError::StoreUnavailable(_)) => withheld += 1,
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert!(ran > 0, "some executions completed");
    assert!(objects.refused.load(Ordering::SeqCst) > 0, "the bucket did refuse ({withheld} refused or withheld)");

    let local = decisions(&store.audit_events(None).unwrap());
    assert!(local.iter().any(|d| d == "attempt"));
    assert!(every_attempt_is_closed(&local), "on the instance: {local:?}");

    objects.throttled.store(false, Ordering::SeqCst);
    assert!(store.carry_pending().unwrap(), "the bucket answers again and everything waiting is carried");
    let durable = durable_chain(objects);
    assert_eq!(durable, local, "the bucket holds exactly what the instance recorded");
}
