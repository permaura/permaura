//! Work that can run for seconds or minutes must not hold the store's `serial` lock, because `/health` answers 503 when the store has not answered within its bound and a hosted worker that fails the probe is restarted mid-work.

use crate::archive::AuditArchive;
use crate::connectors::MockHttpClient;
use crate::error::GatewayError;
use crate::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use crate::service::EnforcementService;
use crate::store::persisted::PersistedSqliteStore;
use crate::store::sqlite::SqliteStore;
use crate::store::{GrantCharge, GrantWindow, Session, SessionRole, Store};
use crate::AppState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::AuditPayload;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt;

const TOKEN: &str = "tok_long_hold_operator";

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("long-hold-{tag}-{}", crate::service::short_id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn operator(store: &dyn Store) {
    store
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_long_hold".into(),
            agent_id: "operator".into(),
            user_id: None,
            device_id: None,
            token: TOKEN.into(),
            role: SessionRole::Operator,
            created_at: crate::store::now_ms(),
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
}

fn charge(store: &dyn Store, n: usize) {
    for i in 0..n {
        let grant = if i % 3 == 0 { "g_a" } else { "g_b" };
        let mut payload = AuditPayload::new(format!("cap.{i}"), "conn", "allow");
        payload.agent_id = Some(format!("agent-{}", i % 2));
        payload.summary = serde_json::json!({ "grant_id": grant });
        store.append_audit_charged(payload, Some(GrantCharge::new(grant))).unwrap();
    }
}

fn usage(store: &dyn Store) -> Vec<u64> {
    ["g_a", "g_b"]
        .iter()
        .map(|g| store.read_grant_usage(&[GrantWindow { grant_id: g, since_ms: i64::MIN }]).unwrap().total(g))
        .collect()
}

async fn send(router: axum::Router, method: &str, uri: &str, bearer: bool) -> (StatusCode, Duration) {
    let mut req = Request::builder().method(method).uri(uri);
    if bearer {
        req = req.header("authorization", format!("Bearer {TOKEN}"));
    }
    let started = Instant::now();
    let resp = router.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    (resp.status(), started.elapsed())
}

/// Archive segment reads that, once armed, take five seconds: a Cloud Storage fetch on a bad day, and longer than the probe's bound.
struct SlowSegments {
    inner: MemoryObjectStore,
    armed: AtomicBool,
    started: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl ObjectStore for SlowSegments {
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
        if n.ends_with(".ndjson") && self.armed.load(Ordering::SeqCst) {
            if let Some(tx) = self.started.lock().unwrap().take() {
                let _ = tx.send(());
            }
            std::thread::sleep(Duration::from_secs(5));
        }
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
        "slow-segments".into()
    }
}

/// The rebuild reads every archived segment, and while it does the probe answers and an authenticated read is served, on the one runtime worker a hosted instance has.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_usage_rebuild_reading_a_slow_archive_holds_neither_the_probe_nor_a_read() {
    let dir = scratch("rebuild");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(dir.join("gw.db").to_str().unwrap()).unwrap());
    rebuild_holds_neither_the_probe_nor_a_read(store).await;
    std::fs::remove_dir_all(&dir).ok();
}

/// The same over the hosted store, whose rebuild used to run the whole walk inside `mutate`.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_hosted_usage_rebuild_reading_a_slow_archive_holds_neither_the_probe_nor_a_read() {
    let dir = scratch("rebuild-hosted");
    let store: Arc<dyn Store> = Arc::new(
        PersistedSqliteStore::open(dir.join("gw.db").to_str().unwrap(), Arc::new(MemoryObjectStore::new()), "store.db", None)
            .unwrap()
            .with_fresh_read_window(Duration::ZERO)
            .with_on_stale(Box::new(|_| {})),
    );
    rebuild_holds_neither_the_probe_nor_a_read(store).await;
    std::fs::remove_dir_all(&dir).ok();
}

async fn rebuild_holds_neither_the_probe_nor_a_read(store: Arc<dyn Store>) {
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let objects = Arc::new(SlowSegments {
        inner: MemoryObjectStore::new(),
        armed: AtomicBool::new(false),
        started: std::sync::Mutex::new(Some(started_tx)),
    });
    let archive = Arc::new(AuditArchive::with_limits(objects.clone(), "acme", "audit", 4, 2));
    let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())).with_audit_archive(archive.clone());
    let router = crate::build_router(AppState::new(service), "127.0.0.1:7376".parse().unwrap());
    operator(store.as_ref());
    charge(store.as_ref(), 8);
    assert!(archive.run_pass(store.as_ref()).unwrap().segment_id.is_some(), "one segment is archived");
    let before = usage(store.as_ref());
    objects.armed.store(true, Ordering::SeqCst);

    let finished = Arc::new(AtomicBool::new(false));
    let rebuild = {
        let (router, finished) = (router.clone(), finished.clone());
        tokio::spawn(async move {
            let out = send(router, "POST", "/v1/grants/rebuild-usage", true).await;
            finished.store(true, Ordering::SeqCst);
            out
        })
    };
    tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .expect("the rebuild reached the archive");

    let probe = {
        let (router, finished) = (router.clone(), finished.clone());
        tokio::spawn(async move { (send(router, "GET", "/health", false).await, finished.load(Ordering::SeqCst)) })
    };
    let read = {
        let (router, finished) = (router.clone(), finished.clone());
        tokio::spawn(async move { (send(router, "GET", "/v1/agents", true).await, finished.load(Ordering::SeqCst)) })
    };
    let ((probe_status, probe_took), rebuilt_before_probe) = probe.await.unwrap();
    let ((read_status, read_took), rebuilt_before_read) = read.await.unwrap();
    assert_eq!(probe_status, StatusCode::OK, "the probe answered {probe_status} after {probe_took:?}");
    assert!(probe_took < crate::rest::HEALTH_STORE_BOUND, "the probe took {probe_took:?}");
    assert!(!rebuilt_before_probe, "the probe answered while the rebuild was still reading the archive");
    assert_eq!(read_status, StatusCode::OK);
    assert!(!rebuilt_before_read, "the read was served while the rebuild was still reading the archive, not after it ({read_took:?})");

    let (status, _) = rebuild.await.unwrap();
    assert_eq!(status, StatusCode::OK, "the rebuild itself completes");
    assert_eq!(usage(store.as_ref()), before, "and refiles exactly what the counter held");
}

// ── an authenticated /health verifies the audit chain ────────────────────────────────────────────

fn router_over(store: Arc<dyn Store>) -> axum::Router {
    let service = EnforcementService::new(store, Arc::new(MockHttpClient::new()));
    crate::build_router(AppState::new(service), "127.0.0.1:7376".parse().unwrap())
}

async fn health(router: axum::Router, bearer: bool) -> (StatusCode, serde_json::Value, Duration) {
    let mut req = Request::builder().uri("/health");
    if bearer {
        req = req.header("authorization", format!("Bearer {TOKEN}"));
    }
    let started = Instant::now();
    let resp = router.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null), started.elapsed())
}

/// The first authenticated `/health` after a cold start checks every held event, 20,000 here, and while it does the probe answers within its bound, on the one runtime worker a hosted instance has.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn an_authenticated_health_verifying_the_chain_does_not_hold_the_probe() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    operator(store.as_ref());
    for i in 0..20_000 {
        store.append_audit(AuditPayload::new(format!("cap.{i}"), "conn", "allow")).unwrap();
    }
    let router = router_over(store.clone());

    let verified = Arc::new(AtomicBool::new(false));
    let full = {
        let (router, verified) = (router.clone(), verified.clone());
        tokio::spawn(async move {
            let out = health(router, true).await;
            verified.store(true, Ordering::SeqCst);
            out
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let probe = {
        let (router, verified) = (router.clone(), verified.clone());
        tokio::spawn(async move { (health(router, false).await, verified.load(Ordering::SeqCst)) })
    };

    let ((status, _, took), verified_first) = probe.await.unwrap();
    let (full_status, body, full_took) = full.await.unwrap();
    assert_eq!(status, StatusCode::OK, "the probe answered {status} after {took:?}");
    assert!(took < crate::rest::HEALTH_STORE_BOUND, "the probe took {took:?}");
    assert!(
        !verified_first,
        "the probe answered while the authenticated /health was still verifying, not after it ({took:?} against {full_took:?})"
    );
    assert_eq!(full_status, StatusCode::OK);
    assert_eq!(body["audit_chain_intact"], serde_json::json!(true));
    assert_eq!(store.audit_events_checked(), 20_000, "every held event was checked once");
}

/// A chain broken at seq 19,000 of 20,000. The first authenticated `/health` proves the 19,000 events before the break and reports it; the second starts from the break, rather than walking all 19,000 again on every request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_broken_chain_is_not_walked_from_the_top_on_every_authenticated_health() {
    const HELD: u64 = 20_000;
    const BROKEN: u64 = 19_000;
    let dir = scratch("broken");
    let path = dir.join("gw.db").to_string_lossy().to_string();
    drop(SqliteStore::open(&path).unwrap());
    let key = std::fs::read(format!("{path}.auditkey")).expect("the sidecar key");
    let key = ed25519_dalek::SigningKey::from_bytes(&<[u8; 32]>::try_from(key.as_slice()).expect("32 bytes"));
    let mut log = permaura_core::AuditLog::with_signing_key(key);
    {
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        let tx = conn.transaction().unwrap();
        for i in 0..HELD {
            let mut event = log.append_at(AuditPayload::new(format!("cap.{i}"), "conn", "allow"), 1_700_000_000_000 + i as i64).unwrap().clone();
            if event.seq == BROKEN {
                event.payload.decision = "deny".into();
            }
            tx.execute(
                "INSERT INTO audit_events (seq, data) VALUES (?1, ?2)",
                rusqlite::params![event.seq as i64, serde_json::to_string(&event).unwrap()],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    operator(store.as_ref());
    let router = router_over(store.clone());

    let (_, first, _) = health(router.clone(), true).await;
    assert_eq!(first["audit_chain_intact"], serde_json::json!(false));
    let after_first = store.audit_events_checked();

    let (_, second, _) = health(router, true).await;
    assert_eq!(second["audit_chain_intact"], serde_json::json!(false), "and the break is still reported");
    let checked = store.audit_events_checked() - after_first;
    assert!(checked <= HELD - BROKEN, "the second /health checked {checked} events, more than the {} from the break on", HELD - BROKEN);
    assert_eq!(after_first, BROKEN + 1, "the first walk checked up to and including the break");
    assert_eq!(store.verify_audit().unwrap(), Some(BROKEN), "at the same seq");
    std::fs::remove_dir_all(&dir).ok();
}
