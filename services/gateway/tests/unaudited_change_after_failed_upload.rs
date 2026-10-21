//! On a hosted worker, a change whose own snapshot upload fails is carried to the bucket together with its audit record.
//!
//! The change commits on the instance, the store carrier uploads it about two seconds later, and a replacement instance restores it. Before the fix the handler returned 503 before appending the record, so the bucket ended up with a credential change or an applied control-plane change and nothing in the chain saying who made it.
#![cfg(feature = "sqlite")]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

const CONNECTION: &str = "braintree_production";
const SECRET: &str = "sec_braintree_prod";
const SECRET_WRITE: &str = "permaura.secret.write";
const POLICY_WRITE: &str = "permaura.policy.write";

/// A bucket that answers 429 to every upload while `refuse` is set, as Cloud Storage does under its per-object write rate or a stalled PUT that times out. Reads always answer.
struct Refusing {
    inner: MemoryObjectStore,
    refuse: AtomicBool,
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
        if self.refuse.load(Ordering::SeqCst) {
            return Err(GatewayError::Internal(format!("object store put synthetic://refusing/{name} returned 429")));
        }
        self.inner.put_if_generation(name, bytes, expected, metadata)
    }
    fn describe(&self) -> String {
        "synthetic://refusing".into()
    }
}

fn dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "permaura-unaudited-{}-{tag}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn open(tag: &str, objects: Arc<dyn ObjectStore>) -> Arc<PersistedSqliteStore> {
    common::isolate_from_the_real_install();
    Arc::new(
        PersistedSqliteStore::open(&dir(tag).join("store.db").to_string_lossy(), objects, DEFAULT_OBJECT, None)
            .unwrap()
            .with_fresh_read_window(Duration::ZERO)
            .with_carry_floor(Duration::ZERO),
    )
}

/// A hosted worker (every request remote, no device paired, so credential writes are unheld) over a bucket the test controls.
fn hosted_worker(tag: &str) -> (Arc<Refusing>, Arc<PersistedSqliteStore>, axum::Router) {
    let objects = Arc::new(Refusing { inner: MemoryObjectStore::new(), refuse: AtomicBool::new(false) });
    let store = open(tag, objects.clone());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let mut state = AppState::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    state.hosted = true;
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    (objects, store, app)
}

async fn send(app: &axum::Router, method: &str, uri: &str, body: Option<serde_json::Value>) -> (StatusCode, String) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .header("content-type", "application/json")
        .body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// What a replacement instance would restore from the bucket.
fn restored(objects: Arc<Refusing>) -> Arc<PersistedSqliteStore> {
    open("restored", objects)
}

fn count(store: &dyn Store, action: &str) -> usize {
    store.audit_events(None).unwrap().iter().filter(|e| e.payload.action == action).count()
}

/// Warm the operator session, so nothing but the write under test uploads during the refused request.
async fn warm(app: &axum::Router) {
    let (status, body) = send(app, "GET", "/v1/connections", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Refuse uploads for one request, then let the bucket recover and carry what the instance holds, as the store carrier does every two seconds.
async fn refused_then_carried(
    objects: &Refusing,
    store: &PersistedSqliteStore,
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: serde_json::Value,
) {
    warm(app).await;
    objects.refuse.store(true, Ordering::SeqCst);
    let (status, text) = send(app, method, uri, Some(body)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "the write's own upload failed: {text}");
    objects.refuse.store(false, Ordering::SeqCst);
    assert!(store.carry_pending().unwrap(), "the carrier carries the local commit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_an_accepted_credential_write_is_recorded() {
    let (objects, store, app) = hosted_worker("control-secret");
    let before = count(store.as_ref(), SECRET_WRITE);
    let (s, body) = send(&app, "POST", &format!("/v1/connections/{CONNECTION}/credential"), Some(serde_json::json!({ "value": "v2" }))).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(count(restored(objects).as_ref(), SECRET_WRITE), before + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_write_whose_upload_fails_is_carried_with_its_record() {
    let (objects, store, app) = hosted_worker("secret");
    let original = store.get_secret(SECRET).unwrap().unwrap().sealed;
    let before = count(store.as_ref(), SECRET_WRITE);
    let uri = format!("/v1/connections/{CONNECTION}/credential");
    refused_then_carried(&objects, &store, &app, "POST", &uri, serde_json::json!({ "value": "swapped" })).await;

    let after = restored(objects);
    assert_ne!(after.get_secret(SECRET).unwrap().unwrap().sealed, original, "the credential change is durable");
    assert_eq!(count(after.as_ref(), SECRET_WRITE), before + 1, "and so is its audit event");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secret_rotation_whose_upload_fails_is_carried_with_its_record() {
    let (objects, store, app) = hosted_worker("rotate");
    let before = count(store.as_ref(), SECRET_WRITE);
    let uri = format!("/v1/secrets/{SECRET}/rotate");
    refused_then_carried(&objects, &store, &app, "POST", &uri, serde_json::json!({ "value": "rotated" })).await;
    assert_eq!(count(restored(objects).as_ref(), SECRET_WRITE), before + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_an_accepted_applied_change_is_recorded() {
    let (objects, store, app) = hosted_worker("control-patch");
    let before = count(store.as_ref(), POLICY_WRITE);
    let (s, body) = send(&app, "PATCH", &format!("/v1/connections/{CONNECTION}"), Some(serde_json::json!({ "label": "Renamed" }))).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(count(restored(objects).as_ref(), POLICY_WRITE), before + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_change_whose_upload_fails_is_carried_with_its_record() {
    let (objects, store, app) = hosted_worker("patch");
    let before = count(store.as_ref(), POLICY_WRITE);
    let uri = format!("/v1/connections/{CONNECTION}");
    refused_then_carried(&objects, &store, &app, "PATCH", &uri, serde_json::json!({ "label": "Renamed" })).await;

    let after = restored(objects);
    assert_eq!(after.get_connection(CONNECTION).unwrap().unwrap().label, "Renamed", "the change is durable");
    assert_eq!(count(after.as_ref(), POLICY_WRITE), before + 1, "and so is its audit event");
}

/// A bucket that notes an upload landing while the test says a change is waiting for its record.
struct Watching {
    inner: MemoryObjectStore,
    between: AtomicBool,
    landed_between: AtomicBool,
}

impl ObjectStore for Watching {
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
        if self.between.load(Ordering::SeqCst) {
            self.landed_between.store(true, Ordering::SeqCst);
        }
        self.inner.put_if_generation(name, bytes, expected, metadata)
    }
    fn describe(&self) -> String {
        "synthetic://watching".into()
    }
}

/// The batch depth that holds a change's upload back is per thread, so another request's write must not upload the change before its record is appended.
#[test]
fn another_threads_write_does_not_upload_a_change_before_its_record() {
    let objects = Arc::new(Watching { inner: MemoryObjectStore::new(), between: AtomicBool::new(false), landed_between: AtomicBool::new(false) });
    let store = open("concurrent", objects.clone());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let sealed = store.get_secret(SECRET).unwrap().unwrap().sealed;
    let mut other = None;
    store
        .change_with_record(&mut || {
            store.put_secret(permaura_core::SecretRecord { id: "sec_changed".into(), sealed: sealed.clone(), metadata: Default::default() })?;
            objects.between.store(true, Ordering::SeqCst);
            let (writer, sealed) = (store.clone(), sealed.clone());
            other = Some(std::thread::spawn(move || {
                writer.put_secret(permaura_core::SecretRecord { id: "sec_other".into(), sealed, metadata: Default::default() })
            }));
            // Long enough for the other thread's write and upload to land when nothing holds it back.
            std::thread::sleep(Duration::from_millis(400));
            objects.between.store(false, Ordering::SeqCst);
            store.append_audit(permaura_core::AuditPayload::new(SECRET_WRITE.to_string(), "sec_changed".to_string(), "allow")).map(|_| ())
        })
        .unwrap();
    other.unwrap().join().unwrap().unwrap();
    assert!(!objects.landed_between.load(Ordering::SeqCst), "an upload carried the change before its record");
    let after = open("concurrent-restored", objects.clone());
    assert!(after.get_secret("sec_changed").unwrap().is_some() && after.get_secret("sec_other").unwrap().is_some());
    assert_eq!(count(after.as_ref(), SECRET_WRITE), count(store.as_ref(), SECRET_WRITE));
}

/// A hosted worker whose database file the test can reach, to make the audit table refuse a write.
fn hosted_worker_at(tag: &str) -> (Arc<Refusing>, Arc<PersistedSqliteStore>, axum::Router, PathBuf) {
    common::isolate_from_the_real_install();
    let objects = Arc::new(Refusing { inner: MemoryObjectStore::new(), refuse: AtomicBool::new(false) });
    let db = dir(tag).join("store.db");
    let store = Arc::new(
        PersistedSqliteStore::open(&db.to_string_lossy(), objects.clone(), DEFAULT_OBJECT, None)
            .unwrap()
            .with_fresh_read_window(Duration::ZERO)
            .with_carry_floor(Duration::ZERO),
    );
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let mut state = AppState::new(EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())));
    state.hosted = true;
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());
    (objects, store, app, db)
}

/// A credential write whose audit record cannot be written is undone, on the instance and in the bucket, rather than standing unrecorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_write_whose_record_cannot_be_written_is_undone() {
    for (tag, uri) in [("record-credential", format!("/v1/connections/{CONNECTION}/credential")), ("record-rotate", format!("/v1/secrets/{SECRET}/rotate"))] {
        let (objects, store, app, db) = hosted_worker_at(tag);
        warm(&app).await;
        let original = store.get_secret(SECRET).unwrap().unwrap().sealed;
        let before = count(store.as_ref(), SECRET_WRITE);
        let sql = rusqlite::Connection::open(&db).unwrap();
        sql.execute_batch("CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'synthetic: the audit write failed'); END;")
            .unwrap();
        let (status, text) = send(&app, "POST", &uri, Some(serde_json::json!({ "value": "unrecorded" }))).await;
        assert!(!status.is_success(), "{tag}: the write cannot be recorded, so it is refused: {status} {text}");
        sql.execute_batch("DROP TRIGGER refuse_audit;").unwrap();
        assert_eq!(store.get_secret(SECRET).unwrap().unwrap().sealed, original, "{tag}: the credential is put back");
        assert!(store.carry_pending().unwrap());
        let after = restored(objects);
        assert_eq!(after.get_secret(SECRET).unwrap().unwrap().sealed, original, "{tag}: and the bucket never holds the change");
        assert_eq!(count(after.as_ref(), SECRET_WRITE), before, "{tag}");
    }
}
