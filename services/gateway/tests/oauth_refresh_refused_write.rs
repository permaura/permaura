//! A rotated OAuth credential survives a store that refuses to write it.
//!
//! The synthetic provider retires every refresh token on first use, so once it has answered, the rotated bundle is the
//! only live copy of the credential. A refused write used to drop it, and the next call presented the spent token and
//! was refused until the user authorized again.
#![cfg(feature = "sqlite")]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::synthetic_oauth::{allowed, describe, invoke_github, service_over, stored, Provider, GITHUB_SECRET};
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::store::persisted::PersistedSqliteStore;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;

fn scratch_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("permaura-gw-exec-a-01-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A bucket that refuses every upload while `refusing` is set, the way Cloud Storage does under a 429 or a stalled PUT.
struct RefusingBucket {
    inner: MemoryObjectStore,
    refusing: AtomicBool,
}

impl ObjectStore for RefusingBucket {
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
        if self.refusing.load(Ordering::SeqCst) {
            return Err(GatewayError::Internal("synthetic 429 from the bucket".into()));
        }
        self.inner.put_if_generation(name, bytes, expected, metadata)
    }
    fn describe(&self) -> String {
        "synthetic://refusing".into()
    }
}

/// The local write itself fails (a full disk): the rotation is kept in memory, used, and written once the store accepts writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotation_the_store_refuses_is_kept_and_written_later() {
    common::isolate_from_the_real_install();
    let path = scratch_dir("sqlite").join("gateway.db").to_string_lossy().into_owned();
    let http = Provider::new();
    http.release.add_permits(16);
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&path).unwrap());
    let s = service_over(store, http.clone());

    let side = rusqlite::Connection::open(&path).unwrap();
    side.execute_batch(
        "CREATE TRIGGER refuse_secret_write BEFORE UPDATE ON secrets \
         BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
    )
    .unwrap();
    let first = invoke_github(s.clone()).await;
    assert!(allowed(&first), "the call goes ahead with the rotation it was handed: {}", describe(&first));
    assert_eq!(stored(s.store().as_ref(), GITHUB_SECRET).refresh_token.as_ref().map(|t| t.expose()), Some(common::synthetic_oauth::OLD_REFRESH));

    side.execute_batch("DROP TRIGGER refuse_secret_write;").unwrap();
    let second = invoke_github(s.clone()).await;
    assert!(allowed(&second), "the spent refresh token was never presented again: {}", describe(&second));
    assert_eq!(http.refreshes(), 1, "one refresh, its rotation carried rather than lost");
    let saved = stored(s.store().as_ref(), GITHUB_SECRET);
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some("synthetic-rotated-0"));
    assert_eq!(saved.access_token, "synthetic-refreshed-0");
    assert_eq!(
        http.upstream_authorization(),
        vec!["Bearer synthetic-refreshed-0".to_string(), "Bearer synthetic-refreshed-0".to_string()]
    );
}

/// The hosted case: an earlier upload failed, so the store is dirty when the rotation is written. It is committed on
/// the instance, and the next upload that succeeds carries it to the bucket a replacement instance restores from.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotation_written_while_the_bucket_refuses_reaches_the_bucket() {
    common::isolate_from_the_real_install();
    let dir = scratch_dir("persisted");
    let bucket = Arc::new(RefusingBucket { inner: MemoryObjectStore::new(), refusing: AtomicBool::new(false) });
    let path = dir.join("gateway.db").to_string_lossy().into_owned();
    let store: Arc<dyn Store> =
        Arc::new(PersistedSqliteStore::open(&path, bucket.clone(), "store.db", None).unwrap().with_carry_floor(std::time::Duration::ZERO));
    let http = Provider::new();
    let s = service_over(store, http.clone());

    let task = tokio::spawn(invoke_github(s.clone()));
    http.entered.notified().await;
    // While the provider is answering, another write fails to upload and leaves the store dirty.
    bucket.refusing.store(true, Ordering::SeqCst);
    let _ = s.store().append_audit(permaura_core::AuditPayload::new("synthetic.other", "r", "allow"));
    http.release.add_permits(1);
    let _ = task.await.unwrap();

    bucket.refusing.store(false, Ordering::SeqCst);
    s.store().append_audit(permaura_core::AuditPayload::new("synthetic.later", "r", "allow")).unwrap();

    let restored_path = dir.join("restored.db").to_string_lossy().into_owned();
    let restored = PersistedSqliteStore::open(&restored_path, bucket.clone(), "store.db", None).unwrap();
    let saved = stored(&restored, GITHUB_SECRET);
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some("synthetic-rotated-0"), "the bucket carries the rotation");
    assert_eq!(http.refreshes(), 1);
}

/// A parked rotation goes when its secret is deleted, rather than staying in memory for the life of the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_parked_rotation_goes_when_its_secret_is_deleted() {
    use tower::ServiceExt;
    common::isolate_from_the_real_install();
    let path = scratch_dir("deleted").join("gateway.db").to_string_lossy().into_owned();
    let http = Provider::new();
    http.release.add_permits(16);
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&path).unwrap());
    let service = Arc::try_unwrap(service_over(store, http.clone())).ok().expect("the only handle");
    let state = permaura_gateway::AppState::new(service);
    let app = permaura_gateway::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());

    let side = rusqlite::Connection::open(&path).unwrap();
    side.execute_batch(
        "CREATE TRIGGER refuse_secret_write BEFORE UPDATE ON secrets \
         BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
    )
    .unwrap();
    assert!(allowed(&invoke_github(state.service.clone()).await));
    assert_eq!(state.service.parked_oauth_rotations(), vec![GITHUB_SECRET.to_string()]);

    let req = axum::http::Request::builder()
        .method("DELETE")
        .uri(format!("/v1/secrets/{GITHUB_SECRET}"))
        .header("authorization", format!("Bearer {}", permaura_gateway::seed::DEMO_TOKEN))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    assert!(state.service.store().get_secret(GITHUB_SECRET).unwrap().is_none());
    assert!(state.service.parked_oauth_rotations().is_empty(), "the deleted credential's rotation is not kept");
}
