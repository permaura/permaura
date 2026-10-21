//! What a hosted worker may conclude from an absent `store.db` at boot. A bucket that
//! was never written may be started fresh; one whose live object was deleted may not, because
//! starting fresh mints a new operator identity and audit key and presents the tenant's reset as a
//! healthy gateway. Every credential, transport and KMS here is synthetic.
#![cfg(feature = "sqlite")]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use permaura_gateway::backend::{AuditKeyWrap, KmsClient};
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use permaura_gateway::store::Store;

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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("permaura-store-boot-{}-{tag}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn open(path: &std::path::Path, objects: Arc<dyn ObjectStore>) -> Result<PersistedSqliteStore, GatewayError> {
    common::isolate_from_the_real_install();
    PersistedSqliteStore::open(
        &path.to_string_lossy(),
        objects,
        DEFAULT_OBJECT,
        Some(AuditKeyWrap { kms: Arc::new(FakeKms), key_id: "synthetic".into(), adopt_plaintext: false }),
    )
}

/// A bucket with no live object. `head` answers exactly as it does for a bucket nothing has ever
/// been written to; only the version history separates the two, which is the whole point of the
/// guard. `history` of `None` is a lookup that could not be answered at all.
struct NoLiveObject {
    inner: MemoryObjectStore,
    history: Option<bool>,
}

impl ObjectStore for NoLiveObject {
    fn head(&self, _name: &str) -> Result<Option<u64>, GatewayError> {
        Ok(None)
    }
    fn head_full(&self, _name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        Ok(None)
    }
    fn has_history(&self, _name: &str) -> Result<bool, GatewayError> {
        match self.history {
            Some(answer) => Ok(answer),
            None => Err(GatewayError::Internal("synthetic: the version listing could not be read".into())),
        }
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
        "gs://synthetic-worker-bucket".into()
    }
}

/// The path the guard must leave alone: nothing has ever been written, so this really is a first
/// boot and it proceeds exactly as before, empty and at generation 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bucket_with_no_history_starts_a_fresh_store() {
    let objects = Arc::new(MemoryObjectStore::new());
    let store = open(&dir("fresh").join("store.db"), objects.clone()).expect("a fresh bucket opens");

    assert_eq!(store.generation(), 0, "nothing has been uploaded yet");
    assert!(store.list_agents().unwrap().is_empty(), "and the store is empty");
    assert_eq!(objects.put_count(), 0, "opening alone uploads nothing");
}

/// The retained versions are the evidence that this store existed, and they are enough to
/// refuse. Nothing is created locally and nothing is uploaded, so the operator can promote a version
/// into place without racing a worker that has already claimed generation 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_store_refuses_to_boot_and_names_the_object() {
    let objects = Arc::new(NoLiveObject { inner: MemoryObjectStore::new(), history: Some(true) });
    let path = dir("deleted").join("store.db");
    let err = open(&path, objects.clone()).err().expect("a deleted store must not open");

    let message = format!("{err}");
    assert!(message.contains("gs://synthetic-worker-bucket"), "the error names the bucket: {message}");
    assert!(message.contains(DEFAULT_OBJECT), "and the object: {message}");
    assert!(
        message.contains(&format!("restore the one you want by copying it, by its generation, back to gs://synthetic-worker-bucket/{DEFAULT_OBJECT}")),
        "and what to do about it: {message}"
    );
    assert!(message.contains("then restart the gateway"), "and what follows the restore: {message}");
    assert!(!path.exists(), "no local database was created");
    assert_eq!(objects.inner.put_count(), 0, "and nothing was uploaded over the retained versions");
}

/// A history lookup that fails says nothing about whether the store existed, so it is refused for
/// the same reason an unreachable bucket is: the one answer that must never be inferred is "empty".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_history_lookup_that_fails_never_starts_fresh() {
    let objects = Arc::new(NoLiveObject { inner: MemoryObjectStore::new(), history: None });
    let path = dir("unreadable").join("store.db");
    let err = open(&path, objects.clone()).err().expect("an unanswerable history must not open");

    assert!(
        format!("{err}").contains("version listing could not be read"),
        "the lookup's own failure is what is reported: {err}"
    );
    assert!(!path.exists(), "no local database was created");
    assert_eq!(objects.inner.put_count(), 0, "and nothing was uploaded");
}
