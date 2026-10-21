//! Slice 9: segments, durable publication, prune, and every crash point between them.
//!
//! The object store is a double throughout, per the workspace rule that only GCS and KMS get one.
//! The SQLite store is real and on disk, because a prune re-signs the boundary and a store with no
//! persisted key refuses to: an `:memory:` store would pass this suite by never doing the thing
//! under test.
#![cfg(feature = "sqlite")]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use permaura_core::audit::{AuditArchiveIndex, AuditSegment};
use permaura_core::{AuditLog, AuditPayload};
use permaura_gateway::archive::{from_ndjson, AuditArchive};
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{GrantCharge, GrantWindow, Store};

// ── doubles ──────────────────────────────────────────────────────────────────────────────────────

/// A memory object store that can be made to stop accepting writes at a chosen point, which is how
/// each crash point in `archive`'s table is reached: the pass dies where the store stops answering.
struct Interruptible {
    inner: MemoryObjectStore,
    /// Writes still to accept before every later one fails. `usize::MAX` accepts everything.
    allow_writes: AtomicUsize,
    /// Fail every read, for the "publication is unavailable" case.
    reads_fail: AtomicBool,
    /// Every name written, in order, so a test can say exactly how far a pass got.
    written: Mutex<Vec<String>>,
    /// Names that read as absent, for an object a lifecycle rule or an operator removed.
    lost: Mutex<Vec<String>>,
}

impl Interruptible {
    fn new() -> Self {
        Interruptible {
            inner: MemoryObjectStore::new(),
            allow_writes: AtomicUsize::new(usize::MAX),
            reads_fail: AtomicBool::new(false),
            written: Mutex::new(Vec::new()),
            lost: Mutex::new(Vec::new()),
        }
    }

    /// Make an object read as absent, which no code path in the gateway can do either.
    fn lose(&self, name: &str) {
        self.lost.lock().unwrap().push(name.to_string());
    }

    fn allow(&self, n: usize) {
        self.allow_writes.store(n, Ordering::SeqCst);
    }

    fn names(&self) -> Vec<String> {
        self.written.lock().unwrap().clone()
    }

    /// Edit an object in place, which no code path in the gateway can do.
    fn overwrite(&self, name: &str, bytes: &[u8]) {
        self.inner.overwrite(name, bytes);
    }
}

impl ObjectStore for Interruptible {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        if self.reads_fail.load(Ordering::SeqCst) {
            return Err(GatewayError::Internal("synthetic: the archive bucket is unreachable".into()));
        }
        if self.lost.lock().unwrap().iter().any(|n| n == name) {
            return Ok(None);
        }
        self.inner.head(name)
    }
    fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        self.inner.head_full(name)
    }
    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        self.inner.has_history(name)
    }
    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        if self.reads_fail.load(Ordering::SeqCst) {
            return Err(GatewayError::Internal("synthetic: the archive bucket is unreachable".into()));
        }
        self.inner.get(name, generation)
    }
    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        let left = self.allow_writes.load(Ordering::SeqCst);
        if left == 0 {
            return Err(GatewayError::Internal(format!("synthetic: the pass died before writing {name}")));
        }
        if left != usize::MAX {
            self.allow_writes.store(left - 1, Ordering::SeqCst);
        }
        let outcome = self.inner.put_if_generation(name, bytes, expected, metadata)?;
        if matches!(outcome, PutOutcome::Stored(_)) {
            self.written.lock().unwrap().push(name.to_string());
        }
        Ok(outcome)
    }
    fn describe(&self) -> String {
        "interruptible".into()
    }
}

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────────

struct Fixture {
    dir: std::path::PathBuf,
    store: Arc<SqliteStore>,
    objects: Arc<Interruptible>,
    archive: Arc<AuditArchive>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

fn fixture(keep_hot: usize, batch: usize) -> Fixture {
    // Before the store, not after: `SqliteStore::open` resolves the vault KEK, and on a machine
    // with a real gateway installed that reaches the developer's own `~/.permaura` and refuses to
    // start. A scratch `dir` is not enough on its own, which is what this file got wrong.
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!(
        "permaura-archive-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    let objects = Arc::new(Interruptible::new());
    // Built directly rather than from the environment: `PERMAURA_AUDIT_ARCHIVE_*` is process-global
    // and these tests run in parallel.
    let archive =
        Arc::new(AuditArchive::with_limits(objects.clone(), "acme", "audit", batch, keep_hot));
    Fixture { dir, store, objects, archive }
}

fn append(store: &dyn Store, n: usize) {
    for i in 0..n {
        store.append_audit(AuditPayload::new(format!("cap.{i}"), "conn", "allow")).unwrap();
    }
}

fn base_seq(store: &dyn Store) -> u64 {
    store.audit_boundary().unwrap().unwrap().base_seq
}

fn index_of(f: &Fixture) -> AuditArchiveIndex {
    f.archive.read_index(0).unwrap()
}

/// Where the index page naming the segment that starts at `base_seq` lives in epoch 0.
fn page_name(base_seq: u64) -> String {
    format!("audit/acme/e0000/index/{base_seq:020}.json")
}

fn page_of(f: &Fixture, base_seq: u64) -> AuditArchiveIndex {
    let name = page_name(base_seq);
    let generation = f.objects.head(&name).unwrap().expect("the page is there");
    serde_json::from_slice(&f.objects.get(&name, generation).unwrap()).unwrap()
}

/// A checkpoint of the fixture's store, with its audit key beside it. The key is a sidecar that
/// `snapshot_to` does not copy, and a store reopened without it mints a new one: it is then a
/// different chain's store, which is exactly what the archive must refuse to prune against.
fn snapshot(f: &Fixture, name: &str) -> std::path::PathBuf {
    let path = f.dir.join(format!("{name}.db"));
    f.store.snapshot_to(&path).unwrap();
    std::fs::copy(f.dir.join("gateway.db.auditkey"), f.dir.join(format!("{name}.db.auditkey"))).unwrap();
    path
}

// ── the invariant ────────────────────────────────────────────────────────────────────────────────

/// The rule the whole module exists for: a row is deleted only after its segment has been written,
/// read back and hashed. Interrupt the pass before the read-back can happen and the hot store is
/// whole.
#[test]
fn a_segment_is_not_prunable_until_it_has_been_read_back_and_hashed() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);

    // One write: the `.ndjson` lands, the manifest does not, the pass dies.
    f.objects.allow(1);
    let err = f.archive.run_pass(f.store.as_ref()).unwrap_err();
    assert!(err.to_string().contains("died before writing"), "{err}");

    assert_eq!(f.store.audit_len().unwrap(), 10, "not one row left the hot store");
    assert_eq!(base_seq(f.store.as_ref()), 0, "and the boundary did not move");
    assert_eq!(f.objects.names().len(), 1, "only the segment bytes were written");
    assert!(index_of(&f).segments.is_empty(), "and nothing names them");
}

/// The other half of the same rule, one step later: the index is what a verifier walks, so a pass
/// that could not update it has published nothing as far as anyone can tell, and must prune nothing.
#[test]
fn a_failed_index_update_leaves_the_hot_store_untouched() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);

    // Two writes: the bytes and the manifest land, the index write dies.
    f.objects.allow(2);
    let err = f.archive.run_pass(f.store.as_ref()).unwrap_err();
    assert!(err.to_string().contains("died before writing"), "{err}");

    assert_eq!(f.store.audit_len().unwrap(), 10);
    assert_eq!(base_seq(f.store.as_ref()), 0);
    assert!(index_of(&f).segments.is_empty());
}

/// The boundary is the statement of where the hot window starts, so it may only move with the prune
/// that made it true. Every interruption above already asserts it did not move; this asserts
/// that when it does move, it moves to exactly the segment that was published.
#[test]
fn the_boundary_moves_only_with_its_prune_and_only_to_the_published_segment() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    let head_of_batch = f.store.audit_events_from(0, 4).unwrap()[3].hash.clone();

    let outcome = f.archive.run_pass(f.store.as_ref()).unwrap();
    assert_eq!(outcome.pruned, 4);
    assert_eq!(outcome.segment_id.as_deref(), Some("seg-00000000000000000000-00000000000000000003"));

    let boundary = f.store.audit_boundary().unwrap().unwrap();
    assert_eq!(boundary.base_seq, 4);
    assert_eq!(boundary.base_hash, head_of_batch, "the base links to the segment's own head");
    assert_eq!(boundary.segment_head.as_deref(), outcome.segment_id.as_deref());
    assert_eq!(f.store.audit_len().unwrap(), 6);
    assert_eq!(f.store.verify_audit().unwrap(), None, "the remaining window still verifies");
}

// ── crash points ─────────────────────────────────────────────────────────────────────────────────

/// Crash after the `.ndjson`: the next pass meets its own bytes under a create-only write, reads
/// them back, finds them identical, and carries on to publish and prune.
#[test]
fn a_pass_that_died_after_writing_the_segment_bytes_resumes_without_republishing() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    f.objects.allow(1);
    f.archive.run_pass(f.store.as_ref()).unwrap_err();

    f.objects.allow(usize::MAX);
    let outcome = f.archive.run_pass(f.store.as_ref()).unwrap();
    assert_eq!(outcome.pruned, 4);
    assert_eq!(base_seq(f.store.as_ref()), 4);
    assert_eq!(index_of(&f).segments.len(), 1);
}

/// Crash after the manifest: the same, one step later.
#[test]
fn a_pass_that_died_after_writing_the_manifest_resumes_without_republishing() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    f.objects.allow(2);
    f.archive.run_pass(f.store.as_ref()).unwrap_err();

    f.objects.allow(usize::MAX);
    let outcome = f.archive.run_pass(f.store.as_ref()).unwrap();
    assert_eq!(outcome.pruned, 4);
    assert_eq!(base_seq(f.store.as_ref()), 4);
}

/// Crash between the index update and the prune, which is the one point where the bucket is ahead
/// of the store. The next pass must adopt the published segment and prune to it rather than build a
/// second segment over the same events.
#[test]
fn a_pass_that_died_between_the_index_and_the_prune_adopts_the_published_segment() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    // Three writes reaches the index and stops before the prune, which is a store call rather than
    // an upload, so the crash has to be simulated: publish fully, then rewind the store's boundary
    // by reopening from a copy taken before the prune.
    let before = snapshot(&f, "before-prune");
    f.archive.run_pass(f.store.as_ref()).unwrap();
    assert_eq!(index_of(&f).segments.len(), 1);

    let rewound = Arc::new(SqliteStore::open(&before.to_string_lossy()).unwrap());
    assert_eq!(rewound.audit_len().unwrap(), 10, "the rewound store never saw the prune");

    let outcome = f.archive.run_pass(rewound.as_ref()).unwrap();
    assert_eq!(outcome.pruned, 4, "it pruned to the segment that was already published");
    assert!(outcome.reason.contains("adopted"), "{}", outcome.reason);
    assert_eq!(index_of(&f).segments.len(), 1, "and published nothing further");
    assert_eq!(rewound.audit_len().unwrap(), 6);
}

/// The one state repetition cannot repair. Two different histories cannot share one segment name,
/// so a name already holding different bytes refuses loudly instead of overwriting, and prunes
/// nothing.
#[test]
fn a_different_segment_under_the_same_name_is_refused_and_prunes_nothing() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    // Something else got here first with the right name and the wrong bytes.
    f.objects
        .put_if_generation(
            "audit/acme/e0000/seg-00000000000000000000-00000000000000000003.ndjson",
            b"not this chain",
            0,
            &BTreeMap::new(),
        )
        .unwrap();

    let err = f.archive.run_pass(f.store.as_ref()).unwrap_err();
    assert!(err.to_string().contains("cannot share one segment name"), "{err}");
    assert_eq!(f.store.audit_len().unwrap(), 10);
    assert_eq!(base_seq(f.store.as_ref()), 0);
}

// ── backpressure ─────────────────────────────────────────────────────────────────────────────────

/// Publication being unavailable costs the tenant a growing hot store and, eventually, the ceiling.
/// It never costs a record: nothing in the writer is on the append path.
#[test]
fn an_unavailable_archive_never_drops_an_event() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    f.objects.reads_fail.store(true, Ordering::SeqCst);

    for _ in 0..3 {
        assert!(f.archive.run_pass(f.store.as_ref()).is_err());
        append(f.store.as_ref(), 2);
    }
    assert_eq!(f.store.audit_len().unwrap(), 16, "every append landed while the bucket was down");
    assert_eq!(base_seq(f.store.as_ref()), 0);
    assert_eq!(f.store.verify_audit().unwrap(), None);
}

/// Bounded work per pass, and resumable: a store far past the floor migrates in as many passes as
/// it takes, each one publishing exactly one batch.
#[test]
fn the_batched_migration_moves_at_most_one_batch_per_pass_and_is_resumable() {
    let f = fixture(3, 4);
    append(f.store.as_ref(), 19);

    let mut segments = Vec::new();
    loop {
        let outcome = f.archive.run_pass(f.store.as_ref()).unwrap();
        let Some(id) = outcome.segment_id else { break };
        assert!(outcome.pruned <= 4, "a pass moved {} events, past the batch", outcome.pruned);
        segments.push(id);
    }
    assert_eq!(segments.len(), 4, "16 events past the floor, four at a time");
    assert_eq!(f.store.audit_len().unwrap(), 3, "the floor is what is left");
    assert_eq!(base_seq(f.store.as_ref()), 16);

    let index = index_of(&f);
    assert_eq!(index.segments.len(), 4);
    // Contiguous, and each segment links to the one before it.
    for pair in index.segments.windows(2) {
        assert_eq!(pair[1].base_seq, pair[0].end_seq + 1);
        assert_eq!(pair[1].prev_hash, pair[0].head_hash);
    }
    assert_eq!(
        f.store.audit_boundary().unwrap().unwrap().base_hash,
        index.segments.last().unwrap().head_hash,
        "and the hot window hangs off the last of them"
    );
}

// ── format ───────────────────────────────────────────────────────────────────────────────────────

/// The published bytes are the events, unchanged, and every manifest and the index verify under the
/// store's own audit key. A segment that verified under the key in its own manifest would prove
/// nothing about whose chain it is.
#[test]
fn a_published_segment_and_its_index_verify_under_the_stores_own_key() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    let original = f.store.audit_events_from(0, 4).unwrap();
    f.archive.run_pass(f.store.as_ref()).unwrap();

    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(&f.store.audit_verifying_key().unwrap()).unwrap();
    let id = index_of(&f).segments[0].segment_id.clone();
    let (bytes, manifest) = f.archive.read_segment(0, &id).unwrap();

    assert!(manifest.verify(&vk), "the manifest signs under the chain's key");
    let pages = f.archive.index_objects(0, 0).unwrap();
    assert_eq!(pages.len(), 1, "one index page for the one segment");
    assert!(pages.iter().all(|page| page.verify(&vk)), "and so does the index");
    assert_eq!(from_ndjson(&bytes).unwrap(), original, "the events are published unchanged");
    assert_eq!(
        AuditLog::verify_from(&from_ndjson(&bytes).unwrap(), &vk, 0, &manifest.prev_hash),
        None,
        "and the published run is a valid chain on its own"
    );
    assert_eq!(manifest.tenant, "acme");
    assert_eq!(manifest.epoch, 0);
    assert_eq!(manifest.count, 4);
}

/// The epoch is in the path, so a restore's fork cannot publish over the abandoned generation's
/// segments even when the two cover the same sequence numbers.
#[test]
fn two_epochs_of_one_tenant_never_share_a_namespace() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let before: Vec<String> = f.objects.names();

    f.store.fork_audit_epoch(1, "hold-test").unwrap();
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let after: Vec<String> = f.objects.names();

    let epoch0: Vec<&String> = before.iter().filter(|n| n.contains("/e0000/")).collect();
    let epoch1: Vec<&String> = after.iter().filter(|n| n.contains("/e0001/")).collect();
    assert!(!epoch0.is_empty() && !epoch1.is_empty(), "both epochs published something");
    for name in &epoch1 {
        assert!(!before.contains(name), "epoch 1 wrote over nothing epoch 0 had: {name}");
    }
    assert_eq!(
        f.archive.read_index(0).unwrap().segments.len(),
        1,
        "and epoch 0's index is untouched"
    );
}

/// Seq numbers are absolute and the segment name is zero-padded, so a plain lexical listing of the
/// bucket is the chain in order.
#[test]
fn segment_names_sort_into_sequence_order() {
    let f = fixture(0, 2);
    append(f.store.as_ref(), 6);
    while f.archive.run_pass(f.store.as_ref()).unwrap().segment_id.is_some() {}

    let ids: Vec<String> =
        index_of(&f).segments.iter().map(|s| s.segment_id.clone()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "lexical order is sequence order");
}

// ── the flag ─────────────────────────────────────────────────────────────────────────────────────

/// With no archive attached the gateway is what it was: nothing is published and nothing is pruned.
/// This is the flag-off case stated against the store rather than against the environment variable,
/// which is process-global and cannot be set safely from a parallel test.
#[test]
fn with_no_archive_attached_nothing_is_published_and_nothing_is_pruned() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 40);
    // What the service does when `audit_archive` is `None`: it never calls the writer.
    assert_eq!(f.store.audit_len().unwrap(), 40);
    assert_eq!(base_seq(f.store.as_ref()), 0);
    assert!(f.store.audit_boundary().unwrap().unwrap().is_genesis());
    assert!(f.objects.names().is_empty(), "no object was written");
}

// ── the budget across a prune ────────────────────────────────────────────────────────────────────

/// The load-bearing one for the grant usage counter, now that a prune actually exists: a `Period::Total` budget is
/// unchanged by the events that charged it leaving the hot store. An audit scan of the same store
/// would report zero and widen the grant.
#[test]
fn a_total_period_grant_keeps_its_budget_across_a_prune() {
    let f = fixture(2, 6);
    for i in 0..8 {
        let mut payload = AuditPayload::new(format!("cap.{i}"), "conn", "allow");
        payload.agent_id = Some("a1".into());
        payload.summary = serde_json::json!({ "grant_id": "g_total" });
        f.store
            .append_audit_charged(payload, Some(GrantCharge::new("g_total")))
            .unwrap();
    }
    let window = GrantWindow { grant_id: "g_total", since_ms: i64::MIN };
    let before = f.store.read_grant_usage(std::slice::from_ref(&window)).unwrap();
    assert_eq!(before.total("g_total"), 8);

    let outcome = f.archive.run_pass(f.store.as_ref()).unwrap();
    assert_eq!(outcome.pruned, 6);

    let after = f.store.read_grant_usage(std::slice::from_ref(&window)).unwrap();
    assert_eq!(after, before, "the budget is not a property of the hot window");
    assert_eq!(after.agent("g_total", "a1"), 8);
    assert_eq!(
        f.store.count_grant_usage(std::slice::from_ref(&window)).unwrap().total("g_total"),
        2,
        "a scan of the hot window is what would have widened the grant"
    );
}

/// A segment's manifest is not a place to hide a different range: every field the signature covers
/// breaks it.
#[test]
fn a_manifest_whose_range_or_linkage_was_edited_no_longer_verifies() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(&f.store.audit_verifying_key().unwrap()).unwrap();
    let id = index_of(&f).segments[0].segment_id.clone();
    let (_, manifest) = f.archive.read_segment(0, &id).unwrap();
    assert!(manifest.verify(&vk));

    for edited in [
        AuditSegment { base_seq: 1, ..manifest.clone() },
        AuditSegment { end_seq: 99, ..manifest.clone() },
        AuditSegment { epoch: 1, ..manifest.clone() },
        // Not "00" repeated: the genuine `prev_hash` of the first segment IS 64 zeros, so that
        // edit would be no edit at all and the assertion would be vacuous.
        AuditSegment { prev_hash: "ab".repeat(32), ..manifest.clone() },
        AuditSegment { head_hash: "ab".repeat(32), ..manifest.clone() },
        AuditSegment { sha256: "ab".repeat(32), ..manifest.clone() },
    ] {
        assert!(!edited.verify(&vk), "{edited:?} must not verify");
    }
}

// ── verification across the boundary ─────────────────────────────────────────────────────────────

use permaura_gateway::archive::{break_kind, ArchivedEvents};

/// Publish three segments and keep a few events hot, which is the shape every verification test
/// below starts from.
fn published(f: &Fixture, total: usize) {
    append(f.store.as_ref(), total);
    while f.archive.run_pass(f.store.as_ref()).unwrap().segment_id.is_some() {}
}

#[test]
fn verify_full_walks_archive_and_hot_and_proves_one_chain() {
    let f = fixture(3, 4);
    published(&f, 19);
    let report = f.archive.verify_full(f.store.as_ref()).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.first_break, None);
    assert_eq!(report.verified_from, 0);
    assert_eq!(report.verified_to, Some(18));
    assert_eq!(report.segments, 4);
    assert_eq!(f.store.audit_len().unwrap(), 3, "and most of it is not in the hot store");
    // The walk names the key it verified under, so a caller holding a pin can tell a history
    // that verifies under a substituted key from this gateway's own.
    let key = f.store.audit_verifying_key().unwrap();
    let json = report.to_json();
    assert_eq!(json["audit_key"]["fingerprint"], permaura_gateway::audit_key::fingerprint(&key).as_str());
    assert_eq!(json["audit_key"]["algorithm"], "ed25519");
}

#[test]
fn verify_full_walks_archive_and_hot_and_finds_a_tampered_archived_event() {
    let f = fixture(3, 4);
    published(&f, 19);
    // Flip a decision inside the second segment, leaving its hash and signature alone, exactly as
    // the in-memory tamper test does to the hot chain.
    let entry = index_of(&f).segments[1].clone();
    let (bytes, _) = f.archive.read_segment(0, &entry.segment_id).unwrap();
    let edited = String::from_utf8(bytes).unwrap().replacen("\"allow\"", "\"deny\"", 1);
    f.objects.overwrite(
        &format!("audit/acme/e0000/{}.ndjson", entry.segment_id),
        edited.as_bytes(),
    );

    let report = f.archive.verify_full(f.store.as_ref()).unwrap();
    assert!(!report.chain_intact);
    assert_eq!(report.break_kind, Some(break_kind::TAMPERED_SEGMENT));
    assert_eq!(report.first_break, Some(entry.base_seq), "{report:?}");
    // A broken walk still says which key it checked against.
    assert_eq!(report.audit_key, f.store.audit_verifying_key().unwrap());
}

#[test]
fn verify_full_detects_a_segment_missing_from_the_index() {
    let f = fixture(3, 4);
    published(&f, 19);
    let index = index_of(&f);
    let dropped = index.segments[1].clone();
    // The page naming one segment is gone and the pages either side of it are whole: a verifier that read only the
    // pages there are would see a chain that simply skips.
    f.objects.lose(&page_name(dropped.base_seq));

    let report = f.archive.verify_full(f.store.as_ref()).unwrap();
    assert!(!report.chain_intact);
    assert_eq!(report.break_kind, Some(break_kind::MISSING_SEGMENT));
    assert_eq!(report.first_break, Some(dropped.base_seq), "{report:?}");
}

#[test]
fn verify_full_detects_a_reordered_segment() {
    let f = fixture(3, 4);
    published(&f, 19);
    let index = index_of(&f);
    // Each page is signed, so the two are swapped whole: each now sits at the seq of the other.
    let (one, two) = (page_of(&f, index.segments[1].base_seq), page_of(&f, index.segments[2].base_seq));
    f.objects.overwrite(&page_name(index.segments[1].base_seq), &serde_json::to_vec(&two).unwrap());
    f.objects.overwrite(&page_name(index.segments[2].base_seq), &serde_json::to_vec(&one).unwrap());

    let report = f.archive.verify_full(f.store.as_ref()).unwrap();
    assert!(!report.chain_intact);
    assert_eq!(report.break_kind, Some(break_kind::REORDERED_SEGMENT));
}

#[test]
fn verify_full_detects_a_boundary_that_does_not_match_the_last_segments_tail() {
    let f = fixture(3, 4);
    published(&f, 19);
    // The index ends one segment early and the store's boundary names a base it does not reach: the
    // two are not each other's.
    let last = index_of(&f).segments.pop().unwrap();
    f.objects.lose(&page_name(last.base_seq));

    let report = f.archive.verify_full(f.store.as_ref()).unwrap();
    assert!(!report.chain_intact);
    assert_eq!(report.break_kind, Some(break_kind::BOUNDARY_MISMATCH), "{report:?}");
}

/// Each of the four failures reports a different kind, which is what lets an operator tell a
/// lifecycle rule that ate a segment from an incident that edited one.
#[test]
fn the_four_archive_failures_are_reported_distinctly() {
    let kinds = [
        break_kind::MISSING_SEGMENT,
        break_kind::REORDERED_SEGMENT,
        break_kind::TAMPERED_SEGMENT,
        break_kind::BOUNDARY_MISMATCH,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for kind in kinds {
        assert!(seen.insert(kind), "{kind} is not distinct");
    }
}

// ── export and rebuild across the boundary ───────────────────────────────────────────────────────

/// The archive walk is an iterator over one segment at a time, and it yields the chain in order.
#[test]
fn the_archived_walk_yields_every_event_in_chain_order() {
    let f = fixture(3, 4);
    append(f.store.as_ref(), 19);
    let all = f.store.audit_events(None).unwrap();
    while f.archive.run_pass(f.store.as_ref()).unwrap().segment_id.is_some() {}

    let walked: Vec<_> = ArchivedEvents::new(&f.archive, f.store.as_ref())
        .unwrap()
        .map(|e| e.unwrap())
        .collect();
    assert_eq!(walked.len(), 16);
    assert_eq!(walked, all[..16].to_vec(), "the archive holds the events unchanged");
    let hot = f.store.audit_events(None).unwrap();
    let joined: Vec<_> = walked.into_iter().chain(hot).collect();
    assert_eq!(joined, all, "archive plus hot is the whole chain");
}

/// A rebuild that cannot read the archive must not quietly produce a budget from the hot window
/// alone: that is the widened grant the counter exists to prevent, arriving by another door.
#[test]
fn a_rebuild_over_an_unreachable_archive_fails_rather_than_counting_half_the_chain() {
    let f = fixture(2, 4);
    for i in 0..8 {
        let mut payload = AuditPayload::new(format!("cap.{i}"), "conn", "allow");
        payload.summary = serde_json::json!({ "grant_id": "g_total" });
        f.store.append_audit_charged(payload, Some(GrantCharge::new("g_total"))).unwrap();
    }
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let window = GrantWindow { grant_id: "g_total", since_ms: i64::MIN };
    let before = f.store.read_grant_usage(std::slice::from_ref(&window)).unwrap();

    let entries = ArchivedEvents::new(&f.archive, f.store.as_ref()).unwrap();
    f.objects.reads_fail.store(true, Ordering::SeqCst);
    let mut walk = entries;
    assert!(f.store.rebuild_grant_usage(&mut walk).is_err(), "the rebuild refuses");

    f.objects.reads_fail.store(false, Ordering::SeqCst);
    let mut walk = ArchivedEvents::new(&f.archive, f.store.as_ref()).unwrap();
    let filed = f.store.rebuild_grant_usage(&mut walk).unwrap();
    assert_eq!(filed, 8);
    assert_eq!(
        f.store.read_grant_usage(std::slice::from_ref(&window)).unwrap(),
        before,
        "and a rebuild over archive plus hot reproduces the counter exactly"
    );
}

// ── the export route ─────────────────────────────────────────────────────────────────────────────


use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

/// Read an NDJSON export into its event lines and its footer.
async fn export(state: permaura_gateway::AppState) -> (Vec<serde_json::Value>, serde_json::Value) {
    let token = common::operator_token(state.clone()).await;
    let resp = permaura_gateway::build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri("/v1/audit/export")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024 * 1024).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let mut lines: Vec<serde_json::Value> =
        text.lines().filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
    let footer = lines.pop().expect("an export always ends with its footer");
    let footer = footer["permaura_audit_export"].clone();
    assert!(!footer.is_null(), "the last line is the footer");
    (lines, footer)
}

fn export_fixture(keep_hot: usize, batch: usize) -> (Fixture, permaura_gateway::AppState) {
    let f = fixture(keep_hot, batch);
    let state = common::seeded_with_archive(
        &f.dir.join("routed.db").to_string_lossy(),
        f.archive.clone(),
    );
    (f, state)
}

#[tokio::test]
async fn an_export_streams_the_archive_and_then_the_hot_window_as_one_chain() {
    let (f, state) = export_fixture(3, 4);
    let store = state.service.store().clone();
    append(store.as_ref(), 19);
    let whole = store.audit_events(None).unwrap();
    while f.archive.run_pass(store.as_ref()).unwrap().segment_id.is_some() {}
    assert!(store.audit_len().unwrap() < whole.len() as u64, "most of it is archived");

    let (lines, footer) = export(state).await;
    let exported: Vec<permaura_core::AuditEvent> =
        lines.into_iter().map(|l| serde_json::from_value(l).unwrap()).collect();
    assert_eq!(exported, whole, "archive plus hot, in order, unchanged");
    assert_eq!(footer["complete"], serde_json::json!(true));
    assert_eq!(footer["archive_configured"], serde_json::json!(true));
    assert!(footer["index"].is_array(), "the footer carries the index");
    assert_eq!(footer["boundary"]["base_seq"], serde_json::json!(16));
}

/// The one an incomplete export must never do is look complete.
#[tokio::test]
async fn an_export_with_the_archive_unreachable_is_marked_incomplete_never_silently_partial() {
    let (f, state) = export_fixture(3, 4);
    let store = state.service.store().clone();
    append(store.as_ref(), 19);
    while f.archive.run_pass(store.as_ref()).unwrap().segment_id.is_some() {}
    let hot = store.audit_events(None).unwrap();

    f.objects.reads_fail.store(true, Ordering::SeqCst);
    let (lines, footer) = export(state).await;

    assert_eq!(footer["complete"], serde_json::json!(false), "it says so");
    assert_eq!(lines.len(), hot.len(), "and serves the hot window rather than nothing");
    let exported: Vec<permaura_core::AuditEvent> =
        lines.into_iter().map(|l| serde_json::from_value(l).unwrap()).collect();
    assert_eq!(exported, hot);
}

/// A gateway with no archive exports what it has and says there is no archive, which is a different
/// claim from "the archive was unreachable" and from "this is everything".
#[tokio::test]
async fn an_export_from_a_gateway_with_no_archive_says_so() {
    let dir = std::env::temp_dir().join(format!(
        "permaura-export-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let state = common::seeded();
    let store = state.service.store().clone();
    append(store.as_ref(), 5);
    let whole = store.audit_events(None).unwrap();

    let (lines, footer) = export(state).await;
    assert_eq!(footer["archive_configured"], serde_json::json!(false));
    assert_eq!(footer["complete"], serde_json::json!(true), "the hot window IS the whole chain here");
    assert_eq!(lines.len(), whole.len());
    std::fs::remove_dir_all(&dir).ok();
}

// ── resuming a publication proves it before pruning ──────────────────────────────────────────────

fn resumable(f: &Fixture) -> (std::path::PathBuf, permaura_core::audit::AuditIndexEntry) {
    append(f.store.as_ref(), 10);
    let checkpoint = snapshot(f, "pre-prune");
    f.archive.run_pass(f.store.as_ref()).unwrap();
    (checkpoint, index_of(f).segments[0].clone())
}

/// A way to damage what an index entry names, and what to call it in a failure.
type Damage = (&'static str, fn(&Fixture, &permaura_core::audit::AuditIndexEntry));

/// A store rewound to before its prune finds the index naming a segment that starts at its base.
/// Whatever is wrong with what that entry names, the resume must keep every row: the index is a
/// claim, and the rows are the only other copy of the events.
#[test]
fn a_resume_over_damaged_archive_data_keeps_every_row_and_the_boundary() {
    let damages: [Damage; 6] = [
        ("corrupt bytes", |f, e| {
            f.objects.overwrite(&format!("audit/acme/e0000/{}.ndjson", e.segment_id), b"corrupt segment")
        }),
        ("missing bytes", |f, e| f.objects.lose(&format!("audit/acme/e0000/{}.ndjson", e.segment_id))),
        ("missing manifest", |f, e| {
            f.objects.lose(&format!("audit/acme/e0000/{}.manifest.json", e.segment_id))
        }),
        ("edited manifest", |f, e| {
            let name = format!("audit/acme/e0000/{}.manifest.json", e.segment_id);
            let (_, mut manifest) = f.archive.read_segment(0, &e.segment_id).unwrap();
            manifest.count += 1;
            f.objects.overwrite(&name, &serde_json::to_vec(&manifest).unwrap());
        }),
        ("an index edited without the audit key", |f, e| {
            let mut page = page_of(f, e.base_seq);
            page.segments[0].sha256 = "00".repeat(32);
            f.objects.overwrite(&page_name(e.base_seq), &serde_json::to_vec(&page).unwrap());
        }),
        ("a segment from another chain", |f, e| {
            // Well-formed and signed, under a key that is not this store's.
            let other = fixture(2, 4);
            append(other.store.as_ref(), 10);
            other.archive.run_pass(other.store.as_ref()).unwrap();
            for suffix in ["ndjson", "manifest.json"] {
                let name = format!("audit/acme/e0000/{}.{suffix}", e.segment_id);
                let generation = other.objects.head(&name).unwrap().unwrap();
                f.objects.overwrite(&name, &other.objects.get(&name, generation).unwrap());
            }
        }),
    ];
    for (damage, apply) in damages {
        let f = fixture(2, 4);
        let (checkpoint, entry) = resumable(&f);
        apply(&f, &entry);

        let rewound = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
        let boundary = rewound.audit_boundary().unwrap();
        let err = f.archive.run_pass(&rewound).unwrap_err();
        assert!(err.to_string().contains("refusing"), "{damage}: {err}");
        assert_eq!(rewound.audit_len().unwrap(), 10, "{damage}: every local row is kept");
        assert_eq!(rewound.audit_boundary().unwrap(), boundary, "{damage}: and so is the boundary");
        assert_eq!(rewound.verify_audit().unwrap(), None, "{damage}: and the hot chain still verifies");
    }
}

/// The refusal is not a dead end: once the archive holds what the index says, the same resume
/// adopts it, prunes once, and publishes nothing new.
#[test]
fn a_resume_refused_over_corrupt_bytes_adopts_once_the_bytes_are_whole_again() {
    let f = fixture(2, 4);
    let (checkpoint, entry) = resumable(&f);
    let name = format!("audit/acme/e0000/{}.ndjson", entry.segment_id);
    let (good, _) = f.archive.read_segment(0, &entry.segment_id).unwrap();
    f.objects.overwrite(&name, b"corrupt segment");

    let rewound = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
    assert!(f.archive.run_pass(&rewound).is_err());
    assert_eq!(rewound.audit_len().unwrap(), 10);

    f.objects.overwrite(&name, &good);
    let outcome = f.archive.run_pass(&rewound).unwrap();
    assert!(outcome.reason.contains("adopted"), "{}", outcome.reason);
    assert_eq!(outcome.pruned, 4);
    assert_eq!(index_of(&f).segments.len(), 1, "and nothing was republished");
    assert!(f.archive.verify_full(&rewound).unwrap().chain_intact);
}

/// A fresh pass appends after the page of the segment before the window, so a page that does not verify is refused
/// before anything is published after it.
#[test]
fn a_pass_does_not_append_to_an_index_it_cannot_verify() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 14);
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let mut page = page_of(&f, 0);
    page.segments[0].head_hash = "00".repeat(32);
    f.objects.overwrite(&page_name(0), &serde_json::to_vec(&page).unwrap());

    let err = f.archive.run_pass(f.store.as_ref()).unwrap_err();
    assert!(err.to_string().contains("does not verify"), "{err}");
    assert_eq!(f.store.audit_len().unwrap(), 10, "nothing further was pruned");
}

// ── restores are branches ────────────────────────────────────────────────────────────────────────

fn drain(archive: &AuditArchive, store: &dyn Store) {
    while archive.run_pass(store).unwrap().segment_id.is_some() {}
}

/// A restore as reconciliation performs one: claim an epoch in the bucket, then fork into it.
fn fork_as_restore(archive: &AuditArchive, store: &dyn Store, restore_id: &str) -> u64 {
    let parent = store.audit_boundary().unwrap().unwrap();
    let epoch = archive.claim_epoch(&parent, restore_id).unwrap();
    assert!(store.fork_audit_epoch(epoch, restore_id).unwrap());
    epoch
}

/// A reproduction, inverted: a checkpoint taken before the original archived anything is
/// restored after the original archived twice. The restored history leaves the original at seq 0, so
/// every original segment is the abandoned suffix, and the restored archive verifies on its own.
#[test]
fn a_restore_from_before_any_prune_verifies_as_its_own_history() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    let checkpoint = snapshot(&f, "checkpoint");
    f.archive.run_pass(f.store.as_ref()).unwrap();
    f.archive.run_pass(f.store.as_ref()).unwrap();
    assert!(f.archive.verify_full(f.store.as_ref()).unwrap().chain_intact);

    let restored = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
    assert_eq!(fork_as_restore(&f.archive, &restored, "hold-a"), 1);
    append(&restored, 3);
    drain(&f.archive, &restored);

    let report = f.archive.verify_full(&restored).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.lineage, vec![0, 1]);
    assert_eq!(report.abandoned, 2, "the original's two segments are kept and counted, not walked");
    assert_eq!(report.verified_to, Some(12));
    let original = f.archive.verify_full(f.store.as_ref()).unwrap();
    assert!(original.chain_intact, "and the original still verifies as its own history: {original:?}");
    assert_eq!(original.lineage, vec![0]);
}

/// The same after a prune: the restored history is the original's archive up to the checkpoint's
/// base, then its own epoch, and nothing the original archived after the checkpoint.
#[test]
fn a_restore_from_after_a_prune_verifies_as_its_own_history() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let checkpoint = snapshot(&f, "checkpoint");
    append(f.store.as_ref(), 6);
    drain(&f.archive, f.store.as_ref());

    let restored = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
    assert_eq!(base_seq(&restored), 4);
    let epoch = fork_as_restore(&f.archive, &restored, "hold-a");
    append(&restored, 5);
    drain(&f.archive, &restored);

    let report = f.archive.verify_full(&restored).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.lineage, vec![0, epoch]);
    assert!(report.abandoned >= 1, "{report:?}");
    let child = f.archive.read_index(epoch).unwrap();
    assert_eq!(child.segments[0].base_seq, 4, "the restored epoch starts where the checkpoint's base was");
    assert_eq!(child.fork.as_ref().map(|f| f.restore_id.as_str()), Some("hold-a"), "and its index names the fork");
    assert!(f.archive.verify_full(f.store.as_ref()).unwrap().chain_intact);
}

/// A restore of a restore follows both forks, not every epoch in order.
#[test]
fn a_restore_of_a_restored_store_follows_its_whole_lineage() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let first = snapshot(&f, "first");
    drain(&f.archive, f.store.as_ref());

    let a = Arc::new(SqliteStore::open(&first.to_string_lossy()).unwrap());
    let ea = fork_as_restore(&f.archive, a.as_ref(), "hold-a");
    append(a.as_ref(), 6);
    f.archive.run_pass(a.as_ref()).unwrap();
    let second = f.dir.join("second.db");
    a.snapshot_to(&second).unwrap();
    std::fs::copy(f.dir.join("first.db.auditkey"), f.dir.join("second.db.auditkey")).unwrap();
    drain(&f.archive, a.as_ref());

    let b = SqliteStore::open(&second.to_string_lossy()).unwrap();
    let eb = fork_as_restore(&f.archive, &b, "hold-b");
    append(&b, 4);
    drain(&f.archive, &b);

    let report = f.archive.verify_full(&b).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.lineage, vec![0, ea, eb]);
    assert_eq!(b.audit_boundary().unwrap().unwrap().lineage.len(), 2);
    assert!(f.archive.verify_full(a.as_ref()).unwrap().chain_intact, "and the branch it left still verifies");
}

/// Two restores of one checkpoint read the same epoch out of it, so the number comes from the bucket:
/// each gets its own namespace, and a retry of either gets back the one it already claimed.
#[test]
fn two_restores_of_one_checkpoint_claim_distinct_epochs() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let checkpoint = snapshot(&f, "checkpoint");
    std::fs::copy(&checkpoint, f.dir.join("checkpoint-b.db")).unwrap();
    std::fs::copy(f.dir.join("checkpoint.db.auditkey"), f.dir.join("checkpoint-b.db.auditkey")).unwrap();
    drain(&f.archive, f.store.as_ref());

    let a = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
    let b = SqliteStore::open(&f.dir.join("checkpoint-b.db").to_string_lossy()).unwrap();
    let parent = a.audit_boundary().unwrap().unwrap();
    assert_eq!(parent, b.audit_boundary().unwrap().unwrap(), "both restores start from the same epoch");

    let ea = fork_as_restore(&f.archive, &a, "hold-a");
    let eb = fork_as_restore(&f.archive, &b, "hold-b");
    assert_ne!(ea, eb, "distinct identities");
    assert_eq!(f.archive.claim_epoch(&parent, "hold-a").unwrap(), ea, "a retry of the first adopts its own claim");
    assert_eq!(f.archive.claim_epoch(&parent, "hold-b").unwrap(), eb);

    append(&a, 3);
    append(&b, 5);
    drain(&f.archive, &a);
    drain(&f.archive, &b);
    for (store, epoch) in [(&a, ea), (&b, eb)] {
        let report = f.archive.verify_full(store).unwrap();
        assert!(report.chain_intact, "{report:?}");
        assert_eq!(report.lineage, vec![0, epoch]);
    }
}

/// A reproduction of an unclaimed-epoch fork, inverted. A restore forked into epoch 1 without claiming it, while an
/// earlier restore of the same checkpoint owns epoch 1, and wrote events there. Retries and a reopen
/// used to fail for ever; the next pass now moves the history forward to a newly claimed epoch,
/// records the move in the chain, and every row reaches a complete, distinct, verifiable lineage.
#[test]
fn a_restore_stranded_in_another_restores_epoch_moves_forward_and_keeps_every_row() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    let checkpoint = snapshot(&f, "checkpoint");
    std::fs::copy(&checkpoint, f.dir.join("checkpoint-b.db")).unwrap();
    std::fs::copy(f.dir.join("checkpoint.db.auditkey"), f.dir.join("checkpoint-b.db.auditkey")).unwrap();

    let a = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
    assert_eq!(fork_as_restore(&f.archive, &a, "prior-restore"), 1);
    drain(&f.archive, &a);
    let epoch_one = f.objects.names().into_iter().filter(|n| n.contains("/e0001/")).count();

    let path_b = f.dir.join("checkpoint-b.db");
    let b = SqliteStore::open(&path_b.to_string_lossy()).unwrap();
    assert!(b.fork_audit_epoch(1, "outage-restore").unwrap(), "forked with no claim, as the old fallback did");
    append(&b, 3);
    let before: Vec<_> = b.audit_events(None).unwrap();
    assert_eq!(before.len(), 13);

    let outcome = f.archive.run_pass(&b).unwrap();
    assert!(outcome.reason.contains("moved"), "{}", outcome.reason);
    let boundary = b.audit_boundary().unwrap().unwrap();
    assert_eq!(boundary.epoch, 2);
    assert_eq!(boundary.lineage.iter().map(|l| l.epoch).collect::<Vec<_>>(), vec![1, 2]);
    let moved = b.audit_events(Some(1)).unwrap().pop().unwrap();
    assert_eq!(moved.payload.action, permaura_gateway::archive::EPOCH_MOVED, "the move is in the chain");
    drop(b);

    // A reopen and repeated passes carry on in epoch 2 rather than failing on epoch 1.
    let b = SqliteStore::open(&path_b.to_string_lossy()).unwrap();
    assert_eq!(b.audit_boundary().unwrap().unwrap().epoch, 2);
    drain(&f.archive, &b);
    assert_eq!(
        f.objects.names().into_iter().filter(|n| n.contains("/e0001/")).count(),
        epoch_one,
        "nothing was written into the other restore's epoch"
    );

    let report = f.archive.verify_full(&b).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.lineage, vec![0, 1, 2]);
    let walked: Vec<_> = ArchivedEvents::new(&f.archive, &b).unwrap().map(|e| e.unwrap()).collect();
    let whole: Vec<_> = walked.into_iter().chain(b.audit_events(None).unwrap()).collect();
    assert_eq!(whole.len(), 14, "all 13 rows and the move event");
    assert_eq!(whole[..13].to_vec(), before, "every row, unchanged, in order");
    let mut walk = ArchivedEvents::new(&f.archive, &b).unwrap();
    b.rebuild_grant_usage(&mut walk).expect("the rebuild reads the same complete lineage");
    assert!(f.archive.verify_full(&a).unwrap().chain_intact, "and the other restore's history is untouched");
}

/// Moving forward is only safe while nothing of the store's history has left the hot window in the
/// stranded epoch. A claim that names another restore after this store published under it was
/// replaced by something other than a writer, and is refused with every row kept.
#[test]
fn a_claim_replaced_after_publication_is_refused_and_keeps_every_row() {
    let f = fixture(2, 4);
    append(f.store.as_ref(), 10);
    let checkpoint = snapshot(&f, "checkpoint");
    let a = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
    assert_eq!(fork_as_restore(&f.archive, &a, "hold-a"), 1);
    f.archive.run_pass(&a).unwrap();
    append(&a, 4);
    let held = a.audit_len().unwrap();
    let boundary = a.audit_boundary().unwrap();

    let mut claim: serde_json::Value = {
        let generation = f.objects.head("audit/acme/e0001/fork.json").unwrap().unwrap();
        serde_json::from_slice(&f.objects.get("audit/acme/e0001/fork.json", generation).unwrap()).unwrap()
    };
    claim["fork"]["restore_id"] = serde_json::json!("hold-someone-else");
    f.objects.overwrite("audit/acme/e0001/fork.json", &serde_json::to_vec(&claim).unwrap());

    // A fresh writer, as after a restart, so nothing is taken from the first one's memory.
    let archive = AuditArchive::with_limits(f.objects.clone(), "acme", "audit", 4, 2);
    let err = archive.run_pass(&a).unwrap_err();
    assert!(err.to_string().contains("already archived under it"), "{err}");
    assert_eq!(a.audit_len().unwrap(), held);
    assert_eq!(a.audit_boundary().unwrap(), boundary, "no move and no prune");
}

/// Export, rebuild and verification read one reader, so they select the same history: the root
/// epoch up to the fork, the restored epoch after it, and nothing from the branch the restore left.
#[test]
fn the_archived_walk_of_a_restored_store_is_exactly_its_selected_history() {
    let f = fixture(2, 4);
    let prefix: Vec<_> = {
        append(f.store.as_ref(), 10);
        f.store.audit_events(None).unwrap()
    };
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let checkpoint = snapshot(&f, "checkpoint");
    append(f.store.as_ref(), 6);
    drain(&f.archive, f.store.as_ref());

    let restored = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
    fork_as_restore(&f.archive, &restored, "hold-a");
    append(&restored, 5);
    let own = restored.audit_events(None).unwrap();
    drain(&f.archive, &restored);

    let walked: Vec<_> = ArchivedEvents::new(&f.archive, &restored).unwrap().map(|e| e.unwrap()).collect();
    let joined: Vec<_> = walked.into_iter().chain(restored.audit_events(None).unwrap()).collect();
    let expected: Vec<_> = prefix[..4].iter().cloned().chain(own).collect();
    assert_eq!(joined, expected, "the original's prefix, then the restored store's own events");
}

// ── budget rebuild reads only complete, authenticated history ────────────────────────────────────

fn charge(store: &dyn Store, n: usize) {
    for i in 0..n {
        let mut payload = AuditPayload::new(format!("cap.{i}"), "conn", "allow");
        payload.summary = serde_json::json!({ "grant_id": "g_total" });
        store.append_audit_charged(payload, Some(GrantCharge::new("g_total"))).unwrap();
    }
}

fn charged(store: &dyn Store) -> u64 {
    let window = GrantWindow { grant_id: "g_total", since_ms: i64::MIN };
    store.read_grant_usage(std::slice::from_ref(&window)).unwrap().total("g_total")
}

/// A reproduction, inverted: an index entry removed without re-signing made the rebuild count
/// 6 of 10. The walk now checks the index before trusting it, and the counter is left as it was.
#[test]
fn a_rebuild_over_an_index_edited_without_its_key_is_refused_and_keeps_the_counter() {
    let f = fixture(2, 4);
    charge(f.store.as_ref(), 10);
    drain(&f.archive, f.store.as_ref());
    assert_eq!(charged(f.store.as_ref()), 10);

    let mut page = page_of(&f, 0);
    page.segments[0].end_seq += 4;
    f.objects.overwrite(&page_name(0), &serde_json::to_vec(&page).unwrap());
    assert!(!f.archive.verify_full(f.store.as_ref()).unwrap().chain_intact);

    let mut walk = ArchivedEvents::new(&f.archive, f.store.as_ref()).unwrap();
    assert!(f.store.rebuild_grant_usage(&mut walk).is_err(), "the rebuild refuses");
    assert_eq!(charged(f.store.as_ref()), 10, "and the counter is untouched");
}

/// The same with the index re-signed by the store's own key: the walk reaches the boundary short and
/// says so, rather than ending as if the history were whole.
#[test]
fn a_rebuild_over_a_resigned_index_missing_a_segment_is_refused_and_keeps_the_counter() {
    let f = fixture(2, 4);
    charge(f.store.as_ref(), 10);
    drain(&f.archive, f.store.as_ref());
    let last = index_of(&f).segments.pop().unwrap();
    f.objects.lose(&page_name(last.base_seq));

    let mut walk = ArchivedEvents::new(&f.archive, f.store.as_ref()).unwrap();
    assert!(f.store.rebuild_grant_usage(&mut walk).is_err());
    assert_eq!(charged(f.store.as_ref()), 10);
}

/// The other reproduction, inverted: with no archive to read, a pruned store rebuilt 2 of 10.
#[test]
fn a_rebuild_with_no_archive_after_a_prune_is_refused_and_keeps_the_counter() {
    let f = fixture(2, 4);
    charge(f.store.as_ref(), 10);
    drain(&f.archive, f.store.as_ref());
    assert!(f.store.rebuild_grant_usage(&mut std::iter::empty()).is_err());
    assert_eq!(charged(f.store.as_ref()), 10);
}

/// The archive walk and the rebuild are bound to one boundary: a prune landing between reading the
/// history and committing it is a refusal, not a gap in the count.
#[test]
fn a_rebuild_whose_boundary_moved_after_the_walk_began_is_refused() {
    let f = fixture(2, 4);
    charge(f.store.as_ref(), 10);
    f.archive.run_pass(f.store.as_ref()).unwrap();
    let mut walk = ArchivedEvents::new(&f.archive, f.store.as_ref()).unwrap();
    f.archive.run_pass(f.store.as_ref()).unwrap();

    assert!(f.store.rebuild_grant_usage(&mut walk).is_err());
    assert_eq!(charged(f.store.as_ref()), 10);
}

/// And a complete, valid history rebuilds to exactly the totals the appends filed, before a prune,
/// after one, and on a restored store.
#[test]
fn a_complete_history_rebuilds_to_the_same_totals_before_and_after_prune_and_restore() {
    let f = fixture(2, 4);
    charge(f.store.as_ref(), 10);
    assert_eq!(f.store.rebuild_grant_usage(&mut std::iter::empty()).unwrap(), 10);
    assert_eq!(charged(f.store.as_ref()), 10);

    f.archive.run_pass(f.store.as_ref()).unwrap();
    let checkpoint = snapshot(&f, "checkpoint");
    drain(&f.archive, f.store.as_ref());
    let mut walk = ArchivedEvents::new(&f.archive, f.store.as_ref()).unwrap();
    assert_eq!(f.store.rebuild_grant_usage(&mut walk).unwrap(), 10);
    assert_eq!(charged(f.store.as_ref()), 10);

    let restored = SqliteStore::open(&checkpoint.to_string_lossy()).unwrap();
    fork_as_restore(&f.archive, &restored, "hold-a");
    charge(&restored, 3);
    drain(&f.archive, &restored);
    assert_eq!(charged(&restored), 13);
    let mut walk = ArchivedEvents::new(&f.archive, &restored).unwrap();
    assert_eq!(restored.rebuild_grant_usage(&mut walk).unwrap(), 13);
    assert_eq!(charged(&restored), 13, "the restored store's own history, not the branch it left");
}

/// The route refuses a rebuild it cannot make whole: a pruned store on a gateway with no archive
/// configured answers an error and leaves every budget as it was.
#[tokio::test]
async fn the_rebuild_route_refuses_a_pruned_store_with_no_archive_configured() {
    let (f, state) = export_fixture(2, 4);
    let path = f.dir.join("routed.db");
    let store = state.service.store().clone();
    charge(store.as_ref(), 10);
    drain(&f.archive, store.as_ref());
    drop(store);
    drop(state);

    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&path.to_string_lossy()).unwrap());
    let http = Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    let state = permaura_gateway::AppState::new(
        permaura_gateway::service::EnforcementService::new(store.clone(), http),
    );
    let token = common::operator_token(state.clone()).await;
    let resp = permaura_gateway::build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/grants/rebuild-usage")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!resp.status().is_success(), "{}", resp.status());
    assert_eq!(charged(store.as_ref()), 10);
}

// ── A float in a result summary ──────────────────────────────────────────────────────────────────

/// Upstream bodies the HTTP connector parses into a float and the result summary keeps verbatim, each one a value serde_json's fast float parser reads one ulp off.
const FLOAT_BODIES: [&str; 4] = ["1e-307", "6.0e-252", "0.11124663410665806", "1.0000000000000001e-307"];

fn append_float_summaries(store: &dyn Store) {
    for body in FLOAT_BODIES {
        let mut payload = AuditPayload::new("generic_http.request", "conn", "allow");
        payload.summary = serde_json::from_slice(body.as_bytes()).expect("a JSON number");
        store.append_audit(payload).unwrap();
    }
}

/// The chain is hashed over the payload as parsed and the row keeps its text, so a restart that re-reads the text to a different value reports the chain broken from that event on.
#[test]
fn a_float_in_a_result_summary_still_verifies_after_the_store_reopens() {
    let f = fixture(1, 8);
    // A store of its own, so it can be closed and reopened the way a restart does: the fixture's stays held.
    let path = f.dir.join("floats.db").to_string_lossy().to_string();
    let store = SqliteStore::open(&path).unwrap();
    append_float_summaries(&store);
    assert_eq!(store.verify_audit().unwrap(), None, "the live chain verifies");
    drop(store);
    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(reopened.audit_len().unwrap(), FLOAT_BODIES.len() as u64);
    assert_eq!(reopened.verify_audit().unwrap(), None, "and so does the chain a restart reads back");
}

/// The same values through the archive, whose pass proves a segment by reading its NDJSON back: a summary that re-read differently refused every pass, so nothing was pruned again and the hot window climbed to the ceiling that refuses executions.
#[test]
fn a_float_in_a_result_summary_does_not_stall_the_archive() {
    let f = fixture(1, 8);
    append_float_summaries(f.store.as_ref());
    let outcome = f.archive.run_pass(f.store.as_ref()).expect("the pass publishes and prunes");
    assert!(outcome.segment_id.is_some(), "a segment was published");
    assert_eq!(base_seq(f.store.as_ref()), FLOAT_BODIES.len() as u64 - 1, "everything but the one kept hot left the store");
    let report = f.archive.verify_full(f.store.as_ref()).unwrap();
    assert!(report.chain_intact, "{report:?}");
}
