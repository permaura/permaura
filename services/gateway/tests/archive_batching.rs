//! Past the hot-window floor the archive runs in batches, not once per call.
//!
//! Every Allow decision and every denial kicks the archive with the hot store's length. Kicking a pass whenever the
//! window held more than KEEP_HOT meant that, once the first prune had brought the window down to the floor, every
//! call's two events were published as a segment of their own and the whole signed index was rewritten, read back
//! and re-signed for each of them: cost growing with the square of executions, and hundreds of thousands of tiny
//! files for a full walk to open. A kick now runs a pass only once a full batch has accumulated above the floor, or
//! when the ceiling signals pressure; `run_pass` itself still drains whatever is eligible for the callers that drive
//! passes by hand.
#![cfg(feature = "sqlite")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use permaura_core::AuditPayload;
use permaura_gateway::archive::{self, AuditArchive};
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{MemoryObjectStore, ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

fn scratch(name: &str) -> std::path::PathBuf {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!("permaura-{name}-{}-{}", std::process::id(), NEXT_DIR.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn append(store: &dyn Store, n: usize) {
    for _ in 0..n {
        store.append_audit(AuditPayload::new("synthetic.call", "synthetic", "allow")).unwrap();
    }
}

/// The trigger itself: nothing below the floor, a full batch above it, and anything above it under pressure.
#[test]
fn a_pass_is_due_at_a_full_batch_above_the_floor_or_under_pressure() {
    let writer = AuditArchive::with_limits(Arc::new(MemoryObjectStore::new()), archive::LOCAL_TENANT, "audit", 100, 50);
    for hot in [0, 1, 49, 50] {
        assert!(!writer.due(hot, false), "{hot} is not above the floor");
        assert!(!writer.due(hot, true), "{hot} is not above the floor even under pressure");
    }
    for hot in [51, 52, 100, 149] {
        assert!(!writer.due(hot, false), "{hot} is above the floor by less than a batch");
        assert!(writer.due(hot, true), "{hot} goes under pressure");
    }
    for hot in [150, 151, 1_000] {
        assert!(writer.due(hot, false), "{hot} is a full batch above the floor");
    }
}

/// The traffic shape: steady calls just past KEEP_HOT, two events per execution and a kick at every call.
/// Expected, and now true: segments of `batch` events, and the index rewritten once per segment rather than per call.
#[test]
fn steady_traffic_past_keep_hot_does_not_publish_a_segment_per_call() {
    let dir = scratch("batched-segments");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    let objects = Arc::new(MemoryObjectStore::new());
    let writer = AuditArchive::with_limits(objects.clone(), archive::LOCAL_TENANT, "audit", 100, 50);
    append(store.as_ref(), 50);
    let mut ran = 0;
    for _call in 0..200 {
        append(store.as_ref(), 2);
        let outcome = writer.run_pass_if_due(store.as_ref(), false).unwrap();
        if outcome.segment_id.is_some() {
            ran += 1;
            assert_eq!(outcome.pruned, 100, "a pass publishes a full batch: {outcome:?}");
        } else {
            assert_eq!(outcome.reason, "below the batch threshold", "{outcome:?}");
        }
        assert!(store.audit_len().unwrap() < 150 + 2, "the window never sits far above floor plus batch");
    }
    let index = writer.read_index(0).unwrap();
    assert_eq!(ran, 4, "four full batches in 400 events");
    assert_eq!(index.segments.len(), 4, "{} segments for 400 events", index.segments.len());
    assert!(index.segments.iter().all(|s| s.end_seq - s.base_seq + 1 == 100), "{:?}", index.segments);
    // Three objects per segment (bytes, manifest, index page): the index was written four times, not two hundred.
    assert_eq!(objects.put_count(), 12, "puts");
    assert_eq!(store.audit_len().unwrap(), 50, "the window is back at the floor after the last batch");
    assert!(writer.verify_full(store.as_ref()).unwrap().chain_intact);
    std::fs::remove_dir_all(dir).ok();
}

/// Under ceiling pressure the threshold is waived: whatever is above the floor goes now, so a batch set higher than
/// the ceiling's headroom still cannot leave the window stuck at the ceiling.
#[test]
fn ceiling_pressure_publishes_a_partial_batch() {
    let dir = scratch("pressure-partial");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    let writer = AuditArchive::with_limits(Arc::new(MemoryObjectStore::new()), archive::LOCAL_TENANT, "audit", 1_000, 50);
    append(store.as_ref(), 80);
    let idle = writer.run_pass_if_due(store.as_ref(), false).unwrap();
    assert_eq!((idle.segment_id, idle.reason), (None, "below the batch threshold"));
    let under_pressure = writer.run_pass_if_due(store.as_ref(), true).unwrap();
    assert_eq!(under_pressure.pruned, 30, "{under_pressure:?}");
    assert_eq!(store.audit_len().unwrap(), 50);
    std::fs::remove_dir_all(dir).ok();
}

/// Every write and every read an archive makes, so a test can say what one pass costs.
#[derive(Default)]
struct Recorder {
    inner: MemoryObjectStore,
    puts: std::sync::Mutex<Vec<(String, u64)>>,
    gets: AtomicUsize,
}

impl ObjectStore for Recorder {
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
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(n, g)
    }
    fn put_if_generation(&self, n: &str, b: &[u8], e: u64, m: &std::collections::BTreeMap<String, String>) -> Result<PutOutcome, GatewayError> {
        self.puts.lock().unwrap().push((n.to_string(), e));
        self.inner.put_if_generation(n, b, e, m)
    }
    fn describe(&self) -> String {
        "recorder".into()
    }
}

/// The other half: the index is append-only. Every object a pass writes is created and never rewritten, each
/// segment adds one index page of its own, and the reads a pass makes do not grow with the history behind it.
#[test]
fn the_index_is_append_only_and_a_pass_reads_the_same_whatever_came_before() {
    let dir = scratch("append-only-index");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    let objects = Arc::new(Recorder::default());
    let writer = AuditArchive::with_limits(objects.clone(), archive::LOCAL_TENANT, "audit", 10, 0);
    let mut reads = Vec::new();
    for _ in 0..40 {
        append(store.as_ref(), 10);
        let before = objects.gets.load(Ordering::SeqCst);
        assert_eq!(writer.run_pass(store.as_ref()).unwrap().pruned, 10);
        reads.push(objects.gets.load(Ordering::SeqCst) - before);
    }
    assert!(reads[1..].iter().all(|n| *n == reads[1]), "reads per pass stay flat as the history grows: {reads:?}");

    let puts = objects.puts.lock().unwrap().clone();
    assert!(puts.iter().all(|(_, expected)| *expected == 0), "every write is create-only: {puts:?}");
    let mut names: Vec<&str> = puts.iter().map(|(n, _)| n.as_str()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), puts.len(), "nothing is written twice");
    assert_eq!(puts.iter().filter(|(n, _)| n.contains("/index/")).count(), 40, "one index page per segment");
    assert!(!puts.iter().any(|(n, _)| n.ends_with("/index.json")), "the whole-epoch index is never written");

    assert_eq!(writer.read_index(0).unwrap().segments.len(), 40);
    let report = writer.verify_full(store.as_ref()).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.segments, 40);
    std::fs::remove_dir_all(dir).ok();
}

/// An archive a build before index pages kept as one whole-epoch `index.json` is read as the start of the index: a
/// segment it published and never pruned is adopted, the next is added as a page after it and named in `index.json`
/// too (the hand-over, which an older build still running in the same rollout meets as a conflict), the whole history
/// verifies, and after the hand-over the old index is never rewritten.
#[test]
fn an_archive_an_earlier_build_indexed_whole_is_adopted_and_extended_with_pages() {
    let dir = scratch("legacy-index");
    let store = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    let built = Arc::new(MemoryObjectStore::new());
    let builder = AuditArchive::with_limits(built.clone(), archive::LOCAL_TENANT, "audit", 4, 2);
    append(store.as_ref(), 10);
    builder.run_pass(store.as_ref()).unwrap();
    let checkpoint = dir.join("before-second-prune.db");
    store.snapshot_to(&checkpoint).unwrap();
    std::fs::copy(dir.join("gateway.db.auditkey"), dir.join("before-second-prune.db.auditkey")).unwrap();
    builder.run_pass(store.as_ref()).unwrap();

    // What the older build left: the same segments and manifests, and one signed index naming both, with no pages.
    let legacy = Arc::new(MemoryObjectStore::new());
    let whole = builder.read_index(0).unwrap();
    assert_eq!(whole.segments.len(), 2);
    let copy = |name: String| {
        let generation = built.head(&name).unwrap().expect("published");
        legacy.put_if_generation(&name, &built.get(&name, generation).unwrap(), 0, &Default::default()).unwrap();
    };
    for entry in &whole.segments {
        copy(format!("{}/{}.ndjson", builder.epoch_prefix(0), entry.segment_id));
        copy(format!("{}/{}.manifest.json", builder.epoch_prefix(0), entry.segment_id));
    }
    let sealed = store.seal_audit_index(whole, "2026-10-01T00:00:00Z").unwrap();
    let index_name = builder.index_name(0);
    legacy.put_if_generation(&index_name, &serde_json::to_vec(&sealed).unwrap(), 0, &Default::default()).unwrap();
    let index_generation = legacy.head(&index_name).unwrap();

    // The store as it was when the older build had published its second segment and not yet pruned it.
    let rewound: Arc<dyn Store> = Arc::new(SqliteStore::open(&checkpoint.to_string_lossy()).unwrap());
    assert_eq!(rewound.audit_boundary().unwrap().unwrap().base_seq, 4);
    let writer = AuditArchive::with_limits(legacy.clone(), archive::LOCAL_TENANT, "audit", 4, 2);
    let adopted = writer.run_pass(rewound.as_ref()).unwrap();
    assert!(adopted.reason.contains("adopted"), "{adopted:?}");
    assert_eq!(rewound.audit_boundary().unwrap().unwrap().base_seq, 8);

    append(rewound.as_ref(), 6);
    let next = writer.run_pass(rewound.as_ref()).unwrap();
    assert_eq!(next.segment_id.as_deref(), Some("seg-00000000000000000008-00000000000000000011"), "{next:?}");
    assert!(legacy.head(&writer.page_name(0, 8)).unwrap().is_some(), "the new segment is a page");
    let handed_over = legacy.head(&index_name).unwrap();
    assert_ne!(handed_over, index_generation, "the hand-over names the first page in the old index too");
    let old_index: permaura_core::audit::AuditArchiveIndex =
        serde_json::from_slice(&legacy.get(&index_name, handed_over.unwrap()).unwrap()).unwrap();
    assert_eq!(old_index.segments.iter().map(|e| e.base_seq).collect::<Vec<_>>(), [0, 4, 8]);

    append(rewound.as_ref(), 4);
    let after = writer.run_pass(rewound.as_ref()).unwrap();
    assert_eq!(after.segment_id.as_deref(), Some("seg-00000000000000000012-00000000000000000015"), "{after:?}");
    assert_eq!(legacy.head(&index_name).unwrap(), handed_over, "past the hand-over the old index is not rewritten");
    assert_eq!(writer.read_index(0).unwrap().segments.len(), 4);
    let report = writer.verify_full(rewound.as_ref()).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.segments, 4, "{report:?}");
    std::fs::remove_dir_all(dir).ok();
}

/// Lowering `PERMAURA_AUDIT_ARCHIVE_KEEP_HOT` alone is the lever the hosted runbooks
/// give for forcing passes on a drill worker. With a fixed batch of 5,000 it published nothing below 5,000 eligible
/// events, so an acceptance run repeated as written (1,359 events over a floor of 600) read as a writer that cannot
/// publish. The default batch now follows a lower floor, and the default floor keeps the default batch.
#[test]
fn lowering_keep_hot_alone_still_starts_passes() {
    assert_eq!(archive::default_batch(archive::DEFAULT_KEEP_HOT), archive::DEFAULT_BATCH);
    assert_eq!(archive::default_batch(50_000), archive::DEFAULT_BATCH);
    assert_eq!(archive::default_batch(600), 600);
    assert_eq!(archive::default_batch(0), archive::MIN_DEFAULT_BATCH);

    let dir = scratch("keep-hot-drill");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    let writer = AuditArchive::with_limits(Arc::new(MemoryObjectStore::new()), archive::LOCAL_TENANT, "audit", archive::default_batch(600), 600);
    append(store.as_ref(), 1_359);
    let pass = writer.run_pass_if_due(store.as_ref(), false).unwrap();
    assert_eq!(pass.pruned, 600, "the drill publishes on the first kick: {pass:?}");
    assert!(writer.verify_full(store.as_ref()).unwrap().chain_intact);
    std::fs::remove_dir_all(dir).ok();
}

/// With `PERMAURA_AUDIT_ARCHIVE_KEEP_HOT` at 0 or 1 the derived batch was 1. Each kick comes with
/// an execution's two events, so a pass taking one never brought a drill worker's backlog down, and every pass sealed a
/// one-event segment for the retention period. The derived batch now has a floor, so a backlog drains in full batches.
#[test]
fn keep_hot_at_zero_or_one_still_drains_a_backlog_in_full_batches() {
    for keep_hot in [0, 1] {
        let batch = archive::default_batch(keep_hot);
        assert_eq!(batch, archive::MIN_DEFAULT_BATCH, "KEEP_HOT {keep_hot}");

        let dir = scratch("keep-hot-floor");
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
        let writer = AuditArchive::with_limits(Arc::new(MemoryObjectStore::new()), archive::LOCAL_TENANT, "audit", batch, keep_hot);
        append(store.as_ref(), 1_359);
        for _call in 0..40 {
            append(store.as_ref(), 2);
            writer.run_pass_if_due(store.as_ref(), false).unwrap();
        }
        let hot = store.audit_len().unwrap() as usize;
        assert!(hot < keep_hot + batch, "KEEP_HOT {keep_hot}: the backlog drained to {hot}");
        let index = writer.read_index(0).unwrap();
        assert!(index.segments.iter().all(|s| s.end_seq - s.base_seq + 1 == batch as u64), "KEEP_HOT {keep_hot}: {:?}", index.segments);
        assert!(writer.verify_full(store.as_ref()).unwrap().chain_intact);
        std::fs::remove_dir_all(dir).ok();

        // The batch of one the floor replaces: the same calls leave the backlog where it was.
        let dir = scratch("keep-hot-one");
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
        let writer = AuditArchive::with_limits(Arc::new(MemoryObjectStore::new()), archive::LOCAL_TENANT, "audit", 1, keep_hot);
        append(store.as_ref(), 1_359);
        for _call in 0..40 {
            append(store.as_ref(), 2);
            writer.run_pass_if_due(store.as_ref(), false).unwrap();
        }
        assert!(store.audit_len().unwrap() >= 1_359, "KEEP_HOT {keep_hot}: a batch of one never drains");
        std::fs::remove_dir_all(dir).ok();
    }
}
