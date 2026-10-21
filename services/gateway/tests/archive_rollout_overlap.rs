//! A build before index pages and this one, both running during a rollout.
//!
//! A build before pages keeps one whole-epoch `index.json` and rewrites it on every pass at the generation it read;
//! this one writes one create-only page per segment. Cloud Run keeps the previous revision serving through a rollout,
//! so for a while both can publish into one epoch. The failing schedule: `index.json` ends at seq 3, this build
//! publishes the page for 4..=7 and prunes to 8, then the older instance publishes its own 4..=5 and rewrites
//! `index.json` at the generation it had read, which succeeded because nothing else touched that file. Every later full
//! verification walked `index.json` to 5, found no page at 6 and reported `boundary_mismatch`, permanently.
//!
//! Two things close it. The first page after `index.json` is named in it as well, at the generation read (the
//! hand-over), so whichever of the two writers rewrites it second meets a conflict. And a reader that finds both a page
//! and an `index.json` entry for one seq follows the page unless only the other continues the history, so a segment an
//! older instance appended after the hand-over is passed over. The older writer is simulated here by what it does to
//! the bucket: publish a segment create-only, then rewrite `index.json` at the generation it read.
#![cfg(feature = "sqlite")]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use permaura_core::audit::{segment_id, sha256_hex, AuditArchiveIndex, AuditIndexEntry, AuditSegmentDraft};
use permaura_core::{AuditEvent, AuditPayload};
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

type Hook = Box<dyn FnOnce(&MemoryObjectStore) + Send>;

/// A bucket that can run an older writer's rewrite of `index.json` just before this build's own write of it lands.
#[derive(Default)]
struct Bucket {
    inner: MemoryObjectStore,
    before_index_write: Mutex<Option<Hook>>,
}

impl ObjectStore for Bucket {
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
    fn put_if_generation(&self, n: &str, b: &[u8], e: u64, m: &BTreeMap<String, String>) -> Result<PutOutcome, GatewayError> {
        if n.ends_with("/index.json") {
            let hook = self.before_index_write.lock().unwrap().take();
            if let Some(hook) = hook {
                hook(&self.inner);
            }
        }
        self.inner.put_if_generation(n, b, e, m)
    }
    fn describe(&self) -> String {
        "rollout bucket".into()
    }
}

struct Rig {
    dir: std::path::PathBuf,
    store: Arc<dyn Store>,
    bucket: Arc<Bucket>,
    writer: AuditArchive,
}

/// Publish `events` as one segment the way either build does: the bytes and the manifest, create-only.
fn publish(objects: &MemoryObjectStore, writer: &AuditArchive, store: &dyn Store, prev_hash: &str, events: &[AuditEvent]) -> AuditIndexEntry {
    let bytes = archive::to_ndjson(events).unwrap();
    let sha = sha256_hex(&bytes);
    let (base_seq, end_seq) = (events[0].seq, events[events.len() - 1].seq);
    let head_hash = events[events.len() - 1].hash.clone();
    let id = segment_id(base_seq, end_seq);
    let manifest = store
        .seal_audit_segment(AuditSegmentDraft {
            tenant: archive::LOCAL_TENANT.into(),
            epoch: 0,
            base_seq,
            end_seq,
            count: events.len() as u64,
            prev_hash: prev_hash.into(),
            head_hash: head_hash.clone(),
            sha256: sha.clone(),
            written_at: "2026-10-14T00:00:00Z".into(),
            gateway_version: "1.3.46".into(),
        })
        .unwrap();
    let prefix = writer.epoch_prefix(0);
    for (name, body) in [(format!("{prefix}/{id}.ndjson"), bytes), (format!("{prefix}/{id}.manifest.json"), serde_json::to_vec(&manifest).unwrap())] {
        assert!(matches!(objects.put_if_generation(&name, &body, 0, &BTreeMap::new()).unwrap(), PutOutcome::Stored(_)), "{name}");
    }
    AuditIndexEntry { segment_id: id, base_seq, end_seq, prev_hash: prev_hash.into(), head_hash, sha256: sha }
}

/// `index.json` as it stands, and its generation.
fn whole_index(objects: &MemoryObjectStore, writer: &AuditArchive) -> (AuditArchiveIndex, u64) {
    let generation = objects.head(&writer.index_name(0)).unwrap().expect("an index.json");
    (serde_json::from_slice(&objects.get(&writer.index_name(0), generation).unwrap()).unwrap(), generation)
}

/// How a build before pages finishes a pass: `index` with `entry` appended, re-signed, written at `generation`.
fn rewrite_index(objects: &MemoryObjectStore, writer: &AuditArchive, store: &dyn Store, mut index: AuditArchiveIndex, generation: u64, entry: AuditIndexEntry) -> PutOutcome {
    index.segments.push(entry);
    let sealed = store.seal_audit_index(index, "2026-10-14T00:00:01Z").unwrap();
    objects.put_if_generation(&writer.index_name(0), &serde_json::to_vec(&sealed).unwrap(), generation, &BTreeMap::new()).unwrap()
}

/// Epoch 0 as a build before pages leaves it: 16 events, segment 0..=3 published and named in `index.json`, the store
/// pruned to 4. The writer is this build, batch 4 and keep-hot 2.
fn rig(name: &str) -> Rig {
    let dir = scratch(name);
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    let bucket = Arc::new(Bucket::default());
    let writer = AuditArchive::with_limits(bucket.clone(), archive::LOCAL_TENANT, "audit", 4, 2);
    append(store.as_ref(), 16);
    let first = store.audit_events_from(0, 4).unwrap();
    let entry = publish(&bucket.inner, &writer, store.as_ref(), permaura_core::GENESIS_PREV_HASH, &first);
    let mut index = AuditArchiveIndex::empty(archive::LOCAL_TENANT.to_string(), 0);
    index.segments.push(entry.clone());
    let sealed = store.seal_audit_index(index, "2026-10-13T00:00:00Z").unwrap();
    bucket.inner.put_if_generation(&writer.index_name(0), &serde_json::to_vec(&sealed).unwrap(), 0, &BTreeMap::new()).unwrap();
    store.prune_audit_to(entry.end_seq, &entry.head_hash, &entry.segment_id).unwrap();
    Rig { dir, store, bucket, writer }
}

fn base(store: &dyn Store) -> u64 {
    store.audit_boundary().unwrap().unwrap().base_seq
}

fn bases(index: &AuditArchiveIndex) -> Vec<u64> {
    index.segments.iter().map(|e| e.base_seq).collect()
}

/// Another schedule: the older instance read `index.json` before this build's first page pass and rewrites it
/// after. The hand-over already moved that generation, so the older write is the one refused, and the history verifies.
#[test]
fn an_older_writers_index_rewrite_after_the_hand_over_is_refused() {
    let r = rig("rollout-older-second");
    let (read_by_older, generation) = whole_index(&r.bucket.inner, &r.writer);
    let older_events = r.store.audit_events_from(4, 2).unwrap();

    let pass = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!((pass.segment_id.as_deref(), pass.pruned), (Some("seg-00000000000000000004-00000000000000000007"), 4), "{pass:?}");
    assert!(r.bucket.inner.head(&r.writer.page_name(0, 4)).unwrap().is_some());
    assert_eq!(bases(&whole_index(&r.bucket.inner, &r.writer).0), [0, 4], "the hand-over named the first page in index.json");

    let older = publish(&r.bucket.inner, &r.writer, r.store.as_ref(), &read_by_older.segments[0].head_hash, &older_events);
    let outcome = rewrite_index(&r.bucket.inner, &r.writer, r.store.as_ref(), read_by_older, generation, older);
    assert!(matches!(outcome, PutOutcome::Conflict), "the older instance's rewrite at the generation it read must fail: {outcome:?}");

    append(r.store.as_ref(), 4);
    assert_eq!(r.writer.run_pass(r.store.as_ref()).unwrap().pruned, 4);
    let report = r.writer.verify_full(r.store.as_ref()).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!((report.segments, report.verified_to), (3, Some(19)), "{report:?}");
    assert_eq!(bases(&r.writer.read_index(0).unwrap()), [0, 4, 8]);
    std::fs::remove_dir_all(r.dir).ok();
}

/// The same race the other way round: the older instance's rewrite lands between this build reading `index.json` and
/// writing its hand-over. This build's write is the one refused; it publishes no page and prunes nothing, and its next
/// pass adopts the older instance's segment after proving it, then hands over after it.
#[test]
fn a_hand_over_an_older_writer_got_in_before_publishes_nothing_and_then_adopts() {
    let r = rig("rollout-older-first");
    let (read_by_older, generation) = whole_index(&r.bucket.inner, &r.writer);
    let older_events = r.store.audit_events_from(4, 2).unwrap();
    let store = r.store.clone();
    let writer = AuditArchive::with_limits(r.bucket.clone(), archive::LOCAL_TENANT, "audit", 4, 2);
    *r.bucket.before_index_write.lock().unwrap() = Some(Box::new(move |objects: &MemoryObjectStore| {
        let older = publish(objects, &writer, store.as_ref(), &read_by_older.segments[0].head_hash, &older_events);
        assert!(matches!(rewrite_index(objects, &writer, store.as_ref(), read_by_older, generation, older), PutOutcome::Stored(_)));
    }));

    let refused = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!(refused.pruned, 0, "{refused:?}");
    assert!(refused.reason.contains("another writer moved the whole-epoch index"), "{refused:?}");
    assert!(r.bucket.inner.head(&r.writer.page_name(0, 4)).unwrap().is_none(), "no page was published over the older segment");
    assert_eq!(base(r.store.as_ref()), 4);

    let adopted = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert!(adopted.reason.contains("adopted"), "{adopted:?}");
    assert_eq!(base(r.store.as_ref()), 6);
    let next = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!(next.segment_id.as_deref(), Some("seg-00000000000000000006-00000000000000000009"), "{next:?}");
    assert_eq!(bases(&whole_index(&r.bucket.inner, &r.writer).0), [0, 4, 6]);
    let report = r.writer.verify_full(r.store.as_ref()).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(bases(&r.writer.read_index(0).unwrap()), [0, 4, 6]);
    std::fs::remove_dir_all(r.dir).ok();
}

/// An older instance that adopted the hand-over's segment and then appended one of its own to `index.json` (so its
/// rewrite succeeded) leaves `index.json` naming a different segment for seqs this build's next page covers. The walk,
/// the index and the export footer follow the page the boundary moved along and pass over the stray.
#[test]
fn a_segment_an_older_writer_appended_after_the_hand_over_is_passed_over() {
    let r = rig("rollout-stray");
    assert_eq!(r.writer.run_pass(r.store.as_ref()).unwrap().pruned, 4);
    let (after_hand_over, generation) = whole_index(&r.bucket.inner, &r.writer);
    let stray_events = r.store.audit_events_from(8, 2).unwrap();
    let stray = publish(&r.bucket.inner, &r.writer, r.store.as_ref(), &after_hand_over.segments[1].head_hash, &stray_events);
    assert!(matches!(rewrite_index(&r.bucket.inner, &r.writer, r.store.as_ref(), after_hand_over, generation, stray), PutOutcome::Stored(_)));

    let pass = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!((pass.segment_id.as_deref(), pass.pruned), (Some("seg-00000000000000000008-00000000000000000011"), 4), "{pass:?}");
    assert_eq!(bases(&whole_index(&r.bucket.inner, &r.writer).0), [0, 4, 8], "index.json still carries the stray");

    let report = r.writer.verify_full(r.store.as_ref()).unwrap();
    assert!(report.chain_intact, "the walk must follow the page past the stray: {report:?}");
    assert_eq!((report.segments, report.verified_to), (3, Some(15)), "{report:?}");
    let followed = r.writer.read_index(0).unwrap();
    assert_eq!(followed.segments.iter().map(|e| (e.base_seq, e.end_seq)).collect::<Vec<_>>(), [(0, 3), (4, 7), (8, 11)]);
    let objects = r.writer.index_objects(0, 0).unwrap();
    assert_eq!(objects.len(), 3, "index.json and the two pages: {objects:?}");
    std::fs::remove_dir_all(r.dir).ok();
}

/// The reader's other branch: the boundary moved along the `index.json` entry, and a page for the same seq that the
/// history does not continue from turned up later (a fenced instance's). The walk follows the entry the history goes on
/// from, and a pass ignores a page that is not the segment the boundary names.
#[test]
fn the_entry_the_history_continues_from_is_followed_when_a_page_disagrees() {
    let r = rig("rollout-legacy-continues");
    let (index, generation) = whole_index(&r.bucket.inner, &r.writer);
    let older_events = r.store.audit_events_from(4, 2).unwrap();
    let fenced_events = r.store.audit_events_from(4, 4).unwrap();
    let older = publish(&r.bucket.inner, &r.writer, r.store.as_ref(), &index.segments[0].head_hash, &older_events);
    let prev = index.segments[0].head_hash.clone();
    assert!(matches!(rewrite_index(&r.bucket.inner, &r.writer, r.store.as_ref(), index, generation, older), PutOutcome::Stored(_)));
    assert!(r.writer.run_pass(r.store.as_ref()).unwrap().reason.contains("adopted"));
    assert_eq!(base(r.store.as_ref()), 6);

    // A page for 4..=7 a fenced instance published before its own prune failed.
    let fenced = publish(&r.bucket.inner, &r.writer, r.store.as_ref(), &prev, &fenced_events);
    let mut page = AuditArchiveIndex::empty(archive::LOCAL_TENANT.to_string(), 0);
    page.segments.push(fenced);
    let sealed = r.store.seal_audit_index(page, "2026-10-14T00:00:02Z").unwrap();
    r.bucket.inner.put_if_generation(&r.writer.page_name(0, 4), &serde_json::to_vec(&sealed).unwrap(), 0, &BTreeMap::new()).unwrap();

    let pass = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!(pass.segment_id.as_deref(), Some("seg-00000000000000000006-00000000000000000009"), "{pass:?}");
    let report = r.writer.verify_full(r.store.as_ref()).unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!((report.segments, report.verified_to), (3, Some(15)), "{report:?}");
    assert_eq!(bases(&r.writer.read_index(0).unwrap()), [0, 4, 6]);
    assert_eq!(r.writer.read_index(0).unwrap().segments[1].end_seq, 5);
    std::fs::remove_dir_all(r.dir).ok();
}
