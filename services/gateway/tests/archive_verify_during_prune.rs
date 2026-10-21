//! An archive pass that prunes while `verify_full` walks the archive is not a broken chain.
//!
//! The walk pins the boundary it starts from, proves every segment below it, then reads the hot window from that base.
//! A pass that lands in between publishes and proves the next segment and prunes the window on, so a read from the
//! old base used to come back starting at the new one and the report said `hot_window` broken at exactly that seq: a
//! false tamper alarm in the console's "Verify full history" and in the hosted verify runbook. The walk now notices the
//! window moved, proves the newly archived segments out of the index and carries on from the new base.
#![cfg(feature = "sqlite")]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

fn lowest_hot_seq(store: &dyn Store) -> Option<u64> {
    store.audit_events_from(0, 1).unwrap().first().map(|e| e.seq)
}

/// Parks the first `get` of an object whose name contains `pattern` after arming until released, so a pass can land mid-walk.
struct Gated {
    inner: Arc<MemoryObjectStore>,
    pattern: Mutex<&'static str>,
    armed: AtomicBool,
    entered: Mutex<std::sync::mpsc::Sender<String>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl ObjectStore for Gated {
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
        if n.contains(*self.pattern.lock().unwrap()) && self.armed.swap(false, Ordering::SeqCst) {
            self.entered.lock().unwrap().send(n.to_string()).unwrap();
            self.release.lock().unwrap().recv_timeout(Duration::from_secs(30)).expect("released");
        }
        self.inner.get(n, g)
    }
    fn put_if_generation(&self, n: &str, b: &[u8], e: u64, m: &BTreeMap<String, String>) -> Result<PutOutcome, GatewayError> {
        self.inner.put_if_generation(n, b, e, m)
    }
    fn describe(&self) -> String {
        "gated".into()
    }
}

struct Rig {
    dir: std::path::PathBuf,
    store: Arc<dyn Store>,
    objects: Arc<Gated>,
    writer: Arc<AuditArchive>,
    entered: std::sync::mpsc::Receiver<String>,
    release: std::sync::mpsc::Sender<()>,
}

/// A store with 20 events, one segment (0..=9) archived and 10 hot, under a writer of batch 10 and keep-hot 10.
fn rig(name: &str) -> Rig {
    let dir = scratch(name);
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let objects = Arc::new(Gated {
        inner: Arc::new(MemoryObjectStore::new()),
        pattern: Mutex::new(".ndjson"),
        armed: AtomicBool::new(false),
        entered: Mutex::new(entered_tx),
        release: Mutex::new(release_rx),
    });
    let writer = Arc::new(AuditArchive::with_limits(objects.clone(), archive::LOCAL_TENANT, "audit", 10, 10));
    append(store.as_ref(), 20);
    let p1 = writer.run_pass(store.as_ref()).unwrap();
    assert_eq!(p1.pruned, 10, "{p1:?}");
    assert_eq!(lowest_hot_seq(store.as_ref()), Some(10));
    Rig { dir, store, objects, writer, entered: entered_rx, release: release_tx }
}

/// Start a full verification that parks on its first segment read; returns the join handle once it is parked.
fn parked_walk(r: &Rig) -> std::thread::JoinHandle<archive::VerificationReport> {
    r.objects.armed.store(true, Ordering::SeqCst);
    let (w, s) = (r.writer.clone(), r.store.clone());
    let verifier = std::thread::spawn(move || w.verify_full(s.as_ref()).unwrap());
    let parked_on = r.entered.recv_timeout(Duration::from_secs(30)).expect("the walk reaches a segment read");
    assert!(parked_on.ends_with("seg-00000000000000000000-00000000000000000009.ndjson"), "{parked_on}");
    verifier
}

/// The reproduction: one pass prunes 10..=19 while the walk is parked on segment 0..=9.
#[test]
fn a_prune_during_a_full_verification_is_not_a_broken_chain() {
    let r = rig("verify-race");
    append(r.store.as_ref(), 10);
    let quiet = r.writer.verify_full(r.store.as_ref()).unwrap();
    assert!(quiet.chain_intact, "control must be intact: {quiet:?}");
    assert_eq!((quiet.segments, quiet.verified_to), (1, Some(29)));

    let verifier = parked_walk(&r);
    let p2 = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!((p2.segment_id.as_deref(), p2.pruned), (Some("seg-00000000000000000010-00000000000000000019"), 10), "{p2:?}");
    assert_eq!(lowest_hot_seq(r.store.as_ref()), Some(20));
    r.release.send(()).unwrap();
    let report = verifier.join().unwrap();
    assert!(report.chain_intact, "nothing was tampered with, yet: {report:?}");
    assert_eq!(report.first_break, None);
    assert_eq!(report.segments, 2, "the segment the pass published mid-walk was proved too: {report:?}");
    assert_eq!(report.verified_to, Some(29), "{report:?}");

    let after = r.writer.verify_full(r.store.as_ref()).unwrap();
    assert!(after.chain_intact, "{after:?}");
    std::fs::remove_dir_all(r.dir).ok();
}

/// Two passes land while the walk is parked, and more events arrive after them: the walk follows the window
/// through both segments and still reads the hot tail it had never seen.
#[test]
fn several_prunes_during_a_full_verification_are_followed_in_one_go() {
    let r = rig("verify-race-twice");
    append(r.store.as_ref(), 20);
    let verifier = parked_walk(&r);
    for expected in ["seg-00000000000000000010-00000000000000000019", "seg-00000000000000000020-00000000000000000029"] {
        let p = r.writer.run_pass(r.store.as_ref()).unwrap();
        assert_eq!((p.segment_id.as_deref(), p.pruned), (Some(expected), 10), "{p:?}");
    }
    assert_eq!(lowest_hot_seq(r.store.as_ref()), Some(30));
    append(r.store.as_ref(), 5);
    r.release.send(()).unwrap();
    let report = verifier.join().unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.segments, 3, "{report:?}");
    assert_eq!(report.verified_to, Some(44), "{report:?}");
    std::fs::remove_dir_all(r.dir).ok();
}

/// Following a prune is not a licence to accept anything: a segment the mid-walk pass published is still proved, so
/// one corrupted in the bucket after publication is reported as tampered at its own seq, not waved through.
#[test]
fn a_segment_published_mid_walk_is_still_proved() {
    let r = rig("verify-race-tampered");
    append(r.store.as_ref(), 10);
    let verifier = parked_walk(&r);
    let p2 = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!(p2.pruned, 10, "{p2:?}");
    r.objects.inner.corrupt(
        &format!("{}/seg-00000000000000000010-00000000000000000019.ndjson", r.writer.epoch_prefix(0)),
        b"not the events that were signed".to_vec(),
    );
    r.release.send(()).unwrap();
    let report = verifier.join().unwrap();
    assert!(!report.chain_intact, "{report:?}");
    assert_eq!(report.break_kind, Some(archive::break_kind::TAMPERED_SEGMENT), "{report:?}");
    assert_eq!(report.first_break, Some(10), "{report:?}");
    std::fs::remove_dir_all(r.dir).ok();
}

/// The residual case: a pass that lands between the walk's `head` of an index object and its `get` of
/// that generation. The pass used to overwrite the one whole-epoch index, so the `get` missed and the walk reported
/// the chain unreadable; index pages are written once, so the generation read is still there and the walk follows the
/// prune as above.
#[test]
fn a_pass_between_reading_an_index_pages_generation_and_its_bytes_is_not_a_broken_chain() {
    let r = rig("verify-race-index");
    append(r.store.as_ref(), 10);
    *r.objects.pattern.lock().unwrap() = "/index/";
    r.objects.armed.store(true, Ordering::SeqCst);
    let (w, st) = (r.writer.clone(), r.store.clone());
    let verifier = std::thread::spawn(move || w.verify_full(st.as_ref()).unwrap());
    let parked_on = r.entered.recv_timeout(Duration::from_secs(30)).expect("the walk reaches an index read");
    assert!(parked_on.ends_with("/index/00000000000000000000.json"), "{parked_on}");

    let p2 = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!(p2.pruned, 10, "{p2:?}");
    r.release.send(()).unwrap();
    let report = verifier.join().unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!((report.segments, report.verified_to), (2, Some(29)), "{report:?}");
    std::fs::remove_dir_all(r.dir).ok();
}

/// The same window on an index an older writer still rewrites (the whole-epoch `index.json`, which this build only
/// reads): a generation that moves between the `head` and the `get` is read again rather than reported unreadable.
#[test]
fn an_index_rewritten_between_reading_its_generation_and_its_bytes_is_read_again() {
    let r = rig("verify-race-rewritten");
    let name = r.writer.index_name(0);
    let whole = r.writer.read_index(0).unwrap();
    let sealed = r.store.seal_audit_index(whole, "2026-10-01T00:00:00Z").unwrap();
    let bytes = serde_json::to_vec(&sealed).unwrap();
    r.objects.inner.put_if_generation(&name, &bytes, 0, &BTreeMap::new()).unwrap();
    *r.objects.pattern.lock().unwrap() = "/index.json";
    r.objects.armed.store(true, Ordering::SeqCst);
    let (w, st) = (r.writer.clone(), r.store.clone());
    let verifier = std::thread::spawn(move || w.verify_full(st.as_ref()).unwrap());
    let parked_on = r.entered.recv_timeout(Duration::from_secs(30)).expect("the walk reaches the index read");
    assert!(parked_on.ends_with("/index.json"), "{parked_on}");

    let generation = r.objects.inner.head(&name).unwrap().unwrap();
    assert!(matches!(r.objects.inner.put_if_generation(&name, &bytes, generation, &BTreeMap::new()).unwrap(), PutOutcome::Stored(_)));
    r.release.send(()).unwrap();
    let report = verifier.join().unwrap();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!((report.segments, report.verified_to), (1, Some(19)), "{report:?}");
    std::fs::remove_dir_all(r.dir).ok();
}

/// A store that moves into another epoch while the walk runs, as a pass moving it out
/// of an epoch another restore claimed does, and then prunes, was reported with `chain_intact: false` and kind
/// `window_moved`, which the console and the hosted verify script read as a broken chain. The walk now starts again
/// from the store's new boundary and proves the history it has now.
#[test]
fn an_epoch_move_and_a_prune_during_a_full_verification_are_walked_again() {
    let r = rig("verify-race-epoch");
    append(r.store.as_ref(), 10);
    let verifier = parked_walk(&r);
    assert!(r.store.fork_audit_epoch(1, "restore_synthetic_move").unwrap());
    let p2 = r.writer.run_pass(r.store.as_ref()).unwrap();
    assert_eq!(p2.pruned, 10, "{p2:?}");
    assert_eq!(r.store.audit_boundary().unwrap().unwrap().epoch, 1);
    r.release.send(()).unwrap();
    let report = verifier.join().unwrap();
    assert!(report.chain_intact, "an epoch move is not a broken chain: {report:?}");
    assert_eq!(report.break_kind, None, "{report:?}");
    assert_eq!(report.lineage, vec![0, 1], "{report:?}");
    assert_eq!((report.segments, report.verified_to), (2, Some(29)), "{report:?}");
    std::fs::remove_dir_all(r.dir).ok();
}

/// A store that is still moving after every walk is answered with an error that claims nothing either way, never with
/// a report that says the chain is broken; the next quiet walk proves it intact.
#[test]
fn a_store_that_keeps_moving_under_the_walk_is_a_conflict_not_a_broken_chain() {
    let r = rig("verify-race-moving");
    // Read once per walk, so each park is the start of a new one.
    *r.objects.pattern.lock().unwrap() = "e0000/seg-00000000000000000000-00000000000000000009.ndjson";
    r.objects.armed.store(true, Ordering::SeqCst);
    let (w, st) = (r.writer.clone(), r.store.clone());
    let verifier = std::thread::spawn(move || w.verify_full(st.as_ref()));
    for epoch in 1..=archive::VERIFY_ATTEMPTS as u64 {
        r.entered.recv_timeout(Duration::from_secs(30)).expect("the walk reaches a segment read");
        append(r.store.as_ref(), 10);
        assert!(r.store.fork_audit_epoch(epoch, &format!("restore_synthetic_{epoch}")).unwrap());
        assert_eq!(r.writer.run_pass(r.store.as_ref()).unwrap().pruned, 10);
        if epoch < archive::VERIFY_ATTEMPTS as u64 {
            r.objects.armed.store(true, Ordering::SeqCst);
        }
        r.release.send(()).unwrap();
    }
    match verifier.join().unwrap() {
        Err(GatewayError::Conflict(detail)) => assert!(detail.contains("nothing is claimed either way"), "{detail}"),
        other => panic!("a store that kept moving is neither intact nor broken: {other:?}"),
    }
    let quiet = r.writer.verify_full(r.store.as_ref()).unwrap();
    assert!(quiet.chain_intact, "{quiet:?}");
    std::fs::remove_dir_all(r.dir).ok();
}
