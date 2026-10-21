//! What the hot audit store actually costs at size, which is where
//! [`permaura_gateway::audit_ceiling`]'s defaults come from.
//!
//! Ignored by default: filling a chain signs one Ed25519 event per row, so a quarter of a million
//! of them is minutes rather than milliseconds and has no place in the suite a push runs. Run it
//! when the numbers need re-deriving:
//!
//! ```text
//! cargo test -p permaura-gateway --release --test audit_scale -- --ignored --nocapture
//! ```
//!
//! No `PERMAURA_DEV` or `PERMAURA_HOME` in front of it any more: `scratch()` pins both, the same
//! way every other fixture in this suite does.
//!
//! What it measures, and why those two numbers:
//!
//! - **Snapshot bytes.** Every mutation on a hosted worker uploads the whole `VACUUM INTO` copy,
//!   and a 512 MiB instance has to hold the database, that copy and the upload buffer at once.
//!   `store::persisted::DEFAULT_WARN_BYTES` (64 MiB) is the existing marker on the same axis.
//! - **Open time.** `load_audit_events` replays every row above the boundary into memory at every
//!   cold start, and a scale-to-zero worker cold-starts constantly.
//! - **Live heap: resident, per clone, and per authorization.** The chain is resident in a
//!   `Vec<AuditEvent>`. `service.rs` USED to clone the whole of it on every invocation to compute
//!   grant budgets and hold that clone for the length of the execution, which made the instance's
//!   exposure one resident copy plus one per concurrent execution and set the ceiling. It now
//!   counts in place (`Store::count_grant_usage`), so `count_heap` is what an invocation costs and
//!   `clone_heap` is what it cost, still measured because `GET /v1/audit` and the export route
//!   materialise the window and because the ceiling was first derived from it. A counting allocator
//!   measures all three exactly instead of guessing a multiplier.
#![cfg(feature = "sqlite")]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

use permaura_core::AuditPayload;
use std::sync::Arc;

use permaura_gateway::archive::AuditArchive;
use permaura_gateway::objectstore::MemoryObjectStore;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{GrantWindow, Store};

/// Net live bytes. Signed because a deallocation can outlive the allocation that this counter saw,
/// on a thread that started before it did; the numbers here are deltas, so that is harmless.
static LIVE: AtomicIsize = AtomicIsize::new(0);

/// The system allocator with a running total. Only this test binary gets it.
struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size as isize - layout.size() as isize, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

fn scratch(tag: &str) -> std::path::PathBuf {
    // The one door to every store this file opens, so the pin goes here. A scratch directory for
    // the database is not isolation on its own: `SqliteStore::open` resolves the vault KEK, and
    // that resolution reads the Permaura home rather than the path it was handed.
    common::isolate_from_the_real_install();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir()
        .join(format!("permaura-audit-scale-{}-{tag}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One event the size of a real one: an `"allow"` carrying the grant id, the policy id and a
/// result summary, which is what the enforcement loop appends on the hot path.
fn synthetic(i: usize) -> AuditPayload {
    let mut payload =
        AuditPayload::new("github.pull_requests.list".to_string(), "github_acme".to_string(), "allow");
    payload.agent_id = Some("codex-cli".into());
    payload.session_id = Some("sess_demo".into());
    payload.execution_location = Some("local".into());
    payload.summary = serde_json::json!({
        "status": 200,
        "result_summary": { "kind": "array", "len": 30 },
        "intent": "list the open pull requests before the release",
        "grant_id": "gr_github_prs",
        "policy_id": "pol_github_prs",
        "notified": false,
        "n": i,
    });
    payload
}

fn measure(events: usize) {
    std::env::set_var("PERMAURA_DEV", "1");
    let dir = scratch(&format!("n{events}"));
    let db = dir.join("gateway.db");
    let path = db.to_string_lossy().to_string();

    let store = SqliteStore::open(&path).expect("a scratch store opens");
    let filled = Instant::now();
    for i in 0..events {
        store.append_audit(synthetic(i)).expect("the chain appends");
    }
    let fill = filled.elapsed();

    let snapshot = dir.join("snapshot.db");
    store.snapshot_to(&snapshot).expect("VACUUM INTO");
    let bytes = std::fs::metadata(&snapshot).unwrap().len();
    let live_bytes = std::fs::metadata(&db).unwrap().len();
    drop(store);

    let before_open = live();
    let opened = Instant::now();
    let reopened = SqliteStore::open(&path).expect("the store reopens");
    let open = opened.elapsed();
    let resident = live() - before_open;
    assert_eq!(reopened.audit_events(None).unwrap().len(), events);

    // What one invocation used to cost: `service.rs` took this exact clone to compute grant budgets
    // and held it until the execution returned. Still measured, because `GET /v1/audit` and the
    // export route materialise the window too, and because it is the number the ceiling was first
    // derived from.
    let before_clone = live();
    let clone = reopened.audit_events(None).unwrap();
    let per_clone = live() - before_clone;
    assert_eq!(clone.len(), events);
    drop(clone);

    // What one invocation costs now: the tally, over the same chain, with a window per grant. Ten
    // grants is a generous estimate of a real tenant's, and the FIRST of them is the one every
    // synthetic event is charged to, so the tally actually matches and the number is not an empty
    // map's. The answer is a handful of integers either way, so this is O(grants) and not
    // O(events), which is the whole of the change.
    let mut grant_ids: Vec<String> = vec!["gr_github_prs".to_string()];
    grant_ids.extend((1..10).map(|i| format!("gr_{i}")));
    let windows: Vec<GrantWindow<'_>> = grant_ids
        .iter()
        .map(|id| GrantWindow { grant_id: id.as_str(), since_ms: i64::MIN })
        .collect();
    let before_count = live();
    let counted = reopened.count_grant_usage(&windows).unwrap();
    let per_invocation = live() - before_count;
    assert_eq!(counted.total("gr_github_prs"), events as u64, "every synthetic event is charged");
    drop(counted);

    let verified = Instant::now();
    assert_eq!(reopened.verify_audit().unwrap(), None, "the chain verifies");
    let verify = verified.elapsed();

    println!(
        "events={events} live_bytes={live_bytes} snapshot_bytes={bytes} snapshot_per_1k={} \
         resident_heap={resident} heap_per_event={} clone_heap={per_clone} \
         count_heap={per_invocation} fill={:?} open={:?} verify={:?}",
        (bytes as f64 / events as f64 * 1000.0).round() as u64,
        (resident as f64 / events as f64).round() as i64,
        fill,
        open,
        verify
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same store, with the archive writer on: what a tenant that has written `events` events
/// actually carries once the oldest of them have been published and pruned.
///
/// The numbers that matter here are the steady-state ones. `resident_heap` and `snapshot_bytes` stop
/// being a function of how much the tenant has ever recorded and become a function of `keep_hot`,
/// which is the whole point of the archive: without it both grow forever and the ceiling is a
/// permanent refusal rather than a temporary one.
fn measure_archived(events: usize, keep_hot: usize, batch: usize) {
    std::env::set_var("PERMAURA_DEV", "1");
    let dir = scratch(&format!("archived-n{events}"));
    let db = dir.join("gateway.db");
    let path = db.to_string_lossy().to_string();

    let store = Arc::new(SqliteStore::open(&path).expect("a scratch store opens"));
    for i in 0..events {
        store.append_audit(synthetic(i)).expect("the chain appends");
    }

    let objects = Arc::new(MemoryObjectStore::new());
    let archive = AuditArchive::with_limits(objects.clone(), "scale", "audit", batch, keep_hot);
    let archiving = Instant::now();
    let mut passes = 0u64;
    let mut pruned = 0u64;
    loop {
        let outcome = archive.run_pass(store.as_ref()).expect("a pass publishes or explains itself");
        if outcome.segment_id.is_none() {
            break;
        }
        passes += 1;
        pruned += outcome.pruned;
    }
    let archived_in = archiving.elapsed();

    let snapshot = dir.join("snapshot.db");
    store.snapshot_to(&snapshot).expect("VACUUM INTO");
    let bytes = std::fs::metadata(&snapshot).unwrap().len();
    let live_bytes = std::fs::metadata(&db).unwrap().len();
    drop(store);

    let before_open = live();
    let reopened = SqliteStore::open(&path).expect("the pruned store reopens");
    let resident = live() - before_open;
    let hot = reopened.audit_len().unwrap();
    assert_eq!(hot, (events as u64) - pruned, "the hot window is what was not pruned");

    let verified = Instant::now();
    assert_eq!(reopened.verify_audit().unwrap(), None, "the remaining window verifies");
    let verify = verified.elapsed();

    let full = Instant::now();
    let report = archive.verify_full(&reopened).expect("a full walk completes");
    let verify_full = full.elapsed();
    assert!(report.chain_intact, "{report:?}");
    assert_eq!(report.verified_to, Some(events as u64 - 1));

    println!(
        "archived events={events} keep_hot={keep_hot} batch={batch} passes={passes} \
         pruned={pruned} hot={hot} live_bytes={live_bytes} snapshot_bytes={bytes} \
         resident_heap={resident} heap_per_hot_event={} segments={} archive_bytes={} \
         archive_run={:?} verify_hot={:?} verify_full={:?}",
        if hot == 0 { 0 } else { (resident as f64 / hot as f64).round() as i64 },
        report.segments,
        objects.total_bytes(),
        archived_in,
        verify,
        verify_full
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "minutes: it signs one event per row, then archives every one of them"]
fn the_archived_store_at_250k_events() {
    measure_archived(250_000, 5_000, 5_000);
}

/// The shape of the archived measurement, at a size the normal suite can afford.
#[test]
fn the_archived_measurement_runs_at_a_size_the_normal_suite_can_afford() {
    measure_archived(10_000, 1_000, 2_000);
}

#[test]
#[ignore = "minutes: it signs one event per row"]
fn the_hot_store_at_100k_events() {
    measure(100_000);
}

#[test]
#[ignore = "minutes: it signs one event per row"]
fn the_hot_store_at_250k_events() {
    measure(250_000);
}

/// A tenth of the smaller case, so the shape of the measurement itself stays covered by the suite a
/// push runs. It asserts nothing about the numbers, only that the thing that produces them works.
#[test]
fn the_measurement_runs_at_a_size_the_normal_suite_can_afford() {
    measure(10_000);
}
