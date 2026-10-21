//! One process writes a self-run store at a time.
//!
//! A gateway asked to stop gives its address up as its drain begins and goes on executing for the
//! rest of its window, against the same `gateway.db`. A successor started in that window used to open
//! the store beside it, each process holding the chain it had loaded, and the second writer of a seq
//! replaced the first's row: a call that finished was recorded as interrupted, charged twice, and the
//! chain still verified. These tests run the two processes for real: this test binary re-runs itself
//! as the predecessor, which holds the store through a slow call while the successor boots the way
//! `permaura start` does. Every credential and transport here is synthetic.
#![cfg(feature = "sqlite")]

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use permaura_core::AuditPayload;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{Agent, GrantCharge, GrantWindow, Store};

/// Set in the environment of the copy of this binary that plays the predecessor, naming its directory.
const PREDECESSOR_ENV: &str = "PERMAURA_TEST_ONE_WRITER_PREDECESSOR";

/// How long the predecessor's call takes after its `attempt` is recorded.
const SLOW_CALL: Duration = Duration::from_secs(3);

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permaura-one-writer-{tag}-{}-{}",
        std::process::id(),
        permaura_gateway::service::short_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn wait_for(path: &Path, limit: Duration) {
    let started = Instant::now();
    while !path.exists() {
        assert!(started.elapsed() < limit, "{} never appeared", path.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The predecessor: a gateway process with a call in flight. A no-op in an ordinary test run.
#[test]
fn predecessor_process() {
    let Some(dir) = std::env::var_os(PREDECESSOR_ENV).map(PathBuf::from) else { return };
    common::isolate_from_the_real_install();
    let db = dir.join("gateway.db");
    let store = SqliteStore::open(db.to_str().unwrap()).expect("the predecessor opens its store");
    // An agent, so the successor's boot finds an install rather than a store to bootstrap.
    store.put_agent(Agent::approved("agent-1", "Synthetic agent", 0)).unwrap();
    let mut attempt = AuditPayload::new("synthetic.refunds.create", "synthetic", "attempt");
    attempt.summary = serde_json::json!({ "execution_id": "exe_slow", "grant_id": "g_slow" });
    store.append_audit(attempt).unwrap();
    std::fs::write(dir.join("ready"), b"").unwrap();
    std::thread::sleep(SLOW_CALL);
    let mut allow = AuditPayload::new("synthetic.refunds.create", "synthetic", "allow");
    allow.summary = serde_json::json!({ "execution_id": "exe_slow", "grant_id": "g_slow", "status": 200 });
    store
        .append_audit_charged(allow, Some(GrantCharge::new("g_slow")))
        .expect("the predecessor records how its call ended");
}

/// The decisions the file holds for one execution, read straight from the table rather than from any process's chain.
fn stored_decisions(db: &Path, execution_id: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(db).unwrap();
    let mut stmt = conn.prepare("SELECT data FROM audit_events ORDER BY seq").unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
    rows.map(|row| serde_json::from_str::<serde_json::Value>(&row.unwrap()).unwrap())
        .filter(|event| event["payload"]["summary"]["execution_id"] == execution_id)
        .map(|event| event["payload"]["decision"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// One writer per store, end to end across two processes. The successor's boot waits for the predecessor to let the store go, so it loads the chain with the slow call's ending in it: nothing is settled as interrupted, the file holds the `attempt` and the `allow`, and the grant is charged once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successor_waits_for_its_predecessor_so_a_slow_call_is_recorded_and_charged_once() {
    common::isolate_from_the_real_install();
    let dir = scratch("successor");
    let db = dir.join("gateway.db");
    let mut predecessor = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "predecessor_process", "--nocapture", "--test-threads=1"])
        .env(PREDECESSOR_ENV, &dir)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("the predecessor starts");
    wait_for(&dir.join("ready"), Duration::from_secs(60));

    // The successor boots the way `permaura start` does, over the same file, while the call runs.
    std::env::set_var("PERMAURA_STORE_PATH", &db);
    let booted = Instant::now();
    let state = tokio::task::spawn_blocking(|| permaura_gateway::AppState::from_env(true)).await.unwrap();
    let waited = booted.elapsed();
    let service = state.service.clone();
    let store = service.store().clone();
    let recorded_before = store.audit_events(Some(1)).unwrap().last().map_or(0, |e| e.seq + 1);
    service.carry_interrupted_budget(recorded_before).unwrap();

    assert!(predecessor.wait().unwrap().success(), "the predecessor recorded its call's ending");
    let settled = service.settle_interrupted_invokes(Duration::ZERO, recorded_before).unwrap();
    service.release_settled_budget(recorded_before).unwrap();

    assert_eq!(
        stored_decisions(&db, "exe_slow"),
        vec!["attempt".to_string(), "allow".to_string()],
        "the finished call keeps its record and nothing calls it interrupted (the successor boot took {waited:?})"
    );
    assert!(settled.invokes.is_empty(), "nothing was left open to settle: {:?}", settled.invokes);
    let usage = store.read_grant_usage(&[GrantWindow { grant_id: "g_slow", since_ms: 0 }]).unwrap();
    assert_eq!(usage.total("g_slow"), 1, "the call is charged once");
    assert_eq!(store.verify_audit().unwrap(), None);
}

/// The store is held for as long as one handle is open on it: a second open is refused, naming who holds it, and succeeds once the first is gone.
#[test]
fn a_second_open_of_a_store_that_is_held_is_refused() {
    common::isolate_from_the_real_install();
    let dir = scratch("second-open");
    let db = dir.join("gateway.db");
    let db = db.to_str().unwrap();
    let first = SqliteStore::open(db).unwrap();
    first.append_audit(AuditPayload::new("synthetic.action", "synthetic", "allow")).unwrap();

    let refused = SqliteStore::open(db).err().expect("a second writer is refused while the first holds the store");
    let message = refused.to_string();
    assert!(message.contains(&std::process::id().to_string()), "it names the process holding the store: {message}");

    drop(first);
    let second = SqliteStore::open(db).expect("the store is free once its holder has gone");
    assert_eq!(second.audit_events(None).unwrap().len(), 1);
}
