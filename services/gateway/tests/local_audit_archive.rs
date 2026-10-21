//! A gateway its owner runs archives its own hot window to its own disk, so the audit ceiling is a bound the chain is held under rather than a wall nothing ever lowers. The store is real SQLite on disk, because a prune re-signs the boundary and an in-memory store has none to archive from.
#![cfg(feature = "sqlite")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use permaura_core::ExecutionLocation;
use permaura_gateway::archive::{self, AuditArchive};
use permaura_gateway::audit_ceiling::{AuditCeiling, AuditCeilingConfig};
use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::objectstore::{LocalObjectStore, ObjectStore, PutOutcome};
use permaura_gateway::seed;
use permaura_gateway::service::{EnforcementService, InvokeOutcome};
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

fn scratch(name: &str) -> std::path::PathBuf {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!(
        "permaura-{name}-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The writer a self-run gateway assembles, and the hosted and switched-off cases that get none.
#[test]
fn a_self_run_gateway_gets_a_local_archive_and_a_hosted_worker_does_not() {
    let home = scratch("local-archive-home");
    let store = SqliteStore::open(&home.join("gateway.db").to_string_lossy()).unwrap();
    let local = archive::local(false, Some(home.clone()), &store).expect("a self-run gateway archives to its own disk");
    assert_eq!(local.tenant(), archive::LOCAL_TENANT);
    assert!(archive::local(true, Some(home.clone()), &store).is_none(), "a hosted worker's archive is its bucket or nothing");
    assert!(archive::local(false, None, &store).is_none(), "no home, nowhere to write");
    let demo = permaura_gateway::store::memory::MemoryStore::new();
    assert!(archive::local(false, Some(home.clone()), &demo).is_none(), "an in-memory store has nothing to archive from");
    std::fs::remove_dir_all(home).ok();
}

/// A local object behaves as a bucket object does: create-only at generation 0, a conditional replace, a read pinned to its generation, and no name that leaves the root.
#[test]
fn a_local_object_store_keeps_a_buckets_generation_rules() {
    let root = scratch("local-objects");
    let objects = LocalObjectStore::new(root.join("archive"));
    let meta = std::collections::BTreeMap::from([("kind".to_string(), "segment".to_string())]);
    assert_eq!(objects.head("audit/local/e0000/index.json").unwrap(), None);
    let PutOutcome::Stored(first) = objects.put_if_generation("audit/local/e0000/index.json", b"one", 0, &meta).unwrap() else {
        panic!("a create on an empty name stores");
    };
    assert_eq!(objects.put_if_generation("audit/local/e0000/index.json", b"two", 0, &meta).unwrap(), PutOutcome::Conflict);
    let PutOutcome::Stored(second) = objects.put_if_generation("audit/local/e0000/index.json", b"two", first, &meta).unwrap() else {
        panic!("a replace at the current generation stores");
    };
    assert!(second > first);
    assert_eq!(objects.get("audit/local/e0000/index.json", second).unwrap(), b"two");
    assert!(objects.get("audit/local/e0000/index.json", first).is_err(), "a stale generation is not served");
    let head = objects.head_full("audit/local/e0000/index.json").unwrap().unwrap();
    assert_eq!((head.generation, head.size, head.metadata), (second, 3, meta.clone()));
    assert!(objects.put_if_generation("../escape", b"x", 0, &meta).is_err());
    assert!(objects.put_if_generation("audit/../../escape", b"x", 0, &meta).is_err());
    std::fs::remove_dir_all(root).ok();
}

/// The attack's traffic shape on a self-run store: denials from many sessions, each inside its own denial budget, more than twice the ceiling. Every denial kicks the archive, which publishes to the gateway's own disk and prunes, so the chain stays under the ceiling, verifies, and an execution still runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denials_past_the_ceiling_are_archived_to_the_gateways_own_disk() {
    let dir = scratch("local-archive");
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&dir.join("gateway.db").to_string_lossy()).unwrap());
    seed::seed(store.as_ref()).unwrap();
    let objects = Arc::new(LocalObjectStore::new(dir.join(archive::LOCAL_DIR)));
    let writer = Arc::new(AuditArchive::with_limits(objects, archive::LOCAL_TENANT, "audit", 100, 50));
    let ceiling = Arc::new(AuditCeiling::new(AuditCeilingConfig { soft: 150, ceiling: 300, log_interval: Duration::ZERO }));
    let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()))
        .with_audit_ceiling(ceiling)
        .with_audit_archive(writer);
    let demo = store.get_session("sess_demo").unwrap().unwrap();

    for i in 0..700 {
        let mut caller = demo.clone();
        caller.id = format!("sess_looping_{i}");
        caller.token = format!("synthetic-looping-token-{i}");
        store.put_session(caller.clone()).unwrap();
        let refund = serde_json::json!({ "amount": 1 });
        let outcome = service
            .invoke(&caller, "braintree.transactions.refund", &refund, None, ExecutionLocation::LocalOnly)
            .await
            .expect("a denial is recorded at any pressure");
        assert!(matches!(outcome, InvokeOutcome::Denied { .. }));
        // The passes run beside the calls, as they do between an agent's requests in wall time.
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while store.audit_len().unwrap() >= 300 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let events = store.audit_len().unwrap();
    assert!(events < 300, "the hot window stays under the ceiling, holding {events}");
    assert!(store.audit_boundary().unwrap().unwrap().base_seq > 0, "the oldest events left the hot store");
    assert_eq!(store.verify_audit().unwrap(), None, "the pruned chain still verifies");
    let index = dir.join(archive::LOCAL_DIR).join("audit").join(archive::LOCAL_TENANT).join("e0000").join("index");
    assert!(index.join(format!("{:020}.json", 0)).exists(), "segments are published under the gateway's home: {}", index.display());

    let outcome = service
        .invoke(&demo, "github.pull_requests.list", &serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }), None, ExecutionLocation::LocalOnly)
        .await
        .expect("execution is not wedged");
    assert!(matches!(outcome, InvokeOutcome::Allowed { .. }));
    std::fs::remove_dir_all(dir).ok();
}

/// A store reinstalled over an earlier install's archive (a purge that left `audit-archive`, or `rm gateway.db` keeping its key) moves that archive aside and starts its own, rather than failing every pass until the audit ceiling refuses every execution.
#[test]
fn a_reinstall_over_an_earlier_archive_starts_a_new_one() {
    for keep_key in [false, true] {
        let home = scratch("reinstall-archive");
        let db = home.join("gateway.db").to_string_lossy().into_owned();
        let writer = |home: &std::path::Path| {
            AuditArchive::with_limits(Arc::new(LocalObjectStore::new(home.join(archive::LOCAL_DIR))), archive::LOCAL_TENANT, "audit", 10, 5)
        };
        let append = |store: &SqliteStore, n: usize| {
            for i in 0..n {
                store.append_audit(permaura_core::AuditPayload::new(format!("cap.{i}"), "r", "allow")).unwrap();
            }
        };

        let earlier = SqliteStore::open(&db).unwrap();
        append(&earlier, 30);
        let published = writer(&home).run_pass(&earlier).unwrap();
        assert!(published.segment_id.is_some(), "the earlier install archived a segment: {published:?}");
        drop(earlier);
        for entry in std::fs::read_dir(&home).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("gateway.db") && !(keep_key && name == "gateway.db.auditkey") {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }

        let fresh = SqliteStore::open(&db).unwrap();
        append(&fresh, 30);
        assert!(archive::local(false, Some(home.clone()), &fresh).is_some(), "the reinstall still archives");
        let aside = std::fs::read_dir(&home)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit-archive.foreign-"))
            .count();
        assert_eq!(aside, 1, "the earlier archive is moved aside, not deleted (keep_key {keep_key})");
        let outcome = writer(&home).run_pass(&fresh).unwrap_or_else(|e| panic!("keep_key {keep_key}: {e}"));
        assert!(outcome.segment_id.is_some() && outcome.pruned > 0, "the reinstall publishes and prunes: {outcome:?}");

        let again = archive::local(false, Some(home.clone()), &fresh).expect("its own archive is kept");
        assert_eq!(again.foreign_to(&fresh).unwrap(), None);
        std::fs::remove_dir_all(home).ok();
    }
}
