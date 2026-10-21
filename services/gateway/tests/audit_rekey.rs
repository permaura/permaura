//! `permaura audit rekey`: the explicit, loud repair for a store whose `gateway.db.auditkey` is gone.
//!
//! A store holding a chain refuses to open without its key and names this
//! repair. The rekey mints a new key and appends, as its first event, a record naming the old chain's
//! head; verification then reports that fork instead of a break, while still checking every old
//! event's hash and link. Everything here is synthetic and in a scratch directory.
#![cfg(feature = "sqlite")]

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::audit::AUDIT_REKEY_ACTION;
use permaura_core::AuditPayload;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use tower::ServiceExt;

fn scratch(tag: &str) -> PathBuf {
    common::isolate_from_the_real_install();
    let dir = std::env::temp_dir().join(format!(
        "permaura-rekey-{tag}-{}-{}",
        std::process::id(),
        permaura_gateway::service::short_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("gateway.db")
}

fn append(store: &dyn Store, n: usize) {
    for i in 0..n {
        store.append_audit(AuditPayload::new(format!("synthetic.action.{i}"), "synthetic", "allow")).unwrap();
    }
}

/// A store with `n` events, closed, whose key file is then lost. Returns the old head's seq and hash.
fn a_store_that_lost_its_key(db: &str, n: usize) -> (u64, String) {
    let store = SqliteStore::open(db).unwrap();
    append(&store, n);
    let head = store.audit_events(Some(1)).unwrap().pop().unwrap();
    drop(store);
    std::fs::remove_file(format!("{db}.auditkey")).unwrap();
    (head.seq, head.hash)
}

#[test]
fn a_store_whose_key_is_gone_names_the_rekey_in_its_refusal() {
    let db = scratch("named");
    let db = db.to_str().unwrap();
    a_store_that_lost_its_key(db, 2);
    let refused = SqliteStore::open(db).err().expect("refused").to_string();
    assert!(refused.contains("permaura audit rekey --yes"), "{refused}");
}

#[test]
fn a_rekey_is_refused_while_the_store_is_held_while_its_key_is_there_and_on_a_store_with_nothing_signed() {
    let db = scratch("refusals");
    let db = db.to_str().unwrap();
    a_store_that_lost_its_key(db, 2);
    let held = permaura_gateway::store::lock::StoreLock::acquire(db, std::time::Duration::ZERO).unwrap();
    let refused = SqliteStore::rekey(db, 1).err().expect("refused while held");
    assert!(matches!(refused, permaura_gateway::error::GatewayError::StoreHeld(_)), "{refused}");
    assert!(!std::path::Path::new(&format!("{db}.auditkey")).exists(), "nothing was minted");
    drop(held);

    let keyed = scratch("keyed");
    let keyed = keyed.to_str().unwrap();
    append(&SqliteStore::open(keyed).unwrap(), 1);
    let refused = SqliteStore::rekey(keyed, 1).err().expect("refused while the key is there").to_string();
    assert!(refused.contains("nothing to rekey"), "{refused}");

    let empty = scratch("empty");
    let empty = empty.to_str().unwrap();
    drop(SqliteStore::open(empty).unwrap());
    std::fs::remove_file(format!("{empty}.auditkey")).unwrap();
    let refused = SqliteStore::rekey(empty, 1).err().expect("refused with nothing signed").to_string();
    assert!(refused.contains("nothing signed"), "{refused}");
}

#[tokio::test]
async fn a_rekey_records_the_fork_and_verification_reports_it_rather_than_a_break() {
    let db = scratch("fork");
    let db = db.to_str().unwrap();
    let (head_seq, head_hash) = a_store_that_lost_its_key(db, 3);

    let (store, event) = SqliteStore::rekey(db, 1_790_000_000_000).unwrap();
    assert_eq!(event.payload.action, AUDIT_REKEY_ACTION);
    assert_eq!(event.seq, head_seq + 1, "the first event under the new key");
    assert_eq!(event.prev_hash, head_hash, "linked to the old chain's head");
    assert_eq!(event.payload.summary["prior_head_seq"], head_seq);
    assert_eq!(event.payload.summary["prior_head_hash"], head_hash.as_str());
    assert!(std::path::Path::new(&format!("{db}.auditkey")).exists(), "the new key is kept beside the store");
    assert_eq!(store.verify_audit().unwrap(), None);
    drop(store);

    // What a gateway reads on its next start.
    let store = SqliteStore::open(db).expect("the store opens under its new key");
    assert_eq!(store.audit_rekey().unwrap().map(|r| r.seq), Some(event.seq));
    assert_eq!(store.verify_audit().unwrap(), None, "the fork is reported, not a break");
    let key = ed25519_dalek::VerifyingKey::from_bytes(&store.audit_verifying_key().unwrap()).unwrap();
    let events = store.audit_events(None).unwrap();
    assert_eq!(
        permaura_core::AuditLog::verify_from(&events, &key, 0, permaura_core::GENESIS_PREV_HASH),
        Some(0),
        "checked strictly, the old key's first event is where it would read as broken"
    );
    append(&store, 2);
    assert_eq!(store.verify_audit().unwrap(), None, "and the chain goes on under the new key");

    let state = permaura_gateway::AppState::from_parts(Arc::new(store), Arc::new(permaura_gateway::connectors::MockHttpClient::new()));
    let token = common::operator_token(state.clone()).await;
    let app = permaura_gateway::build_router(state, "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .uri("/v1/audit-events")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["chain_intact"], true, "{body}");
    assert_eq!(body["key_fork"]["seq"], event.seq, "{body}");
    assert_eq!(body["key_fork"]["prior_head_seq"], head_seq, "{body}");
    assert_eq!(body["key_fork"]["prior_head_hash"], head_hash.as_str(), "{body}");
}

/// The fork excuses only the old key's signatures: an old event whose contents changed still breaks the chain.
#[test]
fn a_rekey_does_not_bless_an_old_event_that_was_altered() {
    let db = scratch("tamper");
    let db = db.to_str().unwrap();
    a_store_that_lost_its_key(db, 3);
    drop(SqliteStore::rekey(db, 1).unwrap());
    let conn = rusqlite::Connection::open(db).unwrap();
    let data: String = conn.query_row("SELECT data FROM audit_events WHERE seq = 1", [], |r| r.get(0)).unwrap();
    let altered = data.replace("\"allow\"", "\"deny\"");
    assert_ne!(altered, data);
    conn.execute("UPDATE audit_events SET data = ?1 WHERE seq = 1", [altered]).unwrap();
    drop(conn);
    assert_eq!(SqliteStore::open(db).unwrap().verify_audit().unwrap(), Some(1));
}

/// A store that had archived events keeps archiving after a rekey: it moves to a new epoch, and the
/// next pass publishes the old key's remaining events, checked by hash and link, under the new key.
#[test]
fn a_rekeyed_store_that_had_archived_keeps_archiving_under_a_new_epoch() {
    let db = scratch("archived");
    let db = db.to_str().unwrap();
    let objects: Arc<dyn permaura_gateway::objectstore::ObjectStore> =
        Arc::new(permaura_gateway::objectstore::MemoryObjectStore::new());
    let archive = permaura_gateway::archive::AuditArchive::with_limits(objects, "acme", "audit", 4, 2);
    let store = SqliteStore::open(db).unwrap();
    append(&store, 10);
    let first = archive.run_pass(&store).unwrap();
    assert!(first.segment_id.is_some(), "a segment was published and pruned: {first:?}");
    let before = store.audit_boundary().unwrap().unwrap();
    assert!(before.base_seq > 0);
    drop(store);
    std::fs::remove_file(format!("{db}.auditkey")).unwrap();

    let (store, event) = SqliteStore::rekey(db, 1).unwrap();
    assert_eq!(event.payload.summary["archive_epoch"], before.epoch + 1);
    drop(store);
    let store = SqliteStore::open(db).expect("the re-signed boundary verifies under the new key");
    let boundary = store.audit_boundary().unwrap().unwrap();
    assert_eq!(boundary.epoch, before.epoch + 1);
    assert_eq!(boundary.base_seq, before.base_seq);
    append(&store, 4);
    let next = archive.run_pass(&store).expect("archiving goes on after the rekey");
    assert!(next.segment_id.is_some(), "{next:?}");
    assert_eq!(store.verify_audit().unwrap(), None);
}
