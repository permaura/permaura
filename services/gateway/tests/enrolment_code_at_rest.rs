//! A redeemed enrolment code is the bearer of the session it opened, so the store keeps a digest of it and never the code itself. Every code here is synthetic.
#![cfg(feature = "sqlite")]

mod common;

use std::sync::Arc;

use permaura_gateway::connectors::MockHttpClient;
use permaura_gateway::service::{now_ms, EnforcementService};
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::{EnrolmentCode, SessionRole, Store};

const CODE: &str = "ENRL-FXTR-0000-1111-2222";
const LEGACY_LIVE: &str = "ENRL-FXTR-3333-4444-5555";
const LEGACY_SPENT: &str = "ENRL-FXTR-6666-7777-8888";

fn scratch_db(tag: &str) -> String {
    common::isolate_from_the_real_install();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("permaura-enrol-at-rest-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("gateway.db").to_string_lossy().into_owned()
}

fn service_over(path: &str) -> EnforcementService {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(path).expect("the store opens"));
    EnforcementService::new(store, Arc::new(MockHttpClient::new()))
}

fn ticket(code: &str, used: bool) -> EnrolmentCode {
    let now = now_ms();
    EnrolmentCode { code: code.into(), label: Some("fixture".into()), created_at: now, expires_at: now + 60_000, used }
}

/// Every credential-shaped value the two tables hold: the key columns and the matching JSON fields.
fn stored_values(path: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(path).unwrap();
    let mut out = Vec::new();
    for (sql, field) in [("SELECT code, data FROM enrolment_codes", "code"), ("SELECT token, data FROM sessions", "token")] {
        let mut stmt = conn.prepare(sql).unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for (column, data) in rows {
            out.push(column);
            let json: serde_json::Value = serde_json::from_str(&data).unwrap();
            if let Some(v) = json[field].as_str() {
                out.push(v.to_string());
            }
        }
    }
    out
}

fn cleanup(path: &str) {
    if let Some(dir) = std::path::Path::new(path).parent() {
        std::fs::remove_dir_all(dir).ok();
    }
}

/// Redeeming the code as a bootstrap bearer leaves a session behind, and nothing in either table authenticates as that agent; the code itself still does.
#[test]
fn a_redeemed_code_leaves_nothing_in_the_store_that_authenticates() {
    let path = scratch_db("redeemed");
    let svc = service_over(&path);
    svc.store().put_enrolment_code(ticket(CODE, false)).unwrap();
    let session = svc.authenticate(CODE).expect("the code opens a session");
    assert_eq!(session.role, SessionRole::Agent);

    let stored = stored_values(&path);
    assert!(stored.len() >= 4, "both rows were read: {stored:?}");
    for value in &stored {
        assert_ne!(value, CODE, "a row still holds the code in clear");
        assert!(svc.authenticate(value).is_err(), "{value}, read from the store, authenticated");
    }
    let raw = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains(CODE), "the code is somewhere in the database file");

    assert_eq!(svc.authenticate(CODE).expect("the agent's bearer still works").id, session.id);
    cleanup(&path);
}

/// The MCP redemption path: the code redeems once by its value, and the stored digest presented as a code redeems nothing.
#[test]
fn a_code_redeems_by_its_value_and_never_by_its_stored_form() {
    let path = scratch_db("consume");
    let store = SqliteStore::open(&path).unwrap();
    store.put_enrolment_code(ticket(CODE, false)).unwrap();
    let stored: String = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("SELECT code FROM enrolment_codes", [], |r| r.get(0))
        .unwrap();
    assert_ne!(stored, CODE);
    assert!(store.consume_enrolment_code(&stored, now_ms()).unwrap().is_none(), "the digest is not a code");
    assert!(store.consume_enrolment_code(CODE, now_ms()).unwrap().is_some(), "the code redeems");
    assert!(store.consume_enrolment_code(CODE, now_ms()).unwrap().is_none(), "once");

    let memory = permaura_gateway::store::memory::MemoryStore::new();
    memory.put_enrolment_code(ticket(CODE, false)).unwrap();
    assert!(memory.consume_enrolment_code(CODE, now_ms()).unwrap().is_some(), "the memory store agrees");
    assert!(memory.consume_enrolment_code(CODE, now_ms()).unwrap().is_none());
    cleanup(&path);
}

/// A store written before codes were hashed: its rows are rewritten in place when it is opened, a live code still redeems by its value, and a spent one (whose session already exists) still names that session's bearer only through the digest.
#[test]
fn codes_stored_in_clear_are_hashed_in_place_and_still_answer() {
    let path = scratch_db("migrated");
    drop(SqliteStore::open(&path).unwrap());
    let spent_session = {
        let svc = service_over(&path);
        svc.store().put_enrolment_code(ticket(LEGACY_SPENT, false)).unwrap();
        svc.authenticate(LEGACY_SPENT).expect("a session from before the upgrade").id
    };
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM enrolment_codes", []).unwrap();
        for (code, used) in [(LEGACY_LIVE, false), (LEGACY_SPENT, true)] {
            conn.execute(
                "INSERT INTO enrolment_codes (code, data) VALUES (?1, ?2)",
                rusqlite::params![code, serde_json::to_string(&ticket(code, used)).unwrap()],
            )
            .unwrap();
        }
        conn.pragma_update(None, "user_version", 8).unwrap();
    }

    let svc = service_over(&path);
    let stored = stored_values(&path);
    for value in &stored {
        assert!(value != LEGACY_LIVE && value != LEGACY_SPENT, "a legacy row kept its code in clear: {stored:?}");
        assert!(svc.authenticate(value).is_err(), "{value}, read from the store, authenticated");
    }
    assert_eq!(svc.authenticate(LEGACY_SPENT).expect("the old agent's bearer still works").id, spent_session);
    assert!(
        svc.store().consume_enrolment_code(LEGACY_LIVE, now_ms()).unwrap().is_some(),
        "a code minted before the upgrade still redeems by its value"
    );
    cleanup(&path);
}
