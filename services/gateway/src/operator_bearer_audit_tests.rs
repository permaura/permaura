//! The gateway's own changes to who holds operator authority are in the audit chain: every operator token and console session it mints, and every one it retires or revokes, by session id and never by bearer.

use crate::store::memory::MemoryStore;
use crate::store::{SessionClass, Store};

fn events(store: &dyn Store, action: &str) -> Vec<permaura_core::AuditEvent> {
    store.audit_events(None).unwrap().into_iter().filter(|e| e.payload.action == action).collect()
}

fn chain_text(store: &dyn Store) -> String {
    serde_json::to_string(&store.audit_events(None).unwrap()).unwrap()
}

#[test]
fn an_operator_token_minted_by_the_gateway_is_recorded_without_its_bearer() {
    let store = MemoryStore::new();
    let token = crate::mint_operator_session(&store).unwrap();
    let session = store.session_by_token(&token).unwrap().unwrap();
    let minted = events(&store, "permaura.operator_token.mint");
    assert_eq!(minted.len(), 1);
    assert_eq!(minted[0].payload.resource, session.id);
    assert_eq!(minted[0].payload.agent_id.as_deref(), Some("operator"));
    assert_eq!(minted[0].payload.summary["class"], "operator_token");
    assert_eq!(minted[0].payload.summary["expires_at"], session.expires_at.unwrap());
    assert!(!chain_text(&store).contains(&token), "the bearer is not recorded");
}

#[test]
fn a_console_session_minted_and_revoked_is_recorded() {
    let store = MemoryStore::new();
    let token = crate::mint_console_session(&store).unwrap();
    let session = store.session_by_token(&token).unwrap().unwrap();
    assert_eq!(session.class, SessionClass::Console);
    let minted = events(&store, "permaura.console_session.mint");
    assert_eq!(minted.len(), 1);
    assert_eq!(minted[0].payload.resource, session.id);

    assert_eq!(crate::revoke_console_sessions(&store), 1);
    let ended = events(&store, "permaura.operator_token.retire");
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].payload.summary["sessions"], serde_json::json!([session.id]));
    assert_eq!(ended[0].payload.summary["reason"], "console_not_needed");
    assert!(!chain_text(&store).contains(&token));
}

#[test]
fn a_rotation_records_what_it_retired_and_until_when() {
    let store = MemoryStore::new();
    let old = crate::mint_operator_session(&store).unwrap();
    let old_id = store.session_by_token(&old).unwrap().unwrap().id;
    let fresh = crate::mint_operator_session(&store).unwrap();
    let until = crate::service::now_ms() + 60_000;
    assert_eq!(crate::retire_operator_tokens_except(&store, &fresh, Some(&old), until), 1);
    let retired = events(&store, "permaura.operator_token.retire");
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].payload.summary["sessions"], serde_json::json!([old_id]));
    assert_eq!(retired[0].payload.summary["until"], until);
    assert_eq!(retired[0].payload.summary["reason"], "rotation");
    let text = chain_text(&store);
    assert!(!text.contains(&old) && !text.contains(&fresh), "no bearer is recorded");
}
