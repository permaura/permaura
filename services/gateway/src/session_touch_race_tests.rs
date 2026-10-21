//! Recording that a session was used must never undo a revocation, bring back a row that was
//! deleted, or put back a token the row no longer carries.
//!
//! The touch used to write back the whole row it had read at authentication. A revocation that landed
//! between that read and the write was replaced with `revoked: false`, and because the row kept its
//! token digest the same bearer authenticated again on every later request.

use super::*;
use crate::connectors::MockHttpClient;
use crate::objectstore::MemoryObjectStore;
use crate::store::memory::MemoryStore;
use crate::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use crate::store::sqlite::SqliteStore;
use crate::store::{AGENT_SESSION_TTL_MS, OPERATOR_SESSION_TTL_MS};
use permaura_core::SecretRecord;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Mutex;
use tower::ServiceExt;

struct Fixture {
    kind: &'static str,
    store: Arc<dyn Store>,
    dir: Option<PathBuf>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("permaura-race-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One of each store a gateway runs on: the in-memory default, local SQLite, and the hosted snapshotting
/// store.
fn every_store(tag: &str) -> Vec<Fixture> {
    let dir = scratch_dir(tag);
    let persisted = PersistedSqliteStore::open(
        &dir.join("gateway.db").to_string_lossy(),
        Arc::new(MemoryObjectStore::new()),
        DEFAULT_OBJECT,
        None,
    )
    .unwrap();
    vec![
        Fixture { kind: "memory", store: Arc::new(MemoryStore::new()), dir: None },
        Fixture { kind: "sqlite", store: Arc::new(SqliteStore::open_in_memory().unwrap()), dir: None },
        Fixture { kind: "persisted", store: Arc::new(persisted), dir: Some(dir) },
    ]
}

fn service(store: Arc<dyn Store>) -> EnforcementService {
    EnforcementService::new(store, Arc::new(MockHttpClient::new()))
}

/// A live session that is due a touch: never used, so the first authentication records it.
fn live(id: &str, bearer: &str, role: SessionRole, now: i64) -> Session {
    let ttl = match role {
        SessionRole::Agent => AGENT_SESSION_TTL_MS,
        SessionRole::Operator => OPERATOR_SESSION_TTL_MS,
    };
    Session {
        class: Default::default(),
        opened_by: None,
        id: id.into(),
        agent_id: "codex-cli".into(),
        user_id: None,
        device_id: None,
        token: bearer.into(),
        role,
        created_at: now - 120_000,
        revoked: false,
        expires_at: Some(now + ttl),
        last_used_at: None,
        actor: None,
    }
}

const ROLES: [SessionRole; 2] = [SessionRole::Agent, SessionRole::Operator];

/// Collects every store and role that breaks an invariant, so one run names all of them rather than
/// stopping at the first.
#[derive(Default)]
struct Failures(Vec<String>);

impl Failures {
    fn check(&mut self, ok: bool, what: String) {
        if !ok {
            self.0.push(what);
        }
    }
}

impl Drop for Failures {
    fn drop(&mut self) {
        if !self.0.is_empty() && !std::thread::panicking() {
            panic!("{} failed:\n  {}", self.0.len(), self.0.join("\n  "));
        }
    }
}

fn unauthorized(svc: &EnforcementService, bearer: &str) -> bool {
    matches!(svc.authenticate(bearer), Err(GatewayError::Unauthorized(_)))
}

/// Two invariants, agent and operator: the request read the session, the operator
/// revoked it, and then the request's touch landed.
#[test]
fn a_touch_that_lands_after_a_revocation_leaves_the_session_revoked() {
    let mut failures = Failures::default();
    for role in ROLES {
        for fx in every_store("revoke") {
            let svc = service(fx.store.clone());
            let now = now_ms();
            fx.store.put_session(live("sess_r", "tok_race_r", role, now)).unwrap();

            let read_at_auth = fx.store.session_by_token("tok_race_r").unwrap().expect("a live session");
            assert!(fx.store.revoke_session("sess_r").unwrap());
            assert!(fx.store.get_session("sess_r").unwrap().unwrap().revoked);
            svc.touch_session(&read_at_auth, now);

            let row = fx.store.get_session("sess_r").unwrap().expect("revocation keeps the row");
            failures.check(row.revoked, format!("{}/{role:?}: the touch put a revoked session back", fx.kind));
            failures.check(unauthorized(&svc, "tok_race_r"), format!("{}/{role:?}: the revoked bearer authenticated", fx.kind));
        }
    }
}

#[test]
fn a_touch_that_lands_after_a_delete_does_not_recreate_the_row() {
    let mut failures = Failures::default();
    for role in ROLES {
        for fx in every_store("delete") {
            let svc = service(fx.store.clone());
            let now = now_ms();
            fx.store.put_session(live("sess_d", "tok_race_d", role, now)).unwrap();

            let read_at_auth = fx.store.session_by_token("tok_race_d").unwrap().expect("a live session");
            assert!(fx.store.delete_session("sess_d").unwrap());
            svc.touch_session(&read_at_auth, now);

            failures.check(
                fx.store.get_session("sess_d").unwrap().is_none(),
                format!("{}/{role:?}: the touch recreated a deleted row", fx.kind),
            );
            failures.check(unauthorized(&svc, "tok_race_d"), format!("{}/{role:?}: a deleted bearer authenticated", fx.kind));
        }
    }
}

/// A row that now carries a different token is not the one the request authenticated against, and
/// writing the old digest back would rotate it backwards.
#[test]
fn a_touch_that_lands_after_a_token_change_does_not_put_the_old_token_back() {
    let mut failures = Failures::default();
    for role in ROLES {
        for fx in every_store("rotate") {
            let svc = service(fx.store.clone());
            let now = now_ms();
            fx.store.put_session(live("sess_t", "tok_race_old", role, now)).unwrap();

            let read_at_auth = fx.store.session_by_token("tok_race_old").unwrap().expect("a live session");
            fx.store.put_session(live("sess_t", "tok_race_new", role, now)).unwrap();
            svc.touch_session(&read_at_auth, now);

            failures.check(unauthorized(&svc, "tok_race_old"), format!("{}/{role:?}: the old token came back", fx.kind));
            let row = fx.store.session_by_token("tok_race_new").unwrap();
            failures.check(
                row.is_some_and(|row| row.last_used_at.is_none()),
                format!("{}/{role:?}: the new token was lost, or the old token's use was recorded on it", fx.kind),
            );
        }
    }
}

/// A session that stopped being usable while the request was in flight stays stopped: a touch only
/// records use of a session that is live when it lands.
#[test]
fn a_touch_that_lands_after_the_session_lapsed_does_not_extend_it() {
    let mut failures = Failures::default();
    for role in ROLES {
        for fx in every_store("lapse") {
            let svc = service(fx.store.clone());
            let now = now_ms();
            fx.store.put_session(live("sess_l", "tok_race_l", role, now)).unwrap();

            let read_at_auth = fx.store.session_by_token("tok_race_l").unwrap().expect("a live session");
            let lapsed = Session { expires_at: Some(now - 1), ..fx.store.get_session("sess_l").unwrap().unwrap() };
            fx.store.put_session(lapsed).unwrap();
            svc.touch_session(&read_at_auth, now);

            let row = fx.store.get_session("sess_l").unwrap().unwrap();
            failures.check(row.expires_at == Some(now - 1), format!("{}/{role:?}: the touch extended a lapsed session", fx.kind));
            failures.check(unauthorized(&svc, "tok_race_l"), format!("{}/{role:?}: a lapsed bearer authenticated", fx.kind));
        }
    }
}

/// Two requests touch the same agent session out of order. The earlier one landing second must not
/// pull the sliding expiry, or the last-use stamp, back to its own older clock.
#[test]
fn an_older_touch_landing_second_never_shortens_the_expiry() {
    let mut failures = Failures::default();
    for fx in every_store("order") {
        let svc = service(fx.store.clone());
        let now = now_ms();
        fx.store.put_session(live("sess_o", "tok_race_o", SessionRole::Agent, now)).unwrap();

        let read_at_auth = fx.store.session_by_token("tok_race_o").unwrap().expect("a live session");
        svc.touch_session(&read_at_auth, now + 5_000);
        svc.touch_session(&read_at_auth, now);

        let row = fx.store.get_session("sess_o").unwrap().unwrap();
        failures.check(
            row.expires_at == Some(now + 5_000 + AGENT_SESSION_TTL_MS),
            format!("{}: the expiry went backwards", fx.kind),
        );
        failures.check(row.last_used_at == Some(now + 5_000), format!("{}: last use went backwards", fx.kind));
    }
}

/// Controls that held before the fix and must keep holding: a revocation after a touch sticks, a
/// touch inside the interval writes nothing, a touch records use and slides only an agent's expiry,
/// and the stored digest is never itself a bearer.
#[test]
fn the_sequential_paths_are_unchanged() {
    for role in ROLES {
        for fx in every_store("controls") {
            let svc = service(fx.store.clone());
            let now = now_ms();

            fx.store.put_session(live("sess_seq", "tok_race_seq", role, now)).unwrap();
            svc.authenticate("tok_race_seq").expect("live");
            assert!(fx.store.revoke_session("sess_seq").unwrap());
            assert!(unauthorized(&svc, "tok_race_seq"), "{}/{role:?}: touch then revoke did not stick", fx.kind);

            let recent = Session { last_used_at: Some(now - 1_000), ..live("sess_recent", "tok_race_recent", role, now) };
            fx.store.put_session(recent.clone()).unwrap();
            let read_at_auth = fx.store.session_by_token("tok_race_recent").unwrap().unwrap();
            svc.touch_session(&read_at_auth, now);
            let row = fx.store.get_session("sess_recent").unwrap().unwrap();
            assert_eq!(row.last_used_at, Some(now - 1_000), "{}/{role:?}: a touch inside the interval wrote", fx.kind);
            assert_eq!(row.expires_at, recent.expires_at);

            let fresh = live("sess_use", "tok_race_use", role, now);
            fx.store.put_session(fresh.clone()).unwrap();
            let read_at_auth = fx.store.session_by_token("tok_race_use").unwrap().unwrap();
            svc.touch_session(&read_at_auth, now + 1);
            let row = fx.store.get_session("sess_use").unwrap().unwrap();
            assert_eq!(row.last_used_at, Some(now + 1), "{}/{role:?}: use was not recorded", fx.kind);
            let expected = match role {
                SessionRole::Agent => Some(now + 1 + AGENT_SESSION_TTL_MS),
                SessionRole::Operator => fresh.expires_at,
            };
            assert_eq!(row.expires_at, expected, "{}/{role:?}: wrong expiry after a touch", fx.kind);
            assert!(!row.revoked && row.role == role && row.agent_id == fresh.agent_id);

            if fx.kind != "memory" {
                assert!(row.token.starts_with(crate::store::SESSION_HASH_PREFIX), "{}: the row holds a digest", fx.kind);
                assert!(unauthorized(&svc, &row.token), "{}: the stored digest authenticated as a bearer", fx.kind);
            }
        }
    }
}

fn as_json(session: &Session) -> serde_json::Value {
    serde_json::to_value(session).unwrap()
}

/// The store operation on its own: it writes the activity fields of a live row, only forward, and
/// leaves everything else in the row as it was.
#[test]
fn the_store_touch_writes_only_the_activity_fields() {
    let mut failures = Failures::default();
    for fx in every_store("store-touch") {
        let now = now_ms();
        let original = Session {
            user_id: Some("user-1".into()),
            device_id: Some("device-1".into()),
            actor: Some(crate::store::SessionActor { sub: "member-1".into(), name: Some("Member".into()), role: None, vault_export: None }),
            ..live("sess_s", "tok_race_s", SessionRole::Agent, now)
        };
        fx.store.put_session(original.clone()).unwrap();
        let stored = fx.store.get_session("sess_s").unwrap().unwrap();

        failures.check(
            fx.store.touch_session("sess_s", &stored.token, now, Some(now + 10)).unwrap(),
            format!("{}: a live row was not touched", fx.kind),
        );
        let row = fx.store.get_session("sess_s").unwrap().unwrap();
        let mut expected = as_json(&stored);
        expected["last_used_at"] = serde_json::json!(now);
        failures.check(as_json(&row) == expected, format!("{}: the touch changed more than last use: {row:?}", fx.kind));

        fx.store.touch_session("sess_s", &stored.token, now - 10, Some(now + 2 * AGENT_SESSION_TTL_MS)).unwrap();
        let row = fx.store.get_session("sess_s").unwrap().unwrap();
        failures.check(row.last_used_at == Some(now), format!("{}: last use moved backwards", fx.kind));
        failures.check(
            row.expires_at == Some(now + 2 * AGENT_SESSION_TTL_MS),
            format!("{}: a later expiry was not taken", fx.kind),
        );

        failures.check(
            fx.store.touch_session("sess_s", "tok_race_s", now + 1, None).unwrap(),
            format!("{}: the presented bearer did not name its own row", fx.kind),
        );
        let row = fx.store.get_session("sess_s").unwrap().unwrap();
        failures.check(
            row.last_used_at == Some(now + 1) && row.expires_at == Some(now + 2 * AGENT_SESSION_TTL_MS),
            format!("{}: a touch with no expiry changed the expiry", fx.kind),
        );
    }
}

/// A touch of a row that is gone, revoked, expired or carrying another token writes nothing and says so.
#[test]
fn the_store_touch_refuses_a_row_that_is_not_live() {
    let mut failures = Failures::default();
    for fx in every_store("store-refuse") {
        let now = now_ms();
        let far = Some(now + AGENT_SESSION_TTL_MS);

        failures.check(
            !fx.store.touch_session("sess_gone", "tok_race_gone", now, far).unwrap(),
            format!("{}: touched a missing row", fx.kind),
        );
        failures.check(fx.store.get_session("sess_gone").unwrap().is_none(), format!("{}: a touch created a row", fx.kind));

        let mut cases = vec![("revoked", live("sess_rv", "tok_race_rv", SessionRole::Agent, now), "tok_race_rv")];
        cases.push(("expired", Session { expires_at: Some(now), ..live("sess_ex", "tok_race_ex", SessionRole::Agent, now) }, "tok_race_ex"));
        cases.push(("other token", live("sess_ot", "tok_race_ot", SessionRole::Agent, now), "tok_race_someone_else"));
        for (case, session, presented) in cases {
            let id = session.id.clone();
            fx.store.put_session(session).unwrap();
            if case == "revoked" {
                fx.store.revoke_session(&id).unwrap();
            }
            let before = as_json(&fx.store.get_session(&id).unwrap().unwrap());
            failures.check(
                !fx.store.touch_session(&id, presented, now, far).unwrap(),
                format!("{}/{case}: reported a touch", fx.kind),
            );
            failures.check(
                as_json(&fx.store.get_session(&id).unwrap().unwrap()) == before,
                format!("{}/{case}: the row changed", fx.kind),
            );
        }
    }
}

/// Revoking changes `revoked` and nothing else, and never creates a row.
#[test]
fn revoking_sets_only_the_flag_and_never_creates_a_row() {
    let mut failures = Failures::default();
    for fx in every_store("store-revoke") {
        let now = now_ms();
        let session = Session { last_used_at: Some(now - 5), ..live("sess_rk", "tok_race_rk", SessionRole::Operator, now) };
        fx.store.put_session(session).unwrap();
        let mut expected = as_json(&fx.store.get_session("sess_rk").unwrap().unwrap());
        expected["revoked"] = serde_json::json!(true);

        failures.check(fx.store.revoke_session("sess_rk").unwrap(), format!("{}: revoke missed a row", fx.kind));
        failures.check(fx.store.revoke_session("sess_rk").unwrap(), format!("{}: a second revoke missed the row", fx.kind));
        failures.check(
            as_json(&fx.store.get_session("sess_rk").unwrap().unwrap()) == expected,
            format!("{}: revoking changed more than the flag", fx.kind),
        );
        failures.check(!fx.store.revoke_session("sess_none").unwrap(), format!("{}: revoked a missing row", fx.kind));
        failures.check(fx.store.get_session("sess_none").unwrap().is_none(), format!("{}: revoke created a row", fx.kind));
    }
}

/// An insert loses to any row already there, a tombstone included.
#[test]
fn insert_session_never_replaces_a_row() {
    let mut failures = Failures::default();
    for fx in every_store("store-insert") {
        let now = now_ms();
        failures.check(
            fx.store.insert_session(live("sess_in", "tok_race_in", SessionRole::Agent, now)).unwrap(),
            format!("{}: the first insert was refused", fx.kind),
        );
        fx.store.revoke_session("sess_in").unwrap();
        let before = as_json(&fx.store.get_session("sess_in").unwrap().unwrap());
        failures.check(
            !fx.store.insert_session(live("sess_in", "tok_race_in2", SessionRole::Agent, now)).unwrap(),
            format!("{}: an insert replaced an existing row", fx.kind),
        );
        failures.check(
            as_json(&fx.store.get_session("sess_in").unwrap().unwrap()) == before,
            format!("{}: the existing row changed", fx.kind),
        );
        failures.check(
            fx.store.session_by_token("tok_race_in2").unwrap().is_none(),
            format!("{}: the refused insert's token resolves", fx.kind),
        );
    }
}

type Hook = Box<dyn FnOnce(&dyn Store) + Send>;

/// The real SQLite store, with a way to run something between a session read and the caller acting on
/// it: the window this race lives in, made deterministic.
struct InterleavingStore {
    inner: SqliteStore,
    after_token_read: Mutex<Option<(String, Hook)>>,
    after_id_read: Mutex<Option<(String, Hook)>>,
}

impl InterleavingStore {
    fn new() -> Self {
        InterleavingStore {
            inner: SqliteStore::open_in_memory().unwrap(),
            after_token_read: Mutex::new(None),
            after_id_read: Mutex::new(None),
        }
    }

    fn take(slot: &Mutex<Option<(String, Hook)>>, key: &str) -> Option<Hook> {
        let mut slot = slot.lock().unwrap();
        if slot.as_ref().is_some_and(|(k, _)| k == key) {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    }
}

macro_rules! delegate {
    ($( fn $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty; )*) => {
        $( fn $name(&self, $( $arg : $ty ),*) -> $ret { self.inner.$name($( $arg ),*) } )*
    };
}

impl Store for InterleavingStore {
    fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError> {
        f(self)
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn session_by_token(&self, token: &str) -> Result<Option<Session>, GatewayError> {
        let seen = self.inner.session_by_token(token)?;
        if let Some(hook) = Self::take(&self.after_token_read, token) {
            hook(&self.inner);
        }
        Ok(seen)
    }
    fn get_session(&self, id: &str) -> Result<Option<Session>, GatewayError> {
        let seen = self.inner.get_session(id)?;
        if let Some(hook) = Self::take(&self.after_id_read, id) {
            hook(&self.inner);
        }
        Ok(seen)
    }
    delegate! {
        fn get_meta(key: &str) -> Result<Option<String>, GatewayError>;
        fn put_meta(key: &str, value: &str) -> Result<(), GatewayError>;
        fn put_agent(agent: Agent) -> Result<(), GatewayError>;
        fn get_agent(id: &str) -> Result<Option<Agent>, GatewayError>;
        fn list_agents() -> Result<Vec<Agent>, GatewayError>;
        fn delete_agent(id: &str) -> Result<bool, GatewayError>;
        fn put_session(session: Session) -> Result<(), GatewayError>;
        fn insert_session(session: Session) -> Result<bool, GatewayError>;
        fn touch_session(id: &str, token: &str, now: i64, extend_expiry_to: Option<i64>) -> Result<bool, GatewayError>;
        fn list_sessions() -> Result<Vec<Session>, GatewayError>;
        fn revoke_session(id: &str) -> Result<bool, GatewayError>;
        fn expire_session_by(id: &str, at: i64) -> Result<bool, GatewayError>;
        fn delete_live_sessions() -> Result<u64, GatewayError>;
        fn delete_session(id: &str) -> Result<bool, GatewayError>;
        fn delete_session_if(id: &str, dead: &dyn Fn(&Session) -> bool) -> Result<bool, GatewayError>;
        fn put_connection(connection: permaura_core::Connection) -> Result<(), GatewayError>;
        fn get_connection(id: &str) -> Result<Option<permaura_core::Connection>, GatewayError>;
        fn list_connections() -> Result<Vec<permaura_core::Connection>, GatewayError>;
        fn delete_connection(id: &str) -> Result<bool, GatewayError>;
        fn put_policy(policy: permaura_core::Policy) -> Result<(), GatewayError>;
        fn get_policy(id: &str) -> Result<Option<permaura_core::Policy>, GatewayError>;
        fn list_policies() -> Result<Vec<permaura_core::Policy>, GatewayError>;
        fn policies_for_connection(connection_id: &str) -> Result<Vec<permaura_core::Policy>, GatewayError>;
        fn delete_policy(id: &str) -> Result<bool, GatewayError>;
        fn put_grant(grant: permaura_core::Grant) -> Result<(), GatewayError>;
        fn get_grant(grant_id: &str) -> Result<Option<permaura_core::Grant>, GatewayError>;
        fn list_grants() -> Result<Vec<permaura_core::Grant>, GatewayError>;
        fn update_grant(grant: permaura_core::Grant) -> Result<bool, GatewayError>;
        fn delete_grant(grant_id: &str) -> Result<bool, GatewayError>;
        fn put_enrolment_code(code: crate::store::EnrolmentCode) -> Result<(), GatewayError>;
        fn mint_enrolment_code(code: crate::store::EnrolmentCode, now_ms: i64, live_max: usize) -> Result<(), GatewayError>;
        fn consume_enrolment_code(code: &str, now_ms: i64) -> Result<Option<crate::store::EnrolmentCode>, GatewayError>;
        fn enrolment_code_redeemable(code: &str, now_ms: i64) -> Result<bool, GatewayError>;
        fn delete_unconsumed_enrolment_codes() -> Result<u64, GatewayError>;
        fn put_secret(record: SecretRecord) -> Result<(), GatewayError>;
        fn put_secret_if_unchanged(id: &str, expected: &permaura_core::SealedSecret, sealed: permaura_core::SealedSecret) -> Result<bool, GatewayError>;
        fn get_secret(id: &str) -> Result<Option<SecretRecord>, GatewayError>;
        fn list_secret_ids() -> Result<Vec<String>, GatewayError>;
        fn delete_secret(id: &str) -> Result<bool, GatewayError>;
        fn put_secret_custody(custody: crate::store::SecretCustody) -> Result<(), GatewayError>;
        fn get_secret_custody(secret_id: &str) -> Result<Option<crate::store::SecretCustody>, GatewayError>;
        fn list_secret_custody() -> Result<Vec<crate::store::SecretCustody>, GatewayError>;
        fn delete_secret_custody(secret_id: &str) -> Result<bool, GatewayError>;
        fn put_capability(cap: Capability) -> Result<(), GatewayError>;
        fn get_capability(id: &str) -> Result<Option<Capability>, GatewayError>;
        fn list_capabilities() -> Result<Vec<Capability>, GatewayError>;
        fn delete_capability(id: &str) -> Result<bool, GatewayError>;
        fn put_approval(approval: PendingApproval) -> Result<(), GatewayError>;
        fn insert_approval(approval: PendingApproval) -> Result<(), GatewayError>;
        fn get_approval(id: &str) -> Result<Option<PendingApproval>, GatewayError>;
        fn set_approval_status(id: &str, status: &str) -> Result<Option<PendingApproval>, GatewayError>;
        fn list_approvals(status: Option<&str>) -> Result<Vec<PendingApproval>, GatewayError>;
        fn put_connector_manifest(manifest: crate::manifest::InstalledManifest) -> Result<(), GatewayError>;
        fn get_connector_manifest(id: &str) -> Result<Option<crate::manifest::InstalledManifest>, GatewayError>;
        fn list_connector_manifests() -> Result<Vec<crate::manifest::InstalledManifest>, GatewayError>;
        fn delete_connector_manifest(id: &str) -> Result<bool, GatewayError>;
        fn claim_once(scope: &str, jti: &str, expires_at_ms: i64) -> Result<bool, GatewayError>;
        fn append_audit_charged(payload: AuditPayload, charge: Option<crate::store::GrantCharge>) -> Result<permaura_core::AuditEvent, GatewayError>;
        fn audit_events(limit: Option<usize>) -> Result<Vec<permaura_core::AuditEvent>, GatewayError>;
        fn audit_len() -> Result<u64, GatewayError>;
        fn put_call_diagnostic(diagnostic: crate::store::CallDiagnostic) -> Result<(), GatewayError>;
        fn call_diagnostics(from_seq: u64) -> Result<Vec<crate::store::CallDiagnostic>, GatewayError>;
        fn purge_call_diagnostics() -> Result<u64, GatewayError>;
        fn audit_events_from(from_seq: u64, limit: usize) -> Result<Vec<permaura_core::AuditEvent>, GatewayError>;
        fn prune_audit_to(end_seq: u64, base_hash: &str, segment_head: &str) -> Result<u64, GatewayError>;
        fn seal_audit_segment(draft: permaura_core::audit::AuditSegmentDraft) -> Result<permaura_core::audit::AuditSegment, GatewayError>;
        fn seal_audit_index(index: permaura_core::audit::AuditArchiveIndex, written_at: &str) -> Result<permaura_core::audit::AuditArchiveIndex, GatewayError>;
        fn audit_verifying_key() -> Result<[u8; 32], GatewayError>;
        fn count_grant_usage(windows: &[crate::store::GrantWindow<'_>]) -> Result<crate::store::GrantUsageCounts, GatewayError>;
        fn read_grant_usage(windows: &[crate::store::GrantWindow<'_>]) -> Result<crate::store::GrantUsageCounts, GatewayError>;
        fn grant_usage_series(grant_id: &str, since_ms: i64, bucket_ms: i64, buckets: usize) -> Result<Vec<u64>, GatewayError>;
        fn rebuild_grant_usage(archived: &mut dyn Iterator<Item = Result<permaura_core::AuditEvent, GatewayError>>) -> Result<u64, GatewayError>;
        fn verify_audit() -> Result<Option<u64>, GatewayError>;
        fn audit_boundary() -> Result<Option<permaura_core::audit::AuditBoundary>, GatewayError>;
        fn fork_audit_epoch(epoch: u64, restore_id: &str) -> Result<bool, GatewayError>;
    }
}

async fn send(router: &axum::Router, method: &str, uri: &str, bearer: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// The race end to end through the REST routes: an agent's request has read its session and is held there
/// while the operator revokes that session over `POST /v1/sessions/:id/revoke`; the held request then
/// finishes, touch included. It was admitted before the revocation, so it may succeed. The next request
/// with the same bearer must not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_over_rest_survives_an_in_flight_requests_touch() {
    let store = Arc::new(InterleavingStore::new());
    let now = now_ms();
    store.put_session(live("sess_race_op", "pgt_race_operator", SessionRole::Operator, now)).unwrap();
    store.put_session(live("sess_race_agent", "tok_race_agent", SessionRole::Agent, now)).unwrap();
    let state = crate::AppState::from_parts(store.clone(), Arc::new(MockHttpClient::new()));
    let router = crate::build_router(state, "127.0.0.1:7376".parse().unwrap());

    let (read_tx, read_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    *store.after_token_read.lock().unwrap() = Some((
        "tok_race_agent".into(),
        Box::new(move |_| {
            read_tx.send(()).unwrap();
            go_rx.recv().unwrap();
        }),
    ));

    let in_flight = {
        let router = router.clone();
        tokio::spawn(async move { send(&router, "GET", "/v1/broker", "tok_race_agent").await })
    };
    tokio::task::spawn_blocking(move || read_rx.recv().expect("the agent's request read its session"))
        .await
        .unwrap();

    let revoked = send(&router, "POST", "/v1/sessions/sess_race_agent/revoke", "pgt_race_operator").await;
    assert_eq!(revoked, StatusCode::OK, "the operator's revoke");
    assert!(store.inner.get_session("sess_race_agent").unwrap().unwrap().revoked);

    go_tx.send(()).unwrap();
    assert_eq!(in_flight.await.unwrap(), StatusCode::OK, "admitted before the revocation");

    assert!(
        store.inner.get_session("sess_race_agent").unwrap().unwrap().revoked,
        "the in-flight request's touch un-revoked the session"
    );
    assert_eq!(
        send(&router, "GET", "/v1/broker", "tok_race_agent").await,
        StatusCode::UNAUTHORIZED,
        "the revoked bearer authenticated on a later request"
    );
}

/// The OAuth path writes a session row when it finds none. If the owner removed the agent between that
/// read and the write, their removal left a revoked row standing for it, and the write must not replace
/// it: that row is what brings the client back Pending rather than Approved.
#[test]
fn a_first_oauth_call_does_not_overwrite_a_removal_that_landed_meanwhile() {
    let store = Arc::new(InterleavingStore::new());
    let svc = service(store.clone());
    let claims = crate::oauth::VerifiedClaims {
        sub: "operator-1".into(),
        azp: Some("client-race".into()),
        name: Some("Client".into()),
        scope: Some("openid mcp offline_access".into()),
        actor: None,
    };
    let agent_id = oauth_agent_id(&claims);
    let row_id = oauth_session_id(&agent_id);
    svc.session_from_jwt(claims.clone()).expect("first contact");
    // The row is gone (the dead-session prune removes a lapsed one) while the agent stays approved.
    assert!(store.delete_session(&row_id).unwrap());
    assert_eq!(store.get_agent(&agent_id).unwrap().unwrap().status, AgentStatus::Approved);

    // Between this call's read of the missing row and its write, the owner removes the agent: the same
    // effect as the `AgentDelete` mutation, which writes a tombstone when it finds no row to revoke.
    let removed = agent_id.clone();
    *store.after_id_read.lock().unwrap() = Some((
        row_id.clone(),
        Box::new(move |s| {
            assert!(s.delete_agent(&removed).unwrap());
            assert!(s.get_session(&oauth_session_id(&removed)).unwrap().is_none());
            s.put_session(oauth_tombstone(&removed)).unwrap();
        }),
    ));
    let _ = svc.session_from_jwt(claims.clone());

    assert!(
        store.get_session(&row_id).unwrap().unwrap().revoked,
        "the in-flight call replaced the owner's tombstone with a live row"
    );
    let _ = svc.session_from_jwt(claims);
    assert_eq!(
        store.get_agent(&agent_id).unwrap().map(|a| a.status),
        Some(AgentStatus::Pending),
        "a removed client must come back Pending"
    );
}
