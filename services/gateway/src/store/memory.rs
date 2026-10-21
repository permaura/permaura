//! The in-memory [`Store`]: a set of `RwLock<HashMap>`s plus the core [`AuditLog`],
//! used by the demo, the tests and `PERMAURA_STORE_PATH=:memory:`; nothing in it
//! survives a restart. Always available, no features required, safe for concurrent
//! axum handlers behind an `Arc`.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::thread::ThreadId;

use permaura_core::{AuditEvent, AuditLog, AuditPayload, Connection, Grant, Policy, SealedSecret, SecretRecord};

use crate::connectors::Capability;
use crate::error::GatewayError;
use crate::manifest::InstalledManifest;

use super::{Agent, EnrolmentCode, GrantUsageTable, PendingApproval, SecretCustody, Session, Store};

/// In-memory store. Each table is an independently-locked map; the audit log owns its
/// own `RwLock` because appends mutate the hash chain.
pub struct MemoryStore {
    agents: RwLock<HashMap<String, Agent>>,
    sessions: RwLock<HashMap<String, Session>>,
    connections: RwLock<HashMap<String, Connection>>,
    policies: RwLock<HashMap<String, Policy>>,
    grants: RwLock<Vec<Grant>>,
    secrets: RwLock<HashMap<String, SecretRecord>>,
    secret_custody: RwLock<HashMap<String, SecretCustody>>,
    capabilities: RwLock<HashMap<String, Capability>>,
    approvals: RwLock<HashMap<String, PendingApproval>>,
    enrolment_codes: RwLock<HashMap<String, EnrolmentCode>>,
    connector_manifests: RwLock<HashMap<String, InstalledManifest>>,
    meta: RwLock<HashMap<String, String>>,
    /// Spent one-shot token ids → the expiry of the token each guards. Keyed `(scope, jti)`, the
    /// same primary key the persistent stores use.
    one_time_claims: RwLock<HashMap<(String, String), i64>>,
    call_diagnostics: RwLock<std::collections::BTreeMap<u64, super::CallDiagnostic>>,
    audit: RwLock<AuditLog>,
    /// The materialised grant budget counter, charged under the same lock as the append that
    /// spends it so the two cannot land apart.
    grant_usage: RwLock<GrantUsageTable>,
    /// The thread inside `run_atomically`, and how deep, mirroring the SQLite store's owner. This
    /// store has nothing to roll back, but it is what every test runs on, so without the same refusal
    /// a write the real stores reject passes here and ships.
    transaction_owner: Mutex<Option<(ThreadId, u32)>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        MemoryStore {
            agents: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            policies: RwLock::new(HashMap::new()),
            grants: RwLock::new(Vec::new()),
            secrets: RwLock::new(HashMap::new()),
            secret_custody: RwLock::new(HashMap::new()),
            capabilities: RwLock::new(HashMap::new()),
            approvals: RwLock::new(HashMap::new()),
            enrolment_codes: RwLock::new(HashMap::new()),
            connector_manifests: RwLock::new(HashMap::new()),
            meta: RwLock::new(HashMap::new()),
            one_time_claims: RwLock::new(HashMap::new()),
            call_diagnostics: RwLock::new(std::collections::BTreeMap::new()),
            audit: RwLock::new(AuditLog::new()),
            grant_usage: RwLock::new(GrantUsageTable::default()),
            transaction_owner: Mutex::new(None),
        }
    }
}

impl MemoryStore {
    /// Construct a fresh, empty in-memory store.
    pub fn new() -> Self {
        MemoryStore::default()
    }

    fn owner(&self) -> Option<(ThreadId, u32)> {
        *self.transaction_owner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn set_owner(&self, value: Option<(ThreadId, u32)>) {
        *self.transaction_owner.lock().unwrap_or_else(|p| p.into_inner()) = value;
    }

    fn owns_transaction(&self) -> bool {
        matches!(self.owner(), Some((t, _)) if t == std::thread::current().id())
    }
}

/// Translate a poisoned lock into a gateway error rather than panicking the handler.
fn lock_err(what: &str) -> GatewayError {
    GatewayError::Internal(format!("lock poisoned: {what}"))
}

impl MemoryStore {
    /// [`Store::put_approval`], or with `insert_only` [`Store::insert_approval`].
    fn write_approval(&self, mut approval: PendingApproval, insert_only: bool) -> Result<(), GatewayError> {
        super::bound_stored_result(&mut approval);
        // Cap the held-approval store so a flood of relayed `requires_approval` calls cannot grow
        // it without bound (a remote memory-DoS).
        //
        // A new *pending* hold beyond the cap is now refused rather than made room for. Evicting the
        // oldest pending one, which is what this did, silently dropped a question a human had been
        // asked, and it is not something the SQLite store could copy anyway: there an eviction is a
        // write, and on a hosted worker a write is a full snapshot upload. Refusing costs a read, and
        // it is the same refusal in both stores.
        const MAX_APPROVALS: usize = crate::store::MAX_PENDING_APPROVALS;
        let mut approvals = self.approvals.write().map_err(|_| lock_err("approvals"))?;
        if let Some(stored) = approvals.get(&approval.id) {
            if insert_only {
                return Err(GatewayError::Conflict(format!(
                    "an approval with id '{}' already exists, and a new hold never writes over one",
                    approval.id
                )));
            }
            super::refuse_settled_approval_rewrite(&approval.id, &stored.status, &approval.status)?;
        }
        let known = approvals.contains_key(&approval.id);
        if !known && approval.status == "pending" {
            let pending = approvals.values().filter(|a| a.status == "pending").count();
            if pending >= MAX_APPROVALS {
                return Err(crate::store::too_many_pending_approvals(pending));
            }
        }
        // A resolved row is only a cached result, so the map stays bounded by dropping the oldest of
        // those rather than by growing. With the refusal above, a pending row is never a victim.
        if !known && approvals.len() >= MAX_APPROVALS {
            let victim = approvals
                .values()
                .filter(|a| a.status != "pending")
                .min_by_key(|a| a.created_at)
                .map(|a| a.id.clone());
            if let Some(id) = victim {
                approvals.remove(&id);
            }
        }
        approvals.insert(approval.id.clone(), approval);
        Ok(())
    }
}

impl Store for MemoryStore {
    fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError> {
        let me = std::thread::current().id();
        let depth = self.owner().map(|(_, d)| d).unwrap_or(0) + 1;
        self.set_owner(Some((me, depth)));
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
        self.set_owner(if depth > 1 { Some((me, depth - 1)) } else { None });
        match out {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(out) => out,
        }
    }
    fn kind(&self) -> &'static str {
        "memory"
    }

    fn put_agent(&self, agent: Agent) -> Result<(), GatewayError> {
        self.agents
            .write()
            .map_err(|_| lock_err("agents"))?
            .insert(agent.id.clone(), agent);
        Ok(())
    }

    fn get_agent(&self, id: &str) -> Result<Option<Agent>, GatewayError> {
        Ok(self
            .agents
            .read()
            .map_err(|_| lock_err("agents"))?
            .get(id)
            .cloned())
    }

    fn list_agents(&self) -> Result<Vec<Agent>, GatewayError> {
        Ok(self
            .agents
            .read()
            .map_err(|_| lock_err("agents"))?
            .values()
            .cloned()
            .collect())
    }

    fn delete_agent(&self, id: &str) -> Result<bool, GatewayError> {
        Ok(self
            .agents
            .write()
            .map_err(|_| lock_err("agents"))?
            .remove(id)
            .is_some())
    }

    fn put_session(&self, session: Session) -> Result<(), GatewayError> {
        self.sessions
            .write()
            .map_err(|_| lock_err("sessions"))?
            .insert(session.id.clone(), session);
        Ok(())
    }

    fn insert_session(&self, session: Session) -> Result<bool, GatewayError> {
        let mut sessions = self.sessions.write().map_err(|_| lock_err("sessions"))?;
        if sessions.contains_key(&session.id) {
            return Ok(false);
        }
        sessions.insert(session.id.clone(), session);
        Ok(true)
    }

    fn touch_session(&self, id: &str, token: &str, now: i64, extend_expiry_to: Option<i64>) -> Result<bool, GatewayError> {
        let mut sessions = self.sessions.write().map_err(|_| lock_err("sessions"))?;
        let Some(s) = sessions.get_mut(id) else { return Ok(false) };
        if s.revoked || s.token != token || s.is_expired(now) {
            return Ok(false);
        }
        s.last_used_at = Some(s.last_used_at.map_or(now, |prev| prev.max(now)));
        if let Some(to) = extend_expiry_to {
            s.expires_at = Some(s.expires_at.map_or(to, |prev| prev.max(to)));
        }
        Ok(true)
    }

    fn session_by_token(&self, token: &str) -> Result<Option<Session>, GatewayError> {
        Ok(self
            .sessions
            .read()
            .map_err(|_| lock_err("sessions"))?
            .values()
            .find(|s| s.token == token)
            .cloned())
    }

    fn get_session(&self, id: &str) -> Result<Option<Session>, GatewayError> {
        Ok(self
            .sessions
            .read()
            .map_err(|_| lock_err("sessions"))?
            .get(id)
            .cloned())
    }

    fn list_sessions(&self) -> Result<Vec<Session>, GatewayError> {
        Ok(self
            .sessions
            .read()
            .map_err(|_| lock_err("sessions"))?
            .values()
            .cloned()
            .collect())
    }

    fn revoke_session(&self, id: &str) -> Result<bool, GatewayError> {
        let mut sessions = self.sessions.write().map_err(|_| lock_err("sessions"))?;
        match sessions.get_mut(id) {
            Some(s) => {
                s.revoked = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn expire_session_by(&self, id: &str, at: i64) -> Result<bool, GatewayError> {
        let mut sessions = self.sessions.write().map_err(|_| lock_err("sessions"))?;
        match sessions.get_mut(id) {
            Some(s) if !s.revoked => {
                s.expires_at = Some(s.expires_at.map_or(at, |e| e.min(at)));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn delete_session(&self, id: &str) -> Result<bool, GatewayError> {
        Ok(self.sessions.write().map_err(|_| lock_err("sessions"))?.remove(id).is_some())
    }

    fn delete_session_if(&self, id: &str, dead: &dyn Fn(&Session) -> bool) -> Result<bool, GatewayError> {
        // One write guard over the judgement and the removal: `run_atomically` here excludes no other
        // thread, the sessions lock does.
        let mut sessions = self.sessions.write().map_err(|_| lock_err("sessions"))?;
        if !sessions.get(id).is_some_and(dead) {
            return Ok(false);
        }
        Ok(sessions.remove(id).is_some())
    }

    fn delete_live_sessions(&self) -> Result<u64, GatewayError> {
        let mut sessions = self.sessions.write().map_err(|_| lock_err("sessions"))?;
        let before = sessions.len();
        sessions.retain(|_, s| s.is_revocation_tombstone());
        Ok((before - sessions.len()) as u64)
    }

    fn put_connection(&self, connection: Connection) -> Result<(), GatewayError> {
        self.connections
            .write()
            .map_err(|_| lock_err("connections"))?
            .insert(connection.id.clone(), connection);
        Ok(())
    }

    fn get_connection(&self, id: &str) -> Result<Option<Connection>, GatewayError> {
        Ok(self
            .connections
            .read()
            .map_err(|_| lock_err("connections"))?
            .get(id)
            .cloned())
    }

    fn list_connections(&self) -> Result<Vec<Connection>, GatewayError> {
        Ok(self
            .connections
            .read()
            .map_err(|_| lock_err("connections"))?
            .values()
            .cloned()
            .collect())
    }

    fn delete_connection(&self, id: &str) -> Result<bool, GatewayError> {
        Ok(self
            .connections
            .write()
            .map_err(|_| lock_err("connections"))?
            .remove(id)
            .is_some())
    }

    fn put_policy(&self, policy: Policy) -> Result<(), GatewayError> {
        self.policies
            .write()
            .map_err(|_| lock_err("policies"))?
            .insert(policy.id.clone(), policy);
        Ok(())
    }

    fn get_policy(&self, id: &str) -> Result<Option<Policy>, GatewayError> {
        Ok(self
            .policies
            .read()
            .map_err(|_| lock_err("policies"))?
            .get(id)
            .cloned())
    }

    fn list_policies(&self) -> Result<Vec<Policy>, GatewayError> {
        Ok(self
            .policies
            .read()
            .map_err(|_| lock_err("policies"))?
            .values()
            .cloned()
            .collect())
    }

    fn policies_for_connection(&self, connection_id: &str) -> Result<Vec<Policy>, GatewayError> {
        Ok(self
            .policies
            .read()
            .map_err(|_| lock_err("policies"))?
            .values()
            .filter(|p| p.connection_id == connection_id)
            .cloned()
            .collect())
    }

    fn delete_policy(&self, id: &str) -> Result<bool, GatewayError> {
        Ok(self
            .policies
            .write()
            .map_err(|_| lock_err("policies"))?
            .remove(id)
            .is_some())
    }

    fn put_grant(&self, grant: Grant) -> Result<(), GatewayError> {
        self.grants
            .write()
            .map_err(|_| lock_err("grants"))?
            .push(grant);
        Ok(())
    }

    fn get_grant(&self, grant_id: &str) -> Result<Option<Grant>, GatewayError> {
        Ok(self
            .grants
            .read()
            .map_err(|_| lock_err("grants"))?
            .iter()
            .find(|g| g.grant_id == grant_id)
            .cloned())
    }

    fn list_grants(&self) -> Result<Vec<Grant>, GatewayError> {
        Ok(self
            .grants
            .read()
            .map_err(|_| lock_err("grants"))?
            .clone())
    }

    fn update_grant(&self, grant: Grant) -> Result<bool, GatewayError> {
        let mut grants = self.grants.write().map_err(|_| lock_err("grants"))?;
        if let Some(slot) = grants.iter_mut().find(|g| g.grant_id == grant.grant_id) {
            *slot = grant;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn delete_grant(&self, grant_id: &str) -> Result<bool, GatewayError> {
        let mut grants = self.grants.write().map_err(|_| lock_err("grants"))?;
        let before = grants.len();
        grants.retain(|g| g.grant_id != grant_id);
        Ok(grants.len() != before)
    }

    fn put_enrolment_code(&self, code: EnrolmentCode) -> Result<(), GatewayError> {
        let code = super::enrolment_code_at_rest(&code);
        let mut codes = self.enrolment_codes.write().map_err(|_| lock_err("enrolment_codes"))?;
        if codes.contains_key(&code.code) {
            return Err(GatewayError::Conflict("the new enrolment code collided with one already issued; mint another".into()));
        }
        codes.insert(code.code.clone(), code);
        Ok(())
    }

    fn mint_enrolment_code(&self, code: EnrolmentCode, now_ms: i64, live_max: usize) -> Result<(), GatewayError> {
        let code = super::enrolment_code_at_rest(&code);
        let mut codes = self.enrolment_codes.write().map_err(|_| lock_err("enrolment_codes"))?;
        let live = codes.values().filter(|c| !c.used && now_ms < c.expires_at).count();
        if live >= live_max {
            return Err(super::too_many_enrolment_codes(live));
        }
        codes.retain(|_, c| now_ms < c.expires_at);
        if codes.contains_key(&code.code) {
            return Err(GatewayError::Conflict("the new enrolment code collided with one already issued; mint another".into()));
        }
        codes.insert(code.code.clone(), code);
        Ok(())
    }

    fn consume_enrolment_code(
        &self,
        code: &str,
        now_ms: i64,
    ) -> Result<Option<EnrolmentCode>, GatewayError> {
        let mut codes = self
            .enrolment_codes
            .write()
            .map_err(|_| lock_err("enrolment_codes"))?;
        match codes.get_mut(&super::bearer_lookup_hash(code)) {
            Some(c) if !c.used && now_ms < c.expires_at => {
                c.used = true;
                Ok(Some(c.clone()))
            }
            _ => Ok(None),
        }
    }

    fn enrolment_code_redeemable(&self, code: &str, now_ms: i64) -> Result<bool, GatewayError> {
        let codes = self.enrolment_codes.read().map_err(|_| lock_err("enrolment_codes"))?;
        Ok(codes.get(&super::bearer_lookup_hash(code)).is_some_and(|c| !c.used && now_ms < c.expires_at))
    }

    fn live_enrolment_code_digests(&self, now_ms: i64) -> Result<Vec<String>, GatewayError> {
        let codes = self.enrolment_codes.read().map_err(|_| lock_err("enrolment_codes"))?;
        Ok(codes.values().filter(|c| !c.used && now_ms < c.expires_at).map(|c| c.code.clone()).collect())
    }

    fn delete_unconsumed_enrolment_codes(&self) -> Result<u64, GatewayError> {
        let mut codes = self
            .enrolment_codes
            .write()
            .map_err(|_| lock_err("enrolment_codes"))?;
        let before = codes.len() as u64;
        codes.retain(|_, c| c.used);
        Ok(before - codes.len() as u64)
    }

    fn put_secret(&self, record: SecretRecord) -> Result<(), GatewayError> {
        self.secrets
            .write()
            .map_err(|_| lock_err("secrets"))?
            .insert(record.id.clone(), record);
        Ok(())
    }

    fn get_secret(&self, id: &str) -> Result<Option<SecretRecord>, GatewayError> {
        Ok(self
            .secrets
            .read()
            .map_err(|_| lock_err("secrets"))?
            .get(id)
            .cloned())
    }

    fn put_secret_if_unchanged(&self, id: &str, expected: &SealedSecret, sealed: SealedSecret) -> Result<bool, GatewayError> {
        let mut secrets = self.secrets.write().map_err(|_| lock_err("secrets"))?;
        match secrets.get_mut(id) {
            Some(record) if record.sealed == *expected => {
                record.sealed = sealed;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn list_secret_ids(&self) -> Result<Vec<String>, GatewayError> {
        Ok(self
            .secrets
            .read()
            .map_err(|_| lock_err("secrets"))?
            .keys()
            .cloned()
            .collect())
    }

    fn delete_secret(&self, id: &str) -> Result<bool, GatewayError> {
        Ok(self
            .secrets
            .write()
            .map_err(|_| lock_err("secrets"))?
            .remove(id)
            .is_some())
    }

    fn put_secret_custody(&self, custody: SecretCustody) -> Result<(), GatewayError> {
        self.secret_custody
            .write()
            .map_err(|_| lock_err("secret_custody"))?
            .insert(custody.secret_id.clone(), custody);
        Ok(())
    }

    fn get_secret_custody(&self, secret_id: &str) -> Result<Option<SecretCustody>, GatewayError> {
        Ok(self
            .secret_custody
            .read()
            .map_err(|_| lock_err("secret_custody"))?
            .get(secret_id)
            .cloned())
    }

    fn list_secret_custody(&self) -> Result<Vec<SecretCustody>, GatewayError> {
        Ok(self
            .secret_custody
            .read()
            .map_err(|_| lock_err("secret_custody"))?
            .values()
            .cloned()
            .collect())
    }

    fn delete_secret_custody(&self, secret_id: &str) -> Result<bool, GatewayError> {
        Ok(self
            .secret_custody
            .write()
            .map_err(|_| lock_err("secret_custody"))?
            .remove(secret_id)
            .is_some())
    }

    fn put_capability(&self, cap: Capability) -> Result<(), GatewayError> {
        self.capabilities
            .write()
            .map_err(|_| lock_err("capabilities"))?
            .insert(cap.id.clone(), cap);
        Ok(())
    }

    fn get_capability(&self, id: &str) -> Result<Option<Capability>, GatewayError> {
        Ok(self
            .capabilities
            .read()
            .map_err(|_| lock_err("capabilities"))?
            .get(id)
            .cloned())
    }

    fn list_capabilities(&self) -> Result<Vec<Capability>, GatewayError> {
        Ok(self
            .capabilities
            .read()
            .map_err(|_| lock_err("capabilities"))?
            .values()
            .cloned()
            .collect())
    }

    fn delete_capability(&self, id: &str) -> Result<bool, GatewayError> {
        Ok(self
            .capabilities
            .write()
            .map_err(|_| lock_err("capabilities"))?
            .remove(id)
            .is_some())
    }

    fn put_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        self.write_approval(approval, false)
    }

    fn insert_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        self.write_approval(approval, true)
    }
    fn get_approval(&self, id: &str) -> Result<Option<PendingApproval>, GatewayError> {
        Ok(self
            .approvals
            .read()
            .map_err(|_| lock_err("approvals"))?
            .get(id)
            .cloned())
    }

    fn set_approval_status(
        &self,
        id: &str,
        status: &str,
    ) -> Result<Option<PendingApproval>, GatewayError> {
        let mut approvals = self.approvals.write().map_err(|_| lock_err("approvals"))?;
        match approvals.get_mut(id) {
            Some(a) => {
                super::refuse_settled_approval_rewrite(id, &a.status, status)?;
                a.status = status.to_string();
                Ok(Some(a.clone()))
            }
            None => Ok(None),
        }
    }

    fn pending_staging_owners(&self) -> Result<Vec<(String, Option<super::HoldRequester>)>, GatewayError> {
        let approvals = self.approvals.read().map_err(|_| lock_err("approvals"))?;
        Ok(approvals
            .values()
            .filter(|a| a.status == "pending" && a.is_control_plane_hold())
            .filter_map(|a| Some((permaura_core::json_stream::string_at(&a.params, "/staging_secret_id")?, a.requested_by.clone())))
            .collect())
    }

    fn list_approvals(&self, status: Option<&str>) -> Result<Vec<PendingApproval>, GatewayError> {
        let approvals = self.approvals.read().map_err(|_| lock_err("approvals"))?;
        let mut out: Vec<PendingApproval> = approvals
            .values()
            .filter(|a| status.map_or(true, |s| a.status == s))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    fn put_connector_manifest(&self, manifest: InstalledManifest) -> Result<(), GatewayError> {
        self.connector_manifests
            .write()
            .map_err(|_| lock_err("connector_manifests"))?
            .insert(manifest.manifest.id.clone(), manifest);
        Ok(())
    }

    fn get_connector_manifest(&self, id: &str) -> Result<Option<InstalledManifest>, GatewayError> {
        Ok(self
            .connector_manifests
            .read()
            .map_err(|_| lock_err("connector_manifests"))?
            .get(id)
            .cloned())
    }

    fn list_connector_manifests(&self) -> Result<Vec<InstalledManifest>, GatewayError> {
        Ok(self
            .connector_manifests
            .read()
            .map_err(|_| lock_err("connector_manifests"))?
            .values()
            .cloned()
            .collect())
    }

    fn delete_connector_manifest(&self, id: &str) -> Result<bool, GatewayError> {
        Ok(self
            .connector_manifests
            .write()
            .map_err(|_| lock_err("connector_manifests"))?
            .remove(id)
            .is_some())
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>, GatewayError> {
        Ok(self
            .meta
            .read()
            .map_err(|_| lock_err("meta"))?
            .get(key)
            .cloned())
    }

    fn put_meta(&self, key: &str, value: &str) -> Result<(), GatewayError> {
        self.meta
            .write()
            .map_err(|_| lock_err("meta"))?
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn claim_once(&self, scope: &str, jti: &str, expires_at_ms: i64) -> Result<bool, GatewayError> {
        // Single-use only within this process, which is all this store can offer and all it needs
        // to: it backs local and test runs, never the multi-instance hosted worker. The prune runs
        // first so a lapsed claim releases its key rather than pinning it forever, and it doubles as
        // the bound on how large this map can grow under a flood of distinct ids.
        let mut claims = self.one_time_claims.write().map_err(|_| lock_err("one_time_claims"))?;
        let now = super::now_ms();
        claims.retain(|_, exp| *exp > now);
        Ok(claims.insert((scope.to_string(), jti.to_string()), expires_at_ms).is_none())
    }

    fn append_audit_charged(
        &self,
        mut payload: AuditPayload,
        charge: Option<super::GrantCharge>,
    ) -> Result<AuditEvent, GatewayError> {
        crate::audit_bound::cut_ids(&mut payload);
        if self.owns_transaction() {
            return Err(GatewayError::Internal(
                "audit events cannot be appended inside a store transaction: the signed chain in memory has no rollback".into(),
            ));
        }
        // The counter lock is taken before the chain lock and held across the append, so a reader
        // never sees an event the counter has not been told about. The other order would let a
        // concurrent `read_grant_usage` authorize against a budget one call behind the chain.
        let mut usage = self.grant_usage.write().map_err(|_| lock_err("grant_usage"))?;
        let mut log = self.audit.write().map_err(|_| lock_err("audit"))?;
        let event = log
            .append(payload)
            .map_err(|e| GatewayError::Internal(format!("audit append failed: {e}")))?
            .clone();
        if let Some(charge) = charge {
            usage.charge(
                &charge.grant_id,
                super::charge_agent(&event.payload),
                event.timestamp,
                super::now_ms(),
            );
        }
        Ok(event)
    }

    fn put_call_diagnostic(&self, diagnostic: super::CallDiagnostic) -> Result<(), GatewayError> {
        let mut rows = self.call_diagnostics.write().map_err(|_| lock_err("call_diagnostics"))?;
        rows.insert(diagnostic.audit_seq, diagnostic);
        let horizon = super::now_ms() - super::CALL_DIAGNOSTICS_RETENTION_MS;
        rows.retain(|_, d| d.recorded_at >= horizon);
        while rows.len() > super::CALL_DIAGNOSTICS_MAX {
            rows.pop_first();
        }
        Ok(())
    }

    fn call_diagnostics(&self, from_seq: u64) -> Result<Vec<super::CallDiagnostic>, GatewayError> {
        let rows = self.call_diagnostics.read().map_err(|_| lock_err("call_diagnostics"))?;
        Ok(rows.range(from_seq..).map(|(_, d)| d.clone()).collect())
    }

    fn purge_call_diagnostics(&self) -> Result<u64, GatewayError> {
        let mut rows = self.call_diagnostics.write().map_err(|_| lock_err("call_diagnostics"))?;
        let n = rows.len() as u64;
        rows.clear();
        Ok(n)
    }

    fn audit_events(&self, limit: Option<usize>) -> Result<Vec<AuditEvent>, GatewayError> {
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        let events = log.events();
        let slice = match limit {
            Some(n) if n < events.len() => &events[events.len() - n..],
            _ => events,
        };
        Ok(slice.to_vec())
    }

    fn audit_events_from(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, GatewayError> {
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        let start = from_seq.saturating_sub(log.base_seq()) as usize;
        let events = log.events();
        if start >= events.len() {
            return Ok(Vec::new());
        }
        let end = start.saturating_add(limit).min(events.len());
        Ok(events[start..end].to_vec())
    }

    /// Nothing to prune to, because there is nothing to prune into. This store keeps no boundary
    /// record, so a prune would leave a chain whose first event is not seq 0 and nothing that says
    /// why, which is indistinguishable from a chain somebody truncated.
    fn prune_audit_to(
        &self,
        _end_seq: u64,
        _base_hash: &str,
        _segment_head: &str,
    ) -> Result<u64, GatewayError> {
        Err(GatewayError::Internal(
            "this store keeps no audit boundary, so a prune would leave a chain with no statement of where it starts: refusing".into(),
        ))
    }

    fn seal_audit_segment(
        &self,
        draft: permaura_core::audit::AuditSegmentDraft,
    ) -> Result<permaura_core::audit::AuditSegment, GatewayError> {
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        Ok(log.seal_segment(draft))
    }

    fn seal_audit_index(
        &self,
        index: permaura_core::audit::AuditArchiveIndex,
        written_at: &str,
    ) -> Result<permaura_core::audit::AuditArchiveIndex, GatewayError> {
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        Ok(log.seal_index(index, written_at))
    }

    fn audit_verifying_key(&self) -> Result<[u8; 32], GatewayError> {
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        Ok(log.verifying_key().to_bytes())
    }

    fn audit_len(&self) -> Result<u64, GatewayError> {
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        Ok(log.events().len() as u64)
    }

    fn count_grant_usage(
        &self,
        windows: &[super::GrantWindow<'_>],
    ) -> Result<super::GrantUsageCounts, GatewayError> {
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        Ok(super::tally_grant_usage(windows, log.events().iter()))
    }

    fn read_grant_usage(
        &self,
        windows: &[super::GrantWindow<'_>],
    ) -> Result<super::GrantUsageCounts, GatewayError> {
        let usage = self.grant_usage.read().map_err(|_| lock_err("grant_usage"))?;
        Ok(usage.read(windows))
    }

    fn grant_usage_series(
        &self,
        grant_id: &str,
        since_ms: i64,
        bucket_ms: i64,
        buckets: usize,
    ) -> Result<Vec<u64>, GatewayError> {
        let usage = self.grant_usage.read().map_err(|_| lock_err("grant_usage"))?;
        Ok(usage.series(grant_id, since_ms, bucket_ms, buckets))
    }

    /// Nothing below this store's hot window can exist (it has no archive and no boundary), so a
    /// rebuild is the hot chain refiled. An archived event handed to it is refused rather than
    /// filed or dropped: this store never pruned, so any such event is also in its hot window.
    fn rebuild_grant_usage(
        &self,
        archived: &mut dyn Iterator<Item = Result<AuditEvent, GatewayError>>,
    ) -> Result<u64, GatewayError> {
        if let Some(event) = archived.next() {
            let seq = event?.seq;
            return Err(GatewayError::Internal(format!(
                "archived event {seq} was handed to a store that has never pruned, so it is also in the hot window: refusing to charge it twice"
            )));
        }
        let mut usage = self.grant_usage.write().map_err(|_| lock_err("grant_usage"))?;
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        usage.clear();
        let mut filed = 0u64;
        let mut file = |event: &AuditEvent, usage: &mut super::GrantUsageTable| {
            if let Some(grant_id) = super::charged_grant(event) {
                // `now_ms` of the event itself: a rebuild refiles history, and folding it against
                // the wall clock as it went would compact rows the next charge is about to need.
                usage.charge(grant_id, super::charge_agent(&event.payload), event.timestamp, 0);
                filed += 1;
            }
        };
        for event in log.events() {
            file(event, &mut usage);
        }
        usage.compact(super::now_ms());
        Ok(filed)
    }

    fn verify_audit(&self) -> Result<Option<u64>, GatewayError> {
        let log = self.audit.read().map_err(|_| lock_err("audit"))?;
        Ok(log.verify())
    }

    /// No boundary record, and so no epoch either. An in-memory store has nothing to archive from
    /// and nothing to reopen into, which is the only thing a boundary is for.
    fn audit_boundary(&self) -> Result<Option<permaura_core::audit::AuditBoundary>, GatewayError> {
        Ok(None)
    }

    /// Nothing to fork, for the reason [`MemoryStore::audit_epoch`] has nothing to report. A restore
    /// that lands on this store still records its fork in the chain; what it cannot do is stamp a
    /// number on a boundary that does not exist.
    fn fork_audit_epoch(&self, _epoch: u64, _restore_id: &str) -> Result<bool, GatewayError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CustodyKind, SecretCustody};

    /// The conditional write swaps only while the stored envelope is the one the caller read,
    /// keeps the stored metadata, and never brings back a deleted secret.
    #[test]
    fn put_secret_if_unchanged_swaps_only_the_envelope_it_was_given() {
        let store = MemoryStore::new();
        let first = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, b"pass", b"first").unwrap();
        let metadata = permaura_core::SecretMetadata { labels: vec!["kept".into()], ..Default::default() };
        store
            .put_secret(SecretRecord { id: "sec_a".into(), sealed: first.clone(), metadata: metadata.clone() })
            .unwrap();

        let second = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, b"pass", b"second").unwrap();
        assert!(store.put_secret_if_unchanged("sec_a", &first, second.clone()).unwrap());
        let row = store.get_secret("sec_a").unwrap().unwrap();
        assert_eq!(row.sealed, second);
        assert_eq!(row.metadata, metadata, "the swap keeps the stored metadata");

        // Replaced since `first` was read: the stale write is refused and the replacement stays.
        let stale = permaura_core::seal(permaura_core::Cipher::Aes256Gcm, b"pass", b"stale").unwrap();
        assert!(!store.put_secret_if_unchanged("sec_a", &first, stale.clone()).unwrap());
        assert_eq!(store.get_secret("sec_a").unwrap().unwrap().sealed, second);

        // Removed: the stale write does not bring it back.
        assert!(store.delete_secret("sec_a").unwrap());
        assert!(!store.put_secret_if_unchanged("sec_a", &second, stale).unwrap());
        assert!(store.get_secret("sec_a").unwrap().is_none());
    }

    /// Custody is keyed by `secret_id`: writing it twice must replace, not accumulate. (The grants
    /// table in this store appends, which is why this is worth asserting rather than assuming.)
    #[test]
    fn putting_custody_twice_replaces_the_row() {
        let store = MemoryStore::new();
        store.put_secret_custody(SecretCustody::local("sec_a", 1)).unwrap();
        store
            .put_secret_custody(SecretCustody::kms("sec_a", b"ct".to_vec(), "cmk", 2))
            .unwrap();

        let all = store.list_secret_custody().unwrap();
        assert_eq!(all.len(), 1, "one row per secret_id");
        assert_eq!(all[0].kind, CustodyKind::Kms, "the later write wins");
        assert_eq!(store.get_secret_custody("sec_a").unwrap().unwrap().enrolled_at, 2);
    }

    #[test]
    fn custody_round_trips_and_deletes() {
        let store = MemoryStore::new();
        assert!(store.get_secret_custody("sec_a").unwrap().is_none());
        assert!(!store.delete_secret_custody("sec_a").unwrap());

        let custody = SecretCustody::infisical("sec_a", Some("REMOTE".into()), 5);
        store.put_secret_custody(custody.clone()).unwrap();
        assert_eq!(store.get_secret_custody("sec_a").unwrap().unwrap(), custody);

        assert!(store.delete_secret_custody("sec_a").unwrap());
        assert!(store.get_secret_custody("sec_a").unwrap().is_none());
        assert!(store.list_secret_custody().unwrap().is_empty());
    }

    #[test]
    fn meta_round_trips_and_the_later_write_wins() {
        let store = MemoryStore::new();
        assert!(store.get_meta(crate::store::APPROVAL_FLOOR_META).unwrap().is_none());

        store.put_meta(crate::store::APPROVAL_FLOOR_META, "device_signed").unwrap();
        assert_eq!(
            store.get_meta(crate::store::APPROVAL_FLOOR_META).unwrap().as_deref(),
            Some("device_signed")
        );

        store.put_meta(crate::store::APPROVAL_FLOOR_META, "approve").unwrap();
        assert_eq!(
            store.get_meta(crate::store::APPROVAL_FLOOR_META).unwrap().as_deref(),
            Some("approve"),
            "a key holds one value, not a history"
        );
    }

    /// A hold as the enforcement loop records one, with a status the test chooses.
    fn approval(id: &str, status: &str) -> PendingApproval {
        PendingApproval {
            id: id.into(),
            session_id: "sess_demo".into(),
            capability: "github.pull_requests.create".into(),
            resource: "github_acme".into(),
            message: "Approve?".into(),
            status: status.into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({ "owner": "synthetic" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: 0,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        }
    }

    /// The same rule and the same error as the SQLite store, asserted here so the two cannot drift.
    ///
    /// This store used to make room by evicting the oldest pending hold, which silently dropped a
    /// question a human had been asked. Refusing the new one keeps every hold that exists and is the
    /// only shape the SQLite store could copy, where an eviction is a write.
    #[test]
    fn a_flood_of_held_approvals_is_refused_at_the_cap() {
        let store = MemoryStore::new();
        for i in 0..crate::store::MAX_PENDING_APPROVALS {
            store.put_approval(approval(&format!("appr_{i}"), "pending")).unwrap();
        }
        let err = store
            .put_approval(approval("appr_one_too_many", "pending"))
            .expect_err("the cap must refuse");
        match err {
            GatewayError::TooManyRequests { reason, .. } => assert_eq!(reason, "approval_backlog"),
            other => panic!("the cap must refuse with the shared error: {other:?}"),
        }
        assert!(store.get_approval("appr_one_too_many").unwrap().is_none());
        assert!(
            store.get_approval("appr_0").unwrap().is_some(),
            "and the oldest hold is still there: the new one was refused, not swapped in"
        );
    }

    /// At the cap a human can still work through the queue, because resolving is an update.
    #[test]
    fn at_the_cap_an_existing_hold_can_still_be_resolved() {
        let store = MemoryStore::new();
        for i in 0..crate::store::MAX_PENDING_APPROVALS {
            store.put_approval(approval(&format!("appr_{i}"), "pending")).unwrap();
        }
        store
            .set_approval_status("appr_0", "approved")
            .expect("resolving at the cap is how the queue comes down")
            .expect("the hold is there");
        store
            .put_approval(approval("appr_next", "pending"))
            .expect("one resolved hold makes room for one new one");
    }

    /// The property the whole single-use guarantee rests on: the second presentation of a ticket is
    /// refused. If this ever returned `true` twice, a pairing ticket would be a reusable bearer.
    #[test]
    fn call_diagnostics_age_out_cap_and_purge() {
        let store = MemoryStore::new();
        let now = crate::store::now_ms();
        let d = |seq: u64, at: i64| crate::store::CallDiagnostic {
            audit_seq: seq,
            recorded_at: at,
            message: format!("failure {seq}"),
            headers: Default::default(),
        };
        store.put_call_diagnostic(d(1, now - crate::store::CALL_DIAGNOSTICS_RETENTION_MS - 1)).unwrap();
        store.put_call_diagnostic(d(2, now)).unwrap();
        assert_eq!(store.call_diagnostics(0).unwrap().iter().map(|x| x.audit_seq).collect::<Vec<_>>(), vec![2]);
        for seq in 3..(3 + crate::store::CALL_DIAGNOSTICS_MAX as u64) {
            store.put_call_diagnostic(d(seq, now)).unwrap();
        }
        let kept = store.call_diagnostics(0).unwrap();
        assert_eq!(kept.len(), crate::store::CALL_DIAGNOSTICS_MAX);
        assert_eq!(kept[0].audit_seq, 3, "the oldest seq went first");
        assert_eq!(store.purge_call_diagnostics().unwrap(), crate::store::CALL_DIAGNOSTICS_MAX as u64);
        assert!(store.call_diagnostics(0).unwrap().is_empty());
    }

    #[test]
    fn a_claim_succeeds_once_and_every_replay_is_refused() {
        let store = MemoryStore::new();
        let exp = crate::store::now_ms() + 60_000;
        assert!(store.claim_once("pair", "jti-1", exp).unwrap());
        assert!(!store.claim_once("pair", "jti-1", exp).unwrap());
        assert!(!store.claim_once("pair", "jti-1", exp).unwrap());
    }

    /// Scopes namespace unrelated token families, so two of them minting the same jti cannot spend
    /// each other's claim.
    #[test]
    fn the_same_jti_in_two_scopes_is_two_claims() {
        let store = MemoryStore::new();
        let exp = crate::store::now_ms() + 60_000;
        assert!(store.claim_once("pair", "shared-jti", exp).unwrap());
        assert!(store.claim_once("floor", "shared-jti", exp).unwrap());
        assert!(!store.claim_once("pair", "shared-jti", exp).unwrap());
    }

    /// Pruning must not resurrect a live token, only release a dead one: the claim exists to stop a
    /// replay within the token's lifetime, and past that the token is refused on its own expiry.
    #[test]
    fn a_lapsed_claim_stops_blocking_but_a_live_one_does_not() {
        let store = MemoryStore::new();
        let now = crate::store::now_ms();
        assert!(store.claim_once("pair", "expired", now - 1).unwrap());
        assert!(store.claim_once("pair", "expired", now + 60_000).unwrap(), "the lapsed row must be pruned");
        assert!(!store.claim_once("pair", "expired", now + 60_000).unwrap(), "and the fresh one must hold");
    }
}

#[cfg(test)]
mod settled_approval_tests {
    use super::*;

    fn hold(id: &str, status: &str) -> PendingApproval {
        PendingApproval {
            id: id.into(),
            session_id: "sess_demo".into(),
            capability: "github.pull_requests.create".into(),
            resource: "github_acme".into(),
            message: "Approve?".into(),
            status: status.into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({ "owner": "synthetic" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: 0,
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        }
    }

    /// The SQLite store's rule, here too so the two cannot drift: a settled approval keeps its status, through either write.
    #[test]
    fn a_settled_approval_is_never_rewritten_to_another_status() {
        let store = MemoryStore::new();
        store.put_approval(hold("appr_1", "pending")).unwrap();
        store.put_approval(hold("appr_1", "denied")).unwrap();
        assert!(store.put_approval(hold("appr_1", crate::store::APPROVAL_UNRESOLVED)).is_err());
        assert!(store.set_approval_status("appr_1", "approved").is_err());
        assert_eq!(store.get_approval("appr_1").unwrap().unwrap().status, "denied");
        store.put_approval(hold("appr_1", "denied")).expect("the settled status itself can be written again");
    }

    /// A new hold is an INSERT, refused over any row already at its id, while a write that keeps a row's status still replaces its other fields: the rule is status-only.
    #[test]
    fn a_new_hold_never_lands_on_an_existing_row() {
        let store = MemoryStore::new();
        let mut first = hold("appr_1", "pending");
        first.message = "the first question".into();
        store.insert_approval(first).unwrap();
        let mut second = hold("appr_1", "pending");
        second.message = "another question".into();
        let refused = store.insert_approval(second.clone()).expect_err("a new hold never writes over one");
        assert!(matches!(refused, GatewayError::Conflict(_)), "{refused}");
        assert_eq!(store.get_approval("appr_1").unwrap().unwrap().message, "the first question");
        store.put_approval(second).expect("an update that keeps the status replaces the other fields");
        assert_eq!(store.get_approval("appr_1").unwrap().unwrap().message, "another question");
    }
}

#[cfg(test)]
mod enrolment_code_put_tests {
    use super::*;

    /// Writing an enrolment code that is already there is refused, the memory store's half.
    #[test]
    fn putting_an_enrolment_code_that_exists_never_revives_it() {
        let store = MemoryStore::new();
        let code = |used: bool| EnrolmentCode { code: "ENRL-SYNTHETIC".into(), label: None, created_at: 0, expires_at: i64::MAX, used };
        store.put_enrolment_code(code(true)).unwrap();
        assert!(store.put_enrolment_code(code(false)).is_err(), "the code is already there");
        assert!(!store.enrolment_code_redeemable("ENRL-SYNTHETIC", 1).unwrap(), "and stays used");
    }
}
