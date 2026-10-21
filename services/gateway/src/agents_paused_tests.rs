//! `PERMAURA_AGENTS_PAUSED`, the deployment's agent pause. A hosted worker in a lapse's grace or a decommission refuses every agent bearer (stored sessions included, which no permaura.com audience change reaches) and every execution, and keeps the console and the vault export working.

use super::*;
use crate::connectors::MockHttpClient;
use crate::store::memory::MemoryStore;

fn hosted_on(store: Arc<dyn Store>) -> EnforcementService {
    let mut svc = EnforcementService::new(store, Arc::new(MockHttpClient::new()));
    svc.hosted = true;
    svc
}

fn code(store: &dyn Store, code: &str) {
    store
        .put_enrolment_code(crate::store::EnrolmentCode {
            code: code.into(),
            label: Some("ci-bot".into()),
            created_at: 0,
            expires_at: i64::MAX,
            used: false,
        })
        .unwrap();
}

fn refused_as_paused<T>(result: Result<T, GatewayError>) {
    match result {
        Err(GatewayError::Denied(message)) => assert_eq!(message, AGENTS_PAUSED_MESSAGE),
        Err(other) => panic!("expected the agent pause, got {other:?}"),
        Ok(_) => panic!("expected the agent pause, and the call went through"),
    }
}

/// An approved agent that enrolled with a code holds a stored session the worker resolves itself.
#[test]
fn a_code_enrolled_approved_agent_is_refused_while_agents_are_paused() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let svc = hosted_on(store.clone());
    let bearer = "pgc_ENRL-AAAA-BBBB-CCCC-DDDD";
    code(store.as_ref(), bearer);
    let session = svc.authenticate(bearer).expect("the code redeems and becomes the agent's bearer");
    let mut agent = store.get_agent(&session.agent_id).unwrap().unwrap();
    agent.status = AgentStatus::Approved;
    store.put_agent(agent).unwrap();

    // What stage one's PERMAURA_REQUIRE_AGENT_APPROVAL does alone, which reaches no agent it has already seen.
    svc.require_agent_approval_for_this_run();
    assert!(svc.authenticate(bearer).is_ok(), "the new-agent gate alone does not cut a stored session");

    // Last used long ago, so a call that got through would slide the expiry.
    let mut row = store.get_session(&session.id).unwrap().unwrap();
    row.last_used_at = Some(1);
    store.put_session(row).unwrap();
    let expiry_before = store.get_session(&session.id).unwrap().unwrap().expires_at;
    svc.pause_agents_for_this_run();
    refused_as_paused(svc.authenticate(bearer));
    assert_eq!(
        store.get_session(&session.id).unwrap().unwrap().expires_at,
        expiry_before,
        "a refused call does not slide the session's expiry"
    );
}

#[test]
fn a_code_is_not_redeemed_while_agents_are_paused_and_still_works_after() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let paused = hosted_on(store.clone());
    paused.pause_agents_for_this_run();
    let bearer = "pgc_ENRL-EEEE-FFFF-GGGG-HHHH";
    code(store.as_ref(), bearer);

    // The agent behind an unredeemed code is not enrolled yet, so it is told no agent can be enrolled, not that it resumes still enrolled.
    match paused.authenticate(bearer) {
        Err(GatewayError::Denied(message)) => assert_eq!(message, AGENTS_PAUSED_ENROLMENT_MESSAGE),
        other => panic!("expected the enrolment refusal, got {other:?}"),
    }
    assert!(store.enrolment_code_redeemable(bearer, now_ms()).unwrap(), "the code is not redeemed");
    assert!(store.list_agents().unwrap().is_empty(), "no agent was created");
    assert_eq!(
        paused.authenticate("not-a-code").unwrap_err().to_string(),
        "unauthorized: unknown or missing session token",
        "a stranger's junk is told nothing about the pause"
    );

    // A cold start with the pause lifted.
    let resumed = hosted_on(store.clone());
    assert_eq!(resumed.authenticate(bearer).expect("redeems").role, SessionRole::Agent);
}

#[test]
fn an_oauth_agent_is_refused_and_not_registered_while_agents_are_paused() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let svc = hosted_on(store.clone());
    let claims = |azp: &str| crate::oauth::VerifiedClaims {
        sub: "operator-1".into(),
        azp: Some(azp.into()),
        name: Some(azp.into()),
        scope: Some("openid mcp offline_access".into()),
        actor: None,
    };
    svc.session_from_jwt(claims("client-claude")).expect("an agent the AS consented to connects");

    svc.pause_agents_for_this_run();
    refused_as_paused(svc.session_from_jwt(claims("client-claude")));
    refused_as_paused(svc.session_from_jwt(claims("client-cursor")));
    assert_eq!(store.list_agents().unwrap().len(), 1, "the new client was not registered");
}

#[tokio::test]
async fn the_operator_keeps_the_console_while_every_execution_is_refused() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    crate::seed::seed(store.as_ref()).unwrap();
    let svc = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()));
    let operator = svc.authenticate(crate::seed::DEMO_TOKEN).unwrap();
    let params = serde_json::json!({ "owner": "synthetic", "repo": "synthetic" });
    let held = svc
        .invoke(&operator, "github.pull_requests.create", &params, Some("synthetic"), ExecutionLocation::LocalOnly)
        .await
        .unwrap();
    let InvokeOutcome::RequiresApproval { approval, .. } = held else { panic!("a High-risk call holds") };

    svc.pause_agents_for_this_run();
    let operator = svc.authenticate(crate::seed::DEMO_TOKEN).expect("the operator still signs in");
    let audit_before = store.audit_len().unwrap();
    refused_as_paused(
        svc.invoke(&operator, "github.pull_requests.create", &params, Some("synthetic"), ExecutionLocation::LocalOnly)
            .await,
    );
    assert_eq!(store.audit_len().unwrap(), audit_before, "a paused refusal writes nothing");

    refused_as_paused(svc.resolve_approval(&approval.id, true, "bearer", Some("operator")).await);
    assert_eq!(store.get_approval(&approval.id).unwrap().unwrap().status, "pending", "nothing was claimed");
    let denied = svc.resolve_approval(&approval.id, false, "bearer", Some("operator")).await.unwrap();
    assert_eq!(denied.status, "denied", "a denial runs nothing and still clears the call");
}

/// A token that was never an agent's is told why it cannot act as one, not that agents are paused.
#[test]
fn an_identity_only_token_on_a_paused_worker_gets_the_scope_denial() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let svc = hosted_on(store.clone());
    svc.pause_agents_for_this_run();
    let claims = crate::oauth::VerifiedClaims {
        sub: "operator-1".into(),
        azp: Some("client-sign-in".into()),
        name: None,
        scope: Some("openid profile".into()),
        actor: None,
    };
    match svc.session_from_jwt(claims) {
        Err(GatewayError::Denied(message)) => {
            assert!(message.starts_with("this token cannot act as an agent"), "{message}");
        }
        other => panic!("expected the `mcp` scope denial, got {other:?}"),
    }
    assert!(store.list_agents().unwrap().is_empty(), "nothing was registered");
}

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

fn approved_code_agent(svc: &EnforcementService, store: &dyn Store, bearer: &str) -> Session {
    code(store, bearer);
    let session = svc.authenticate(bearer).expect("the code redeems and becomes the agent's bearer");
    let mut agent = store.get_agent(&session.agent_id).unwrap().unwrap();
    agent.status = AgentStatus::Approved;
    store.put_agent(agent).unwrap();
    session
}

fn last_used(store: &dyn Store, id: &str, at: i64) {
    let mut row = store.get_session(id).unwrap().unwrap();
    row.last_used_at = Some(at);
    row.expires_at = Some(at + crate::store::AGENT_SESSION_TTL_MS);
    store.put_session(row).unwrap();
}

/// refute:pause:1. A paid lapse's grace runs to the period end plus 30 days and a restore can land in the export window after it, so a pause outlives the 30-day sliding expiry of every agent that was not used during it, which is all of them.
#[test]
fn an_agent_paused_for_longer_than_its_session_ttl_works_again_when_the_plan_is_restored() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let running = hosted_on(store.clone());
    let session = approved_code_agent(&running, store.as_ref(), "pgc_ENRL-JJJJ-KKKK-LLLL-MMMM");
    let now = now_ms();
    // Used a day before the worker paused 40 days ago: its expiry passed 11 days ago, past the week after which a dead row is deleted.
    last_used(store.as_ref(), &session.id, now - 41 * DAY_MS);
    store.put_meta(crate::store::AGENTS_PAUSED_SINCE_META, &(now - 40 * DAY_MS).to_string()).unwrap();

    let paused = hosted_on(store.clone());
    paused.pause_agents_for_this_run();
    paused.settle_agent_session_clock_at_start().unwrap();
    assert_eq!(
        crate::store::agents_paused_since(store.as_ref()).unwrap(),
        Some(now - 40 * DAY_MS),
        "a later paused boot keeps when the pause began"
    );
    refused_as_paused(paused.authenticate("pgc_ENRL-JJJJ-KKKK-LLLL-MMMM"));
    crate::prune_dead_sessions(store.as_ref(), true);
    crate::sweep_idle_agent_sessions(store.as_ref(), true);
    assert!(
        store.get_session(&session.id).unwrap().is_some_and(|row| !row.revoked),
        "nothing deletes or retires a session for going unused while agents are paused"
    );

    let resumed = hosted_on(store.clone());
    resumed.settle_agent_session_clock_at_start().unwrap();
    let back = resumed.authenticate("pgc_ENRL-JJJJ-KKKK-LLLL-MMMM").expect("the agent works again with the bearer it enrolled with");
    assert_eq!(back.id, session.id);
    let expiry = store.get_session(&session.id).unwrap().unwrap().expires_at.unwrap();
    assert!(expiry >= now + crate::store::AGENT_SESSION_TTL_MS - 60_000, "a call after the pause slides the expiry as before");
    assert_eq!(crate::store::agents_paused_since(store.as_ref()).unwrap(), None, "the pause is settled once");
}

/// The clock is moved by the pause and no further: a session that had run out before agents were paused stays expired, and one with time left keeps exactly that time.
#[test]
fn the_resume_moves_each_session_by_the_pause_and_revives_none_that_had_run_out_before_it() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let running = hosted_on(store.clone());
    let stale = approved_code_agent(&running, store.as_ref(), "pgc_ENRL-NNNN-PPPP-QQQQ-RRRR");
    let live = approved_code_agent(&running, store.as_ref(), "pgc_ENRL-SSSS-TTTT-UUUU-VVVV");
    let now = now_ms();
    let since = now - 31 * DAY_MS;
    last_used(store.as_ref(), &stale.id, since - 31 * DAY_MS);
    last_used(store.as_ref(), &live.id, since - 10 * DAY_MS);
    store.put_meta(crate::store::AGENTS_PAUSED_SINCE_META, &since.to_string()).unwrap();

    let paused = hosted_on(store.clone());
    paused.pause_agents_for_this_run();
    assert_eq!(
        paused.authenticate("pgc_ENRL-NNNN-PPPP-QQQQ-RRRR").unwrap_err().to_string(),
        "unauthorized: session has expired",
        "a session that ran out before the pause is told so, not that agents are paused"
    );

    let resumed = hosted_on(store.clone());
    assert_eq!(resumed.settle_agent_session_clock_at_start().unwrap(), 1);
    let moved = store.get_session(&live.id).unwrap().unwrap().expires_at.unwrap();
    let span = moved - (since - 10 * DAY_MS + crate::store::AGENT_SESSION_TTL_MS);
    assert!((now - since..now - since + 60_000).contains(&span), "moved by the paused span, {span} ms");
    assert!(resumed.authenticate("pgc_ENRL-SSSS-TTTT-UUUU-VVVV").is_ok());
    assert_eq!(resumed.authenticate("pgc_ENRL-NNNN-PPPP-QQQQ-RRRR").unwrap_err().to_string(), "unauthorized: session has expired");
    assert_eq!(resumed.settle_agent_session_clock_at_start().unwrap(), 0, "a second boot moves nothing");
}

/// The first paused boot records the pause, so a worker that is paused and resumed without anything else marking it still has a span to settle.
#[test]
fn a_paused_boot_records_when_the_pause_began() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let paused = hosted_on(store.clone());
    paused.pause_agents_for_this_run();
    let before = now_ms();
    paused.settle_agent_session_clock_at_start().unwrap();
    let since = crate::store::agents_paused_since(store.as_ref()).unwrap().expect("recorded");
    assert!(since >= before && since <= now_ms());
}

fn legacy_idle_agent(store: &dyn Store, id: &str, token: &str) {
    store
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: id.into(),
            agent_id: "agent-legacy".into(),
            user_id: None,
            device_id: None,
            token: token.into(),
            role: SessionRole::Agent,
            created_at: now_ms() - crate::store::AGENT_SESSION_TTL_MS - DAY_MS,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
}

/// The paused boot's record of the pause is best-effort, so the maintenance pass reads the run's own pause too: nothing ages out or is deleted while agents are paused, and the missing record is written then.
#[test]
fn the_maintenance_pass_keeps_every_agent_session_on_a_paused_run_that_could_not_record_the_pause() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let running = hosted_on(store.clone());
    let session = approved_code_agent(&running, store.as_ref(), "pgc_ENRL-WWWW-XXXX-YYYY-ZZZZ");
    let now = now_ms();
    // Live when agents were paused, and run out eight days ago during the pause: past the week after which a dead row is deleted.
    last_used(store.as_ref(), &session.id, now - 8 * DAY_MS - crate::store::AGENT_SESSION_TTL_MS);
    legacy_idle_agent(store.as_ref(), "sess-legacy", "tok-legacy");

    let paused = hosted_on(store.clone());
    paused.pause_agents_for_this_run();
    assert_eq!(crate::store::agents_paused_since(store.as_ref()).unwrap(), None, "the boot's record of the pause failed");
    crate::maintain_agent_sessions(&paused);

    assert!(store.get_session(&session.id).unwrap().is_some(), "a session that ran out during the pause is not deleted");
    assert!(!store.get_session("sess-legacy").unwrap().unwrap().revoked, "a legacy row is not retired for going unused during the pause");
    assert!(crate::store::agents_paused_since(store.as_ref()).unwrap().is_some(), "the pass records the pause the boot could not");
}

/// A resume boot that could not settle the clock leaves the pause recorded, and the maintenance pass settles it rather than waiting for a boot that may be days away on an always-on worker.
#[test]
fn the_maintenance_pass_settles_a_resume_the_boot_could_not() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let running = hosted_on(store.clone());
    let session = approved_code_agent(&running, store.as_ref(), "pgc_ENRL-ABAB-CDCD-EFEF-GHGH");
    let now = now_ms();
    let since = now - 40 * DAY_MS;
    last_used(store.as_ref(), &session.id, since - DAY_MS);
    store.put_meta(crate::store::AGENTS_PAUSED_SINCE_META, &since.to_string()).unwrap();

    let resumed = hosted_on(store.clone());
    assert_eq!(
        resumed.authenticate("pgc_ENRL-ABAB-CDCD-EFEF-GHGH").unwrap_err().to_string(),
        "unauthorized: session has expired",
        "with the settle not run, the agent reads as expired"
    );
    crate::maintain_agent_sessions(&resumed);
    assert!(resumed.authenticate("pgc_ENRL-ABAB-CDCD-EFEF-GHGH").is_ok(), "the pass settled the clock and the agent works again");
    assert_eq!(crate::store::agents_paused_since(store.as_ref()).unwrap(), None);
}

/// Admission control counts a session the pause holds as live, so it reaches the pause refusal in its own bucket instead of the unauthenticated one every stranger's junk shares.
#[test]
fn a_session_the_pause_holds_is_a_live_bearer_for_admission_control() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let running = hosted_on(store.clone());
    let held = approved_code_agent(&running, store.as_ref(), "pgc_ENRL-HOLD-HOLD-HOLD-HOLD");
    let dead = approved_code_agent(&running, store.as_ref(), "pgc_ENRL-DEAD-DEAD-DEAD-DEAD");
    let now = now_ms();
    let since = now - 40 * DAY_MS;
    last_used(store.as_ref(), &held.id, since - DAY_MS);
    last_used(store.as_ref(), &dead.id, since - 31 * DAY_MS);
    store.put_meta(crate::store::AGENTS_PAUSED_SINCE_META, &since.to_string()).unwrap();

    let paused = hosted_on(store.clone());
    paused.pause_agents_for_this_run();
    assert!(paused.bearer_is_live("pgc_ENRL-HOLD-HOLD-HOLD-HOLD"), "held by the pause");
    refused_as_paused(paused.authenticate("pgc_ENRL-HOLD-HOLD-HOLD-HOLD"));
    assert!(!paused.bearer_is_live("pgc_ENRL-DEAD-DEAD-DEAD-DEAD"), "a session that ran out before the pause is not");
}
