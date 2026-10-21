//! The new-agent gate is on by default once a device is paired on a gateway reachable from off the host (a hosted worker, or a self-run gateway with a public URL). With no device it stays off, and an operator's stored choice always wins.

use super::*;
use crate::connectors::MockHttpClient;
use crate::policy_guard::Mutation;
use crate::store::memory::MemoryStore;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

const FLIP: &str = "permaura.agent_gate.default";

fn hosted() -> EnforcementService {
    hosted_on(Arc::new(MemoryStore::new()))
}

fn hosted_on(store: Arc<dyn Store>) -> EnforcementService {
    let mut svc = EnforcementService::new(store, Arc::new(MockHttpClient::new()));
    svc.keyring_persistence = KeyringPersistence::Store;
    svc.hosted = true;
    svc.refresh_keyring_now();
    svc
}

fn public_self_run() -> EnforcementService {
    let oauth = Arc::new(crate::oauth::OAuthRs::new(crate::oauth::RsConfig {
        public_url: "https://g-gate.permaura.test".into(),
        mcp_resource: "https://g-gate.permaura.test/mcp".into(),
        public_url_aliases: Vec::new(),
        issuer: "https://permaura.test".into(),
        jwks_uri: "https://permaura.test/api/auth/jwks".into(),
        owner_sub: Some("operator-1".into()),
    }));
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let backend: Arc<dyn SecretBackend> = Arc::new(LocalVaultBackend::new(store.clone(), vault_passphrase().to_vec()));
    EnforcementService::from_components(
        store,
        Arc::new(MockHttpClient::new()),
        Arc::new(crate::connectors::MockCommandRunner::new()),
        backend,
        Some(oauth),
    )
}

fn loopback_self_run() -> EnforcementService {
    EnforcementService::new(Arc::new(MemoryStore::new()), Arc::new(MockHttpClient::new()))
}

fn pubkey(seed: u8) -> String {
    STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes())
}

/// Through the one writer every pairing reaches, so the flip is exercised where it happens.
fn pair(svc: &EnforcementService, approver_id: &str, seed: u8) {
    let m = Mutation::ApproverKeyTrust {
        approver_id: approver_id.into(),
        approver_pubkey: pubkey(seed),
        person: None,
        replaces: None,
    };
    crate::rest::apply_mutation_as(svc.store().as_ref(), svc, &m, "test_owner", serde_json::Map::new())
        .expect("the device is trusted");
}

fn revoke(svc: &EnforcementService, approver_id: &str) {
    let m = Mutation::ApproverKeyRevoke { approver_id: approver_id.into() };
    crate::rest::apply_mutation_as(svc.store().as_ref(), svc, &m, "test_owner", serde_json::Map::new())
        .expect("the device is revoked");
}

fn connect(svc: &EnforcementService, azp: &str) -> AgentStatus {
    let claims = crate::oauth::VerifiedClaims {
        sub: "operator-1".into(),
        azp: Some(azp.into()),
        name: Some(azp.into()),
        scope: Some("openid mcp offline_access".into()),
        actor: None,
    };
    let session = svc.session_from_jwt(claims).expect("the client connects");
    svc.store().get_agent(&session.agent_id).unwrap().expect("the agent is registered").status
}

fn flips(svc: &EnforcementService) -> Vec<serde_json::Value> {
    svc.store()
        .audit_events(None)
        .unwrap()
        .into_iter()
        .filter(|e| e.payload.action == FLIP)
        .map(|e| e.payload.summary)
        .collect()
}

#[test]
fn a_hosted_worker_with_no_device_keeps_the_gate_off() {
    let svc = hosted();
    assert!(!svc.require_agent_approval(), "nothing could hold an approval yet, so nothing changes");
    assert_eq!(connect(&svc, "client-early"), AgentStatus::Approved);
}

#[test]
fn the_first_device_on_a_hosted_worker_turns_the_gate_on_and_records_why() {
    let svc = hosted();
    assert_eq!(connect(&svc, "client-early"), AgentStatus::Approved);

    pair(&svc, "device:alpha", 31);
    assert!(svc.require_agent_approval(), "a paired device is now the gate");
    let recorded = flips(&svc);
    assert_eq!(recorded.len(), 1, "the flip is in the audit chain: {recorded:?}");
    assert_eq!(recorded[0]["from"], false);
    assert_eq!(recorded[0]["to"], true);
    assert_eq!(recorded[0]["authority"], "test_owner");

    assert_eq!(connect(&svc, "client-late"), AgentStatus::Pending, "a new agent now waits for a decision");
    assert_eq!(connect(&svc, "client-early"), AgentStatus::Approved, "an agent approved before is unaffected");

    pair(&svc, "device:beta", 32);
    assert_eq!(flips(&svc).len(), 1, "a second device changes nothing, so it records nothing");
}

#[test]
fn a_self_run_gateway_with_a_public_url_turns_the_gate_on_at_its_first_device() {
    let svc = public_self_run();
    assert!(!svc.require_agent_approval());
    pair(&svc, "device:alpha", 33);
    assert!(svc.require_agent_approval());
    assert_eq!(flips(&svc).len(), 1);
    assert_eq!(connect(&svc, "client-late"), AgentStatus::Pending);
}

#[test]
fn a_loopback_only_self_run_gateway_keeps_the_gate_off_with_a_device() {
    let svc = loopback_self_run();
    pair(&svc, "device:alpha", 34);
    assert!(!svc.require_agent_approval(), "no OAuth client can reach a gateway with no public URL");
    assert!(flips(&svc).is_empty());
    assert_eq!(connect(&svc, "client-late"), AgentStatus::Approved);
}

/// A `false` stored before any device was trusted was confirmed by nobody a device holder controls, so the first device returns the gate to its default (the rule the approval floor follows).
#[test]
fn a_false_stored_before_any_device_is_cleared_by_the_first_pairing() {
    let svc = hosted();
    svc.set_require_agent_approval(false).unwrap();
    assert!(!svc.require_agent_approval());
    pair(&svc, "device:alpha", 35);
    assert!(svc.require_agent_approval(), "the unanchored choice does not outlive the first device");
    assert_ne!(
        svc.store().get_meta(BROKER_REQUIRE_AGENT_APPROVAL_META).unwrap().as_deref(),
        Some("false"),
        "the stored row is cleared back to the default"
    );
    let recorded = flips(&svc);
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(recorded[0]["from"], false);
    assert_eq!(recorded[0]["to"], true);
    assert_eq!(recorded[0]["cleared_stored_choice"], true, "{recorded:?}");
    assert!(recorded[0]["reason"].as_str().unwrap().contains("before any device"), "{recorded:?}");
    assert_eq!(connect(&svc, "client-late"), AgentStatus::Pending);
}

/// The mark is a store row, so another instance or the next process clears it just the same.
#[test]
fn the_unanchored_mark_survives_a_restart() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    hosted_on(store.clone()).set_require_agent_approval(false).unwrap();
    let next = hosted_on(store);
    assert!(!next.require_agent_approval());
    pair(&next, "device:alpha", 38);
    assert!(next.require_agent_approval());
}

/// A `false` the operator stored while a device was already trusted is theirs, and outlives later pairings, the first one after an emptied keyring included.
#[test]
fn a_false_stored_while_a_device_was_trusted_survives_later_pairings() {
    let svc = hosted();
    pair(&svc, "device:alpha", 39);
    svc.set_require_agent_approval(false).unwrap();
    pair(&svc, "device:beta", 40);
    assert!(!svc.require_agent_approval());
    revoke(&svc, "device:alpha");
    revoke(&svc, "device:beta");
    pair(&svc, "device:gamma", 41);
    assert!(!svc.require_agent_approval(), "the anchored choice survives a new first device");
    assert_eq!(flips(&svc).len(), 1, "only the first pairing's flip, before the operator chose");
    assert_eq!(connect(&svc, "client-late"), AgentStatus::Approved);
}

#[test]
fn a_true_stored_before_pairing_survives() {
    let svc = hosted();
    svc.set_require_agent_approval(true).unwrap();
    pair(&svc, "device:alpha", 42);
    assert!(svc.require_agent_approval());
    assert_eq!(
        svc.store().get_meta(BROKER_REQUIRE_AGENT_APPROVAL_META).unwrap().as_deref(),
        Some("true"),
        "a stored true is never touched"
    );
    assert!(flips(&svc).is_empty());
}

/// A gateway no OAuth client can reach has nothing for the gate to hold, so its stored choice is left as it is.
#[test]
fn a_loopback_only_gateway_keeps_its_stored_false() {
    let svc = loopback_self_run();
    svc.set_require_agent_approval(false).unwrap();
    pair(&svc, "device:alpha", 43);
    assert_eq!(
        svc.store().get_meta(BROKER_REQUIRE_AGENT_APPROVAL_META).unwrap().as_deref(),
        Some("false")
    );
    assert!(flips(&svc).is_empty());
}

#[test]
fn an_operators_stored_true_survives_emptying_the_keyring() {
    let svc = hosted();
    svc.set_require_agent_approval(true).unwrap();
    pair(&svc, "device:alpha", 36);
    revoke(&svc, "device:alpha");
    assert!(svc.require_agent_approval());
    assert!(flips(&svc).is_empty());
}

#[test]
fn emptying_the_keyring_returns_the_default_gate_to_off_and_records_it() {
    let svc = hosted();
    pair(&svc, "device:alpha", 37);
    revoke(&svc, "device:alpha");
    assert!(!svc.require_agent_approval(), "with no device the default is off again");
    let recorded = flips(&svc);
    assert_eq!(recorded.len(), 2, "{recorded:?}");
    assert_eq!(recorded[1]["from"], true);
    assert_eq!(recorded[1]["to"], false);
}

/// A gateway already paired when it upgrades to a build where the gate defaults on starts holding new agents at that boot. The chain says why, once.
#[test]
fn an_upgrade_that_turns_the_gate_on_for_a_paired_gateway_is_recorded_at_boot_once() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let before = hosted_on(store.clone());
    assert!(before.trust_approver_key_durable("device:alpha", &pubkey(43)).unwrap(), "paired under the previous build, which recorded no flip");
    assert!(store.get_meta(BROKER_REQUIRE_AGENT_APPROVAL_META).unwrap().is_none(), "no stored choice");
    assert!(flips(&before).is_empty());

    let upgraded = hosted_on(store.clone());
    assert!(upgraded.require_agent_approval(), "the default is on at this boot");
    assert!(upgraded.record_agent_gate_default_at_start().unwrap());
    let recorded = flips(&upgraded);
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(recorded[0]["from"], false);
    assert_eq!(recorded[0]["to"], true);
    assert_eq!(recorded[0]["authority"], "upgrade", "{recorded:?}");
    assert!(recorded[0]["reason"].as_str().unwrap().contains("upgrade"), "{recorded:?}");

    let restarted = hosted_on(store);
    assert!(!restarted.record_agent_gate_default_at_start().unwrap(), "nothing changed since the row");
    assert_eq!(flips(&restarted).len(), 1);
}

/// A flip the pairing itself recorded is not recorded again by the next boot, and a gateway whose default stays off records nothing.
#[test]
fn a_flip_already_recorded_or_a_gate_that_stays_off_writes_nothing_at_boot() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    pair(&hosted_on(store.clone()), "device:alpha", 44);
    let next = hosted_on(store);
    assert!(!next.record_agent_gate_default_at_start().unwrap());
    assert_eq!(flips(&next).len(), 1, "only the pairing's own row");

    let unpaired = hosted();
    assert!(!unpaired.record_agent_gate_default_at_start().unwrap());
    let loopback = loopback_self_run();
    assert!(loopback.trust_approver_key_durable("device:alpha", &pubkey(45)).unwrap());
    assert!(!loopback.record_agent_gate_default_at_start().unwrap());
    assert!(flips(&unpaired).is_empty() && flips(&loopback).is_empty());
}

/// An operator's stored choice is theirs: the boot records nothing over it.
#[test]
fn a_stored_choice_is_not_recorded_as_a_default_at_boot() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let before = hosted_on(store.clone());
    assert!(before.trust_approver_key_durable("device:alpha", &pubkey(46)).unwrap());
    before.set_require_agent_approval(false).unwrap();
    let next = hosted_on(store);
    assert!(!next.record_agent_gate_default_at_start().unwrap());
    assert!(flips(&next).is_empty());
}
