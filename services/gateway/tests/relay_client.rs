//! Worker dial-out client tests: the handshake (worker side) and the local-invoke path,
//! driven over an in-memory transport with a mock hub.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use tokio::sync::mpsc;

use permaura_core::{ExecutionLocation, Principal};
use permaura_gateway::relay::approver::ApproverKeyring;
use permaura_gateway::relay::{
    handle_approval_result, handle_invoke, run_worker_handshake, WorkerConfig,
};
use permaura_gateway::store::{PendingApproval, Session, SessionRole};
use permaura_gateway::AppState;
use permaura_relay::{
    approval_result_preimage, hello_preimage, request_hash, sign, verify, ApprovalResult, AuthAck,
    Challenge, CloseCode, Envelope, Frame, InvokeOrigin, InvokeRequest, ProtocolVersion, RelayError,
    RelayOutcome, RelayTransport, SessionCtx,
};

mod common;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Seed a held approval for an existing seeded capability and return (state, params, request_hash).
fn seed_held_approval(state: &AppState, approval_id: &str) -> (serde_json::Value, String) {
    let session = Session {
        class: Default::default(),
        opened_by: None,
        id: "sess_appr".into(),
        agent_id: "codex-cli".into(),
        user_id: Some("sam".into()),
        device_id: None,
        token: String::new(),
        role: SessionRole::Operator,
        created_at: now_ms(),
        revoked: false,
        expires_at: None,
        last_used_at: None,
        actor: None,
    };
    state.service.store().put_session(session).unwrap();
    let params = serde_json::json!({ "status": "failed" });
    let cap = "braintree.transactions.search";
    state
        .service
        .store()
        .put_approval(PendingApproval {
            id: approval_id.into(),
            session_id: "sess_appr".into(),
            capability: cap.into(),
            resource: "braintree_production".into(),
            message: "Approve the held call?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: params.clone().into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: now_ms(),
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
    (params.clone(), request_hash(cap, &params))
}

/// A device keypair enrolled under `approver`, plus a signed ApprovalResult for the held call.
fn signed_approval(
    seed: u8,
    approver: &str,
    job_id: &str,
    approval_id: &str,
    approve: bool,
    request_hash: &str,
) -> (ApproverKeyring, ApprovalResult) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    let mut keyring = ApproverKeyring::new();
    keyring.add(approver, pubkey);
    let decided_at = now_ms();
    let preimage = approval_result_preimage(job_id, approval_id, approve, request_hash, approver, decided_at);
    let device_sig = sign(&sk, &preimage);
    let result = ApprovalResult {
        job_id: job_id.into(),
        approval_id: approval_id.into(),
        approve,
        request_hash: request_hash.into(),
        approver: approver.into(),
        decided_at,
        approver_pubkey: Some(STANDARD.encode(sk.verifying_key().to_bytes())),
        audience: None,
        display_digest: None,
        device_sig,
    };
    (keyring, result)
}

#[tokio::test]
async fn a_valid_device_signed_approval_runs_the_held_call() {
    let state = common::seeded_accepting_legacy_signatures();
    let (_params, req_hash) = seed_held_approval(&state, "appr_ok");
    let (keyring, ar) = signed_approval(42, "device:phone", "job_ok", "appr_ok", true, &req_hash);

    let terminal = handle_approval_result(&state.service, &keyring, ar).await;
    assert!(
        matches!(terminal.as_ref().map(|t| &t.outcome), Some(RelayOutcome::Allowed { .. })),
        "a valid device-signed approval should run the held call: {terminal:?}"
    );
    assert_eq!(terminal.unwrap().job_id, "job_ok");
}

/// A relayed approval the gateway refuses before its claim (here the JSON pool has no room within its wait) leaves the approval pending, so its job stays open instead of ending as a denial, and a later delivery runs the call.
#[tokio::test]
async fn a_relayed_approval_refused_before_its_claim_leaves_the_job_open() {
    use permaura_gateway::limits::LimitsConfig;
    use permaura_gateway::memory::MemoryBudget;
    use std::sync::Arc;
    use std::time::Duration;
    common::isolate_from_the_real_install();
    let store: Arc<dyn permaura_gateway::store::Store> = Arc::new(permaura_gateway::store::memory::MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let config = LimitsConfig { json_pool_wait: Duration::from_millis(50), ..LimitsConfig::defaults_for(true) };
    let service = permaura_gateway::service::EnforcementService::new(store, Arc::new(permaura_gateway::connectors::MockHttpClient::new()))
        .with_memory_budget(MemoryBudget::from_config(&config));
    let state = AppState::new(service);
    state.service.set_accept_v1_device_signatures(true);
    state.service.set_require_display_bound_approvals(false);
    let (_params, req_hash) = seed_held_approval(&state, "appr_busy");

    let pool = state.service.memory().pool().clone();
    let full = pool.reserve(pool.max_bytes(), Duration::ZERO).await.unwrap();
    let (keyring, ar) = signed_approval(43, "device:phone", "job_busy", "appr_busy", true, &req_hash);
    assert!(handle_approval_result(&state.service, &keyring, ar).await.is_none(), "no terminal outcome while the call can still run");
    assert_eq!(state.service.store().get_approval("appr_busy").unwrap().unwrap().status, "pending");

    drop(full);
    let (keyring, ar) = signed_approval(43, "device:phone", "job_busy", "appr_busy", true, &req_hash);
    let terminal = handle_approval_result(&state.service, &keyring, ar).await;
    assert!(matches!(terminal.as_ref().map(|t| &t.outcome), Some(RelayOutcome::Allowed { .. })), "{terminal:?}");
}

/// A relayed approval refused at a claim already spent ends its job, though the row still reads pending: nothing can resolve the approval again, so an open job would wait for a call that never runs. A claim is spent and the row left pending when an approval's resolution failed past its claim and its settlement was not written.
#[tokio::test]
async fn a_relayed_approval_whose_claim_is_spent_ends_its_job() {
    common::isolate_from_the_real_install();
    let state = AppState::in_memory_seeded();
    state.service.set_accept_v1_device_signatures(true);
    state.service.set_require_display_bound_approvals(false);
    let (_params, req_hash) = seed_held_approval(&state, "appr_spent");
    assert!(state.service.store().claim_once("approval-resolution", "appr_spent", i64::MAX).unwrap());

    let (keyring, ar) = signed_approval(44, "device:phone", "job_spent", "appr_spent", true, &req_hash);
    let terminal = handle_approval_result(&state.service, &keyring, ar).await;
    assert_eq!(state.service.store().get_approval("appr_spent").unwrap().unwrap().status, "pending");
    assert!(matches!(terminal.as_ref().map(|t| &t.outcome), Some(RelayOutcome::Denied { .. })), "{terminal:?}");
}

#[tokio::test]
async fn an_approval_from_an_unenrolled_device_is_refused() {
    let state = common::seeded_accepting_legacy_signatures();
    let (_p, req_hash) = seed_held_approval(&state, "appr_x");
    // The signature is valid, but the approver is NOT in the worker's keyring → refuse.
    let (_keyring_with_phone, ar) = signed_approval(7, "device:rogue", "job_x", "appr_x", true, &req_hash);
    let empty = ApproverKeyring::new();
    assert!(handle_approval_result(&state.service, &empty, ar).await.is_none());
}

#[tokio::test]
async fn a_forged_signature_is_refused_even_for_an_enrolled_approver() {
    let state = common::seeded_accepting_legacy_signatures();
    let (_p, req_hash) = seed_held_approval(&state, "appr_f");
    let (keyring, mut ar) = signed_approval(8, "device:phone", "job_f", "appr_f", true, &req_hash);
    ar.device_sig = STANDARD.encode([0u8; 64]); // garbage signature
    assert!(handle_approval_result(&state.service, &keyring, ar).await.is_none());
}

#[tokio::test]
async fn a_self_approval_by_the_requester_is_refused() {
    let state = common::seeded_accepting_legacy_signatures();
    let (_p, req_hash) = seed_held_approval(&state, "appr_self");
    // seed_held_approval's session is user "sam", so an approval signed as user:sam is the
    // requester approving its own call, even though the signature itself is valid.
    let (keyring, ar) = signed_approval(11, "user:sam", "job_self", "appr_self", true, &req_hash);
    assert!(
        handle_approval_result(&state.service, &keyring, ar).await.is_none(),
        "the requesting principal must not be able to approve its own held call"
    );
}

#[tokio::test]
async fn an_approval_redirected_onto_a_different_call_is_refused() {
    let state = common::seeded_accepting_legacy_signatures();
    let (_p, _req_hash) = seed_held_approval(&state, "appr_r");
    // Sign over a DIFFERENT request_hash than the held call's → request_hash mismatch.
    let (keyring, ar) = signed_approval(9, "device:phone", "job_r", "appr_r", true, "hash_of_another_call");
    assert!(handle_approval_result(&state.service, &keyring, ar).await.is_none());
}

#[tokio::test]
async fn a_stale_but_validly_signed_decision_is_refused() {
    let state = common::seeded_accepting_legacy_signatures();
    let (_p, req_hash) = seed_held_approval(&state, "appr_stale");
    let (keyring, mut ar) = signed_approval(21, "device:phone", "job_s", "appr_stale", true, &req_hash);
    // Re-sign over a decided_at far in the past: the signature is valid but the decision is stale, so
    // the freshness gate must refuse it (bounds late replay of a captured, still-pending decision).
    let stale = now_ms() - 30 * 60 * 1000;
    let sk = SigningKey::from_bytes(&[21u8; 32]);
    let pre = approval_result_preimage("job_s", "appr_stale", true, &req_hash, "device:phone", stale);
    ar.decided_at = stale;
    ar.device_sig = sign(&sk, &pre);
    assert!(
        handle_approval_result(&state.service, &keyring, ar).await.is_none(),
        "a validly-signed but stale decision must be refused"
    );
}

#[tokio::test]
async fn a_key_paired_into_the_service_keyring_verifies_on_the_shared_path() {
    let state = common::seeded_accepting_legacy_signatures();
    let (_p, req_hash) = seed_held_approval(&state, "appr_paired");
    let sk = SigningKey::from_bytes(&[33u8; 32]);
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    // Trust the key through the service, exactly as the worker-local pairing endpoint does.
    assert!(state.service.trust_approver_key("device:paired", &pubkey));
    let decided_at = now_ms();
    let pre =
        approval_result_preimage("job_p", "appr_paired", true, &req_hash, "device:paired", decided_at);
    let ar = ApprovalResult {
        job_id: "job_p".into(),
        approval_id: "appr_paired".into(),
        approve: true,
        request_hash: req_hash,
        approver: "device:paired".into(),
        decided_at,
        approver_pubkey: Some(pubkey),
        audience: None,
        display_digest: None,
        device_sig: sign(&sk, &pre),
    };
    // The relay loop verifies against a snapshot of the SERVICE's keyring (shared with REST).
    let keyring = state.service.approver_keyring_snapshot();
    let terminal = handle_approval_result(&state.service, &keyring, ar).await;
    assert!(
        matches!(terminal.as_ref().map(|t| &t.outcome), Some(RelayOutcome::Allowed { .. })),
        "a key paired into the service keyring should verify: {terminal:?}"
    );
}

struct MemoryTransport {
    tx: mpsc::Sender<Envelope>,
    rx: mpsc::Receiver<Envelope>,
}

#[async_trait]
impl RelayTransport for MemoryTransport {
    async fn send(&mut self, env: Envelope) -> Result<(), RelayError> {
        self.tx.send(env).await.map_err(|_| RelayError::ConnectionClosed)
    }
    async fn recv(&mut self) -> Result<Envelope, RelayError> {
        self.rx.recv().await.ok_or(RelayError::ConnectionClosed)
    }
    async fn close(&mut self, _: CloseCode) -> Result<(), RelayError> {
        Ok(())
    }
}

fn memory_pair() -> (MemoryTransport, MemoryTransport) {
    let (a, ar) = mpsc::channel(16);
    let (b, br) = mpsc::channel(16);
    (MemoryTransport { tx: a, rx: br }, MemoryTransport { tx: b, rx: ar })
}

#[tokio::test]
async fn worker_handshake_signs_a_hello_that_verifies() {
    let sk = SigningKey::from_bytes(&[8u8; 32]);
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    let config = WorkerConfig {
        worker_id: "worker_x".into(),
        org_id: "org_x".into(),
        signing_key: sk,
    };

    let (mut worker_t, mut hub_t) = memory_pair();

    // A mock hub: recv ChallengeRequest, issue a fixed Challenge, recv Hello, verify its sig.
    let pubkey_for_hub = pubkey.clone();
    let hub = async move {
        let _cr = hub_t.recv().await.unwrap(); // ChallengeRequest
        hub_t
            .send(Envelope::new(0, 1, Frame::Challenge(Challenge {
                challenge: "chal-123".into(),
                connection_id: "conn-abc".into(),
            })))
            .await
            .unwrap();
        let signed = match hub_t.recv().await.unwrap().frame {
            Frame::Hello(s) => s,
            other => panic!("expected hello, got {other:?}"),
        };
        let preimage =
            hello_preimage("worker_x", "org_x", "chal-123", "conn-abc", ProtocolVersion::CURRENT);
        let sig_ok = verify(&pubkey_for_hub, &preimage, &signed.sig).is_ok();
        hub_t
            .send(Envelope::new(0, 1, Frame::AuthAck(AuthAck {
                version: ProtocolVersion::CURRENT,
                session_epoch: 1,
                heartbeat_interval_ms: 15_000,
                heartbeat_miss_limit: 3,
                server_time: 1,
            })))
            .await
            .unwrap();
        sig_ok
    };

    let worker = run_worker_handshake(&mut worker_t, &config);
    let (sig_ok, res) = tokio::join!(hub, worker);

    assert!(sig_ok, "the worker's Hello signature must verify against its pubkey");
    assert!(res.is_ok(), "worker handshake should complete: {res:?}");
}

#[tokio::test]
async fn handle_invoke_runs_locally_and_allows_a_seeded_capability() {
    let state = common::seeded_accepting_legacy_signatures();
    let service = state.service.clone();
    // A relayed call is remote whatever its frame says, so the seeded local-only secret has to allow it.
    let store = service.store();
    let mut secret = store.get_secret("sec_braintree_prod").unwrap().expect("the seeded Braintree secret");
    secret.metadata.allowed_execution_locations.push(ExecutionLocation::RemoteAllowed);
    store.put_secret(secret).unwrap();

    let params = serde_json::json!({ "status": "failed", "date": "2026-06-21" });
    let req = InvokeRequest {
        job_id: "job_1".into(),
        session_ctx: SessionCtx {
            cp_session_id: "cp_sess".into(),
            org_id: "org_x".into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: "braintree.transactions.search".into(),
        params: params.clone(),
        request_hash: request_hash("braintree.transactions.search", &params),
        reason: Some("relayed search".into()),
        execution_location: ExecutionLocation::LocalOnly,
        deadline_ms: 9_999_999_999_999,
    };

    let result = handle_invoke(&service, "org_x", req).await;
    assert_eq!(result.job_id, "job_1");
    assert!(
        matches!(result.outcome, RelayOutcome::Allowed { .. }),
        "the seeded read-only capability should be allowed"
    );
    // No secret / auth header leaks into the relayed result.
    let json = serde_json::to_string(&result).unwrap().to_lowercase();
    assert!(!json.contains("authorization"));
}

/// A relayed invoke stored its session with an empty token, under the id the control plane chose, so an
/// empty bearer on `/mcp` authenticated as the relayed agent, and a chosen id that named a real session
/// overwrote it (here the operator's, which also lost its own bearer).
#[tokio::test]
async fn a_relayed_session_cannot_be_reached_with_an_empty_bearer_or_overwrite_a_real_one() {
    use tower::ServiceExt;
    let state = common::seeded();
    let service = state.service.clone();
    // A relayed call is remote whatever its frame says, so the seeded local-only secret has to allow it.
    let mut secret = service.store().get_secret("sec_braintree_prod").unwrap().expect("the seeded Braintree secret");
    secret.metadata.allowed_execution_locations.push(ExecutionLocation::RemoteAllowed);
    service.store().put_secret(secret).unwrap();
    let params = serde_json::json!({ "status": "failed", "date": "2026-06-21" });
    let req = InvokeRequest {
        job_id: "job_empty".into(),
        session_ctx: SessionCtx {
            cp_session_id: "sess_demo".into(),
            org_id: "org_x".into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: "braintree.transactions.search".into(),
        params: params.clone(),
        request_hash: request_hash("braintree.transactions.search", &params),
        reason: None,
        execution_location: ExecutionLocation::LocalOnly,
        deadline_ms: 9_999_999_999_999,
    };
    let result = handle_invoke(&service, "org_x", req).await;
    assert!(matches!(result.outcome, RelayOutcome::Allowed { .. }), "the relayed call itself still runs");

    let real = service.authenticate(permaura_gateway::seed::DEMO_TOKEN).expect("the real session keeps its bearer");
    assert_eq!((real.id.as_str(), real.role), ("sess_demo", SessionRole::Operator));
    assert!(service.authenticate("").is_err(), "an empty bearer names nobody");
    assert!(!service.bearer_is_live(""));
    let relayed: Vec<Session> =
        service.store().list_sessions().unwrap().into_iter().filter(|s| s.id.starts_with("relay:")).collect();
    assert_eq!(relayed.len(), 1, "the relayed session lives in its own namespace");
    assert!(!relayed[0].token.is_empty(), "with a token of its own");

    let app = permaura_gateway::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "permaura_invoke", "arguments": { "capability": "braintree.transactions.search", "params": params } },
    });
    for header in ["Bearer ", ""] {
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", header)
                    .body(axum::body::Body::from(call.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], -32001, "an empty bearer must not invoke ({header:?}): {body}");
    }
}

#[tokio::test]
async fn handle_invoke_rejects_a_request_hash_mismatch() {
    let state = common::seeded_accepting_legacy_signatures();
    let service = state.service.clone();

    let req = InvokeRequest {
        job_id: "job_2".into(),
        session_ctx: SessionCtx {
            cp_session_id: "s".into(),
            org_id: "o".into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: "braintree.transactions.search".into(),
        params: serde_json::json!({ "status": "failed" }),
        request_hash: "deadbeef".into(), // does not match the params
        reason: None,
        execution_location: ExecutionLocation::LocalOnly,
        deadline_ms: 9_999_999_999_999,
    };

    let result = handle_invoke(&service, "o", req).await;
    assert!(
        matches!(result.outcome, RelayOutcome::Denied { .. }),
        "a forged request_hash must be refused"
    );
}

#[tokio::test]
async fn handle_invoke_rejects_an_expired_deadline() {
    let state = common::seeded_accepting_legacy_signatures();
    let params = serde_json::json!({ "status": "failed" });
    let req = InvokeRequest {
        job_id: "job_3".into(),
        session_ctx: SessionCtx {
            cp_session_id: "s".into(),
            org_id: "org_x".into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: "braintree.transactions.search".into(),
        params: params.clone(),
        request_hash: request_hash("braintree.transactions.search", &params),
        reason: None,
        execution_location: ExecutionLocation::LocalOnly,
        deadline_ms: 1, // long past
    };
    let result = handle_invoke(&state.service, "org_x", req).await;
    assert!(matches!(result.outcome, RelayOutcome::Denied { .. }), "an expired job must be refused");
}

#[tokio::test]
async fn handle_invoke_rejects_a_cross_org_invoke() {
    let state = common::seeded_accepting_legacy_signatures();
    let params = serde_json::json!({ "status": "failed" });
    let req = InvokeRequest {
        job_id: "job_4".into(),
        session_ctx: SessionCtx {
            cp_session_id: "s".into(),
            org_id: "org_a".into(),
            principal: Principal::agent("codex-cli"),
            origin: InvokeOrigin::Relay,
            authenticated_at: 1,
        },
        capability: "braintree.transactions.search".into(),
        params: params.clone(),
        request_hash: request_hash("braintree.transactions.search", &params),
        reason: None,
        execution_location: ExecutionLocation::LocalOnly,
        deadline_ms: 9_999_999_999_999,
    };
    // The worker serves org_b, but the relayed invoke claims org_a → refused.
    let result = handle_invoke(&state.service, "org_b", req).await;
    assert!(matches!(result.outcome, RelayOutcome::Denied { .. }), "a cross-org invoke must be refused");
}

/// The relay transport takes the same gateway binding as REST: a frame signed for another worker's
/// audience is refused here, and one signed for this worker's runs the held call.
#[tokio::test]
async fn a_relayed_approval_signed_for_another_worker_is_refused() {
    let state = common::seeded_accepting_legacy_signatures();
    let (_p, req_hash) = seed_held_approval(&state, "appr_aud");
    let own = state.service.approval_audience().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[44u8; 32]);
    let mut keyring = ApproverKeyring::new();
    keyring.add("device:phone", STANDARD.encode(sk.verifying_key().to_bytes()));
    let frame = |audience: &str| {
        let decided_at = now_ms();
        let preimage = permaura_relay::approval_result_preimage_v2(
            audience, "job_aud", "appr_aud", true, &req_hash, "device:phone", decided_at,
        );
        ApprovalResult {
            job_id: "job_aud".into(),
            approval_id: "appr_aud".into(),
            approve: true,
            request_hash: req_hash.clone(),
            approver: "device:phone".into(),
            decided_at,
            approver_pubkey: None,
            audience: Some(audience.into()),
            display_digest: None,
            device_sig: sign(&sk, &preimage),
        }
    };
    assert!(
        handle_approval_result(&state.service, &keyring, frame("aud_another_worker")).await.is_none(),
        "a signature made for another worker must not run the held call here"
    );
    let terminal = handle_approval_result(&state.service, &keyring, frame(&own)).await;
    assert!(
        matches!(terminal.as_ref().map(|t| &t.outcome), Some(RelayOutcome::Allowed { .. })),
        "one made for this worker does: {terminal:?}"
    );
}
