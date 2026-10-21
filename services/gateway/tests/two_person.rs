//! Two-person approval: a `device_signed` action can require signatures from N **distinct**
//! people's paired devices before the held call runs. Each key is bound to the person it approves
//! for, so an iPhone and the Watch paired through it are one person, not two.
//!
//! These tests exist for the failure modes, not the happy path. The rule is only worth anything if
//! one person cannot satisfy it alone: by signing twice, by holding two paired identities or two
//! paired devices, or by being the principal that requested the call in the first place.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;

use permaura_gateway::policy_guard::Mutation;
use permaura_gateway::relay::approver::ApproverKeyring;
use permaura_gateway::relay::handle_approval_result;
use permaura_gateway::service::SignedApprovalOutcome;
use permaura_gateway::store::{PendingApproval, Session, SessionRole};
use permaura_gateway::AppState;
use permaura_relay::{approval_result_preimage, request_hash, sign, ApprovalResult, RelayOutcome};

mod common;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

const CAP: &str = "braintree.transactions.search";

/// Seed a held approval needing `quorum` distinct signatures. Returns its request_hash.
fn seed(state: &AppState, approval_id: &str, quorum: u8) -> String {
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_2p".into(),
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
        })
        .unwrap();
    let params = serde_json::json!({ "status": "failed" });
    state
        .service
        .store()
        .put_approval(PendingApproval {
            id: approval_id.into(),
            session_id: "sess_2p".into(),
            capability: CAP.into(),
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
            required_tier: "device_signed".into(),
            required_signatures: quorum,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
    request_hash(CAP, &params)
}

/// A signing key from a fixed seed, so a test can deliberately reuse one across two approver ids.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Sign an approval decision as `approver` using `sk`.
fn result_from(
    sk: &SigningKey,
    approver: &str,
    approval_id: &str,
    approve: bool,
    req_hash: &str,
) -> ApprovalResult {
    let decided_at = now_ms();
    let preimage =
        approval_result_preimage(approval_id, approval_id, approve, req_hash, approver, decided_at);
    ApprovalResult {
        job_id: approval_id.into(),
        approval_id: approval_id.into(),
        approve,
        request_hash: req_hash.into(),
        approver: approver.into(),
        decided_at,
        approver_pubkey: Some(STANDARD.encode(sk.verifying_key().to_bytes())),
        audience: None,
        display_digest: None,
        device_sig: sign(sk, &preimage),
    }
}

/// Each device bound to a person of its own, the way two different people's phones are.
fn keyring(entries: &[(&str, &SigningKey)]) -> ApproverKeyring {
    let mut k = ApproverKeyring::new();
    for (id, sk) in entries {
        k.add_for(*id, STANDARD.encode(sk.verifying_key().to_bytes()), Some(format!("person-of-{id}")));
    }
    k
}

/// Devices bound to the person given, or to nobody, as a key paired before keys named a person is.
fn keyring_of(entries: &[(&str, &SigningKey, Option<&str>)]) -> ApproverKeyring {
    let mut k = ApproverKeyring::new();
    for (id, sk, person) in entries {
        k.add_for(*id, STANDARD.encode(sk.verifying_key().to_bytes()), person.map(str::to_string));
    }
    k
}

#[tokio::test]
async fn one_signature_is_not_enough_for_a_two_person_action() {
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_2p", 2);
    let (a, b) = (key(11), key(22));
    let ring = keyring(&[("device:alice", &a), ("device:bob", &b)]);

    let first = state
        .service
        .verify_signed_approval(&ring, &result_from(&a, "device:alice", "appr_2p", true, &hash));
    match first {
        SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => {
            assert_eq!((collected, required), (1, 2));
        }
        _ => panic!("one signature of two must not verify the approval"),
    }
    // The held call must still be untouched: this is the whole point.
    let stored = state.service.store().get_approval("appr_2p").unwrap().unwrap();
    assert_eq!(stored.status, "pending");
    assert!(stored.result.is_none(), "nothing may execute on a half-satisfied quorum");

    let second = state
        .service
        .verify_signed_approval(&ring, &result_from(&b, "device:bob", "appr_2p", true, &hash));
    assert!(
        matches!(second, SignedApprovalOutcome::Verified),
        "the second distinct device completes the quorum"
    );
}

#[tokio::test]
async fn the_same_device_cannot_sign_twice_to_reach_a_quorum() {
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_dup", 2);
    let a = key(11);
    let ring = keyring(&[("device:alice", &a)]);

    for _ in 0..3 {
        let out = state
            .service
            .verify_signed_approval(&ring, &result_from(&a, "device:alice", "appr_dup", true, &hash));
        match out {
            SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => {
                assert_eq!((collected, required), (1, 2), "a repeat signature must not count again");
            }
            _ => panic!("one device signing repeatedly must never satisfy a two-person rule"),
        }
    }
    assert_eq!(
        state.service.store().get_approval("appr_dup").unwrap().unwrap().signatures.len(),
        1
    );
}

#[tokio::test]
async fn one_device_paired_under_two_names_cannot_satisfy_a_two_person_rule() {
    // The attack the approver-id check alone would miss: pair the same phone twice under two
    // approver ids and sign with each. Distinctness is enforced on the trusted KEY too.
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_twin", 2);
    let a = key(11);
    let ring = keyring(&[("device:alice", &a), ("device:alice-spare", &a)]);

    let first = state
        .service
        .verify_signed_approval(&ring, &result_from(&a, "device:alice", "appr_twin", true, &hash));
    assert!(matches!(first, SignedApprovalOutcome::AwaitingSignatures { collected: 1, .. }));

    let second = state.service.verify_signed_approval(
        &ring,
        &result_from(&a, "device:alice-spare", "appr_twin", true, &hash),
    );
    match second {
        SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => {
            assert_eq!(
                (collected, required),
                (1, 2),
                "two identities backed by one key are one device"
            );
        }
        _ => panic!("the same key under a second name must not complete the quorum"),
    }
}

// ── People, not devices ───────────────────────────────────────────────────────────────

/// The defect: one person's iPhone and the Watch paired through it are two keys and one person, so
/// together they are one signature toward a two-person rule however many times each signs.
#[tokio::test]
async fn one_persons_phone_and_watch_are_one_person_toward_a_two_person_rule() {
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_one_person", 2);
    let (phone, watch, other) = (key(11), key(12), key(22));
    let ring = keyring_of(&[
        ("device:sam-iphone", &phone, Some("user_sam")),
        ("device:sam-watch", &watch, Some("user_sam")),
        ("device:omar-iphone", &other, Some("user_omar")),
    ]);

    let first = state
        .service
        .verify_signed_approval(&ring, &result_from(&phone, "device:sam-iphone", "appr_one_person", true, &hash));
    assert!(matches!(first, SignedApprovalOutcome::AwaitingSignatures { collected: 1, required: 2, .. }));
    let second = state
        .service
        .verify_signed_approval(&ring, &result_from(&watch, "device:sam-watch", "appr_one_person", true, &hash));
    match second {
        SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => {
            assert_eq!((collected, required), (1, 2), "the Watch is the same person as the phone");
        }
        _ => panic!("one person's two devices must not satisfy a two-person rule"),
    }
    assert_eq!(state.service.store().get_approval("appr_one_person").unwrap().unwrap().status, "pending");

    let third = state
        .service
        .verify_signed_approval(&ring, &result_from(&other, "device:omar-iphone", "appr_one_person", true, &hash));
    assert!(matches!(third, SignedApprovalOutcome::Verified), "a second person completes it");
}

/// The rule for a key paired before keys named a person: it is nobody in particular, so it may be the
/// only signature (a single-signature rule is unaffected) but never the second person, alone or
/// beside another unbound key or a bound one. Treating it as a person of its own would let every
/// iPhone and Watch paired before keys named a person go on satisfying two-person rules as one person.
#[tokio::test]
async fn a_key_bound_to_nobody_is_never_the_second_person() {
    let state = common::seeded_accepting_legacy_signatures();
    let (old_phone, old_watch, bound) = (key(31), key(32), key(33));
    let ring = keyring_of(&[
        ("device:old-phone", &old_phone, None),
        ("device:old-watch", &old_watch, None),
        ("device:priya-iphone", &bound, Some("user_priya")),
    ]);

    let hash = seed(&state, "appr_unbound_pair", 2);
    for (sk, id) in [(&old_phone, "device:old-phone"), (&old_watch, "device:old-watch")] {
        let out = state.service.verify_signed_approval(&ring, &result_from(sk, id, "appr_unbound_pair", true, &hash));
        assert!(
            matches!(out, SignedApprovalOutcome::AwaitingSignatures { collected: 1, required: 2, .. }),
            "two keys bound to nobody are at most one person"
        );
    }

    let hash = seed(&state, "appr_unbound_second", 2);
    let first = state
        .service
        .verify_signed_approval(&ring, &result_from(&bound, "device:priya-iphone", "appr_unbound_second", true, &hash));
    assert!(matches!(first, SignedApprovalOutcome::AwaitingSignatures { collected: 1, .. }));
    let second = state
        .service
        .verify_signed_approval(&ring, &result_from(&old_watch, "device:old-watch", "appr_unbound_second", true, &hash));
    assert!(
        matches!(second, SignedApprovalOutcome::AwaitingSignatures { collected: 1, required: 2, .. }),
        "an unbound key beside a bound one adds no person: it may be that person's other device"
    );

    let hash = seed(&state, "appr_unbound_single", 1);
    let only = state
        .service
        .verify_signed_approval(&ring, &result_from(&old_phone, "device:old-phone", "appr_unbound_single", true, &hash));
    assert!(matches!(only, SignedApprovalOutcome::Verified), "a single-signature rule is unaffected");
}

/// Two people signed with keys paired before keys named a person, so the hold waited at one person.
/// Once both keys are bound to their people the saved signatures already make two, and a re-delivered
/// signature completes the hold rather than reporting it still pending.
#[tokio::test]
async fn a_redelivered_signature_completes_a_hold_its_saved_signatures_now_satisfy() {
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_repaired", 2);
    let (priya, omar) = (key(81), key(82));
    let before = keyring_of(&[("device:priya-old", &priya, None), ("device:omar-old", &omar, None)]);
    for (sk, id) in [(&priya, "device:priya-old"), (&omar, "device:omar-old")] {
        let out = state.service.verify_signed_approval(&before, &result_from(sk, id, "appr_repaired", true, &hash));
        assert!(matches!(out, SignedApprovalOutcome::AwaitingSignatures { collected: 1, required: 2, .. }), "setup");
    }

    let after = keyring_of(&[("device:priya-old", &priya, Some("user_priya")), ("device:omar-old", &omar, Some("user_omar"))]);
    let again = state.service.verify_signed_approval(&after, &result_from(&omar, "device:omar-old", "appr_repaired", true, &hash));
    assert!(matches!(again, SignedApprovalOutcome::Verified), "the saved signatures are two people now");
}

/// The defect on a self-run gateway: the iPhone is paired at the host naming the account it is
/// signed in as, the Watch is paired through it naming the same account and co-signed by the iPhone,
/// and both approve a two-person hold. That is one person, so it stays pending.
#[tokio::test]
async fn a_self_run_phone_and_watch_named_for_one_person_are_one_person() {
    let state = common::seeded();
    let app = permaura_gateway::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (phone, watch) = (key(51), key(52));
    let (status, body) = self_run_pair(&app, "device:sam-iphone", &phone, Some("user_sam")).await;
    assert_eq!(status, axum::http::StatusCode::OK, "setup: the first device: {body}");
    let (status, held) = self_run_pair(&app, "device:sam-watch", &watch, Some("user_sam")).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "setup: the Watch waits for the iPhone: {held}");
    let held_id = held["approval_id"].as_str().expect("a held enrolment names its approval").to_string();
    let (status, resp) = http_co_sign(&app, &held_id, "device:sam-iphone", &phone).await;
    assert_eq!(status, axum::http::StatusCode::OK, "setup: the iPhone confirms the Watch: {resp}");

    assert!(state.service.approver_keyring_snapshot().trusted_key("device:sam-watch").is_some(), "setup: the Watch is trusted");

    seed(&state, "appr_self_run_one_person", 2);
    let (status, first) = http_co_sign(&app, "appr_self_run_one_person", "device:sam-iphone", &phone).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{first}");
    let (status, second) = http_co_sign(&app, "appr_self_run_one_person", "device:sam-watch", &watch).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "one person's iPhone and Watch must not satisfy a two-person rule: {second}");
    assert_eq!(second["status"], "pending", "{second}");
    assert_eq!(state.service.store().get_approval("appr_self_run_one_person").unwrap().unwrap().status, "pending");
}

/// A self-run gateway binds the person its pairing names, vouched for by whoever relays it at the
/// host: an unnamed pairing stays unbound, re-pairing an unbound key binds it, and a key bound to one
/// person is refused re-attribution to another rather than held for a co-signature it could give itself.
#[tokio::test]
async fn a_self_run_pairing_binds_the_person_it_names() {
    let state = common::seeded();
    let app = permaura_gateway::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let phone = key(41);

    let (status, body) = self_run_pair(&app, "device:sam-iphone", &phone, None).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["person_bound"], false);
    assert_eq!(state.service.approver_keyring_snapshot().person("device:sam-iphone"), None);

    let (status, body) = self_run_pair(&app, "device:sam-iphone", &phone, Some("user_sam")).await;
    assert_eq!(status, axum::http::StatusCode::OK, "binding an unbound key is not a new enrolment: {body}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:sam-iphone"), Some("user_sam"));

    let (status, body) = self_run_pair(&app, "device:sam-iphone", &phone, Some("user_omar")).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("different person"), "{body}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:sam-iphone"), Some("user_sam"));

    let (status, body) = self_run_pair(&app, "device:sam-iphone", &phone, None).await;
    assert_eq!(status, axum::http::StatusCode::OK, "a re-pair that names nobody keeps the binding: {body}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:sam-iphone"), Some("user_sam"));

    let (status, body) = self_run_pair(&app, "device:sam-iphone", &phone, Some(&"x".repeat(200))).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");

    // Keys paired before keys named a person. Binding the Watch to the person the iPhone already is
    // cannot add a person, so it applies; binding Omar's is a second person arriving, which a loopback
    // bearer must not mint alone, so it waits for a trusted device to confirm it like a new device.
    let (watch, omar) = (key(42), key(43));
    assert!(state.service.trust_approver_key("device:sam-watch", &STANDARD.encode(watch.verifying_key().to_bytes())));
    assert!(state.service.trust_approver_key("device:omar-iphone", &STANDARD.encode(omar.verifying_key().to_bytes())));
    let (status, body) = self_run_pair(&app, "device:sam-watch", &watch, Some("user_sam")).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:sam-watch"), Some("user_sam"));
    let (status, held) = self_run_pair(&app, "device:omar-iphone", &omar, Some("user_omar")).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{held}");
    assert_eq!(held["already_trusted"], true, "{held}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:omar-iphone"), None);
    assert!(state.service.approver_keyring_snapshot().trusted_key("device:omar-iphone").is_some(), "still trusted meanwhile");
    let held_id = held["approval_id"].as_str().unwrap().to_string();
    let (status, resp) = http_co_sign(&app, &held_id, "device:sam-iphone", &phone).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{resp}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:omar-iphone"), Some("user_omar"));
}

/// Two attributions held for the same unbound key are signed in turn: the first binds it, and the
/// second, signed later on an older hold, must not then move the device to another person.
#[tokio::test]
async fn a_held_attribution_cannot_move_a_device_bound_since_it_was_held() {
    let state = common::seeded();
    let app = permaura_gateway::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let (phone, omar) = (key(70), key(71));
    let (status, body) = self_run_pair(&app, "device:sam-iphone", &phone, Some("user_sam")).await;
    assert_eq!(status, axum::http::StatusCode::OK, "setup: {body}");
    assert!(state.service.trust_approver_key("device:omar-iphone", &STANDARD.encode(omar.verifying_key().to_bytes())));

    let (status, as_omar) = self_run_pair(&app, "device:omar-iphone", &omar, Some("user_omar")).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "setup: {as_omar}");
    let (status, as_eve) = self_run_pair(&app, "device:omar-iphone", &omar, Some("user_eve")).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "setup: the key is still unbound, so this is held too: {as_eve}");

    let (status, resp) = http_co_sign(&app, as_omar["approval_id"].as_str().unwrap(), "device:sam-iphone", &phone).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{resp}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:omar-iphone"), Some("user_omar"));

    let (status, resp) = http_co_sign(&app, as_eve["approval_id"].as_str().unwrap(), "device:sam-iphone", &phone).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "the older hold is refused when applied: {resp}");
    assert!(resp["error"].as_str().unwrap_or_default().contains("different person"), "{resp}");
    assert_eq!(state.service.approver_keyring_snapshot().person("device:omar-iphone"), Some("user_omar"), "not moved");
}

/// One request through the router as the seeded operator, over loopback.
async fn http(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let req = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", permaura_gateway::seed::DEMO_TOKEN))
        .body(body.map_or_else(axum::body::Body::empty, |b| axum::body::Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

/// Co-sign a held approval as a trusted device, the way the phone does: read the signing inputs the
/// gateway serves, sign the v3 preimage, post it back.
async fn http_co_sign(
    app: &axum::Router,
    approval_id: &str,
    approver: &str,
    sk: &SigningKey,
) -> (axum::http::StatusCode, serde_json::Value) {
    let (_s, appr) = http(app, "GET", &format!("/v1/approvals/{approval_id}"), None).await;
    let request_hash = appr["request_hash"].as_str().expect("a hold serves its request_hash");
    let job_id = appr["job_id"].as_str().expect("a hold serves its job_id");
    let audience = appr["approval_audience"].as_str().expect("a hold serves its audience");
    let shown = permaura_relay::approval_display_full_digest_of(&appr).expect("a hold serves its full rendering");
    let decided_at = now_ms();
    let preimage = permaura_relay::approval_result_preimage_v3(
        audience,
        job_id,
        approval_id,
        true,
        request_hash,
        &shown,
        approver,
        decided_at,
    );
    let body = serde_json::json!({
        "approval_id": approval_id,
        "approve": true,
        "approver": approver,
        "request_hash": request_hash,
        "decided_at": decided_at,
        "job_id": job_id,
        "approver_pubkey": STANDARD.encode(sk.verifying_key().to_bytes()),
        "audience": audience,
        "display_digest": shown,
        "device_sig": sign(sk, &preimage),
    });
    http(app, "POST", "/v1/approvals", Some(body)).await
}

/// `POST /v1/approver-keys/pair` over loopback, naming `person` when given.
async fn self_run_pair(
    app: &axum::Router,
    approver_id: &str,
    sk: &SigningKey,
    person: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = now_ms();
    let mut body = serde_json::json!({
        "approver_id": approver_id,
        "approver_pubkey": pubkey,
        "issued_at": issued_at,
        "sig": sign(sk, &permaura_relay::approver_pairing_preimage(approver_id, &pubkey, issued_at)),
    });
    if let Some(person) = person {
        body["person"] = serde_json::json!(person);
    }
    http(app, "POST", "/v1/approver-keys/pair", Some(body)).await
}

#[tokio::test]
async fn a_single_denial_ends_it_without_waiting_for_a_quorum() {
    // Two-person approval means two people must agree to PROCEED. It never means one person can
    // be outvoted into proceeding, so one refusal is enough and is acted on immediately.
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_veto", 2);
    let a = key(11);
    let ring = keyring(&[("device:alice", &a)]);

    let out = state
        .service
        .verify_signed_approval(&ring, &result_from(&a, "device:alice", "appr_veto", false, &hash));
    assert!(
        matches!(out, SignedApprovalOutcome::Verified),
        "a denial resolves immediately regardless of quorum"
    );
}

#[tokio::test]
async fn a_quorum_of_one_is_unchanged_single_signature_behaviour() {
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_one", 1);
    let a = key(11);
    let ring = keyring(&[("device:alice", &a)]);
    let out = state
        .service
        .verify_signed_approval(&ring, &result_from(&a, "device:alice", "appr_one", true, &hash));
    assert!(matches!(out, SignedApprovalOutcome::Verified));
}

#[tokio::test]
async fn the_relay_path_holds_the_job_open_until_the_quorum_lands() {
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_relay", 2);
    let (a, b) = (key(11), key(22));
    let ring = keyring(&[("device:alice", &a), ("device:bob", &b)]);

    // First signature: no terminal outcome, so the relayed job stays open.
    let first = handle_approval_result(
        &state.service,
        &ring,
        result_from(&a, "device:alice", "appr_relay", true, &hash),
    )
    .await;
    assert!(first.is_none(), "a half-satisfied quorum must not terminate the job");

    let second = handle_approval_result(
        &state.service,
        &ring,
        result_from(&b, "device:bob", "appr_relay", true, &hash),
    )
    .await;
    assert!(
        matches!(second.as_ref().map(|t| &t.outcome), Some(RelayOutcome::Allowed { .. })),
        "the completing signature runs the held call: {second:?}"
    );
}

#[tokio::test]
async fn the_requesting_principal_cannot_be_one_of_the_two() {
    // Separation of duty holds for every signer, not just the first: otherwise the caller could
    // supply half of their own two-person approval.
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_self", 2);
    let (a, b) = (key(11), key(22));
    // The held call's session is user `sam`; `user:sam` signing is self-approval.
    let ring = keyring(&[("user:sam", &a), ("device:bob", &b)]);

    let out = state
        .service
        .verify_signed_approval(&ring, &result_from(&a, "user:sam", "appr_self", true, &hash));
    assert!(
        matches!(out, SignedApprovalOutcome::Refused(_)),
        "the requesting principal must not count toward the quorum"
    );
    assert!(state.service.store().get_approval("appr_self").unwrap().unwrap().signatures.is_empty());
}

#[tokio::test]
async fn a_signature_bound_to_different_params_never_counts() {
    // Each signature independently re-binds to the held call. A second signer cannot be handed a
    // different request to sign and have it counted toward this approval.
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_bind", 2);
    let (a, b) = (key(11), key(22));
    let ring = keyring(&[("device:alice", &a), ("device:bob", &b)]);

    let first = state
        .service
        .verify_signed_approval(&ring, &result_from(&a, "device:alice", "appr_bind", true, &hash));
    assert!(matches!(first, SignedApprovalOutcome::AwaitingSignatures { collected: 1, .. }));

    let other_hash = request_hash(CAP, &serde_json::json!({ "status": "settled" }));
    let out = state.service.verify_signed_approval(
        &ring,
        &result_from(&b, "device:bob", "appr_bind", true, &other_hash),
    );
    assert!(matches!(out, SignedApprovalOutcome::Refused(_)));
    assert_eq!(
        state.service.store().get_approval("appr_bind").unwrap().unwrap().signatures.len(),
        1,
        "a refused signature must not be recorded"
    );
}

#[tokio::test]
async fn revoking_a_device_takes_back_the_half_approval_it_already_gave() {
    // The lost-phone case. Alice signs, then her device is revoked because it was stolen. Bob's
    // signature must NOT complete a two-person rule on its own: the whole point of revoking is
    // that the stolen device no longer speaks for her.
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_revoked", 2);
    let (a, b) = (key(11), key(22));
    let mut ring = keyring(&[("device:alice", &a), ("device:bob", &b)]);

    let first = state
        .service
        .verify_signed_approval(&ring, &result_from(&a, "device:alice", "appr_revoked", true, &hash));
    assert!(matches!(first, SignedApprovalOutcome::AwaitingSignatures { collected: 1, .. }));

    ring.revoke("device:alice");

    let second = state
        .service
        .verify_signed_approval(&ring, &result_from(&b, "device:bob", "appr_revoked", true, &hash));
    match second {
        SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => {
            assert_eq!(
                (collected, required),
                (1, 2),
                "the revoked device's signature must stop counting"
            );
        }
        _ => panic!("a revoked device's stale signature must not complete the quorum"),
    }
}

#[tokio::test]
async fn a_device_that_repaired_with_a_new_key_is_not_the_device_that_signed() {
    // Same approver id, different key: the phone was wiped and re-paired. Its earlier signature
    // was made by a key that no longer exists, so it cannot carry into the new pairing.
    let state = common::seeded_accepting_legacy_signatures();
    let hash = seed(&state, "appr_rotate", 2);
    let (a, a2, b) = (key(11), key(99), key(22));
    let mut ring = keyring(&[("device:alice", &a), ("device:bob", &b)]);

    let first = state
        .service
        .verify_signed_approval(&ring, &result_from(&a, "device:alice", "appr_rotate", true, &hash));
    assert!(matches!(first, SignedApprovalOutcome::AwaitingSignatures { collected: 1, .. }));

    // Re-pair alice's id onto a fresh key.
    ring.revoke("device:alice");
    ring.add("device:alice", STANDARD.encode(a2.verifying_key().to_bytes()));

    let second = state
        .service
        .verify_signed_approval(&ring, &result_from(&b, "device:bob", "appr_rotate", true, &hash));
    assert!(
        matches!(second, SignedApprovalOutcome::AwaitingSignatures { collected: 1, required: 2, .. }),
        "a signature from a superseded key must not count"
    );
}

// ── the trust root itself: a held `ApproverKeyTrust` ──────────────────────────────────
//
// Enrolling a device on a hosted worker with a keyring that is already live is queued as a held
// `device_signed` approval and applied only when a device this gateway ALREADY trusts signs for it.
// That reuses everything above rather than inventing a second resolution path, so the properties the
// rest of this file pins apply to the trust root too, which is the one place they matter most.

/// The synthetic capability every held control-plane mutation is queued under. Named here because
/// `rest::POLICY_WRITE_CAP` is crate-internal; the string is the wire contract and must match.
const POLICY_WRITE_CAP: &str = "permaura.policy.write";

fn key_trust(approver_id: &str, sk: &SigningKey) -> Mutation {
    Mutation::ApproverKeyTrust {
        approver_id: approver_id.into(),
        approver_pubkey: STANDARD.encode(sk.verifying_key().to_bytes()),
        person: None,
        replaces: None,
    }
}

/// Seed a held `ApproverKeyTrust` needing `quorum` signatures, the way `hold_mutation_approval`
/// writes one. Returns its request_hash.
fn seed_key_trust(state: &AppState, approval_id: &str, quorum: u8, m: &Mutation) -> String {
    let params = serde_json::to_value(m).expect("a mutation encodes as approval params");
    state
        .service
        .store()
        .put_approval(PendingApproval {
            id: approval_id.into(),
            // A control-plane change has no requesting agent session, the same empty id the service
            // writes, so separation-of-duty resolves against nothing rather than a stale row.
            session_id: String::new(),
            capability: POLICY_WRITE_CAP.into(),
            resource: "control-plane".into(),
            message: permaura_gateway::rest::HELD_PAIRING_NOTE.into(),
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
            required_tier: "device_signed".into(),
            required_signatures: quorum,
            signatures: Vec::new(),
            requested_by: None,
        })
        .unwrap();
    request_hash(POLICY_WRITE_CAP, &params)
}

#[tokio::test]
async fn a_held_key_enrolment_is_co_signed_over_the_exact_approver_and_key() {
    // The co-signature is not a vote on "some enrolment": it covers the exact (approver_id, pubkey)
    // pair, because `request_hash` is recomputed from the stored mutation. Without that, a control
    // plane that got a signature over one enrolment could swap in a key of its own before applying.
    let state = common::seeded_accepting_legacy_signatures();
    let alice = key(11);
    let new_phone = key(33);
    let ring = keyring(&[("device:alice", &alice)]);

    let m = key_trust("device:new-phone", &new_phone);
    let held = state
        .service
        .hold_mutation_approval(POLICY_WRITE_CAP, &m, permaura_gateway::rest::HELD_PAIRING_NOTE, None)
        .expect("a keyring write is held like any other control-plane mutation");
    assert_eq!(held.required_tier, "device_signed");
    assert_eq!(
        held.required_signatures, 1,
        "a trust-root change needs ONE already-trusted device, not a quorum"
    );

    let hash = request_hash(POLICY_WRITE_CAP, &serde_json::to_value(&m).unwrap());
    assert_eq!(
        permaura_gateway::service::held_request_hash(&held.capability, &held.params),
        hash,
        "the held params must be the mutation verbatim, or the device signs something else"
    );

    // The device being enrolled cannot vouch for itself: `trusted_key` resolves signers through the
    // keyring, and it is not in it yet. This is what makes "a second device needs an existing one"
    // mean anything at all.
    let out = state.service.verify_signed_approval(
        &ring,
        &result_from(&new_phone, "device:new-phone", &held.id, true, &hash),
    );
    assert!(
        matches!(out, SignedApprovalOutcome::Refused(_)),
        "the key being enrolled must not be able to approve its own enrolment"
    );

    // A signature covering a DIFFERENT key's enrolment does not count for this one, even from a
    // genuinely trusted device: the same approver id carrying another public key is another request.
    let swapped = key_trust("device:new-phone", &key(44));
    let swapped_hash = request_hash(POLICY_WRITE_CAP, &serde_json::to_value(&swapped).unwrap());
    assert_ne!(swapped_hash, hash, "swapping the enrolled key must change what is signed over");
    let out = state.service.verify_signed_approval(
        &ring,
        &result_from(&alice, "device:alice", &held.id, true, &swapped_hash),
    );
    assert!(
        matches!(out, SignedApprovalOutcome::Refused(_)),
        "a signature over another key's enrolment must not apply to this one"
    );
    assert!(
        state.service.store().get_approval(&held.id).unwrap().unwrap().signatures.is_empty(),
        "a refused signature must not be recorded"
    );

    let out = state
        .service
        .verify_signed_approval(&ring, &result_from(&alice, "device:alice", &held.id, true, &hash));
    assert!(
        matches!(out, SignedApprovalOutcome::Verified),
        "an already-trusted device signing the exact held enrolment completes it"
    );
}

#[tokio::test]
async fn a_revoked_co_signers_signature_is_withdrawn_from_a_held_key_enrolment() {
    // The lost-phone case, applied to the trust root. Alice half-approves enrolling a new device,
    // then her own device is revoked because it was stolen. Her signature must stop counting: if it
    // did not, whoever holds the stolen phone would already be halfway to enrolling one of their own.
    let state = common::seeded_accepting_legacy_signatures();
    let (alice, bob) = (key(11), key(22));
    let new_phone = key(55);
    let mut ring = keyring(&[("device:alice", &alice), ("device:bob", &bob)]);
    let m = key_trust("device:new-phone", &new_phone);
    let hash = seed_key_trust(&state, "appr_trust_2p", 2, &m);

    let first = state.service.verify_signed_approval(
        &ring,
        &result_from(&alice, "device:alice", "appr_trust_2p", true, &hash),
    );
    assert!(matches!(first, SignedApprovalOutcome::AwaitingSignatures { collected: 1, .. }));

    ring.revoke("device:alice");

    let second = state.service.verify_signed_approval(
        &ring,
        &result_from(&bob, "device:bob", "appr_trust_2p", true, &hash),
    );
    match second {
        SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => {
            assert_eq!(
                (collected, required),
                (1, 2),
                "the revoked device's half-approval of a keyring write must be withdrawn"
            );
        }
        _ => panic!("a revoked device must not carry a new device into the keyring"),
    }
    let stored = state.service.store().get_approval("appr_trust_2p").unwrap().unwrap();
    assert_eq!(stored.status, "pending", "nothing may be enrolled on a withdrawn signature");
}


// ── Destructive mutations hold wherever they arrived from ────────────────────────────────────────

/// The gap this closes: every delete was exempt from the ladder, because the guard that decides
/// asks only whether a change can grant more access. A delete never can, so `GrantDelete` is
/// hard-coded as tightening. That is right about permission and silent about data.
///
/// It matters because the operator token is a 0600 file, readable by every agent the owner runs. With
/// the export held, such an agent can no longer take the credentials; without this it could still
/// delete them, with every guard in the path agreeing that deleting is the safe direction.
#[test]
fn a_delete_is_destructive_even_though_it_only_ever_removes_access() {
    use permaura_gateway::policy_guard::{is_destructive, is_strictly_tightening, GuardContext, Mutation};

    let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
    let delete = Mutation::GrantDelete { grant_id: "g1".into() };

    // Both are true at once, and that is the whole point: the two questions are different.
    assert!(
        is_strictly_tightening(&delete, &ctx),
        "a delete removes authorization, which is what the existing guard measures"
    );
    assert!(
        is_destructive(&delete, &ctx),
        "and it destroys the grant, which is what the ladder now also has to see"
    );
}

/// Not everything is destructive, or the ladder would hold ordinary edits and become friction people
/// route around.
#[test]
fn an_ordinary_edit_is_not_destructive() {
    use permaura_gateway::policy_guard::{is_destructive, GuardContext, Mutation};

    let ctx = GuardContext { policies: &[], grants: &[], connections: &[], agents: &[] };
    assert!(!is_destructive(&Mutation::AgentApprove { agent_id: "a1".into() }, &ctx));
    assert!(!is_destructive(
        &Mutation::CapabilityEnable { connection_id: "c1".into(), capability: "cap".into() },
        &ctx
    ));
}
