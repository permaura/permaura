//! What an approver signs is bound to what they were shown.
//!
//! Every approval read carries `params_display` (compact, capped, with `complete`), and the
//! single-approval read also carries `params_display_full` (uncapped, up to a ceiling). A device binds
//! the digest of the full rendering it showed into a v3 signature; the gateway recomputes it from the
//! held row, refuses a signature over any other rendering, and refuses any approve of a call too large
//! to render whole. No rendering ever carries a secret.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::service::SignedApprovalOutcome;
use permaura_gateway::store::{PendingApproval, Session, SessionRole};
use permaura_gateway::{build_router, seed, AppState};
use permaura_relay::{
    approval_display_digest_of, approval_display_full_digest, approval_display_full_digest_of,
    approval_result_preimage_v2, approval_result_preimage_v3, approval_shown_full_digest, request_hash, sign,
    ApprovalResult, DisplayContext, DisplayRow, DisplayState,
};
use tower::ServiceExt;

mod common;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    remote: bool,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
    if remote {
        builder = builder.header("cf-ray", "abc123");
    }
    let req = match body {
        Some(b) => builder.header("content-type", "application/json").body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

async fn raw(app: &axum::Router, uri: &str) -> String {
    let req = Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {uri}");
    String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap()
}

fn pubkey_of(sk: &ed25519_dalek::SigningKey) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sk.verifying_key().to_bytes())
}

fn gateway_with_device(seed_byte: u8, approver: &str) -> (axum::Router, AppState, ed25519_dalek::SigningKey) {
    let state = common::seeded();
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
    assert!(state.service.trust_approver_key(approver, &pubkey_of(&sk)));
    (app, state, sk)
}

const PADDLE_CAP: &str = "paddle.subscriptions.cancel";

/// The attack's example, held as an agent call: the agent's stated intent says one thing, the
/// parameters another, and the message is what the policy engine actually writes.
fn hold(state: &AppState, id: &str, params: serde_json::Value) -> PendingApproval {
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_agent".into(),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: String::new(),
            role: SessionRole::Agent,
            created_at: now_ms(),
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
    let approval = PendingApproval {
        id: id.into(),
        session_id: "sess_agent".into(),
        capability: PADDLE_CAP.into(),
        resource: "paddle_live".into(),
        message: "Approve 'subscriptions.cancel' on 'paddle_live'?".into(),
        status: "pending".into(),
        grant_id: None,
        policy_id: None,
        params: params.into(),
        result: None,
        result_status: None,
        resolution_reason: None,
        created_at: now_ms(),
        expires_at: None,
        risk: Some(permaura_core::RiskTier::High),
        action_description: Some("Cancel a subscription.".into()),
        intent: Some("Cancel the customer's subscription at the end of the billing period, as they asked.".into()),
        required_tier: "device_signed".into(),
        required_signatures: 1,
        signatures: Vec::new(),
        requested_by: None,
    };
    state.service.store().put_approval(approval.clone()).unwrap();
    approval
}

fn hold_paddle_cancel(state: &AppState, id: &str) -> PendingApproval {
    hold(state, id, serde_json::json!({ "subscription_id": "sub_01h8x2k", "effective_from": "immediately" }))
}

/// A v3 decision over `display_digest` for the approval `served` describes.
fn v3_result(
    sk: &ed25519_dalek::SigningKey,
    approver: &str,
    served: &serde_json::Value,
    approve: bool,
    audience: Option<&str>,
    display_digest: &str,
) -> ApprovalResult {
    let approval_id = served["id"].as_str().unwrap();
    let request_hash = served["request_hash"].as_str().unwrap();
    let decided_at = now_ms();
    let preimage = approval_result_preimage_v3(
        audience.unwrap_or(""),
        approval_id,
        approval_id,
        approve,
        request_hash,
        display_digest,
        approver,
        decided_at,
    );
    ApprovalResult {
        job_id: approval_id.into(),
        approval_id: approval_id.into(),
        approve,
        request_hash: request_hash.into(),
        approver: approver.into(),
        decided_at,
        approver_pubkey: Some(pubkey_of(sk)),
        audience: audience.map(str::to_string),
        display_digest: Some(display_digest.into()),
        device_sig: sign(sk, &preimage),
    }
}

fn v2_result(sk: &ed25519_dalek::SigningKey, approval_id: &str, rh: &str, approve: bool, audience: &str) -> ApprovalResult {
    let decided_at = now_ms();
    let preimage = approval_result_preimage_v2(audience, approval_id, approval_id, approve, rh, "device:phone", decided_at);
    ApprovalResult {
        job_id: approval_id.into(),
        approval_id: approval_id.into(),
        approve,
        request_hash: rh.into(),
        approver: "device:phone".into(),
        decided_at,
        approver_pubkey: None,
        audience: Some(audience.into()),
        display_digest: None,
        device_sig: sign(sk, &preimage),
    }
}

fn describe(o: &SignedApprovalOutcome) -> String {
    match o {
        SignedApprovalOutcome::Verified => "verified".into(),
        SignedApprovalOutcome::AlreadyResolved(p) => format!("already resolved ({})", p.status),
        SignedApprovalOutcome::AwaitingSignatures { collected, required, .. } => format!("awaiting {collected} of {required}"),
        SignedApprovalOutcome::Refused(why) => format!("refused: {why}"),
    }
}

fn body_of(r: &ApprovalResult) -> serde_json::Value {
    serde_json::to_value(r).unwrap()
}

fn context(served: &serde_json::Value) -> DisplayContext<'_> {
    DisplayContext {
        capability: served["capability"].as_str().unwrap(),
        resource: served["resource"].as_str().unwrap(),
        risk: served["risk"].as_str().unwrap(),
        action_description: served["action_description"].as_str(),
        message: served["message"].as_str().unwrap(),
        intent: served["intent"].as_str(),
    }
}

/// What a broker would put on the approver's screen in place of the real call: the same approval,
/// with `effective_from` rewritten to match the agent's story, and the rendering's own digest
/// recomputed so the doctored response is internally consistent.
fn doctored(served: &serde_json::Value) -> serde_json::Value {
    let mut fake = served.clone();
    let rows: Vec<DisplayRow> = serde_json::from_value(fake["params_display_full"]["rows"].clone()).unwrap();
    let rows: Vec<DisplayRow> = rows
        .into_iter()
        .map(|mut r| {
            if r.path == "effective_from" {
                r.value = "\"next_billing_period\"".into();
            }
            r
        })
        .collect();
    fake["params_display_full"]["digest"] = serde_json::json!(approval_display_full_digest(&context(served), &rows));
    fake["params_display_full"]["rows"] = serde_json::to_value(rows).unwrap();
    fake
}

async fn read(app: &axum::Router, id: &str) -> serde_json::Value {
    let (status, body) = send(app, "GET", &format!("/v1/approvals/{id}"), false, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn every_approval_read_serves_the_parameters_the_call_would_run_with() {
    let (app, state, _sk) = gateway_with_device(41, "device:phone");
    hold_paddle_cancel(&state, "appr_paddle");

    let one = read(&app, "appr_paddle").await;
    let expected = serde_json::json!([
        { "path": "effective_from", "state": "shown", "value": "\"immediately\"" },
        { "path": "subscription_id", "state": "shown", "value": "\"sub_01h8x2k\"" },
    ]);
    assert_eq!(one["params_display"]["rows"], expected, "{one}");
    assert_eq!(one["params_display"]["complete"], true, "{one}");
    assert_eq!(one["params_display_full"]["rows"], expected, "{one}");
    assert_eq!(
        one["intent"], "Cancel the customer's subscription at the end of the billing period, as they asked.",
        "the agent's claim is served on its own, beside the parameters that contradict it"
    );
    assert_eq!(approval_display_digest_of(&one).ok().as_deref(), one["params_display"]["digest"].as_str());
    assert_eq!(approval_display_full_digest_of(&one).ok().as_deref(), one["params_display_full"]["digest"].as_str());

    let (_s, list) = send(&app, "GET", "/v1/approvals?status=pending", false, None).await;
    let listed = list["approvals"].as_array().unwrap().iter().find(|a| a["id"] == "appr_paddle").unwrap();
    assert_eq!(listed["params_display"], one["params_display"], "the queue and the detail agree");
    assert!(listed.get("params_display_full").is_none(), "only the single read carries the full rendering");
}

/// The attack: the approver is shown the agent's story and signs for the real parameters. Now the
/// device signs the digest of what it showed, and a rendering that is not this call's is refused.
#[tokio::test]
async fn a_signature_over_a_rendering_that_is_not_this_call_is_refused() {
    let (app, state, sk) = gateway_with_device(42, "device:phone");
    hold_paddle_cancel(&state, "appr_paddle");
    let served = read(&app, "appr_paddle").await;

    let fake = doctored(&served);
    let shown = approval_display_full_digest_of(&fake).expect("the doctored rendering is internally consistent");
    let signed = v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &shown);
    let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(body_of(&signed))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("parameters shown on the approving device"),
        "the refusal says why: {body}"
    );
    let row = state.service.store().get_approval("appr_paddle").unwrap().unwrap();
    assert_eq!(row.status, "pending", "nothing ran");
    assert!(row.signatures.is_empty(), "and no signature was recorded");

    let honest = approval_display_full_digest_of(&served).unwrap();
    let keyring = state.service.approver_keyring_snapshot();
    let outcome = state
        .service
        .verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &honest));
    assert!(matches!(outcome, SignedApprovalOutcome::Verified), "{}", describe(&outcome));
}

/// The compact digest is never enough to approve: an approve binds the full rendering's own domain.
#[tokio::test]
async fn an_approve_over_the_compact_rendering_is_refused() {
    let (app, state, sk) = gateway_with_device(50, "device:phone");
    hold_paddle_cancel(&state, "appr_paddle");
    let served = read(&app, "appr_paddle").await;
    let compact = approval_display_digest_of(&served).unwrap();
    let keyring = state.service.approver_keyring_snapshot();
    let outcome = state
        .service
        .verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &compact));
    assert!(matches!(outcome, SignedApprovalOutcome::Refused(ref why) if why.contains("parameters shown")), "{}", describe(&outcome));
}

/// The padding probe: 32 keys that sort first push `effective_from` off the card. The card
/// says it is incomplete, and the full rendering, the one an approve binds, still shows it.
#[tokio::test]
async fn padding_can_push_a_parameter_off_the_card_but_never_out_of_what_is_approved() {
    let (app, state, sk) = gateway_with_device(49, "device:phone");
    let mut params = serde_json::Map::new();
    for i in 0..32 {
        params.insert(format!("A{i:02}"), serde_json::json!("x"));
    }
    params.insert("subscription_id".into(), serde_json::json!("sub_01h8x2k"));
    params.insert("effective_from".into(), serde_json::json!("immediately"));
    hold(&state, "appr_padded", serde_json::Value::Object(params));
    let served = read(&app, "appr_padded").await;

    let compact = &served["params_display"];
    assert_eq!(compact["complete"], false, "{compact}");
    assert!(compact["omitted"].as_u64().unwrap() > 0);
    assert!(!compact["rows"].as_array().unwrap().iter().any(|r| r["path"] == "effective_from"));
    assert!(approval_shown_full_digest(&{
        let mut card = served.clone();
        card.as_object_mut().unwrap().remove("params_display_full");
        card
    })
    .is_err(), "a surface that showed only the card has shown less than the call");

    let full = served["params_display_full"]["rows"].as_array().unwrap();
    assert!(full.iter().any(|r| r["path"] == "effective_from" && r["value"] == "\"immediately\""), "{served}");
    let keyring = state.service.approver_keyring_snapshot();
    let digest = approval_display_full_digest_of(&served).unwrap();
    let outcome = state.service.verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &digest));
    assert!(matches!(outcome, SignedApprovalOutcome::Verified), "{}", describe(&outcome));
}

/// A call too large to render whole is served as `too_large`, and nothing can approve it; a device
/// can still deny it.
#[tokio::test]
async fn a_call_too_large_to_show_whole_can_only_be_denied() {
    let (app, state, sk) = gateway_with_device(51, "device:phone");
    let big: Vec<serde_json::Value> = (0..20_000).map(|i| serde_json::json!({ "k": i, "s": "abcdefghij".repeat(3) })).collect();
    hold(&state, "appr_big", serde_json::json!({ "effective_from": "immediately", "items": big }));
    let served = read(&app, "appr_big").await;
    assert_eq!(served["params_display_full"]["too_large"], true, "{}", served["params_display_full"]);
    assert!(served["params_display_full"].get("rows").is_none());
    let err = approval_display_full_digest_of(&served).unwrap_err();
    assert!(err.contains("too large") && err.contains("policy rung"), "{err}");

    // Whatever digest a device sends, the gateway renders the call itself and refuses.
    let compact = approval_display_digest_of(&served).unwrap();
    let (status, body) =
        send(&app, "POST", "/v1/approvals", false, Some(body_of(&v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &compact)))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("too large to show in full"), "{body}");

    // Checked at the verifier, where a REST and a relayed decision meet: the held capability is not in
    // the demo estate, so resolving it over REST would stop at the capability lookup instead.
    let keyring = state.service.approver_keyring_snapshot();
    let deny = state.service.verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, false, served["approval_audience"].as_str(), &compact));
    assert!(!matches!(deny, SignedApprovalOutcome::Refused(_)), "a denial still lands: {}", describe(&deny));
}

/// A deny binds nothing that runs, so a v3 deny over a rendering that differs is still a deny.
#[tokio::test]
async fn a_v3_deny_over_another_rendering_still_denies() {
    let (app, state, sk) = gateway_with_device(48, "device:phone");
    let audience = state.service.approval_audience().unwrap();
    hold_paddle_cancel(&state, "appr_paddle");
    let served = read(&app, "appr_paddle").await;
    let fake = approval_display_full_digest_of(&doctored(&served)).unwrap();
    let keyring = state.service.approver_keyring_snapshot();
    let deny = state.service.verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, false, Some(&audience), &fake));
    assert!(!matches!(deny, SignedApprovalOutcome::Refused(_)), "{}", describe(&deny));
}

/// The other half of the binding: a signature over the right rendering cannot be redirected onto
/// another digest by whoever relays it.
#[tokio::test]
async fn a_relayed_digest_that_differs_from_the_signed_one_fails_verification() {
    let (app, state, sk) = gateway_with_device(43, "device:phone");
    hold_paddle_cancel(&state, "appr_paddle");
    let served = read(&app, "appr_paddle").await;
    let honest = approval_display_full_digest_of(&served).unwrap();
    let fake = approval_display_full_digest_of(&doctored(&served)).unwrap();
    let mut swapped = v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &fake);
    swapped.display_digest = Some(honest);
    let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(body_of(&swapped))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("did not verify"), "{body}");
}

/// End to end through REST on a hold that runs cleanly: a v3 signature over what was served resolves
/// it, without an audience (only where the gateway still takes signatures that name none) and then
/// with one (the other order is the v2 ratchet's refusal).
#[tokio::test]
async fn a_device_that_signs_what_it_was_shown_resolves_the_hold() {
    let (app, state, sk) = gateway_with_device(44, "device:phone");
    state.service.set_accept_v1_device_signatures(true);
    let audience = state.service.approval_audience().unwrap();
    for bound in [None, Some(audience.as_str())] {
        let (_s, _b) = send(&app, "PUT", "/v1/approval-floor", false, Some(serde_json::json!({ "floor": "device_signed" }))).await;
        let (status, held) = send(&app, "PUT", "/v1/approval-floor", false, Some(serde_json::json!({ "floor": "approve" }))).await;
        assert_eq!(status, StatusCode::ACCEPTED, "setup: lowering the floor is held: {held}");
        let id = held["approval_id"].as_str().unwrap();
        let served = read(&app, id).await;
        assert!(
            served["params_display_full"]["rows"].as_array().unwrap().iter().any(|r| r["path"] == "floor" && r["value"] == "\"approve\""),
            "the floor being set is on screen: {served}"
        );
        let shown = approval_display_full_digest_of(&served).unwrap();
        let signed = v3_result(&sk, "device:phone", &served, true, bound, &shown);
        let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(body_of(&signed))).await;
        assert_eq!(status, StatusCode::OK, "audience {bound:?}: {body}");
        assert!(!state.service.require_device_signed_approval(), "the change landed");
    }
}

/// The audience and display bindings as the defaults, with nothing set in the environment. A device with no pin for this
/// gateway (paired before the audience existed, or never pinned) signs with no audience; it is refused,
/// and the words say it has to be paired again, because the phone shows them as its re-pair message.
/// An approve that does not bind what the approver was shown is refused too.
#[tokio::test]
async fn by_default_an_unpinned_device_is_told_to_pair_again_and_a_blind_approve_is_refused() {
    let (app, state, sk) = gateway_with_device(53, "device:phone");
    assert!(!state.service.accepts_v1_device_signatures(), "v1 is refused by default");
    assert!(state.service.requires_display_bound_approvals(), "the display binding is required by default");
    hold_paddle_cancel(&state, "appr_paddle");
    let served = read(&app, "appr_paddle").await;
    let shown = approval_display_full_digest_of(&served).unwrap();

    let unpinned = v3_result(&sk, "device:phone", &served, true, None, &shown);
    let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(body_of(&unpinned))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let why = body["error"].as_str().unwrap_or_default();
    assert!(why.contains("must be paired with this gateway again"), "the refusal says to pair again: {body}");
    assert!(!why.contains('\u{2014}'), "{why}");
    let mut blank = unpinned.clone();
    blank.audience = Some(String::new());
    let (status, body) = send(&app, "POST", "/v1/approvals", false, Some(body_of(&blank))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("paired with this gateway again"), "an empty audience is no pin: {body}");

    let keyring = state.service.approver_keyring_snapshot();
    let audience = state.service.approval_audience().unwrap();
    let rh = served["request_hash"].as_str().unwrap();
    let blind = state.service.verify_signed_approval(&keyring, &v2_result(&sk, "appr_paddle", rh, true, &audience));
    assert!(matches!(blind, SignedApprovalOutcome::Refused(ref why) if why.contains("only approvals that bind")), "{}", describe(&blind));

    let pinned = state
        .service
        .verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, Some(&audience), &shown));
    assert!(matches!(pinned, SignedApprovalOutcome::Verified), "a current, pinned device approves: {}", describe(&pinned));
}

/// A v3 signature with no audience is held to the v1 rules, so binding the display never widens
/// which gateways a signature is good for.
#[tokio::test]
async fn a_display_bound_signature_with_no_audience_follows_the_v1_rules() {
    let (app, state, sk) = gateway_with_device(45, "device:phone");
    hold_paddle_cancel(&state, "appr_paddle");
    let served = read(&app, "appr_paddle").await;
    let shown = approval_display_full_digest_of(&served).unwrap();
    let keyring = state.service.approver_keyring_snapshot();

    state.service.set_accept_v1_device_signatures(false);
    let refused = state
        .service
        .verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, None, &shown));
    assert!(matches!(refused, SignedApprovalOutcome::Refused(ref why) if why.contains("paired with this gateway again")), "{}", describe(&refused));

    let audience = state.service.approval_audience().unwrap();
    let bound = state
        .service
        .verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, Some(&audience), &shown));
    assert!(matches!(bound, SignedApprovalOutcome::Verified), "{}", describe(&bound));

    let elsewhere = state
        .service
        .verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, Some("aud_other"), &shown));
    assert!(matches!(elsewhere, SignedApprovalOutcome::Refused(ref why) if why.contains("different gateway")), "{}", describe(&elsewhere));
}

/// An app that predates the rendering keeps working until its first v3 signature. After that, an
/// approval from the same approver that does not bind the display did not come from its app, and is
/// refused; a denial is not, because it runs nothing.
#[tokio::test]
async fn an_approver_that_has_signed_what_it_saw_cannot_approve_blind() {
    let (app, state, sk) = gateway_with_device(46, "device:phone");
    state.service.set_require_display_bound_approvals(false);
    let audience = state.service.approval_audience().unwrap();
    hold_paddle_cancel(&state, "appr_one");
    let keyring = state.service.approver_keyring_snapshot();
    let rh = request_hash(PADDLE_CAP, &serde_json::json!({ "subscription_id": "sub_01h8x2k", "effective_from": "immediately" }));
    assert!(matches!(state.service.verify_signed_approval(&keyring, &v2_result(&sk, "appr_one", &rh, true, &audience)), SignedApprovalOutcome::Verified));

    hold_paddle_cancel(&state, "appr_two");
    let second = read(&app, "appr_two").await;
    let shown = approval_display_full_digest_of(&second).unwrap();
    let outcome = state
        .service
        .verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &second, true, Some(&audience), &shown));
    assert!(matches!(outcome, SignedApprovalOutcome::Verified), "{}", describe(&outcome));

    hold_paddle_cancel(&state, "appr_three");
    let blind = state.service.verify_signed_approval(&keyring, &v2_result(&sk, "appr_three", &rh, true, &audience));
    assert!(matches!(blind, SignedApprovalOutcome::Refused(ref why) if why.contains("parameters shown before")), "{}", describe(&blind));
    let deny = state.service.verify_signed_approval(&keyring, &v2_result(&sk, "appr_three", &rh, false, &audience));
    assert!(!matches!(deny, SignedApprovalOutcome::Refused(_)), "a denial still lands: {}", describe(&deny));
}

/// `PERMAURA_REQUIRE_DISPLAY_BOUND_APPROVALS`: on by default, so no approve without the display binding,
/// from any approver, whatever it has signed before; a denial still lands. Turned off, an approver that
/// has never signed v3 can approve unbound again.
#[tokio::test]
async fn the_gateway_requires_the_display_binding_on_every_approve_unless_opted_out() {
    let (_app, state, sk) = gateway_with_device(52, "device:phone");
    let audience = state.service.approval_audience().unwrap();
    hold_paddle_cancel(&state, "appr_one");
    let rh = request_hash(PADDLE_CAP, &serde_json::json!({ "subscription_id": "sub_01h8x2k", "effective_from": "immediately" }));
    let keyring = state.service.approver_keyring_snapshot();
    assert!(state.service.requires_display_bound_approvals(), "on by default");
    let refused = state.service.verify_signed_approval(&keyring, &v2_result(&sk, "appr_one", &rh, true, &audience));
    assert!(matches!(refused, SignedApprovalOutcome::Refused(ref why) if why.contains("only approvals that bind")), "{}", describe(&refused));
    let deny = state.service.verify_signed_approval(&keyring, &v2_result(&sk, "appr_one", &rh, false, &audience));
    assert!(!matches!(deny, SignedApprovalOutcome::Refused(_)), "{}", describe(&deny));

    state.service.set_require_display_bound_approvals(false);
    hold_paddle_cancel(&state, "appr_two");
    let unbound = state.service.verify_signed_approval(&keyring, &v2_result(&sk, "appr_two", &rh, true, &audience));
    assert!(matches!(unbound, SignedApprovalOutcome::Verified), "{}", describe(&unbound));
}

/// The credential a held change carries never reaches an approval surface. The secret has no prefix
/// any value rule knows, so only the sealed-kind rule keeps it off the screen.
#[tokio::test]
async fn a_held_credential_change_serves_no_part_of_the_secret() {
    const SECRET: &str = "Zq8mWv3pLt6nRx1kYc4hBf7s";
    let (app, state, _sk) = gateway_with_device(47, "device:phone");

    let (status, held) = send(
        &app,
        "POST",
        "/v1/connections/braintree_production/credential",
        true,
        Some(serde_json::json!({ "value": SECRET })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let id = held["approval_id"].as_str().unwrap().to_string();

    let mut carried = state.service.store().get_approval(&id).unwrap().unwrap();
    carried.id = "appr_carries_value".into();
    carried.params = serde_json::json!({
        "kind": "credential_set",
        "connection_id": "braintree_production",
        "value": SECRET,
        "previous": { "value": SECRET },
        "material_id": { "raw": SECRET },
    }).into();
    state.service.store().put_approval(carried).unwrap();

    for uri in [
        format!("/v1/approvals/{id}"),
        "/v1/approvals/appr_carries_value".to_string(),
        "/v1/approvals".to_string(),
        "/v1/approvals?status=pending".to_string(),
    ] {
        let text = raw(&app, &uri).await;
        assert!(!text.contains(SECRET), "{uri} leaked the secret: {text}");
        assert!(!text.contains("Zq8mWv3p"), "{uri} leaked part of it: {text}");
    }
    let one = read(&app, "appr_carries_value").await;
    for rows in [&one["params_display"]["rows"], &one["params_display_full"]["rows"]] {
        assert!(
            rows.as_array().unwrap().iter().any(|r| r["path"] == "value"
                && r["state"] == DisplayState::Redacted.as_str()
                && r["value"] == "set, 24 characters"),
            "the approver is told a value is set and how long it is: {one}"
        );
        assert!(
            rows.as_array().unwrap().iter().any(|r| r["path"] == "connection_id" && r["value"] == "\"braintree_production\""),
            "and which connection it is for: {one}"
        );
    }
}

/// The connection's own redaction list, the one its results are redacted with, also redacts what the
/// approver sees.
#[tokio::test]
async fn the_connections_redaction_list_redacts_the_rendering_too() {
    let (app, state, _sk) = gateway_with_device(53, "device:phone");
    let store = state.service.store();
    let mut connection = store.get_connection("braintree_production").unwrap().unwrap();
    connection.redact_fields.push("customer_email".into());
    store.put_connection(connection).unwrap();
    let mut a = hold(&state, "appr_bt", serde_json::json!({ "customer_email": "jo@example.com", "amount": 40 }));
    a.resource = "braintree_production".into();
    store.put_approval(a).unwrap();
    let one = read(&app, "appr_bt").await;
    let rows = one["params_display_full"]["rows"].as_array().unwrap();
    assert!(rows.iter().any(|r| r["path"] == "customer_email" && r["state"] == "redacted"), "{one}");
    assert!(!raw(&app, "/v1/approvals/appr_bt").await.contains("jo@example.com"));
}

/// For a capability with a pinned request shape only the parameters it forwards are rendered, so a
/// card cannot be padded with keys the call never sends.
#[tokio::test]
async fn only_the_parameters_a_pinned_shape_forwards_are_shown() {
    let (app, state, _sk) = gateway_with_device(54, "device:phone");
    let store = state.service.store();
    let mut cap = store.list_capabilities().unwrap().into_iter().next().expect("a seeded capability");
    cap.id = PADDLE_CAP.into();
    cap.http = Some(permaura_gateway::connectors::HttpSpec {
        base_url: "https://api.paddle.com".into(),
        path: "/subscriptions/{subscription_id}/cancel".into(),
        path_params: vec!["subscription_id".into()],
        body_params: vec!["effective_from".into()],
        ..Default::default()
    });
    store.put_capability(cap).unwrap();
    let mut params = serde_json::Map::new();
    for i in 0..40 {
        params.insert(format!("A{i:02}"), serde_json::json!("padding"));
    }
    params.insert("subscription_id".into(), serde_json::json!("sub_01h8x2k"));
    params.insert("effective_from".into(), serde_json::json!("immediately"));
    hold(&state, "appr_pinned", serde_json::Value::Object(params));
    let one = read(&app, "appr_pinned").await;
    let paths: Vec<&str> =
        one["params_display"]["rows"].as_array().unwrap().iter().map(|r| r["path"].as_str().unwrap()).collect();
    assert_eq!(paths, vec!["effective_from", "subscription_id"], "{one}");
    assert_eq!(one["params_display"]["complete"], true);
}

/// The text fields a surface prints are escaped the way values are, and the digest binds the escaped
/// form, so a direction override in a capability description cannot make it read as something else.
#[tokio::test]
async fn the_served_text_fields_are_escaped_and_bound() {
    let (app, state, _sk) = gateway_with_device(55, "device:phone");
    let mut a = hold_paddle_cancel(&state, "appr_text");
    a.action_description = Some("Cancel\u{202e}lanif".into());
    a.intent = Some("pаypal refund\nnow".into());
    state.service.store().put_approval(a).unwrap();
    let one = read(&app, "appr_text").await;
    assert_eq!(one["action_description"], "Cancel\\u{202e}lanif", "{one}");
    assert_eq!(one["intent"], "p\\u{0430}ypal refund\\nnow", "{one}");
    assert!(approval_display_full_digest_of(&one).is_ok(), "the digest is over the escaped text a surface prints");
}

/// An agent's `reason` is kept on the hold and served as `intent`, the agent's claim, apart from the
/// gateway's own message, and it is not one of the parameters.
#[tokio::test]
async fn an_agents_stated_reason_is_served_as_its_intent() {
    let (app, _state, _sk) = gateway_with_device(56, "device:phone");
    let (status, body) = send(&app, "POST", "/mcp", false, Some(serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "github.pull_requests.create", "arguments": {
            "repo": "synthetic/permaura-web", "title": "Docs typo", "head": "agent/rewrite-auth", "base": "main",
            "reason": "Open a draft PR against my scratch branch",
        } },
    }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body.to_string().split("appr_").nth(1).map(|t| format!("appr_{}", &t[..32])).expect("held");
    let one = read(&app, &id).await;
    assert_eq!(one["intent"], "Open a draft PR against my scratch branch", "{one}");
    assert_eq!(one["message"], "Approve 'pull_requests.create' on 'github_acme'?", "{one}");
    let rows = one["params_display_full"]["rows"].as_array().unwrap();
    assert!(rows.iter().any(|r| r["path"] == "base" && r["value"] == "\"main\""), "{one}");
    assert!(!rows.iter().any(|r| r["path"] == "reason"), "the reason is not a parameter: {one}");
}

fn budget(release_ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(if cfg!(debug_assertions) { release_ms * 10 } else { release_ms })
}

/// The queue stall: one agent's adversarial reason or parameter cost seconds per list read
/// at 16 KB and most of a minute at 64 KB, for every reader of the queue. With several such holds
/// pending, reading the queue and each hold stays fast.
#[tokio::test]
async fn adversarial_holds_do_not_stall_the_queue_or_the_detail_read() {
    let (app, state, _sk) = gateway_with_device(57, "device:phone");
    for (n, unit) in ["a.", "sk-", "eyJ.", "x=", "digest a=", "password="].iter().enumerate() {
        let big = unit.repeat(256 * 1024 / unit.len());
        let mut a = hold(&state, &format!("appr_adv_{n}"), serde_json::json!({ "body": big.clone(), "note": "ok" }));
        a.intent = Some(big);
        state.service.store().put_approval(a).unwrap();
    }
    let started = std::time::Instant::now();
    let (status, list) = send(&app, "GET", "/v1/approvals?status=pending", false, None).await;
    let list_took = started.elapsed();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["approvals"].as_array().unwrap().len(), 6);
    assert!(list_took < budget(400), "the queue read took {list_took:?}");
    for n in 0..6 {
        let started = std::time::Instant::now();
        let one = read(&app, &format!("appr_adv_{n}")).await;
        let took = started.elapsed();
        assert!(took < budget(400), "the detail read of hold {n} took {took:?}");
        assert!(one["intent"].as_str().unwrap().chars().count() < 400, "the served intent stays cut");
    }
}

/// An agent's reason is cut and masked before it is stored anywhere, the hold and the audit chain
/// included, because every member who reads the audit log reads it.
#[tokio::test]
async fn an_agents_long_reason_is_cut_and_masked_where_it_is_stored() {
    let (app, state, _sk) = gateway_with_device(58, "device:phone");
    let reason = format!("rotate with ghp_abcdefghijklmnopqrstuvwxyz0123 {}", "z".repeat(100_000));
    let (status, body) = send(&app, "POST", "/mcp", false, Some(serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "github.pull_requests.create", "arguments": {
            "repo": "synthetic/permaura-web", "title": "x", "head": "h", "base": "main", "reason": reason,
        } },
    }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body.to_string().split("appr_").nth(1).map(|t| format!("appr_{}", &t[..32])).expect("held");
    let held = state.service.store().get_approval(&id).unwrap().unwrap();
    let kept = held.intent.unwrap();
    assert!(kept.len() <= permaura_gateway::approval_display::MAX_STORED_INTENT_BYTES + 64, "{}", kept.len());
    assert!(kept.contains("[redacted]") && !kept.contains("ghp_abcdefghijklmnopqrstuvwxyz0123"));
    assert!(kept.contains("cut from"), "it says it was cut");
    let audit = raw(&app, "/v1/audit-events?limit=50").await;
    assert!(!audit.contains("ghp_abcdefghijklmnopqrstuvwxyz0123"), "the audit chain never saw the token");
    assert!(!audit.contains(&"z".repeat(5_000)), "nor the whole reason");
}

/// A held settings change is titled with the names the owner gave things and carries a plain note, the
/// row stores exactly that text, and the digests over it verify: the gateway digests what it stored, so
/// rewording the title needs nothing from the signing contract.
#[tokio::test]
async fn a_held_settings_change_is_titled_by_name_and_its_digests_verify() {
    let (app, state, sk) = gateway_with_device(59, "device:phone");
    let (status, held) = send(
        &app,
        "POST",
        "/v1/connections/github_acme/credential",
        true,
        Some(serde_json::json!({ "value": "ghp_synthetic_for_the_hold" })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let title = "Save the new credential for \u{201c}GitHub \u{b7} GitHub (@github_acme)\u{201d}, sent to api.github.com";
    assert_eq!(held["action_description"], title, "{held}");
    assert_eq!(held["message"], permaura_gateway::rest::HELD_REQUESTED_NOTE, "{held}");

    let id = held["approval_id"].as_str().unwrap();
    let row = state.service.store().get_approval(id).unwrap().unwrap();
    assert_eq!(row.action_description.as_deref(), Some(title));
    assert_eq!(row.message, permaura_gateway::rest::HELD_REQUESTED_NOTE);
    assert_eq!(row.resource, "control-plane");
    assert_eq!(row.params.to_value_unbounded()["kind"], "credential_promote", "the ids stay in the params for the details view");
    assert_eq!(row.params.to_value_unbounded()["connection_id"], "github_acme");

    let served = read(&app, id).await;
    assert_eq!(served["action_description"], title, "{served}");
    assert_eq!(served["message"], permaura_gateway::rest::HELD_REQUESTED_NOTE, "{served}");
    for field in ["action_description", "message", "risk"] {
        assert_eq!(held[field], served[field], "the 202 and the served approval agree on {field}");
    }
    assert_eq!(approval_display_digest_of(&served).ok().as_deref(), served["params_display"]["digest"].as_str());
    let digest = approval_display_full_digest_of(&served).unwrap();
    assert_eq!(Some(digest.as_str()), served["params_display_full"]["digest"].as_str());
    let keyring = state.service.approver_keyring_snapshot();
    let outcome = state.service.verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &digest));
    assert!(matches!(outcome, SignedApprovalOutcome::Verified), "{}", describe(&outcome));
}

/// A repoint of an SSH connection names the connection and the new host, and a delete held over
/// loopback says why it needs a device rather than claiming it came through the account.
#[tokio::test]
async fn held_connection_changes_name_the_connection_and_say_why_they_are_held() {
    let (app, _state, _sk) = gateway_with_device(60, "device:phone");
    let (status, held) = send(
        &app,
        "PATCH",
        "/v1/connections/ssh_prod",
        true,
        Some(serde_json::json!({ "ssh": { "host": "db2.internal" } })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(
        held["action_description"],
        "Change the connection \u{201c}SSH \u{b7} SSH (db1.internal)\u{201d}: change its SSH host to \u{201c}db2.internal\u{201d}",
        "{held}"
    );
    assert_eq!(held["message"], permaura_gateway::rest::HELD_REQUESTED_NOTE, "{held}");

    let (status, held) = send(&app, "DELETE", "/v1/connections/github_acme", false, None).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(
        held["action_description"],
        "Delete the connection \u{201c}GitHub \u{b7} GitHub (@github_acme)\u{201d} and everything that uses it",
        "{held}"
    );
    assert_eq!(held["message"], permaura_gateway::rest::HELD_DESTRUCTIVE_NOTE, "{held}");
}

/// The names in a held change's title come from the gateway's own records at hold time: the policy,
/// grant, agent and device names, and the connection a saved credential belongs to.
#[tokio::test]
async fn held_titles_read_names_from_the_gateways_own_records() {
    use permaura_gateway::policy_guard::Mutation;
    let (_app, state, sk) = gateway_with_device(61, "device:phone");
    state.service.enroll_device(permaura_gateway::push::Device {
        id: "device_1".into(),
        name: "Sam's iPhone".into(),
        platform: Some("ios".into()),
        push_token: None,
        approver_id: Some("device:phone".into()),
        approver_pubkey: Some(pubkey_of(&sk)),
        enrolled_at: now_ms(),
        revoked: false,
    });
    let describe = |m: Mutation| state.service.describe_mutation(&m);
    assert_eq!(
        describe(Mutation::PolicyDelete { policy_id: "pol_github_prs".into() }),
        "Delete the policy \u{201c}Pull requests\u{201d} for \u{201c}GitHub \u{b7} GitHub (@github_acme)\u{201d}"
    );
    assert_eq!(
        describe(Mutation::GrantDelete { grant_id: "gr_ssh_prod".into() }),
        "Delete the grant \u{201c}SSH ops\u{201d}"
    );
    assert_eq!(
        describe(Mutation::AgentApprove { agent_id: "codex-cli".into() }),
        "Let the agent \u{201c}Codex CLI\u{201d} connect"
    );
    assert_eq!(
        describe(Mutation::SecretDelete { secret_id: "sec_github_acme".into() }),
        "Delete the saved credential for \u{201c}GitHub \u{b7} GitHub (@github_acme)\u{201d}"
    );
    assert_eq!(
        describe(Mutation::ApproverKeyRevoke { approver_id: "device:phone".into() }),
        "Remove \u{201c}Sam's iPhone\u{201d}, the last trusted device. After this nothing will need a device signature"
    );
    let rotated = ed25519_dalek::SigningKey::from_bytes(&[62; 32]);
    let title = describe(Mutation::ApproverKeyTrust {
        approver_id: "device:phone".into(),
        approver_pubkey: pubkey_of(&rotated),
        person: None,
        replaces: None,
    });
    assert!(title.starts_with("Replace the trusted key for \u{201c}Sam's iPhone\u{201d}: key "), "{title}");
}

/// A name is stored as written and spelled out once, where the title is served: a direction override
/// and a zero-width space each appear as one escape, a straight quote is served as it is inside the
/// curly quotes, and a curly quote in the name becomes a straight one so it cannot close the name. The
/// 202 the console reads shows exactly what a device is served and signs over.
#[tokio::test]
async fn a_held_title_is_escaped_once_and_the_202_matches_what_is_served() {
    let (app, state, sk) = gateway_with_device(63, "device:phone");
    let cases = [
        ("Helper\u{202e}tpircs\u{200b}bot", "Save the new credential for \u{201c}Helper\\u{202e}tpircs\\u{200b}bot\u{201d}, sent to api.github.com"),
        ("Sam's \"work\" Mac", "Save the new credential for \u{201c}Sam's \"work\" Mac\u{201d}, sent to api.github.com"),
        ("Prod\u{201d} and delete \u{201c}Billing", "Save the new credential for \u{201c}Prod\" and delete \"Billing\u{201d}, sent to api.github.com"),
    ];
    for (label, want) in cases {
        let store = state.service.store();
        let mut connection = store.get_connection("github_acme").unwrap().unwrap();
        connection.label = label.into();
        connection.name = label.into();
        store.put_connection(connection).unwrap();
        let (status, held) = send(
            &app,
            "POST",
            "/v1/connections/github_acme/credential",
            true,
            Some(serde_json::json!({ "value": "ghp_synthetic_for_the_hold" })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{held}");
        let served = read(&app, held["approval_id"].as_str().unwrap()).await;
        assert_eq!(served["action_description"], want, "{served}");
        assert!(!served["action_description"].as_str().unwrap().contains("\\\\"), "nothing is escaped twice: {served}");
        for field in ["action_description", "message", "risk"] {
            assert_eq!(held[field], served[field], "the 202 shows what the phone shows for {field}");
        }
        let digest = approval_display_full_digest_of(&served).unwrap();
        let keyring = state.service.approver_keyring_snapshot();
        let outcome =
            state.service.verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &digest));
        assert!(matches!(outcome, SignedApprovalOutcome::Verified), "{label:?}: {}", describe(&outcome));
    }
}

/// Editing an existing policy says what the edit changes, not just which policy it touches: the action
/// it loosens is in the title the row stores, the one every surface is served, and the 202, and the
/// digests over that title verify.
#[tokio::test]
async fn a_held_policy_edit_titles_what_it_changes() {
    let (app, state, sk) = gateway_with_device(64, "device:phone");
    let store = state.service.store();
    let mut policy = store.get_policy("pol_github_prs").unwrap().unwrap();
    policy.allow = vec!["pull_requests.list".into()];
    policy.requires_approval = vec!["pull_requests.create".into()];
    store.put_policy(policy).unwrap();

    let (status, held) = send(
        &app,
        "PUT",
        "/v1/policies/pol_github_prs",
        true,
        Some(serde_json::json!({
            "connection_id": "github_acme",
            "name": "Pull requests",
            "allow": ["pull_requests.list", "pull_requests.create"],
            "grant_ids": ["gr_github_prs"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    let title = "Change the policy \u{201c}Pull requests\u{201d} for \u{201c}GitHub \u{b7} GitHub (@github_acme)\u{201d}: pull_requests.create: \
                 needs approval \u{2192} runs without asking";
    let id = held["approval_id"].as_str().unwrap();
    let row = store.get_approval(id).unwrap().unwrap();
    assert_eq!(row.action_description.as_deref(), Some(title));
    assert_eq!(row.params.to_value_unbounded()["kind"], "policy_upsert", "the whole proposed policy stays in the params");

    let served = read(&app, id).await;
    assert_eq!(served["action_description"], title, "{served}");
    assert_eq!(held["action_description"], served["action_description"]);
    let digest = approval_display_full_digest_of(&served).unwrap();
    assert_eq!(Some(digest.as_str()), served["params_display_full"]["digest"].as_str());
    let keyring = state.service.approver_keyring_snapshot();
    let outcome = state.service.verify_signed_approval(&keyring, &v3_result(&sk, "device:phone", &served, true, served["approval_audience"].as_str(), &digest));
    assert!(matches!(outcome, SignedApprovalOutcome::Verified), "{}", describe(&outcome));
}

/// Hosted Production has two connections labelled "Gmail", told apart only by name, so a title names a
/// connection by its label and its name together whenever the two differ.
#[tokio::test]
async fn two_connections_with_one_label_are_told_apart_by_name() {
    let (app, state, _sk) = gateway_with_device(65, "device:phone");
    let store = state.service.store();
    let mut first = store.get_connection("github_acme").unwrap().unwrap();
    first.label = "Gmail".into();
    first.name = "t5-conn-3".into();
    store.put_connection(first.clone()).unwrap();
    store
        .put_connection(permaura_core::Connection {
            id: "github_two".into(),
            name: "t5-conn-6".into(),
            secret_id: "sec_github_two".into(),
            ..first
        })
        .unwrap();

    let mut titles = Vec::new();
    for id in ["github_acme", "github_two"] {
        let (status, held) = send(
            &app,
            "POST",
            &format!("/v1/connections/{id}/credential"),
            true,
            Some(serde_json::json!({ "value": "ghp_synthetic_for_the_hold" })),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{held}");
        let served = read(&app, held["approval_id"].as_str().unwrap()).await;
        titles.push(served["action_description"].as_str().unwrap().to_string());
    }
    assert_eq!(
        titles,
        [
            "Save the new credential for \u{201c}Gmail \u{b7} t5-conn-3\u{201d}, sent to api.github.com",
            "Save the new credential for \u{201c}Gmail \u{b7} t5-conn-6\u{201d}, sent to api.github.com",
        ]
    );

    let (status, held) = send(&app, "DELETE", "/v1/connections/github_two", false, None).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{held}");
    assert_eq!(
        held["action_description"],
        "Delete the connection \u{201c}Gmail \u{b7} t5-conn-6\u{201d} and everything that uses it"
    );
}
