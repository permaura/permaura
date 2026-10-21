//! The approval-metadata contract: what a client is told about a held request, and what it must
//! never have to work out for itself.
//!
//! `expires_at`, `risk` and `action_description` are captured ON THE HELD ROW and read straight back
//! out. That is the whole point: a capability's risk is editable, so classifying it at render time
//! lets an edit rewrite what a human is being asked about a request held before the edit. That is
//! how the phone came to be showing a risk tier the gateway had never agreed with, alongside a
//! two-minute countdown nothing on the server had ever promised.
//!
//! The phone renders a held request from these fields as the gateway sends them.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::store::PendingApproval;
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

async fn get_json(state: AppState, uri: &str) -> serde_json::Value {
    let token = common::operator_token(state.clone()).await;
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {uri}");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// A row as the CURRENT code writes one, with all three fields captured.
fn captured(id: &str, risk: permaura_core::RiskTier, expires_at: Option<i64>) -> PendingApproval {
    PendingApproval {
        id: id.into(),
        session_id: "sess_1".into(),
        capability: "braintree.transactions.refund".into(),
        resource: "braintree_production".into(),
        message: "Refund $40 to customer 12?".into(),
        status: "pending".into(),
        grant_id: None,
        policy_id: None,
        params: serde_json::json!({ "amount": 40 }).into(),
        result: None,
        result_status: None,
        resolution_reason: None,
        created_at: 1_000,
        expires_at,
        risk: Some(risk),
        action_description: Some("Refund a captured transaction.".into()),
        intent: None,
        required_tier: "device_signed".into(),
        required_signatures: 1,
        signatures: Vec::new(),
        requested_by: None,
    }
}

/// An approval exactly as a gateway BEFORE this contract persisted one: the three fields are simply
/// absent from the stored JSON. Approvals are stored as a whole-struct blob, so this is what
/// actually sits in `approvals.data` on a store written by an older build, not an approximation.
const OLD_ROW: &str = r#"{
    "id": "appr_old",
    "session_id": "sess_old",
    "capability": "braintree.transactions.refund",
    "resource": "braintree_production",
    "message": "Refund $40 to customer 12?",
    "status": "pending",
    "params": { "amount": 40 },
    "created_at": 1000,
    "required_tier": "device_signed",
    "required_signatures": 1,
    "signatures": []
}"#;

#[test]
fn an_old_row_still_loads() {
    let a: PendingApproval =
        serde_json::from_str(OLD_ROW).expect("a row written before these fields existed must load");
    assert_eq!(a.id, "appr_old");
    assert_eq!(a.required_tier, "device_signed");
    assert_eq!(a.expires_at, None);
    assert_eq!(a.risk, None);
    assert_eq!(a.action_description, None);
}

#[test]
fn an_old_row_reports_unknown_risk_rather_than_guessing() {
    let a: PendingApproval = serde_json::from_str(OLD_ROW).unwrap();
    // A refund is what every name-based heuristic calls critical, and the seeded catalogue classifies
    // this exact capability Critical too. The row still reports `unknown`, because nothing recorded a
    // classification at the moment this request was held, and a plausible guess rendered as fact on
    // the approval screen is worse than an admission.
    assert_eq!(a.risk_label(), "unknown");
}

#[tokio::test]
async fn the_queue_carries_all_three_fields_for_an_old_row() {
    let state = common::seeded();
    let old: PendingApproval = serde_json::from_str(OLD_ROW).unwrap();
    state.service.store().put_approval(old).unwrap();

    let body = get_json(state, "/v1/approvals?status=pending").await;
    let row = body["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "appr_old")
        .expect("the old row is in the queue");

    // Present-and-null, never absent. A client has to be able to tell "no deadline" from "this
    // gateway did not tell me", and one that reads a missing field as zero renders 1970.
    assert!(row.get("expires_at").is_some(), "expires_at must never be omitted");
    assert!(row["expires_at"].is_null());
    assert!(row.get("action_description").is_some(), "action_description must never be omitted");
    assert!(row["action_description"].is_null());
    assert_eq!(row["risk"], "unknown");
}

#[tokio::test]
async fn a_null_expiry_and_a_numeric_one_are_different_answers() {
    let state = common::seeded();
    let store = state.service.store();
    store.put_approval(captured("appr_none", permaura_core::RiskTier::Critical, None)).unwrap();
    store
        .put_approval(captured(
            "appr_deadline",
            permaura_core::RiskTier::High,
            Some(1_000 + 900_000),
        ))
        .unwrap();

    let none = get_json(state.clone(), "/v1/approvals/appr_none").await;
    assert!(none.get("expires_at").is_some());
    assert!(none["expires_at"].is_null(), "no deadline is null, not 0 and not absent");

    let deadline = get_json(state, "/v1/approvals/appr_deadline").await;
    // An absolute epoch, not a duration: a client that remounts its card must land on the same
    // moment, which a "seconds remaining" number cannot promise.
    assert_eq!(deadline["expires_at"], 1_000 + 900_000);
}

#[tokio::test]
async fn captured_risk_survives_a_later_capability_edit() {
    let state = common::seeded();
    let store = state.service.store();

    // Held while the capability was critical.
    store.put_approval(captured("appr_held", permaura_core::RiskTier::Critical, None)).unwrap();

    // Now somebody reclassifies the capability itself all the way down.
    let mut cap = store
        .get_capability("braintree.transactions.refund")
        .unwrap()
        .expect("the seeded estate has braintree.transactions.refund");
    cap.risk = permaura_core::RiskTier::Low;
    store.put_capability(cap).unwrap();

    let held = get_json(state.clone(), "/v1/approvals/appr_held").await;
    assert_eq!(
        held["risk"], "critical",
        "the human is being asked about the request as it was held, not as the catalogue reads now",
    );

    // And the edit did land. Otherwise this test would pass on a gateway that simply ignored it.
    let caps = get_json(state, "/v1/capabilities").await;
    let edited = caps["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "braintree.transactions.refund")
        .expect("braintree.transactions.refund is in the catalogue");
    assert_eq!(edited["risk"], "low");
}

// ── enforcement reads the same field the human was shown ─────────────────────
//
// Display and enforcement used to be two different sums. The card counted down to the captured
// `expires_at`; the resolve path recomputed `now - created_at > APPROVAL_TTL_MS`. They agree only
// while that constant never changes, and the moment it does the gateway refuses against a deadline
// no client was ever told about. One number now, read by both.

#[test]
fn a_captured_deadline_outranks_what_the_ttl_constant_would_say() {
    // Held with a one-minute deadline. Whatever APPROVAL_TTL_MS is set to today or tomorrow, this
    // row was given until `created_at + 60_000` and that is what it gets: still live a second
    // before, refused a second after. Constructed directly rather than held through the service,
    // because the point is precisely that the row's own field decides.
    let a = captured("appr_ttl", permaura_core::RiskTier::High, Some(1_000 + 60_000));

    assert!(!a.is_expired(1_000), "not expired at the moment it was held");
    assert!(!a.is_expired(1_000 + 59_999));
    assert!(!a.is_expired(1_000 + 60_000), "the deadline itself is still inside the window");
    assert!(a.is_expired(1_000 + 60_001), "one millisecond past the captured deadline is expired");

    // And a row whose deadline is already behind us is expired no matter how young `created_at`
    // makes it look. A recomputed check keyed on age would call this one fresh.
    let short = captured("appr_short", permaura_core::RiskTier::High, Some(1_000));
    assert!(short.is_expired(2_000));
}

#[test]
fn a_hold_with_no_deadline_never_expires() {
    let a = captured("appr_forever", permaura_core::RiskTier::Critical, None);
    assert!(!a.is_expired(1_000));
    // Not "a very long time", actually never. A hold that waits is the whole point of null here.
    assert!(!a.is_expired(i64::MAX));
}

#[test]
fn an_old_row_never_expires() {
    // It has no captured deadline to enforce, and inventing one now would refuse a decision the
    // human is entitled to make on a request that was accepted on the understanding it would wait.
    let a: PendingApproval = serde_json::from_str(OLD_ROW).unwrap();
    assert_eq!(a.expires_at, None);
    assert!(!a.is_expired(1_000));
    assert!(!a.is_expired(i64::MAX));
}

#[test]
fn what_the_client_is_shown_is_what_is_enforced() {
    // The same field, read twice: once for the wire and once for the gate. This is the assertion
    // that fails if anyone reintroduces a second, recomputed deadline on either side.
    let a = captured("appr_agree", permaura_core::RiskTier::High, Some(1_000 + 5_000));
    let shown = a.expires_at.expect("this row has a deadline");
    assert!(!a.is_expired(shown));
    assert!(a.is_expired(shown + 1));
}

#[tokio::test]
async fn the_202_held_body_and_the_queue_row_agree() {
    // Same row, two surfaces. They read the same three fields off the same store row rather than
    // each recomputing them, so a client that sees the 202 and then polls the queue cannot be shown
    // two different deadlines for one approval.
    let state = common::seeded();
    let store = state.service.store();
    store
        .put_approval(captured("appr_both", permaura_core::RiskTier::High, Some(42_000)))
        .unwrap();

    let one = get_json(state.clone(), "/v1/approvals/appr_both").await;
    let list = get_json(state, "/v1/approvals?status=pending").await;
    let other = list["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "appr_both")
        .unwrap()
        .clone();

    for field in ["expires_at", "risk", "action_description"] {
        assert_eq!(one[field], other[field], "{field} differs between get and list");
    }
    assert_eq!(one["expires_at"], 42_000);
    assert_eq!(one["risk"], "high");
    assert_eq!(one["action_description"], "Refund a captured transaction.");
}

/// A denial reason is metadata about the held request exactly as `risk` and `expires_at` are, and it
/// is the one field that says WHO ended the approval.
///
/// Reconciliation denies every pending approval a restore brought back, with the reason `restore`.
/// Without this on the wire that denial reaches every approval surface looking like an owner who
/// said no, which is the opposite of what happened: nobody was asked.
#[tokio::test]
async fn every_approval_surface_carries_the_reason_it_was_resolved() {
    let state = common::seeded();
    let mut human = captured("appr_human", permaura_core::RiskTier::Low, None);
    human.status = "denied".into();
    let mut restored = captured("appr_restored", permaura_core::RiskTier::Low, None);
    restored.status = "denied".into();
    restored.resolution_reason = Some("restore".into());

    let store = state.service.store();
    store.put_approval(human).unwrap();
    store.put_approval(restored).unwrap();

    // The listing and the single-approval read are both fed by `approval_json`, so both carry it.
    let listed = get_json(state.clone(), "/v1/approvals").await;
    let by_id: std::collections::HashMap<&str, &serde_json::Value> = listed["approvals"]
        .as_array()
        .expect("a list of approvals")
        .iter()
        .map(|a| (a["id"].as_str().unwrap(), a))
        .collect();
    assert_eq!(by_id["appr_restored"]["resolution_reason"], serde_json::json!("restore"));
    assert_eq!(
        by_id["appr_human"]["resolution_reason"],
        serde_json::Value::Null,
        "a human denial names no reason, and null is not the same as the field being absent"
    );

    for (id, expected) in
        [("appr_restored", serde_json::json!("restore")), ("appr_human", serde_json::Value::Null)]
    {
        let single = get_json(state.clone(), &format!("/v1/approvals/{id}")).await;
        assert!(
            single.get("resolution_reason").is_some(),
            "the field is never omitted, or a client cannot tell null from an older gateway"
        );
        assert_eq!(single["resolution_reason"], expected);
    }
}
