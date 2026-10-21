//! `/health`'s answer to a challenge: proof that the gateway holds the operator token it
//! published, so a client can tell its gateway from whatever took the port while it was down without
//! sending the token to find out.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::health_proof::{proof, verify, CHALLENGE_HEADER, CONSOLE_PROOF_HEADER, PROOF_HEADER};
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

const CHALLENGE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `GET /health` against a router bound on `port`, with whatever headers are given. Returns the
/// proof header, if any, and the body.
async fn ask(state: AppState, port: u16, headers: &[(&str, &str)]) -> (Option<String>, serde_json::Value) {
    let mut req = Request::builder().uri("/health");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = build_router(state, format!("127.0.0.1:{port}").parse().unwrap())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let proof = resp
        .headers()
        .get(PROOF_HEADER)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (proof, serde_json::from_slice(&bytes).unwrap())
}

fn with_token(token: &str) -> AppState {
    let state = common::seeded();
    state.published_token.set(Some(token.to_string()));
    state
}

#[tokio::test]
async fn a_challenge_is_answered_with_the_proof_of_the_published_token() {
    let (got, body) = ask(with_token("pgt_published"), 7376, &[(CHALLENGE_HEADER, CHALLENGE)]).await;
    assert_eq!(got, proof("pgt_published", 7376, CHALLENGE));
    // The body is the unauthenticated one: a challenge proves nothing about the caller.
    assert_eq!(body, serde_json::json!({ "status": "ok", "service": "permaura-gateway" }));
}

#[tokio::test]
async fn the_proof_is_over_the_port_the_gateway_is_bound_to() {
    let (got, _) = ask(with_token("pgt_published"), 7399, &[(CHALLENGE_HEADER, CHALLENGE)]).await;
    assert_eq!(got, proof("pgt_published", 7399, CHALLENGE));
    assert_ne!(got, proof("pgt_published", 7376, CHALLENGE), "relayed to 7376 it must not verify");
}

#[tokio::test]
async fn the_proof_follows_the_token_when_it_is_replaced() {
    let state = with_token("pgt_before");
    let (before, _) = ask(state.clone(), 7376, &[(CHALLENGE_HEADER, CHALLENGE)]).await;
    state.published_token.set(Some("pgt_after".into()));
    let (after, _) = ask(state, 7376, &[(CHALLENGE_HEADER, CHALLENGE)]).await;
    assert_eq!(before, proof("pgt_before", 7376, CHALLENGE));
    assert_eq!(after, proof("pgt_after", 7376, CHALLENGE));
}

#[tokio::test]
async fn no_challenge_or_a_malformed_one_gets_no_proof_and_the_same_body() {
    let plain = serde_json::json!({ "status": "ok", "service": "permaura-gateway" });
    for headers in [
        vec![],
        vec![(CHALLENGE_HEADER, "short")],
        vec![(CHALLENGE_HEADER, &"a".repeat(65)[..])],
        vec![(CHALLENGE_HEADER, "0123456789abcdef0123+/==")],
    ] {
        let (got, body) = ask(with_token("pgt_published"), 7376, &headers).await;
        assert_eq!(got, None, "{headers:?}");
        assert_eq!(body, plain, "{headers:?}");
    }
}

/// A hosted worker, or a gateway whose store is outside its home, publishes no token, so there is
/// nothing a local client holds to check an answer against.
#[tokio::test]
async fn a_gateway_that_published_no_token_proves_nothing() {
    let state = common::seeded();
    state.published_token.set(None);
    let (got, _) = ask(state, 7376, &[(CHALLENGE_HEADER, CHALLENGE)]).await;
    assert_eq!(got, None);
}

/// The demo estate's operator bearer is the published constant, and the demo gateway proves that.
#[tokio::test]
async fn a_demo_gateway_proves_the_demo_bearer() {
    let (got, _) = ask(common::seeded(), 7376, &[(CHALLENGE_HEADER, CHALLENGE)]).await;
    assert_eq!(got, proof(permaura_gateway::seed::DEMO_TOKEN, 7376, CHALLENGE));
}

/// The bearer still reads the full status document (`permaura status`, the desktop's version and
/// conditions), and the proof rides along on it too.
#[tokio::test]
async fn an_operator_bearer_still_gets_the_full_document_with_the_proof() {
    let state = common::seeded();
    let token = common::operator_token(state.clone()).await;
    state.published_token.set(Some(token.clone()));
    let bearer = format!("Bearer {token}");
    let (got, body) = ask(
        state,
        7376,
        &[("authorization", bearer.as_str()), (CHALLENGE_HEADER, CHALLENGE)],
    )
    .await;
    assert_eq!(got, proof(&token, 7376, CHALLENGE));
    assert!(body["version"].is_string(), "{body}");
}

// ── The console sessions permaura.com holds ────────────────────────────────────────────────────

const ACKNOWLEDGED: &str = "pgc_console_acknowledged";
const PENDING: &str = "pgc_console_pending";

/// `GET /health` with a challenge, returning both proof headers.
async fn both_proofs(state: AppState, port: u16, challenge: &str) -> (Option<String>, Option<String>) {
    let resp = build_router(state, format!("127.0.0.1:{port}").parse().unwrap())
        .oneshot(Request::builder().uri("/health").header(CHALLENGE_HEADER, challenge).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let header = |name: &str| resp.headers().get(name).map(|v| v.to_str().unwrap().to_string());
    (header(PROOF_HEADER), header(CONSOLE_PROOF_HEADER))
}

/// The session permaura.com acknowledged is proved in its own header, keyed on that session exactly as the operator proof is keyed on the operator token.
#[tokio::test]
async fn an_acknowledged_console_session_is_proved_in_its_own_header() {
    let state = with_token("pgt_published");
    state.held_console_sessions.set(vec![ACKNOWLEDGED.into()]);
    let (operator, console) = both_proofs(state, 7376, CHALLENGE).await;
    let console = console.expect("a console proof");
    assert!(!console.contains(','), "one session, one proof: {console}");
    assert!(verify(ACKNOWLEDGED, 7376, CHALLENGE, &console), "{console}");
    assert_eq!(operator, proof("pgt_published", 7376, CHALLENGE), "the operator proof is still there");
}

/// A session minted but not yet acknowledged is proved too, newest first, so a browser handed either one can check the listener.
#[tokio::test]
async fn a_pending_console_session_is_proved_first_beside_the_acknowledged_one() {
    let state = with_token("pgt_published");
    state.held_console_sessions.set(vec![PENDING.into(), ACKNOWLEDGED.into()]);
    let (_, console) = both_proofs(state, 7399, CHALLENGE).await;
    let console = console.expect("console proofs");
    let proofs: Vec<&str> = console.split(',').collect();
    assert_eq!(proofs.len(), 2, "{console}");
    assert!(verify(PENDING, 7399, CHALLENGE, proofs[0]), "newest first: {console}");
    assert!(verify(ACKNOWLEDGED, 7399, CHALLENGE, proofs[1]), "{console}");
    assert!(!verify(PENDING, 7376, CHALLENGE, proofs[0]), "bound to the port like the operator proof");
}

/// The console reads at most four proofs, so the gateway lists no more than that: the newest four, newest first.
#[tokio::test]
async fn at_most_four_console_proofs_are_listed_newest_first() {
    let state = with_token("pgt_published");
    let sessions: Vec<String> = (1..=5).rev().map(|n| format!("pgc_console_session_{n}")).collect();
    state.held_console_sessions.set(sessions.clone());
    let (_, console) = both_proofs(state, 7376, CHALLENGE).await;
    let console = console.expect("console proofs");
    let proofs: Vec<&str> = console.split(',').collect();
    assert_eq!(proofs.len(), permaura_core::health_proof::CONSOLE_PROOF_MAX, "{console}");
    for (session, offered) in sessions.iter().zip(&proofs) {
        assert!(verify(session, 7376, CHALLENGE, offered), "{session}: {console}");
    }
}

/// With no console session (a public URL configured, or nothing minted yet) the console header is absent and the operator proof is unchanged.
#[tokio::test]
async fn no_console_session_means_no_console_header() {
    let state = with_token("pgt_published");
    state.held_console_sessions.set(Vec::new());
    let (operator, console) = both_proofs(state, 7376, CHALLENGE).await;
    assert_eq!(console, None);
    assert_eq!(operator, proof("pgt_published", 7376, CHALLENGE));

    let state = with_token("pgt_published");
    state.held_console_sessions.set(vec![ACKNOWLEDGED.into()]);
    for headers in [vec![], vec![(CHALLENGE_HEADER, "short")]] {
        let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
            .oneshot(headers.iter().fold(Request::builder().uri("/health"), |r, (k, v)| r.header(*k, *v)).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(resp.headers().get(CONSOLE_PROOF_HEADER).is_none(), "no valid challenge, no proof: {headers:?}");
    }
}

/// The operator proof is byte for byte the operator-proof test vector whatever console sessions are held.
#[tokio::test]
async fn the_operator_proof_is_unchanged_beside_console_sessions() {
    let state = with_token("pgt_ag01testvectortoken");
    state.held_console_sessions.set(vec![PENDING.into(), ACKNOWLEDGED.into()]);
    let (operator, _) = both_proofs(state, 7376, CHALLENGE).await;
    assert_eq!(operator.as_deref(), Some("4900eebce3ab46dfd1a9fa5d468d6f7021db4d73e4b37ba51fc75db2e223f767"));
}

/// The browser's contract, computed by the permaura.com console's own `healthProof` helper and copied unchanged into `fixtures/health-proof-contract.json`: every vector comes back from the real `/health`, in the header it names.
#[tokio::test]
async fn the_browser_contract_vectors_come_back_from_health() {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/health-proof-contract.json")).expect("the contract fixture parses");
    assert!(!vectors.is_empty());
    for v in &vectors {
        let (challenge, token, expected) =
            (v["challenge"].as_str().unwrap(), v["token"].as_str().unwrap(), v["expectedProof"].as_str().unwrap());
        let port = u16::try_from(v["port"].as_u64().unwrap()).unwrap();
        assert_eq!(proof(token, port, challenge).as_deref(), Some(expected), "{v}");

        let state = common::seeded();
        let console = v["header"].as_str().unwrap().eq_ignore_ascii_case(CONSOLE_PROOF_HEADER);
        if console {
            state.published_token.set(Some("pgt_not_the_key".into()));
            state.held_console_sessions.set(vec![token.to_string()]);
        } else {
            assert!(v["header"].as_str().unwrap().eq_ignore_ascii_case(PROOF_HEADER), "{v}");
            state.published_token.set(Some(token.to_string()));
        }
        let (operator, console_proof) = both_proofs(state, port, challenge).await;
        let got = if console { console_proof } else { operator };
        assert_eq!(got.as_deref(), Some(expected), "{v}");
    }
}
