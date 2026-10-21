//! The release-channel check, end to end: fetch → verify → compare → `/health`.
//!
//! The unit tests in `release.rs` cover signature verification and version ordering in isolation.
//! What they cannot cover is the part that decides whether the field is worth anything: that a
//! genuinely newer published release actually flips `manifest_behind` to `true`, and that a manifest
//! whose signature does not verify leaves it `null` rather than being believed.
//!
//! One test in its own binary, driving the states in sequence. The answer is process-global (it has
//! to be: `/health` reads it from a handler with no channel to a background task), so parallel
//! tests over it would race each other rather than test anything.

use std::io::{Read, Write};
use std::net::TcpListener;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use permaura_gateway::{build_router, AppState};
use tower::ServiceExt;

mod common;

/// The fixed DER header of an Ed25519 SubjectPublicKeyInfo: 12 bytes, then the raw 32-byte key.
/// Building the PEM here rather than shipping a fixture keeps the test honest: it verifies against a
/// key it derived from the signing key it actually signed with.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn spki_pem(key: &SigningKey) -> String {
    let mut der = SPKI_PREFIX.to_vec();
    der.extend_from_slice(key.verifying_key().as_bytes());
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        STANDARD.encode(der)
    )
}

/// Serve `body` at any path and `sig` at any path ending `.sig`, until the process ends.
fn serve(listener: TcpListener, body: Vec<u8>, sig: String) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let payload: Vec<u8> = if req.lines().next().unwrap_or("").contains(".sig") {
                sig.as_bytes().to_vec()
            } else {
                body.clone()
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&payload);
            let _ = stream.flush();
        }
    });
}

async fn manifest_behind_field(state: AppState) -> serde_json::Value {
    let token = common::operator_token(state.clone()).await;
    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["manifest_behind"].clone()
}

#[tokio::test]
async fn a_newer_published_release_flips_the_field_and_a_forged_one_does_not() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    // A version no gateway will ever legitimately be at, so the comparison is unambiguous whatever
    // this crate's version happens to be when the test runs.
    let manifest = br#"{"version":"999.0.0","assets":{}}"#.to_vec();
    let sig = STANDARD.encode(key.sign(&manifest).to_bytes());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local manifest listener");
    let port = listener.local_addr().unwrap().port();
    serve(listener, manifest, sig);

    std::env::set_var("PERMAURA_MANIFEST_URL", format!("http://127.0.0.1:{port}/gateway.json"));

    // ── 1. Nothing asked yet: null, never "current". ──────────────────────────────────────────
    assert!(
        manifest_behind_field(common::seeded()).await.is_null(),
        "a gateway that has not checked must not claim to be up to date"
    );

    // ── 2. A manifest signed by a key we do NOT trust changes nothing. ────────────────────────
    // This is the property the whole field rests on: the manifest lives on a mutable branch of a
    // public repo, so its contents are evidence of nothing without the pinned signature.
    std::env::set_var("PERMAURA_RELEASE_PUBKEY", spki_pem(&SigningKey::from_bytes(&[9u8; 32])));
    assert_eq!(permaura_gateway::release::check_now().await, None);
    assert!(
        manifest_behind_field(common::seeded()).await.is_null(),
        "an unverifiable manifest must leave the answer unknown, not believed"
    );

    // ── 3. With the signing key trusted, the same bytes flip it. ──────────────────────────────
    std::env::set_var("PERMAURA_RELEASE_PUBKEY", spki_pem(&key));
    assert_eq!(permaura_gateway::release::check_now().await, Some(true));
    assert_eq!(
        manifest_behind_field(common::seeded()).await,
        serde_json::json!(true)
    );
}
