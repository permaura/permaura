//! OAuth refresh coordination beyond the refresh-race regression (`oauth_refresh_race.rs`).
//!
//! The token endpoint is the synthetic provider in `common::synthetic_oauth`: refreshes are held until
//! the test releases them and every refresh token is retired on first use, so each schedule here is
//! forced rather than hoped for and a lost rotation fails the next call the way a real provider would.
//! No network, no real keys or providers.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use common::synthetic_oauth::{
    allowed, cred, cred_with_refresh, describe, invoke, invoke_github, memory_service, put, service_over, stored,
    Provider, GITHUB_SECRET, OLD_REFRESH, TOKEN_URL,
};
use permaura_gateway::error::GatewayError;
use permaura_gateway::oauth_connect::{PendingAuth, PendingBinding};
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use tower::ServiceExt;

const VERCEL_SECRET: &str = "sec_vercel";

fn scratch_db(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("permaura-oauth-refresh-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("gateway.db").to_string_lossy().into_owned()
}

/// The adopted schedule 2 against a persistence-backed store: the conditional write has to be
/// atomic inside SQLite too, and the invocation that lost its refresh goes upstream with the new
/// authorization rather than with the token it refreshed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_backed_replacement_during_a_refresh_keeps_the_new_authorization() {
    common::isolate_from_the_real_install();
    let http = Provider::new();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&scratch_db("replace")).unwrap());
    let s = service_over(store, http.clone());

    let task = tokio::spawn(invoke_github(s.clone()));
    http.entered.notified().await;
    put(s.store().as_ref(), GITHUB_SECRET, &cred("synthetic-new-authorization", i64::MAX));
    http.release.add_permits(1);
    let outcome = task.await.unwrap();
    assert!(allowed(&outcome), "{}", describe(&outcome));

    let saved = stored(s.store().as_ref(), GITHUB_SECRET);
    assert_eq!(saved.access_token, "synthetic-new-authorization", "the stale refresh must not land");
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some(OLD_REFRESH));
    assert_eq!(http.refreshes(), 1);
    assert_eq!(
        http.upstream_authorization(),
        vec!["Bearer synthetic-new-authorization".to_string()],
        "the call retried with the replacement, not with the discarded refresh"
    );
}

/// The real `GET /oauth/callback` landing while an older refresh of the same slot is in flight. The
/// callback keeps its plain replace; the refresh that started first is the one that yields.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_byo_callback_wins_over_a_stale_refresh() {
    common::isolate_from_the_real_install();
    let http = Provider::new();
    let state = AppState::in_memory_seeded_with_http(http.clone());
    let s = state.service.clone();
    put(s.store().as_ref(), GITHUB_SECRET, &cred("synthetic-expired", 1));

    let task = tokio::spawn(invoke_github(s.clone()));
    http.entered.notified().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let connection = s.store().get_connection("github_acme").unwrap().unwrap();
    let operator = s.store().session_by_token(seed::DEMO_TOKEN).unwrap().unwrap();
    state.oauth_pending.insert(
        "synthetic-state".into(),
        PendingAuth {
            connection_id: "github_acme".into(),
            provider: "synthetic".into(),
            client_id: "synthetic-client".into(),
            client_secret: "synthetic-client-secret".into(),
            redirect_uri: "http://127.0.0.1:7376/oauth/callback".into(),
            token_url: TOKEN_URL.into(),
            code_verifier: None,
            scopes: vec![],
            created_ms: now,
            binding: PendingBinding::capture(&s, &connection, &operator, false).unwrap(),
        },
        now,
    );
    let resp = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(
            Request::builder()
                .uri("/oauth/callback?code=synthetic-code&state=synthetic-state")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page = String::from_utf8(axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
    assert!(page.contains("is connected"), "the callback completed: {page}");
    assert_eq!(stored(s.store().as_ref(), GITHUB_SECRET).access_token, "synthetic-new-authorization");

    http.release.add_permits(1);
    let outcome = task.await.unwrap();
    assert!(allowed(&outcome), "{}", describe(&outcome));
    let saved = stored(s.store().as_ref(), GITHUB_SECRET);
    assert_eq!(saved.access_token, "synthetic-new-authorization", "the older refresh overwrote the callback's result");
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some("synthetic-new-refresh"));
    assert_eq!(http.refreshes(), 1);
    assert_eq!(http.upstream_authorization(), vec!["Bearer synthetic-new-authorization".to_string()]);
}

/// The operator path. `send_with_credential` runs inside the request handler's own future, which
/// the inbound request timeout or a closed tab drops mid-refresh, after the provider has already
/// retired the old refresh token. The refresh runs detached from that future, so its rotation
/// lands anyway and the next call reuses it; before, the stored bundle kept the dead token and the
/// next call was refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operator_call_abandoned_mid_refresh_still_lands_its_rotation() {
    let (s, http) = memory_service();
    let cap = s.store().get_capability("github.pull_requests.list").unwrap().unwrap();
    let task = {
        let s = s.clone();
        tokio::spawn(async move {
            s.send_with_credential(&cap, &serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }))
                .await
                .map(|r| r.status)
        })
    };
    http.entered.notified().await;
    task.abort();
    assert!(matches!(task.await, Err(join) if join.is_cancelled()));
    assert_eq!(
        stored(s.store().as_ref(), GITHUB_SECRET).access_token,
        "synthetic-expired",
        "nothing is written while the refresh is still in flight"
    );

    http.release.add_permits(1);
    let outcome = tokio::time::timeout(Duration::from_secs(5), invoke_github(s.clone()))
        .await
        .expect("the next call was not blocked behind the abandoned refresh");
    assert!(allowed(&outcome), "{}", describe(&outcome));
    assert_eq!(http.refreshes(), 1, "the abandoned refresh's rotation was reused, not repeated");
    let saved = stored(s.store().as_ref(), GITHUB_SECRET);
    assert_eq!(saved.access_token, "synthetic-refreshed-0");
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some("synthetic-rotated-0"));
    assert_eq!(http.upstream_authorization(), vec!["Bearer synthetic-refreshed-0".to_string()]);
}

/// A caller dropped while still queued for the slot has nothing in flight: it leaves no task behind,
/// the holder's rotation lands as usual and the slot is free for the next call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_dropped_while_waiting_for_the_slot_leaves_it_free() {
    let (s, http) = memory_service();
    let holder = tokio::spawn(invoke_github(s.clone()));
    http.entered.notified().await;
    let cap = s.store().get_capability("github.pull_requests.list").unwrap().unwrap();
    let waiter = {
        let s = s.clone();
        tokio::spawn(async move {
            s.send_with_credential(&cap, &serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }))
                .await
                .map(|r| r.status)
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    waiter.abort();
    assert!(matches!(waiter.await, Err(join) if join.is_cancelled()));

    http.release.add_permits(1);
    let outcome = holder.await.unwrap();
    assert!(allowed(&outcome), "{}", describe(&outcome));
    let outcome = tokio::time::timeout(Duration::from_secs(5), invoke_github(s.clone()))
        .await
        .expect("the next call was not blocked behind the dropped waiter");
    assert!(allowed(&outcome), "{}", describe(&outcome));
    assert_eq!(http.refreshes(), 1, "the dropped waiter never reached the provider, and the next call reused the rotation");
    assert_eq!(http.upstream_authorization(), vec!["Bearer synthetic-refreshed-0".to_string(); 2]);
}

/// An agent invocation runs its execution in a task the caller's disconnect never aborts, so a
/// refresh the caller abandoned still completes: its rotation lands (a one-use refresh token the
/// provider has already consumed must not be lost) and the slot is released behind it. The next
/// call reuses that rotation rather than refreshing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invocation_abandoned_mid_refresh_still_lands_its_rotation() {
    let (s, http) = memory_service();
    let task = tokio::spawn(invoke_github(s.clone()));
    http.entered.notified().await;
    task.abort();
    assert!(matches!(task.await, Err(join) if join.is_cancelled()));
    assert_eq!(
        stored(s.store().as_ref(), GITHUB_SECRET).access_token,
        "synthetic-expired",
        "nothing is written while the refresh is still in flight"
    );

    http.release.add_permits(1);
    let outcome = tokio::time::timeout(Duration::from_secs(5), invoke_github(s.clone()))
        .await
        .expect("the next call was not blocked behind the abandoned execution");
    assert!(allowed(&outcome), "{}", describe(&outcome));
    assert_eq!(http.refreshes(), 1, "the abandoned execution's rotation was reused, not repeated");
    let saved = stored(s.store().as_ref(), GITHUB_SECRET);
    assert_eq!(saved.access_token, "synthetic-refreshed-0");
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some("synthetic-rotated-0"));
}

/// A refresh the provider refuses fails that call, writes nothing, and releases the slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_refresh_releases_the_slot_and_leaves_the_credential_untouched() {
    let (s, http) = memory_service();
    http.fail_next_refresh.store(true, Ordering::SeqCst);
    http.release.add_permits(1);
    let outcome = invoke_github(s.clone()).await;
    assert!(matches!(outcome, Err(GatewayError::Unauthorized(_))), "{}", describe(&outcome));
    let saved = stored(s.store().as_ref(), GITHUB_SECRET);
    assert_eq!(saved.access_token, "synthetic-expired", "a failed refresh wrote something");
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some(OLD_REFRESH));

    http.release.add_permits(1);
    let outcome = tokio::time::timeout(Duration::from_secs(5), invoke_github(s.clone()))
        .await
        .expect("the next call was not blocked behind the failed refresh");
    assert!(allowed(&outcome), "{}", describe(&outcome));
    assert_eq!(http.refreshes(), 2);
    assert_eq!(stored(s.store().as_ref(), GITHUB_SECRET).access_token, "synthetic-refreshed-1");
}

/// Coordination is per secret: a held refresh of one credential never delays another's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_credentials_refresh_concurrently() {
    let (s, http) = memory_service();
    put(
        s.store().as_ref(),
        VERCEL_SECRET,
        &cred_with_refresh("synthetic-expired-vercel", "synthetic-old-refresh-vercel", 1),
    );

    let github = tokio::spawn(invoke_github(s.clone()));
    http.entered.notified().await;
    let vercel = tokio::spawn(invoke(s.clone(), "vercel.projects.list", serde_json::json!({})));
    tokio::time::timeout(Duration::from_secs(5), http.entered.notified())
        .await
        .expect("the second credential's refresh waited behind the first's slot");
    assert_eq!(http.refreshes(), 2, "both refreshes are in flight at once");

    http.release.add_permits(2);
    let (a, b) = (github.await.unwrap(), vercel.await.unwrap());
    assert!(allowed(&a), "{}", describe(&a));
    assert!(allowed(&b), "{}", describe(&b));
    let tokens: std::collections::BTreeSet<String> = [GITHUB_SECRET, VERCEL_SECRET]
        .into_iter()
        .map(|id| stored(s.store().as_ref(), id).access_token.expose().to_string())
        .collect();
    assert_eq!(tokens.len(), 2, "each credential kept its own refresh: {tokens:?}");
}

/// The same one-use token under contention, with persistence: the second call queues behind the
/// first's slot, re-reads the rotation it persisted and goes upstream without a refresh of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_backed_concurrent_calls_share_one_refresh() {
    common::isolate_from_the_real_install();
    let http = Provider::new();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&scratch_db("share")).unwrap());
    let s = service_over(store, http.clone());

    let a = tokio::spawn(invoke_github(s.clone()));
    http.entered.notified().await;
    let b = tokio::spawn(invoke_github(s.clone()));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), http.entered.notified()).await.is_err(),
        "the second call sent its own refresh instead of waiting on the slot"
    );
    http.release.add_permits(2);
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    assert!(allowed(&ra) && allowed(&rb), "{} / {}", describe(&ra), describe(&rb));
    assert_eq!(http.refreshes(), 1);
    let saved = stored(s.store().as_ref(), GITHUB_SECRET);
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some("synthetic-rotated-0"));
    assert_eq!(
        http.upstream_authorization(),
        vec!["Bearer synthetic-refreshed-0".to_string(); 2],
        "both calls went upstream with the one rotation"
    );
}
