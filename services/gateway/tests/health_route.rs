//! There is exactly one health path, and it is the one that works everywhere.
//!
//! `/healthz` was the original spelling and is gone. Google's frontend answers that path itself on
//! Cloud Run, so the container never saw the request and every hosted worker read as dead to anything
//! probing it, the console's reachability dot and the desktop's included. Keeping both spellings alive
//! would have left the broken one working locally and failing only in the one place it mattered, which
//! is how it went unnoticed the first time.

use axum::body::Body;
use axum::http::{Request, StatusCode};
#[cfg(feature = "sqlite")]
use permaura_gateway::service::EnforcementService;
#[cfg(feature = "sqlite")]
use permaura_gateway::store::sqlite::SqliteStore;
#[cfg(feature = "sqlite")]
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, AppState};
#[cfg(feature = "sqlite")]
use std::time::{Duration, Instant};
use tower::ServiceExt;

mod common;

async fn status_of(state: AppState, path: &str) -> StatusCode {
    build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn health_answers_without_a_credential() {
    assert_eq!(status_of(common::seeded(), "/health").await, StatusCode::OK);
}

#[tokio::test]
async fn healthz_is_gone_rather_than_kept_as_a_second_name() {
    // Pinned so nobody restores it for symmetry: two spellings means probes drift onto the one that
    // fails behind Google's frontend, and nothing local ever catches it.
    assert_eq!(status_of(common::seeded(), "/healthz").await, StatusCode::NOT_FOUND);
}

/// A SQLite store with a transaction on another thread that holds `serial` until told to stop, and the state over it.
#[cfg(feature = "sqlite")]
fn wedged_store() -> (AppState, std::sync::mpsc::Sender<()>) {
    common::isolate_from_the_real_install();
    let store: std::sync::Arc<dyn Store> = std::sync::Arc::new(SqliteStore::open_in_memory().unwrap());
    let state = AppState::new(EnforcementService::new(
        store.clone(),
        std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new()),
    ));
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let (holding, held) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        store.run_atomically(&mut |_| {
            let _ = holding.send(());
            let _ = wait.recv();
            Ok(())
        })
    });
    held.recv_timeout(Duration::from_secs(10)).expect("the transaction took the store");
    (state, release)
}

/// A store that has stopped answering (a deadlock on `serial`) fails the liveness probe within a bound. `/health` used to answer 200 without touching the store, so Cloud Run never restarted a worker whose every real request hung.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_fails_within_a_bound_when_the_store_does_not_answer() {
    let (state, release) = wedged_store();
    let started = Instant::now();
    let status = tokio::time::timeout(Duration::from_secs(10), status_of(state, "/health"))
        .await
        .expect("/health answered at all");
    let took = started.elapsed();
    let _ = release.send(());
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "a wedged store must fail the probe");
    assert!(took < Duration::from_secs(5), "inside the liveness probe's 5 s timeout: took {took:?}");
}

/// A store that is only busy for a moment still answers 200: the probe waits out a short hold rather than failing on it.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_waits_out_a_short_hold_on_the_store() {
    let (state, release) = wedged_store();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        let _ = release.send(());
    });
    assert_eq!(status_of(state, "/health").await, StatusCode::OK);
}
