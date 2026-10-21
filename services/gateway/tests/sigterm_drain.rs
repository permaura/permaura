//! A gateway told to stop while a call is running lets it finish and records how it ended.
//!
//! Its own test binary because it sends a real `SIGTERM` to its own process, and the handler the
//! gateway installs for it is process-wide: in a binary with other tests, their servers would hear it.
//! Before the drain there was no handler at all, and this signal ended the process mid-call.
//!
//! Every credential and transport here is synthetic.
#![cfg(unix)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse};
use permaura_gateway::drain;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use permaura_gateway::AppState;

/// An upstream that answers after `delay`, saying when the request reached it.
struct Slow {
    delay: Duration,
    sent: AtomicUsize,
    entered: tokio::sync::Notify,
}

#[async_trait]
impl HttpClient for Slow {
    async fn send(&self, _request: HttpRequest) -> anyhow::Result<HttpResponse> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        tokio::time::sleep(self.delay).await;
        Ok(HttpResponse::json(200, serde_json::json!({ "pulls": [] })))
    }
}

/// A seeded gateway on a real loopback socket, its service, and its address.
async fn serving(
    delay: Duration,
) -> (Arc<dyn Store>, Arc<EnforcementService>, Arc<Slow>, std::net::SocketAddr, tokio::net::TcpListener, axum::Router)
{
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let http = Arc::new(Slow { delay, sent: AtomicUsize::new(0), entered: tokio::sync::Notify::new() });
    let state = AppState::new(EnforcementService::new(store.clone(), http.clone()));
    let service = state.service.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = permaura_gateway::build_router(state, addr);
    (store, service, http, addr, listener, app)
}

/// Invoke a Low-risk read over HTTP, the way an agent does.
async fn invoke(addr: std::net::SocketAddr) -> reqwest::Response {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("http://{addr}/v1/invoke"))
        .bearer_auth(permaura_gateway::seed::DEMO_TOKEN)
        .json(&serde_json::json!({
            "capability": "github.pull_requests.list",
            "params": { "owner": "synthetic", "repo": "synthetic" },
            "reason": "synthetic",
        }))
        .send()
        .await
        .expect("the gateway answers the call it was running")
}

fn decisions(store: &Arc<dyn Store>) -> Vec<String> {
    store.audit_events(None).unwrap().into_iter().map(|e| e.payload.decision).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sigterm_during_an_execution_lets_it_finish_and_records_its_terminal_event() {
    let (store, service, http, addr, listener, app) = serving(Duration::from_millis(1500)).await;
    // Installed now, as `permaura start` installs it before it binds.
    let stop = drain::stop_requested(Arc::new(tokio::sync::Notify::new()));
    let server = tokio::spawn(drain::serve_until_stopped(listener, app, service.clone(), stop, drain::DRAIN_WINDOW));

    let call = tokio::spawn(invoke(addr));
    tokio::time::timeout(Duration::from_secs(10), http.entered.notified())
        .await
        .expect("the call reached the upstream");

    // SAFETY: signalling this process with a signal it has a handler for.
    assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGTERM) }, 0);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !service.executions().is_draining() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SIGTERM starts the drain");

    // Nothing new is admitted while it drains, and the refusal comes before anything is recorded.
    let before = decisions(&store).len();
    let refused = service
        .invoke(
            &store.get_session("sess_demo").unwrap().unwrap(),
            "github.pull_requests.list",
            &serde_json::json!({ "owner": "synthetic", "repo": "synthetic" }),
            Some("synthetic"),
            permaura_core::ExecutionLocation::LocalOnly,
        )
        .await;
    assert!(
        matches!(&refused, Err(permaura_gateway::error::GatewayError::TooManyRequests { reason, .. }) if reason == drain::DRAINING_REASON),
        "{:?}",
        refused.err()
    );
    assert_eq!(decisions(&store).len(), before, "a refused call records nothing");

    // The call that was running finishes, and its caller gets the answer.
    let answered = call.await.unwrap();
    assert_eq!(answered.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = answered.json().await.unwrap();
    assert_eq!(body["upstream_status"], 200, "{body}");

    let drained = tokio::time::timeout(drain::DRAIN_WINDOW + Duration::from_secs(5), server)
        .await
        .expect("the drain is bounded")
        .unwrap()
        .unwrap();
    assert_eq!(drained.reason, "SIGTERM received");
    assert!(drained.requests_finished && drained.executions_finished, "{drained:?}");
    assert_eq!(drained.still_running, 0);
    assert!(drained.store_carried);

    assert_eq!(http.sent.load(Ordering::SeqCst), 1);
    let decisions = decisions(&store);
    assert_eq!(decisions.iter().filter(|d| *d == "attempt").count(), 1, "{decisions:?}");
    assert_eq!(decisions.iter().filter(|d| *d == "allow").count(), 1, "the terminal event is recorded: {decisions:?}");
    assert_eq!(decisions.last().map(String::as_str), Some("allow"), "{decisions:?}");
}

/// A call that would outlive the window does not hold the process open past it. Triggered by
/// `POST /v1/shutdown`'s signal rather than SIGTERM, so it cannot hear the other test's signal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_that_outlives_the_window_does_not_hold_the_exit() {
    let (_store, service, http, addr, listener, app) = serving(Duration::from_secs(60)).await;
    let requested = Arc::new(tokio::sync::Notify::new());
    let stop = {
        let requested = requested.clone();
        async move {
            requested.notified().await;
            "graceful shutdown requested"
        }
    };
    let window = Duration::from_millis(400);
    let server = tokio::spawn(drain::serve_until_stopped(listener, app, service.clone(), stop, window));
    let _call = tokio::spawn(invoke(addr));
    tokio::time::timeout(Duration::from_secs(10), http.entered.notified()).await.unwrap();

    let asked = tokio::time::Instant::now();
    requested.notify_one();
    let drained = tokio::time::timeout(Duration::from_secs(5), server).await.expect("bounded").unwrap().unwrap();
    assert!(asked.elapsed() < window + drain::CARRY_BUDGET + Duration::from_millis(500), "{:?}", asked.elapsed());
    assert!(!drained.executions_finished, "{drained:?}");
    assert_eq!(drained.still_running, 1, "{drained:?}");
}
