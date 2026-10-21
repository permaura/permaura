//! The execution ceiling fires inside the task an invocation runs its execution in, so the
//! task boundary that saves an abandoned invocation's refresh does not save one the ceiling cuts
//! off. The refresh has to outlive that too.
//!
//! One test in its own binary: the ceiling is read from the environment once per process.

mod common;

use std::time::Duration;

use common::synthetic_oauth::{allowed, describe, invoke_github, memory_service, stored, GITHUB_SECRET};
use permaura_gateway::error::GatewayError;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_the_execution_ceiling_cuts_off_still_lands_its_rotation() {
    // The smallest ceiling the limits accept, set before anything reads it.
    std::env::set_var("PERMAURA_LIMIT_EXECUTION_MS", "1000");
    let (s, http) = memory_service();

    let outcome = invoke_github(s.clone()).await;
    assert!(matches!(outcome, Err(GatewayError::UpstreamTimeout(_))), "{}", describe(&outcome));
    assert_eq!(http.refreshes(), 1, "the refresh reached the provider before the ceiling fired");
    assert_eq!(
        stored(s.store().as_ref(), GITHUB_SECRET).access_token,
        "synthetic-expired",
        "nothing is written while the refresh is still in flight"
    );

    http.release.add_permits(1);
    let outcome = tokio::time::timeout(Duration::from_secs(5), invoke_github(s.clone()))
        .await
        .expect("the next call was not blocked behind the cut-off refresh");
    assert!(allowed(&outcome), "{}", describe(&outcome));
    assert_eq!(http.refreshes(), 1, "the cut-off refresh's rotation was reused, not repeated");
    let saved = stored(s.store().as_ref(), GITHUB_SECRET);
    assert_eq!(saved.access_token, "synthetic-refreshed-0");
    assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()), Some("synthetic-rotated-0"));
    assert_eq!(http.upstream_authorization(), vec!["Bearer synthetic-refreshed-0".to_string()]);
}
