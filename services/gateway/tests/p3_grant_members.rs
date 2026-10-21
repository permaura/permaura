use axum::{body::Body, http::{Request, StatusCode}};
use serde_json::json;
use tower::ServiceExt;
mod common;

#[tokio::test]
async fn updating_a_grant_validates_the_agents_it_names() {
    let state = common::seeded();
    let grant = state.service.store().list_grants().unwrap().into_iter().find(|g| !g.is_default).unwrap();
    let app = permaura_gateway::build_router(state, "127.0.0.1:49151".parse().unwrap());
    let request = Request::builder().method("PUT").uri(format!("/v1/grants/{}", grant.grant_id))
        .header("authorization", format!("Bearer {}", permaura_gateway::seed::DEMO_TOKEN)).header("content-type", "application/json")
        .body(Body::from(json!({"name":grant.name,"policy_ids":grant.policy_ids,"agents":[{"agent_id":"not-enrolled"}]}).to_string())).unwrap();
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_grant_cannot_amplify_classification_with_unbounded_named_members() {
    let state = common::seeded();
    let app = permaura_gateway::build_router(state, "127.0.0.1:49151".parse().unwrap());
    let request = Request::builder().method("POST").uri("/v1/grants")
        .header("authorization", format!("Bearer {}", permaura_gateway::seed::DEMO_TOKEN)).header("content-type", "application/json")
        .body(Body::from(json!({"name":"synthetic", "policy_ids":[],"agents":vec![json!({"agent_id":"codex-cli"});1025]}).to_string())).unwrap();
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::BAD_REQUEST);
}
