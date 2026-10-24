//! A WordPress site as a connection: discovery, the import review and its digest, re-sync and its
//! pinning rule, WordPress presets, and a call through an imported capability.
//!
//! The site is the Events Manager Pro support forum's real REST index, trimmed to three namespaces
//! (`tests/fixtures/wordpress/forum-index.json`). Every upstream answer comes from a `MockHttpClient`
//! queue, so nothing here touches a network, and every credential is synthetic.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::{HttpMethod, HttpResponse, MockHttpClient};
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const FORUM: &str = include_str!("fixtures/wordpress/forum-index.json");
const ABILITIES: &str = include_str!("fixtures/wordpress/abilities.json");
const SITE: &str = "https://eventsmanagerpro.com/support";
const ROOT: &str = "https://eventsmanagerpro.com/support/wp-json";

fn forum() -> Value {
    serde_json::from_str(FORUM).unwrap()
}

fn forum_query_style() -> Value {
    serde_json::from_str(&FORUM.replace(
        "https://eventsmanagerpro.com/support/wp-json/",
        "https://eventsmanagerpro.com/support/index.php?rest_route=/",
    ))
    .unwrap()
}

fn not_found() -> HttpResponse {
    HttpResponse { status: 404, text: Some("<html>not found</html>".into()), ..HttpResponse::default() }
}

struct Rig {
    state: AppState,
    http: Arc<MockHttpClient>,
}

fn rig() -> Rig {
    common::isolate_from_the_real_install();
    let http = Arc::new(MockHttpClient::new());
    let state = AppState::in_memory_seeded_with_http(http.clone());
    Rig { state, http }
}

impl Rig {
    async fn call_with(&self, method: &str, uri: &str, body: Option<Value>, extra: &[(&str, &str)]) -> (StatusCode, Value) {
        let app = build_router(self.state.clone(), "127.0.0.1:7376".parse().unwrap());
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN));
        for (k, v) in extra {
            builder = builder.header(*k, *v);
        }
        let body = match body {
            Some(b) => {
                builder = builder.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let resp = app.oneshot(builder.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        self.call_with("POST", uri, Some(body), &[]).await
    }

    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        self.call_with("GET", uri, None, &[]).await
    }

    fn capability(&self, id: &str) -> Option<permaura_gateway::connectors::Capability> {
        self.state.service.store().get_capability(id).unwrap()
    }

    fn connection(&self, id: &str) -> permaura_core::Connection {
        self.state.service.store().get_connection(id).unwrap().expect("the connection exists")
    }

    /// Import the forum's `bbpress/v1` namespace as `wordpress_support`.
    async fn import_forum(&self) -> Value {
        self.http.push_response(HttpResponse::json(200, forum()));
        let (status, body) = self
            .post(
                "/v1/connections/import-wordpress",
                json!({ "name": "Support", "url": SITE, "namespaces": ["bbpress/v1"], "digest": reviewed(&forum(), &["bbpress/v1"]) }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body
    }
}

/// The digest a dry run of `index` for `namespaces` returns, which a create must send.
fn reviewed(index: &Value, namespaces: &[&str]) -> String {
    let namespaces: Vec<String> = namespaces.iter().map(|n| n.to_string()).collect();
    permaura_gateway::wordpress::digest(index, Some(&namespaces))
}

fn ids(list: &Value) -> Vec<String> {
    list.as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().to_string()).collect()
}

fn find<'a>(list: &'a Value, id: &str) -> &'a Value {
    list.as_array().unwrap().iter().find(|c| c["id"] == id).unwrap_or_else(|| panic!("no {id} in {list}"))
}

#[tokio::test]
async fn discover_reports_the_site_its_routing_and_its_namespaces() {
    let rig = rig();
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig.post("/v1/connections/discover", json!({ "url": format!("{SITE}/") })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["kind"], "wordpress");
    assert_eq!(body["site_url"], SITE);
    assert_eq!(body["rest_root"], ROOT);
    assert_eq!(body["routing"], "pretty");
    assert_eq!(body["name"], "Events Manager Pro Support");
    assert_eq!(body["abilities_available"], true);
    assert_eq!(body["digest"].as_str().unwrap().len(), 64);
    let namespaces: Vec<&str> =
        body["namespaces"].as_array().unwrap().iter().map(|n| n["namespace"].as_str().unwrap()).collect();
    assert_eq!(namespaces, ["bbpress/v1", "wp/v2", "wp-abilities/v1"]);
    assert_eq!(rig.http.requests()[0].url, format!("{SITE}/wp-json/"));
}

#[tokio::test]
async fn discover_says_plainly_when_nothing_is_there_and_refuses_a_bad_url() {
    let rig = rig();
    rig.http.push_response(not_found());
    rig.http.push_response(not_found());
    rig.http.push_response(HttpResponse { status: 200, ..HttpResponse::default() });
    let (status, body) = rig.post("/v1/connections/discover", json!({ "url": "https://shop.example.com" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["kind"], "none");
    assert_eq!(body["tried"].as_array().unwrap().len(), 3);

    for bad in ["http://shop.example.com", "not a url", "https://u:p@shop.example.com"] {
        let (status, _) = rig.post("/v1/connections/discover", json!({ "url": bad })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn an_import_dry_run_returns_the_review_and_writes_nothing() {
    let rig = rig();
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig
        .post(
            "/v1/connections/import-wordpress",
            json!({ "name": "Support", "url": SITE, "namespaces": ["bbpress/v1"], "dry_run": true }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("connection_id").is_none(), "a dry run creates nothing to name");
    assert_eq!(body["rest_root"], ROOT);
    assert_eq!(body["routing"], "pretty");
    assert_eq!(body["base_url"], ROOT);
    assert_eq!(body["redact_fields"], json!(["email", "user_email", "author_email", "author_ip", "author_user_agent", "ip", "ip_address"]));
    assert!(body["skipped"].as_array().unwrap().is_empty(), "{}", body["skipped"]);
    let caps = &body["capabilities"];
    let trash = find(caps, "wordpress_support.bbpress.topics.actions.trash");
    assert_eq!(trash["method"], "POST");
    assert_eq!(trash["path"], "/bbpress/v1/topics/{id}/actions/trash");
    assert_eq!(trash["risk"], "critical");
    assert_eq!(trash["requires_approval"], true);
    assert_eq!(trash["disabled"], true);
    let list = find(caps, "wordpress_support.bbpress.topics.list");
    assert_eq!((list["method"].as_str(), list["disabled"].as_bool()), (Some("GET"), Some(false)));

    assert!(rig.state.service.store().get_connection("wordpress_support").unwrap().is_none());
    assert!(rig.capability("wordpress_support.bbpress.topics.list").is_none());
}

#[tokio::test]
async fn an_import_persists_the_connection_its_source_and_its_redaction_together() {
    let rig = rig();
    let body = rig.import_forum().await;
    assert_eq!(body["connection_id"], "wordpress_support");
    let digest = body["digest"].as_str().unwrap().to_string();

    let connection = rig.connection("wordpress_support");
    assert_eq!(connection.connector, "wordpress");
    assert_eq!(connection.label, "WordPress");
    assert_eq!(connection.secret_id, "sec_wordpress_support");
    assert!(connection.redact_fields.contains(&"author_ip".to_string()));
    let source = connection.source.as_ref().unwrap();
    assert_eq!(source.kind, permaura_core::SourceKind::Wordpress);
    assert_eq!(source.url, SITE);
    assert_eq!(source.rest_root.as_deref(), Some(ROOT));
    assert_eq!(source.namespaces, ["bbpress/v1"]);
    assert_eq!(source.digest.as_deref(), Some(digest.as_str()));
    assert!(!source.abilities);
    assert_eq!(connection.capabilities.len(), body["capabilities"].as_array().unwrap().len());
    for id in &connection.capabilities {
        assert!(rig.capability(id).is_some(), "{id} was stored with its connection");
    }
    assert!(connection.disabled_capabilities.contains(&"wordpress_support.bbpress.topics.actions.close".to_string()));
    assert!(!connection.disabled_capabilities.contains(&"wordpress_support.bbpress.topics.get".to_string()));

    let (status, one) = rig.get("/v1/connections/wordpress_support").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(one["source"]["kind"], "wordpress");
    assert_eq!(one["source"]["rest_root"], ROOT);
    assert_eq!(one["redact_fields"].as_array().unwrap().len(), 7);
    let (_, all) = rig.get("/v1/connections").await;
    let listed = find(&all["connections"], "wordpress_support");
    assert_eq!(listed["source"]["namespaces"], json!(["bbpress/v1"]));
    // A connection that was not discovered carries no source at all.
    assert!(find(&all["connections"], "github_acme")["source"].is_null());

    let (status, _) = rig
        .post("/v1/connections/import-wordpress", json!({ "name": "Support", "url": SITE, "namespaces": ["bbpress/v1"] }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the id is taken");
}

#[tokio::test]
async fn an_import_whose_reviewed_digest_is_stale_is_refused() {
    let rig = rig();
    let mut moved = forum();
    moved["routes"]["/bbpress/v1/topics"]["endpoints"][1]["args"]["pinned"] = json!({ "type": "boolean" });
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (_, review) = rig
        .post("/v1/connections/import-wordpress", json!({ "name": "Support", "url": SITE, "namespaces": ["bbpress/v1"], "dry_run": true }))
        .await;
    let reviewed = review["digest"].as_str().unwrap();

    rig.http.push_response(HttpResponse::json(200, moved));
    let (status, body) = rig
        .post(
            "/v1/connections/import-wordpress",
            json!({ "name": "Support", "url": SITE, "namespaces": ["bbpress/v1"], "digest": reviewed }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["error"].as_str().unwrap().contains("changed since it was reviewed"), "{body}");
    assert!(rig.state.service.store().get_connection("wordpress_support").unwrap().is_none());

    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, _) = rig
        .post(
            "/v1/connections/import-wordpress",
            json!({ "name": "Support", "url": SITE, "namespaces": ["bbpress/v1"], "digest": reviewed }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "an unchanged site imports what was reviewed");
}

/// The site writes its REST index and can change it between the review and the create, so a create is stored only against the digest of what was reviewed.
#[tokio::test]
async fn an_import_without_the_reviewed_digest_is_refused() {
    let rig = rig();
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig
        .post("/v1/connections/import-wordpress", json!({ "name": "Support", "url": SITE, "namespaces": ["bbpress/v1"] }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("digest"), "{body}");
    assert!(rig.state.service.store().get_connection("wordpress_support").unwrap().is_none());
}

#[tokio::test]
async fn an_import_refuses_a_namespace_the_site_does_not_serve() {
    let rig = rig();
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig
        .post("/v1/connections/import-wordpress", json!({ "name": "S", "url": SITE, "namespaces": ["events-manager/v1"], "dry_run": true }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("bbpress/v1"), "names what the site does serve: {body}");
}

#[tokio::test]
async fn a_resync_adds_disabled_overwrites_and_disables_changes_and_keeps_removals() {
    let rig = rig();
    rig.import_forum().await;
    let conn = "wordpress_support";
    let stats = format!("{conn}.bbpress.stats.get");
    let selftest = format!("{conn}.bbpress.mcp.selftest.get");
    let pin = format!("{conn}.bbpress.topics.pin.create");
    assert!(!rig.connection(conn).disabled_capabilities.contains(&stats), "a read starts enabled");

    let mut next = forum();
    let routes = next["routes"].as_object_mut().unwrap();
    routes.remove("/bbpress/v1/mcp/selftest");
    routes["/bbpress/v1/stats"]["endpoints"][0]["args"] = json!({ "period": { "type": "string" } });
    routes.insert(
        "/bbpress/v1/topics/(?P<id>[\\d]+)/pin".into(),
        json!({ "namespace": "bbpress/v1", "methods": ["POST"], "endpoints": [{ "methods": ["POST"], "args": { "id": { "type": "integer" } } }] }),
    );

    rig.http.push_response(HttpResponse::json(200, next.clone()));
    let (status, diff) = rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "dry_run": true })).await;
    assert_eq!(status, StatusCode::OK, "{diff}");
    assert_eq!(diff["dry_run"], true);
    assert_eq!(ids(&diff["added"]), [pin.as_str()]);
    assert_eq!(ids(&diff["changed"]), [stats.as_str()]);
    assert_eq!(ids(&diff["removed"]), [selftest.as_str()]);
    let total = rig.connection(conn).capabilities.len() as u64;
    let refreshed = diff["refreshed"].as_array().unwrap();
    assert!(!refreshed.is_empty(), "the new pin route is a sibling of the topic routes: {diff}");
    let disabled_before = rig.connection(conn).disabled_capabilities;
    assert_eq!(diff["unchanged"].as_u64().unwrap(), total - 2 - refreshed.len() as u64);
    assert_eq!(find(&diff["added"], &pin)["disabled"], true);
    assert!(rig.capability(&pin).is_none(), "a dry run writes nothing");
    assert!(!rig.connection(conn).disabled_capabilities.contains(&stats));

    rig.http.push_response(HttpResponse::json(200, next));
    let (status, applied) = rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["rest"] })).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["dry_run"], false);
    let connection = rig.connection(conn);
    assert!(connection.capabilities.contains(&pin) && connection.disabled_capabilities.contains(&pin), "added lands disabled");
    assert!(connection.disabled_capabilities.contains(&stats), "a changed read is disabled until reviewed");
    let mut newly: Vec<&String> = connection.disabled_capabilities.iter().filter(|c| !disabled_before.contains(c)).collect();
    newly.sort();
    assert_eq!(newly, [&stats, &pin], "recording a sibling route switches nothing else off");
    assert_eq!(rig.capability(&stats).unwrap().http.unwrap().query_params, ["period"], "and overwritten");
    assert!(connection.capabilities.contains(&selftest) && rig.capability(&selftest).is_some(), "removed is kept");
    let source = connection.source.unwrap();
    assert_eq!(source.digest.as_deref(), applied["digest"].as_str());
    assert!(source.synced_at > 0);
}

/// A plugin capability stored before path patterns were recorded refuses `akismet/akismet`; a re-sync records the plugins route's own pattern in place, so the plugin is addressed again and the operator's switch stays where it was.
#[tokio::test]
async fn a_resync_records_path_patterns_on_a_stored_capability_and_keeps_it_enabled() {
    let rig = rig();
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig
        .post("/v1/connections/import-wordpress", json!({ "name": "Site", "url": SITE, "namespaces": ["wp/v2"], "digest": reviewed(&forum(), &["wp/v2"]) }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let conn = "wordpress_site";
    let store = rig.state.service.store();
    let plugin_caps: Vec<String> = rig
        .connection(conn)
        .capabilities
        .into_iter()
        .filter(|id| rig.capability(id).and_then(|c| c.http).is_some_and(|h| h.path == "/wp/v2/plugins/{plugin}"))
        .collect();
    assert_eq!(plugin_caps.len(), 3, "read, update and delete: {plugin_caps:?}");

    // Every capability as a release before path patterns stored it, and the plugin ones switched on by the operator.
    for id in rig.connection(conn).capabilities {
        let mut cap = rig.capability(&id).unwrap();
        let mut blob = serde_json::to_value(cap.http.as_ref().unwrap()).unwrap();
        blob.as_object_mut().unwrap().remove("path_patterns");
        blob.as_object_mut().unwrap().remove("sibling_routes");
        blob.as_object_mut().unwrap().remove("route_patterns_read");
        cap.http = Some(serde_json::from_value(blob).unwrap());
        store.put_capability(cap).unwrap();
    }
    let mut connection = rig.connection(conn);
    connection.disabled_capabilities.retain(|c| !plugin_caps.contains(c));
    store.put_connection(connection).unwrap();
    for id in &plugin_caps {
        let cap = rig.capability(id).unwrap();
        assert!(cap.http.as_ref().unwrap().path_patterns.is_empty() && cap.http.as_ref().unwrap().sibling_routes.is_empty());
        let refusal = permaura_gateway::connectors::build_request_for("wordpress", &cap, &json!({ "plugin": "akismet/akismet" }), b"u:p").unwrap_err();
        assert_eq!(refusal.code, "path_identifier");
        assert!(refusal.reason.contains("re-sync"), "the refusal names the remedy: {}", refusal.reason);
    }

    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, applied) = rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["rest"] })).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert!(applied["changed"].as_array().unwrap().is_empty(), "recording a pattern is not a change to review: {applied}");
    assert!(applied["added"].as_array().unwrap().is_empty(), "{applied}");
    let recorded = ids(&applied["refreshed"]);
    for id in &plugin_caps {
        assert!(recorded.contains(id), "{id} in {recorded:?}");
        assert_eq!(find(&applied["refreshed"], id)["disabled"], false);
    }
    let connection = rig.connection(conn);
    for id in &plugin_caps {
        assert!(!connection.disabled_capabilities.contains(id), "{id} stays enabled");
        let cap = rig.capability(id).unwrap();
        let req = permaura_gateway::connectors::build_request(&cap, &json!({ "plugin": "akismet/akismet" }), b"u:p").unwrap();
        assert!(req.url.starts_with(&format!("{ROOT}/wp/v2/plugins/akismet/akismet")), "{id}: {}", req.url);
        let refusal = permaura_gateway::connectors::build_request(&cap, &json!({ "plugin": "akismet%2F..%2Fx" }), b"u:p").unwrap_err();
        assert_eq!(refusal.code, "path_identifier");
    }

    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, again) = rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "dry_run": true })).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert!(again["refreshed"].as_array().unwrap().is_empty(), "{again}");
    assert!(again["changed"].as_array().unwrap().is_empty(), "{again}");
}

/// A re-sync that records path patterns in place grows the stored rows, so the capability-bytes ceiling counts the refreshed rows against the ones they replace, as it does a changed one.
#[tokio::test]
async fn a_resync_whose_refreshed_rows_pass_the_capability_ceiling_is_refused() {
    use permaura_gateway::limits::{Limits, LimitsConfig};
    let rig = rig();
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig
        .post("/v1/connections/import-wordpress", json!({ "name": "Site", "url": SITE, "namespaces": ["wp/v2"], "digest": reviewed(&forum(), &["wp/v2"]) }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let conn = "wordpress_site";
    let store = rig.state.service.store();
    for id in rig.connection(conn).capabilities {
        let mut cap = rig.capability(&id).unwrap();
        let mut blob = serde_json::to_value(cap.http.as_ref().unwrap()).unwrap();
        for field in ["path_patterns", "sibling_routes", "route_patterns_read"] {
            blob.as_object_mut().unwrap().remove(field);
        }
        cap.http = Some(serde_json::from_value(blob).unwrap());
        store.put_capability(cap).unwrap();
    }
    let stored = store.capability_bytes().unwrap();
    let limits = LimitsConfig { capability_bytes: stored, ..LimitsConfig::default() };
    let full = Rig { state: rig.state.clone().with_limits(Arc::new(Limits::new(limits))), http: rig.http.clone() };

    full.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = full.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["rest"] })).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(store.capability_bytes().unwrap(), stored, "nothing was rewritten");

    let room = LimitsConfig { capability_bytes: stored * 2, ..LimitsConfig::default() };
    let roomy = Rig { state: rig.state.clone().with_limits(Arc::new(Limits::new(room))), http: rig.http.clone() };
    roomy.http.push_response(HttpResponse::json(200, forum()));
    let (status, applied) = roomy.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["rest"] })).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert!(!applied["refreshed"].as_array().unwrap().is_empty(), "the same re-sync with room records the patterns: {applied}");
    assert!(store.capability_bytes().unwrap() > stored, "and the rows grew");
}

#[tokio::test]
async fn abilities_need_the_sealed_credential_and_are_read_with_it() {
    let rig = rig();
    rig.import_forum().await;
    let conn = "wordpress_support";
    let (status, body) =
        rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["abilities"] })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (status, _) = rig.post(&format!("/v1/connections/{conn}/credential"), json!({ "value": "sam:abcd efgh ijkl" })).await;
    assert_eq!(status, StatusCode::OK);

    let before = rig.http.requests().len();
    rig.http.push_response(HttpResponse::json(200, serde_json::from_str(ABILITIES).unwrap()));
    let (status, diff) =
        rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["abilities"] })).await;
    assert_eq!(status, StatusCode::OK, "{diff}");
    let sent = &rig.http.requests()[before..];
    assert_eq!(sent.len(), 1, "one short page, and no index fetch for an abilities-only re-sync");
    assert_eq!(sent[0].url, format!("{ROOT}/wp-abilities/v1/abilities?per_page=100&page=1"));
    let expected = format!("Basic {}", base64_encode(b"sam:abcd efgh ijkl"));
    assert_eq!(sent[0].headers.get("Authorization"), Some(&expected));

    assert_eq!(diff["added"].as_array().unwrap().len(), 5, "{}", diff["added"]);
    assert_eq!(diff["skipped"].as_array().unwrap().len(), 2);
    assert_eq!(diff["unchanged"], 0, "REST capabilities are out of scope for an abilities-only re-sync");
    assert!(diff["removed"].as_array().unwrap().is_empty());
    let connection = rig.connection(conn);
    let get_topic = format!("{conn}.abilities.bbpress_get_topic");
    assert!(connection.disabled_capabilities.contains(&get_topic), "even a read lands disabled on re-sync");
    assert!(connection.source.as_ref().unwrap().abilities);
    let http = rig.capability(&get_topic).unwrap().http.unwrap();
    assert_eq!(http.method, HttpMethod::Get);

    let (_, audit) = rig.get("/v1/audit-events").await;
    let read = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["payload"]["action"] == "permaura.connection.abilities.read")
        .expect("the credential's use is audited");
    assert_eq!(read["payload"]["decision"], "allow");
    assert_eq!(read["payload"]["resource"], conn);
    assert_eq!(read["payload"]["summary"]["abilities"], 7);
    assert!(!shows_the_password(read), "the audit never carries the credential: {read}");

    // The default sources now include abilities, and an unchanged re-read changes nothing.
    rig.http.push_response(HttpResponse::json(200, forum()));
    rig.http.push_response(HttpResponse::json(200, serde_json::from_str(ABILITIES).unwrap()));
    let (status, again) = rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "dry_run": true })).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert!(again["added"].as_array().unwrap().is_empty() && again["changed"].as_array().unwrap().is_empty(), "{again}");
    assert_eq!(again["unchanged"].as_u64().unwrap(), connection.capabilities.len() as u64);
}

#[tokio::test]
async fn an_abilities_read_requested_remotely_still_executes_here_like_an_invoke() {
    // The custody gate is about where a call executes, and every MCP invoke executes on this gateway
    // (`ExecutionLocation::LocalOnly`) whatever network it arrived over; a hosted worker or the broker
    // must be able to read Abilities with a credential sealed the ordinary way.
    let rig = rig();
    rig.import_forum().await;
    let conn = "wordpress_support";
    let (status, _) = rig.post(&format!("/v1/connections/{conn}/credential"), json!({ "value": "sam:pw" })).await;
    assert_eq!(status, StatusCode::OK);
    rig.http.push_response(HttpResponse::json(200, serde_json::from_str(ABILITIES).unwrap()));
    let (status, body) = rig
        .call_with(
            "POST",
            &format!("/v1/connections/{conn}/resync"),
            Some(json!({ "sources": ["abilities"] })),
            &[("x-forwarded-for", "203.0.113.9")],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body["added"].as_array().unwrap().is_empty(), "{body}");
    let (_, audit) = rig.get("/v1/audit-events").await;
    let read = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["payload"]["action"] == "permaura.connection.abilities.read")
        .expect("the credential's use is audited");
    assert_eq!(read["payload"]["decision"], "allow");
    assert_eq!(read["payload"]["execution_location"], "local");
    assert_eq!(read["payload"]["summary"]["requested_remotely"], true);
}

#[tokio::test]
async fn resync_refuses_connections_it_cannot_re_read() {
    let rig = rig();
    let (status, body) = rig.post("/v1/connections/github_acme/resync", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no source: {body}");

    let (status, body) = rig
        .post("/v1/connections/import-openapi", json!({ "name": "Pasted", "id": "pasted", "spec": PETS, "base_url": "https://api.example.com/v1" }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = rig.post("/v1/connections/pasted/resync", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a pasted document has no URL to re-read");
    assert!(body["error"].as_str().unwrap().contains("pasted"), "{body}");

    rig.import_forum().await;
    let (status, _) = rig.post("/v1/connections/wordpress_support/resync", json!({ "sources": ["graphql"] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── OpenAPI re-sync ───────────────────────────────────────────────────────────

const PETS: &str = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Pets", "version": "1" },
  "servers": [{ "url": "https://api.example.com/v1" }, { "url": "https://sandbox.example.com/v1" }],
  "components": { "securitySchemes": { "key": { "type": "apiKey", "in": "header", "name": "X-Pets-Key" } } },
  "security": [{ "key": [] }],
  "paths": {
    "/pets": {
      "get": { "operationId": "listPets", "parameters": [{ "name": "limit", "in": "query" }] },
      "post": { "operationId": "createPet", "requestBody": { "content": { "application/json": { "schema": { "properties": { "name": {} } } } } } }
    },
    "/pets/{id}": { "get": { "operationId": "getPet", "parameters": [{ "name": "id", "in": "path", "required": true }] } }
  }
}"#;

fn document(text: &str) -> HttpResponse {
    HttpResponse { status: 200, text: Some(text.into()), ..HttpResponse::default() }
}

#[tokio::test]
async fn an_openapi_connection_re_reads_its_document_and_keeps_the_operators_choices() {
    let rig = rig();
    let spec_url = "https://api.example.com/openapi.json";
    rig.http.push_response(document(PETS));
    let (status, body) = rig
        .post(
            "/v1/connections/import-openapi",
            json!({
                "name": "Pets", "id": "pets", "spec_url": spec_url,
                "base_url": "https://api.example.com/v1",
                "auth": { "scheme": "bearer" },
                "digest": permaura_gateway::openapi::digest(PETS.as_bytes())
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(!rig.connection("pets").disabled_capabilities.contains(&"pets.listPets".to_string()));

    let next = PETS
        .replace(r#"{ "name": "limit", "in": "query" }"#, r#"{ "name": "limit", "in": "query" }, { "name": "species", "in": "query" }"#)
        .replace(
            r#""/pets/{id}": { "get": { "operationId": "getPet", "parameters": [{ "name": "id", "in": "path", "required": true }] } }"#,
            r#""/owners": { "get": { "operationId": "listOwners" } }"#,
        );
    assert_ne!(next, PETS);
    rig.http.push_response(document(&next));
    let before = rig.http.requests().len();
    let (status, diff) = rig.post("/v1/connections/pets/resync", json!({ "dry_run": true })).await;
    assert_eq!(status, StatusCode::OK, "{diff}");
    assert_eq!(rig.http.requests()[before].url, spec_url, "the document is read again from where it was imported");
    assert_eq!(ids(&diff["added"]), ["pets.listOwners"]);
    assert_eq!(ids(&diff["changed"]), ["pets.listPets"]);
    assert_eq!(ids(&diff["removed"]), ["pets.getPet"]);
    assert_eq!(diff["unchanged"], 1, "createPet is unchanged, so the pinned server and auth were carried over");

    rig.http.push_response(document(&next));
    let (status, applied) = rig.post("/v1/connections/pets/resync", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let connection = rig.connection("pets");
    for id in ["pets.listOwners", "pets.listPets"] {
        assert!(connection.disabled_capabilities.contains(&id.to_string()), "{id} lands disabled");
    }
    assert!(connection.capabilities.contains(&"pets.getPet".to_string()), "removed is kept");
    let http = rig.capability("pets.listOwners").unwrap().http.unwrap();
    assert_eq!(http.base_url, "https://api.example.com/v1");
    assert!(matches!(http.auth, permaura_gateway::connectors::AuthScheme::Bearer), "the operator's auth choice survives");
    assert_eq!(connection.source.unwrap().digest.as_deref(), applied["digest"].as_str());

    let (status, _) = rig.post("/v1/connections/pets/resync", json!({ "sources": ["abilities"] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "abilities are a WordPress source");
}

// ── WordPress presets ─────────────────────────────────────────────────────────

fn bbpress_manifest(namespace: &str) -> Value {
    json!({
        "id": "bbpress-forum",
        "name": "bbPress",
        "vertical": "comms",
        "description": "A curated slice of a bbPress forum.",
        "base_url": "https://{site}/wp-json/bbpress/v1",
        "auth": { "scheme": "basic" },
        "wordpress": { "namespace": namespace },
        "capabilities": [
            { "id": "topics.list", "method": "GET", "path": "/topics", "query_params": ["per_page", "page"] },
            { "id": "topics.close", "method": "POST", "path": "/topics/{id}/actions/close", "path_params": ["id"] }
        ]
    })
}

async fn install(rig: &Rig, manifest: Value) {
    let (status, body) = rig.post("/v1/connectors/install", json!({ "manifest": manifest, "version": 1 })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn a_wordpress_preset_is_pinned_to_the_discovered_site_under_either_routing() {
    let rig = rig();
    install(&rig, bbpress_manifest("bbpress/v1")).await;

    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig
        .post("/v1/connections/from-preset", json!({ "preset_id": "bbpress-forum", "name": "Pretty", "id": "pretty", "site_url": SITE }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["base_url"], format!("{ROOT}/bbpress/v1"));
    assert_eq!(body["customised"], true);
    let http = rig.capability("pretty.topics.list").unwrap().http.unwrap();
    assert_eq!((http.base_url.as_str(), http.path.as_str(), http.route_param.as_deref()), (&*format!("{ROOT}/bbpress/v1"), "/topics", None));
    let source = rig.connection("pretty").source.unwrap();
    assert_eq!(source.kind, permaura_core::SourceKind::Wordpress);
    assert_eq!(source.namespaces, ["bbpress/v1"]);
    assert_eq!(source.rest_root.as_deref(), Some(ROOT));
    assert!(rig.connection("pretty").disabled_capabilities.contains(&"pretty.topics.close".to_string()));

    rig.http.push_response(not_found());
    rig.http.push_response(HttpResponse::json(200, forum_query_style()));
    let (status, body) = rig
        .post("/v1/connections/from-preset", json!({ "preset_id": "bbpress-forum", "name": "Plain", "id": "plain", "site_url": SITE }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["base_url"], format!("{SITE}/"));
    let cap = rig.capability("plain.topics.list").unwrap();
    let http = cap.http.as_ref().unwrap();
    assert_eq!(http.path, "/bbpress/v1/topics");
    assert_eq!(http.route_param.as_deref(), Some("rest_route"));
    let req = permaura_gateway::connectors::build_request(&cap, &json!({ "per_page": 2 }), b"u:p").unwrap();
    assert_eq!(req.url, format!("{SITE}/?rest_route=/bbpress/v1/topics&per_page=2"));
}

#[tokio::test]
async fn a_wordpress_preset_needs_a_site_that_serves_its_namespace() {
    let rig = rig();
    install(&rig, bbpress_manifest("events-manager/v1")).await;
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig
        .post("/v1/connections/from-preset", json!({ "preset_id": "bbpress-forum", "name": "X", "site_url": SITE }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error = body["error"].as_str().unwrap();
    assert!(error.contains("events-manager/v1") && error.contains("bbpress/v1"), "{error}");

    let (status, body) = rig.post("/v1/connections/from-preset", json!({ "preset_id": "bbpress-forum", "name": "Y" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no site: {body}");

    let (status, body) = rig
        .post(
            "/v1/connections/from-preset",
            json!({ "preset_id": "bbpress-forum", "name": "Z", "id": "explicit", "base_url": "https://forum.example.com/wp-json/events-manager/v1" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "an explicit base_url needs no discovery: {body}");
    assert_eq!(rig.connection("explicit").source.unwrap().namespaces, ["events-manager/v1"]);
}

/// The bundled Events Manager preset binds to the operator's own site: reads are on, writes start off, and anything that touches a booking or deletes asks first.
#[tokio::test]
async fn the_bundled_events_manager_preset_binds_to_your_site_with_bookings_gated() {
    let rig = rig();
    let base = "https://events.example.com/wp-json/events-manager/v1";
    let (status, body) =
        rig.post("/v1/connections/from-preset", json!({ "preset_id": "events-manager", "name": "Events", "id": "em", "base_url": base })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(rig.connection("em").source.unwrap().namespaces, ["events-manager/v1"]);
    let disabled = rig.connection("em").disabled_capabilities;
    let off = |id: &str| disabled.contains(&format!("em.{id}"));
    for id in ["events.list", "events.availability", "bookings.list", "locations.towns"] {
        assert!(!off(id), "{id} is a read");
    }
    for id in ["events.create", "tickets.update", "bookings.create", "bookings.status", "bookings.delete", "media.upload"] {
        assert!(off(id), "{id} is a write");
    }
    for id in ["bookings.create", "bookings.update", "bookings.status", "bookings.delete", "events.delete"] {
        assert!(rig.capability(&format!("em.{id}")).unwrap().requires_approval, "{id}");
    }
    let read = rig.capability("em.events.read").unwrap();
    let req = permaura_gateway::connectors::build_request(&read, &json!({ "id": "123:4" }), b"u:p").unwrap();
    assert_eq!(req.url, format!("{base}/events/123%3A4"), "a timeslot id stays in its one segment");
}

#[tokio::test]
async fn a_templated_base_url_is_never_pinned_and_presets_say_when_a_host_is_required() {
    let rig = rig();
    install(&rig, bbpress_manifest("bbpress/v1")).await;
    install(
        &rig,
        json!({
            "id": "tenant-api", "name": "Tenant API", "vertical": "data",
            "base_url": "https://{tenant}.example.com/api",
            "capabilities": [{ "id": "things.list", "method": "GET", "path": "/things" }]
        }),
    )
    .await;

    let (status, body) = rig.post("/v1/connections/from-preset", json!({ "preset_id": "tenant-api", "name": "T" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(rig.state.service.store().get_connection("tenant_api_t").unwrap().is_none());
    let (status, _) = rig
        .post("/v1/connections/from-preset", json!({ "preset_id": "tenant-api", "name": "T", "base_url": "https://{tenant}.example.com/api" }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a placeholder is not a host");
    let (status, _) = rig
        .post("/v1/connections/from-preset", json!({ "preset_id": "tenant-api", "name": "T", "base_url": "https://acme.example.com/api" }))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = rig.post("/v1/connections/from-preset", json!({ "preset_id": "stripe", "name": "S", "site_url": SITE })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "site_url is only for a WordPress preset");

    let (_, presets) = rig.get("/v1/presets").await;
    let presets = &presets["presets"];
    let bbpress = find(presets, "bbpress-forum");
    assert_eq!(bbpress["wordpress"], json!({ "namespace": "bbpress/v1" }));
    assert_eq!(bbpress["base_url_required"], true);
    assert_eq!(find(presets, "tenant-api")["base_url_required"], true);
    assert_eq!(find(presets, "tenant-api")["wordpress"], Value::Null);
    assert_eq!(find(presets, "stripe")["base_url_required"], false);
}

// ── A call through an imported capability ─────────────────────────────────────

#[tokio::test]
async fn an_imported_capability_calls_the_pinned_site_with_the_sealed_application_password() {
    let rig = rig();
    rig.import_forum().await;
    let conn = "wordpress_support";
    let (status, _) = rig.post(&format!("/v1/connections/{conn}/credential"), json!({ "value": "sam:abcd efgh" })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, policy) = rig
        .post(
            "/v1/policies",
            json!({ "id": "pol_forum", "connection_id": conn, "name": "Read the forum", "allow": ["bbpress.topics.list", "bbpress.topics.actions.trash"] }),
        )
        .await;
    assert!(status.is_success(), "{policy}");
    let (status, grant) = rig
        .post("/v1/grants", json!({ "grant_id": "gr_forum", "name": "Forum", "policy_ids": ["pol_forum"], "agents": ["codex-cli"] }))
        .await;
    assert!(status.is_success(), "{grant}");

    rig.http.push_response(HttpResponse::json(
        200,
        json!([{
            "id": 7,
            "title": "Bookings page is blank",
            "author_ip": "203.0.113.7",
            "author_email": "someone@example.com",
            "author": { "name": "Someone", "user_email": "someone@example.com" }
        }]),
    ));
    let before = rig.http.requests().len();
    // An agent's own `url` is not a parameter of the pinned capability, so it is refused by name and nothing is sent.
    let (status, body) = rig
        .post(
            "/v1/invoke",
            json!({
                "capability": format!("{conn}.bbpress.topics.list"),
                "params": { "per_page": 5, "status": "publish", "url": "https://attacker.example/steal" }
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap_or_default().contains("'url'"), "{body}");
    assert_eq!(rig.http.requests().len(), before, "nothing was sent");
    let (status, body) = rig
        .post("/v1/invoke", json!({ "capability": format!("{conn}.bbpress.topics.list"), "params": { "per_page": 5, "status": "publish" } }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sent = rig.http.requests()[before].clone();
    assert_eq!(sent.method, HttpMethod::Get);
    assert_eq!(sent.url, format!("{ROOT}/bbpress/v1/topics?per_page=5&status=publish"));
    assert_eq!(sent.headers.get("Authorization"), Some(&format!("Basic {}", base64_encode(b"sam:abcd efgh"))));
    let topic = &body["result"][0];
    assert_eq!(topic["id"], 7);
    // The WordPress defaults on the connection reach the per-call redaction union.
    assert_eq!(topic["author_ip"], "[redacted]");
    assert_eq!(topic["author_email"], "[redacted]");
    assert_eq!(topic["author"]["user_email"], "[redacted]");
    assert_eq!(topic["author"]["name"], "Someone");

    // A write the import left switched off stays off, whatever a policy allows.
    let (status, body) = rig
        .post("/v1/invoke", json!({ "capability": format!("{conn}.bbpress.topics.actions.trash"), "params": { "id": 7 } }))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(rig.http.requests().len(), before + 1, "nothing else went upstream");
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Whether `event` shows the application password the abilities test seals, a word of it, or the Basic credential it is sent in. Not its first word alone: "abcd" is hex, which an event's hash and signature spell by chance in about one run in 350.
fn shows_the_password(event: &Value) -> bool {
    let text = event.to_string();
    ["abcd efgh", "efgh", "ijkl"].iter().any(|word| text.contains(word)) || text.contains(&base64_encode(b"sam:abcd efgh ijkl"))
}

#[test]
fn the_password_check_finds_the_password_and_not_hex_that_spells_part_of_it() {
    let event = json!({
        "hash": "fde0abcd2de34a2e147391ad6e26bb5ccdf41a6f799b56890f1ce699e71c5004",
        "payload": { "action": "permaura.connection.abilities.read", "summary": { "abilities": 7 } },
        "signature": "0e88b3767e6e99906f2f22da52982457fb7ac558cd02ddecd664691f779539bb521e184d1c66cffbf17d382ac9e17a68db02fd4f1cc09e0462edbc2ecabcd02",
    });
    assert!(!shows_the_password(&event), "hex is not the password");
    for leaked in ["sam:abcd efgh ijkl".to_string(), "abcd efgh".to_string(), "ijkl".to_string(), base64_encode(b"sam:abcd efgh ijkl")] {
        assert!(shows_the_password(&json!({ "payload": { "summary": { "detail": leaked } } })), "{leaked}");
    }
}

/// The owner may lower what a site's annotations could only raise. A read-only ability lands High, gated on every call; the owner sets it to run without an approval, a re-sync of the same listing keeps that, and an annotation that changes what the ability derives as (now destructive) drops the setting so the re-sync shows the change.
#[tokio::test]
async fn the_owner_can_set_an_abilitys_posture_and_a_resync_keeps_it() {
    let rig = rig();
    rig.import_forum().await;
    let conn = "wordpress_support";
    let (status, _) = rig.post(&format!("/v1/connections/{conn}/credential"), json!({ "value": "sam:abcd efgh ijkl" })).await;
    assert_eq!(status, StatusCode::OK);
    rig.http.push_response(HttpResponse::json(200, serde_json::from_str(ABILITIES).unwrap()));
    let (status, diff) = rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["abilities"] })).await;
    assert_eq!(status, StatusCode::OK, "{diff}");
    let get_topic = format!("{conn}.abilities.bbpress_get_topic");
    let posture = |rig: &Rig| {
        let c = rig.capability(&get_topic).unwrap();
        (c.risk, c.requires_approval)
    };
    assert_eq!(posture(&rig), (permaura_core::RiskTier::High, false), "High floors at an approval on every call");

    let (status, set) = rig
        .post(&format!("/v1/connections/{conn}/capability-posture"), json!({ "capability": get_topic, "risk": "medium", "requires_approval": false }))
        .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(posture(&rig), (permaura_core::RiskTier::Medium, false));
    let (_, audit) = rig.get("/v1/audit-events?limit=500").await;
    let recorded = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["payload"]["summary"]["mutation"]["kind"] == "capability_posture")
        .expect("the setting is in the audit chain");
    assert_eq!(recorded["payload"]["summary"]["mutation"]["from"]["risk"], "high", "{recorded}");
    assert_eq!(recorded["payload"]["summary"]["mutation"]["risk"], "medium", "{recorded}");
    let (status, refused) = rig
        .post(&format!("/v1/connections/{conn}/capability-posture"), json!({ "capability": get_topic, "risk": "low", "requires_approval": false, "method": "GET" }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an unknown field is refused, not dropped: {refused}");

    rig.http.push_response(HttpResponse::json(200, serde_json::from_str(ABILITIES).unwrap()));
    let (status, again) = rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["abilities"] })).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert!(!ids(&again["changed"]).contains(&get_topic), "the same listing changes nothing: {again}");
    assert_eq!(posture(&rig), (permaura_core::RiskTier::Medium, false), "a re-sync keeps the owner's setting");

    let mut moved: Value = serde_json::from_str(ABILITIES).unwrap();
    moved[0]["meta"]["annotations"]["destructive"] = json!(true);
    rig.http.push_response(HttpResponse::json(200, moved));
    let (status, changed) = rig.post(&format!("/v1/connections/{conn}/resync"), json!({ "sources": ["abilities"] })).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert!(ids(&changed["changed"]).contains(&get_topic), "{changed}");
    assert_eq!(posture(&rig), (permaura_core::RiskTier::Critical, true), "an annotation that raises it drops the setting");
    assert!(rig.capability(&get_topic).unwrap().http.unwrap().owner_posture.is_none());
}

/// A WordPress connection may be named after a connector family; listing its Abilities sends its credential to the site, judged by its family (`wordpress`), not by its id.
#[tokio::test]
async fn a_wordpress_connection_named_after_a_family_still_lists_its_abilities() {
    let rig = rig();
    rig.http.push_response(HttpResponse::json(200, forum()));
    let (status, body) = rig
        .post(
            "/v1/connections/import-wordpress",
            json!({ "name": "Support", "id": "github", "url": SITE, "namespaces": ["bbpress/v1"], "digest": reviewed(&forum(), &["bbpress/v1"]) }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _) = rig.post("/v1/connections/github/credential", json!({ "value": "sam:abcd efgh ijkl" })).await;
    assert_eq!(status, StatusCode::OK);
    rig.http.push_response(HttpResponse::json(200, serde_json::from_str(ABILITIES).unwrap()));
    let (status, diff) = rig.post("/v1/connections/github/resync", json!({ "sources": ["abilities"] })).await;
    assert_eq!(status, StatusCode::OK, "{diff}");
    assert_eq!(diff["added"].as_array().unwrap().len(), 5, "{diff}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resync_waits_for_the_owner_change_before_comparing_the_new_listing() {
    let rig = Arc::new(rig());
    let imported = rig.import_forum().await;
    let id = imported["connection_id"].as_str().unwrap().to_string();
    rig.http.push_response(HttpResponse::json(200, forum()));
    let lock = rig.state.service.control_plane_mutex().lock().await;
    let task = {
        let rig = rig.clone();
        tokio::spawn(async move { rig.post(&format!("/v1/connections/{id}/resync"), json!({})).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let finished = task.is_finished();
    drop(lock);
    let (status, body) = task.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!finished, "the resync must compare and write under the owner's control-plane lock");
}
