use permaura_core::{Action, RiskTier};
use permaura_gateway::connectors::{CapabilityKind, HttpMethod, HttpSpec, OwnerPosture};
use permaura_gateway::policy_guard::{Mutation, PostureFrom};
use permaura_gateway::vault_bundle::{self, BundlePayload, CapabilityRecord, ImportOptions};
use serde_json::json;
mod common;

#[test]
fn the_posture_sentence_names_the_effective_gate_and_quotes_the_path() {
    let state = common::seeded();
    let title = state.service.describe_mutation(&Mutation::CapabilityPosture {
        connection_id: "github_acme".into(), capability: "github.pull_requests.list".into(),
        risk: RiskTier::Medium, requires_approval: false,
        from: PostureFrom { action: Action::Read, risk: RiskTier::High, requires_approval: false,
            method: HttpMethod::Get, path: "/status) forged (\"line\"\n".into() },
    });
    assert!(title.contains("an approval on every call"), "{title}");
    assert!(!title.contains("/status) forged (") && !title.contains('\n'), "{title}");
}

#[test]
fn a_non_http_capability_cannot_be_described_as_an_http_call_or_imported_with_its_spec() {
    let state = common::seeded();
    let store = state.service.store();
    let mut cap = store.get_capability("github.pull_requests.list").unwrap().unwrap();
    cap.kind = CapabilityKind::Command;
    cap.http = Some(HttpSpec { path: "/status".into(), ..Default::default() });
    assert_eq!(permaura_gateway::service::held_call_sentence(&cap), cap.description);
    let payload = BundlePayload { capabilities: vec![CapabilityRecord::from(&cap)], ..Default::default() };
    assert!(vault_bundle::validate(store.as_ref(), &payload, &ImportOptions { allow_command_capabilities: true, ..Default::default() }).is_err());
}

#[test]
fn a_new_floor_replaces_an_owner_setting_made_against_an_older_floor() {
    let state = common::seeded();
    let store = state.service.store();
    let mut connection = store.get_connection("github_acme").unwrap().unwrap();
    connection.connector = "wordpress".into();
    let mut cap = store.get_capability("github.pull_requests.list").unwrap().unwrap();
    cap.risk = RiskTier::Low;
    cap.requires_approval = false;
    cap.http = Some(HttpSpec { path: "/purge".into(), owner_posture: Some(OwnerPosture {
        risk: RiskTier::Low, requires_approval: false, from_action: Action::Read,
        from_risk: RiskTier::Medium, from_requires_approval: false,
    }), ..Default::default() });
    store.put_connection(connection).unwrap();
    store.put_capability(cap.clone()).unwrap();
    let moved = permaura_gateway::posture_floor::refloor_stored(store.as_ref()).unwrap();
    assert!(moved.iter().any(|m| m.capability == cap.id));
    let now = store.get_capability(&cap.id).unwrap().unwrap();
    assert_eq!(now.risk, RiskTier::Critical);
    assert!(now.http.unwrap().owner_posture.is_none());
}

#[test]
fn mixed_and_compound_wordpress_paths_have_the_same_floor_at_import_and_start() {
    use permaura_gateway::wordpress::{derive, stored_floor, RestPin};
    let pin = RestPin::from_rest_root("https://site.example/wp-json").unwrap();
    for path in ["purge-(?P<kind>[a-z]+)", "(?P<id>[a-z]+)-delete", "purgeall", "flushcache", "deleteall", "resetpassword", "emptytrash"] {
        let route = json!({"namespace":"acme/v1", "endpoints":[{"methods":["GET"], "args":{}}]});
        let index = json!({"namespaces":["acme/v1"], "routes":{ "/acme/v1":route, (format!("/acme/v1/{path}")):route }});
        let derived = derive(&index, &["acme/v1".into()], "c", "sec", &pin);
        let cap = derived.capabilities.iter().find(|c| c.http.as_ref().is_some_and(|h| h.path != "/acme/v1")).unwrap();
        assert_eq!(cap.risk, RiskTier::Critical, "{path}");
        assert_eq!(stored_floor("c", cap, &["acme/v1".into()]), Some((cap.action, cap.risk, cap.requires_approval)), "{path}");
    }
}

#[test]
fn a_wordpress_vault_restore_keeps_the_namespace_out_of_its_floor() {
    let state = common::seeded();
    let store = state.service.store();
    let mut connection = store.get_connection("github_acme").unwrap().unwrap();
    connection.connector = "wordpress".into();
    connection.source = Some(serde_json::from_value(json!({"kind":"wordpress", "url":"https://site.example", "namespaces":["password-reset/v1"]})).unwrap());
    let mut cap = store.get_capability("github.pull_requests.list").unwrap().unwrap();
    cap.action = Action::Read;
    cap.risk = RiskTier::Medium;
    cap.requires_approval = false;
    cap.http = Some(HttpSpec { path: "/password-reset/v1/status".into(), ..Default::default() });
    store.put_connection(connection.clone()).unwrap();
    let payload = BundlePayload { connections: vec![connection], capabilities: vec![CapabilityRecord::from(&cap)], ..Default::default() };
    let manifest = vault_bundle::preview(store.as_ref(), &payload, 0, "source".into(), "self-run".into()).unwrap();
    assert!(!manifest.raised.contains(&cap.id), "{:?}", manifest.raised);
}

/// A vault bundle may only raise what a WordPress route's method gives: a delete or a write it declares as a low read imports at the method's floor, while an operation word in a namespace still raises nothing.
#[test]
fn a_wordpress_write_in_a_vault_bundle_imports_at_its_method_floor() {
    let state = common::seeded();
    let store = state.service.store();
    let mut connection = store.get_connection("github_acme").unwrap().unwrap();
    connection.id = "site".into();
    connection.connector = "wordpress".into();
    connection.source = Some(serde_json::from_value(json!({"kind":"wordpress", "url":"https://site.example", "namespaces":["wp/v2", "password-reset/v1"]})).unwrap());
    assert!(store.get_connection(&connection.id).unwrap().is_none(), "the bundle brings the connection");
    let base = store.get_capability("github.pull_requests.list").unwrap().unwrap();
    let declared = |action: &str, method: HttpMethod, path: &str| {
        let mut cap = base.clone();
        cap.id = format!("{}.{action}", connection.id);
        cap.resource = connection.id.clone();
        (cap.action, cap.risk, cap.requires_approval) = (Action::Read, RiskTier::Low, false);
        cap.http = Some(HttpSpec { method, path: path.into(), ..Default::default() });
        CapabilityRecord::from(&cap)
    };
    let mut records = vec![
        declared("wp_v2.users.delete", HttpMethod::Delete, "/wp/v2/users/{id}"),
        declared("wp_v2.posts.create", HttpMethod::Post, "/wp/v2/posts"),
        declared("wp_v2.posts.update", HttpMethod::Put, "/wp/v2/posts/{id}"),
        declared("password_reset_v1.status.get", HttpMethod::Get, "/password-reset/v1/status"),
    ];
    let payload = BundlePayload { connections: vec![connection.clone()], capabilities: records.clone(), ..Default::default() };
    let manifest = vault_bundle::preview(store.as_ref(), &payload, 0, "source".into(), "self-run".into()).unwrap();
    vault_bundle::raise_to_floor(store.as_ref(), &[connection], &mut records).unwrap();
    let posture = |i: usize| (records[i].action, records[i].risk, records[i].requires_approval);
    assert_eq!(posture(0), (Action::Delete, RiskTier::Critical, true), "a delete declared a low read");
    assert_eq!(posture(1), (Action::Create, RiskTier::High, false), "a create declared a low read");
    assert_eq!(posture(2), (Action::Update, RiskTier::High, false), "an update declared a low read");
    assert_eq!(posture(3), (Action::Read, RiskTier::Medium, false), "the namespace's operation word raises nothing");
    for i in 0..3 {
        assert!(manifest.raised.contains(&records[i].id), "{} {:?}", records[i].id, manifest.raised);
    }
}

/// The start-up pass writes only a row it changes. On a hosted worker every write uploads the whole store, so a pass that rewrote each floored row on every start would make every cold start pay one upload per row.
#[test]
fn a_second_floor_pass_writes_nothing() {
    use permaura_gateway::store::{sqlite::SqliteStore, Store};
    common::isolate_from_the_real_install();
    let store = SqliteStore::open_in_memory().unwrap();
    permaura_gateway::seed::seed(&store).unwrap();
    let mut connection = store.get_connection("github_acme").unwrap().unwrap();
    connection.connector = "wordpress".into();
    let mut raised = store.get_capability("github.pull_requests.list").unwrap().unwrap();
    raised.http = Some(HttpSpec { path: "/purge".into(), ..Default::default() });
    let mut at_floor = raised.clone();
    at_floor.id = "github.cache.flush".into();
    (at_floor.action, at_floor.risk, at_floor.requires_approval) = (Action::Execute, RiskTier::Critical, true);
    at_floor.http = Some(HttpSpec { path: "/flushcache".into(), ..Default::default() });
    let mut owned = at_floor.clone();
    owned.id = "github.cache.reset".into();
    (owned.risk, owned.requires_approval) = (RiskTier::Low, false);
    owned.http = Some(HttpSpec { path: "/reset".into(), owner_posture: Some(OwnerPosture {
        risk: RiskTier::Low, requires_approval: false, from_action: Action::Execute,
        from_risk: RiskTier::Critical, from_requires_approval: true,
    }), ..Default::default() });
    connection.capabilities.extend([at_floor.id.clone(), owned.id.clone()]);
    store.put_connection(connection).unwrap();
    for cap in [raised.clone(), at_floor.clone(), owned.clone()] {
        store.put_capability(cap).unwrap();
    }
    let changes = store.change_count().unwrap();
    let moved = permaura_gateway::posture_floor::refloor_stored(&store).unwrap();
    assert_eq!(moved.iter().map(|m| m.capability.as_str()).collect::<Vec<_>>(), [raised.id.as_str()], "{moved:?}");
    let row = |id: &str| serde_json::to_value(CapabilityRecord::from(&store.get_capability(id).unwrap().unwrap())).unwrap();
    assert_eq!(row(&at_floor.id), serde_json::to_value(CapabilityRecord::from(&at_floor)).unwrap(), "a row at its floor is left as it was");
    assert_eq!(row(&owned.id), serde_json::to_value(CapabilityRecord::from(&owned)).unwrap(), "and so is the owner's own setting while its floor holds");
    assert!(store.change_count().unwrap() > changes, "the first pass writes the row it raised");
    let changes = store.change_count().unwrap();
    assert!(permaura_gateway::posture_floor::refloor_stored(&store).unwrap().is_empty());
    assert_eq!(store.change_count().unwrap(), changes, "a second start writes nothing");
}

#[test]
fn a_floor_pass_keeps_its_changed_capabilities_for_the_next_console_read() {
    let state = common::seeded();
    let store = state.service.store();
    let mut connection = store.get_connection("github_acme").unwrap().unwrap();
    connection.connector = "wordpress".into();
    let mut cap = store.get_capability("github.pull_requests.list").unwrap().unwrap();
    cap.http = Some(HttpSpec { path: "/purge".into(), ..Default::default() });
    store.put_connection(connection).unwrap();
    store.put_capability(cap.clone()).unwrap();
    permaura_gateway::posture_floor::refloor_stored(store.as_ref()).unwrap();
    let text = store.get_meta("last_posture_floor_pass").unwrap().expect("the last floor pass is kept for the console");
    let moved: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(moved[0]["capability"], cap.id);
    permaura_gateway::posture_floor::refloor_stored(store.as_ref()).unwrap();
    assert_eq!(store.get_meta("last_posture_floor_pass").unwrap(), Some(text));
}

#[tokio::test]
async fn the_owner_posture_route_refuses_a_command_with_a_leftover_http_spec() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let state = common::seeded();
    let store = state.service.store();
    let mut cap = store.get_capability("github.pull_requests.list").unwrap().unwrap();
    cap.kind = CapabilityKind::Command;
    cap.http = Some(HttpSpec { path: "/status".into(), ..Default::default() });
    store.put_capability(cap).unwrap();
    let app = permaura_gateway::build_router(state, "127.0.0.1:49151".parse().unwrap());
    let request = Request::builder().method("POST").uri("/v1/connections/github_acme/capability-posture")
        .header("authorization", format!("Bearer {}", permaura_gateway::seed::DEMO_TOKEN)).header("content-type", "application/json")
        .body(Body::from(json!({"capability":"github.pull_requests.list", "risk":"medium", "requires_approval":false}).to_string())).unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
}
