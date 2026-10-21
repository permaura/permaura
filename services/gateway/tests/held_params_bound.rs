//! A held call keeps its params in the store until a human decides, and every approvals listing reads every pending row, so what an agent can make the gateway hold is bounded: one held call's params by their cost as a tree, and every pending agent hold together by the bytes the rows take.
//! Neither refusal writes anything. A held call's params are parsed for its execution under the memory budget before the approval is claimed, so a budget with no room leaves it pending.
//!
//! Every credential here is synthetic.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::connectors::json_budget::{MemoryCharge, MemoryPool};
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse, MockHttpClient};
use permaura_gateway::limits::{Limits, LimitsConfig};
use permaura_gateway::memory::MemoryBudget;
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::sqlite::SqliteStore;
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, seed, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

/// High risk, so the seeded policy holds it for a human.
const HELD: &str = "github.pull_requests.create";

fn gateway(config: &LimitsConfig) -> AppState {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let service = EnforcementService::new(store, Arc::new(MockHttpClient::new())).with_memory_budget(MemoryBudget::from_config(config));
    AppState::new(service)
}

async fn invoke(state: &AppState, params: Value) -> (StatusCode, Value) {
    invoke_text(state, json!({ "capability": HELD, "params": params }).to_string()).await
}

async fn invoke_text(state: &AppState, body: String) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method("POST")
        .uri("/v1/invoke")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn pr(extra: Value) -> Value {
    let mut params = json!({ "owner": "synthetic", "repo": "synthetic", "title": "t", "head": "h", "base": "b" });
    params.as_object_mut().unwrap().insert("extra".into(), extra);
    params
}

fn one_key_objects(count: usize) -> Value {
    Value::Array((0..count).map(|_| json!({ "a": 1 })).collect())
}

fn pending(state: &AppState) -> usize {
    state.service.store().list_approvals(Some("pending")).unwrap().len()
}

fn audit_len(state: &AppState) -> usize {
    state.service.store().audit_events(None).unwrap().len()
}

/// One ceiling on an agent call's unpacked size, held or not. On a 64 MiB pool it is 32 MiB, half the pool, and a call over it is refused with a 413 whether the policy would run it or hold it, before anything is written.
#[tokio::test]
async fn a_call_over_the_ceiling_is_refused_held_or_not_and_nothing_is_written() {
    let state = gateway(&LimitsConfig { json_pool_bytes: 64 * 1024 * 1024, ..LimitsConfig::defaults_for(true) });
    assert_eq!(state.service.memory().unpacked_limit(), 32 * 1024 * 1024);
    let before = audit_len(&state);
    // About 470 KiB of one-key objects: well inside the 2 MiB body limit, about 41 MiB as a tree, over the 32 MiB ceiling.
    for capability in [UNHELD, HELD] {
        let (status, answer) = invoke_as(&state, capability, &pr(one_key_objects(60_000))).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{capability}: {answer}");
        assert!(answer["error"].as_str().unwrap().contains("once unpacked"), "{answer}");
    }
    assert_eq!(pending(&state), 0, "no hold was written");
    assert_eq!(audit_len(&state), before, "and nothing was recorded");

    // A large but flat value (a base64 file for an SFTP put is the realistic case) is held.
    let (status, answer) = invoke(&state, pr(json!("A".repeat(1536 * 1024)))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", answer.to_string().chars().take(200).collect::<String>());
    assert_eq!(pending(&state), 1);
}

/// A list of `item(i)` as long as fits in `cap` bytes of JSON.
fn list_up_to(cap: usize, item: impl Fn(usize) -> Value) -> Value {
    let (mut items, mut len) = (Vec::new(), 2);
    loop {
        let next = item(items.len());
        let more = next.to_string().len() + 1;
        if len + more > cap {
            return Value::Array(items);
        }
        len += more;
        items.push(next);
    }
}

fn uuid(i: usize) -> Value {
    let h = (i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    json!(format!("{:08x}-{:04x}-4{:03x}-a{:03x}-{:012x}", h >> 32, (h >> 16) & 0xffff, h & 0xfff, (h >> 20) & 0xfff, h.rotate_left(17) & 0xffff_ffff_ffff))
}

const PARAGRAPH: &str = "Hi Sam, thanks for getting back to me so quickly. I have attached the revised schedule for the spring delivery and marked the two dates that moved. Could you confirm the loading dock is free on both mornings, and let me know if the updated quantities work for your team? Best regards, Alex";

/// A held call's tree is bounded, by the one ceiling on every agent call's unpacked size since 1.3.53 and before that by a hold ceiling (earlier builds had neither and held every call up to the body limit), and approving one reserves its text beside the tree within the pool, so lists of strings and of messages up to the 2 MiB body are held and can be approved. Checked against the tree and twice the text, as an earlier build did, 1650 KiB of any of these was 413.
#[tokio::test]
async fn lists_of_strings_and_messages_up_to_the_body_limit_are_held_and_approved() {
    let state = gateway(&LimitsConfig::defaults_for(true));
    type Item = fn(usize) -> Value;
    let family: [(&str, Item); 4] = [
        ("UUIDs", uuid),
        ("e-mail addresses", |i| json!(format!("firstname.lastname{i}@example.com"))),
        ("URLs", |i| json!(format!("https://example.com/items/{i}"))),
        ("messages {to, subject, body}", |i| {
            json!({ "to": format!("customer{i}@example.com"), "subject": format!("Your order #{}", 100_000 + i), "body": PARAGRAPH })
        }),
    ];
    for (shape, item) in family {
        for kib in [1300, 1650, 2040] {
            let (status, answer) = invoke(&state, pr(list_up_to(kib * 1024, item))).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{kib} KiB of {shape}: {}", answer.to_string().chars().take(300).collect::<String>());
            let id = answer["approval_id"].as_str().unwrap().to_string();
            let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
            assert_eq!(approved.status, "approved", "{kib} KiB of {shape}");
        }
    }
    assert_eq!(pending(&state), 0);
}

/// The longest list of `item(i)` whose request body, as [`invoke`] sends it, is at most `body` bytes.
fn list_for_body(body: usize, item: impl Fn(usize) -> Value) -> Value {
    let envelope = json!({ "capability": HELD, "params": pr(json!([])) }).to_string().len() - 2;
    list_up_to(body - envelope, item)
}

const FIRST: [&str; 8] = ["james", "maria", "li", "ahmed", "olivia", "noah", "sofia", "kenji"];
const LAST: [&str; 8] = ["smith", "garcia", "wong", "khan", "brown", "nguyen", "rossi", "tanaka"];
const DOMAIN: [&str; 5] = ["gmail.com", "outlook.com", "yahoo.com", "company.co", "icloud.com"];

/// Not held: low risk, so the seeded policy runs it at once. It takes the same params as [`HELD`].
const UNHELD: &str = "github.pull_requests.list";

async fn invoke_as(state: &AppState, capability: &str, params: &Value) -> (StatusCode, Value) {
    invoke_text(state, json!({ "capability": capability, "params": params }).to_string()).await
}

const LABELS: [&str; 8] = ["bug", "ui", "p1", "docs", "infra", "api", "p2", "ux"];
const COUNTRIES: [&str; 8] = ["US", "GB", "DE", "FR", "JP", "AU", "CA", "NZ"];

/// One ceiling for held and unheld calls: the same params are sent to a call the policy runs at once and to one it holds, on hosted defaults, at 1.0, 1.3, 1.65 and 2.0 MiB bodies, and both are admitted and the held one approved. The costliest here, 2 MiB of `{x, y}` points, is 112.6 MiB as a tree, under the 128 MiB ceiling every agent call is checked against before the policy decides whether to hold it. At the 25 MiB hold ceiling of an earlier repair `{id}` rows were refused held from 472 KiB while the same call ran unheld, and 1.3.52 refused held, and ran unheld, trees between its 164 MiB hold ceiling and 183 MiB and params serde_json writes longer than the body; a call over the one ceiling is refused both ways (`unpacked_limit.rs`), and longer text is held at its stored length (below).
#[tokio::test]
async fn a_list_admitted_unheld_is_held_and_approved_at_every_size_on_hosted_defaults() {
    const MIB: f64 = 1024.0 * 1024.0;
    type Item = Box<dyn Fn(usize) -> Value>;
    let family: Vec<(&str, Item)> = vec![
        ("integer ids, 6 to 7 digits", Box::new(|i| json!(100_000 + i as u64))),
        ("one-digit numbers", Box::new(|i| json!(i % 10))),
        ("{id} rows", Box::new(|i| json!({ "id": 100_000 + i }))),
        ("line items {id, qty}", Box::new(|i| json!({ "id": 100_000 + i, "qty": i % 9 + 1 }))),
        ("line items {sku, quantity, price}", Box::new(|i| json!({ "sku": format!("SKU-{i:06}"), "quantity": i % 9 + 1, "price": (i % 500) as f64 + 0.99 }))),
        ("contacts {name, email}", Box::new(|i| json!({ "name": format!("{} {}", FIRST[i % 8], LAST[i / 8 % 8]), "email": format!("{}.{}{}@{}", FIRST[i % 8], LAST[i / 8 % 8], i / 64, DOMAIN[i % 5]) }))),
        ("contacts {id, email}", Box::new(|i| json!({ "id": i, "email": format!("user{i}@example.com") }))),
        ("points {x, y}", Box::new(|i| json!({ "x": i % 10, "y": i / 10 % 10 }))),
        ("country codes", Box::new(|i| json!(COUNTRIES[i % 8]))),
        ("sheet rows of 6 short strings", Box::new(|i| json!([FIRST[i % 8], LAST[i / 8 % 8], format!("{i}"), COUNTRIES[i % 8], "yes", "12.50"]))),
        ("sheet rows of 6 small numbers", Box::new(|i| json!([i % 100, (i * 7) % 1000, (i * 13) % 50, i % 9, (i * 3) % 400, (i * 11) % 75]))),
        ("labels of 2 to 5 characters", Box::new(|i| json!(LABELS[i % 8]))),
        ("e-mail addresses", Box::new(|i| json!(format!("user{i}@example.com")))),
        ("E.164 phone numbers", Box::new(|i| json!(format!("+1555{i:07}")))),
        ("messages with a one-line body", Box::new(|i| json!({ "to": format!("user{i}@example.com"), "subject": format!("Re: order {i}"), "body": "Thanks, see you then." }))),
    ];
    for (shape, item) in &family {
        let state = gateway(&LimitsConfig::defaults_for(true));
        for mib in [1.0, 1.3, 1.65, 2.0] {
            let params = pr(list_for_body((mib * MIB) as usize, item));
            let (unheld, ran) = invoke_as(&state, UNHELD, &params).await;
            let (held, answer) = invoke_as(&state, HELD, &params).await;
            let cut = |v: &Value| v.to_string().chars().take(300).collect::<String>();
            assert_eq!((unheld, held), (StatusCode::OK, StatusCode::ACCEPTED), "{mib} MiB of {shape}: unheld {}, held {}", cut(&ran), cut(&answer));
            let id = answer["approval_id"].as_str().unwrap().to_string();
            let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
            assert_eq!(approved.status, "approved", "{mib} MiB of {shape}");
        }
        assert_eq!(pending(&state), 0);
    }
}

/// Raising the body limit lowered the 1.3.52 hold ceiling while the unheld bound stayed put, so ordinary lists ran unheld and were refused held. Now one ceiling decides for both, and a raised body limit leaves it at 128 MiB: with an 8 or a 16 MiB body, 2.5 MiB of `{x, y}` points (about 141 MiB as a tree) is refused both ways, and 2 MiB of them (about 113 MiB), which 1.3.52 ran unheld at either, is admitted both ways and approved.
#[tokio::test]
async fn a_raised_body_limit_leaves_the_one_ceiling_where_it_is_for_held_and_unheld_calls() {
    const MIB: usize = 1024 * 1024;
    let cut = |v: &Value| v.to_string().chars().take(300).collect::<String>();
    let points = |i: usize| json!({ "x": i % 10, "y": i / 10 % 10 });
    for (body, ceiling, refused_at, admitted_at) in [(8 * MIB, 128 * MIB, 5 * MIB / 2, 2 * MIB), (16 * MIB, 128 * MIB, 5 * MIB / 2, 2 * MIB)] {
        let config = LimitsConfig { body_exec_bytes: body, ..LimitsConfig::defaults_for(true) };
        let state = gateway(&config).with_limits(Arc::new(Limits::new(config.clone())));
        assert_eq!(state.service.memory().unpacked_limit(), ceiling as u64, "a {body}-byte body limit");
        let before = audit_len(&state);
        let over = pr(list_for_body(refused_at, points));
        for capability in [UNHELD, HELD] {
            let (status, answer) = invoke_as(&state, capability, &over).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}-byte limit, {capability}: {}", cut(&answer));
        }
        assert_eq!((pending(&state), audit_len(&state)), (0, before), "nothing was written");
        let under = pr(list_for_body(admitted_at, points));
        let (unheld, ran) = invoke_as(&state, UNHELD, &under).await;
        assert_eq!(unheld, StatusCode::OK, "{body}-byte limit: {}", cut(&ran));
        let (held, answer) = invoke_as(&state, HELD, &under).await;
        assert_eq!(held, StatusCode::ACCEPTED, "{body}-byte limit: {}", cut(&answer));
        let id = answer["approval_id"].as_str().unwrap().to_string();
        let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
        assert_eq!(approved.status, "approved");
    }
}

#[tokio::test]
async fn pending_holds_are_bounded_together_by_the_bytes_they_store() {
    // A 16 KiB body keeps the budget's floor, one hold's text and the rest of its row, under the 128 KiB asked for.
    let config = LimitsConfig { held_total_bytes: 128 * 1024, body_exec_bytes: 16 * 1024, ..LimitsConfig::defaults_for(true) };
    let state = gateway(&config);
    assert_eq!(state.service.memory().held_total_bytes(), 128 * 1024);
    let mut held = 0;
    let refusal = loop {
        let (status, answer) = invoke(&state, pr(json!("x".repeat(10 * 1024)))).await;
        if status != StatusCode::ACCEPTED {
            break (status, answer);
        }
        held += 1;
        assert!(held < 20, "the ceiling never bit");
    };
    assert!((11..=12).contains(&held), "about 128 KiB of 10 KiB holds: {held}");
    assert_eq!(refusal.0, StatusCode::TOO_MANY_REQUESTS, "{}", refusal.1);
    assert_eq!(refusal.1["reason"], "held_params", "{}", refusal.1);
    assert_eq!(pending(&state), held, "the refused call was not held");
    assert!(state.service.store().pending_hold_bytes().unwrap() <= 128 * 1024);

    // Resolving one makes room for the next.
    let first = state.service.store().list_approvals(Some("pending")).unwrap().pop().unwrap();
    state.service.resolve_approval(&first.id, false, "bearer", Some("operator")).await.unwrap();
    let (status, answer) = invoke(&state, pr(json!("x".repeat(10 * 1024)))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");
}

/// `bytes` of description on [`HELD`], which every hold of it stores in its row.
fn describe_held(state: &AppState, bytes: usize) {
    let store = state.service.store();
    let mut cap = store.get_capability(HELD).unwrap().unwrap();
    cap.description = "d".repeat(bytes);
    store.put_capability(cap).unwrap();
}

/// An agent hold was checked against the held-params ceiling by its params' text alone, while the pending rows are counted whole, so the queue could pass the ceiling by one row's other fields. A row is counted whole now, its capability's description, message and ids with its params.
#[tokio::test]
async fn an_agent_holds_whole_row_is_counted_against_the_ceiling() {
    const KIB: u64 = 1024;
    let ceiling = 110 * KIB;
    // An 8 KiB body keeps the budget's floor under the 110 KiB asked for.
    let state = gateway(&LimitsConfig { held_total_bytes: ceiling, body_exec_bytes: 8 * 1024, ..LimitsConfig::defaults_for(true) });
    describe_held(&state, 20 * 1024);
    let mut held = 0u64;
    let refusal = loop {
        let (status, answer) = invoke(&state, pr(json!("x".repeat(4 * 1024)))).await;
        if status != StatusCode::ACCEPTED {
            break (status, answer);
        }
        held += 1;
        assert!(held < 20, "the ceiling never bit");
    };
    assert_eq!(refusal.0, StatusCode::TOO_MANY_REQUESTS, "{}", refusal.1);
    let stored = state.service.store().pending_hold_bytes().unwrap();
    let row = stored / held;
    assert!(row > 24 * KIB, "each row carries the 20 KiB description beside its 4 KiB of params: {row}");
    assert!(stored <= ceiling, "the pending rows stay under the ceiling: {stored} of {ceiling}, {held} holds");
    assert!(stored + row > ceiling, "and the refused one would have passed it");
}

/// A hold whose row is larger than the held-params budget was refused with a 429 on an empty queue, which no retry could clear, though the same call ran unheld. The budget is never below one hold of a body's length of params and the room [`permaura_gateway::limits::HOLD_ROW_OVERHEAD_BYTES`] gives the rest of its row, and a hold alone in the queue is admitted whatever its row takes: here its capability's description is longer than that room.
#[tokio::test]
async fn a_hold_alone_in_the_queue_is_admitted_whatever_its_row_takes() {
    let state = gateway(&LimitsConfig { held_total_bytes: 1024 * 1024, ..LimitsConfig::defaults_for(true) });
    describe_held(&state, 128 * 1024);
    let params = pr(json!("A".repeat(2 * 1024 * 1024 - 400)));
    let cut = |v: &Value| v.to_string().chars().take(300).collect::<String>();
    let (unheld, ran) = invoke_as(&state, UNHELD, &params).await;
    assert_eq!(unheld, StatusCode::OK, "{}", cut(&ran));
    let (held, answer) = invoke_as(&state, HELD, &params).await;
    assert_eq!(held, StatusCode::ACCEPTED, "{}", cut(&answer));
    let stored = state.service.store().pending_hold_bytes().unwrap();
    assert!(stored > state.service.memory().held_total_bytes(), "one row past the budget, held alone: {stored}");

    // With it waiting, the next is refused until it is resolved.
    let (status, refused) = invoke_as(&state, HELD, &params).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{}", cut(&refused));
    assert_eq!(refused["reason"], "held_params");
    let id = answer["approval_id"].as_str().unwrap().to_string();
    state.service.resolve_approval(&id, false, "bearer", Some("operator")).await.unwrap();
    let (status, answer) = invoke_as(&state, HELD, &params).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", cut(&answer));
}

#[tokio::test]
async fn approving_with_no_room_in_the_budget_leaves_the_call_pending() {
    let state = gateway(&LimitsConfig { json_pool_wait: Duration::from_millis(50), ..LimitsConfig::defaults_for(true) });
    let (status, answer) = invoke(&state, pr(json!({ "note": "small" }))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");
    let id = answer["approval_id"].as_str().unwrap().to_string();

    let pool = state.service.memory().pool().clone();
    let everything = pool.reserve(pool.max_bytes(), Duration::ZERO).await.unwrap();
    let refused = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await;
    let error = refused.expect_err("no room to parse the held params");
    assert!(error.to_string().contains("retry"), "{error}");
    let row = state.service.store().get_approval(&id).unwrap().unwrap();
    assert_eq!(row.status, "pending", "nothing was claimed: the approver can try again");

    drop(everything);
    let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
    assert_eq!(approved.status, "approved");
    assert!(approved.result.is_some(), "the held call ran with its params");
    assert_eq!(pool.available_bytes(), pool.max_bytes(), "and gave its room back");
}

async fn get(state: &AppState, uri: &str) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder().uri(uri).header("authorization", format!("Bearer {}", seed::DEMO_TOKEN)).body(Body::empty()).unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Params serde_json writes longer than they were sent (exponent-written numbers: 2 MiB of `1e15` is 24 MiB as a tree and 7.6 MiB as text) were refused held while they ran unheld. A held call's text is now kept and charged at its stored length, never refused for being longer: its row counts whole against the held total, and approving it reserves four times that text. On hosted and self-run defaults the call runs unheld, is held, and is approved.
#[tokio::test]
async fn a_held_call_written_longer_than_the_body_limit_is_held_and_charged_at_its_stored_length() {
    let mut body = format!(r#"{{"capability":"{HELD}","params":{{"owner":"synthetic","repo":"synthetic","title":"t","head":"h","base":"b","extra":[1e15"#);
    while body.len() + 8 < 2040 * 1024 {
        body.push_str(",1e15");
    }
    body.push_str("]}}");
    for hosted in [true, false] {
        let state = gateway(&LimitsConfig::defaults_for(hosted));
        let (status, answer) = invoke_text(&state, body.replacen(HELD, UNHELD, 1)).await;
        assert_eq!(status, StatusCode::OK, "hosted {hosted}, unheld: {}", answer.to_string().chars().take(300).collect::<String>());
        let (status, answer) = invoke_text(&state, body.clone()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "hosted {hosted}, held: {}", answer.to_string().chars().take(300).collect::<String>());
        let id = answer["approval_id"].as_str().unwrap().to_string();
        let row = state.service.store().get_approval(&id).unwrap().unwrap();
        assert!(row.params.len() > 7 * 1024 * 1024, "kept as this gateway writes it: {} bytes", row.params.len());
        assert!(state.service.store().pending_hold_bytes().unwrap() > row.params.len() as u64, "and its row counted whole");
        let approved = state.service.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
        assert_eq!(approved.status, "approved", "hosted {hosted}");
        let pool = state.service.memory().pool();
        assert_eq!(pool.available_bytes(), pool.max_bytes(), "the approval gave its room back");
    }
}

/// Rendering a held call for an approver builds its params tree, up to the one ceiling on an agent call's unpacked size, so a listing, a read and the check of what a device was shown each charge that tree to the JSON pool while they render. With no room they are a 429 "memory" the surface can retry; nothing is rendered uncharged.
#[tokio::test]
async fn rendering_a_held_call_charges_its_tree_to_the_pool() {
    let state = gateway(&LimitsConfig { json_pool_wait: Duration::from_millis(50), ..LimitsConfig::defaults_for(true) });
    let (status, answer) = invoke(&state, pr(list_up_to(2040 * 1024, |i| json!(100_000 + i)))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{}", answer.to_string().chars().take(300).collect::<String>());
    let id = answer["approval_id"].as_str().unwrap().to_string();
    let row = state.service.store().get_approval(&id).unwrap().unwrap();
    let tree = permaura_gateway::approval_display::tree_bytes(&row).expect("a held call renders from a tree");
    assert!(tree > 16 * 1024 * 1024, "2 MiB of integer ids is a large tree: {tree}");

    let pool = state.service.memory().pool().clone();
    let most = pool.reserve(pool.max_bytes() - tree / 2, Duration::ZERO).await.unwrap();
    for uri in ["/v1/approvals".to_string(), format!("/v1/approvals/{id}")] {
        let (status, answer) = get(&state, &uri).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "GET {uri}: {}", answer.to_string().chars().take(300).collect::<String>());
        assert_eq!(answer["reason"], "memory", "GET {uri}");
    }
    let approve: permaura_relay::ApprovalResult = serde_json::from_value(json!({
        "job_id": id, "approval_id": id, "approve": true, "request_hash": "h", "approver": "device:phone", "decided_at": 1,
        "display_digest": "d", "device_sig": "s",
    }))
    .unwrap();
    let refused = state.service.display_room_for_signed(&approve).await.expect_err("an approve's check renders the held call");
    assert!(refused.to_string().contains("retry"), "{refused}");
    let deny = permaura_relay::ApprovalResult { approve: false, ..approve.clone() };
    assert_eq!(state.service.display_room_for_signed(&deny).await.unwrap().bytes(), 0, "a denial renders nothing");

    drop(most);
    for uri in ["/v1/approvals".to_string(), format!("/v1/approvals/{id}")] {
        let (status, answer) = get(&state, &uri).await;
        assert_eq!(status, StatusCode::OK, "GET {uri}: {}", answer.to_string().chars().take(300).collect::<String>());
        assert_eq!(pool.available_bytes(), pool.max_bytes(), "GET {uri} gave its room back");
    }
    assert!(state.service.display_room_for_signed(&approve).await.unwrap().bytes() >= tree);
}

/// Answers like [`MockHttpClient`], and while the call is out queues a reservation for all but 1 MiB of the pool, as another large call would, which it keeps once the approved call has given its room back.
struct CrowdsThePool {
    pool: Arc<MemoryPool>,
    crowd: Arc<Mutex<Option<MemoryCharge>>>,
    inner: MockHttpClient,
}

#[async_trait]
impl HttpClient for CrowdsThePool {
    async fn send(&self, request: HttpRequest) -> anyhow::Result<HttpResponse> {
        let (pool, crowd) = (self.pool.clone(), self.crowd.clone());
        tokio::spawn(async move {
            let charge = pool.reserve(pool.max_bytes() - 1024 * 1024, Duration::from_secs(60)).await.unwrap();
            *crowd.lock().unwrap() = Some(charge);
        });
        tokio::task::yield_now().await;
        self.inner.send(request).await
    }
}

async fn post_approval(state: &AppState, id: &str, approve: bool) -> (StatusCode, Value) {
    let app = build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
    let request = Request::builder()
        .method("POST")
        .uri("/v1/approvals")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", seed::DEMO_TOKEN))
        .body(Body::from(json!({ "approval_id": id, "approve": approve }).to_string()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Once an approval is settled, rendering it is only for reading it back, so a pool with no room to render it at once answers with the recorded status and no rendering, never a 429 that reads as a call that did not run or a refusal that was not recorded. The rendering is served again once there is room.
#[tokio::test]
async fn a_settled_approval_is_answered_with_its_status_when_the_pool_has_no_room_to_render_it() {
    common::isolate_from_the_real_install();
    let config = LimitsConfig { json_pool_wait: Duration::from_millis(50), ..LimitsConfig::defaults_for(true) };
    let budget = MemoryBudget::from_config(&config);
    let pool = budget.pool().clone();
    let crowd = Arc::new(Mutex::new(None));
    let client = CrowdsThePool { pool: pool.clone(), crowd: crowd.clone(), inner: MockHttpClient::new() };
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    seed::seed(store.as_ref()).expect("the demo estate seeds");
    let state = AppState::new(EnforcementService::new(store, Arc::new(client)).with_memory_budget(budget));

    // 1 MiB of integer ids, a 12 MiB tree: more than the crowd leaves.
    let mut ids = Vec::new();
    for _ in 0..2 {
        let (status, answer) = invoke(&state, pr(list_up_to(1024 * 1024, |i| json!(100_000 + i)))).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{}", answer.to_string().chars().take(300).collect::<String>());
        ids.push(answer["approval_id"].as_str().unwrap().to_string());
    }
    let tree = permaura_gateway::approval_display::tree_bytes(&state.service.store().get_approval(&ids[0]).unwrap().unwrap()).unwrap();
    assert!(tree > 1024 * 1024, "{tree}");

    let (status, answer) = post_approval(&state, &ids[0], true).await;
    assert_eq!(status, StatusCode::OK, "the call ran: {}", answer.to_string().chars().take(300).collect::<String>());
    assert_eq!(answer["status"], "approved");
    assert!(answer["result"].is_object(), "{answer}");
    assert_eq!(answer["params_rendered"], false, "{answer}");
    assert_eq!(answer["params_display"]["rows"], json!([]));

    for _ in 0..100 {
        if crowd.lock().unwrap().is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(crowd.lock().unwrap().is_some(), "the crowd took the pool when the approved call gave it back");
    assert!(pool.available_bytes() < tree);

    let (status, answer) = post_approval(&state, &ids[1], false).await;
    assert_eq!(status, StatusCode::OK, "the denial was recorded: {}", answer.to_string().chars().take(300).collect::<String>());
    assert_eq!(answer["status"], "denied");
    assert_eq!(answer["params_rendered"], false, "{answer}");
    assert_eq!(state.service.store().get_approval(&ids[1]).unwrap().unwrap().status, "denied");

    drop(crowd.lock().unwrap().take());
    let (status, answer) = get(&state, &format!("/v1/approvals/{}", ids[0])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["status"], "approved");
    assert!(answer.get("params_rendered").is_none(), "rendered again: {}", answer.to_string().chars().take(300).collect::<String>());
    assert!(!answer["params_display"]["rows"].as_array().unwrap().is_empty());
    assert_eq!(pool.available_bytes(), pool.max_bytes());
}
