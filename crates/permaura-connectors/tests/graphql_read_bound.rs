//! What reading an agent's GraphQL documents holds, counted with every growing buffer holding its old copy, for the shapes that cost the most: brackets nested as deep as the body allows, alias pairs by the hundred thousand, distinct names the response must redact, documents in a batched body and in a URL's `query` parameter, under the generic proxy and an imported spec with a rule.
//! The request check holds no more than [`graphql::read_bytes`] beside what the request builder holds anyway. The aliases a response is redacted under hold no more than [`response_alias_room`], beside the stack a document is read with and a URL's parse; that room is taken from the pool before any alias is kept when it is past [`UNCHARGED_ALIAS_ROOM`]. A document that names more than [`MAX_RESPONSE_ALIASES`] of them, or one whose room the pool does not have, has its whole response redacted; one within the uncharged room, or whose documents alias no key, takes nothing, whatever room the pool has.
//!
//! A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak. Every host here is synthetic.

mod metered_alloc;

use metered_alloc::{count_realloc_as_copy, peak_growth_sync, MIB};
use permaura_connectors::graphql;
use permaura_connectors::json_budget::MemoryPool;
use permaura_connectors::{
    request_refusal, response_alias_room, response_redact_keys, AuthScheme, Capability, CapabilityKind, GraphqlOperation, GraphqlSpec, HttpMethod,
    HttpSpec, ResponseRedaction, MAX_RESPONSE_ALIASES, UNCHARGED_ALIAS_ROOM,
};
use permaura_core::json_stream::agent_view;
use permaura_core::{Action, CredentialScrub, RiskTier};
use serde_json::{json, Value};

const DOC: usize = 2 * MIB - 64;

fn capability(action: Action, http: Option<HttpSpec>) -> Capability {
    Capability {
        id: "probe.request".into(),
        description: "synthetic".into(),
        risk: RiskTier::Low,
        action,
        requires_approval: false,
        resource: "probe".into(),
        secret_id: "sec".into(),
        kind: CapabilityKind::Http,
        command: None,
        http,
        ssh: None,
    }
}

fn graphql_spec(rule: Option<GraphqlSpec>) -> HttpSpec {
    HttpSpec {
        method: HttpMethod::Post,
        base_url: "https://api.probe.test".into(),
        path: "/graphql".into(),
        body_params: vec!["query".into(), "variables".into()],
        auth: AuthScheme::Bearer,
        graphql: rule,
        ..HttpSpec::default()
    }
}

/// GraphQL names distinct once lowercased, as the redaction compares them, shortest first, so as many fit as can.
fn names() -> impl Iterator<Item = String> {
    const FIRST: &[u8] = b"abcdefghijklmnopqrstuvwxyz_";
    const REST: &[u8] = b"abcdefghijklmnopqrstuvwxyz_0123456789";
    (0usize..).map(|mut n| {
        let mut len = 1;
        let mut count = FIRST.len();
        while n >= count {
            n -= count;
            len += 1;
            count *= REST.len();
        }
        let mut name = vec![FIRST[n % FIRST.len()]];
        n /= FIRST.len();
        for _ in 1..len {
            name.push(REST[n % REST.len()]);
            n /= REST.len();
        }
        String::from_utf8(name).unwrap()
    })
}

/// `{ x:b y:b ... }` with `count` aliases, every one distinct and every field one the redaction names.
fn distinct_aliases_up_to(count: usize, field: &str) -> String {
    let mut doc = String::from("{");
    for name in names().take(count) {
        doc.push_str(&name);
        doc.push(':');
        doc.push_str(field);
        doc.push(' ');
    }
    doc.push('}');
    doc
}

/// `{ x:b y:b ... }` up to `cap` bytes, every alias distinct and every field one the redaction names.
fn distinct_aliases(cap: usize, field: &str) -> String {
    let mut doc = String::from("{");
    for name in names() {
        if doc.len() + name.len() + field.len() + 3 > cap {
            break;
        }
        doc.push_str(&name);
        doc.push(':');
        doc.push_str(field);
        doc.push(' ');
    }
    doc.push('}');
    doc
}

fn percent_encoded(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b == b'_' { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// The documents a call's params carry, as the request check and the response read them.
fn documents(params: &Value) -> Vec<String> {
    let mut found: Vec<String> = match params.get("body") {
        Some(Value::Array(batch)) => batch.iter().filter_map(|op| op.get("query")?.as_str()).map(str::to_string).collect(),
        Some(body) => body.get("query").and_then(Value::as_str).map(str::to_string).into_iter().collect(),
        None => params.get("query").and_then(Value::as_str).map(str::to_string).into_iter().collect(),
    };
    if let Some(url) = params.get("url").and_then(Value::as_str) {
        let parsed = reqwest::Url::parse(url).unwrap();
        found.extend(parsed.query_pairs().filter(|(k, _)| k == "query").map(|(_, v)| v.into_owned()));
    }
    found
}

/// The redaction keys of a response and the room they hold, or `None` when it is redacted whole.
fn keys_of(redaction: ResponseRedaction) -> Option<(Vec<String>, u64)> {
    match redaction {
        ResponseRedaction::Keys { keys, room } => Some((keys, room.bytes())),
        ResponseRedaction::Whole => None,
    }
}

#[test]
fn what_reading_a_document_holds_is_inside_what_the_call_reserved_for_it() {
    count_realloc_as_copy(true);
    let scrub = CredentialScrub::default();
    let pool = MemoryPool::new(1 << 30);
    let proxy = capability(Action::Read, None);
    let proxy_control = capability(Action::Execute, None);
    let ruled = capability(
        Action::Read,
        Some(graphql_spec(Some(GraphqlSpec { operation: GraphqlOperation::Query, root_fields: vec!["viewer".into()] }))),
    );
    let ruled_control = capability(Action::Execute, Some(graphql_spec(None)));

    let body = |doc: &str| json!({ "method": "GET", "url": "https://api.probe.test/graphql", "body": { "query": doc, "variables": {} } });
    let deep = format!("query {{ a {}", "{".repeat(DOC - 12));
    let past_the_most = distinct_aliases(DOC, "b");
    let cases: Vec<(&str, &Capability, &Capability, Value, bool)> = vec![
        ("'{' x 2 MiB", &proxy, &proxy_control, body(&"{".repeat(DOC)), false),
        ("'a:b ' x 512 Ki", &proxy, &proxy_control, body(&"a:b ".repeat(DOC / 4)), false),
        ("'{a:b a:b ...}'", &proxy, &proxy_control, body(&format!("{{{}}}", "a:b ".repeat(DOC / 4 - 1))), false),
        ("brackets 2 MiB deep", &proxy, &proxy_control, body(&deep), false),
        ("distinct aliases of b", &proxy, &proxy_control, body(&past_the_most), true),
        ("distinct aliases, raw", &proxy, &proxy_control, body(&format!("{}%", distinct_aliases(DOC - 1, "secret"))), true),
        ("'a:' x 1 Mi", &proxy, &proxy_control, body(&"a:".repeat(DOC / 2)), false),
        ("as many as are kept", &proxy, &proxy_control, body(&distinct_aliases_up_to(MAX_RESPONSE_ALIASES as usize, "secret")), false),
        ("one more than that", &proxy, &proxy_control, body(&distinct_aliases_up_to(MAX_RESPONSE_ALIASES as usize + 1, "secret")), true),
        (
            "a batched body",
            &proxy,
            &proxy_control,
            json!({ "method": "POST", "url": "https://api.probe.test/graphql", "body": [
                { "query": distinct_aliases(DOC / 4, "secret"), "variables": {} },
                { "query": "{".repeat(DOC / 4) },
                { "query": format!("{{{}}}", "a:b ".repeat(DOC / 16)), "operationName": "Q" },
                "not an operation"
            ] }),
            true,
        ),
        (
            "a GET's query parameter",
            &proxy,
            &proxy_control,
            json!({ "method": "GET", "url": format!("https://api.probe.test/graphql?operationName=Q&qu%65ry={}", percent_encoded(&distinct_aliases(DOC / 9, "b"))) }),
            true,
        ),
        ("'{a:b ...}' under a rule", &ruled, &ruled_control, json!({ "query": format!("{{{}}}", "a:b ".repeat(DOC / 4 - 1)), "variables": {} }), false),
        ("distinct aliases under a rule", &ruled, &ruled_control, json!({ "query": distinct_aliases(DOC, "secret") }), true),
        ("an ordinary query", &proxy, &proxy_control, body("query Viewer($first: Int) { viewer { id name s: secret } }"), false),
    ];

    let keys: Vec<String> = ["b", "secret", "creator.email"].map(String::from).to_vec();
    let respond = |cap: &Capability, params: &Value, keys: &[String]| {
        peak_growth_sync(|| {
            let kept = keys_of(response_redact_keys("generic-http", cap, params, keys, &pool));
            let view = kept.as_ref().map(|(keys, _)| agent_view(br#"{"b":1,"a":{"secret":2},"s":3}"#, &scrub, keys).unwrap());
            (kept, view)
        })
    };
    // The redaction set and view a call gets with no document, which its keys alone decide.
    let (_, keys_alone) = respond(&proxy, &json!({ "method": "GET", "url": "https://api.probe.test/graphql" }), &keys);
    for (shape, cap, control, params, whole) in &cases {
        let docs = documents(params);
        let stack = docs.iter().map(|d| graphql::read_bytes(d) as usize).max().unwrap_or(0);
        let (_, builder) = peak_growth_sync(|| request_refusal("generic-http", control, params));
        let (_, gate) = peak_growth_sync(|| request_refusal("generic-http", cap, params));
        assert!(gate <= builder + stack, "{shape}: the request check held {gate} bytes, past the builder's {builder} and the {stack} its stack may take");

        let room = response_alias_room("generic-http", cap, params, &keys) as usize;
        // A URL's documents are read from its parse, one decoded parameter at a time.
        let url = params.get("url").and_then(Value::as_str).map_or(0, |url| 2 * url.len() + 64);
        let ((kept, _view), response) = respond(cap, params, &keys);
        println!(
            "{shape:<30} request check {:>6.2} MiB beside the builder's {:>5.2}; response {:>6.2} MiB beside {:>5.2} MiB taken, {}",
            gate as f64 / MIB as f64,
            builder as f64 / MIB as f64,
            response as f64 / MIB as f64,
            room as f64 / MIB as f64,
            kept.as_ref().map_or("redacted whole".to_string(), |(keys, _)| format!("{} keys", keys.len()))
        );
        assert_eq!(kept.is_none(), *whole, "{shape}: redacted whole");
        if let Some((_, held)) = &kept {
            let charged = if room as u64 > UNCHARGED_ALIAS_ROOM { room } else { 0 };
            assert!(*held as usize >= charged && (*held == 0) == (charged == 0), "{shape}: the pool held {held} bytes for {room}");
        }
        assert!(
            response <= keys_alone + room + stack + url,
            "{shape}: the response's aliases held {response} bytes, past the {keys_alone} its keys take alone, the {room} taken for them, the {stack} of a stack and {url} for a URL"
        );

        for document in &docs {
            let (_, reading) = peak_growth_sync(|| graphql::read(document, |_, _, _| {}));
            assert!(reading as u64 <= graphql::read_bytes(document), "{shape}: reading held {reading} bytes, past its {}", graphql::read_bytes(document));
            let (pairs, scanning) = peak_growth_sync(|| {
                let mut pairs = 0usize;
                graphql::aliases(document, |_, _| pairs += 1);
                pairs
            });
            assert_eq!(scanning, 0, "{shape}: scanning {pairs} alias pairs holds nothing");
        }
    }

    // A pool with no room redacts a response whose aliases need room from it, and asks nothing of it for a few aliases or none.
    let full = MemoryPool::new(1024);
    let _all = full.try_reserve(1024).unwrap();
    let many = body(&distinct_aliases_up_to(MAX_RESPONSE_ALIASES as usize / 2, "secret"));
    assert!(response_alias_room("generic-http", &proxy, &many, &keys) > UNCHARGED_ALIAS_ROOM);
    assert!(keys_of(response_redact_keys("generic-http", &proxy, &many, &keys, &full)).is_none(), "no room: redacted whole");
    let ordinary = body("query Viewer($first: Int) { viewer { id name s: secret } }");
    let (with_alias, held) = keys_of(response_redact_keys("generic-http", &proxy, &ordinary, &keys, &full)).expect("a few aliases need no room");
    assert_eq!((with_alias.last().map(String::as_str), held), (Some("s"), 0));
    let unaliased = body("query Viewer { viewer { id secret } }");
    assert_eq!(keys_of(response_redact_keys("generic-http", &proxy, &unaliased, &keys, &full)), Some((keys.clone(), 0)));
    assert!(response_alias_room("generic-http", &proxy, &ordinary, &keys) < 16 * 1024, "an ordinary query takes next to nothing");
    let searches = [
        json!({ "method": "GET", "url": "https://api.probe.test/items?q=1&page=2" }),
        json!({ "method": "GET", "url": "https://api.probe.test/items?query=red+shoes&page=2" }),
        json!({ "method": "POST", "url": "https://api.probe.test/items", "body": { "query": "red shoes" } }),
        json!({ "method": "POST", "url": "https://api.probe.test/items", "body": { "name": "x", "rows": [1, 2, 3] } }),
        unaliased,
    ];
    for no_alias in &searches {
        assert_eq!(response_alias_room("generic-http", &proxy, no_alias, &keys), 0, "{no_alias}");
        assert_eq!(keys_of(response_redact_keys("generic-http", &proxy, no_alias, &keys, &full)), Some((keys.clone(), 0)), "{no_alias}");
    }
    let imported_search = capability(Action::Read, Some(graphql_spec(None)));
    assert_eq!(response_alias_room("openapi", &imported_search, &json!({ "query": "red shoes" }), &keys), 0);
    assert_eq!(response_alias_room("github", &capability(Action::List, None), &json!({ "owner": "o", "repo": "r" }), &keys), 0);
    // An imported spec that never forwards `query` never reads one, whatever the agent sends.
    let unforwarded = capability(Action::Read, Some(HttpSpec { body_params: vec!["name".into()], ..graphql_spec(None) }));
    assert_eq!(response_alias_room("openapi", &unforwarded, &json!({ "query": "a:secret ".repeat(DOC / 9) }), &keys), 0);

    // However many keys a call has: a few aliases can take a set of them past a capacity step, which holds a table twice as large beside the old one, a cost that grows with the keys and not with the aliases.
    let few = |count: usize| body(&format!("{{ {} e: email }}", (0..count).map(|n| format!("s{n}: secret")).collect::<Vec<_>>().join(" ")));
    let documents = [few(0), few(1), few(3), few(8), body(&distinct_aliases_up_to(300, "secret"))];
    for count in 1..=240 {
        let keys: Vec<String> = (0..count)
            .map(|n| match n {
                0 => "secret".to_string(),
                1 => "creator.email".to_string(),
                n if n % 10 == 0 => format!("o{n}.f{n}"),
                n => format!("key_{n}"),
            })
            .collect();
        let (_, keys_alone) = respond(&proxy, &json!({ "method": "GET", "url": "https://api.probe.test/graphql" }), &keys);
        for params in &documents {
            let room = response_alias_room("generic-http", &proxy, params, &keys) as usize;
            let stack = documents_of(params);
            let url = params["url"].as_str().map_or(0, |url| 2 * url.len() + 64);
            let ((kept, _), response) = respond(&proxy, params, &keys);
            assert!(kept.is_some(), "{count} keys: redacted whole");
            assert!(
                response <= keys_alone + room + stack + url,
                "{count} keys, {:.40}: the response's aliases held {response} bytes, past the {keys_alone} its keys take alone, the {room} taken for them, the {stack} of a stack and {url} for a URL",
                params["body"]["query"]
            );
        }
    }
}

/// The most the stack [`graphql::read`] keeps for any document `params` carries can take.
fn documents_of(params: &Value) -> usize {
    documents(params).iter().map(|d| graphql::read_bytes(d) as usize).max().unwrap_or(0)
}
