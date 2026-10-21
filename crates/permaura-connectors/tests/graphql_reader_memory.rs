//! What reading an agent's GraphQL document holds, measured on the two calls the gateway makes with it: the request check, at the gate and when the request is built, and the alias resolution for its response. Reading the document holds nothing in proportion to it but the brackets open at once. Before, the reader lexed the whole document into a vector of owned tokens and collected every operation and alias pair it found, so on these shapes, about 2 MiB each, either call held 38.5 to 147.3 MiB, about 19 to 74 times the document. The exception is '%' x 2 MiB, which the lexer refuses at its first byte; there the request check held nothing and the alias resolution 2 or 50 MiB.
//!
//! The old reader's figures above were measured with this binary before `response_redact_keys` took the pool; it no longer compiles against the old reader. A binary of its own with one test, because the meter is the process-wide allocator and any test running beside it would move the peak. Every host here is synthetic.

mod metered_alloc;

use metered_alloc::{count_realloc_as_copy, peak_growth_sync, MIB};
use permaura_connectors::json_budget::MemoryPool;
use permaura_connectors::{request_refusal, response_redact_keys, Capability, CapabilityKind};
use permaura_core::{Action, RiskTier};
use serde_json::json;

/// What fits in the 2 MiB execution body beside `{"query":"...","variables":{}}`.
const DOC: usize = 2 * MIB - 64;

fn proxy(action: Action) -> Capability {
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
        http: None,
        ssh: None,
    }
}

#[test]
fn reading_an_agents_graphql_document_holds_nothing_in_proportion_to_it_but_its_open_brackets() {
    count_realloc_as_copy(true);
    let read = proxy(Action::Read);
    // Its request check reads nothing (a write capability with no rule), so it measures the builder alone.
    let control = proxy(Action::Execute);
    let keys = vec!["b".to_string(), "secret".to_string()];
    let pool = MemoryPool::new(1 << 30);
    let shapes = [
        ("'{' x 2 MiB", "{".repeat(DOC)),
        ("'a:b ' x 512 Ki", "a:b ".repeat(DOC / 4)),
        ("'{a:b a:b ...}'", format!("{{{}}}", "a:b ".repeat(DOC / 4 - 1))),
        ("'{a}' x 700 Ki", "{a}".repeat(DOC / 3)),
        ("'{ a a a ... }'", format!("{{{}}}", "a ".repeat(DOC / 2 - 1))),
        ("'a:' x 1 Mi", "a:".repeat(DOC / 2)),
        ("'%' x 2 MiB", "%".repeat(DOC)),
        ("'a:b ' ... '%'", format!("{}%", "a:b ".repeat(DOC / 4 - 1))),
    ];
    for (shape, doc) in &shapes {
        // A body with `variables` is held as GraphQL whatever it reads as; one without only when it reads as one.
        for (check, body) in [("content", json!({ "query": doc })), ("shaped", json!({ "query": doc, "variables": {} }))] {
            let params = json!({ "method": "GET", "url": "https://api.probe.test/graphql", "body": body });
            let (_, builder) = peak_growth_sync(|| request_refusal("generic-http", &control, &params));
            let (_, gate) = peak_growth_sync(|| request_refusal("generic-http", &read, &params));
            let (_, response) = peak_growth_sync(|| response_redact_keys("generic-http", &read, &params, &keys, &pool));
            let gate = gate.saturating_sub(builder);
            println!("{shape:<20} {check:<8} request check {:>6.1} MiB, response aliases {:>6.1} MiB", gate as f64 / MIB as f64, response as f64 / MIB as f64);
            assert!(gate < 8 * MIB, "{shape} ({check}): the request check held {} MiB over the builder's own", gate / MIB);
            assert!(response < 8 * MIB, "{shape} ({check}): resolving its aliases held {} MiB", response / MIB);
        }
    }
}
