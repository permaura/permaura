//! What an approval's rendering may build on a hosted worker: never under the 1.3.52 hold ceiling (164 MiB, the pool less four bodies of text and an execution's buffers), so a control-plane change, which gets no tree check, renders wherever 1.3.52 rendered it, though agent calls meet a 128 MiB ceiling. A row over it renders as too large to show, which no device can sign an approve for.
//!
//! One test in a binary of its own, because the rendering limit is read from the environment once per process. Every credential here is synthetic.

use permaura_gateway::approval_display::tree_bytes;
use permaura_gateway::connectors::json_budget::estimate;
use permaura_gateway::limits::{render_limit_bytes, LimitsConfig};
use permaura_gateway::store::PendingApproval;

mod common;

const MIB: u64 = 1024 * 1024;

fn change_held_with(params: String) -> PendingApproval {
    let mut approval: PendingApproval = serde_json::from_value(serde_json::json!({
        "id": "appr_change",
        "session_id": "sess_operator",
        "capability": "permaura.connector.install",
        "resource": "permaura",
        "message": "Install a connector?",
        "status": "pending",
    }))
    .unwrap();
    approval.params = permaura_core::JsonText::from_string(params).unwrap();
    approval
}

/// A manifest-like document of `rows` one-letter capability lines.
fn manifest(rows: usize) -> String {
    format!(r#"{{"capabilities":[{}]}}"#, vec![r#"{"a":1}"#; rows].join(","))
}

#[test]
fn a_hosted_rendering_builds_trees_up_to_the_1_3_52_hold_ceiling() {
    common::isolate_from_the_real_install();
    std::env::remove_var("PERMAURA_LIMIT_JSON_POOL_BYTES");
    std::env::set_var("PERMAURA_HOSTED", "1");
    let config = LimitsConfig::from_env();
    assert_eq!(config.unpacked_limit(), 128 * MIB);
    assert_eq!(render_limit_bytes(), 164 * MIB);

    let between = manifest(210_000);
    let tree = estimate(between.as_bytes());
    assert!(tree > 128 * MIB && tree <= 164 * MIB, "{tree}");
    assert_eq!(tree_bytes(&change_held_with(between)), Some(tree), "a change 1.3.52 rendered renders");

    let over = manifest(250_000);
    assert!(estimate(over.as_bytes()) > 164 * MIB);
    assert_eq!(tree_bytes(&change_held_with(over)), None, "past it, too large to show");
    std::env::remove_var("PERMAURA_HOSTED");
}
