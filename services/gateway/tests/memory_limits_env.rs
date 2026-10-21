//! The JSON memory limits the environment overrides, and the one ceiling on an agent call's unpacked size that follows them.
//!
//! One test in a binary of its own, because the variables are process-wide and every other binary's tests run in parallel with each other.

mod common;

use permaura_gateway::limits::{LimitsConfig, DEFAULT_INTERNAL_TREE_BYTES, OUTGOING_BODY_TENTHS};

const VARS: [&str; 4] = ["PERMAURA_LIMIT_JSON_POOL_BYTES", "PERMAURA_LIMIT_HOLD_TREE_BYTES", "PERMAURA_LIMIT_INTERNAL_TREE_BYTES", "PERMAURA_LIMIT_BODY_EXEC_BYTES"];
const MIB: u64 = 1024 * 1024;

#[test]
fn the_unpacked_ceiling_follows_the_pool_the_environment_sets_and_the_internal_ceiling_is_overridable() {
    common::isolate_from_the_real_install();
    for var in VARS {
        std::env::remove_var(var);
    }
    assert_eq!(LimitsConfig::from_env_for(true).internal_tree_bytes, DEFAULT_INTERNAL_TREE_BYTES);
    assert_eq!(LimitsConfig::from_env_for(true).unpacked_limit(), 128 * MIB, "the hosted 192 MiB pool less 64 MiB");
    assert_eq!(LimitsConfig::from_env_for(false).unpacked_limit(), 448 * MIB, "the self-run 512 MiB pool less 64 MiB");

    // The ceiling is the pool less 64 MiB, held or not, for whatever pool the environment sets from 128 MiB up; below that half the pool is kept instead, so it never reaches nothing. Only the pool moves it.
    std::env::set_var("PERMAURA_LIMIT_JSON_POOL_BYTES", (300 * MIB).to_string());
    assert_eq!(LimitsConfig::from_env_for(true).unpacked_limit(), 236 * MIB);
    std::env::set_var("PERMAURA_LIMIT_JSON_POOL_BYTES", (100 * MIB).to_string());
    assert_eq!(LimitsConfig::from_env_for(false).unpacked_limit(), 50 * MIB, "half of a pool under 128 MiB is kept instead");
    std::env::set_var("PERMAURA_LIMIT_JSON_POOL_BYTES", "1");
    assert_eq!(LimitsConfig::from_env_for(true).json_pool_bytes, 16 * MIB, "clamped to its floor");
    assert_eq!(LimitsConfig::from_env_for(true).unpacked_limit(), 8 * MIB, "half the floor, never nothing");
    std::env::remove_var("PERMAURA_LIMIT_JSON_POOL_BYTES");
    for body in [32, 40, 64] {
        std::env::set_var("PERMAURA_LIMIT_BODY_EXEC_BYTES", (body * MIB).to_string());
        assert_eq!(LimitsConfig::from_env_for(true).unpacked_limit(), 128 * MIB, "a {body} MiB body limit leaves the hosted ceiling where it is");
    }
    std::env::remove_var("PERMAURA_LIMIT_BODY_EXEC_BYTES");

    // The hold-tree knob is gone: setting it moves nothing, and a call at the ceiling sent within the body can still be approved, its params reserving at most their tree and 4.5 times the body.
    std::env::set_var("PERMAURA_LIMIT_JSON_POOL_BYTES", (64 * MIB).to_string());
    std::env::set_var("PERMAURA_LIMIT_HOLD_TREE_BYTES", (60 * MIB).to_string());
    let config = LimitsConfig::from_env_for(true);
    assert_eq!(config.json_pool_bytes, 64 * MIB);
    assert_eq!(config.unpacked_limit(), 32 * MIB);
    assert!(config.unpacked_limit() + OUTGOING_BODY_TENTHS * config.body_exec_bytes as u64 / 10 <= config.json_pool_bytes);
    std::env::set_var("PERMAURA_LIMIT_HOLD_TREE_BYTES", "1");
    assert_eq!(LimitsConfig::from_env_for(true).unpacked_limit(), 32 * MIB);

    // The ceiling on a document the gateway fetches for itself is a knob like every other.
    std::env::set_var("PERMAURA_LIMIT_INTERNAL_TREE_BYTES", (8 * MIB).to_string());
    assert_eq!(LimitsConfig::from_env_for(true).internal_tree_bytes, 8 * MIB);
    std::env::set_var("PERMAURA_LIMIT_INTERNAL_TREE_BYTES", "1");
    assert_eq!(LimitsConfig::from_env_for(false).internal_tree_bytes, MIB, "clamped to its floor");

    for var in VARS {
        std::env::remove_var(var);
    }
}
