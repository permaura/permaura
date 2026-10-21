//! The hosted admission defaults and the environment that overrides them.
//!
//! One test in a binary of its own, because the variables are process-wide and every other binary's
//! tests run in parallel with each other.

mod common;

use permaura_gateway::limits::{LimitsConfig, DEFAULT_SELF_RUN_WORKER_RATE_BURST};

const VARS: [&str; 4] = [
    "PERMAURA_LIMIT_RATE_PER_MIN",
    "PERMAURA_LIMIT_RATE_BURST",
    "PERMAURA_WORKER_RATE_PER_MIN",
    "PERMAURA_WORKER_RATE_BURST",
];

fn rates(c: &LimitsConfig) -> (u32, u32, Option<u32>, u32) {
    (c.rate_per_min, c.rate_burst, c.worker_rate_per_min, c.worker_rate_burst)
}

#[test]
fn hosted_rates_default_to_the_store_ceiling_and_the_environment_still_overrides_them() {
    common::isolate_from_the_real_install();
    for var in VARS {
        std::env::remove_var(var);
    }
    assert_eq!(rates(&LimitsConfig::from_env_for(true)), (30, 10, Some(30), 10));
    assert_eq!(rates(&LimitsConfig::from_env_for(false)), (120, 30, None, DEFAULT_SELF_RUN_WORKER_RATE_BURST));

    // A plan that lowers only the worker rate takes each caller down with it.
    std::env::set_var("PERMAURA_WORKER_RATE_PER_MIN", "20");
    std::env::set_var("PERMAURA_WORKER_RATE_BURST", "4");
    assert_eq!(rates(&LimitsConfig::from_env_for(true)), (20, 4, Some(20), 4));

    // One that raises it leaves a caller at the hosted default, which is the store's ceiling.
    std::env::set_var("PERMAURA_WORKER_RATE_PER_MIN", "1200");
    std::env::remove_var("PERMAURA_WORKER_RATE_BURST");
    assert_eq!(rates(&LimitsConfig::from_env_for(true)), (30, 10, Some(1200), 10));

    // The per-caller knobs still win outright.
    std::env::set_var("PERMAURA_LIMIT_RATE_PER_MIN", "90");
    std::env::set_var("PERMAURA_LIMIT_RATE_BURST", "15");
    assert_eq!(rates(&LimitsConfig::from_env_for(true)), (90, 15, Some(1200), 10));

    // A gateway its owner runs that opts into a worker rate keeps the burst it always had.
    std::env::remove_var("PERMAURA_LIMIT_RATE_PER_MIN");
    std::env::remove_var("PERMAURA_LIMIT_RATE_BURST");
    assert_eq!(rates(&LimitsConfig::from_env_for(false)), (120, 30, Some(1200), DEFAULT_SELF_RUN_WORKER_RATE_BURST));

    for var in VARS {
        std::env::remove_var(var);
    }
}
