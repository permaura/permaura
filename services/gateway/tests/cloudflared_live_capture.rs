//! The tunnel-pinning guard against what a real connector reports, not against fixtures shaped from cloudflared's source.
//!
//! Captured on 15 Oct 2026 from cloudflared 2026.7.3 running this crate's configuration for a throwaway locally managed tunnel (hostname and edge locations replaced). `config-local.json` and `metrics-local.txt` are the healthy connector; `config-pushed.json` is the same connector after a configuration was PUT to the tunnel through the API (which turned the tunnel remotely managed) and it reconnected, at which point it applied the pushed ingress over its own file.

use permaura_gateway::tunnel::{config_violation, private_network_traffic, Pin, PrivateNetwork};

mod common;

const CONFIG_LOCAL: &str = include_str!("fixtures/cloudflared-2026.7.3/config-local.json");
const CONFIG_PUSHED: &str = include_str!("fixtures/cloudflared-2026.7.3/config-pushed.json");
const METRICS_LOCAL: &str = include_str!("fixtures/cloudflared-2026.7.3/metrics-local.txt");

fn pin() -> Pin {
    Pin {
        host: "studio-mini.permaura.app".into(),
        origin: "http://127.0.0.1:7399".into(),
        metrics_port: 0,
    }
}

#[test]
fn a_live_connector_running_the_local_file_passes_the_guard() {
    let running: serde_json::Value = serde_json::from_str(CONFIG_LOCAL).unwrap();
    assert_eq!(config_violation(&running, &pin()), None);
}

#[test]
fn a_live_connector_that_applied_a_pushed_configuration_is_stopped() {
    let running: serde_json::Value = serde_json::from_str(CONFIG_PUSHED).unwrap();
    let why = config_violation(&running, &pin()).expect("version 2 routing to 127.0.0.1:9 is not the local file");
    assert!(why.contains("Cloudflare pushed a different configuration"), "{why}");
    assert!(why.contains("version 2"), "{why}");
}

/// The live page carries three of the four counters at zero; `cloudflared_udp_total_flows` is not exported until a v3 flow exists, which is why the guard needs only one of them present.
#[test]
fn a_live_connectors_metrics_read_as_quiet() {
    assert!(METRICS_LOCAL.contains("cloudflared_tcp_total_sessions 0"));
    assert!(!METRICS_LOCAL.contains("cloudflared_udp_total_flows"));
    assert!(matches!(private_network_traffic(METRICS_LOCAL), PrivateNetwork::Quiet));
}
