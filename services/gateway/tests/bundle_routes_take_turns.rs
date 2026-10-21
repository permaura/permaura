//! Every integration test binary that sends a vault bundle request builds its router through `common::build_router`, so its bundle requests take turns on the gateway's one key-derivation permit instead of queuing past the permit's 15 s wait and failing with a 429 on a loaded machine.

mod common;

#[test]
fn every_test_binary_that_sends_a_bundle_request_builds_the_turn_taking_router() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut checked = 0;
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // bundle_open_gate.rs tests the permit itself, so its requests have to meet it.
        if path.extension().is_none_or(|e| e != "rs") || name == "bundle_open_gate.rs" || name == "bundle_routes_take_turns.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        if !text.contains("/v1/vault/export") && !text.contains("/v1/vault/import") {
            continue;
        }
        checked += 1;
        let gateways_own = text.contains("permaura_gateway::build_router")
            || text.lines().any(|l| l.trim_start().starts_with("use permaura_gateway::") && l.contains("build_router"));
        if gateways_own {
            offenders.push(name);
        }
    }
    assert!(checked >= 10, "the scan found only {checked} test files sending bundle requests, so it is not reading the suite");
    assert!(offenders.is_empty(), "these build the gateway's router directly, so their bundle requests queue on one permit with every other test in the binary: {offenders:?}");
}
