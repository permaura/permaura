//! The README's from-source gateway is a release build, and the README says what a debug build trusts that a release build does not: the `cfg(debug_assertions)` gates on the development signing keys and the trust-root overrides are exactly what a reader following the README would otherwise build.

mod common;

const README: &str = include_str!("../../../README.md");

fn build_from_source() -> &'static str {
    let start = README.find("## Build from source").expect("the README has a Build from source section");
    let rest = &README[start + 3..];
    &rest[..rest.find("\n## ").unwrap_or(rest.len())]
}

#[test]
fn the_readme_runs_a_release_gateway_and_says_what_a_debug_build_trusts() {
    let section = build_from_source();
    let runs: Vec<&str> = section.lines().filter(|l| l.trim_start().starts_with("cargo run")).collect();
    assert!(!runs.is_empty(), "the section shows how to run a gateway");
    for run in runs {
        assert!(run.contains("--release"), "a gateway run from the README is a release build: {run}");
    }
    assert!(section.contains("development connector-signing"), "the README names the development signing keys a debug build trusts");
    assert!(section.contains("public development key"), "and the public development KEK it honors");
}
