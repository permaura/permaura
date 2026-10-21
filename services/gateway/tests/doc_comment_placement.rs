//! Items whose doc comments an inserted item once took over keep their own: rustdoc gives a `///` block to the next item, so a constant or a helper slipped between a doc and its item silently documents the wrong thing.

mod common;

/// The doc lines directly above `item` in `source`, skipping attributes, nearest last.
fn doc_above(source: &str, item: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let at = lines.iter().position(|l| l.starts_with(item)).unwrap_or_else(|| panic!("{item} is in the source"));
    let mut docs = Vec::new();
    let mut i = at;
    while i > 0 {
        i -= 1;
        let line = lines[i].trim_start();
        if line.starts_with("#[") {
            continue;
        }
        if !line.starts_with("///") {
            break;
        }
        docs.push(line.to_string());
    }
    docs
}

#[test]
fn each_of_these_items_keeps_its_own_doc() {
    let rest = include_str!("../src/rest.rs");
    let cli = include_str!("../src/cli/mod.rs");
    let callback = doc_above(rest, "fn callback_page(");
    assert!(callback.iter().any(|l| l.contains("result page")), "callback_page has its doc: {callback:?}");
    let cap = doc_above(rest, "const CALLBACK_DETAIL_MAX_CHARS");
    assert!(cap.iter().all(|l| !l.contains("result page")), "the constant does not take callback_page's doc: {cap:?}");
    let auth = doc_above(cli, "enum AuthCmd");
    assert!(auth.iter().any(|l| l.contains("permaura auth")), "AuthCmd has its doc: {auth:?}");
    let flag = doc_above(cli, "fn given_on_the_command_line");
    assert!(flag.iter().all(|l| !l.contains("permaura auth")), "the helper does not take AuthCmd's doc: {flag:?}");
}

#[test]
fn build_and_restore_advice_names_the_actual_exceptions() {
    let readme = include_str!("../../../README.md");
    let getting_started = include_str!("../../../docs/getting-started.md");
    let migrations = include_str!("../src/store/migrations.rs");
    assert!(readme.contains("loopback overrides for the account API and control plane"));
    assert!(getting_started.contains("README's build-trust warning"));
    assert!(migrations.contains("a recovery code spent"));
    assert!(!migrations.contains("device key or recovery code revoked"));
}
