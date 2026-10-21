//! Synthetic persisted estate for the desktop's opt-in protocol integration pass.
#![cfg(feature = "sqlite")]
mod common;
#[test]
#[ignore = "only the desktop approver script supplies a dedicated scratch home"]
fn seed_desktop_approver_fixture() {
    common::isolate_from_the_real_install();
    let home = std::path::PathBuf::from(std::env::var_os("PERMAURA_DESKTOP_FIXTURE_HOME").expect("explicit scratch home"));
    let home = home.canonicalize().unwrap();
    let temp = std::env::temp_dir().canonicalize().unwrap();
    assert!(home.starts_with(temp) && home.file_name().unwrap().to_string_lossy().starts_with("permaura-approver-it"));
    assert!(!home.join("gateway.db").exists(), "the fixture must start empty");
    std::env::set_var("PERMAURA_HOME", &home);
    common::assert_isolated();
    let store = permaura_gateway::store::sqlite::SqliteStore::open(home.join("gateway.db").to_str().unwrap()).unwrap();
    permaura_gateway::seed::seed(&store).unwrap();
}
