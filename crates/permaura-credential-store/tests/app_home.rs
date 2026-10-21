//! Where an app store's home resolves from a test outside this crate's unit tests.
//!
//! An integration test links the library without `cfg(test)`, so in a release macOS Keychain build an app store here takes its home from the user record, whatever `PERMAURA_HOME` says, and a test that writes through one has to guard itself as `real_store.rs` does. Nothing here reads or writes any home: it only compares paths.

use permaura_credential_store::CredentialStore;

const APP: CredentialStore = CredentialStore {
    service: "com.permaura.test.app-home",
    account: "app-home",
    file_name: "app-home",
    needs_stable_code_identity: false,
    operator_sets_custody: false,
    keychain_access_group: None,
};

#[test]
fn an_integration_test_is_isolated_by_permaura_home_only_where_the_build_honors_it() {
    let scratch = std::env::temp_dir().join(format!("permaura-app-home-{}", std::process::id()));
    std::env::set_var("PERMAURA_HOME", &scratch);
    let resolved = APP.path().expect("an app store's home resolves");

    if cfg!(debug_assertions) || !cfg!(all(target_os = "macos", feature = "apple-native")) {
        assert_eq!(resolved, scratch.join(APP.file_name));
    } else {
        assert!(
            !resolved.starts_with(&scratch),
            "a release Keychain build's integration test must not be taken for isolated by PERMAURA_HOME: {}",
            resolved.display()
        );
        assert!(resolved.ends_with(format!(".permaura/{}", APP.file_name)), "{}", resolved.display());
    }
}
