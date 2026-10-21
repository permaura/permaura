//! The round trip against the machine's ACTUAL credential store.
//!
//! Everything in the unit tests drives the decision table with the store's answer passed in, because
//! that is the only way to reach arms a healthy machine will not produce on demand: a locked
//! keyring, a session with no bus, two custodies disagreeing. What none of them touch is `keyring`
//! itself, so a change that broke the real read/write path would leave them all green.
//!
//! This is the other half: create, read back, hand back, and confirm the entry is really gone. It
//! uses a service name nothing ships with and cleans up after itself, but it does write to the real
//! login keychain / Credential Manager / Secret Service, so it is `#[ignore]`d and run deliberately:
//!
//!   cargo test -p permaura-credential-store --features apple-native -- --ignored
//!
//! On macOS it passes without a prompt because one process reads back what it just wrote. That is
//! also exactly why an ad-hoc-signed binary cannot rely on the same store across an UPDATE, which is
//! what `needs_stable_code_identity` exists to say.
//!
//! **Run it WITHOUT the feature and it still says `ok`**: it falls to the file branch and asserts
//! that half, which is correct on a Linux runner and misleading on a developer's Mac, where the whole
//! reason to run this is the Keychain. The only signal used to be the clock: 0.00s for the file
//! branch against ~2s for the real one. So the test now names the custody it exercised and, where a
//! store must have been used, asserts that it was.

use permaura_credential_store::CredentialStore;

/// Scoped to a service name nothing ships with, so a run that dies mid-way cannot collide with a
/// real secret.
const SCRATCH: CredentialStore = CredentialStore {
    service: "com.permaura.test.real-store-round-trip",
    account: "vault-kek",
    file_name: "vault-kek",
    needs_stable_code_identity: false,
    operator_sets_custody: false,
    keychain_access_group: None,
};

/// Exists ONLY in a build that cannot do what this file is for: a platform whose credential store is
/// always there, compiled without the backend that reaches it. In that configuration the round trip
/// below silently takes the file branch and reports `ok`, so the run looks like proof and is not.
///
/// `#[ignore]` as well, so it fires exactly when someone asks for these tests and not during an
/// ordinary `cargo test -p permaura-credential-store`, where the 23 unit tests are legitimately
/// feature-free. A workspace build never sees it: the gateway turns both backends on.
#[test]
#[ignore = "guard for the round trip below; runs with --ignored like it does"]
#[cfg(any(
    all(target_os = "macos", not(feature = "apple-native")),
    all(target_os = "windows", not(feature = "windows-native")),
))]
fn this_build_cannot_reach_the_store_it_is_meant_to_be_testing() {
    panic!(
        "this platform has an OS credential store and this build did not compile the backend for it, \
         so the round trip beside this can only exercise the owner-only file and would pass without \
         touching the store at all. Re-run with --features apple-native (macOS) or --features \
         windows-native (Windows)."
    );
}

#[test]
#[ignore = "writes to the machine's real credential store; run with --ignored"]
fn a_secret_survives_the_store_and_comes_back_out_unchanged() {
    let home = std::env::temp_dir().join(format!("permaura-realstore-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("PERMAURA_HOME", &home);
    let file = home.join("vault-kek");
    let marker = home.join("vault-kek.in-os-store");
    // A release macOS Keychain build keeps an app store's home in the user record, where `vault-kek` is the gateway's own file.
    let resolved = SCRATCH.path().expect("the scratch home resolves");
    assert_eq!(resolved, file, "this build ignores PERMAURA_HOME for an app store, so the round trip would reach the user's real home; run it in a debug build");

    let _ = SCRATCH.forget();

    // First run: nothing anywhere, so a secret is minted and stored.
    let minted = SCRATCH.resolve_or_create().expect("first run must provision a secret");
    assert_eq!(minted.len(), 43);

    // Second run on the same machine returns the SAME secret. A different one here is the whole
    // class of bug this crate exists to prevent: it orphans everything sealed under the first.
    assert_eq!(
        SCRATCH.resolve_or_create().expect("a second resolution must not mint"),
        minted,
        "the secret must be stable across restarts"
    );

    let stored_natively = marker.exists();
    eprintln!(
        "custody exercised: {}",
        if stored_natively { "the machine's OS credential store" } else { "the owner-only file" }
    );
    // Without this the file branch is a silent pass on a machine whose Keychain is the entire point
    // of running the test. macOS with `apple-native` has no reachable-store question to answer (the
    // scratch store does not ask for a stable code identity, so Custody::of can only say Native), and
    // Windows Credential Manager is likewise always there. Linux is deliberately not asserted: a
    // session with no bus reaching the file branch is correct, and that is what CI runs on.
    #[cfg(any(
        all(target_os = "macos", feature = "apple-native"),
        all(target_os = "windows", feature = "windows-native")
    ))]
    assert!(
        stored_natively,
        "this build has a native credential store that is always reachable, so the secret must have \
         gone into it: reaching the file branch means the store was never exercised and this test \
         proved nothing about it"
    );
    if stored_natively {
        assert!(!file.exists(), "adoption leaves no on-disk copy behind");
    } else {
        // No usable native store on this machine: a headless Linux runner, or a build with no
        // backend feature. The file must then be doing the job.
        assert!(file.exists(), "with no native store the secret has to reach the disk");
    }

    // Removal, which is what a sign-out and an uninstall do. Every custody, not just the one this
    // run happened to use.
    SCRATCH.forget().expect("forget must succeed");
    assert!(!file.exists(), "the owner-only copy must be gone");
    assert!(!marker.exists(), "nothing may still claim the store");

    // And the entry really is deleted rather than merely unclaimed: resolving again has to MINT. If
    // `forget` only dropped the claim, this would find the old secret still sitting in the store and
    // return it, which is the difference between signing out and appearing to.
    let after = SCRATCH.resolve_or_create().expect("provision again");
    assert_ne!(after, minted, "the old entry must have been deleted, not just stopped being claimed");

    let _ = SCRATCH.forget();
    let _ = std::fs::remove_dir_all(&home);
}
