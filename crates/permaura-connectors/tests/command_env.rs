//! A command capability's child sees an explicit environment, not the gateway's. A gateway started from a shell carries that shell's exported keys, systemd's `CREDENTIALS_DIRECTORY` and the vault passphrase variables, and a program the agent can make print its environment would hand every one of them back in its output.
//!
//! Its own test binary, because the environment is process-wide.

#![cfg(unix)]

use std::collections::BTreeMap;

use permaura_connectors::{CommandInvocation, CommandRunner, RealCommandRunner};

#[tokio::test]
async fn a_command_child_sees_only_the_allowlist_and_its_own_injected_variables() {
    for (name, value) in [
        ("CREDENTIALS_DIRECTORY", "/run/credentials/permaura.service"),
        ("PERMAURA_VAULT_PASSPHRASE_FILE", "/run/secrets/permaura-passphrase"),
        ("PERMAURA_VAULT_PASSPHRASE", "synthetic-passphrase"),
        ("PERMAURA_ANNOUNCE_SECRET", "synthetic-announce"),
        ("GITHUB_TOKEN", "synthetic-shell-export"),
        ("AWS_SECRET_ACCESS_KEY", "synthetic-shell-export"),
        ("LC_ALL", "C"),
        ("TMPDIR", "/tmp/"),
    ] {
        std::env::set_var(name, value);
    }
    let invocation = CommandInvocation {
        program: "/usr/bin/env".into(),
        args: Vec::new(),
        envs: BTreeMap::from([("SYNTHETIC_TOKEN".to_string(), "injected".to_string())]),
    };
    let out = RealCommandRunner::new().run(invocation).await.expect("env runs");
    let seen: BTreeMap<&str, &str> = out.stdout.lines().filter_map(|line| line.split_once('=')).collect();
    // Names only in a failure message: on a failure the child's values are whatever the test host's environment holds.
    let names: Vec<&str> = seen.keys().copied().collect();

    for leaked in [
        "CREDENTIALS_DIRECTORY",
        "PERMAURA_VAULT_PASSPHRASE_FILE",
        "PERMAURA_VAULT_PASSPHRASE",
        "PERMAURA_ANNOUNCE_SECRET",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
    ] {
        assert!(!seen.contains_key(leaked), "{leaked} reached the child: {names:?}");
    }
    assert_eq!(seen.get("SYNTHETIC_TOKEN"), Some(&"injected"), "the capability's own variable is set");
    assert_eq!(seen.get("PATH").copied(), std::env::var("PATH").ok().as_deref(), "PATH resolves programs");
    assert_eq!(seen.get("LC_ALL"), Some(&"C"));
    assert_eq!(seen.get("TMPDIR"), Some(&"/tmp/"));
    assert!(seen.keys().all(|name| ["PATH", "HOME", "LANG", "TMPDIR", "SYNTHETIC_TOKEN"].contains(name) || name.starts_with("LC_")), "only the allowlist: {names:?}");
}
