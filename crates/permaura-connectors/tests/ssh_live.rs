//! Live end-to-end test of the real (`russh`-backed) SSH transport.
//!
//! Every other SSH test uses [`MockSshRunner`], so they prove the *builder* and the gateway wiring but
//! never touch russh's network path: host-key verification, public-key auth, the exec channel, and the
//! SFTP subsystem. This test exercises `RealSshRunner` against an actual sshd, which is the only thing
//! that catches a semantic break from a russh version bump (a signature can still type-check while its
//! behaviour has moved).
//!
//! It is OFF by default: it needs a real sshd, so it self-skips unless the environment points it at
//! one. To run it (see the harness in the migration commit that added it):
//!
//! ```text
//! PERMAURA_SSH_TEST_ADDR=127.0.0.1:2222 \
//! PERMAURA_SSH_TEST_USER=$(whoami) \
//! PERMAURA_SSH_TEST_KEY=/path/to/client_ed25519 \
//! PERMAURA_SSH_TEST_FP=SHA256:... \
//! PERMAURA_SSH_TEST_ROOT=/path/to/scoped/dir \
//!   cargo test -p permaura-connectors --features ssh-transport --test ssh_live -- --nocapture
//! ```

#![cfg(feature = "ssh-transport")]

use std::time::Duration;

use permaura_connectors::ssh::{
    RealSshRunner, SshCredentialKind, SshEgress, SshHostKey, SshInvocation, SshOutcome, SshRunOp, SshRunner,
    SshTarget,
};
use zeroize::Zeroizing;

struct Env {
    host: String,
    port: u16,
    user: String,
    key: Zeroizing<Vec<u8>>,
    fingerprint: String,
    root: String,
}

/// Read the harness env, or `None` to skip (so a plain `cargo test` on a machine with no test sshd
/// passes instead of failing).
fn env() -> Option<Env> {
    let addr = std::env::var("PERMAURA_SSH_TEST_ADDR").ok()?;
    let (host, port) = addr.rsplit_once(':')?;
    let key_path = std::env::var("PERMAURA_SSH_TEST_KEY").ok()?;
    Some(Env {
        host: host.to_string(),
        port: port.parse().ok()?,
        user: std::env::var("PERMAURA_SSH_TEST_USER").ok()?,
        key: Zeroizing::new(std::fs::read(key_path).ok()?),
        fingerprint: std::env::var("PERMAURA_SSH_TEST_FP").ok()?,
        root: std::env::var("PERMAURA_SSH_TEST_ROOT").ok()?,
    })
}

fn target(e: &Env, host_key: SshHostKey) -> SshTarget {
    SshTarget { host: e.host.clone(), port: e.port, user: e.user.clone(), host_key }
}

fn invocation(e: &Env, host_key: SshHostKey, op: SshRunOp) -> SshInvocation {
    SshInvocation {
        target: target(e, host_key),
        credential_kind: SshCredentialKind::PrivateKey,
        credential: e.key.clone(),
        op,
        egress: SshEgress::Unrestricted,
    }
}

fn runner() -> RealSshRunner {
    RealSshRunner::with_timeout(Duration::from_secs(15))
}

#[tokio::test]
async fn real_ssh_exec_runs_and_captures_output() {
    let Some(e) = env() else {
        eprintln!("ssh_live: skipped (PERMAURA_SSH_TEST_* not set)");
        return;
    };
    let inv = invocation(
        &e,
        SshHostKey::Fingerprint { sha256: e.fingerprint.clone() },
        SshRunOp::Exec { command: "echo permaura-live-exec".into(), max_output_bytes: 4096 },
    );
    let out = runner().run(inv).await.expect("exec should succeed against the live host");
    match out {
        SshOutcome::Exec(o) => {
            assert_eq!(o.code, 0, "exit code");
            assert!(o.stdout.contains("permaura-live-exec"), "stdout was {:?}", o.stdout);
        }
        other => panic!("expected exec outcome, got {other:?}"),
    }
}

/// The security-critical one: a WRONG pinned fingerprint must abort before auth. If a russh bump ever
/// weakened `check_server_key`, this is what catches it, and it is exactly the MITM defence the whole
/// connector is built around.
#[tokio::test]
async fn real_ssh_rejects_a_wrong_host_key_fingerprint() {
    let Some(e) = env() else {
        eprintln!("ssh_live: skipped (PERMAURA_SSH_TEST_* not set)");
        return;
    };
    let wrong = SshHostKey::Fingerprint {
        sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    let inv = invocation(
        &e,
        wrong,
        SshRunOp::Exec { command: "echo should-never-run".into(), max_output_bytes: 128 },
    );
    let result = runner().run(inv).await;
    assert!(
        result.is_err(),
        "a mismatched host-key fingerprint MUST fail: got a successful outcome, meaning MITM is undefended",
    );
}

/// And the correct fingerprint must be accepted, proving the pin isn't just failing everything.
#[tokio::test]
async fn real_ssh_accepts_the_correct_host_key_fingerprint() {
    let Some(e) = env() else {
        eprintln!("ssh_live: skipped (PERMAURA_SSH_TEST_* not set)");
        return;
    };
    let inv = invocation(
        &e,
        SshHostKey::Fingerprint { sha256: e.fingerprint.clone() },
        SshRunOp::Exec { command: "true".into(), max_output_bytes: 16 },
    );
    assert!(runner().run(inv).await.is_ok(), "the correct fingerprint must be accepted");
}

#[tokio::test]
async fn real_ssh_sftp_put_get_list_round_trip() {
    let Some(e) = env() else {
        eprintln!("ssh_live: skipped (PERMAURA_SSH_TEST_* not set)");
        return;
    };
    let hk = || SshHostKey::Fingerprint { sha256: e.fingerprint.clone() };
    let payload = b"permaura round-trip payload".to_vec();

    // PUT
    let put = invocation(
        &e,
        hk(),
        SshRunOp::Put { path: format!("{}/roundtrip.txt", e.root), content: payload.clone(), max_bytes: 1 << 20 },
    );
    match runner().run(put).await.expect("sftp put") {
        SshOutcome::Put { bytes } => assert_eq!(bytes, payload.len() as u64),
        other => panic!("expected put outcome, got {other:?}"),
    }

    // GET it back
    let get = invocation(
        &e,
        hk(),
        SshRunOp::Get { path: format!("{}/roundtrip.txt", e.root), max_bytes: 1 << 20 },
    );
    match runner().run(get).await.expect("sftp get") {
        SshOutcome::Get { bytes, content_base64 } => {
            assert_eq!(bytes, payload.len() as u64);
            let decoded = base64_decode(&content_base64);
            assert_eq!(decoded, payload, "round-tripped content must match");
        }
        other => panic!("expected get outcome, got {other:?}"),
    }

    // LIST: the file we just wrote must appear
    let list = invocation(&e, hk(), SshRunOp::List { path: e.root.clone() });
    match runner().run(list).await.expect("sftp list") {
        SshOutcome::List { entries, .. } => {
            assert!(
                entries.iter().any(|en| en.name == "roundtrip.txt"),
                "listing must include the written file; got {:?}",
                entries.iter().map(|en| &en.name).collect::<Vec<_>>(),
            );
        }
        other => panic!("expected list outcome, got {other:?}"),
    }
}

/// The read cap must still bite over the real transport.
#[tokio::test]
async fn real_ssh_sftp_get_enforces_the_byte_cap() {
    let Some(e) = env() else {
        eprintln!("ssh_live: skipped (PERMAURA_SSH_TEST_* not set)");
        return;
    };
    // Write 100 bytes, then try to read with a 10-byte cap: must error rather than truncate.
    let big = vec![b'x'; 100];
    let put = invocation(
        &e,
        SshHostKey::Fingerprint { sha256: e.fingerprint.clone() },
        SshRunOp::Put { path: format!("{}/capped.txt", e.root), content: big, max_bytes: 1 << 20 },
    );
    runner().run(put).await.expect("sftp put for cap test");

    let get = invocation(
        &e,
        SshHostKey::Fingerprint { sha256: e.fingerprint.clone() },
        SshRunOp::Get { path: format!("{}/capped.txt", e.root), max_bytes: 10 },
    );
    assert!(runner().run(get).await.is_err(), "an over-cap read must fail, not silently truncate");
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(s.as_bytes()).expect("valid base64")
}
