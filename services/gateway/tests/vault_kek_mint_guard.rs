//! The gateway never mints a fresh vault KEK over a vault that already exists.
//!
//! The real binary, because the KEK resolves once per process and the decision is made on the boot
//! path. Every run uses a scratch home in the OS temp directory, file custody (so nothing reaches an
//! OS credential store) and a free loopback port, and none sets `PERMAURA_DEV`, which would skip the
//! per-install key entirely.
#![cfg(all(unix, feature = "sqlite"))]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use permaura_core::crypto::{self, Cipher};
use permaura_core::vault::SecretMetadata;
use permaura_core::SecretRecord;
use permaura_gateway::store::Store;

/// The key the vault in these scenarios was sealed under, which no run is ever given back.
const ORIGINAL_KEK: &[u8] = b"the-original-install-kek";

/// The published dev constant, which the re-seal sweep can still open and move to a real key.
const DEV_KEK: &[u8] = b"permaura-dev-vault-passphrase";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("permaura-kek-guard-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// A store at `db` holding one credential sealed under `kek`.
fn vault_at(db: &Path, kek: &[u8]) {
    common::isolate_from_the_real_install();
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    let store = permaura_gateway::store::sqlite::SqliteStore::open(&db.to_string_lossy()).expect("the store opens");
    store
        .put_secret(SecretRecord {
            id: "sec_live".into(),
            sealed: crypto::seal(Cipher::Aes256Gcm, kek, b"a live upstream token").unwrap(),
            metadata: SecretMetadata::default(),
        })
        .unwrap();
}

/// Whether the credential in `db` still opens under `kek`.
fn opens_under(db: &Path, kek: &[u8]) -> bool {
    let conn = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let data: String = conn.query_row("SELECT data FROM secrets WHERE id = 'sec_live'", [], |r| r.get(0)).unwrap();
    let record: SecretRecord = serde_json::from_str(&data).unwrap();
    crypto::open(&record.sealed, kek).is_ok()
}

struct Boot {
    served: bool,
    exited_ok: bool,
    log: String,
}

/// Start the real binary over `home` and report whether it came up, then stop it.
async fn boot(home: &Path, env: &[(&str, &str)]) -> Boot {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert_ne!(port, 7376, "never the port a real gateway on this machine listens on");
    let addr = format!("127.0.0.1:{port}");
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_permaura"));
    cmd.args(["start", "--addr", &addr])
        .env("PERMAURA_HOME", home)
        .env("PERMAURA_VAULT_CUSTODY", "file")
        .env("PERMAURA_NO_UPGRADE", "1")
        .env("RUST_LOG", "info");
    for key in [
        "PERMAURA_DEV",
        "PERMAURA_HOSTED",
        "PERMAURA_RELAY_URL",
        "PERMAURA_STORE_PATH",
        "PERMAURA_VAULT_PASSPHRASE",
        "PERMAURA_VAULT_PASSPHRASE_FILE",
        "PERMAURA_VAULT_PASSPHRASE_STDIN",
        "PERMAURA_ALLOW_INSECURE_VAULT",
        "CREDENTIALS_DIRECTORY",
    ] {
        cmd.env_remove(key);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("the gateway binary starts");
    let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
    let health = format!("http://{addr}/health");
    let mut served = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if matches!(client.get(&health).send().await, Ok(r) if r.status().is_success()) {
            served = true;
            child.start_kill().ok();
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("the gateway exits")
        .unwrap();
    Boot {
        served,
        exited_ok: output.status.success(),
        log: format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)),
    }
}

/// A refusal: it never served, it said `phrase`, and it left no fresh key behind.
fn refused(run: &Boot, home: &Path, phrase: &str) {
    assert!(!run.served && !run.exited_ok, "the gateway came up instead of refusing:\n{}", run.log);
    assert!(run.log.contains(phrase), "the refusal must say '{phrase}':\n{}", run.log);
    assert!(!home.join("vault-kek").exists(), "a fresh vault KEK was minted:\n{}", run.log);
}

#[tokio::test]
async fn a_kek_file_that_cannot_be_read_stops_the_gateway_rather_than_minting() {
    let home = scratch("file-missing");
    let missing = home.join("mounted-kek-that-is-not-there");
    let run = boot(&home, &[("PERMAURA_VAULT_PASSPHRASE_FILE", missing.to_str().unwrap())]).await;
    refused(&run, &home, "PERMAURA_VAULT_PASSPHRASE_FILE");
}

#[tokio::test]
async fn an_empty_kek_file_stops_the_gateway_rather_than_minting() {
    let home = scratch("file-empty");
    let empty = home.join("mounted-kek");
    std::fs::write(&empty, "\n").unwrap();
    let run = boot(&home, &[("PERMAURA_VAULT_PASSPHRASE_FILE", empty.to_str().unwrap())]).await;
    refused(&run, &home, "empty");
}

#[tokio::test]
async fn a_stdin_hand_over_that_delivers_nothing_stops_the_gateway_rather_than_minting() {
    let home = scratch("stdin-empty");
    let run = boot(&home, &[("PERMAURA_VAULT_PASSPHRASE_STDIN", "1")]).await;
    refused(&run, &home, "PERMAURA_VAULT_PASSPHRASE_STDIN");
}

/// The marker beside `gateway.db` cannot vouch for a store kept somewhere else, so a home with no key
/// in it looked like a first run while the store it pointed at held a sealed vault.
#[tokio::test]
async fn a_store_outside_the_home_holding_sealed_credentials_is_not_minted_over() {
    let home = scratch("outside-home");
    let db = scratch("outside-store").join("gateway.db");
    vault_at(&db, ORIGINAL_KEK);
    let run = boot(&home, &[("PERMAURA_STORE_PATH", db.to_str().unwrap())]).await;
    refused(&run, &home, "sealed");
    assert!(run.log.contains(db.to_str().unwrap()), "the refusal names the store:\n{}", run.log);
    assert!(opens_under(&db, ORIGINAL_KEK), "the vault is untouched");
}

/// A home whose key and marker are both gone, which is also where a lost marker and a store that
/// would not answer lead: nothing anywhere names the key, and the store beside them still holds
/// credentials sealed under it.
#[tokio::test]
async fn a_home_whose_key_and_marker_are_gone_is_not_minted_over_while_its_store_holds_sealed_credentials() {
    let home = scratch("lost-key");
    let db = home.join("gateway.db");
    vault_at(&db, ORIGINAL_KEK);
    let run = boot(&home, &[]).await;
    refused(&run, &home, "sealed");
    assert!(opens_under(&db, ORIGINAL_KEK), "the vault is untouched");
}

/// The marker says the key lives in the OS store, and this launch cannot reach one.
#[tokio::test]
async fn a_marker_naming_the_os_store_is_not_minted_over() {
    let home = scratch("marker");
    std::fs::write(home.join("vault-kek.in-os-store"), "the secret with this name lives in this machine's OS credential store\n").unwrap();
    let run = boot(&home, &[]).await;
    refused(&run, &home, "Refusing to mint a replacement");
}

#[tokio::test]
async fn a_genuinely_fresh_home_initialises() {
    let home = scratch("fresh");
    let run = boot(&home, &[]).await;
    assert!(run.served, "a fresh home must come up:\n{}", run.log);
    assert!(home.join("vault-kek").exists(), "with a key of its own:\n{}", run.log);
}

/// The one vault a fresh key may be minted over: everything in it opens under the published dev
/// constant, which the re-seal sweep moves to the new key on the same boot.
#[tokio::test]
async fn a_store_sealed_only_under_the_dev_constant_still_moves_to_a_real_key() {
    let home = scratch("dev-sealed");
    let db = home.join("gateway.db");
    vault_at(&db, DEV_KEK);
    let run = boot(&home, &[]).await;
    assert!(run.served, "a dev-sealed vault upgrades rather than refusing:\n{}", run.log);
    let kek = std::fs::read(home.join("vault-kek")).expect("a real key was minted");
    let kek = String::from_utf8(kek).unwrap();
    assert!(opens_under(&db, kek.trim_end().as_bytes()), "and the credential moved to it");
    assert!(!opens_under(&db, DEV_KEK));
}
