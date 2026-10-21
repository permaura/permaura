//! This machine's install identity: a stable id plus a secret, minted once and kept in
//! `install.json` under the Permaura home, created `0600` on Unix. On Windows the file gets no
//! owner-only ACL of its own.
//!
//! A gateway can be linked into several permaura.com workspaces at once, and the web rows are keyed
//! on a `base_url` that is `http://127.0.0.1:7376` on every local install in the world. Presenting
//! this identity at enrolment stamps each link with the machine that made it, which is what lets a
//! machine later ask "who links me", "drop that one", and, for a headless install, ask for its own
//! tunnel without a human minting anything.
//!
//! The secret is a capability over this machine's links, including links owned by accounts nobody is
//! signed into here. That is intended: anything able to drive the hardware must be severable from the
//! hardware. It is not an escalation either: whoever can read a `0600` file in `~/.permaura` already
//! holds `operator.token` and can do anything the gateway can do.
//!
//! The desktop app has minted one of these since it shipped; a `curl | sh` install never did, which
//! is why a VPS could not list its own links, revoke them, or provision remote access. The shape is
//! deliberately identical so one machine cannot end up with two identities depending on which half
//! of the product touched it last.

use std::io;
use std::path::PathBuf;

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Id + secret for this install. Serialized as-is to `install.json`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Install {
    /// Stable `gwi_`-prefixed id for this machine, stamped onto every link it makes.
    pub install_id: String,
    /// The capability half. Sent alongside the id; stored on the server only as a hash.
    pub secret: String,
}

fn install_path() -> Option<PathBuf> {
    crate::paths::permaura_path("install.json")
}

fn no_home_err() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "no home directory to store the install identity under, set PERMAURA_HOME",
    )
}

/// base64url(no-pad) of `n` bytes from the OS CSPRNG.
fn random_b64url(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn write_0600(path: &PathBuf, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
    }
    Ok(())
}

/// The identity already on this machine, if it has one.
pub fn load() -> Option<Install> {
    load_at(&install_path()?)
}

fn load_at(path: &PathBuf) -> Option<Install> {
    let data = std::fs::read(path).ok()?;
    serde_json::from_slice(&data).ok()
}

/// The install identity, minting and persisting one on first call.
///
/// Rotating the secret would orphan every existing link (the stored hashes would stop matching and
/// the machine could no longer revoke them), so an existing readable file is always reused. One
/// that does not parse is replaced with a fresh identity, which orphans the links the old one made.
pub fn ensure() -> io::Result<Install> {
    ensure_at(&install_path().ok_or_else(no_home_err)?)
}

fn ensure_at(path: &PathBuf) -> io::Result<Install> {
    if let Some(existing) = load_at(path) {
        return Ok(existing);
    }
    let install = Install {
        // 24 bytes → 32 base64url chars, inside the `gwi_` + 16..40 shape the API validates.
        install_id: format!("gwi_{}", random_b64url(24)),
        secret: random_b64url(32),
    };
    write_0600(path, &serde_json::to_vec_pretty(&install)?)?;
    Ok(install)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id has to satisfy the shape permaura.com validates, or enrolment silently drops the
    /// identity and the machine goes back to being unable to manage itself.
    #[test]
    fn minted_ids_match_the_api_shape() {
        let id = format!("gwi_{}", random_b64url(24));
        assert!(id.starts_with("gwi_"));
        let body = &id[4..];
        assert!(
            (16..=40).contains(&body.len()),
            "body was {} chars",
            body.len()
        );
        assert!(body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn secrets_do_not_repeat() {
        assert_ne!(random_b64url(32), random_b64url(32));
    }

    /// Reusing an existing identity is the whole contract: a fresh secret would orphan every link
    /// this machine has already made.
    #[test]
    fn ensure_is_stable_across_calls() {
        let dir = std::env::temp_dir().join(format!("permaura-install-{}", random_b64url(8)));
        let path = dir.join("install.json");
        let first = ensure_at(&path).unwrap();
        let second = ensure_at(&path).unwrap();
        assert_eq!(first.install_id, second.install_id);
        assert_eq!(first.secret, second.secret);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The file is a capability over this machine's links, so it must never be group- or
    /// world-readable.
    #[cfg(unix)]
    #[test]
    fn the_identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("permaura-install-{}", random_b64url(8)));
        let path = dir.join("install.json");
        ensure_at(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        std::fs::remove_dir_all(&dir).ok();
    }
}
