//! Getting hold of `cloudflared`, and running it.
//!
//! A tunnel needs a connector, and on a bare VPS there is never one installed. The desktop app has
//! always assumed the operator supplied their own: reasonable on a laptop where Homebrew or the MSI
//! put it there, useless on a box whose whole setup is one `curl | sh` line.
//!
//! So: use theirs if they have one, and only fetch a copy when they do not. An apt- or brew-managed
//! cloudflared keeps its own update path and we must not shadow it; what we download lives under
//! `~/.permaura/bin` and belongs to us.
//!
//! Cloudflare publishes no checksum file with its releases, so there is no upstream manifest to
//! verify against. The pin below is therefore ours: a version, and the digest of each artefact at
//! that version, recorded here so that bumping it is a reviewed commit rather than whatever the
//! internet served today. This mirrors how CI already pins gitleaks.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// The cloudflared release we install when the machine has none.
///
/// Bumping this means updating every digest below in the same commit. A version without its digests
/// is a download nobody checked.
pub const PINNED_VERSION: &str = "2026.8.3";

/// `(target, asset, sha256)` for the platforms a headless gateway actually runs on.
///
/// macOS ships a `.tgz` rather than a bare binary, and a headless Mac is rare enough that it is left
/// to Homebrew: the entry is absent rather than half-supported, so the error names the reason.
const PINNED: &[(&str, &str, &str)] = &[
    ("x86_64-linux", "cloudflared-linux-amd64", "f29324fe934d1e100617484c78deef803c4dc2cd351d645bbde42e96b4fccc5e"),
    ("aarch64-linux", "cloudflared-linux-arm64", "4bcfd35521a7cbc545ebfd5d57334a71ee180e2a64874981f374c81472118391"),
    ("arm-linux", "cloudflared-linux-arm", "7a7cac4ad4561ff55797eaf27aae1a0be37498c85502715bc87e3bad919d928c"),
    ("x86-linux", "cloudflared-linux-386", "691e3a2b8926f90ec4fcec4f4bc8e38b1de14f6232d93a24f6cb7b2c23ab5e92"),
];

/// This machine's key into [`PINNED`].
fn target_key() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some(match std::env::consts::ARCH {
            "x86_64" => "x86_64-linux",
            "aarch64" => "aarch64-linux",
            "arm" => "arm-linux",
            "x86" => "x86-linux",
            _ => return None,
        })
    } else {
        None
    }
}

fn bin_name() -> &'static str {
    if cfg!(windows) {
        "cloudflared.exe"
    } else {
        "cloudflared"
    }
}

/// Where a cloudflared we installed lives. Never a system path: what apt or brew owns stays theirs.
fn managed_path() -> Option<PathBuf> {
    permaura_core::paths::permaura_path("bin").map(|d| d.join(bin_name()))
}

/// Directories the official installers use, checked after PATH.
fn known_dirs() -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
            .iter()
            .map(PathBuf::from)
            .collect()
    } else if cfg!(target_os = "linux") {
        ["/usr/local/bin", "/usr/bin", "/snap/bin"]
            .iter()
            .map(PathBuf::from)
            .collect()
    } else {
        Vec::new()
    }
}

/// An already-installed cloudflared, if this machine has one.
///
/// PATH first, then the install dirs, then ours. Deliberately in that order: an operator who manages
/// their own copy should keep getting it, including its updates, and the one we fetched is the last
/// resort rather than the preferred answer.
pub fn find_existing() -> Option<PathBuf> {
    let name = bin_name();
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for dir in known_dirs() {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    managed_path().filter(|p| p.is_file())
}

/// Hex sha256 of a file.
fn digest_of(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex_lower(&h.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Resolve cloudflared, downloading a pinned build only if the machine has none.
///
/// The download is verified against [`PINNED`] before it is ever made executable: a binary that does
/// not match its digest is deleted, not run, and not kept for a later attempt to stumble onto.
pub async fn ensure() -> Result<PathBuf> {
    if let Some(existing) = find_existing() {
        return Ok(existing);
    }

    let Some(key) = target_key() else {
        bail!(
            "cloudflared is not installed and this platform has no pinned build. \
             Install it yourself (https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) \
             and run this again."
        );
    };
    let (_, asset, want) = PINNED
        .iter()
        .find(|(t, _, _)| *t == key)
        .copied()
        .context("no pinned cloudflared for this platform")?;

    let dest = managed_path().context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let url = format!(
        "https://github.com/cloudflare/cloudflared/releases/download/{PINNED_VERSION}/{asset}"
    );
    println!("Fetching cloudflared {PINNED_VERSION}…");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let bytes = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("downloading {url}"))?
        .error_for_status()
        .with_context(|| format!("downloading {url}"))?
        .bytes()
        .await?;

    // Write to a sibling temp path first so a failed verify never leaves something runnable behind,
    // and so a half-written file cannot be picked up as "already installed" by the next run.
    let tmp = dest.with_extension("partial");
    std::fs::write(&tmp, &bytes)?;

    let got = digest_of(&tmp)?;
    if got != want {
        let _ = std::fs::remove_file(&tmp);
        bail!(
            "the cloudflared download did not match its pinned checksum \
             (expected {want}, got {got}). Refusing to run it"
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, &dest)?;
    println!("  installed to {}", dest.display());
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pinned_entry_has_a_real_digest() {
        for (target, asset, sha) in PINNED {
            assert!(!asset.is_empty(), "{target} has no asset");
            assert_eq!(sha.len(), 64, "{target} digest is not a sha256: {sha}");
            assert!(
                sha.chars().all(|c| c.is_ascii_hexdigit()),
                "{target} digest is not hex: {sha}"
            );
        }
    }

    #[test]
    fn targets_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for (t, _, _) in PINNED {
            assert!(seen.insert(*t), "duplicate pinned target {t}");
        }
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
