//! Every ed25519 check in the workspace is `verify_strict`.
//!
//! `VerifyingKey` has no inherent `verify`: the non-strict check is only reachable through the `Verifier` trait, which accepts a small-order key and lets one fixed 64-byte value verify as every message under it. So the class is pinned by refusing the trait itself anywhere in the workspace's Rust, test code included, rather than by one test per call site, and by refusing any renaming of the crates that could name it without their own names.

use std::path::{Path, PathBuf};

mod common;

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != "node_modules" && !name.to_string_lossy().starts_with('.') {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Each path expression that names the ed25519 or signature crates, up to the end of its statement, so a multi-line `use` is read whole.
fn crate_paths(source: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for prefix in ["ed25519_dalek::", "ed25519::", "signature::"] {
        let mut rest = source;
        while let Some(at) = rest.find(prefix) {
            let tail = &rest[at..];
            let end = tail.find(';').unwrap_or(tail.len());
            found.push(&tail[..end]);
            rest = &tail[prefix.len()..];
        }
    }
    found
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
}

/// The trait by name, a glob that brings it in, or `{self}`, which binds the crate under another name.
fn names_the_trait(path: &str) -> bool {
    let after = path.split_once("::").map_or("", |(_, rest)| rest).trim_start();
    let binds_the_crate = after.starts_with('{') && words(&after[..after.find('}').unwrap_or(after.len())]).any(|w| w == "self");
    words(path).any(|w| w == "Verifier") || path.contains("::*") || binds_the_crate
}

/// A `use` or `extern crate` that renames one of the crates, after which a path can name the trait without the crate's own name.
fn renames_a_crate(source: &str) -> Vec<String> {
    let code: String = source.lines().map(|l| l.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n");
    code.split(';')
        .filter(|statement| {
            let tokens: Vec<&str> = statement.split_whitespace().collect();
            tokens.windows(3).any(|w| {
                matches!(w[0], "use" | "crate")
                    && ["ed25519_dalek", "ed25519", "signature"].contains(&w[1].trim_start_matches("::"))
                    && w[2] == "as"
            })
        })
        .map(|statement| statement.trim().lines().next().unwrap_or("").to_string())
        .collect()
}

/// What in `source` could reach the non-strict verify, one line each.
fn offenders_in(source: &str) -> Vec<String> {
    let mut found: Vec<String> = crate_paths(source)
        .into_iter()
        .filter(|p| names_the_trait(p))
        .map(|p| p.lines().next().unwrap_or(p).to_string())
        .collect();
    found.extend(renames_a_crate(source));
    found
}

#[test]
fn the_scan_catches_every_way_to_name_the_trait() {
    for source in [
        "use ed25519_dalek::{Signature, Verifier, VerifyingKey};",
        "use ed25519_dalek::{\n    Signature,\n    Verifier,\n};",
        "use ed25519_dalek::*;",
        "use ed25519_dalek::Verifier as _;",
        "use ed25519_dalek::ed25519::signature::Verifier;",
        "fn f(k: &VerifyingKey) { ed25519_dalek::Verifier::verify(k, m, s); }",
        "use ed25519_dalek as ed;\nuse ed::Verifier;",
        "use ::ed25519_dalek as ed;",
        "extern crate ed25519_dalek as dalek;",
        "use ed25519_dalek::{self, VerifyingKey};",
        "use ed25519_dalek::{VerifyingKey, self as dalek};",
        "pub use signature as sig;",
    ] {
        assert!(!offenders_in(source).is_empty(), "the scan must refuse: {source}");
    }
    for source in [
        "use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};",
        "let sk = ed25519_dalek::SigningKey::from_bytes(&self.seed);",
        "// an ed25519 signature as the proof",
        "vk.verify_strict(m, &sig)",
    ] {
        assert!(offenders_in(source).is_empty(), "the scan must allow: {source}");
    }
}

#[test]
fn no_rust_in_the_workspace_reaches_the_non_strict_ed25519_verify() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for dir in ["crates", "services"] {
        rust_files(&root.join(dir), &mut files);
    }
    assert!(files.len() > 50, "the scan must actually see the workspace, saw {}", files.len());
    let this = Path::new(file!()).file_name().unwrap();
    let offenders: Vec<String> = files
        .iter()
        .filter(|f| f.file_name() != Some(this))
        .flat_map(|f| {
            let source = std::fs::read_to_string(f).unwrap_or_default();
            offenders_in(&source)
                .into_iter()
                .map(|p| format!("{}: {}", f.strip_prefix(&root).unwrap_or(f).display(), p))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(offenders.is_empty(), "use verify_strict, never the Verifier trait:\n{}", offenders.join("\n"));
}
