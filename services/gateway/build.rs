//! Stamps the commit this binary was built from into the executable, so `/health` can report
//! `build_sha`. Two builds of the same `version` are otherwise indistinguishable over the wire,
//! which makes "is the fix deployed" unanswerable for a self-hosted or hosted gateway alike.
//!
//! Resolution order, first non-empty wins:
//!   1. `PERMAURA_BUILD_SHA`: an explicit override for a build that has no git context (a source
//!      tarball, a vendored crate, a reproducible-build pipeline).
//!   2. `GITHUB_SHA`: every CI and release build gets this for free.
//!   3. `git rev-parse HEAD` in the source tree.
//! Falling through leaves it `unknown`, which is honest and never fails the build: a gateway that
//! cannot name its commit must still compile and run.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Only these inputs decide the value, so re-run when any of them changes rather than on every source edit. The Git files are declared by `git_head` when it is the source.
    println!("cargo:rerun-if-env-changed=PERMAURA_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-changed=build.rs");

    let sha = non_empty(std::env::var("PERMAURA_BUILD_SHA").ok())
        .or_else(|| non_empty(std::env::var("GITHUB_SHA").ok()))
        .or_else(git_head)
        .unwrap_or_else(|| "unknown".to_string());

    // Trimmed to 12: long enough to be unambiguous in this repo, short enough to read in a health
    // document or a support ticket.
    let short: String = sha.chars().take(12).collect();
    println!("cargo:rustc-env=PERMAURA_BUILD_SHA={short}");
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn git_head() -> Option<String> {
    let sha = git(&["rev-parse", "HEAD"])?;
    watch_head();
    Some(sha)
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    non_empty(String::from_utf8(out.stdout).ok())
}

/// Declare the files that move when HEAD does: HEAD itself, in the worktree's own git directory, and the branch it names, which a linked worktree keeps in the common directory it shares, as a loose ref or only in `packed-refs`.
fn watch_head() {
    let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]).map(PathBuf::from) else {
        return;
    };
    let common = git(&["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .map(PathBuf::from)
        .unwrap_or_else(|| git_dir.clone());
    watch(&git_dir.join("HEAD"));
    let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) else {
        return;
    };
    let loose = common.join(branch);
    if loose.exists() {
        watch(&loose);
        return;
    }
    // Packed only: the next commit writes the loose file, which shows as a change to the nearest directory under refs/ that already exists.
    watch(&common.join("packed-refs"));
    let refs = common.join("refs");
    if let Some(dir) = loose.ancestors().skip(1).find(|p| p.starts_with(&refs) && p.exists()) {
        watch(dir);
    }
}

/// Declare `path` only if it exists: Cargo re-runs a build script on every build while a path it declared is missing, which would recompile the gateway each time.
fn watch(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
