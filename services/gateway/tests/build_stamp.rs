//! `/health`'s `build_sha` names the commit a warm build was made from, not the one the last full build saw.
//!
//! build.rs read `git rev-parse HEAD` but declared only its two environment overrides and itself as inputs, so Cargo never re-ran it when HEAD moved: a binary rebuilt after a commit kept reporting the commit before. Each case builds a throwaway crate that carries the gateway's own build.rs, in a fresh repository, commits, rebuilds without cleaning, and reads the stamp back.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_RS: &str = include_str!("../build.rs");

/// A scratch repository holding a crate that prints the stamp build.rs gives it.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        common::isolate_from_the_real_install();
        let root = std::env::temp_dir().join(format!("permaura-build-stamp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"stamp-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[workspace]\n",
        )
        .unwrap();
        std::fs::write(repo.join("build.rs"), BUILD_RS).unwrap();
        std::fs::write(repo.join(".gitignore"), "/target\n").unwrap();
        write_main(&repo, "A");
        let fixture = Fixture { root };
        fixture.git(&repo, &["init", "-q", "-b", "main"]);
        fixture.git(&repo, &["add", "."]);
        fixture.commit(&repo, "A");
        fixture
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let out = scrubbed(Command::new("git"))
            .current_dir(dir)
            .args(["-c", "user.name=Stamp Fixture", "-c", "user.email=stamp@example.invalid", "-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn commit(&self, dir: &Path, message: &str) -> String {
        // A commit in the same instant as the build it follows would carry the same mtime, which Cargo reads as unchanged on a filesystem that keeps whole seconds.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        self.git(dir, &["commit", "-q", "--allow-empty", "-am", message]);
        self.git(dir, &["rev-parse", "HEAD"])
    }

    /// Build without cleaning and report the stamp, with the fixture's own target directory so nothing is shared with the build running this test.
    fn stamp(&self, dir: &Path) -> String {
        let out = scrubbed(Command::new(env!("CARGO")))
            .current_dir(dir)
            .args(["run", "--offline", "--quiet"])
            .env("CARGO_TARGET_DIR", dir.join("target"))
            .output()
            .expect("cargo runs");
        assert!(out.status.success(), "cargo run: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// Whether a second build with nothing moved reuses the last one. A watched path that does not exist would make Cargo re-run build.rs, and so recompile the crate, on every build.
    fn fresh(&self, dir: &Path) -> bool {
        let out = scrubbed(Command::new(env!("CARGO")))
            .current_dir(dir)
            .args(["build", "--offline", "-v"])
            .env("CARGO_TARGET_DIR", dir.join("target"))
            .output()
            .expect("cargo runs");
        let log = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "cargo build: {log}");
        log.contains("Fresh stamp-fixture")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The overrides build.rs prefers to Git would answer for it (CI sets `GITHUB_SHA`), and a variable a Git hook exports would point git at another repository.
fn scrubbed(mut command: Command) -> Command {
    for var in ["PERMAURA_BUILD_SHA", "GITHUB_SHA", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "RUSTC_WRAPPER"] {
        command.env_remove(var);
    }
    command
}

fn write_main(dir: &Path, marker: &str) {
    std::fs::write(
        dir.join("src/main.rs"),
        format!("// {marker}\nfn main() {{\n    println!(\"{{}}\", env!(\"PERMAURA_BUILD_SHA\"));\n}}\n"),
    )
    .unwrap();
}

fn short(sha: &str) -> &str {
    &sha[..12]
}

#[test]
fn a_rebuild_after_a_commit_reports_the_new_commit() {
    let f = Fixture::new("plain");
    let repo = f.repo();
    let a = f.git(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(f.stamp(&repo), short(&a));

    write_main(&repo, "B");
    let b = f.commit(&repo, "B");
    assert_eq!(f.stamp(&repo), short(&b), "a source change committed as B and rebuilt warm reports B");

    let c = f.commit(&repo, "C");
    assert_eq!(f.stamp(&repo), short(&c), "a commit that changes no source still moves the stamp");
}

#[test]
fn a_linked_worktree_reports_its_own_commit() {
    let f = Fixture::new("worktree");
    let repo = f.repo();
    let tree = f.root.join("tree");
    f.git(&repo, &["worktree", "add", "-q", "-b", "lane", tree.to_str().unwrap()]);
    let a = f.git(&tree, &["rev-parse", "HEAD"]);
    assert_eq!(f.stamp(&tree), short(&a));
    assert!(f.fresh(&tree));

    write_main(&tree, "B");
    let b = f.commit(&tree, "B");
    assert_eq!(f.stamp(&tree), short(&b), "the worktree's HEAD and branch live in two different git directories");

    f.git(&tree, &["checkout", "-q", "--detach", &a]);
    assert_eq!(f.stamp(&tree), short(&a), "a detached HEAD is followed too");
    assert!(f.fresh(&tree));
}

#[test]
fn a_packed_branch_ref_is_followed_once_a_commit_writes_it_loose() {
    let f = Fixture::new("packed");
    let repo = f.repo();
    f.git(&repo, &["pack-refs", "--all"]);
    assert!(!repo.join(".git/refs/heads/main").exists(), "the branch is only in packed-refs");
    let a = f.git(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(f.stamp(&repo), short(&a));
    assert!(f.fresh(&repo), "watching for the loose ref to appear does not rebuild while it has not");

    let b = f.commit(&repo, "B");
    assert_eq!(f.stamp(&repo), short(&b));
}

#[test]
fn an_unchanged_head_does_not_rebuild() {
    let f = Fixture::new("quiet");
    let repo = f.repo();
    let a = f.git(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(f.stamp(&repo), short(&a));
    assert!(f.fresh(&repo), "nothing it watches moved, so nothing reruns");
}
