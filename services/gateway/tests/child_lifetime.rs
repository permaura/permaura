//! Every child process core starts dies with the gateway, because every one goes through the one spawner, which on Linux forks on a thread living as long as the process.
//!
//! Linux ties `PR_SET_PDEATHSIG` to the thread that forked the child. Forked on a Tokio worker, the tunnel connector was SIGKILLed whenever the runtime retired that worker after a `block_in_place`, which the store does on ordinary paths; forked with no signal at all, a command connector's program or the notify `buzz` CLI outlived a gateway that was killed mid-call. The behavior is pinned by the spawner's own tests in `crates/permaura-platform/src/child.rs` (the Linux ones run on Linux CI); this pins the class, so no other site can arm the signal on whatever thread it runs on, or start a child without it.
//!
//! Parse Rust items and calls, excluding only items and files their parent declares test-only. A process started inside a third-party crate is beyond this scan.

mod common;

use std::path::{Path, PathBuf};

/// The one file allowed to arm a parent-death signal or start a process directly, relative to the workspace root.
const SPAWNER: &str = "crates/permaura-platform/src/child.rs";

/// Every other source file that builds a process `Command`, and how its children end. A file not named here fails the scan until someone says which it is.
const BUILDS_COMMANDS: &[(&str, Ends)] = &[
    ("services/gateway/src/cli/start.rs", Ends::Spawner),
    ("crates/permaura-connectors/src/command.rs", Ends::Spawner),
    ("services/gateway/src/notify.rs", Ends::Spawner),
    // The rest wait for the child to exit before going on: CLI commands, `hostname` during `start --pair`, and the build script.
    ("services/gateway/src/cli/restart.rs", Ends::Waited),
    ("services/gateway/src/cli/uninstall.rs", Ends::Waited),
    ("services/gateway/src/cli/enroll.rs", Ends::Waited),
    ("services/gateway/build.rs", Ends::Waited),
];

#[derive(PartialEq)]
enum Ends {
    /// Every command the file builds is started by the spawner, so it dies with the gateway.
    Spawner,
    /// `output()` or `status()`: the caller waits for it to exit.
    Waited,
}

/// Any spelling of the parent-death signal: libc's constant, nix's `set_pdeathsig`, rustix's `set_parent_process_death_signal`, or a `prctl` in any case.
const ARMS_A_SIGNAL: &[&str] = &["pdeathsig", "death_signal", "prctl"];

/// Any way of starting a process other than through the spawner: a `Command`'s `spawn()`, a bare fork, `posix_spawn`, or an exec family call.


fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target" || n == "node_modules" || n == "tests") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// What one file's production code holds, lower-cased: the lines the scan refuses, how many process `Command`s it builds, and how many times it calls the spawner.
struct Scan {
    refused: Vec<String>,
    commands: usize,
    spawner_calls: usize,
}

fn requires_test(meta: &syn::Meta) -> bool {
    use syn::parse::Parser;
    match meta {
        syn::Meta::Path(p) => p.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let Ok(parts) = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated.parse2(list.tokens.clone()) else { return false };
            if list.path.is_ident("all") { parts.iter().any(requires_test) } else { !parts.is_empty() && parts.iter().all(requires_test) }
        }
        _ => false,
    }
}

fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().filter(|a| a.path().is_ident("cfg")).any(|a| a.parse_args::<syn::Meta>().is_ok_and(|m| requires_test(&m)))
}

fn scan(relative: &str, text: &str) -> Scan {
    use syn::visit::Visit;
    struct Scanner { result: Scan, aliases: Vec<String> }
    impl<'ast> Visit<'ast> for Scanner {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            let attrs = match item {
                syn::Item::Fn(x) => &x.attrs, syn::Item::Mod(x) => &x.attrs,
                syn::Item::Const(x) => &x.attrs, syn::Item::Static(x) => &x.attrs,
                syn::Item::Impl(x) => &x.attrs, syn::Item::Use(x) => &x.attrs,
                syn::Item::Struct(x) => &x.attrs, syn::Item::Enum(x) => &x.attrs,
                syn::Item::Trait(x) => &x.attrs, syn::Item::Type(x) => &x.attrs,
                _ => &[][..],
            };
            if !test_only(attrs) { syn::visit::visit_item(self, item); }
        }
        fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
            if rename.ident == "Command" { self.aliases.push(rename.rename.to_string()); }
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "spawn" && call.args.is_empty() { self.result.refused.push("direct process spawn".into()); }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(expr) = call.func.as_ref() {
                let parts: Vec<_> = expr.path.segments.iter().map(|s| s.ident.to_string()).collect();
                let name = parts.last().map(String::as_str).unwrap_or_default();
                let command = parts.iter().any(|p| p == "Command" || self.aliases.contains(p));
                if command && matches!(name, "new" | "from") { self.result.commands += 1; }
                if command && name == "spawn" || matches!(name, "fork" | "vfork" | "posix_spawn" | "posix_spawnp" | "execv" | "execve" | "execvp" | "execvpe" | "execl" | "execlp" | "execle" | "fexecve") {
                    self.result.refused.push(format!("direct process call {}", parts.join("::")));
                }
                if parts.iter().any(|p| p == "permaura_platform") && name.starts_with("spawn_") { self.result.spawner_calls += 1; }
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_path(&mut self, path: &'ast syn::Path) {
            if path.segments.iter().any(|s| ARMS_A_SIGNAL.iter().any(|word| s.ident.to_string().to_ascii_lowercase().contains(word))) {
                self.result.refused.push("parent-death signal outside the spawner".into());
            }
            syn::visit::visit_path(self, path);
        }
    }
    let mut scanner = Scanner { result: Scan { refused: vec![], commands: 0, spawner_calls: 0 }, aliases: vec![] };
    match syn::parse_file(text) {
        Ok(file) => scanner.visit_file(&file),
        Err(_) => match syn::parse_str::<syn::Block>(&format!("{{{text}}}")) {
            Ok(block) => scanner.visit_block(&block),
            Err(error) => scanner.result.refused.push(format!("{relative}: cannot parse Rust: {error}")),
        }
    }
    scanner.result
}

fn test_module_files(path: &Path, text: &str) -> Vec<PathBuf> {
    use syn::visit::Visit;
    struct Modules<'a> { parent: &'a Path, found: Vec<PathBuf> }
    impl<'ast> Visit<'ast> for Modules<'_> {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if test_only(&item.attrs) && item.content.is_none() {
                let explicit = item.attrs.iter().find(|a| a.path().is_ident("path")).and_then(|a| {
                    if let syn::Meta::NameValue(n) = &a.meta { if let syn::Expr::Lit(e) = &n.value { if let syn::Lit::Str(s) = &e.lit { return Some(s.value()); } } }
                    None
                });
                let base = self.parent.parent().unwrap();
                let found = explicit.map(|p| base.join(p)).unwrap_or_else(|| base.join(format!("{}.rs", item.ident)));
                self.found.push(found);
            } else { syn::visit::visit_item_mod(self, item); }
        }
    }
    let mut modules = Modules { parent: path, found: vec![] };
    if let Ok(file) = syn::parse_file(text) { modules.visit_file(&file); }
    modules.found
}

#[test]
fn every_child_core_starts_goes_through_the_spawner() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("the workspace root");
    let mut sources = Vec::new();
    for tree in ["crates", "services"] {
        rust_sources(&root.join(tree), &mut sources);
    }
    assert!(sources.len() > 50, "the scan found the workspace's sources: {}", sources.len());
    let tests: Vec<_> = sources.iter().flat_map(|p| test_module_files(p, &std::fs::read_to_string(p).unwrap_or_default())).collect();
    let mut found = Vec::new();
    for path in sources.iter().filter(|p| !tests.contains(p)) {
        let relative = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if relative == SPAWNER {
            continue;
        }
        let file = scan(&relative, &std::fs::read_to_string(path).unwrap_or_default());
        found.extend(file.refused);
        if file.commands == 0 && file.spawner_calls == 0 {
            continue;
        }
        match BUILDS_COMMANDS.iter().find(|(f, _)| *f == relative) {
            None => found.push(format!("{relative} builds a process Command and is not in BUILDS_COMMANDS: say how its children end")),
            Some((_, Ends::Spawner)) if file.spawner_calls == 0 => found.push(format!("{relative} is named as using the spawner but never calls it")),
            Some((_, Ends::Spawner)) if file.commands > file.spawner_calls => found.push(format!(
                "{relative} builds {} process Commands and starts {} through the spawner: every one it builds must go through it",
                file.commands, file.spawner_calls
            )),
            Some(_) => {}
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
    let spawner = std::fs::read_to_string(root.join(SPAWNER)).unwrap_or_default();
    assert!(spawner.contains("PR_SET_PDEATHSIG"), "{SPAWNER} arms the signal");
}

/// The scan catches the other spellings of the signal and of starting a process, sees past a test module halfway down a file and past a URL before a call, and counts a command a spawner-routed file runs some other way.
#[test]
fn the_scan_catches_every_spelling() {
    let refused = |source: &str| scan("crates/x/src/lib.rs", source).refused;
    for (source, what) in [
        ("nix::sys::prctl::set_pdeathsig(Some(Signal::SIGKILL))?;", "nix's set_pdeathsig"),
        ("rustix::process::set_parent_process_death_signal(Some(Signal::Kill))?;", "rustix's death signal"),
        ("libc::PRCTL_SET(1);", "a prctl in another case"),
        ("let pid = unsafe { libc::fork() };", "a bare fork"),
        ("unsafe { libc::posix_spawn(&mut pid, path, null(), null(), argv, envp) };", "posix_spawn"),
        ("nix::unistd::execv(&path, &args)?;", "an exec"),
        ("let child = Run::new(\"x\").spawn()?;", "a spawn"),
        ("let child = Command::new(\"curl\").arg(\"https://h\").spawn()?;", "a spawn after a URL"),
        ("#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n\nfn later() { let c = Command::new(\"x\").spawn(); }", "a spawn after a test module"),
    ] {
        assert!(!refused(source).is_empty(), "missed {what}: {source}");
    }
    for (source, what) in [
        ("let cmd = tokio::process::Command::from(std_cmd);", "a Command converted from another"),
        ("use std::process::Command as Run;\nfn f() { Run::new(\"x\").status(); }", "a Command imported under another name"),
        ("use std::process::{Command as Run, Stdio};\nfn f() { Run::new(\"x\").output(); }", "a Command imported under another name in braces"),
    ] {
        assert!(scan("crates/x/src/lib.rs", source).commands > 0, "did not see that the file builds a Command: {what}");
    }
    let mixed = scan(
        "crates/x/src/lib.rs",
        "fn a() { permaura_platform::child::spawn_tokio_dying_with_this_process(Command::new(\"a\")); }\nfn b() { Command::new(\"b\").status(); }",
    );
    assert_eq!((mixed.commands, mixed.spawner_calls), (2, 1), "a second command run with status() is counted");
    let quiet = scan(
        "crates/x/src/lib.rs",
        "// a comment about the prctl the spawner arms, and Command::new(\"x\").spawn()\nlet s = \"posix_spawn and .spawn() in a string\";\ntokio::spawn(async {});\n#[cfg(test)]\nfn t() { Command::new(\"y\").spawn(); }",
    );
    assert!(quiet.refused.is_empty() && quiet.commands == 0, "comments, strings, task spawns and test items are not processes: {:?}", quiet.refused);
    let comment_only = scan("crates/x/src/lib.rs", "// permaura_platform::child::spawn_dying_with_this_process\nfn f() {}");
    assert_eq!(comment_only.spawner_calls, 0, "a comment is not a call to the spawner");
}

#[test]
fn the_scan_reads_rust_items_and_ufcs_calls_without_filename_guesses() {
    for source in [
        "fn f() { std::process::Command::spawn(&mut cmd); }",
        "use std::process::Command as Run; fn f() { Run::spawn(&mut cmd); }",
        "fn f() { let text = br#\"x \\\" y\"#; Command::new(\"x\").spawn(); }",
        "#[cfg(test)] const SAMPLE: u8 = 1; fn live() { Command::new(\"x\").spawn(); }",
    ] {
        assert!(!scan("crates/x/src/lib.rs", source).refused.is_empty(), "missed {source}");
    }
    assert!(!scan("crates/x/src/live_tests.rs", "fn f() { Command::new(\"x\").spawn(); }").refused.is_empty());
    assert!(scan("crates/x/src/lib.rs", "fn f() { let x = br#\"quote \\\" and .spawn() here\"#; }").refused.is_empty());
}
