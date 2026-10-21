//! The guard on the rest of this directory: no test in it may reach the machine's real Permaura
//! install.
//!
//! The failure it exists to stop is not hypothetical and does not show up in CI. A GitHub runner
//! has no `~/.permaura`, so a test that resolves the default home finds nothing there, mints
//! whatever it needed and passes. On a machine with a real gateway on it the same test finds a real
//! `vault-kek.in-os-store`, cannot read the OS credential store from an unsigned test binary, and
//! panics with "refusing to start" before its first assertion. That is the correct behaviour aimed
//! at the wrong process, and because `scripts/pre-push.sh` runs the suite it took local pushes with
//! it. `audit_archive.rs` and `audit_scale.rs` were both in that state: a scratch directory for the
//! SQLite file, and nothing at all pinning the home the vault resolves through.
//!
//! Two tests, because there are two ways to lose this. The first is that something moves the pin at
//! run time; the second, far more likely, is that a new test file simply never makes it, and no
//! amount of runtime checking inside this binary can see into another one. So the second test reads
//! the suite's own sources.
//!
//! What the source scan does NOT catch, and nothing here can: a file that pins in one fixture and
//! not in another. `restore_reconciliation.rs` was exactly that, and it names the helper three
//! times, so every rule expressible over one file's text calls it compliant. Three of its tests
//! still called `seed::seed` (which seals the demo estate, so it resolves the KEK) ahead of the
//! fixture that pins. What catches that shape is running the suite on a machine that HAS an
//! install, where the unpinned path panics, and the point of this whole change is that doing so is
//! possible again. A CI runner with no `~/.permaura` will never see it.

mod common;

use std::path::{Path, PathBuf};

/// What a test file has to name to be considered isolated. Either it routes through `common`, whose
/// every constructor pins the home, or it says so itself.
const ISOLATOR: &str = "isolate_from_the_real_install";

/// Calls that resolve the vault KEK, and so the Permaura home, whatever path they are handed. A
/// file making one of these must pin the home in its own fixture rather than inherit a pin from
/// whichever neighbouring test happened to run first: within a binary that ordering is the test
/// harness's to choose, and a filter that runs one test by name takes it away entirely. That is not
/// a theoretical ordering either, and it is why the list is this long rather than just the store:
/// `vault_portability.rs` reaches `vault_passphrase()` directly from a fixture that builds its own
/// minimal estate, and `gateway.rs` builds two states through `in_memory_seeded_with_http`.
///
/// `SqliteStore::open` is deliberately the whole needle for both store types, since
/// `PersistedSqliteStore::open` contains it.
const RESOLVES_THE_VAULT: [&str; 6] = [
    "SqliteStore::open",
    "AppState::in_memory_seeded",
    "AppState::from_parts",
    "AppState::new",
    "vault_passphrase",
    "seed::seed",
];

/// The live half: this process is pinned, and pinned somewhere that is not the developer's home.
///
/// It is `assert_isolated` that does the work, and it is called by every fixture in the suite, so
/// this test is really asserting that the guard itself still fires rather than silently passing on
/// a machine where `HOME` is unset or the pin has gone missing.
#[test]
fn this_binary_resolves_a_scratch_home_and_not_the_real_one() {
    common::isolate_from_the_real_install();

    let home = permaura_core::permaura_home().expect("the pin resolves");
    assert!(home.starts_with(std::env::temp_dir()), "a test home belongs in the OS temp directory: {home:?}");

    let real = permaura_core::permaura_path("vault-kek").expect("the pin resolves");
    assert!(!real.exists(), "a scratch home must not already hold a vault KEK: {real:?}");
}

/// The half that reaches the files this binary cannot: every other integration test in this
/// directory pins the home too.
///
/// A source scan rather than anything cleverer because the thing being checked is a property of a
/// *different* binary. `PERMAURA_HOME` is process-global, so the only runtime signal one test binary
/// could leave for another is the environment it was started in, and that is exactly what must not
/// be relied on. Reading the sources is the one check that runs before the offending binary does.
#[test]
fn every_test_in_this_directory_pins_the_permaura_home() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut unpinned: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&dir).expect("the suite's own directory is readable") {
        let path = entry.expect("a readable entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name() == Some(Path::new(file!()).file_name().unwrap()) {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let source = std::fs::read_to_string(&path).expect("a readable test file");
        // Matched against the code with its line comments cut off, so that a doc comment saying
        // which constructor a fixture deliberately does NOT use is not read as using it.
        let code = strip_line_comments(&source);

        // `mod common;` is the floor: without it the helper is not even in scope, and a file that
        // builds an estate any other way is building it by hand.
        if !source.contains("mod common;") {
            unpinned.push(format!("{name}: does not declare `mod common;`"));
            continue;
        }
        // And a file that opens a store itself must pin it itself, rather than hope a neighbour did.
        if let Some(call) = RESOLVES_THE_VAULT.iter().find(|c| code.contains(**c)) {
            if !code.contains(ISOLATOR) {
                unpinned.push(format!("{name}: calls {call} without naming {ISOLATOR}"));
            }
        }
    }

    // Sorted so the same breakage reads the same way twice: `read_dir` does not promise an order.
    unpinned.sort();
    assert!(
        unpinned.is_empty(),
        "these integration tests can resolve the developer's real ~/.permaura, which on a machine \
         with a gateway installed panics before the first assertion and blocks every push:\n  {}\n\
         Call common::isolate_from_the_real_install() in the fixture, before the first store or \
         AppState.",
        unpinned.join("\n  "),
    );
}

/// The source with everything from `//` to the end of each line removed.
///
/// Crude on purpose: a `//` inside a string literal loses the rest of that line too. The only cost
/// is a needle hiding behind one, and a needle behind a `//` on the same line is a comment anyway.
fn strip_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}
