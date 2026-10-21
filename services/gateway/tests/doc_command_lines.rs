//! No example this repository publishes puts the operator token, an agent's token or enrolment code, or a pairing code on a command line: an argument is in the process list, which every local user can read on a stock Linux, and in shell history. The CLI's own help already says so of the pairing code; the docs have to agree.

mod common;

/// Every document a reader copies commands from, by path from the repository root, with its text.
const DOCS: &[(&str, &str)] = &[
    ("README.md", include_str!("../../../README.md")),
    ("RUNBOOK.md", include_str!("../../../RUNBOOK.md")),
    ("docs/README.md", include_str!("../../../docs/README.md")),
    ("docs/architecture.md", include_str!("../../../docs/architecture.md")),
    ("docs/connector-authoring.md", include_str!("../../../docs/connector-authoring.md")),
    ("docs/data-model.md", include_str!("../../../docs/data-model.md")),
    ("docs/getting-started.md", include_str!("../../../docs/getting-started.md")),
    ("docs/mcp-integration.md", include_str!("../../../docs/mcp-integration.md")),
    ("docs/platforms.md", include_str!("../../../docs/platforms.md")),
    ("docs/policy-language.md", include_str!("../../../docs/policy-language.md")),
    ("docs/security.md", include_str!("../../../docs/security.md")),
    ("docs/threat-model.md", include_str!("../../../docs/threat-model.md")),
    ("examples/braintree-generic-http/README.md", include_str!("../../../examples/braintree-generic-http/README.md")),
    ("examples/github/README.md", include_str!("../../../examples/github/README.md")),
    ("examples/openapi-import/README.md", include_str!("../../../examples/openapi-import/README.md")),
    ("examples/stripe/README.md", include_str!("../../../examples/stripe/README.md")),
    ("packages/sdk/README.md", include_str!("../../../packages/sdk/README.md")),
    ("packages/sdk-python/README.md", include_str!("../../../packages/sdk-python/README.md")),
    ("packages/types/README.md", include_str!("../../../packages/types/README.md")),
    ("packages/ui/README.md", include_str!("../../../packages/ui/README.md")),
    ("packages/mcp-stdio/README.md", include_str!("../../../packages/mcp-stdio/README.md")),
    ("packages/mcp-stdio/src/cli.ts", include_str!("../../../packages/mcp-stdio/src/cli.ts")),
    ("packages/gateway/README.md", include_str!("../../../packages/gateway/README.md")),
    ("packages/gateway/bin/cli.mjs", include_str!("../../../packages/gateway/bin/cli.mjs")),
];

fn docs() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut docs: Vec<(String, String)> = DOCS.iter().map(|(path, text)| (path.to_string(), text.to_string())).collect();
    let mut extra: Vec<String> = std::fs::read_dir(root.join("docs"))
        .unwrap_or_else(|e| panic!("docs: {e}"))
        .map(|entry| entry.unwrap_or_else(|e| panic!("docs: {e}")).file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".md"))
        .map(|name| format!("docs/{name}"))
        .filter(|path| !DOCS.iter().any(|(listed, _)| listed == path))
        .collect();
    extra.sort();
    extra.dedup();
    for path in extra {
        let text = std::fs::read_to_string(root.join(&path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        docs.push((path, text));
    }
    docs
}

/// Shapes that put a secret in a command's arguments: a token expanded into a header argument (the safe form reads the header from a process substitution, `-H @<(printf ...)`), an agent token handed to `claude mcp add -e`, a pairing code given to `--pair` or to `pair` as an argument, and a token given to `--token`.
const ON_A_COMMAND_LINE: &[&str] = &[
    "Bearer $(cat",
    "Bearer $(<",
    "-H \"Authorization: Bearer $",
    "OP=\"Authorization: Bearer",
    "-e PERMAURA_AGENT_TOKEN=",
    "--pair PGW-",
    "--pair=PGW-",
    "permaura pair PGW-",
    "--token pgt_",
    "--token=pgt_",
    "-H \"$OP\"",
    "--header \"Authorization: Bearer",
    "--recovery-code <",
    "--ticket <",
];

#[test]
fn no_published_example_puts_a_token_or_a_code_on_a_command_line() {
    let mut found = Vec::new();
    for (path, text) in docs() {
        for (n, line) in text.lines().enumerate() {
            for shape in ON_A_COMMAND_LINE {
                if line.contains(shape) {
                    found.push(format!("{path}:{}: {}", n + 1, line.trim()));
                }
            }
        }
    }
    assert!(found.is_empty(), "examples that put a secret in a command's arguments:\n{}", found.join("\n"));
}

/// The POSIX `VAR=value command` form fails in PowerShell and cmd, so every document that gives it for the pairing code, on a launcher that runs on Windows, also gives the PowerShell (`$env:`) and cmd (`set`) forms.
#[test]
fn every_pairing_example_in_the_env_form_has_its_windows_forms() {
    let mut missing = Vec::new();
    for (path, text) in docs() {
        if !text.contains("PERMAURA_PAIR_CODE=PGW-") {
            continue;
        }
        for windows in ["$env:PERMAURA_PAIR_CODE", "set \"PERMAURA_PAIR_CODE="] {
            if !text.contains(windows) {
                missing.push(format!("{path}: no `{windows}` form"));
            }
        }
    }
    assert!(missing.is_empty(), "POSIX-only pairing examples:\n{}", missing.join("\n"));
}

/// What the CLI and the launcher print when they suggest a next step: the same rule as the docs, so no hint tells someone to type a pairing code or a token as an argument.
const HINT_SOURCES: &[(&str, &str)] = &[
    ("services/gateway/src/cli/enroll.rs", include_str!("../src/cli/enroll.rs")),
    ("services/gateway/src/cli/start.rs", include_str!("../src/cli/start.rs")),
    ("services/gateway/src/cli/announce.rs", include_str!("../src/cli/announce.rs")),
    ("services/gateway/src/cli/commands.rs", include_str!("../src/cli/commands.rs")),
    ("services/gateway/src/cli/auth.rs", include_str!("../src/cli/auth.rs")),
    ("packages/gateway/bin/cli.mjs", include_str!("../../../packages/gateway/bin/cli.mjs")),
];

#[test]
fn no_hint_the_cli_prints_puts_a_secret_on_a_command_line() {
    let mut found = Vec::new();
    for (path, text) in HINT_SOURCES {
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") || code.starts_with("*") || code.starts_with("assert") {
                continue;
            }
            for shape in ["permaura pair <code>", "Pass --token", "pass --token"] {
                if code.contains(shape) {
                    found.push(format!("{path}:{}: {}", n + 1, code));
                }
            }
        }
    }
    assert!(found.is_empty(), "hints that put a secret in a command's arguments:\n{}", found.join("\n"));
}
