//! The command seam: drive a locked-down CLI by running a fixed, allow-listed program
//! with the connection's token injected as an environment variable.
//!
//! This is the safe answer to "the agent uses the `vercel` CLI": rather than handing the
//! agent the ambient `vercel login` session (an unscoped, long-lived credential on disk),
//! Permaura runs a *fixed* argv it controls and injects the connection's stored token into
//! `VERCEL_TOKEN` server-side, the same way the HTTP path shapes the secret into a header,
//! so the agent never holds it. The operator chooses how narrow and how long-lived that token
//! is when they add it.
//!
//! Hard rules enforced here:
//!
//! - The runner receives a program + a **vec of args**, never a shell string. Nothing is
//!   ever passed through `sh -c`, so there is no shell to inject into.
//! - Placeholders are substituted from agent params *only* when whitelisted, and every
//!   substituted value is rejected if it contains shell metacharacters or whitespace it
//!   should not carry, defence in depth even though there is no shell.
//! - The runner **never logs the env map**. The injected token is held in the invocation,
//!   wiped when it drops, and handed to the child process's environment through the
//!   `Command`'s own copy, which is not wiped.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// The default wall-clock budget for a single command invocation. A locked-down CLI
/// that hangs must not pin the gateway, so the real runner kills the child after this.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// A fully-resolved command to run: a program, its argument vector, and the environment
/// overlay (which carries the injected scoped token). There is deliberately no shell
/// string field: the argv is the contract, and it is passed to the OS exec directly.
///
/// The environment's values are wiped when the invocation drops and never printed by `Debug`. Spawning
/// copies them into the `Command`'s own environment and from there into the child's, and neither copy is wiped.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandInvocation {
    /// The program to exec (e.g. `vercel`). A fixed value from the [`CommandSpec`], never
    /// agent-supplied.
    pub program: String,
    /// The argument vector, already substituted and validated. Each element is one argv
    /// slot; spaces inside an element are a single argument, not a word split.
    pub args: Vec<String>,
    /// Environment variables to set on the child process. Contains the injected secret
    /// (e.g. `VERCEL_TOKEN`). This map is never logged.
    pub envs: BTreeMap<String, String>,
}

impl Drop for CommandInvocation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.envs.values_mut().for_each(Zeroize::zeroize);
    }
}

impl std::fmt::Debug for CommandInvocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandInvocation")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("envs", &self.envs.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The captured result of a command: its exit code and the two output streams as UTF-8
/// (lossy). The gateway redacts `stdout` before returning it to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandOutput {
    /// The process exit code (`-1` if it was terminated by a signal / had no code).
    pub code: i32,
    /// Captured standard output, UTF-8 lossy.
    pub stdout: String,
    /// Captured standard error, UTF-8 lossy.
    pub stderr: String,
}

/// The seam connectors depend on to run a locked-down CLI. Object-safe so the gateway can
/// hold `Arc<dyn CommandRunner>` and swap a [`MockCommandRunner`] in offline and in tests.
///
/// Implementors MUST treat [`CommandInvocation::args`] as a literal argv (no shell), and
/// MUST NOT log [`CommandInvocation::envs`].
#[async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run `inv` to completion and return its [`CommandOutput`].
    async fn run(&self, inv: CommandInvocation) -> anyhow::Result<CommandOutput>;
}

/// The production runner: spawns the child via [`tokio::process::Command`], passing the
/// argv directly to the OS (no shell), overlaying the env map, capturing both streams,
/// and killing the child if it overruns the timeout.
pub struct RealCommandRunner {
    timeout: Duration,
    max_output_bytes: u64,
}

impl RealCommandRunner {
    /// A runner with the [`DEFAULT_COMMAND_TIMEOUT`] and the configured output cap.
    pub fn new() -> Self {
        RealCommandRunner {
            timeout: DEFAULT_COMMAND_TIMEOUT,
            max_output_bytes: crate::caps::command_max_output_bytes(),
        }
    }

    /// A runner with an explicit timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        RealCommandRunner {
            timeout,
            ..RealCommandRunner::new()
        }
    }

    /// A runner with an explicit per-stream output cap. The cap is normally read once per process
    /// from the environment, which a test cannot vary; this is how a test pins one.
    pub fn with_output_cap(mut self, max_output_bytes: u64) -> Self {
        self.max_output_bytes = max_output_bytes;
        self
    }
}

impl Default for RealCommandRunner {
    fn default() -> Self {
        RealCommandRunner::new()
    }
}

/// How a command-connector `program` name resolves when launched, judged against Windows' rules
/// (the strictest). Windows `CreateProcess` only auto-appends `.exe`, and there is deliberately no
/// PATHEXT emulation here: the connector program is handed to the OS verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramForm {
    /// A path (contains a separator) or an explicit `.exe`/`.com`: launches directly on every OS.
    Direct,
    /// An explicit `.cmd`/`.bat`: launches via cmd.exe delegation (the std runtime does the arg
    /// escaping). Fine on Windows.
    BatchScript,
    /// A bare name, no extension, no separator. Resolves via PATH: always fine on Unix, and fine on
    /// Windows *iff* a real `<name>.exe` is on PATH (e.g. `node`, `git`, `python`), but a bare name
    /// that is actually a `.cmd`/`.bat` PATH shim (how `npm`, `yarn`, `pnpm`, `vercel` global
    /// installs land) will NOT launch on Windows.
    BareName,
}

/// Classify a connector `program` string (see [`ProgramForm`]). Pure and OS-independent, so the same
/// judgement can be surfaced in docs, at connection-creation time, and in the run-time error hint.
pub fn classify_program(program: &str) -> ProgramForm {
    if program.contains('/') || program.contains('\\') {
        return ProgramForm::Direct;
    }
    let lower = program.to_ascii_lowercase();
    if lower.ends_with(".exe") || lower.ends_with(".com") {
        ProgramForm::Direct
    } else if lower.ends_with(".cmd") || lower.ends_with(".bat") {
        ProgramForm::BatchScript
    } else {
        ProgramForm::BareName
    }
}

/// Turn a raw spawn failure into an actionable error. On Windows, a `NotFound` for a bare-name
/// program is very likely a `.cmd`/`.bat` PATH shim the OS won't launch. Say so and how to fix it,
/// instead of a cryptic "program not found". Only fires when the spawn ACTUALLY failed, so a valid
/// bare `.exe` (`node`, `git`) is never rejected.
fn spawn_error(program: &str, e: std::io::Error) -> anyhow::Error {
    #[cfg(windows)]
    if e.kind() == std::io::ErrorKind::NotFound && classify_program(program) == ProgramForm::BareName
    {
        return anyhow::anyhow!(
            "could not launch command '{program}': {e}. On Windows a bare PATH name only resolves to \
             a real .exe. A .cmd/.bat shim (npm, yarn, pnpm, vercel, …) will not launch. Set the \
             connector program to an explicit '{program}.cmd' (or .bat), or to an absolute path."
        );
    }
    anyhow::Error::new(e).context(format!("could not launch command '{program}'"))
}

#[async_trait]
impl CommandRunner for RealCommandRunner {
    async fn run(&self, inv: CommandInvocation) -> anyhow::Result<CommandOutput> {
        // `Command::new(program).args(...)` execs the program directly. There is no shell
        // and no word-splitting; each `arg` is one argv slot. The child's environment is the
        // allowlist from the gateway's own plus the injected vars, nothing else (see `inherited`).
        let mut cmd = tokio::process::Command::new(&inv.program);
        cmd.args(&inv.args)
            .env_clear()
            .envs(std::env::vars_os().filter(|(name, _)| name.to_str().is_some_and(inherited)))
            .envs(&inv.envs)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // In a process group of its own on Linux, so whatever the program starts itself is ended with it below; elsewhere it stays in the gateway's group, through which a service manager's cleanup works.
        #[cfg(target_os = "linux")]
        cmd.process_group(0);

        // The program the gateway starts dies with the gateway on Linux, so a gateway killed mid-call does not leave it running with the injected credential in its environment. Anything it starts itself is ended through its group when this call ends, but on a gateway's death only by a service manager that kills the whole unit (systemd's default). Started inside the call's own timeout, so a stuck start cannot hold the call longer.
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut child = match tokio::time::timeout_at(deadline, permaura_platform::child::spawn_tokio_dying_with_this_process(cmd)).await {
            Ok(spawned) => spawned.map_err(|e| spawn_error(&inv.program, e))?,
            Err(_) => anyhow::bail!("command '{}' could not be started within the {}s timeout", inv.program, self.timeout.as_secs()),
        };
        #[cfg(target_os = "linux")]
        let _group = ProcessGroup(child.id());
        let cap = self.max_output_bytes;
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();

        let collect = async {
            // Both pipes are drained concurrently. Reading one to EOF first would deadlock a child
            // that fills the other pipe's kernel buffer while we are not reading it.
            let (out, err) = tokio::try_join!(
                read_capped(stdout.as_mut(), cap, "stdout"),
                read_capped(stderr.as_mut(), cap, "stderr"),
            )?;
            let status = child.wait().await?;
            Ok::<_, anyhow::Error>((status, out, err))
        };

        let (status, out, err) = match tokio::time::timeout_at(deadline, collect).await {
            Ok(Ok(triple)) => triple,
            // A cap breach or a pipe error. The child is still running and still writing, so it is
            // killed here rather than left to `kill_on_drop`: the drop happens when this scope ends,
            // which on the error path is after the caller has already been answered.
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(e);
            }
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!(
                    "command '{}' exceeded the {}s timeout",
                    inv.program,
                    self.timeout.as_secs()
                );
            }
        };

        Ok(CommandOutput {
            code: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
        })
    }
}

/// The process group a command child leads on Linux, ended whenever the call ends, by any path: the program's exit, a timeout, a cap breach, or the caller dropping the call. The program itself is already gone or killed by then; this ends what it started.
#[cfg(target_os = "linux")]
struct ProcessGroup(Option<u32>);

#[cfg(target_os = "linux")]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(leader) = self.0 {
            permaura_platform::child::kill_process_group(leader);
        }
    }
}

/// Whether a command child inherits the gateway's variable `name`: only what a CLI needs to find programs, its home and a temp directory and to speak the locale. The gateway's environment also holds the vault passphrase variables, systemd's `CREDENTIALS_DIRECTORY` and whatever keys the shell that started it exported, and a program the agent can make print its environment would return them.
fn inherited(name: &str) -> bool {
    #[cfg(windows)]
    {
        // Variable names are case-insensitive on Windows, and a process cannot start without the system ones.
        const WINDOWS: &[&str] = &[
            "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        ];
        let upper = name.to_ascii_uppercase();
        WINDOWS.contains(&upper.as_str()) || ["HOME", "LANG", "TMPDIR"].contains(&upper.as_str()) || upper.starts_with("LC_")
    }
    #[cfg(not(windows))]
    {
        ["PATH", "HOME", "LANG", "TMPDIR"].contains(&name) || name.starts_with("LC_")
    }
}

/// Read one of a child's pipes to EOF or to `cap` bytes, whichever comes first, failing on the cap.
///
/// Failing rather than truncating is the same judgement the HTTP connector makes: the gateway hands
/// `stdout` back to the agent as the capability's result, and a silently shortened result is one the
/// agent has no way to tell from a complete one. `stream` names which pipe breached so an operator
/// raising the cap knows which side to size.
///
/// The error text carries the cap and the stream name only, never captured bytes, because the
/// command connector's output can hold whatever the injected token fetched.
async fn read_capped<R>(reader: Option<&mut R>, cap: u64, stream: &str) -> anyhow::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };
    let mut buf = Vec::new();
    // `cap + 1` so the read stops one byte past the limit: that byte is what distinguishes "exactly
    // at the cap" (fine) from "there was more" (a breach).
    let read = reader.take(cap + 1).read_to_end(&mut buf).await?;
    if read as u64 > cap {
        anyhow::bail!("command {stream} exceeded the {cap}-byte output cap");
    }
    Ok(buf)
}

/// A deterministic offline / test double. It records every invocation it is handed (so a
/// test can assert on the exact argv and confirm the token was injected) and returns a
/// canned [`CommandOutput`], so the gateway's command path runs end-to-end with no real
/// CLI installed and no side effects.
#[derive(Clone)]
pub struct MockCommandRunner {
    invocations: Arc<Mutex<Vec<CommandInvocation>>>,
    canned: Arc<Mutex<CommandOutput>>,
}

impl MockCommandRunner {
    /// A mock that returns a generic successful `whoami`-shaped stdout for every call.
    pub fn new() -> Self {
        MockCommandRunner {
            invocations: Arc::new(Mutex::new(Vec::new())),
            canned: Arc::new(Mutex::new(CommandOutput {
                code: 0,
                stdout: "permaura-bot\n".to_string(),
                stderr: String::new(),
            })),
        }
    }

    /// A mock pre-loaded with a specific canned output.
    pub fn with_output(output: CommandOutput) -> Self {
        let m = MockCommandRunner::new();
        *m.canned.lock().unwrap() = output;
        m
    }

    /// Replace the canned output returned by subsequent calls.
    pub fn set_output(&self, output: CommandOutput) {
        *self.canned.lock().unwrap() = output;
    }

    /// Every invocation captured so far, in order.
    pub fn invocations(&self) -> Vec<CommandInvocation> {
        self.invocations.lock().unwrap().clone()
    }

    /// The most recently captured invocation, if any.
    pub fn last_invocation(&self) -> Option<CommandInvocation> {
        self.invocations.lock().unwrap().last().cloned()
    }
}

impl Default for MockCommandRunner {
    fn default() -> Self {
        MockCommandRunner::new()
    }
}

#[async_trait]
impl CommandRunner for MockCommandRunner {
    async fn run(&self, inv: CommandInvocation) -> anyhow::Result<CommandOutput> {
        self.invocations.lock().unwrap().push(inv);
        Ok(self.canned.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inherited set is the allowlist and nothing that carries a gateway secret.
    #[test]
    fn a_command_child_inherits_only_the_allowlisted_names() {
        for name in ["PATH", "HOME", "LANG", "TMPDIR", "LC_ALL", "LC_CTYPE"] {
            assert!(inherited(name), "{name}");
        }
        for name in [
            "CREDENTIALS_DIRECTORY",
            "PERMAURA_VAULT_PASSPHRASE",
            "PERMAURA_VAULT_PASSPHRASE_FILE",
            "PERMAURA_ANNOUNCE_SECRET",
            "PERMAURA_INFISICAL_CLIENT_SECRET",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "SSH_AUTH_SOCK",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(!inherited(name), "{name}");
        }
    }

    /// What a command connector's program starts itself does not outlive the call. The program here backgrounds a sleeper, prints its pid and exits; when the call returns the sleeper is gone too, ended through the program's process group. Linux only, where command connectors get a group of their own.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn what_the_program_starts_itself_ends_with_the_call() {
        let runner = RealCommandRunner::new();
        let out = runner
            .run(CommandInvocation {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "sleep 30 >/dev/null 2>&1 & echo $!".into()],
                envs: BTreeMap::new(),
            })
            .await
            .expect("the program runs");
        let pid: u32 = out.stdout.trim().parse().expect("the program printed its sleeper's pid");
        let gone = |pid: u32| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .map(|stat| stat.rsplit_once(')').is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')))
                .unwrap_or(true)
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !gone(pid) && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let left = !gone(pid);
        if left {
            let _ = std::process::Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
        assert!(!left, "the sleeper the program started outlived the call");
    }

    /// A child that never stops printing is the runaway case: the cap has to stop the read AND the
    /// runner has to kill the child, or the process keeps writing into a pipe nobody drains for the
    /// rest of the 60 second budget. Bounded by an outer timeout so a regression fails the test
    /// instead of hanging the suite.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_runaway_command_is_capped_and_the_child_is_killed() {
        let runner = RealCommandRunner::new().with_output_cap(16 * 1024);
        let call = runner.run(CommandInvocation {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "yes permaura".into()],
            envs: BTreeMap::new(),
        });
        let err = tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .expect("the cap ends the call long before the command timeout")
            .expect_err("unbounded output is an error, never a truncated result");
        let text = err.to_string();
        assert!(text.contains("output cap"), "unexpected error: {text}");
        assert!(text.contains("stdout"), "the breaching stream is named: {text}");
        // Nothing the child wrote reaches the message, so it needs no redaction.
        assert!(!text.contains("permaura "), "captured output leaked into the error: {text}");
    }

    /// The cap must not shorten a legitimate result: output under it comes back whole.
    #[cfg(unix)]
    #[tokio::test]
    async fn output_under_the_cap_is_returned_whole() {
        let runner = RealCommandRunner::new().with_output_cap(64 * 1024);
        let out = runner
            .run(CommandInvocation {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "printf 'hello'; printf 'oops' >&2".into()],
                envs: BTreeMap::new(),
            })
            .await
            .expect("a small command succeeds");
        assert_eq!(out.stdout, "hello");
        assert_eq!(out.stderr, "oops");
        assert_eq!(out.code, 0);
    }

    /// stderr is capped on its own count, not folded into stdout's: a command that is quiet on
    /// stdout and loud on stderr is the same memory problem.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_runaway_stderr_is_capped_too() {
        let runner = RealCommandRunner::new().with_output_cap(16 * 1024);
        let call = runner.run(CommandInvocation {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "yes permaura >&2".into()],
            envs: BTreeMap::new(),
        });
        let err = tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .expect("the cap ends the call")
            .expect_err("unbounded stderr is an error");
        assert!(err.to_string().contains("stderr"), "unexpected error: {err}");
    }

    #[test]
    fn classify_program_covers_the_windows_launch_rules() {
        use ProgramForm::*;
        let cases = [
            // Explicit executables and any path form launch directly on every OS.
            ("vercel.exe", Direct),
            ("TOOL.EXE", Direct),
            ("thing.com", Direct),
            ("/usr/local/bin/vercel", Direct),
            (r"C:\tools\vercel.cmd", Direct), // a path is Direct even if it ends .cmd: the OS has the full spec
            ("./run", Direct),
            // Explicit batch scripts launch via cmd.exe delegation.
            ("deploy.cmd", BatchScript),
            ("Deploy.BAT", BatchScript),
            // Bare names: fine on Unix / real-exe on Windows, but the .cmd-shim trap on Windows.
            ("vercel", BareName),
            ("npm", BareName),
            ("node", BareName),
        ];
        for (program, want) in cases {
            assert_eq!(classify_program(program), want, "classify_program({program:?})");
        }
    }

    #[tokio::test]
    async fn mock_records_invocation_and_returns_canned() {
        let runner = MockCommandRunner::with_output(CommandOutput {
            code: 0,
            stdout: "ok".into(),
            stderr: String::new(),
        });
        let mut envs = BTreeMap::new();
        envs.insert("VERCEL_TOKEN".to_string(), "tok".to_string());
        let out = runner
            .run(CommandInvocation {
                program: "vercel".into(),
                args: vec!["whoami".into()],
                envs,
            })
            .await
            .unwrap();
        assert_eq!(out.stdout, "ok");
        let captured = runner.last_invocation().unwrap();
        assert_eq!(captured.program, "vercel");
        assert_eq!(captured.args, vec!["whoami".to_string()]);
        assert_eq!(captured.envs.get("VERCEL_TOKEN").unwrap(), "tok");
    }

    #[tokio::test]
    async fn real_runner_execs_argv_without_a_shell() {
        // `echo` is everywhere; the key assertion is that the args are passed as a literal
        // argv (no word-splitting): a single arg containing a space stays one argument, and
        // a `$VAR` is NOT expanded because there is no shell.
        let runner = RealCommandRunner::new();
        let out = runner
            .run(CommandInvocation {
                program: "echo".into(),
                args: vec!["hello world".into(), "$HOME".into()],
                envs: BTreeMap::new(),
            })
            .await
            .unwrap();
        assert_eq!(out.code, 0);
        // echo joins argv with single spaces; `$HOME` is literal because no shell expanded it.
        assert_eq!(out.stdout.trim_end(), "hello world $HOME");
    }
}
