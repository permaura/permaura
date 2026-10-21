# Contributing to Permaura

Thanks for looking. Permaura is a permission layer that sits between AI agents and real
credentials, so the bar for changes here is a bit higher than for most projects. A bug in this
codebase is somebody's production API key.

## Before you write code

**Open an issue.** Bug reports, reproductions, feature requests and design arguments are all
welcome, and the enforcement path in particular benefits from people poking holes in it. If you
have found something that is wrong, saying so in an issue is the most useful thing you can do.

**Security issues do not go in the issue tracker.** Report them privately: see
[SECURITY.md](SECURITY.md) or `security@permaura.com`. That includes anything you are unsure
about; we would much rather read a false alarm than find out from someone else.

## License

This repository is the Permaura gateway: the local capability broker that runs on your own
machine, and the crates and packages it is built from. It is open source under the terms in
[LICENSE](LICENSE).

Permaura's hosted control plane, the web console, and the desktop and mobile apps are separate,
proprietary, and not published here. Nothing in this repository requires them: the gateway runs
standalone, and an account only adds the hosted conveniences.

The name "Permaura" and the Permaura logo are not covered by the code license. See
[TRADEMARK.md](TRADEMARK.md).

## Pull requests are closed for now

We are not accepting outside pull requests at the moment, including small ones. This is not a
judgment on anybody's patch. Permaura is one company's work so far, and keeping the copyright in
one place preserves the option to change the license later without having to track down and get
agreement from everyone who ever sent a fix. Once that is settled we will open pull requests
behind a contributor license agreement, which is a one-click signature on your first
contribution and nothing after that.

In the meantime, an issue is worth as much as a patch and often more. Describe the problem, or
paste the diff you would have sent, and we will write it up with the reasoning in the commit. If
you found it, the issue will say so.

Security issues are the exception to all of this and still go to `security@permaura.com`, never
to the tracker.

## Working on the code

```bash
cargo test --workspace       # everything, offline: no network, no live credentials
cargo clippy --all-targets   # keep it clean; warnings in new code get flagged in review
cargo fmt --all
```

The whole test suite runs offline by design: the HTTP client, the command runner, and the SSH
transport all default to deterministic mocks. If a test of yours needs the network, it belongs
behind a feature flag or it belongs somewhere else.

## What review will ask you about

- **Does it fail closed?** When something is missing, malformed, expired, or ambiguous, the answer
  is deny. Guessing is how credentials leak.
- **Does the plaintext window get smaller or larger?** Secrets are opened for one call and wiped.
  A change that widens or lengthens that window needs a reason.
- **Does it hold at the boundary rather than the call site?** Invariants enforced in one place
  survive the next person's refactor; invariants enforced by every caller remembering do not.
- **Is there a test for the failure, not just the success?** The interesting cases are the refused
  ones, and a test that would still pass with the check removed is not a test of the check.
- **Comments explain *why*.** The code already says what it does.

## Commit messages

Say what changed and why it mattered. A reader six months from now should be able to tell whether
your commit is the one they are looking for without opening the diff.
