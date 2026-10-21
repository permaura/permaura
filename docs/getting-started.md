# Getting started

This page gets the **engine** in this repository running on your own machine and verified, then hands you off. It is the developer's entry point: build it, start it, confirm it is enforcing, understand what it wrote to disk and why.

It deliberately stops at a running, verified gateway. Everything past that point (creating connections, writing policies, granting agents, approving held calls) is product surface that changes faster than this repo's docs can track, and it is documented once, properly, at **[permaura.com/docs](https://permaura.com/docs)**. See [Where to go next](#where-to-go-next).

## What you are running

One binary, `permaura` (`services/gateway`), with the whole surface behind subcommands:

| Command | What it is |
| --- | --- |
| `permaura start` | The enforcement runtime. REST `/v1` + MCP `/mcp`. This is the thing you run. |
| `permaura status`, `grant`, `vault`, `audit`, … | The command-line control surface. Talks to a running gateway over HTTP. |
| `permaura stop`, `permaura upgrade` | Drain and exit; fetch the latest published binary and replace this one. |

There is also `permad` (`crates/permaura-daemon`), a demo binary that serves the same router over a seeded in-memory estate with mock transports and the published demo bearer. Never use it for real credentials, and you do not need it to follow this page.

> **Bare `permaura` prints help and starts nothing.** Starting a gateway is always `permaura start`: a typo must never leave a server bound to a port.

## 1. Install

### From this repository

```bash
cargo build --release -p permaura-gateway
./target/release/permaura --version
```

`make gateway` runs a debug build on `127.0.0.1:7376` in one step. Read the [README's build-trust warning](../README.md#build-from-source) before using a debug build with real credentials. `cargo build` builds the whole workspace, `cargo test` runs the suite.

### Prebuilt

```bash
npm i -g permaura
permaura start
```

Puts `permaura` on your PATH on macOS, Linux and Windows alike, downloads the binary to `~/.permaura/bin/permaura`, and starts it. Takes a pairing code in `PERMAURA_PAIR_CODE` to enroll against a permaura.com account (`PERMAURA_PAIR_CODE=PGW-XXXXXXXXXX permaura start` in a POSIX shell, `$env:PERMAURA_PAIR_CODE = "PGW-XXXXXXXXXX"; permaura start` in PowerShell, `set "PERMAURA_PAIR_CODE=PGW-XXXXXXXXXX" && permaura start` in cmd; `--pair <code>` works too, but puts the code in the process list) and `--addr` (or `PERMAURA_ADDR`) to move off 7376. Every run checks for a newer gateway; the launcher itself is npm's, so refresh that with `npm update -g permaura`.

No Node on the machine, or you want it to survive a reboot:

```bash
curl -fsSL https://permaura.com/install | sh
```

Fetches the same binary directly and can register a service, which is what makes it the right choice for a server. macOS and Linux.

For a one-off or a box you will not keep, `npx -y permaura start` runs the same thing with nothing installed and nothing left on your PATH.

> The installer verifies each download's sha256 against a manifest that permaura.com checked against the pinned Ed25519 release key before serving the script.

## 2. First run

Real by default. HTTP, command execution and SSH are all live with no configuration:

```bash
permaura start
```

```text
INFO permaura_gateway: real transports live: HTTP, command execution and SSH
INFO permaura_gateway::store::migrations: applied gateway store migration version=1 …
INFO permaura_gateway::service: generated a per-install vault KEK path=~/.permaura/vault-kek
INFO permaura_gateway: persistent SQLite store path=~/.permaura/gateway.db
INFO permaura_gateway: clean gateway: no demo data; per-gateway operator token minted
INFO permaura_gateway: operator token published for the installer path=~/.permaura/operator.token
INFO permaura_gateway: Permaura gateway listening: give agents permission, not keys addr=127.0.0.1:7376
```

A first run creates these under `~/.permaura`, all owner-only:

| File | What it holds |
| --- | --- |
| `gateway.db` | The store: connections, policies, grants, agents, sealed secrets, the audit chain. SQLite, migrated on start. |
| `gateway.db.auditkey` | The audit chain's Ed25519 signing key. It sits beside the store, so anyone who can rewrite the store can usually re-sign it. |
| `vault-kek` | This install's vault key-encryption key, generated on first run if nothing supplied one, unless the OS credential store holds it instead (Windows Credential Manager, or the Keychain for a Developer ID signed macOS build). |
| `operator.token` | A real Operator session bearer, minted at clean bootstrap. This is the credential the installer, the CLI and the console enroll with. |

A clean gateway carries **no demo data**, and no environment variable can seed it. Demo data is `--demo` only, which is always in-memory with mock transports.

`PERMAURA_HOME` relocates all of the above. `PERMAURA_STORE_PATH` overrides just the store (`:memory:` for a throwaway gateway, which ignores `config.toml` and starts no tunnel, relay or pairing).

### Where the vault key comes from

There is no passphrase prompt. The gateway resolves its vault KEK through a fixed ladder ([`services/gateway/src/service.rs`](../services/gateway/src/service.rs), `vault_passphrase()`), taking the first that yields a key:

1. **Handed over on stdin** (`PERMAURA_VAULT_PASSPHRASE_STDIN=1`). What a supervisor should use: it never lands in the process environment.
2. **A file path** (`PERMAURA_VAULT_PASSPHRASE_FILE`).
3. **A persistent per-install key**, generated on first run and kept in the OS credential store where the gateway can use one (Windows Credential Manager, or the macOS Keychain for a Developer ID signed build), otherwise in the owner-only file `~/.permaura/vault-kek`. This is what a plain `curl … | sh` or headless install gets, so those get real at-rest custody rather than a shared constant.
4. **Fail closed.** A real gateway that reaches the end of the ladder refuses to start rather than sealing under the public dev constant. `PERMAURA_ALLOW_INSECURE_VAULT=1` opts into starting with no meaningful at-rest encryption, for a throwaway install only.

`PERMAURA_VAULT_PASSPHRASE`, the old inline variable, no longer hands anything over. A gateway that finds it set says so on boot and ignores it, because anything running as this user could read it out of the process environment and every child inherited it. If you still set it, move the value to one of the two routes above before upgrading: a gateway that ignores it resolves a different key, and a vault sealed under the inline value will not open.

Step 4 is deliberate. A gateway that starts, reports itself healthy, and seals a customer's credentials under a constant published in a public repository is worse than one that will not start.

## 3. Verify it is enforcing

Health is public. Everything else is not:

```bash
curl -s http://127.0.0.1:7376/health
```

```json
{"service":"permaura-gateway","status":"ok"}
```

An authenticated call adds the counts, the version and `audit_chain_intact`.

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7376/v1/agents          # 401, no token
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example.com' http://127.0.0.1:7376/v1/agents   # 421 host not allowed
```

The `401` is the operator plane refusing an unauthenticated caller. The `421` is the Host allowlist refusing a DNS-rebinding probe: on every path but `/health` (which tells a rebound page only that something is listening), the gateway answers only hosts it recognizes (its own bind address, plus `PERMAURA_PUBLIC_URL` / `PERMAURA_ALLOWED_HOSTS` when set). An Origin allowlist alone cannot stop rebinding, because a rebound page keeps its own Origin and targets loopback by IP.

Authenticated calls use the operator token:

```bash
curl -s -H @<(printf 'Authorization: Bearer %s\n' "$(cat ~/.permaura/operator.token)") \
  http://127.0.0.1:7376/v1/agents
```

The header comes from a process substitution so the token is never in curl's arguments, where every local user can read it. That needs bash or zsh; a POSIX `sh` does not know `<(…)`.

Or let the CLI find it for you (`permaura` reads `~/.permaura/operator.token` by default):

```bash
permaura status
```

## 4. The flags that change posture

Transport posture (real, mock or demo) is chosen by CLI flag, never by environment variable, so a transport is never silently canned for an end user. You opt *out* of real, you do not opt in.

| Flag | Effect |
| --- | --- |
| *(none)* | Real HTTP, real command execution, real SSH. The default. |
| `--mock` | Deterministic mock transports for HTTP, commands and SSH, so capabilities make no upstream call and run nothing. The gateway still reads `config.toml` and can start its tunnel or relay; `--demo` or `PERMAURA_STORE_PATH=:memory:` does neither. For local exploration and CI. |
| `--demo` | A throwaway in-memory gateway carrying the seeded demo estate, with mock transports. Its operator bearer is a published constant, so never put one on a network. |

Bind address is `--addr` (or `PERMAURA_ADDR`), defaulting to `127.0.0.1:7376`.

Stopping is a drain. `permaura stop` (which sends `POST /v1/shutdown`), `SIGTERM` and Ctrl-C all stop the gateway admitting new calls, give the calls already running up to 8 seconds to finish and record how they ended, then exit. A call approved by a human that is still running when the gateway is killed outright (a crash, `SIGKILL`, a reboot) is never run again: the next start records it as interrupted with an unknown outcome, and the approval shows as unresolved.

## 5. What the operator plane will not do remotely

Three operator-plane actions need the operator token and, on a self-run gateway, a caller on the gateway's own host: they are refused for any non-loopback peer, any Cloudflare-tunnelled request, and anything carrying forwarding headers. On a hosted gateway, opening a session and shutting down are refused outright, and pairing or lowering the floor needs the owner's OAuth session plus a single-use step-up ticket from a fresh sign-in:

- `POST /v1/sessions` (opening a session)
- `POST /v1/shutdown` (graceful stop)
- approver-key pairing and lowering the approval floor

This is by design: a copied operator token alone should not be enough to open sessions, stop the gateway, trust a new approver key or reopen bearer approvals from off the host. Manage a remote gateway either on the box itself, or through permaura.com's broker. See [architecture.md](./architecture.md) for the execution modes.

## Where to go next

**In this repository:**

- [architecture.md](./architecture.md): the local core, the control plane, the hosted worker, the enforcement loop, the three execution modes.
- [policy-language.md](./policy-language.md): principals, resources, actions, conditions, risk tiers, decisions.
- [data-model.md](./data-model.md): the tables and the hash-chained audit chain.
- [connector-authoring.md](./connector-authoring.md): writing your own capabilities.
- [threat-model.md](./threat-model.md): what Permaura defends against, and what it does not.
- [platforms.md](./platforms.md): supported targets and where `~/.permaura` lives per platform.
- [`examples/`](../examples): illustrative connector sketches (the gateway does not load them).

**Using the product:** [permaura.com/docs](https://permaura.com/docs) covers connecting a gateway to the console, creating connections, granting agents, approvals, and remote access, with screenshots and the current UI.
