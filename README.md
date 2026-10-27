# Permaura

> **Give agents permission, not keys.**

Permaura is a permission layer for AI agents. An agent asks it to do something, Permaura checks
policy, and if the call is allowed it makes the upstream request itself, with the real credential
injected on the gateway's side, and hands back the redacted result. The agent never holds the
secret.

This repository is the Permaura gateway: the `permaura` binary you run on your own machine, with
its policy engine, sealed vault, redaction, signed audit log and connectors, plus the TypeScript and
Python SDKs and the MCP stdio bridge that agent clients register. It runs standalone, with no
account. [LICENSING.md](LICENSING.md) says what is here and what is not.

## The enforcement loop

```
agent calls a capability ── MCP/HTTP ──▶ gateway
  identify session → policy check → Decision
    Deny             → 403 and the reason
    RequiresApproval → 202 and a pending approval that a person resolves
    Allow            → open the sealed secret, call upstream, redact, append to the audit log
agent receives the result, never the raw secret
```

Policy is deny by default. There is deliberately no `get_secret` tool: no route returns a stored
secret, which is opened only to make an upstream call or to re-seal it into a vault export the
operator asked for and protects with their own passphrase. The audit log is hash-chained and
Ed25519-signed, so editing or removing an event inside the chain is detected; removing events from
the end is not, and on a self-run gateway whoever can write the database can usually read the
signing key beside it. [The threat model](docs/threat-model.md) is specific about what that does
and does not cover.

## Try it

```bash
npx permaura start
```

Or install it, on macOS or Linux:

```bash
curl -fsSL https://permaura.com/install | sh
permaura start
```

The gateway listens on `127.0.0.1:7376` and keeps its state in `~/.permaura/gateway.db`. Bare
`permaura` prints the help and starts nothing: starting a gateway is always `permaura start`. To
look around without touching anything real, `permaura start --demo` runs an in-memory gateway with a
seeded demo estate and mock transports.

## Build from source

You need stable Rust (1.88 or newer). The TypeScript packages need Node 20 and pnpm.

```bash
cargo build --release -p permaura-gateway             # target/release/permaura
cargo run --release -p permaura-gateway -- start      # a gateway on 127.0.0.1:7376
curl -s http://127.0.0.1:7376/health

cargo test --workspace                                # offline: no network, no live credentials
```

Run a gateway you rely on from a release build. A debug build (`cargo run` without `--release`, or
`make gateway`) is for working on Permaura itself: it also trusts the development connector-signing
keys, so a manifest signed with them installs as Permaura-signed, it takes the release key, the
release manifest, the account API and the control plane from the environment where a release build
keeps its pinned ones except for loopback overrides for the account API and control plane.
`PERMAURA_DEV=1` seals secrets under the public development key.

Upstream calls are real by default. `permaura start --mock` swaps in deterministic mock transports
for HTTP, command execution and SSH, and `PERMAURA_STORE_PATH=:memory:` gives a throwaway gateway
that keeps no store and, like `--demo`, takes nothing from `config.toml` and starts no tunnel, relay
or pairing. Both still read this home's vault key, and create one if the home has none.

MCP clients register the stdio bridge in `packages/mcp-stdio`. To build it from source:

```bash
pnpm install && pnpm --filter @permaura/mcp-stdio build   # packages/mcp-stdio/dist/cli.js
```

[RUNBOOK.md](RUNBOOK.md) walks through the whole loop with Claude Code, Codex and Cursor: adding a
secret and a grant, an allowed call, an approval and a denied one.

## Layout

```
services/gateway/              the permaura binary: the axum enforcement service (REST /v1 and
                               MCP /mcp) and the operator CLI that drives it
crates/
  permaura-core/               envelope crypto (Argon2id, AES-GCM, ChaCha20), the vault, the
                               signed audit chain, redaction, domain types
  permaura-policy/             the deny-by-default policy engine: Allow, Deny or RequiresApproval
  permaura-connectors/         the HTTP, command and SSH seams and the built-in connectors
  permaura-credential-store/   keeps a secret in the OS credential store, or an owner-only file
                               where there is no usable one
  permaura-platform/           the small audited OS boundary for private files
  permaura-relay/              signature verification and the wire format for device approvals
  permaura-daemon/             permad, a demo binary: the gateway router over a seeded in-memory
                               estate with mock transports and the published demo bearer
packages/
  gateway/                     the npm launcher, published as `permaura`
  mcp-stdio/                   the stdio bridge MCP clients register
  sdk/, sdk-python/            the TypeScript and Python SDKs
  types/, ui/                  shared TypeScript types and UI primitives
docs/                          architecture, data model, policy language, connector authoring,
                               security and the threat model
examples/                      connector examples: GitHub, Braintree, Stripe, OpenAPI import
scripts/                       connector-signing ceremony tools and build checks
```

Start with [docs/architecture.md](docs/architecture.md) for how the pieces fit, and
[docs/threat-model.md](docs/threat-model.md) for what this does and does not defend against.

## License

The code is licensed under the [Apache License, Version 2.0](LICENSE). The hosted service, the web
console and the desktop and mobile apps are proprietary and live elsewhere, and none of them is
needed to run the gateway. The name and logo are not covered by the code license: see
[TRADEMARK.md](TRADEMARK.md).

## Security and contributing

Please report a vulnerability privately, by email to security@permaura.com, and never in a public
issue or discussion: [SECURITY.md](SECURITY.md) has the process. Questions, ideas and talk about how
you use Permaura go in [GitHub Discussions](https://github.com/permaura/permaura/discussions). Bug
reports, reproductions and design arguments are welcome as
[issues](https://github.com/permaura/permaura/issues). Pull requests are closed for now, and
[CONTRIBUTING.md](CONTRIBUTING.md) explains why and what helps instead.
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) is short.

Permaura™ is a trademark of Pixelite SL.
