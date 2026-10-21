# Permaura documentation

> **Give agents permission, not keys.**

Permaura is a local-first, remote-capable permission layer for AI agents. It sits between an agent (Claude Code, Codex CLI, Cursor, Claude Desktop, a remote MCP client) and the real systems and credentials that agent wants to touch. The agent calls a *capability*; Permaura checks *policy*, injects the real secret server-side, performs the action, and returns only the *result*. The secret never reaches the model, the prompt context, the terminal history, the logs, or the agent process.

There is one product binary, `permaura` (the workspace also builds `permad`, a demo-only binary over a seeded in-memory estate): `permaura start` is the enforcement runtime you run, and every other subcommand is the control surface that talks to it. The fixed MCP tools are named `permaura_*`. The Rust crates are `permaura-core`, `permaura-policy`, `permaura-connectors`, `permaura-credential-store`, `permaura-platform`, `permaura-relay`, `permaura-daemon`, and the gateway crate `permaura-gateway`, which builds the binary. The npm scope is `@permaura/*`, except the launcher itself, which is the bare `permaura` package.

## The one idea

Never give the agent a credential when you can give it a capability. Deny by default. Separate intent from execution. Risk-tier every action. Audit every policy decision and every execution. The model never receives raw secrets.

```text
Agent asks to do something
        ↓
Permaura checks policy
        ↓
Permaura performs the API call (with the real secret, server-side) or denies it
        ↓
Agent receives the redacted result, never the raw secret
```

## Documentation map

Start with **getting-started** if you want to run something, **architecture** if you want to understand the system, and **policy-language** if you want to write rules. For using the product rather than running the engine, see [permaura.com/docs](https://permaura.com/docs).

| Document | What it covers |
| --- | --- |
| [getting-started.md](./getting-started.md) | Build or install `permaura`, start it, and verify it is enforcing. What a first run writes to `~/.permaura`, where the vault key comes from, and the `--mock` / `--demo` flags. |
| [platforms.md](./platforms.md) | Supported OS/arch targets, where `~/.permaura` lives per platform (`%USERPROFILE%` on Windows) and the `PERMAURA_HOME` override, Windows command-connector rules, and WSL guidance. |
| [architecture.md](./architecture.md) | The local core, the control plane, the hosted worker, the enforcement loop, and a components diagram. The three execution modes. |
| [mcp-integration.md](./mcp-integration.md) | Step-by-step config for adding Permaura as an MCP server to Claude Code, Codex CLI, Cursor, and Claude Desktop: STDIO via `@permaura/mcp-stdio` and remote streamable HTTP with bearer/OAuth. Real config JSON. |
| [policy-language.md](./policy-language.md) | Principals, resources, actions, conditions, risk tiers, decisions, example grants, deny-by-default, and the Cedar future path. |
| [connector-authoring.md](./connector-authoring.md) | `defineConnector` in TypeScript and Python: capability ids, risk, `requiresApproval`, redaction, input schemas. |
| [data-model.md](./data-model.md) | The tables, the `secrets` / `secret_versions` / `secret_metadata` split, the hash-chained audit chain. |
| [security.md](./security.md) | Envelope encryption, Argon2id, AES-256-GCM, ed25519 hash-chained audit, vault key custody per platform, approval trust state, redaction, deny-by-default, and the boundaries not claimed. |
| [threat-model.md](./threat-model.md) | What Permaura defends against, the trust boundaries, and what it cannot prevent. |

## Examples

The [`examples/`](../examples) directory holds illustrative connector sketches written against the SDK's `defineConnector`; the gateway does not load them, so they show the shape of a capability rather than something you can run against it:

- [`examples/github`](../examples/github): a `defineConnector` TypeScript example for guarded GitHub PR creation.
- [`examples/braintree-generic-http`](../examples/braintree-generic-http): a generic-HTTP connector template for Braintree `transactions.search` / `transactions.refund`, showing risk tiers, approval, and redaction.
- [`examples/stripe`](../examples/stripe): a read-only Stripe capability example.
- [`examples/openapi-import`](../examples/openapi-import): how an OpenAPI spec maps to capabilities, with a sample spec snippet.

## The MCP tool surface

Permaura exposes a small, stable set of fixed MCP tools, plus one tool per capability the agent can reach:

```text
permaura_list_capabilities    What can I do in this session?
permaura_enroll               Redeem a one-time enrollment code.
permaura_request_grant        Get guidance on asking the operator for a grant (it grants nothing).
permaura_invoke               Run a named capability with parameters.
permaura_http_request         Run a guarded generic HTTP request (only where the gateway offers it).
permaura_get_approval_status  Poll a pending approval.
permaura_explain_denial       Ask why an action was denied.
permaura_revoke_session       Revoke the current session's token.
```

There is deliberately no `permaura_get_secret`, no `permaura_get_api_key`, and no `permaura_export_token`. Those tools do not exist, which is what makes the secret-export class of prompt-injection attacks fail by construction.
