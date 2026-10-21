# @permaura/mcp-stdio

A local **STDIO MCP server** that bridges the `permaura_*` tools to a [Permaura](https://permaura.com) gateway. Add it to Claude Code, Codex, or Cursor and the agent gains scoped, audited capabilities: it never sees a raw secret.

```
agent  ──stdio──▶  permaura-mcp  ──http──▶  Permaura gateway  ──▶  upstream API
                   (this package)          (policy, secret            (real call)
                                            injection, audit)
```

## What it exposes

Whatever the gateway's own tool list says: the fixed tools below, plus one tool per capability this agent can reach (for example `fal.image.generate`). When the gateway cannot be reached the bridge advertises only the fixed tools.

| Tool | Purpose |
| --- | --- |
| `permaura_list_capabilities` | Discover what the session may do |
| `permaura_enroll` | Redeem a one-time enrollment code (in the gateway's own list only) |
| `permaura_request_grant` | Returns how to ask the operator for access (nothing is recorded; a human makes the grant) |
| `permaura_invoke` | Call a capability; secret injected server-side, result redacted |
| `permaura_http_request` | Generic HTTP request, still policy-checked (only where the gateway offers it) |
| `permaura_get_approval_status` | Poll a pending approval |
| `permaura_explain_denial` | Get the reason a call was denied |
| `permaura_revoke_session` | Revoke the session's token (the agent's grants stay) |

There is **no** `get_secret` / `get_api_key` / `export_token`. By design.

## Install

```bash
npm install -g @permaura/mcp-stdio
# or run on demand
npx -y @permaura/mcp-stdio
```

The binary is `permaura-mcp`. It bridges to `http://127.0.0.1:7376` by default. Node 20 or later.

## The agent's token

Each agent gets its own token, and it is never the operator token.

1. In the console, open **Agents → Connect agent** and copy the one-time code (`ENRL-…`). On a gateway that is not connected to the console, mint one on the gateway's own machine, into a file only you can read: `permaura agent enroll --label claude-code --out ~/.permaura/claude-code.token`.
2. Put that file's path in `PERMAURA_AGENT_TOKEN_FILE` in the MCP server's config (below), or the code itself in `PERMAURA_AGENT_TOKEN`. The code is single-use and lives 15 minutes; the agent's first call redeems it, and from then on the same value is that agent's own token.
3. Approve the agent on the console's **Agents** page, then grant it what it needs. Until then the gateway refuses its tool calls.

**Never configure an agent with the operator token** (`~/.permaura/operator.token`, which the launcher never prints, or `PERMAURA_TOKEN`). It administers the gateway: on the gateway's own machine it creates grants and changes policy immediately, so an agent holding it can give itself any access the gateway can grant. The bridge ignores `PERMAURA_TOKEN` for that reason, so a shell that exports it for the `permaura` CLI does not hand it to an agent started from that shell.

### Configuration

| Env | Flag | Default |
| --- | --- | --- |
| `PERMAURA_GATEWAY_URL` | `--url` | `http://127.0.0.1:7376` |
| `PERMAURA_AGENT_TOKEN` | `--token` | _(none)_ |
| `PERMAURA_AGENT_TOKEN_FILE` | `--token-file` | _(none)_; a leading `~/` is your home. `--token-file` outranks `PERMAURA_AGENT_TOKEN`, and the variable form is read only when `PERMAURA_AGENT_TOKEN` is unset. The bridge warns when the file is readable by others or not a regular file, and will not start when a named file cannot be read |
| `PERMAURA_MCP_MAX_MESSAGE_BYTES` | _(none)_ | `10485760` |

A JSON-RPC line longer than `PERMAURA_MCP_MAX_MESSAGE_BYTES` is discarded with one note on stderr and the bridge keeps serving, rather than closing its transport the way the SDK's default does. Only the host that spawned the bridge can write to its stdin, and the gateway's own body limit on `/mcp` (2 MiB by default) is lower, so nothing the gateway would accept is cut here.

Use the file or the environment variable for the token. A `--token` flag stays readable in the process list, by any local user, for as long as the bridge runs, and the bridge says so on stderr.

Logs go to **stderr**; stdout is reserved for the MCP protocol stream.

## Register with an agent

### Claude Code

```bash
claude mcp add permaura -e PERMAURA_AGENT_TOKEN_FILE=~/.permaura/claude-code.token -- npx -y @permaura/mcp-stdio
```

Or in a project's `.mcp.json` (keep a file that holds a token out of version control):

```json
{
  "mcpServers": {
    "permaura": {
      "command": "npx",
      "args": ["-y", "@permaura/mcp-stdio"],
      "env": {
        "PERMAURA_GATEWAY_URL": "http://127.0.0.1:7376",
        "PERMAURA_AGENT_TOKEN": "ENRL-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
      }
    }
  }
}
```

### Codex

In `~/.codex/config.toml`:

```toml
[mcp_servers.permaura]
command = "npx"
args = ["-y", "@permaura/mcp-stdio"]

[mcp_servers.permaura.env]
PERMAURA_GATEWAY_URL = "http://127.0.0.1:7376"
PERMAURA_AGENT_TOKEN = "ENRL-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
```

### Cursor

In `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project):

```json
{
  "mcpServers": {
    "permaura": {
      "command": "npx",
      "args": ["-y", "@permaura/mcp-stdio"],
      "env": {
        "PERMAURA_GATEWAY_URL": "http://127.0.0.1:7376",
        "PERMAURA_AGENT_TOKEN": "ENRL-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
      }
    }
  }
}
```

## The token is sent only after the listener proves it holds it

Before every request that carries the agent's token to a gateway on this machine, the bridge asks `/health` for a proof that the listener stores that token, sending a fresh challenge and a one-way key that names the token without revealing it. Only a process holding the gateway's store can answer: the gateway itself, or a copy of its data. So another account that binds the gateway's port while it is down is sent nothing, and the call fails saying so. The bridge tells the causes apart: a current gateway that no longer holds the token (enrol the agent again), a proof that does not match (another program or another gateway), and no proof at all (a gateway older than 1.3.56, which cannot give it: upgrade it with `permaura upgrade`, or another program). It writes the outcome to stderr when it starts.

The proof and the request travel on two connections, so a program that took the port in the instant between them, as the gateway exited, would receive the token. That is the same bound the `permaura` CLI's own proof has.

## Calls are never sent twice

Every `tools/call` goes to the gateway's `POST /mcp`. Only a 404 from `/mcp` (a gateway without that endpoint, which ran nothing) sends the call to the typed `/v1` REST surface instead. `permaura_explain_denial` is never sent there, and neither are `permaura_request_grant` and `permaura_revoke_session`, whose REST routes are the operator's. If a call times out (150 seconds, above the gateway's own 120), the connection drops, or the gateway answers 5xx, the bridge does not retry: the gateway may still be running it, so the agent is told the outcome is unknown and to check the activity log first.

All policy enforcement, secret injection, redaction, and audit happen in the gateway. This bridge is a transport adapter and holds no secrets.

## Programmatic use

```ts
import { startStdioBridge } from "@permaura/mcp-stdio";

await startStdioBridge({ baseUrl: "http://127.0.0.1:7376", token: process.env.PERMAURA_AGENT_TOKEN });
```

## Build

```bash
pnpm build      # tsup -> dist (index + cli, esm + .d.ts)
pnpm typecheck  # tsc --noEmit
pnpm test       # build, then node --test
```
