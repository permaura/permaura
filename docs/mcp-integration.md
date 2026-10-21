# MCP integration

Permaura is an MCP server. Agents talk to it the same way they talk to any other Model Context Protocol server, except the tools it exposes are *capabilities*, not raw credentials. This document shows how to register Permaura with Claude Code, Codex CLI, Cursor, and Claude Desktop, both ways Permaura can be reached:

- **Local STDIO** via the `@permaura/mcp-stdio` package, which bridges MCP over stdin/stdout to the `permaura` gateway on this machine. Best for local-first, single-machine use. Secrets stay on this machine.
- **Remote streamable HTTP** with bearer or OAuth auth, pointing at a Permaura gateway (cloud or self-hosted). Best for remote agents, teams, and CI.

Both expose the same tool surface: these fixed tools, including `permaura_enroll` (which redeems an enrollment code), plus one tool per capability the agent can reach (for example `fal.image.generate`). `permaura_http_request` appears only on a gateway that offers the generic HTTP capability.

```text
permaura_list_capabilities
permaura_enroll
permaura_request_grant
permaura_invoke
permaura_http_request
permaura_get_approval_status
permaura_explain_denial
permaura_revoke_session
```

There is no `get_secret` / `get_api_key` / `export_token`. By design.

## Prerequisites

For STDIO mode the gateway must be running on this machine (`permaura start`, or `npx -y permaura start`). See [getting-started.md](./getting-started.md) for the full first-run walkthrough. `@permaura/mcp-stdio` is run with `npx` in the snippets below, so there is nothing to install globally.

For remote HTTP mode you need the gateway's MCP URL. Clients that can open a browser sign in with OAuth and need no token; everything else needs the agent's own token, below.

### The agent's own token

Every agent gets a token of its own, from a one-time enrollment code:

1. In the console, open **Agents → Connect agent** and copy the code (`ENRL-…`). On a gateway that is not connected to the console, mint one on the gateway's own machine, into a file only you can read:

   ```bash
   permaura agent enroll --label claude-code --out ~/.permaura/claude-code.token
   ```

2. Configure the agent with the code as its bearer: for the STDIO bridge, the file's path in `PERMAURA_AGENT_TOKEN_FILE` (or the code itself in `PERMAURA_AGENT_TOKEN`), or the `Authorization` header for remote HTTP. The code is single-use and lives 15 minutes; the agent's first call redeems it, and from then on the same value is that agent's own token.
3. The agent arrives **Pending**. Approve it on the console's **Agents** page (or `permaura agent approve <id>` on the gateway's machine), then grant it what it needs. Its tool calls are refused until then.

**Never configure an agent with the operator token.** That is `~/.permaura/operator.token` (which the launcher never prints), and what the `permaura` CLI reads from `PERMAURA_TOKEN`. It administers the gateway: on the gateway's own machine it creates grants and changes policy immediately, so an agent holding it can give itself any access the gateway can grant. The STDIO bridge ignores `PERMAURA_TOKEN` so that a shell exporting it for the CLI does not pass it to an agent started from that shell.

---

## Claude Code

Claude Code reads MCP servers from `.mcp.json` at the project root (shared, committed) or from your user config. Use the `permaura` CLI helper or edit the file directly.

### STDIO (local-first)

```bash
claude mcp add permaura -e PERMAURA_AGENT_TOKEN_FILE=~/.permaura/claude-code.token -- npx -y @permaura/mcp-stdio
```

That writes an entry equivalent to this `.mcp.json`:

```json
{
  "mcpServers": {
    "permaura": {
      "command": "npx",
      "args": ["-y", "@permaura/mcp-stdio"],
      "env": {
        "PERMAURA_GATEWAY_URL": "http://127.0.0.1:7376",
        "PERMAURA_AGENT_TOKEN_FILE": "~/.permaura/claude-code.token"
      }
    }
  }
}
```

`PERMAURA_GATEWAY_URL` is the gateway the bridge talks to (this is the default); `PERMAURA_AGENT_TOKEN_FILE` names the file holding this agent's own token, so the config holds only a path (`PERMAURA_AGENT_TOKEN` takes the token itself; keep a `.mcp.json` that holds one out of version control). Use the environment variable rather than the bridge's `--token` flag, which stays readable in the process list for as long as the bridge runs.

### Remote streamable HTTP (bearer)

```json
{
  "mcpServers": {
    "permaura": {
      "type": "http",
      "url": "https://g-xxxx.permaura.com/mcp",
      "headers": {
        "Authorization": "Bearer ${PERMAURA_AGENT_TOKEN}"
      }
    }
  }
}
```

Set `PERMAURA_AGENT_TOKEN` in your environment so the token is not committed. Claude Code expands `${VAR}` from the environment when it reads `.mcp.json`.

### Remote with OAuth

For OAuth, omit the static header and let Claude Code run the authorization flow against the gateway's well-known OAuth metadata:

```json
{
  "mcpServers": {
    "permaura": {
      "type": "http",
      "url": "https://g-xxxx.permaura.com/mcp"
    }
  }
}
```

On first use Claude Code discovers the gateway's OAuth endpoints, opens a browser for consent, and stores the resulting token. The gateway advertises two scopes, `mcp` and `offline_access`; what the agent may then do is decided by its grants, not by the OAuth scope.

---

## Codex CLI

Codex configures MCP servers in `~/.codex/config.toml`. It supports both local STDIO servers and remote streamable HTTP servers with bearer or OAuth auth.

### STDIO (local-first)

```toml
[mcp_servers.permaura]
command = "npx"
args = ["-y", "@permaura/mcp-stdio"]

[mcp_servers.permaura.env]
PERMAURA_GATEWAY_URL = "http://127.0.0.1:7376"
PERMAURA_AGENT_TOKEN = "ENRL-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
```

### Remote streamable HTTP (bearer)

```toml
[mcp_servers.permaura]
url = "https://g-xxxx.permaura.com/mcp"

[mcp_servers.permaura.http_headers]
Authorization = "Bearer ${PERMAURA_AGENT_TOKEN}"
```

### Remote with OAuth

```toml
[mcp_servers.permaura]
url = "https://g-xxxx.permaura.com/mcp"
auth = "oauth"
```

Codex runs the OAuth flow on first connect and caches the token; subsequent calls reuse it until it expires.

---

## Cursor

Cursor reads MCP servers from `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project). The schema matches Claude Code's.

### STDIO (local-first)

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

### Remote streamable HTTP (bearer)

```json
{
  "mcpServers": {
    "permaura": {
      "url": "https://g-xxxx.permaura.com/mcp",
      "headers": {
        "Authorization": "Bearer ${PERMAURA_AGENT_TOKEN}"
      }
    }
  }
}
```

Give each client its own code from **Connect agent** rather than sharing one token, so the audit log attributes calls to the right agent.

---

## Claude Desktop

Claude Desktop reads `claude_desktop_config.json`. On macOS it lives at `~/Library/Application Support/Claude/claude_desktop_config.json`.

### STDIO (local-first)

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

Restart Claude Desktop after editing the file. The Permaura tools then appear in the tool list.

### Remote streamable HTTP

Claude Desktop's remote MCP support uses the same streamable HTTP transport. Point it at the gateway and supply a bearer token or run the OAuth flow:

```json
{
  "mcpServers": {
    "permaura": {
      "type": "http",
      "url": "https://g-xxxx.permaura.com/mcp",
      "headers": {
        "Authorization": "Bearer ${PERMAURA_AGENT_TOKEN}"
      }
    }
  }
}
```

---

## Verifying the connection

Once registered, ask the agent to list its capabilities. Under the hood the client calls:

```json
{
  "tool": "permaura_list_capabilities",
  "arguments": {}
}
```

A healthy response looks like:

```json
{
  "capabilities": [
    { "id": "braintree.transactions.search", "description": "Search Braintree transactions", "risk": "medium" },
    { "id": "github.pull_requests.create",    "description": "Create pull requests",          "risk": "high" }
  ]
}
```

If the list is empty, no active grant covers this agent, or it is still Pending. Approve it, then create a grant with `permaura grant --agent <id> --resource <resource> --allow <action>` or have the agent call `permaura_request_grant`. If the connection fails entirely, confirm the gateway is running (`permaura status`) for STDIO, or that the token is valid and unexpired for HTTP.

## A first guarded invoke

```json
{
  "tool": "permaura_invoke",
  "arguments": {
    "capability": "braintree.transactions.search",
    "params": { "status": "failed", "date": "2026-06-21" },
    "reason": "User asked me to summarize yesterday's failed payments."
  }
}
```

Permaura checks policy, runs the call with the injected secret, redacts the response, returns structured results, and writes an audit event, and the API key never appears anywhere the agent can see.

## STDIO vs remote: choosing a transport

| | STDIO (`@permaura/mcp-stdio`) | Remote HTTP (gateway) |
| --- | --- | --- |
| Where secrets live | In the gateway on the same machine | In the gateway the URL reaches: yours (through a tunnel or your own reverse proxy) or a hosted worker |
| Best for | Single-machine, local-first | Remote agents, teams, CI, always-on |
| Auth | The agent's own token (`PERMAURA_AGENT_TOKEN`) | The agent's own token, or OAuth |
| Requires a local gateway | Yes | No: the gateway the URL points at |
| Approvals | A held call waits for the operator's session or a paired device's signature | The same |

Many users run both: STDIO for local coding agents, and the remote gateway for a hosted agent or a teammate, pointing at the same policies and the same audit trail.
