#!/usr/bin/env node
/**
 * `permaura-mcp`: the STDIO MCP server an agent registers locally. It reads config from the environment and a couple of flags, then bridges the `permaura_*` tools to the local Permaura gateway.
 *
 * Everything written to stdout is reserved for the MCP JSON-RPC stream; logs go to stderr so they never corrupt the protocol.
 *
 * Env / flags:
 *   PERMAURA_GATEWAY_URL  (or --url)    default http://127.0.0.1:7376
 *   PERMAURA_AGENT_TOKEN  (or --token)  this agent's own bearer token
 *   PERMAURA_AGENT_TOKEN_FILE (or --token-file) a file holding it; --token-file outranks PERMAURA_AGENT_TOKEN
 *   PERMAURA_MCP_MAX_MESSAGE_BYTES       longest JSON-RPC line accepted on stdin (default 10 MiB)
 */
import { startStdioBridge, SERVER_INFO } from "./server.js";
import { DEFAULT_GATEWAY_URL, GatewayClient } from "./gateway.js";
import { maxMessageBytesFromEnv } from "./transport.js";
import { resolveAgentToken } from "./token.js";

const HELP = `permaura-mcp: local STDIO MCP server for Permaura (give agents permission, not keys).

Bridges the permaura_* tools to your Permaura gateway over stdio. Register it with
Claude Code / Codex / Cursor; the agent calls capabilities through Permaura and never
sees a raw secret. stdout carries the MCP JSON-RPC stream; all logs go to stderr.

Usage:
  permaura-mcp [options]

Options:
  -u, --url <url>      Gateway base URL    (env PERMAURA_GATEWAY_URL, default ${DEFAULT_GATEWAY_URL})
  -t, --token <token>  This agent's token  (env PERMAURA_AGENT_TOKEN). Prefer the file or the
                       variable: a flag stays readable in the process list for as long as the
                       bridge runs.
      --token-file <path>
                       A file holding this agent's token (env PERMAURA_AGENT_TOKEN_FILE). The flag
                       outranks PERMAURA_AGENT_TOKEN; the variable is read only when it is unset.
                       Only the path is in any config or command line.
  -h, --help           Print this help and exit
  -v, --version        Print the version and exit

Environment:
  PERMAURA_GATEWAY_URL   Gateway base URL (overridden by --url)
  PERMAURA_AGENT_TOKEN   This agent's own token (overridden by --token)
  PERMAURA_AGENT_TOKEN_FILE
                         A file holding it, read when PERMAURA_AGENT_TOKEN is unset; a leading ~/
                         is your home directory. It should be readable by you alone.
  PERMAURA_MCP_MAX_MESSAGE_BYTES
                         Longest JSON-RPC line accepted on stdin, in bytes (default 10485760).
                         A longer line is discarded with a note on stderr; the bridge keeps running.

The agent's token is the one-time code from the console's Agents page (Connect agent),
or from \`permaura agent enroll\` on the gateway's machine: once redeemed it is that
agent's own token. Never use the operator token (~/.permaura/operator.token, the token
the permaura CLI reads from PERMAURA_TOKEN). It administers the gateway, and an agent
holding it can grant itself access. This bridge ignores PERMAURA_TOKEN.

Example (Claude Code), with the code in a file only you can read:
  permaura agent enroll --label claude-code --out ~/.permaura/claude-code.token
  claude mcp add permaura -e PERMAURA_AGENT_TOKEN_FILE=~/.permaura/claude-code.token -- npx -y @permaura/mcp-stdio
`;

function parseArgs(argv: string[]): { url?: string; token?: string; tokenFile?: string; help?: boolean; version?: boolean } {
  const out: { url?: string; token?: string; tokenFile?: string; help?: boolean; version?: boolean } = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      out.help = true;
    } else if (arg === "--version" || arg === "-v") {
      out.version = true;
    } else if (arg === "--url" || arg === "-u") {
      out.url = argv[++i];
    } else if (arg === "--token" || arg === "-t") {
      out.token = argv[++i];
    } else if (arg === "--token-file") {
      out.tokenFile = argv[++i];
    } else if (arg?.startsWith("--token-file=")) {
      out.tokenFile = arg.slice("--token-file=".length);
    } else if (arg?.startsWith("--url=")) {
      out.url = arg.slice("--url=".length);
    } else if (arg?.startsWith("--token=")) {
      out.token = arg.slice("--token=".length);
    }
  }
  return out;
}

async function main(): Promise<void> {
  const flags = parseArgs(process.argv.slice(2));

  // Help and version are handled before any transport is opened, and print to stdout so
  // `permaura-mcp --help | …` works the way a human expects. They never start the bridge.
  if (flags.help) {
    process.stdout.write(HELP);
    return;
  }
  if (flags.version) {
    process.stdout.write(`${SERVER_INFO.name} ${SERVER_INFO.version}\n`);
    return;
  }

  const baseUrl = flags.url ?? process.env.PERMAURA_GATEWAY_URL ?? undefined;
  // PERMAURA_TOKEN is deliberately not read: it is where the permaura CLI looks for the operator
  // token, and an agent's MCP server usually inherits the environment of the shell that started it.
  const { token, note, fatal } = resolveAgentToken({ flag: flags.token, fileFlag: flags.tokenFile, env: process.env });
  if (note) process.stderr.write(`[permaura-mcp] ${note}\n`);
  if (fatal) {
    // Named and unusable: starting tokenless would only answer every call with a 401.
    process.stderr.write(`[permaura-mcp] ${fatal}\n`);
    process.exit(2);
  }

  await startStdioBridge({ baseUrl, token, maxMessageBytes: maxMessageBytesFromEnv() });
  // After the transport is up, so a listener slow to answer the proof never delays the client's handshake.
  if (token) {
    void new GatewayClient({ baseUrl, token })
      .checkGateway()
      .then((refusal) => refusal && process.stderr.write(`[permaura-mcp] ${refusal}\n`))
      .catch(() => {});
  }
  // Log to stderr only: stdout is the MCP transport.
  process.stderr.write(`[permaura-mcp] bridging to ${baseUrl ?? DEFAULT_GATEWAY_URL} over stdio\n`);
  if (!token) {
    process.stderr.write(
      process.env.PERMAURA_TOKEN
        ? "[permaura-mcp] PERMAURA_TOKEN is set but ignored: it holds the operator token. Give this agent its own token in PERMAURA_AGENT_TOKEN.\n"
        : "[permaura-mcp] no PERMAURA_AGENT_TOKEN: the gateway refuses tool calls until this agent has its own token.\n",
    );
  }
}

main().catch((err) => {
  process.stderr.write(`[permaura-mcp] fatal: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
