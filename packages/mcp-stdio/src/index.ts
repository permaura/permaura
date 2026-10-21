/**
 * @permaura/mcp-stdio: a local STDIO MCP server that bridges the `permaura_*` tools to the local Permaura gateway. Add it to Claude Code, Codex, or Cursor; the agent then calls capabilities through Permaura instead of holding raw secrets.
 *
 * The package ships a `permaura-mcp` binary (see `./cli.ts`). This entry point exports the programmatic API for embedding the bridge in another host.
 */
export { createBridgeServer, startStdioBridge, SERVER_INFO, type BridgeOptions } from "./server.js";
export { GatewayClient, GatewayError, DEFAULT_GATEWAY_URL, DEFAULT_TIMEOUT_MS, bearerDigest, bearerKey, bearerProof, type GatewayClientOptions, type GatewayToolResult } from "./gateway.js";
export { PERMAURA_TOOLS, PERMAURA_TOOL_NAMES, type McpToolDefinition } from "./tools.js";
export { BoundedStdioServerTransport, DEFAULT_MAX_MESSAGE_BYTES, MAX_MESSAGE_BYTES_ENV, maxMessageBytesFromEnv, type BoundedStdioOptions } from "./transport.js";
export { resolveAgentToken, type TokenSources, type ResolvedToken, type TokenFileStat } from "./token.js";
