import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_GATEWAY_URL, GatewayClient, GatewayError, type GatewayClientOptions } from "./gateway.js";
import { PERMAURA_TOOLS } from "./tools.js";
import { BoundedStdioServerTransport } from "./transport.js";

/** Package identity advertised in the MCP `initialize` handshake. */
export const SERVER_INFO = {
  name: "permaura-mcp",
  version: "0.1.0",
} as const;

export interface BridgeOptions extends GatewayClientOptions {
  /** Longest JSON-RPC line accepted on stdin, in bytes; longer lines are discarded and the bridge keeps serving. */
  maxMessageBytes?: number;
}

/**
 * Build the STDIO MCP server that bridges the `permaura_*` tools to the local gateway.
 *
 * The MCP SDK's `Server` handles `initialize` and the JSON-RPC framing for us; we register two handlers:
 *  - `tools/list` returns the gateway's live tool list, or the static {@link PERMAURA_TOOLS} advertisement when the gateway cannot be reached.
 *  - `tools/call` forwards the name and arguments to the gateway via {@link GatewayClient}, wrapping whatever the gateway returns as MCP tool-result content.
 *
 * The bridge holds no secrets and makes no policy decisions: it is a transport adapter. All enforcement happens in the gateway.
 */
export function createBridgeServer(options: BridgeOptions = {}): {
  server: Server;
  gateway: GatewayClient;
} {
  const gateway = new GatewayClient(options);

  const server = new Server(SERVER_INFO, {
    capabilities: {
      tools: {},
    },
  });

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    // Prefer the gateway's LIVE tool list: the fixed permaura_* tools PLUS a dynamic tool per
    // capability (e.g. fal.image.generate, with its own input schema). Fall back to the static
    // advertisement only if the gateway is unreachable.
    const live = await gateway.listTools();
    return { tools: (live ?? PERMAURA_TOOLS) as typeof PERMAURA_TOOLS };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const { name, arguments: args } = request.params;

    // Forward ANY tool name to the gateway, both the fixed permaura_* tools and the dynamic
    // per-capability tools. The gateway validates the name and enforces policy.
    try {
      const result = await gateway.callTool(name, (args ?? {}) as Record<string, unknown>);
      const text =
        typeof result.data === "string" ? result.data : JSON.stringify(result.data, null, 2);
      return {
        isError: result.isError,
        content: [{ type: "text", text }],
      };
    } catch (err) {
      const text =
        err instanceof GatewayError
          ? err.message
          : `The bridge failed before the call reached the Permaura gateway at ${options.baseUrl ?? DEFAULT_GATEWAY_URL}: ${err instanceof Error ? err.message : String(err)}`;
      return { isError: true, content: [{ type: "text", text }] };
    }
  });

  return { server, gateway };
}

/** Connect the bridge to stdio and start serving. Resolves once the transport is connected. */
export async function startStdioBridge(options: BridgeOptions = {}): Promise<Server> {
  const { server } = createBridgeServer(options);
  const transport = new BoundedStdioServerTransport(process.stdin, process.stdout, { maxMessageBytes: options.maxMessageBytes });
  await server.connect(transport);
  return server;
}
