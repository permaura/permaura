/**
 * The static `tools/list` advertisement: the seven `permaura_*` tools with their JSON-Schema input. The bridge serves it only when the gateway cannot be reached; a reachable gateway's own list replaces it, so nothing here may promise more than the gateway does. Every argument named here is one the gateway's own tool declares, because the gateway refuses any other, and each tool requires what the gateway's requires. `permaura_list_capabilities` reads no argument, so neither side refuses one.
 *
 * There is intentionally no `get_secret` / `get_api_key` / `export_token`. The agent can request that a capability be invoked; it can never request the credential behind it.
 */

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
}

export const PERMAURA_TOOLS: McpToolDefinition[] = [
  {
    name: "permaura_list_capabilities",
    description:
      "List the capabilities this session may attempt (risk-tiered). Use this first to discover what actions are available before invoking. Returns capability ids like `braintree.transactions.search` with a risk tier and description, never any secret. It takes no arguments and ignores any it is sent.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "permaura_request_grant",
    description:
      "Find out how this agent gets access to a connection's capability. Grants are created by a human in the console (policy to agent), so this returns guidance and records nothing: it does not self-grant, and the operator is not notified.",
    inputSchema: {
      type: "object",
      properties: {
        connection: { type: "string", description: "The connection you need, e.g. `braintree_production`." },
        capabilities: {
          type: "array",
          items: { type: "string" },
          description: "Capability ids you want permitted, e.g. [\"braintree_production.transactions.search\"].",
        },
      },
      required: ["connection"],
      additionalProperties: false,
    },
  },
  {
    name: "permaura_invoke",
    description:
      "Invoke a named capability. Permaura checks policy, injects the real secret server-side, performs the action, and returns only a redacted result. If the action is high-risk it may return a pending approval instead of a result.",
    inputSchema: {
      type: "object",
      properties: {
        capability: { type: "string", description: "Capability id, e.g. `braintree.transactions.search`." },
        params: { type: "object", description: "Capability-specific parameters.", additionalProperties: true },
        reason: { type: "string", description: "Justification recorded on the audit trail and shown on any approval gate." },
      },
      required: ["capability"],
      additionalProperties: false,
    },
  },
  {
    name: "permaura_http_request",
    description:
      "Make a policy-gated generic HTTP request, only where the gateway offers the generic HTTP capability. The secret is injected server-side, so you supply only non-auth headers. The response is redacted before it returns.",
    inputSchema: {
      type: "object",
      properties: {
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] },
        url: { type: "string", description: "Absolute https URL on a host the connection allows; plain http is refused." },
        headers: { type: "object", description: "Non-auth headers only; Permaura injects Authorization itself.", additionalProperties: { type: "string" } },
        body: { description: "JSON body for write methods." },
      },
      required: ["url"],
      additionalProperties: false,
    },
  },
  {
    name: "permaura_get_approval_status",
    description:
      "Poll a pending approval raised by an earlier `permaura_invoke`. Returns the current status (pending/approved/denied/expired/revoked).",
    inputSchema: {
      type: "object",
      properties: {
        approval_id: { type: "string" },
      },
      required: ["approval_id"],
      additionalProperties: false,
    },
  },
  {
    name: "permaura_explain_denial",
    description:
      "Get the reason a capability is denied or held for approval for this session, so you can adjust your approach or ask the user. Use it after a denial, not to test whether an action is allowed: some gateway versions answer it by attempting the call.",
    inputSchema: {
      type: "object",
      properties: {
        capability: { type: "string", description: "Capability id that was denied." },
      },
      required: ["capability"],
      additionalProperties: false,
    },
  },
  {
    name: "permaura_revoke_session",
    description:
      "Tear down the current (or a named) session and immediately invalidate its grants. Use to end access when your task is complete.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: { type: "string", description: "Session to revoke; defaults to the current session." },
      },
      additionalProperties: false,
    },
  },
];

/** The set of tool names this bridge serves, for fast membership checks. */
export const PERMAURA_TOOL_NAMES = new Set(PERMAURA_TOOLS.map((t) => t.name));
