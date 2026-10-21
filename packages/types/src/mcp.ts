import { z } from "zod";

/**
 * Parameter schemas for seven of the fixed `permaura_*` MCP tools. The gateway also offers `permaura_enroll` and one tool per capability an agent can reach. There is deliberately no `get_secret`, `get_api_key`, or `export_token`: the agent can ask for a *capability* to be invoked, but can never ask for the underlying credential.
 *
 * Each schema is the `arguments` object the agent passes in a `tools/call`, exactly as the gateway's own tool declares it: the gateway refuses any argument a tool does not declare, so every schema here is strict except `permaura_list_capabilities`'s, whose arguments the gateway ignores.
 */

/** `permaura_list_capabilities`: discover what the current session may do. It reads no arguments, and the gateway ignores any it is sent, so this schema strips them rather than refusing. */
export const ListCapabilitiesParamsSchema = z.object({});
export type ListCapabilitiesParams = z.infer<typeof ListCapabilitiesParamsSchema>;

/** `permaura_request_grant`: ask how to get access to a connection's capability. It returns guidance and records nothing; it never self-grants and never returns a secret. */
export const RequestGrantParamsSchema = z
  .object({
    /** The connection the agent needs, e.g. `braintree_production`. */
    connection: z.string(),
    /** Capability ids the agent wants permitted. */
    capabilities: z.array(z.string()).optional(),
  })
  .strict();
export type RequestGrantParams = z.infer<typeof RequestGrantParamsSchema>;

/** `permaura_invoke`: call a named capability. The result returns redacted; the secret stays server-side. */
export const InvokeParamsSchema = z
  .object({
    /** Capability id, e.g. `braintree.transactions.search`. */
    capability: z.string(),
    /** Capability-specific parameters. */
    params: z.record(z.string(), z.unknown()).default({}),
    /** Justification recorded on the audit trail and shown on any approval gate. */
    reason: z.string().optional(),
  })
  .strict();
export type InvokeParams = z.infer<typeof InvokeParamsSchema>;

/** `permaura_http_request`: the generic HTTP capability, where the gateway offers it. The host is still policy-checked and the auth secret is injected server-side. */
export const HttpRequestParamsSchema = z
  .object({
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]).optional(),
    /** Absolute https URL on a host the connection allows; plain http is refused. */
    url: z.string(),
    /** Non-auth headers only; Permaura injects the Authorization header itself. */
    headers: z.record(z.string(), z.string()).optional(),
    /** JSON body for write methods. */
    body: z.unknown().optional(),
  })
  .strict();
export type HttpRequestParams = z.infer<typeof HttpRequestParamsSchema>;

/** `permaura_get_approval_status`: poll a pending approval raised by an earlier invoke. */
export const GetApprovalStatusParamsSchema = z
  .object({
    approval_id: z.string(),
  })
  .strict();
export type GetApprovalStatusParams = z.infer<typeof GetApprovalStatusParamsSchema>;

/** `permaura_explain_denial`: get the human-readable reason a capability/action was denied, so the agent can adjust or ask the user. */
export const ExplainDenialParamsSchema = z
  .object({
    /** Capability id or action that was denied. */
    capability: z.string(),
    /** Optionally the params that triggered the denial, to get a parameter-specific explanation. */
    params: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();
export type ExplainDenialParams = z.infer<typeof ExplainDenialParamsSchema>;

/** `permaura_revoke_session`: revoke the current (or a named) session's token at once. The agent's grants are unchanged. */
export const RevokeSessionParamsSchema = z
  .object({
    /** Session to revoke; defaults to the caller's current session. */
    session_id: z.string().optional(),
  })
  .strict();
export type RevokeSessionParams = z.infer<typeof RevokeSessionParamsSchema>;

/** The seven tool names these schemas cover. The bridge advertises its own list, and the gateway's list also carries `permaura_enroll` and per-capability tools. */
export const PERMAURA_MCP_TOOLS = [
  "permaura_list_capabilities",
  "permaura_request_grant",
  "permaura_invoke",
  "permaura_http_request",
  "permaura_get_approval_status",
  "permaura_explain_denial",
  "permaura_revoke_session",
] as const;
export type PermauraMcpTool = (typeof PERMAURA_MCP_TOOLS)[number];

// Crash at import time rather than silently advertising tool names that violate the MCP spec pattern ^[a-zA-Z0-9_-]{1,64}$.
const _MCP_NAME_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const _badNames = PERMAURA_MCP_TOOLS.filter((n) => !_MCP_NAME_RE.test(n));
if (_badNames.length > 0) {
  throw new Error(`MCP tool name(s) violate spec ^[a-zA-Z0-9_-]{1,64}$: ${_badNames.join(", ")}`);
}

/** Map from each MCP tool name to its zod param schema, matching the gateway's own tool arguments. Nothing in this repository validates against it yet. */
export const MCP_TOOL_PARAM_SCHEMAS = {
  "permaura_list_capabilities": ListCapabilitiesParamsSchema,
  "permaura_request_grant": RequestGrantParamsSchema,
  "permaura_invoke": InvokeParamsSchema,
  "permaura_http_request": HttpRequestParamsSchema,
  "permaura_get_approval_status": GetApprovalStatusParamsSchema,
  "permaura_explain_denial": ExplainDenialParamsSchema,
  "permaura_revoke_session": RevokeSessionParamsSchema,
} as const;
