import { z } from "zod";
import { RiskTierSchema, ActionSchema } from "./primitives.js";

/**
 * A capability is the unit of permission an agent can call. Its id is `<connector>.<action-path>`, e.g. `braintree.transactions.search` or `github.pull_requests.create`. The leading segment is the connector id; the trailing segment normalizes to one of the canonical `Action` verbs (`search`, `create`, ...) for policy evaluation.
 *
 * This is the *spec* the agent sees, never the implementation. It carries no secret, no upstream URL, only the contract: id, human description, risk, whether it always needs approval, and a JSON-Schema rendering of its input shape.
 */
export const CapabilitySpecSchema = z.object({
  /** `<connector>.<action>`, e.g. `braintree.transactions.search`. */
  id: z.string().regex(/^[a-z0-9_]+(\.[a-z0-9_]+)+$/, {
    message: "capability id must be dot-delimited snake_case, e.g. braintree.transactions.search",
  }),
  /** Human-readable one-liner shown to the agent and in the console. */
  description: z.string().optional(),
  risk: RiskTierSchema,
  /** The normalized verb this capability maps to for policy purposes. */
  action: ActionSchema.optional(),
  /** Connector that owns this capability (the leading id segment), surfaced for grouping. */
  connector: z.string().optional(),
  /** True if every call is held at the `approve` rung whatever the policy says; the operator token or a paired device resolves it. */
  requiresApproval: z.boolean().optional(),
  /**
   * JSON Schema describing the capability's input. On the TS authoring side this is produced from a zod schema; over the wire and in the registry it is plain JSON Schema so any language can render a form or validate.
   */
  inputSchema: z.record(z.string(), z.unknown()).optional(),
});
export type CapabilitySpec = z.infer<typeof CapabilitySpecSchema>;
