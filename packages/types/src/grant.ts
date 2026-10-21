import { z } from "zod";
import { PrincipalSchema } from "./principal.js";
import { ConditionsSchema } from "./conditions.js";

/**
 * Legacy grant shape, which no longer matches the gateway. A gateway grant binds policies (which hold the allow, deny and approval lists) to one agent or all agents, under an optional expiry and per-period call limits; nothing is permitted until a grant binds a policy that allows it.
 *
 * `allowed_actions` / `denied_actions` carry capability-id suffixes (e.g. `transactions.search`) rather than bare verbs, so a single grant on an integration can permit some sub-capabilities and forbid others.
 */
export const GrantSchema = z.object({
  grant_id: z.string(),
  principal: PrincipalSchema,
  /** The resource this grant covers, e.g. `braintree_production`. */
  resource: z.string(),
  allowed_actions: z.array(z.string()),
  denied_actions: z.array(z.string()).default([]),
  conditions: ConditionsSchema.default({}),
  /** Calls already consumed, surfaced for UIs and budgeting. */
  calls_used: z.number().int().nonnegative().optional(),
  created_at: z.string().datetime({ offset: true }).optional(),
  revoked_at: z.string().datetime({ offset: true }).nullable().optional(),
});
export type Grant = z.infer<typeof GrantSchema>;
