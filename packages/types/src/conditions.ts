import { z } from "zod";
import { ExecutionLocationSchema } from "./primitives.js";

/**
 * @deprecated Not implemented. The gateway has no grant conditions: none of these fields is applied, and a request carrying `conditions` (or any one of them) is refused with a 400 naming it. What a gateway does enforce is a grant's expiry and call limits and a policy's rungs, including `device_signed` with a quorum of distinct people. Kept only so the unsupported request types that still name it compile.
 */
export const ConditionsSchema = z.object({
  /** Hard expiry of the grant. After this instant the grant is dead regardless of remaining call budget. */
  expires_at: z.string().datetime({ offset: true }).optional(),
  /** Total number of invocations permitted under this grant. */
  max_calls: z.number().int().nonnegative().optional(),
  /** Ceiling for monetary actions (`charge`, `refund`). Compared against `Resource.amount`. */
  max_amount: z.number().nonnegative().optional(),
  /** Outbound hosts the generic HTTP proxy may reach. Deny if the request host is not in this list. */
  allowed_hosts: z.array(z.string()).optional(),
  /** Path prefixes/globs permitted on the matched host. */
  allowed_paths: z.array(z.string()).optional(),
  /** Repos a repo-scoped action may touch, e.g. `acme/app`. */
  allowed_repos: z.array(z.string()).optional(),
  /** Environments the action may target, e.g. `staging`, `production`. */
  allowed_environments: z.array(z.string()).optional(),
  /** Action verbs (or capability ids) that always require human approval even when otherwise allowed. */
  approval_required: z.array(z.string()).optional(),
  /** When true, the action is only permitted during configured business hours. */
  business_hours_only: z.boolean().optional(),
  /** Where the action may physically run. */
  execution_location: ExecutionLocationSchema.optional(),
  /** Force a local biometric (Touch ID) gate before executing. */
  requires_touch_id: z.boolean().optional(),
  /** Force enterprise dual-control: a second human must independently approve. */
  requires_two_person_approval: z.boolean().optional(),
  /** Field names the redaction layer must strip from the response before it returns to the agent. */
  redact_fields: z.array(z.string()).optional(),
});
export type Conditions = z.infer<typeof ConditionsSchema>;
