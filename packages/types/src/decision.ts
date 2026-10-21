import { z } from "zod";
import {
  DecisionKindSchema,
  ApprovalTypeSchema,
  ExecutionLocationSchema,
} from "./primitives.js";
import { PrincipalSchema, ResourceSchema } from "./principal.js";

/**
 * Describes the human gate that must clear before a held action proceeds. Returned inside a `requires_approval` decision. The approval is, by default, single-use and bound to the exact action and parameters that produced it.
 */
export const ApprovalRequirementSchema = z.object({
  type: ApprovalTypeSchema,
  /** When true (default), the approval authorizes exactly one execution and then burns. */
  single_use: z.boolean().default(true),
  /** Human-facing message shown on the approval prompt, e.g. "Codex wants to refund AUD 49.00 ...". */
  message: z.string(),
});
export type ApprovalRequirement = z.infer<typeof ApprovalRequirementSchema>;

/**
 * The output of the policy engine. `decision` is the verdict, `reason` is always human-readable (it is what `permaura.explain_denial` surfaces), and `approval` is present iff `decision === "requires_approval"`.
 */
export const DecisionSchema = z.object({
  decision: DecisionKindSchema,
  reason: z.string(),
  /** The policy that produced this decision, when one matched. */
  policy_id: z.string().optional(),
  approval: ApprovalRequirementSchema.optional(),
});
export type Decision = z.infer<typeof DecisionSchema>;

/**
 * The input fed to the policy engine to produce a `Decision`. It carries who is asking, what verb, against what resource, in what session/context.
 */
export const PolicyDecisionInputSchema = z.object({
  principal: PrincipalSchema,
  /** Capability id or normalized action verb being evaluated, e.g. `transactions.refund`. */
  action: z.string(),
  resource: ResourceSchema,
  context: z
    .object({
      session_id: z.string().optional(),
      requested_at: z.string().datetime({ offset: true }).optional(),
      execution_location: ExecutionLocationSchema.optional(),
    })
    .optional(),
});
export type PolicyDecisionInput = z.infer<typeof PolicyDecisionInputSchema>;
