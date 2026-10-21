import { z } from "zod";

/**
 * Risk tiers, normalized exactly to the four levels the core enforcement runtime understands. Every capability and every policy decision is scored against one of these. `high` and `critical` both hold a call at the `approve` rung, which the operator token or a paired device resolves; a policy can require a device signature on top.
 */
export const RiskTierSchema = z.enum(["low", "medium", "high", "critical"]);
export type RiskTier = z.infer<typeof RiskTierSchema>;

/**
 * Normalized, snake_case action verbs. This list is the canonical mirror of `permaura_core::Action` on the Rust side, so keep the two in lockstep. A capability id like `braintree.transactions.refund` is parsed down to one of these verbs (`refund`) when the policy engine evaluates it.
 */
export const ActionSchema = z.enum([
  "read",
  "search",
  "list",
  "create",
  "update",
  "delete",
  "execute",
  "deploy",
  "refund",
  "charge",
  "rotate_secret",
  "export",
  "send",
]);
export type Action = z.infer<typeof ActionSchema>;

/**
 * Where the request came from, as the gateway judged it: `local_only` for a caller on its own host, `remote_allowed` for a hosted, tunnelled or proxied one. It is recorded on the audit event and does not change the decision.
 */
export const ExecutionLocationSchema = z.enum(["local_only", "remote_allowed"]);
export type ExecutionLocation = z.infer<typeof ExecutionLocationSchema>;

/**
 * The concrete place an individual tool call ran. Distinct from `ExecutionLocation`, which is a *policy constraint*; this is the *observed* fact recorded on a tool_call / audit_event.
 */
export const ExecutionSiteSchema = z.enum(["local", "remote", "hosted", "customer"]);
export type ExecutionSite = z.infer<typeof ExecutionSiteSchema>;

/**
 * The three terminal policy outcomes. `requires_approval` is not a denial: it is a hold pending a human gate, after which the action proceeds or is dropped.
 */
export const DecisionKindSchema = z.enum(["allow", "deny", "requires_approval"]);
export type DecisionKind = z.infer<typeof DecisionKindSchema>;

/**
 * Approval mechanisms. `push` is an approval the operator token or a paired device can resolve, and `device_signed` is the top rung of the approval ladder, where only an ed25519 signature from a paired approver device can resolve the hold (a semi-trusted broker bearer is never sufficient; a policy's `device_signed_quorum` can require several distinct people). The gateway never issues `touch_id` or `two_person`.
 */
export const ApprovalTypeSchema = z.enum([
  "touch_id",
  "push",
  "two_person",
  "device_signed",
]);
export type ApprovalType = z.infer<typeof ApprovalTypeSchema>;

/** Lifecycle of an approval request once it has been raised. */
export const ApprovalStatusSchema = z.enum([
  "pending",
  "approved",
  "denied",
  "expired",
  "revoked",
]);
export type ApprovalStatus = z.infer<typeof ApprovalStatusSchema>;

/** ISO-8601 timestamp string. Kept as a branded-ish alias so the intent is legible in DTOs. */
export const IsoTimestampSchema = z.string().datetime({ offset: true });
export type IsoTimestamp = z.infer<typeof IsoTimestampSchema>;
