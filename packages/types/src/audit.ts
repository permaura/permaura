import { z } from "zod";
import { DecisionKindSchema, ExecutionSiteSchema } from "./primitives.js";

/**
 * The redacted, summary view of what an action returned. Never the raw body: Permaura stores summaries, hashes, and field counts so an audit reader can reason about what happened without re-exposing secrets or PII.
 */
export const ResultSummarySchema = z.object({
  status: z.enum(["success", "error", "denied"]),
  records_returned: z.number().int().nonnegative().optional(),
  fields_redacted: z.number().int().nonnegative().optional(),
  error_code: z.string().optional(),
});
export type ResultSummary = z.infer<typeof ResultSummarySchema>;

/**
 * A single audit row. Audit events are append-only and hash-chained: each row carries the hash of the previous row in `prev_hash`, the hash of its own canonical content in `hash`, and an ed25519 `signature` over `hash`. A verifier walks the chain confirming `hash(row) === row.hash` and `row.prev_hash === previous.hash`, then checks the signature, so editing or removing a row inside the chain breaks it. Removing rows from the end does not, and whoever can write the store can usually read the signing key beside it.
 *
 * This row contains no raw secret material: ids, a decision and a redacted `result_summary`.
 */
export const AuditEventSchema = z.object({
  event_id: z.string(),
  /** Monotonic sequence number within an org's chain; the chain is ordered by this. */
  sequence: z.number().int().nonnegative().optional(),
  timestamp: z.string().datetime({ offset: true }),
  org_id: z.string().optional(),
  user_id: z.string().optional(),
  agent_id: z.string().optional(),
  device_id: z.string().optional(),
  session_id: z.string().optional(),
  /** The capability id / action that ran, e.g. `braintree.transactions.search`. */
  action: z.string(),
  resource: z.string(),
  decision: DecisionKindSchema,
  policy_id: z.string().optional(),
  execution_location: ExecutionSiteSchema.optional(),
  /** Not recorded by the gateway. */
  secret_id: z.string().optional(),
  secret_version: z.string().optional(),
  result_summary: ResultSummarySchema.optional(),
  /** Hash of the previous event in the chain (`null`/absent for the genesis event). */
  prev_hash: z.string().nullable().optional(),
  /** Hash over this event's canonical content. */
  hash: z.string().optional(),
  /** ed25519 signature over `hash`, hex- or base64-encoded. */
  signature: z.string().optional(),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;
