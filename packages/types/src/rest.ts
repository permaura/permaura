import { z } from "zod";
import {
  RiskTierSchema,
  ExecutionSiteSchema,
  ApprovalStatusSchema,
  ApprovalTypeSchema,
} from "./primitives.js";
import { PrincipalSchema } from "./principal.js";
import { ConditionsSchema } from "./conditions.js";
import { GrantSchema } from "./grant.js";
import { DecisionSchema } from "./decision.js";
import { CapabilitySpecSchema } from "./capability.js";
import { AuditEventSchema, ResultSummarySchema } from "./audit.js";

/**
 * Request and response DTOs for the public REST API (v1). Each endpoint has a request schema (suffix `RequestSchema`) and a response schema (suffix `ResponseSchema`). They describe an earlier version of the gateway's API: the gateway is the source of truth, and several of these shapes no longer match it.
 */

/* POST /v1/sessions: open an agent session. */
export const CreateSessionRequestSchema = z.object({
  principal: PrincipalSchema,
  /** Optional human-readable label for the session, e.g. "Codex: failed payment triage". */
  label: z.string().optional(),
  /** Default execution location for the session unless a grant narrows it. */
  execution_location: z.enum(["local_only", "remote_allowed"]).optional(),
});
export type CreateSessionRequest = z.infer<typeof CreateSessionRequestSchema>;

export const SessionSchema = z.object({
  session_id: z.string(),
  principal: PrincipalSchema,
  label: z.string().optional(),
  status: z.enum(["active", "revoked", "expired"]),
  created_at: z.string().datetime({ offset: true }),
  expires_at: z.string().datetime({ offset: true }).optional(),
});
export type Session = z.infer<typeof SessionSchema>;

export const CreateSessionResponseSchema = z.object({
  session: SessionSchema,
  /** Bearer token the agent presents on subsequent calls for this session. */
  token: z.string(),
});
export type CreateSessionResponse = z.infer<typeof CreateSessionResponseSchema>;

/* GET /v1/capabilities: list capabilities visible to the caller. */
export const ListCapabilitiesQuerySchema = z.object({
  session_id: z.string().optional(),
  /** Ignored by the gateway, which lists what this session could attempt whatever this says (everything for an operator). */
  scope: z.enum(["current_session", "all"]).optional(),
  connector: z.string().optional(),
});
export type ListCapabilitiesQuery = z.infer<typeof ListCapabilitiesQuerySchema>;

export const ListCapabilitiesResponseSchema = z.object({
  capabilities: z.array(CapabilitySpecSchema),
});
export type ListCapabilitiesResponse = z.infer<typeof ListCapabilitiesResponseSchema>;

/* POST /v1/grants: mint a grant. */
export const CreateGrantRequestSchema = z.object({
  principal: PrincipalSchema,
  resource: z.string(),
  allowed_actions: z.array(z.string()),
  denied_actions: z.array(z.string()).optional(),
  conditions: ConditionsSchema.optional(),
  /** Free-text justification recorded on the audit trail. */
  reason: z.string().optional(),
});
export type CreateGrantRequest = z.infer<typeof CreateGrantRequestSchema>;

export const CreateGrantResponseSchema = z.object({ grant: GrantSchema });
export type CreateGrantResponse = z.infer<typeof CreateGrantResponseSchema>;

/**
 * A reusable permission template scoped to a connection (mirror of `permaura_core::Policy`). A policy names only *what is allowed, denied, or gated*, never an agent, expiry, or call limit (those are grant concerns). The five capability-id lists are the rungs of the approval ladder: `allow` (auto, silent), `notify` (executes immediately + after-the-fact push), `requires_approval` (the `approve` rung: held, resolvable by an operator bearer or a device signature), `device_signed` (held, resolvable by a device signature only), and `deny` (deny always wins). `notify` and `device_signed` default to `[]` so policies from gateways predating the ladder still parse.
 */
export const PolicySchema = z.object({
  /** Stable id, e.g. `pol_123`. */
  id: z.string(),
  /** The connection this policy is scoped to (`Connection.id`). */
  connection_id: z.string(),
  /** Operator-facing name, e.g. `Read-only`. */
  name: z.string().default(""),
  /** Capability action ids explicitly allowed (the `auto` rung), e.g. `transactions.search`. */
  allow: z.array(z.string()),
  /** Capability action ids explicitly denied. Deny always wins over allow. */
  deny: z.array(z.string()),
  /** Capability action ids that, even when allowed, must be escalated to a human (the `approve` rung). */
  requires_approval: z.array(z.string()),
  /** Capability action ids that execute immediately but push an after-the-fact notification to enrolled devices (the `notify` rung). */
  notify: z.array(z.string()).default([]),
  /** Capability action ids whose approval may ONLY be resolved by an ed25519 device signature (the `device_signed` rung). Fails closed when no device is paired. */
  device_signed: z.array(z.string()).default([]),
});
export type Policy = z.infer<typeof PolicySchema>;

/* POST /v1/invoke: call a capability. The secret is injected server-side; only a redacted result returns. */
export const InvokeRequestSchema = z.object({
  session_id: z.string().optional(),
  /** Capability id, e.g. `braintree.transactions.search`. */
  capability: z.string(),
  /** Capability-specific input. The gateway forwards only the parameter names the capability declares; it does not check types or bounds. */
  params: z.record(z.string(), z.unknown()).default({}),
  /** Why the agent is making this call, recorded and shown on any approval prompt. */
  reason: z.string().optional(),
});
export type InvokeRequest = z.infer<typeof InvokeRequestSchema>;

/**
 * The outcome of an invoke. Exactly one of `result` (when the decision allowed and execution completed), `approval` (when a human gate is now pending), or neither-with-`decision: deny` is populated. `result` is already redacted.
 */
export const InvokeResponseSchema = z.object({
  decision: DecisionSchema,
  /** Redacted, structured result. Present only when the call executed. */
  result: z.unknown().optional(),
  result_summary: ResultSummarySchema.optional(),
  /** Set when the decision is `requires_approval`; poll `/v1/approvals` or `get_approval_status` with this id. */
  approval_id: z.string().optional(),
  execution_location: ExecutionSiteSchema.optional(),
  /** Id of the recorded tool_call / audit event for this invocation. */
  tool_call_id: z.string().optional(),
});
export type InvokeResponse = z.infer<typeof InvokeResponseSchema>;

/* POST /v1/approvals: resolve (or query) an approval. */
export const ApprovalSchema = z.object({
  approval_id: z.string(),
  status: ApprovalStatusSchema,
  type: ApprovalTypeSchema,
  message: z.string(),
  session_id: z.string().optional(),
  capability: z.string().optional(),
  /** The approval-ladder rung this hold was created at. `approve` is resolvable by an operator bearer or a device signature; `device_signed` requires a device signature only. Defaults to `approve` so approvals from gateways predating the ladder still parse. */
  required_tier: z.enum(["approve", "device_signed"]).default("approve"),
  created_at: z.string().datetime({ offset: true }),
  resolved_at: z.string().datetime({ offset: true }).nullable().optional(),
  expires_at: z.string().datetime({ offset: true }).optional(),
});
export type Approval = z.infer<typeof ApprovalSchema>;

export const ResolveApprovalRequestSchema = z.object({
  approval_id: z.string(),
  /** The human's verdict. */
  decision: z.enum(["approve", "deny"]),
  /** The approver id that signed (`device:<id>` / `user:<id>`), sent only with a device signature. */
  approver: z.string().optional(),
});
export type ResolveApprovalRequest = z.infer<typeof ResolveApprovalRequestSchema>;

export const ResolveApprovalResponseSchema = z.object({ approval: ApprovalSchema });
export type ResolveApprovalResponse = z.infer<typeof ResolveApprovalResponseSchema>;

/* GET /v1/audit-events: page the hash-chained audit log. */
export const ListAuditEventsQuerySchema = z.object({
  session_id: z.string().optional(),
  agent_id: z.string().optional(),
  /** ISO instant; only events at or after this time are returned. */
  since: z.string().datetime({ offset: true }).optional(),
  limit: z.number().int().positive().max(1000).optional(),
  /** Opaque cursor from a previous page. */
  cursor: z.string().optional(),
});
export type ListAuditEventsQuery = z.infer<typeof ListAuditEventsQuerySchema>;

export const ListAuditEventsResponseSchema = z.object({
  events: z.array(AuditEventSchema),
  next_cursor: z.string().nullable().optional(),
});
export type ListAuditEventsResponse = z.infer<typeof ListAuditEventsResponseSchema>;

/* POST /v1/secrets: store a secret (ciphertext is created server-side; the plaintext never persists in the clear). */
export const CreateSecretRequestSchema = z.object({
  name: z.string(),
  /** Logical type, e.g. `api_key`, `oauth_token`, `password`. */
  type: z.string(),
  integration: z.string().optional(),
  /** The plaintext secret value, encrypted at rest immediately under envelope encryption; never returned by any endpoint. */
  value: z.string(),
  execution_location: z.enum(["local_only", "remote_allowed"]).optional(),
  risk_classification: RiskTierSchema.optional(),
  labels: z.record(z.string(), z.string()).optional(),
});
export type CreateSecretRequest = z.infer<typeof CreateSecretRequestSchema>;

/** A secret reference. Deliberately carries no ciphertext or plaintext, only metadata an operator needs. */
export const SecretRefSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  integration: z.string().optional(),
  version: z.string(),
  risk_classification: RiskTierSchema.optional(),
  rotation_status: z.enum(["current", "rotating", "revoked"]).optional(),
  created_at: z.string().datetime({ offset: true }),
  last_used_at: z.string().datetime({ offset: true }).nullable().optional(),
});
export type SecretRef = z.infer<typeof SecretRefSchema>;

export const CreateSecretResponseSchema = z.object({ secret: SecretRefSchema });
export type CreateSecretResponse = z.infer<typeof CreateSecretResponseSchema>;

/* POST /v1/secrets/:id/rotate: rotate to a new version. */
export const RotateSecretRequestSchema = z.object({
  /** New plaintext value. If omitted, the connector's native rotation is invoked to generate one. */
  value: z.string().optional(),
});
export type RotateSecretRequest = z.infer<typeof RotateSecretRequestSchema>;

export const RotateSecretResponseSchema = z.object({ secret: SecretRefSchema });
export type RotateSecretResponse = z.infer<typeof RotateSecretResponseSchema>;

/* POST /v1/devices/enroll: enroll a device into an org. */
export const EnrollDeviceRequestSchema = z.object({
  name: z.string(),
  platform: z.enum(["macos", "ios", "android", "linux", "windows"]).optional(),
  /** Not read by the gateway, which takes `approver_pubkey` and records it untrusted until the key is paired. The audit chain is signed by the gateway's own key, and no key is bound to hardware. */
  public_key: z.string().optional(),
});
export type EnrollDeviceRequest = z.infer<typeof EnrollDeviceRequestSchema>;

export const DeviceSchema = z.object({
  id: z.string(),
  name: z.string(),
  platform: z.string().optional(),
  enrolled_at: z.string().datetime({ offset: true }),
});
export type Device = z.infer<typeof DeviceSchema>;

export const EnrollDeviceResponseSchema = z.object({
  device: DeviceSchema,
  /** Enrollment token the device persists to authenticate future calls. */
  enrollment_token: z.string(),
});
export type EnrollDeviceResponse = z.infer<typeof EnrollDeviceResponseSchema>;

/* POST /v1/agents/register: register an agent identity. */
export const RegisterAgentRequestSchema = z.object({
  /** Stable agent id, e.g. `codex-cli`, `claude-code`, `cursor`, or a custom one. */
  agent: z.string(),
  display_name: z.string().optional(),
  device: z.string().optional(),
});
export type RegisterAgentRequest = z.infer<typeof RegisterAgentRequestSchema>;

export const AgentSchema = z.object({
  id: z.string(),
  agent: z.string(),
  display_name: z.string().optional(),
  registered_at: z.string().datetime({ offset: true }),
});
export type Agent = z.infer<typeof AgentSchema>;

export const RegisterAgentResponseSchema = z.object({ agent: AgentSchema });
export type RegisterAgentResponse = z.infer<typeof RegisterAgentResponseSchema>;

/** Uniform error envelope returned by the gateway on non-2xx responses. */
export const ApiErrorSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    /** Present on denials: the policy reason, suitable for `explain_denial`. */
    reason: z.string().optional(),
  }),
});
export type ApiError = z.infer<typeof ApiErrorSchema>;
