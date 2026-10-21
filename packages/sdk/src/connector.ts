import { z, type ZodTypeAny } from "zod";
import type { RiskTier, CapabilitySpec } from "@permaura/types";

/**
 * Context handed to a capability's `execute`. Everything in it comes from whoever calls `invoke`; no Permaura component calls `execute`, and no policy has run. It carries metadata, never another credential.
 */
export interface ExecuteContext {
  /** The session this invocation belongs to. */
  sessionId?: string;
  /** Who/what is invoking, stringified, e.g. `agent:codex-cli`. */
  principal?: string;
  /** The integration account, e.g. `production`. */
  account?: string;
  /** Field names the caller asked to be redacted, to pass straight into `redact({ fields })`. */
  redactFields?: string[];
  /** Where this call is permitted to run. */
  executionLocation?: "local_only" | "remote_allowed";
  /** Free-text reason the agent supplied for the call. */
  reason?: string;
}

/** Arguments object passed to a capability's `execute`. Generic over the validated input type. */
export interface ExecuteArgs<TInput> {
  /** The capability input, already validated against `inputSchema`. */
  input: TInput;
  /** The upstream secret (plaintext) the caller of `invoke` supplied. Use it, do not return it. */
  secret: string;
  context: ExecuteContext;
}

/**
 * One capability definition, as authored. `inputSchema` is a zod schema; the SDK both validates input against it at invoke time and renders it to JSON Schema for the public `CapabilitySpec`.
 */
export interface CapabilityDefinition<TSchema extends ZodTypeAny = ZodTypeAny> {
  /** Action-path suffix, e.g. `transactions.search`. Combined with the connector id to form the full capability id. */
  id: string;
  risk: RiskTier;
  /** Human-readable description shown to the agent and console. */
  description?: string;
  /** Recorded in the capability's spec; the SDK enforces nothing. A gateway capability with this flag is held at the `approve` rung on every call. */
  requiresApproval?: boolean;
  inputSchema: TSchema;
  execute: (args: ExecuteArgs<z.infer<TSchema>>) => Promise<unknown> | unknown;
}

/** Configuration object passed to {@link defineConnector}. */
export interface ConnectorConfig {
  /** Connector id and the leading segment of every capability id, e.g. `braintree`. */
  id: string;
  description?: string;
  capabilities: CapabilityDefinition[];
}

/**
 * A built connector. Carries the original definitions plus derived lookups: the public `CapabilitySpec[]` (safe to hand an agent) and a `getCapability` resolver keyed by full capability id (`<connector>.<id>`).
 */
export interface Connector {
  id: string;
  description?: string;
  capabilities: CapabilityDefinition[];
  /** The agent-facing specs (risk, description, JSON-Schema input) with no execution detail. */
  specs: CapabilitySpec[];
  /** Resolve a capability by its full id, e.g. `braintree.transactions.search`. */
  getCapability(fullId: string): CapabilityDefinition | undefined;
  /** Validate and invoke a capability by full id. Throws if unknown or input is invalid. */
  invoke(fullId: string, input: unknown, secret: string, context?: ExecuteContext): Promise<unknown>;
}

/**
 * Best-effort conversion of a zod schema to a JSON-Schema-ish object for the public `CapabilitySpec.inputSchema`. We avoid a hard dependency on `zod-to-json-schema`: this handles the common shapes (object/string/number/boolean/array/enum/optional) and falls back to an open object for anything exotic, which is sufficient for surfacing an input shape to an agent or rendering a form.
 */
function zodToJsonSchema(schema: ZodTypeAny): Record<string, unknown> {
  const def = (schema as { _def?: { typeName?: string } })._def;
  const typeName = def?.typeName;

  switch (typeName) {
    case "ZodObject": {
      const shape = (schema as unknown as { shape: Record<string, ZodTypeAny> }).shape;
      const properties: Record<string, unknown> = {};
      const required: string[] = [];
      for (const [key, value] of Object.entries(shape)) {
        properties[key] = zodToJsonSchema(value);
        if (!value.isOptional()) required.push(key);
      }
      return {
        type: "object",
        properties,
        ...(required.length ? { required } : {}),
        additionalProperties: false,
      };
    }
    case "ZodString":
      return { type: "string" };
    case "ZodNumber":
      return { type: "number" };
    case "ZodBoolean":
      return { type: "boolean" };
    case "ZodArray":
      return {
        type: "array",
        items: zodToJsonSchema((schema as unknown as { element: ZodTypeAny }).element),
      };
    case "ZodEnum":
      return { type: "string", enum: (schema as unknown as { options: string[] }).options };
    case "ZodOptional":
    case "ZodNullable":
    case "ZodDefault":
      return zodToJsonSchema(
        (schema as unknown as { unwrap: () => ZodTypeAny }).unwrap(),
      );
    default:
      return { type: "object" };
  }
}

/** Parse the normalized `Action` verb out of a capability suffix, e.g. `transactions.search` -> `search`. Returns the last dot segment; callers map it to the `Action` enum where it matches. */
function trailingVerb(id: string): string {
  const parts = id.split(".");
  return parts[parts.length - 1] ?? id;
}

/**
 * Author a Permaura connector. This is the entry point:
 *
 * ```ts
 * const braintree = defineConnector({
 *   id: "braintree",
 *   capabilities: [
 *     { id: "transactions.search", risk: "medium", inputSchema: SearchSchema, execute: async ({ input, secret }) => redact(await api.search(input, secret)) },
 *     { id: "transactions.refund", risk: "critical", requiresApproval: true, inputSchema: RefundSchema, execute: async ({ input, secret }) => api.refund(input, secret) },
 *   ],
 * });
 * ```
 *
 * The returned `Connector` exposes agent-safe `specs`, a `getCapability` resolver, and a validating `invoke`.
 */
export function defineConnector(config: ConnectorConfig): Connector {
  const byFullId = new Map<string, CapabilityDefinition>();
  const specs: CapabilitySpec[] = [];

  for (const cap of config.capabilities) {
    const fullId = `${config.id}.${cap.id}`;
    byFullId.set(fullId, cap);
    specs.push({
      id: fullId,
      connector: config.id,
      description: cap.description,
      risk: cap.risk,
      action: trailingVerb(cap.id) as CapabilitySpec["action"],
      requiresApproval: cap.requiresApproval,
      inputSchema: zodToJsonSchema(cap.inputSchema),
    });
  }

  return {
    id: config.id,
    description: config.description,
    capabilities: config.capabilities,
    specs,
    getCapability(fullId: string) {
      return byFullId.get(fullId);
    },
    async invoke(fullId, input, secret, context = {}) {
      const cap = byFullId.get(fullId);
      if (!cap) {
        throw new Error(`Unknown capability: ${fullId}`);
      }
      const parsed = cap.inputSchema.parse(input);
      return cap.execute({ input: parsed, secret, context });
    },
  };
}
