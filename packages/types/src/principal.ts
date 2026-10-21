import { z } from "zod";

/**
 * A principal is *who or what is asking*. Permaura models this as a structured tuple rather than a single string. The gateway's policy engine matches grants on the agent id only; user and device are recorded for audit. Stringified it reads `user:<id>` / `agent:<id>` / `device:<id>` / `org:<id>`, but on the wire it travels as this object.
 *
 * `agent` is intentionally an open string rather than an enum: the well-known values are `codex-cli`, `claude-code`, and `cursor`, but third-party and remote agents register their own ids.
 */
export const PrincipalSchema = z.object({
  user: z.string().optional(),
  agent: z.string().optional(),
  device: z.string().optional(),
  org: z.string().optional(),
});
export type Principal = z.infer<typeof PrincipalSchema>;

/** Well-known first-party agent identifiers. Not exhaustive, since `Principal.agent` accepts any registered id. */
export const KNOWN_AGENTS = ["codex-cli", "claude-code", "cursor"] as const;
export type KnownAgent = (typeof KNOWN_AGENTS)[number];

/**
 * A resource is *what the action touches*. The gateway's policy engine keys a decision on the connection and the capability's action id only; it reads none of the flexible fields here (`transaction_id`, `amount`, `currency`, `account`, `repo`, `environment`, `host`, `path`, `method`), and no condition such as `max_amount` or `allowed_repos` is evaluated against them. A generic-HTTP connection's host allowlist lives on the connection.
 *
 * Canonical stringified forms are `secret:<name>`, `integration:<name>`, `repo:<x>`, `environment:<env>`, `transaction:<id>`.
 */
export const ResourceSchema = z.object({
  /** e.g. `secret`, `integration`, `repo`, `environment`, `transaction`. */
  kind: z.string().optional(),
  /** The named integration this resource belongs to, e.g. `braintree`, `github`. */
  integration: z.string().optional(),
  /** The integration account / connection, e.g. `production`. */
  account: z.string().optional(),
  /** The named secret, e.g. `braintree_prod`. */
  secret: z.string().optional(),
  repo: z.string().optional(),
  environment: z.string().optional(),
  transaction_id: z.string().optional(),
  /** Monetary amount for `charge` / `refund` actions. Informational: no condition compares it with anything. */
  amount: z.number().optional(),
  currency: z.string().optional(),
  /** Outbound HTTP target, used by generic-proxy `allowed_hosts` / method matching. */
  host: z.string().optional(),
  path: z.string().optional(),
  method: z.string().optional(),
});
export type Resource = z.infer<typeof ResourceSchema>;
