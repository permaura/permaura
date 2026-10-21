/**
 * A redaction helper for SDK connectors. It is not the gateway's redaction, which the gateway applies to every capability it runs. `redact()` walks an arbitrary value and replaces matching field values with a placeholder, returning a deep copy (the input is never mutated).
 *
 * It matches on two axes:
 *  1. An explicit `fields` list (exact key names, case-insensitive), typically the `redactFields` an `ExecuteContext` carries.
 *  2. A default set of always-dangerous key patterns (API keys, tokens, authorization headers, cookies, card PAN/CVV, private keys, passwords, database URLs) so a connector author gets safe-by-default behavior even without configuring anything.
 */

/** Default key-name patterns that are redacted unconditionally. Matched case-insensitively as substrings of the key. */
export const DEFAULT_REDACT_PATTERNS: readonly string[] = [
  "api_key",
  "apikey",
  "secret",
  "token",
  "access_token",
  "refresh_token",
  "authorization",
  "auth",
  "cookie",
  "set-cookie",
  "password",
  "passwd",
  "private_key",
  "client_secret",
  "card_number",
  "pan",
  "cvv",
  "cvc",
  "ssn",
  "database_url",
  "db_url",
  "connection_string",
];

/** Value standing in for any redacted field. */
export const REDACTION_PLACEHOLDER = "[REDACTED]" as const;

export interface RedactOptions {
  /** Exact field names to redact (case-insensitive), e.g. from `ExecuteContext.redactFields`. */
  fields?: string[];
  /** When false, skip the built-in dangerous-key patterns and redact only `fields`. Defaults to true. */
  useDefaults?: boolean;
  /** Override the placeholder written in place of a redacted value. */
  placeholder?: string;
  /** Maximum recursion depth, a guard against pathological/cyclic structures. Defaults to 64. */
  maxDepth?: number;
}

/** Count of fields redacted, returned by {@link redactWithCount}. */
export interface RedactResult<T> {
  value: T;
  fieldsRedacted: number;
}

function keyMatches(key: string, exactLower: Set<string>, patterns: readonly string[]): boolean {
  const lower = key.toLowerCase();
  if (exactLower.has(lower)) return true;
  for (const p of patterns) {
    if (lower.includes(p)) return true;
  }
  return false;
}

/**
 * Redact sensitive fields from a value and report how many were scrubbed.
 */
export function redactWithCount<T>(value: T, options: RedactOptions = {}): RedactResult<T> {
  const exactLower = new Set((options.fields ?? []).map((f) => f.toLowerCase()));
  const patterns = options.useDefaults === false ? [] : DEFAULT_REDACT_PATTERNS;
  const placeholder = options.placeholder ?? REDACTION_PLACEHOLDER;
  const maxDepth = options.maxDepth ?? 64;
  let count = 0;
  const seen = new WeakSet<object>();

  function walk(node: unknown, depth: number): unknown {
    if (depth > maxDepth) return node;
    if (node === null || typeof node !== "object") return node;
    if (seen.has(node as object)) return node;
    seen.add(node as object);

    if (Array.isArray(node)) {
      return node.map((item) => walk(item, depth + 1));
    }

    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
      if (keyMatches(key, exactLower, patterns)) {
        out[key] = placeholder;
        count += 1;
      } else {
        out[key] = walk(val, depth + 1);
      }
    }
    return out;
  }

  return { value: walk(value, 0) as T, fieldsRedacted: count };
}

/**
 * Redact sensitive fields from a value, returning a scrubbed deep copy. This is the helper named in the connector authoring example: call it on any upstream response before returning it from `execute`.
 *
 * @example
 * return redact(await braintree.search(input, secret), { fields: context.redactFields });
 */
export function redact<T>(value: T, options: RedactOptions = {}): T {
  return redactWithCount(value, options).value;
}
