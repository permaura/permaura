/**
 * @permaura/sdk: the TypeScript SDK for Permaura.
 *
 * Two halves:
 *  - `PermauraClient`: a typed wrapper over the REST API (v1), backed by the shared `@permaura/types` contracts.
 *  - The connector authoring API: `defineConnector`, plus the `redact` helper, for describing risk-tiered capabilities and running them in your own process. They enforce no policy, and the gateway does not load them.
 *
 * Domain types are re-exported from `@permaura/types` so consumers can import everything from one place.
 */

export {
  PermauraClient,
  PermauraApiError,
  DEFAULT_BASE_URL,
  bearerDigest,
  bearerKey,
  bearerProof,
  type PermauraClientOptions,
} from "./client.js";

export {
  defineConnector,
  type Connector,
  type ConnectorConfig,
  type CapabilityDefinition,
  type ExecuteArgs,
  type ExecuteContext,
} from "./connector.js";

export {
  redact,
  redactWithCount,
  DEFAULT_REDACT_PATTERNS,
  REDACTION_PLACEHOLDER,
  type RedactOptions,
  type RedactResult,
} from "./redact.js";

// Re-export the domain contract so SDK users have a single import surface.
export * from "@permaura/types";
