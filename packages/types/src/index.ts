/**
 * @permaura/types: the canonical TypeScript domain contract for Permaura.
 *
 * Every schema here is a zod schema with an inferred type of the same name (minus the `Schema` suffix). Validate at the boundary with the `*Schema`, carry the inferred type everywhere else. These schemas describe an earlier version of the gateway's API: the gateway is the source of truth, and several shapes here, `Grant` and `Conditions` among them, no longer match it.
 */

export * from "./primitives.js";
export * from "./principal.js";
export * from "./conditions.js";
export * from "./capability.js";
export * from "./decision.js";
export * from "./grant.js";
export * from "./audit.js";
export * from "./rest.js";
export * from "./mcp.js";
