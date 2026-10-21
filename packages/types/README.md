# @permaura/types

The canonical TypeScript domain contract for [Permaura](https://permaura.com): _give agents permission, not keys._

Every export is a [zod](https://zod.dev) schema paired with an inferred type. Validate untrusted input at the boundary with the `*Schema`; carry the inferred type everywhere else. These schemas describe an earlier version of the gateway's API. The gateway is the source of truth, and several shapes here, `Grant` and `Conditions` among them, no longer match it.

## Install

```bash
pnpm add @permaura/types
```

## What's in here

| Area | Exports |
| --- | --- |
| Primitives | `RiskTier`, `Action`, `ExecutionLocation`, `ExecutionSite`, `DecisionKind`, `ApprovalType`, `ApprovalStatus` |
| Policy model | `Principal`, `Resource`, `Conditions`, `Grant` |
| Decisions | `Decision`, `ApprovalRequirement`, `PolicyDecisionInput` |
| Capabilities | `CapabilitySpec` |
| Audit | `AuditEvent`, `ResultSummary` |
| REST DTOs | request/response schemas for every `/v1` endpoint |
| MCP | param schemas for seven of the fixed `permaura_*` tools, `PERMAURA_MCP_TOOLS`, `MCP_TOOL_PARAM_SCHEMAS` |

## Usage

```ts
import { DecisionSchema, type Decision } from "@permaura/types";

// Validate something off the wire.
const decision: Decision = DecisionSchema.parse(await res.json());

if (decision.decision === "requires_approval") {
  console.log(decision.approval?.message);
}
```

The `Grant` type here is the legacy shape and no longer matches the gateway, whose grants bind policies to agents under limits; do not build one from it.

The schemas cover `permaura_list_capabilities`, `permaura_request_grant`, `permaura_invoke`, `permaura_http_request`, `permaura_get_approval_status`, `permaura_explain_denial` and `permaura_revoke_session`. The gateway also offers `permaura_enroll` and one tool per capability an agent can reach, and the MCP bridge does not use these schemas. There is intentionally no `get_secret` / `get_api_key` / `export_token`: the agent receives capabilities and results, never credentials.

## Build

```bash
pnpm build      # tsup -> dist (esm + .d.ts)
pnpm typecheck  # tsc --noEmit
```
