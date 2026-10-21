# @permaura/sdk

> **Out of date and unsupported.** This client no longer matches the gateway's v1 REST API: it sends `principal` where session creation needs `agent_id`, sends `decision` where resolving an approval needs a boolean `approve`, and expects response shapes the gateway does not return. Do not use it until it is realigned. To drive a gateway today, follow the [REST API walkthrough](https://docs.permaura.com/developers/rest-api-walkthrough) and the [REST API reference](https://docs.permaura.com/developers/rest-api).

The TypeScript SDK for [Permaura](https://permaura.com): _give agents permission, not keys._

Two halves:

- **`PermauraClient`**: a typed wrapper written for an earlier REST API; see the notice above.
- **Connector authoring**: `defineConnector(...)` and the `redact()` helper, for describing risk-tiered capabilities and running them in your own process. They enforce no policy, and the gateway does not load them.

## Install

```bash
pnpm add @permaura/sdk
```

## Talking to the gateway

```ts
import { PermauraClient } from "@permaura/sdk";

// Defaults to the local broker at http://127.0.0.1:7376.
const client = new PermauraClient();

// Open a session for the Codex agent.
const { session, token } = await client.createSession({
  principal: { user: "sam", agent: "codex-cli", device: "sam-macbook" },
  label: "Failed payment triage",
});
client.setToken(token);

// Discover what this session may do.
const { capabilities } = await client.listCapabilities({ scope: "current_session" });

// Invoke a capability. The secret is injected server-side; the result returns redacted.
const res = await client.invoke({
  session_id: session.session_id,
  capability: "braintree.transactions.search",
  params: { status: "failed", date: "2026-06-21" },
  reason: "User asked me to summarize yesterday's failed payments.",
});

if (res.decision.decision === "requires_approval") {
  console.log("Waiting on a human:", res.decision.approval?.message);
} else if (res.decision.decision === "allow") {
  console.log(res.result); // already redacted
}
```

Denials throw a `PermauraApiError` whose `.reason` carries the human-readable policy explanation:

```ts
import { PermauraApiError } from "@permaura/sdk";

try {
  await client.invoke({ capability: "braintree.transactions.refund", params: {} });
} catch (err) {
  if (err instanceof PermauraApiError) console.error(err.reason);
}
```

## Authoring a connector

A connector describes risk-tiered capabilities over a real upstream API. `execute` receives whatever secret the caller of `invoke` passes; it should use it and never return it.

```ts
import { defineConnector, redact } from "@permaura/sdk";
import { z } from "zod";

const braintree = defineConnector({
  id: "braintree",
  capabilities: [
    {
      id: "transactions.search",
      risk: "medium",
      description: "Search Braintree transactions",
      inputSchema: z.object({
        status: z.enum(["settled", "failed", "voided"]).optional(),
        date: z.string().optional(),
      }),
      execute: async ({ input, secret, context }) => {
        const result = await braintreeApi.search(input, secret);
        // Scrub card data and any fields the caller passed in context.redactFields.
        return redact(result, { fields: context.redactFields });
      },
    },
    {
      id: "transactions.refund",
      risk: "critical",
      requiresApproval: true,
      inputSchema: z.object({ transactionId: z.string(), amount: z.number() }),
      execute: async ({ input, secret }) => braintreeApi.refund(input, secret),
    },
  ],
});

// Agent-safe specs: risk, description, JSON-Schema input, no execution detail.
console.log(braintree.specs);
//=> [{ id: "braintree.transactions.search", risk: "medium", ... }, ...]
```

`redact()` strips an explicit field list plus a built-in set of always-dangerous keys (api keys, tokens, authorization headers, cookies, card PAN/CVV, private keys, passwords, database URLs). Use `redactWithCount()` when you also want the number of fields it redacted.

## Build

```bash
pnpm build      # tsup -> dist (esm + .d.ts)
pnpm typecheck  # tsc --noEmit
```
