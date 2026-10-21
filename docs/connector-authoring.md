# Connector authoring

A *connector* teaches Permaura how to perform a family of actions against an external system (GitHub, Stripe, Braintree, an internal API) as a set of named *capabilities*. `defineConnector` (TypeScript) and `define_connector` (Python) are SDK helpers for describing capabilities and running them in your own process with a secret you supply: the gateway does not load or run SDK connectors. Capabilities the gateway enforces come from its built-in connectors, presets, installed manifests, OpenAPI and WordPress imports, and SSH connections.

This document covers `defineConnector` in TypeScript and Python: capability ids, risk tiers, `requiresApproval`, redaction, and input schemas. Illustrative sketches live in [`examples/`](../examples).

## The shape

A connector has an `id` and a list of capabilities. Each capability has:

- **`id`**: the dotted action path, combined with the connector id to form the full capability id. Connector `braintree` + capability `transactions.search` → `braintree.transactions.search`.
- **`risk`**: one of `low`, `medium`, `high`, `critical`. This sets the default policy behavior (see [policy-language.md](./policy-language.md)).
- **`requiresApproval`**: optional. Recorded in the capability's spec; on a capability the gateway runs, the equivalent flag holds every call at the `approve` rung whatever the policy says, and the operator token or a paired device resolves it.
- **`inputSchema`**: a Zod schema in TS, or a validating callable in Python, that the SDK's `invoke` applies to the parameters *before* `execute` runs. The gateway does not run it.
- **`execute`**: an async function receiving `{ input, secret, context }` and returning a result that has been run through `redact`. The `secret` is whatever the caller of `invoke` passes; the function never returns it.

## TypeScript

The TypeScript SDK (`@permaura/sdk`) exposes `defineConnector`, `redact`, and risk helpers. A minimal, real connector:

```ts
import { defineConnector, redact } from "@permaura/sdk";
import { z } from "zod";

// Input schemas validate untrusted, agent-supplied parameters before anything runs.
const TransactionSearchSchema = z.object({
  status: z.enum(["settled", "failed", "voided", "authorized"]).optional(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  limit: z.number().int().min(1).max(200).default(50),
});

const RefundSchema = z.object({
  transactionId: z.string().min(1),
  amount: z.number().positive(),
  currency: z.string().length(3),
});

export const braintree = defineConnector({
  id: "braintree",
  capabilities: [
    {
      id: "transactions.search",
      risk: "medium",
      inputSchema: TransactionSearchSchema,
      // `secret` is whatever the caller of `invoke` passes. Never return it; redact the result before returning it.
      execute: async ({ input, secret, context }) => {
        const result = await braintreeApi.transactions.search(input, secret);
        return redact(result, {
          fields: ["card_number", "cvv", "billing_address", "customer_email"],
        });
      },
    },
    {
      id: "transactions.refund",
      risk: "critical",
      requiresApproval: true, // recorded in the spec; the SDK itself enforces nothing
      inputSchema: RefundSchema,
      execute: async ({ input, secret }) => {
        return braintreeApi.transactions.refund(input, secret);
      },
    },
  ],
});
```

### Notes on the TS shape

- `risk: "critical"` plus `requiresApproval: true` is the belt-and-suspenders pattern for irreversible actions. On a capability the gateway runs, even if a policy allows the action, a capability flagged this way is still held at the `approve` rung, which the operator token or a paired device resolves.
- `redact` is called inside `execute` because nothing else will: the gateway's own redaction applies to the capabilities it runs, not to an SDK connector running in your process.
- `context` carries whatever the caller of `invoke` supplies (session id, principal, account, redaction fields, execution location, reason). No policy runs before `execute` in the SDK, so nothing in `context` is a decision to rely on.
- An exception thrown inside `execute` propagates unchanged to whoever called `invoke`; the SDK does not scrub it, so never put the secret in an error message.

## Python

The Python SDK (`permaura`) mirrors the TypeScript shape. Its `input_schema` is a callable that validates and returns the input, so a Pydantic model needs a one-line adapter, and `execute` receives the input and an `ExecuteContext` carrying the secret.

```python
from typing import Any, Mapping, Optional

from pydantic import BaseModel, Field, conint, constr

from permaura import Capability, define_connector, redact
from permaura.types import RiskTier


class TransactionSearch(BaseModel):
    status: Optional[str] = Field(default=None, pattern="^(settled|failed|voided|authorized)$")
    date: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    limit: conint(ge=1, le=200) = 50


class Refund(BaseModel):
    transaction_id: constr(min_length=1)
    amount: float = Field(gt=0)
    currency: constr(min_length=3, max_length=3)


def validated(model: type[BaseModel]):
    return lambda data: model(**data).model_dump()


def search_transactions(input: Mapping[str, Any], ctx):
    # `ctx.secret` is whatever the caller of `invoke` passed. Never return it; redact the result.
    result = braintree_api.transactions.search(input, ctx.secret)
    return redact(result, fields=["card_number", "cvv", "billing_address", "customer_email"])


def refund_transaction(input: Mapping[str, Any], ctx):
    return braintree_api.transactions.refund(input, ctx.secret)


braintree = define_connector(
    id="braintree",
    capabilities=[
        Capability(
            id="transactions.search",
            risk=RiskTier.MEDIUM,
            input_schema=validated(TransactionSearch),
            execute=search_transactions,
        ),
        Capability(
            id="transactions.refund",
            risk=RiskTier.CRITICAL,
            requires_approval=True,
            input_schema=validated(Refund),
            execute=refund_transaction,
        ),
    ],
)
```

The Python and TypeScript SDKs intentionally use the same field names where the language allows (`risk`, `requires_approval` / `requiresApproval`, `input_schema` / `inputSchema`, `execute`) so a connector reads the same in either language.

## Capability ids

The full capability id is `<connector>.<action>`. The action portion is a dotted path whose leaf maps to a normalized verb:

```text
braintree.transactions.search   →  verb: search   →  default risk: medium
braintree.transactions.refund   →  verb: refund   →  default risk: critical
github.pull_requests.create     →  verb: create   →  default risk: high
stripe.charges.read             →  verb: read     →  default risk: medium
```

Keep ids stable: agents, grants, and audit events all reference them. Renaming a capability id is a breaking change for every grant that names it.

## Risk and approval

The `risk` you declare is the default policy behavior. A policy can require approval for a `medium` action it considers sensitive (its `requires_approval` list), but nothing can lower the floor that `high` and `critical` risk set. Use `requiresApproval: true` on the capability when the action is *inherently* dangerous (refunds, charges, deletes, prod secret rotation) so the approval hold travels with the capability and does not depend on every policy author remembering to add it.

| Action kind | Suggested `risk` | `requiresApproval` |
| --- | --- | --- |
| read / list / search | `low` or `medium` | no |
| export | `high` (already held for approval by its risk) | no |
| create / update / deploy (non-prod) | `high` (already held for approval by its risk) | no |
| refund / charge / delete / prod deploy / rotate_secret | `critical` | yes |

## Redaction

Two layers protect responses:

1. **In-connector**: call `redact(result, { fields: [...] })` (TS) / `redact(result, fields=[...])` (Python) inside `execute`. Declare the fields the integration is known to expose: card numbers, CVVs, emails, addresses, tokens.
2. **Gateway backstop**: for the capabilities it runs, the gateway replaces the value of any field named in its default set (`api_key`, `token`, `authorization`, `cookie`, `password`, `secret`, `private_key`, `card_number`, `pan`, `cvv`, `ssn`, `database_url` and similar), plus the `redact_fields` of the connection and of every policy that permits the call, and scrubs any copy of the injected secret itself (8 bytes or longer) from the response. An SDK connector running in your own process gets only the first layer.

Never return the `secret`, and never echo an inbound authorization header. If a connector must surface *some* identifying field (a masked last-4), mask it inside `execute` rather than relying on downstream redaction to guess.

## Input schemas

In the SDK, `inputSchema` is the validation boundary between untrusted input and the upstream call: `invoke` applies it *before* `execute`. Use it to:

- constrain enums and formats (a date must look like a date, a status must be a known value),
- bound sizes (`limit` capped at 200, `amount` positive),
- reject anything unexpected (prefer strict schemas that drop unknown keys).

In the SDK, a request that fails `inputSchema` never reaches `execute`; nothing is audited, because the SDK has no audit log. The gateway does not validate types or bounds: its capabilities forward only the parameter names they declare.

## How a gateway capability runs end-to-end

1. Agent calls `permaura_invoke` with `capability: "braintree.transactions.search"`, `params`, and a `reason`.
2. The gateway resolves the capability from its catalog and keeps only the parameter names it declares.
3. The policy engine evaluates the agent's grants and the capability's risk → `allow` / `deny` / `requires_approval`.
4. On `allow` (or after approval), the gateway opens the secret and makes the upstream call the capability pins.
5. The gateway redacts the response by field name and scrubs any copy of the injected secret.
6. The agent receives the result; the audit event records the capability, the decision, the agent and session, the upstream status, the shape of the result (record, field or character counts) and the grant and policy that allowed it.

An SDK connector is not part of this loop: it runs only in a process that calls its `invoke`, with whatever secret that process supplies, and none of the identity, policy, approval, redaction backstop or audit above applies to it.

## Command connectors on Windows

A command connector runs a fixed, allow-listed `program` with an argv vector, passed to the OS
directly, never through a shell (`Command::new(program).args(args)`). Windows resolves the program
differently from Unix, and Permaura does **not** emulate `PATHEXT`, so the `program` value must be a
form Windows can actually launch:

| `program` form | Example | Launches? |
|---|---|---|
| Explicit executable | `vercel.exe`, `tool.com` | Yes, directly |
| Absolute / relative path | `C:\tools\vercel.cmd`, `./run` | Yes (the OS has the full spec) |
| Explicit batch script | `deploy.cmd`, `deploy.bat` | Yes, via `cmd.exe` delegation (the runtime escapes the args) |
| Bare name → a real `.exe` on `PATH` | `node`, `git`, `python` | Yes (`CreateProcess` auto-appends `.exe`) |
| **Bare name → a `.cmd`/`.bat` `PATH` shim** | `npm`, `yarn`, `pnpm`, `vercel` | **No** |

The last row is the trap: npm/yarn/pnpm global installs (and many Node CLIs like `vercel`) put a
`*.cmd` shim on `PATH`, and Windows' `CreateProcess` only auto-appends `.exe`: it will not find the
`.cmd`. Set the connector `program` to the explicit `vercel.cmd` (or an absolute path) instead of the
bare `vercel`. macOS and Linux resolve all bare names via `PATH` as usual, so this only affects
Windows connectors. When a bare-name launch fails on Windows, the gateway's error message says
exactly this and how to fix it.
