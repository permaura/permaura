/**
 * Permaura example connector: Stripe (read-only).
 *
 * The narrowest, safest possible payments connector: it exposes ONLY read capabilities. There is no charge, no refund, no subscription update: those capabilities are not defined, so an agent (or an injection steering one) has nothing dangerous to call. This is the right starting posture for financial data: let the agent diagnose and summarize, never move money.
 *
 * An illustrative sketch against the SDK's `defineConnector`. The gateway does not load this file, and `httpRequest` stands in for your own HTTP client: the SDK does not export one. Whoever calls `invoke` supplies the secret.
 */

import { defineConnector, redact, httpRequest } from "@permaura/sdk";
import { z } from "zod";

const STRIPE_BASE_URL = "https://api.stripe.com/v1";

// Stripe responses can contain card details, billing addresses, and emails. Strip them at the source; Permaura's gateway redaction is the backstop.
const STRIPE_REDACT_FIELDS = [
  "number",
  "cvc",
  "exp_month",
  "exp_year",
  "address",
  "email",
  "phone",
  "client_secret",
];

const ListSchema = z.object({
  limit: z.number().int().min(1).max(100).default(20),
  // A Stripe cursor for pagination; opaque, so just length-bounded.
  startingAfter: z.string().max(255).optional(),
});

const ChargeReadSchema = z.object({
  chargeId: z.string().min(1).max(255).regex(/^ch_[A-Za-z0-9]+$/),
});

const CustomerReadSchema = z.object({
  customerId: z.string().min(1).max(255).regex(/^cus_[A-Za-z0-9]+$/),
});

export const stripeConnector = defineConnector({
  id: "stripe",
  capabilities: [
    {
      id: "charges.list",
      risk: "medium",
      inputSchema: ListSchema,
      execute: async ({ input, secret }) => {
        const response = await httpRequest({
          method: "GET",
          url: `${STRIPE_BASE_URL}/charges`,
          query: { limit: input.limit, starting_after: input.startingAfter },
          auth: { type: "bearer", secret },
        });
        return redact(response.body, { fields: STRIPE_REDACT_FIELDS });
      },
    },
    {
      id: "charges.read",
      risk: "medium",
      inputSchema: ChargeReadSchema,
      execute: async ({ input, secret }) => {
        const response = await httpRequest({
          method: "GET",
          url: `${STRIPE_BASE_URL}/charges/${input.chargeId}`,
          auth: { type: "bearer", secret },
        });
        return redact(response.body, { fields: STRIPE_REDACT_FIELDS });
      },
    },
    {
      id: "customers.read",
      risk: "medium",
      inputSchema: CustomerReadSchema,
      execute: async ({ input, secret }) => {
        const response = await httpRequest({
          method: "GET",
          url: `${STRIPE_BASE_URL}/customers/${input.customerId}`,
          auth: { type: "bearer", secret },
        });
        return redact(response.body, { fields: STRIPE_REDACT_FIELDS });
      },
    },
    {
      id: "disputes.list",
      risk: "medium",
      inputSchema: ListSchema,
      execute: async ({ input, secret }) => {
        const response = await httpRequest({
          method: "GET",
          url: `${STRIPE_BASE_URL}/disputes`,
          query: { limit: input.limit, starting_after: input.startingAfter },
          auth: { type: "bearer", secret },
        });
        return redact(response.body, { fields: STRIPE_REDACT_FIELDS });
      },
    },
  ],
  // No charges.create, refunds.create, subscriptions.update, or customers.delete. A read-only connector cannot be coerced into a write because the write capabilities do not exist.
});

export default stripeConnector;
