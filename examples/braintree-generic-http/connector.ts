/**
 * Permaura example connector: Braintree via the generic HTTP template.
 *
 * An illustrative sketch against the SDK's `defineConnector`. It shows the full risk-tier story on one connector, a medium-risk read (`transactions.search`) and a critical, approval-gated write (`transactions.refund`), plus redaction of payment data.
 *
 * The gateway does not load this file, and `httpRequest` stands in for your own HTTP client: the SDK does not export one. Whoever calls `invoke` supplies the secret.
 */

import { defineConnector, redact, httpRequest } from "@permaura/sdk";
import { z } from "zod";

// The generic-HTTP template is configured with a base URL, an auth method, and allow/deny lists. In a real deployment these come from the integration_account config; inlined here for clarity.
const BRAINTREE_BASE_URL = "https://api.braintreegateway.com";

// ---------------------------------------------------------------------------
// Input schemas. transactions.search is read-only and forgiving; refund is
// strict because it moves money: amount must be positive, currency a 3-letter
// code, and the transaction id non-empty.
// ---------------------------------------------------------------------------

const TransactionSearchSchema = z.object({
  status: z.enum(["settled", "failed", "voided", "authorized", "submitted_for_settlement"]).optional(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  limit: z.number().int().min(1).max(200).default(50),
});

const RefundSchema = z.object({
  transactionId: z.string().min(1).max(64),
  amount: z.number().positive(),
  currency: z.string().length(3),
});

// Payment payloads carry exactly the fields you never want an agent to see. These are stripped at the source; Permaura's gateway redaction is a second backstop.
const PAYMENT_REDACT_FIELDS = [
  "card_number",
  "cvv",
  "billing_address",
  "customer_email",
  "payment_method_token",
];

// ---------------------------------------------------------------------------
// The connector.
// ---------------------------------------------------------------------------

export const braintreeConnector = defineConnector({
  id: "braintree",
  capabilities: [
    {
      // Reading transactions is medium risk: useful, reversible, but it touches
      // customer/payment data, so it is allowed within a grant WITH masking.
      id: "transactions.search",
      risk: "medium",
      inputSchema: TransactionSearchSchema,
      execute: async ({ input, secret }) => {
        // The secret is injected as the API credential for this outbound call only. It is never returned and never logged.
        const response = await httpRequest({
          method: "GET",
          url: `${BRAINTREE_BASE_URL}/transactions`,
          query: {
            status: input.status,
            date: input.date,
            limit: input.limit,
          },
          auth: { type: "api_key", secret },
        });

        return redact(response.body, { fields: PAYMENT_REDACT_FIELDS });
      },
    },
    {
      // Refunds are CRITICAL: irreversible movement of money. requiresApproval
      // means a human approves every single one (single-use, bound to these
      // exact parameters) regardless of what any grant says. This is the
      // belt-and-suspenders pattern from the docs.
      id: "transactions.refund",
      risk: "critical",
      requiresApproval: true,
      inputSchema: RefundSchema,
      execute: async ({ input, secret }) => {
        const response = await httpRequest({
          method: "POST",
          url: `${BRAINTREE_BASE_URL}/transactions/${input.transactionId}/refund`,
          body: {
            amount: input.amount,
            currency: input.currency,
          },
          auth: { type: "api_key", secret },
        });

        // Even the refund confirmation gets redacted: no need to echo card data back to the agent.
        return redact(response.body, { fields: PAYMENT_REDACT_FIELDS });
      },
    },
  ],
});

export default braintreeConnector;
