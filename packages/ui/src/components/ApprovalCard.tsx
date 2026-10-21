import * as React from "react";
import { cn } from "../cn.js";
import { RiskBadge, type RiskTier } from "./RiskBadge.js";

/** Approval mechanisms, mirroring `ApprovalType` in @permaura/types. */
export type ApprovalType = "touch_id" | "push" | "two_person";

export interface ApprovalCardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** The human-facing prompt, e.g. "Codex wants to refund AUD 49.00 for Braintree transaction abc123." */
  message: string;
  /** Capability being gated, e.g. `braintree.transactions.refund`. */
  capability?: string;
  /** Which agent is asking, e.g. `codex-cli`. */
  agent?: string;
  risk?: RiskTier;
  type?: ApprovalType;
  /** When true, the approval authorizes exactly one execution. Defaults to true. */
  singleUse?: boolean;
  /** Disable the buttons while a decision is in flight. */
  busy?: boolean;
  onApprove?: () => void;
  onDeny?: () => void;
}

const APPROVAL_LABEL: Record<ApprovalType, string> = {
  touch_id: "Touch ID",
  push: "Device approval",
  two_person: "Two-person approval",
};

/**
 * The card shown when a high-risk action is held for human approval, the visual centrepiece of the "patient 0" demo, where a prompt-injected refund is intercepted. It surfaces who is asking, what they want, the risk tier, and the approval method, with Approve / Deny actions.
 *
 * This is a controlled, presentational component: it renders state and emits intent via `onApprove` / `onDeny`; the host wires those to `PermauraClient.resolveApproval`.
 */
export const ApprovalCard = React.forwardRef<HTMLDivElement, ApprovalCardProps>(
  (
    {
      message,
      capability,
      agent,
      risk = "critical",
      type = "touch_id",
      singleUse = true,
      busy = false,
      onApprove,
      onDeny,
      className,
      style,
      ...rest
    },
    ref,
  ) => {
    return (
      <div
        ref={ref}
        role="group"
        aria-label="Approval request"
        className={cn("bst-approval-card", className)}
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 14,
          padding: 18,
          maxWidth: 420,
          background: "var(--bst-surface)",
          border: "1px solid var(--bst-border-strong)",
          borderRadius: "var(--bst-radius-lg)",
          boxShadow: "var(--bst-shadow)",
          fontFamily: "var(--bst-font-sans)",
          color: "var(--bst-fg)",
          ...style,
        }}
        {...rest}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--bst-fg-muted)" }}>
            Approval required
          </span>
          <RiskBadge risk={risk} />
        </div>

        <p style={{ margin: 0, fontSize: 15, lineHeight: 1.5 }}>{message}</p>

        {(agent || capability) && (
          <dl
            style={{
              display: "grid",
              gridTemplateColumns: "auto 1fr",
              rowGap: 4,
              columnGap: 12,
              margin: 0,
              fontSize: 12,
              color: "var(--bst-fg-subtle)",
            }}
          >
            {agent ? (
              <>
                <dt>Agent</dt>
                <dd style={{ margin: 0, fontFamily: "var(--bst-font-mono)", color: "var(--bst-fg-muted)" }}>{agent}</dd>
              </>
            ) : null}
            {capability ? (
              <>
                <dt>Capability</dt>
                <dd style={{ margin: 0, fontFamily: "var(--bst-font-mono)", color: "var(--bst-fg-muted)" }}>{capability}</dd>
              </>
            ) : null}
            <dt>Method</dt>
            <dd style={{ margin: 0, color: "var(--bst-fg-muted)" }}>
              {APPROVAL_LABEL[type]}
              {singleUse ? " · single-use" : ""}
            </dd>
          </dl>
        )}

        <div style={{ display: "flex", gap: 10, marginTop: 2 }}>
          <button
            type="button"
            disabled={busy}
            onClick={onDeny}
            style={{
              flex: 1,
              padding: "9px 14px",
              borderRadius: "var(--bst-radius)",
              border: "1px solid var(--bst-border-strong)",
              background: "transparent",
              color: "var(--bst-fg)",
              fontWeight: 600,
              fontSize: 14,
              cursor: busy ? "not-allowed" : "pointer",
              opacity: busy ? 0.6 : 1,
            }}
          >
            Deny
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={onApprove}
            style={{
              flex: 1,
              padding: "9px 14px",
              borderRadius: "var(--bst-radius)",
              border: "1px solid transparent",
              background: "var(--bst-accent)",
              color: "var(--bst-accent-fg)",
              fontWeight: 600,
              fontSize: 14,
              cursor: busy ? "not-allowed" : "pointer",
              opacity: busy ? 0.6 : 1,
            }}
          >
            Approve
          </button>
        </div>
      </div>
    );
  },
);
ApprovalCard.displayName = "ApprovalCard";
