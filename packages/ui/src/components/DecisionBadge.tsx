import * as React from "react";
import { cn } from "../cn.js";

/** The three terminal policy outcomes, mirroring `DecisionKind` in @permaura/types. */
export type DecisionKind = "allow" | "deny" | "requires_approval";

export interface DecisionBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  decision: DecisionKind;
}

const DECISION_LABEL: Record<DecisionKind, string> = {
  allow: "Allowed",
  deny: "Denied",
  requires_approval: "Approval required",
};

const DECISION_VARS: Record<DecisionKind, { fg: string; bg: string }> = {
  allow: { fg: "var(--bst-allow)", bg: "var(--bst-allow-soft)" },
  deny: { fg: "var(--bst-deny)", bg: "var(--bst-deny-soft)" },
  requires_approval: { fg: "var(--bst-approval)", bg: "var(--bst-approval-soft)" },
};

/** Small inline glyph per decision (a check, a cross, a clock) drawn as inline SVG so there is no icon-font dependency. */
function DecisionGlyph({ decision }: { decision: DecisionKind }): React.ReactElement {
  const common = { width: 12, height: 12, viewBox: "0 0 16 16", fill: "none", "aria-hidden": true } as const;
  if (decision === "allow") {
    return (
      <svg {...common}>
        <path d="M3 8.5l3 3 7-7" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (decision === "deny") {
    return (
      <svg {...common}>
        <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth={2} strokeLinecap="round" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <circle cx={8} cy={8} r={6} stroke="currentColor" strokeWidth={1.6} />
      <path d="M8 5v3.2l2 1.4" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/**
 * A badge for a policy decision. Allow is green, deny is red, requires-approval is amber. This is the badge that appears on audit rows, the policy simulator, and the approval queue.
 */
export const DecisionBadge = React.forwardRef<HTMLSpanElement, DecisionBadgeProps>(
  ({ decision, className, style, ...rest }, ref) => {
    const vars = DECISION_VARS[decision];
    return (
      <span
        ref={ref}
        data-decision={decision}
        className={cn("bst-decision-badge", className)}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          padding: "2px 8px",
          borderRadius: "var(--bst-radius-sm)",
          fontFamily: "var(--bst-font-sans)",
          fontSize: 12,
          fontWeight: 600,
          lineHeight: 1.4,
          color: vars.fg,
          background: vars.bg,
          border: `1px solid ${vars.fg}33`,
          ...style,
        }}
        {...rest}
      >
        <DecisionGlyph decision={decision} />
        {DECISION_LABEL[decision]}
      </span>
    );
  },
);
DecisionBadge.displayName = "DecisionBadge";
