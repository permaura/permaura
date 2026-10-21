import * as React from "react";
import { cn } from "../cn.js";

/** Risk tiers, mirroring `RiskTier` in @permaura/types. Kept as a local literal so this package has no hard dependency on the types package (it is a pure presentational layer). */
export type RiskTier = "low" | "medium" | "high" | "critical";

export interface RiskBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  risk: RiskTier;
  /** Show a leading dot. Defaults to true. */
  dot?: boolean;
}

const RISK_LABEL: Record<RiskTier, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

const RISK_VARS: Record<RiskTier, { fg: string; bg: string }> = {
  low: { fg: "var(--bst-risk-low)", bg: "var(--bst-risk-low-soft)" },
  medium: { fg: "var(--bst-risk-medium)", bg: "var(--bst-risk-medium-soft)" },
  high: { fg: "var(--bst-risk-high)", bg: "var(--bst-risk-high-soft)" },
  critical: { fg: "var(--bst-risk-critical)", bg: "var(--bst-risk-critical-soft)" },
};

/**
 * A compact, colour-coded badge for a capability or action's risk tier. Colours are driven entirely by the token CSS variables so the badge re-themes with the rest of the app. Import `@permaura/ui/tokens.css` once for the variables to resolve.
 */
export const RiskBadge = React.forwardRef<HTMLSpanElement, RiskBadgeProps>(
  ({ risk, dot = true, className, style, ...rest }, ref) => {
    const vars = RISK_VARS[risk];
    return (
      <span
        ref={ref}
        data-risk={risk}
        className={cn("bst-risk-badge", className)}
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
        {dot ? (
          <span
            aria-hidden
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: vars.fg,
              flex: "none",
            }}
          />
        ) : null}
        {RISK_LABEL[risk]}
      </span>
    );
  },
);
RiskBadge.displayName = "RiskBadge";
