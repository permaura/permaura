import * as React from "react";
import { cn } from "../cn.js";

/** Coarse status states used across the console: sessions, devices, the broker itself. */
export type Status = "online" | "pending" | "offline" | "error";

export interface StatusDotProps extends React.HTMLAttributes<HTMLSpanElement> {
  status: Status;
  /** Optional text label rendered after the dot. */
  label?: string;
  /** Gently pulse the dot, appropriate for `pending`/`online` live states. */
  pulse?: boolean;
  /** Dot diameter in px. Defaults to 8. */
  size?: number;
}

const STATUS_VARS: Record<Status, string> = {
  online: "var(--bst-status-online)",
  pending: "var(--bst-status-pending)",
  offline: "var(--bst-status-offline)",
  error: "var(--bst-status-error)",
};

const STATUS_LABEL: Record<Status, string> = {
  online: "Online",
  pending: "Pending",
  offline: "Offline",
  error: "Error",
};

/**
 * A coloured status dot with an optional label, optionally pulsing. Used on the agents list, device rows, and the menu-bar broker status. The pulse animation is injected once via a keyframes style tag scoped by class name.
 */
export const StatusDot = React.forwardRef<HTMLSpanElement, StatusDotProps>(
  ({ status, label, pulse = false, size = 8, className, style, ...rest }, ref) => {
    const color = STATUS_VARS[status];
    return (
      <span
        ref={ref}
        data-status={status}
        className={cn("bst-status-dot", className)}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          fontFamily: "var(--bst-font-sans)",
          fontSize: 13,
          color: "var(--bst-fg-muted)",
          ...style,
        }}
        {...rest}
      >
        <span
          aria-hidden
          style={{
            position: "relative",
            width: size,
            height: size,
            borderRadius: "50%",
            background: color,
            flex: "none",
            boxShadow: pulse ? `0 0 0 0 ${color}` : undefined,
            animation: pulse ? "bst-pulse 1.8s ease-out infinite" : undefined,
          }}
        />
        {label ?? STATUS_LABEL[status]}
        {pulse ? (
          <style>{`@keyframes bst-pulse {0% {box-shadow: 0 0 0 0 ${color}66;} 70% {box-shadow: 0 0 0 6px ${color}00;} 100% {box-shadow: 0 0 0 0 ${color}00;}}`}</style>
        ) : null}
      </span>
    );
  },
);
StatusDot.displayName = "StatusDot";
