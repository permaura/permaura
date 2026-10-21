/**
 * Tiny class-name joiner. Filters out falsy values and joins with spaces. We keep this dependency-free (no `clsx`/`tailwind-merge`) so the package stays lean for the Tauri bundles: the components use token-driven inline-style fallbacks plus optional class hooks, not a utility-class framework.
 */
export type ClassValue = string | number | null | false | undefined;

export function cn(...values: ClassValue[]): string {
  return values.filter((v): v is string | number => Boolean(v)).join(" ");
}
