#!/usr/bin/env bash
#
# The macOS half of CI, run locally before a push.
#
# CI builds and tests the workspace on Linux by default; this compiles and tests it on the machine you
# push from, usually a Mac. Clippy, cargo-audit and gitleaks run in CI, not here.
#
#   scripts/pre-push.sh              run the check
#   scripts/pre-push.sh --install    install it as this project's pre-push hook
#
# Bypass one push with `git push --no-verify`, or set PERMAURA_SKIP_PREPUSH=1.
set -euo pipefail

hooks_dir() {
  local custom
  custom=$(git config --get core.hooksPath || true)
  if [ -n "$custom" ]; then
    printf '%s\n' "$custom"
    return
  fi
  # A linked worktree keeps its `.git` as a file pointing at the shared repository, so hooks live in
  # the common dir and installing once covers every worktree of this project.
  printf '%s\n' "$(cd "$(git rev-parse --git-common-dir)" && pwd)/hooks"
}

if [ "${1:-}" = "--install" ]; then
  dir=$(hooks_dir)
  mkdir -p "$dir"
  # A shim rather than a symlink: the hook is shared by every worktree, so the path to this script
  # differs per invocation and has to be resolved at run time rather than baked in at install time.
  cat > "$dir/pre-push" <<'HOOK'
#!/usr/bin/env bash
script="$(git rev-parse --show-toplevel)/scripts/pre-push.sh"
# Absent on refs that predate it. A hook that blocks every push from an older branch, with an exec
# error rather than a reason, is worse than one that quietly does nothing there.
[ -x "$script" ] || exit 0
exec "$script"
HOOK
  chmod +x "$dir/pre-push"
  echo "installed $dir/pre-push"
  exit 0
fi

if [ -n "${PERMAURA_SKIP_PREPUSH:-}" ]; then
  echo "pre-push: skipped (PERMAURA_SKIP_PREPUSH set)"
  exit 0
fi

cd "$(git rev-parse --show-toplevel)"

# Saying so matters: on anything but a Mac this run is a duplicate of CI's Linux lane and covers
# nothing that CI does not already cover, so a pass here means less than it looks like it does.
if [ "$(uname -s)" != "Darwin" ]; then
  echo "pre-push: not macOS, so this does not stand in for the parked CI lane" >&2
fi

# CI skips docs-only pushes, and a doc is where a retracted security claim comes back, so the export's pattern test runs here too. It takes seconds and is absent from the public tree.
if [ -f scripts/test_public_export.py ]; then
  echo "pre-push: public export patterns"
  python3 scripts/test_public_export.py
fi

echo "pre-push: cargo test --workspace"
cargo test --workspace
