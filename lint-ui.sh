#!/usr/bin/env bash
# Checks first-party JavaScript for HTML insertion that bypasses escapeHtml(),
# locally, in pre-commit and in CI (ported from KEEN). Sites that predate the
# check are listed in services/ui/tests/eslint-suppressions.json; --prune
# removes entries once their sites are fixed, so the list only shrinks.
set -euo pipefail
ospmae_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ospmae_root"
mode="${1:---check}"
case "$mode" in
  --check) extra=() ;;
  --prune) extra=(--prune-suppressions) ;;
  --suppress-all) extra=(--suppress-all) ;;
  *) echo 'Use --check or --prune' >&2; exit 2 ;;
esac
linter=services/ui/tests/node_modules/eslint/bin/eslint.js
if [ ! -f "$linter" ]; then
  echo 'Install frontend tooling: npm ci --prefix services/ui/tests' >&2
  exit 1
fi
exec node "$linter" \
  --config services/ui/tests/eslint.config.mjs \
  --suppressions-location services/ui/tests/eslint-suppressions.json \
  ${extra[@]+"${extra[@]}"} \
  services/ui/public
