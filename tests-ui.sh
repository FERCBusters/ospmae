#!/usr/bin/env bash
# npm ci --prefix services/ui/tests installs the locked, test-only DOM dependencies.
set -euo pipefail
ospmae_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ospmae_root"
report_dir="$ospmae_root/test-results"
mkdir -p "$report_dir"
if [ ! -f services/ui/tests/node_modules/c8/bin/c8.js ]; then
  echo 'Install frontend test dependencies: npm ci --prefix services/ui/tests' >&2
  exit 1
fi
# Every statement, branch and function of the first-party UI is covered. The
# requirement tracks coverage-requirement-ui.txt until the suite reaches 100.
requirement=$(cat "$ospmae_root/coverage-requirement-ui.txt" 2>/dev/null || echo 100)
requirement=$(echo "$requirement" | tr -d '[:space:]')
cd "$ospmae_root"
node services/ui/tests/node_modules/c8/bin/c8.js \
  --all --include='services/ui/public' --exclude='services/ui/public/vendor/**' \
  --check-coverage --statements "$requirement" --lines "$requirement" \
  --reporter=text-summary --reporter=json-summary --reporter=lcov --reporter=html \
  --reports-dir="$report_dir/frontend-coverage" \
  node --experimental-vm-modules --test \
  --test-reporter=spec --test-reporter=junit \
  --test-reporter-destination=stdout --test-reporter-destination="$report_dir/frontend.xml" \
  services/ui/tests/*.test.mjs
