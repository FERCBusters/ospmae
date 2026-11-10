#!/usr/bin/env bash
# Run OSPMAE backend and frontend contracts against a disposable test database.
set -euo pipefail
ospmae_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${OSPMAE_TEST_DATABASE_URL:?Set OSPMAE_TEST_DATABASE_URL to a disposable database (never production)}"
command -v node >/dev/null
export OSPMAE_DATABASE_URL="$OSPMAE_TEST_DATABASE_URL"
export AWS_EC2_METADATA_DISABLED=true
export PYTHONUNBUFFERED=1
export TZ=UTC
export PYTHONPATH="$ospmae_root/services/api"
report_dir="$ospmae_root/test-results"
mkdir -p "$report_dir"
cd "$ospmae_root/services/api"

find_python() {
  if [ -n "${PYTHON_BIN:-}" ] && command -v "${PYTHON_BIN}" >/dev/null; then
    echo "${PYTHON_BIN}"
  elif command -v python3 >/dev/null; then
    echo python3
  else
    echo python
  fi
}
PY=""
if [ -n "${PYTHON_BIN:-}" ] && command -v "${PYTHON_BIN}" >/dev/null; then PY="${PYTHON_BIN}"; elif command -v python3 >/dev/null; then PY="python3"; fi
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ]; then PY="${VIRTUAL_ENV}/bin/python"; fi
if command -v poetry >/dev/null && poetry env info -p >/dev/null 2>&1; then
  poetry_bin="$(poetry env info -p)/bin/python"
  if [ -x "$poetry_bin" ]; then PY="$poetry_bin"; fi
fi

"$PY" - <<'PY'
import os, time
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
url = os.environ['OSPMAE_TEST_DATABASE_URL']
if make_url(url).get_backend_name() == 'postgresql':
    engine = create_engine(url, connect_args={'connect_timeout': 3})
    for attempt in range(10):
        try:
            with engine.connect() as connection:
                connection.execute(text('SELECT 1'))
            break
        except Exception:
            if attempt == 9:
                raise SystemExit('Test PostgreSQL did not become ready.') from None
            time.sleep(1)
    engine.dispose()
PY

result=0
# Every statement and branch of the API is covered; untested lines and branches
# fail the run. The coverage requirement tracks the measured level in
# coverage-requirement.txt until the suite reaches 100 for every module.
requirement=$(cat "$ospmae_root/coverage-requirement.txt" 2>/dev/null || echo 100)
"$PY" -m pytest tests -ra --tb=short \
  --junitxml="$report_dir/pytest.xml" \
  --cov=app --cov-branch "--cov-fail-under=$requirement" \
  --cov-report=term:skip-covered \
  --cov-report="xml:$report_dir/backend-coverage.xml" \
  --cov-report="json:$report_dir/backend-coverage.json" \
  --cov-report="html:$report_dir/backend-coverage" || result=1

# A missing test-DB setting must never turn the full CI job green via skips.
"$PY" - "$report_dir/pytest.xml" <<'PY' || result=1
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
cases = list(root.iter('testcase'))
if not cases:
    raise SystemExit('No tests were reported.')
skipped = [c.attrib.get('name', '?') for c in cases if c.find('skipped') is not None]
if skipped:
    raise SystemExit('Full suite unexpectedly skipped tests: ' + ', '.join(skipped))
PY

# Exercise DOM workflows and record frontend coverage; still run after backend failures.
bash "$ospmae_root/tests-ui.sh" || result=1

# Also check syntax in first-party pages not yet exercised by behavioural tests.
# Page scripts that use ESM syntax stay modules for the parse check.
while IFS= read -r -d '' file; do
  if head -c 4096 "$file" | grep -qE '^[[:space:]]*(import|export) '; then
    node --input-type=module --check < "$file" || result=1
  else
    node --check "$file" || result=1
  fi
done < <(find "$ospmae_root/services/ui/public" -path '*/vendor' -prune -o -type f -name '*.js' -print0)
exit "$result"
