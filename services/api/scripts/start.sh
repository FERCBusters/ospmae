#!/usr/bin/env bash
set -euo pipefail

cd /app
export PATH="/app/.venv/bin:$PATH"
export PYTHONPATH="${PYTHONPATH:-/app}"
: "${OSPMAE_DATABASE_URL:?OSPMAE_DATABASE_URL is required}"

echo "[component-api] waiting for database..."
python - <<'PYCODE'
import os, time
import sqlalchemy as sa

url = os.environ['OSPMAE_DATABASE_URL']
engine = sa.create_engine(url, pool_pre_ping=True)
deadline = time.time() + 60
while True:
    try:
        with engine.connect() as c:
            c.execute(sa.text('SELECT 1'))
        print('[component-api] database ready')
        break
    except Exception:
        if time.time() > deadline:
            raise
        time.sleep(1)
PYCODE

echo "[component-api] running migrations..."
alembic upgrade head

echo "[component-api] starting uvicorn..."
# Forwarded headers are read by the application, from OSPMAE_TRUSTED_PROXY_CIDRS
# only (app/security/client_addr.py); the server's own rewriting stays off.
exec uvicorn app.main:app --host "${OSPMAE_API_HOST:-0.0.0.0}" --port "${OSPMAE_API_PORT:-8080}" --no-proxy-headers
