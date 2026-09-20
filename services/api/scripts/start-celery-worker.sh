#!/usr/bin/env sh
set -eu

export PATH="/app/.venv/bin:$PATH"
export PYTHONPATH="${PYTHONPATH:-/app}"

exec celery -A app.celery_app.celery_app worker --loglevel=INFO --without-heartbeat --without-gossip --without-mingle
