#!/usr/bin/env sh
set -eu

export PATH="/app/.venv/bin:$PATH"
export PYTHONPATH="${PYTHONPATH:-/app}"

# One task per process at a time, and processes are replaced periodically, so
# a scan that leaks memory or file handles cannot accumulate.
exec celery -A app.celery_app.celery_app worker --loglevel=INFO --without-heartbeat --without-gossip --without-mingle \
  --concurrency="${OSPMAE_WORKER_CONCURRENCY:-2}" --prefetch-multiplier=1 --max-tasks-per-child=100
