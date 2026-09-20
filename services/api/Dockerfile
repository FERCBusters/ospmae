FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    git \
    openssh-client \
    ca-certificates \
    python3-poetry \
    python3-venv \
    cosign \
  && rm -rf /var/lib/apt/lists/*

# Install Syft for dependency cataloging and Grype for optional vulnerability
# scanning in the worker. OSPMAE_SYFT_ENABLED and OSPMAE_GRYPE_ENABLED control
# whether scans actually invoke these binaries.
RUN curl -sSfL https://get.anchore.io/syft | sh -s -- -v -b /usr/local/bin \
 && curl -sSfL https://get.anchore.io/grype | sh -s -- -v -b /usr/local/bin

COPY pyproject.toml poetry.lock* /app/

# Make poetry put the venv in /app/.venv and use the image's Python
RUN poetry config virtualenvs.in-project true \
 && poetry env use /usr/local/bin/python \
 && if [ -f poetry.lock ]; then \
      poetry install --no-interaction --no-ansi --only main --no-root; \
    else \
      poetry lock --no-interaction --no-ansi \
   && poetry install --no-interaction --no-ansi --only main --no-root; \
    fi

# Make the venv the default Python for runtime
ENV PATH="/app/.venv/bin:$PATH"

COPY app /app/app
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic
COPY scripts /app/scripts

RUN chmod +x /app/scripts/start.sh /app/scripts/start-celery-worker.sh /app/scripts/start-celery-beat.sh

# Create non-root runtime user
RUN addgroup --system --gid 10001 ospmae \
 && adduser --system --uid 10001 --ingroup ospmae --home /home/ospmae ospmae \
 && mkdir -p /var/lib/ospmae \
 && chown -R ospmae:ospmae /app /var/lib/ospmae

USER ospmae
ENV HOME=/home/ospmae

CMD ["/app/scripts/start.sh"]
