FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b

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
#
# Each scanner is a named release: the installer comes from that release's
# own tag, installs that version only, and (-v) verifies the release's signed
# checksums with cosign before unpacking. Raise a version here to update.
ARG SYFT_VERSION=1.54.0
ARG GRYPE_VERSION=0.117.0
RUN curl -sSfL "https://raw.githubusercontent.com/anchore/syft/v${SYFT_VERSION}/install.sh" \
      | sh -s -- -v -b /usr/local/bin "v${SYFT_VERSION}" \
 && curl -sSfL "https://raw.githubusercontent.com/anchore/grype/v${GRYPE_VERSION}/install.sh" \
      | sh -s -- -v -b /usr/local/bin "v${GRYPE_VERSION}" \
 && syft version | grep -F "${SYFT_VERSION}" \
 && grype version | grep -F "${GRYPE_VERSION}"

# The lock is part of the build: without it the build stops instead of
# resolving whatever versions are newest that day.
COPY pyproject.toml poetry.lock /app/

# Make poetry put the venv in /app/.venv and use the image's Python
RUN poetry config virtualenvs.in-project true \
 && poetry env use /usr/local/bin/python \
 && poetry install --no-interaction --no-ansi --only main --no-root

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
