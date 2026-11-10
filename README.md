# OSPMAE - Open Source Project Management and Analysis Environment

OSPMAE encodes open-source projects, architectures, frameworks, standards, capabilities and their evidence requirements in machine-readable and visual forms. A project maintainer maps a release once; any adopter (or ecosystem operator) reads that mapping each time from the machine-readable record. The Grype/Syft dependency pipeline turns a project's repositories into a live source of vulnerability findings for the whole catalogue, and each release keeps an exportable record of what it contains.

Applications in the same family share a design system and conventions: **KEEN** (adopter-side assurance), OSPMAE (adoption readiness, this repository), and the **mosp-design-system** shared UI foundation.

## What is in the box

- **Projects and versions** - a catalogue of open-source projects with releases, drafts, subscriptions, changelog records and exportable manifests. Owners and owner groups manage their own projects; the catalogue is the common meeting point between project capabilities and adopter needs.
- **Frameworks and capability mapping** - architecture frameworks (Universal Wallet Reference Architecture by default) encoded as machine-readable trees with per-node capability definitions, project-to-framework mappings and D3 visualisations.
- **Dependency scanning** - an operator-configured Grype/Syft pipeline clones policy-permitted repositories (host allowlist, command allowlists, fixed scrubbed environment), parses lockfiles/SBOMs and records dependencies, vulnerabilities and remediation status against each version.
- **Comparisons** - side-by-side project/version diffs with capability matrices and dependency/vulnerability deltas, plus CSV/XLSX/PDF exports served as neutral attachments.
- **Questions and notifications** - account-threaded questions on project versions with role-based answer permissions, e-mail notifications, and realtime browser notification over a bounded WebSocket channel.
- **Authentication** - local accounts (PBKDF2/260k), OpenID Connect with per-provider configuration, optional trusted header identity from an authenticating proxy, database-backed sessions with rolling and absolute lifetimes, and CSRF-protected unsafe writes.

## Installation feature switches

Each optional product area answers 404 and disappears from the UI and background schedules when switched off in `.env` (`OSPMAE_FEATURE_*`, all default `true`):

| Switch | What it toggles |
| --- | --- |
| `OSPMAE_FEATURE_FRAMEWORKS` | framework management, capability trees, UWRA seeding |
| `OSPMAE_FEATURE_MANIFESTS` | manifest editing, sharing and export |
| `OSPMAE_FEATURE_QUESTIONS` | question threads, notifications bell |
| `OSPMAE_FEATURE_DEPENDENCY_SCANS` | Grype/Syft discovery, dependency dashboard, release feeds |
| `OSPMAE_FEATURE_COMPARISONS` | the project compare endpoint |
| `OSPMAE_FEATURE_RELEASE_FEED` | RSS/Atom release polling |

Authentication, projects, administration and the unified dependency/vulnerability dashboard stay available in every configuration.

## Running it

### Docker Compose (the supported deployment shape)

```bash
cp .env.example .env                # then edit the required values
docker compose up --build
```

`.env.example` documents every setting. Set the `:?`-guarded values (`POSTGRES_PASSWORD` and `REDIS_PASSWORD`) before the first `docker compose up`; compose refuses to start a deployment with either one missing.

The services:

- `component-ui` - nginx serving the built UI, proxying `/v1/` and `/ws/` to the API, adding the security headers and cache policy from `services/ui/nginx/default.conf`.
- `component-api` - the FastAPI application (uvicorn) alongside Celery workers and a beat scheduler.
- `postgres` / `valkey` - catalogue storage and the Celery broker.

Third-party container images are pinned by digest; `tools/docker_image_pins.py check` verifies that every tracked tag still resolves to its pinned digest, and the nightly workflow opens review when an upstream tag moves (see `.github/workflows/docker-image-pins.yml`).

### Environment settings worth knowing

| Setting | Purpose |
| --- | --- |
| `OSPMAE_PUBLIC_BASE_URL` | The origin used in links printed into e-mail (reset, approval, verification). Set this before enabling mail flows. |
| `OSPMAE_FEATURE_*` | Installation switches above. |
| `OSPMAE_LOCAL_AUTH_ENABLED`, `OSPMAE_PASSWORD_RESET_*` | Local accounts, reset/verification flows. |
| `OSPMAE_OIDC_*` (or `OSPMAE_GITHUB_*`) | SSO providers; each enabled provider requires explicit `CLIENT_ID`, `CLIENT_SECRET`, endpoints and `REDIRECT_URI`. |
| `OSPMAE_TRUST_REMOTE_USER` + `OSPMAE_REMOTE_USER_HEADER_NAME` | Trusted header identity for deployments where the network path alone reaches the API through the authenticating proxy. |
| `OSPMAE_TRUSTED_PROXY_CIDRS` | Networks whose hosts may form the trusted side of a forwarded client address chain (rate limits, audit records). |
| `OSPMAE_DEPENDENCY_DISCOVERY_*`, `OSPMAE_SYFT_*`, `OSPMAE_GRYPE_*` | Scan pipeline policy (host allowlist, time/memory budgets, scanner paths). |
| `OSPMAE_SMTP_*` | Outgoing mail. |

## Development

```bash
# API tests, lint, types (Poetry env)
cd services/api
poetry install --with dev --no-root
poetry run bash ../../tests.sh          # needs OSPMAE_TEST_DATABASE_URL

# UI tests and formatting
npm ci --prefix services/ui/tests
bash tests-ui.sh
bash format-ui.sh --check
```

`tests.sh` runs the whole CI surface locally: backend pytest with branch coverage against the configured disposable database (SQLite works; CI uses PostgreSQL), the no-skips guard, UI tests under c8, and syntax checks across first-party JavaScript. `.github/workflows/tests.yml` runs the same steps on every push. Documentation for development conventions lives in `AGENTS.md`; the deployment security model lives in `SECURITY.md`.

## Repository layout

```
services/api/           FastAPI application, Alembic migrations, tasks, tests
services/ui/            nginx + first-party pages, build tooling, tests
services/api/alembic/   Migrations (through 0027_user_preference_theme)
tools/                  docker-image-pins
.github/workflows/      CI (tests, docker-image-pins)
```

## Licence

See `LICENSE` and the bundled design-system licence (`services/ui/public/vendor/mosp-design-system/LICENSE` after a build).
