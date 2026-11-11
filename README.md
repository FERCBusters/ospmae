# OSPMAE - Open Source Project Management and Analysis Environment

OSPMAE encodes open-source projects, architectures, frameworks, standards, capabilities and their evidence requirements in machine-readable and visual forms. A project maintainer maps a release once; any adopter (or ecosystem operator) reads that mapping each time from the machine-readable record. The Grype/Syft dependency pipeline turns a project's repositories into a live source of vulnerability findings for the whole catalogue, and each release keeps an exportable record of what it contains.

Applications in the same family share a design system and conventions: **KEEN** (adopter-side assurance), OSPMAE (adoption readiness, this repository), and the **mosp-design-system** shared UI foundation.

## What is in the box

- **Projects and versions** - a catalogue of open-source projects with releases, drafts, subscriptions, changelog records and exportable manifests. Owners and owner groups manage their own projects; the catalogue is the common meeting point between project capabilities and adopter needs. A project can track one branch of its repository in place of releases: the branch head is re-cloned and scanned on an interval the owner chooses, once an hour at most. A project following a release feed stages each new release as a draft for its owners to publish, or publishes new releases as they arrive when the owner switches that on; the version that becomes Latest is scanned either way.
- **Frameworks and capability mapping** - architecture frameworks (Universal Wallet Reference Architecture by default) encoded as machine-readable trees with per-node capability definitions, project-to-framework mappings and D3 visualisations.
- **Dependency scanning** - an operator-configured Grype/Syft pipeline clones policy-permitted repositories (host allowlist, command allowlists, fixed scrubbed environment), parses lockfiles/SBOMs and records dependencies, vulnerabilities and remediation status against each version.
- **Comparisons** - side-by-side project/version diffs with capability matrices and dependency/vulnerability deltas, plus CSV/XLSX/PDF exports served as neutral attachments.
- **Questions and notifications** - account-threaded questions on project versions with role-based answer permissions, e-mail notifications, and realtime browser notification over a bounded WebSocket channel.
- **Organisations and dashboards** - organisations are first-class records that projects belong to (created from the free-text name on first use), with admin-managed user/group membership, a global dependency dashboard with per-project unfixed-finding summaries and organisation filters, and a searchable dependency browser keyed by UUID.
- **E-mail delivery** - outgoing mail is a transactional outbox: senders queue inside their own transaction and a worker delivers with exponential backoff, recording each attempt so a broken SMTP configuration is visible in the admin's E-mail outbox view (and users can see their own delivery history under Account).
- **Authentication** - local accounts (PBKDF2/260k) with a second factor (TOTP authenticator apps, WebAuthn security keys/passkeys and single-use recovery codes), OpenID Connect with per-provider configuration, optional trusted header identity from an authenticating proxy, database-backed sessions with rolling and absolute lifetimes, and CSRF-protected unsafe writes. The second factor applies to local sign-in under the `OSPMAE_MFA_POLICY` setting (`optional`, `admins`, or `all`); an account's enrolment change invalidates its existing local sessions, a five-minute browser ceremony runs outside the session cookie, and WebAuthn requires an HTTPS `OSPMAE_PUBLIC_BASE_URL`.

## Installation feature switches

Administrators switch optional product areas on and off on the Administration page (**Features** tab, `/admin.html#features`); a switched-off area answers 404, disappears from the UI and skips its background work, and its records are kept. Each save is checked against the configuration revision it started from, and every revision is kept. The deployment's `.env` switches (`OSPMAE_FEATURE_*`, all default `true`) are a ceiling: an area turned off there stays off and its switch on the page cannot turn it on.

| Switch | What it toggles |
| --- | --- |
| `OSPMAE_FEATURE_FRAMEWORKS` | framework management, capability trees, UWRA seeding |
| `OSPMAE_FEATURE_MANIFESTS` | manifest editing, sharing and export |
| `OSPMAE_FEATURE_QUESTIONS` | question threads, notifications bell |
| `OSPMAE_FEATURE_DEPENDENCY_SCANS` | Grype/Syft discovery, dependency dashboard, release feeds, tracked-branch re-scans |
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

### Initial user creation

Run the following to create the initial (admin) user:

```bash
docker compose exec -T component-api python - <<'PY'
from app.db.session import SessionLocal
from app.security.auth import create_user
db = SessionLocal()
try:
    create_user(
        db,
        username="admin",            # 1-64 chars: letters, digits, _ - .
        password="SomethingStrongHere!",  # >= 8 chars
        email="admin@example.com",   # optional: account and security mail
        role="admin",
    )
finally:
    db.close()
PY
```

### Second-factor recovery

When a local account has lost its authenticators and recovery codes, an operator removes them so the owner can sign in with the password and enrol again; the account's local sessions end and the owner is mailed a security notice:

```bash
docker compose exec component-api python scripts/mfa_admin.py USERNAME --reset --confirm-username USERNAME
```

### Environment settings worth knowing

| Setting | Purpose |
| --- | --- |
| `OSPMAE_PUBLIC_BASE_URL` | The origin used in links printed into e-mail (SSO email address verification, which needs HTTPS). Set this before enabling mail flows. |
| `OSPMAE_FEATURE_*` | Installation switches above. |
| `OSPMAE_LOCAL_AUTH_ENABLED` | Local password sign-in. Administrators create accounts, set their e-mail and reset passwords; single sign-on reaches existing accounts only. |
| `OSPMAE_MFA_POLICY`, `OSPMAE_MFA_ENCRYPTION_KEY` | Local second factor: `optional` (default), `admins` or `all` accounts must complete TOTP/security-key/recovery-code verification on local sign-in; the key is a persistent Fernet key (`openssl rand -base64 32`) that encrypts TOTP secrets at rest and belongs in your secrets manager. |
| `OSPMAE_OIDC_*` (or `OSPMAE_GITHUB_*`) | SSO providers; each enabled provider requires explicit `CLIENT_ID`, `CLIENT_SECRET`, endpoints and `REDIRECT_URI`. |
| `OSPMAE_TRUST_REMOTE_USER` + `OSPMAE_REMOTE_USER_HEADER_NAME` | Trusted header identity for deployments where the network path alone reaches the API through the authenticating proxy. |
| `OSPMAE_TRUSTED_PROXY_CIDRS` | Networks whose hosts may form the trusted side of a forwarded client address chain (rate limits, audit records). |
| Project `project_type` | Not a setting: it is a server-controlled vocabulary (ledger, identity, wallet, credentials, interoperability, privacy, cryptography, governance, tooling, library, application, service, other); free-text values are refused at intake. |
| Framework-gated fields | The capability/profiles/protocols/keys/algorithms fields describe the Universal Wallet Reference Architecture. They are presented only in the framework-options wizard step; with `OSPMAE_FEATURE_FRAMEWORKS=false` the step is removed and blank values save, so nothing leaks into a framework-free deployment. |
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

`tests.sh` runs the whole CI surface locally: backend pytest with branch coverage against a disposable PostgreSQL database named by `OSPMAE_TEST_DATABASE_URL` (the suite runs on PostgreSQL only, and empties the database it is given), the no-skips guard, UI tests under c8, and syntax checks across first-party JavaScript. `.github/workflows/tests.yml` runs the same steps on every push. Documentation for development conventions lives in `AGENTS.md`; the deployment security model lives in `SECURITY.md`.

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
