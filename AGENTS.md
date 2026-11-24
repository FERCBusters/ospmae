# Working on OSPMAE

## Scope and structure

- Read the relevant code and tests before editing. Prefer small changes to the layer that owns the behaviour, using existing helpers and services.
- Keep HTTP handlers focused on validation, authorisation and responses. Signing in, sessions, second factors, single sign-on, CSRF, request limits, client addresses, the audit trail and the shared security primitives come from the `MOSP` framework (`FERCBusters/mosp`, pinned in `services/api/pyproject.toml`), which KEEN and MIDENA share; OSPMAE binds to it in `app/__init__.py` and takes part through `app/mosp_hooks.py`. OSPMAE's own route policy, permissions and catalogue security live in `services/api/app/security/`; scanning lives in `services/api/app/depscan/` and `services/api/app/tasks/`; mail and domain services live in `services/api/app/services/`. Feature switches live in `app/core/features.py` (administrator-managed, with `OSPMAE_FEATURE_*` as the deployment ceiling; keep it aligned with KEEN's and MIDENA's) and gate routes through `require_feature`; pass the request's session to `is_enabled(key, db)` where one exists.
- A behaviour the three applications share belongs in MOSP, changed there for all of them; OSPMAE keeps only what is its own. Where OSPMAE needs something MOSP lacks, add it to MOSP (with MOSP's tests) rather than a local copy.
- Use the design system and shared UI helpers (`@fercbusters/mosp-design-system`, pinned by commit in `services/ui/package.json` and vendored into `public/vendor/` by `scripts/vendor-assets.mjs`). The unified navbar is `initNavbar()` driven by `public/mosp-ui-config.js`. Keep API authorisation authoritative even when the UI hides an action.
- Remove code only after checking all callers, configuration references and runtime entry points. Do not introduce compatibility machinery without a concrete supported use case.
- Before writing a helper, search for an existing one in OSPMAE and in MOSP, and reuse or extend it. Shared homes include:
  - `app/security/route_policy.py`: `OSPMAE_POLICY`, the rule for every OSPMAE route, merged with MOSP's own (`mosp.security.route_policy`).
  - `app/security/permissions.py`: OSPMAE's permission codes and their seed; `mosp.security.permissions.has_permission` for every check and `bump_authz_versions` after any change to an account's role, groups or permissions, so its sessions follow.
  - `app/security/project_access.py`: `owns_project`, `can_view_drafts`, `ensure_version_visible` (who a project belongs to and who reads its drafts).
  - `app/security/repo_credentials.py`: private repository tokens; `repository_of` and `same_repository` for deciding whether two addresses are one repository.
  - `app/security/outbound.py`: `public_client` for every server-side fetch of a user-supplied address (HTTPS only, connected to the validated address); `app/security/url_safety.py`: `validate_public_https_url` and `public_https_addresses`.
  - `app/security/regex_shape.py`: `check_pattern_shape`, `compile_supplied_pattern` and `search_within` for release-feed ignore patterns.
  - `app/depscan/scan.py`: `validate_repo_url` and `_git_env`; `app/depscan/parsers.py`: `_bounded_read`; `app/depscan/ecosystems.py`: ecosystem names shared by Syft and Grype.
  - `app/services/scan_queue.py`: `mark_scan_queued`, `launch_dependency_scan`, `launch_release_discovery` (queue in the database, then hand to the broker).
  - `mosp.security.client_ip`: `request_ip` (forwarded addresses through `OSPMAE_SECURITY_TRUSTED_PROXY_CIDRS`); `mosp.security.rate_limit`: `sliding_window_allow` for Valkey-backed allowances and `address_allowance` (an IPv6 /64 counts as one address).
  - `mosp.security.urls`: `external_url` for stored links, `same_site_path` for redirects and stored paths; `mosp.security.xml`: `parse_untrusted_xml` for every XML document a user or upstream supplies.
  - `mosp.core.datetime_utils`: `utc_now_naive` for every stored timestamp, `iso_or_none` for every serialised one, `parse_iso_datetime_or_none` and `to_utc_naive` for times read from outside; `mosp.core.email_address`: `single_mailbox` for account e-mail.
  - `mosp.security.auth`: `require_authenticated` and `require_admin` for every route's account.
  - `mosp.core.task_deadline`: `TIME_LIMITS`, re-raised before every broad handler in task and scan code, and `grace()` for what must still be written after the limit (`tests/test_celery_contract.py` checks both).
  - `mosp.security.json_shape.decode_json` for every JSON document from outside (lockfiles, scanner output); `mosp.security.csv.spreadsheet_cell` for every spreadsheet cell; `mosp.security.redaction.redact_str` for error text that can carry credentials; `mosp.services.text.split_filter_values` for comma-separated filters.
  - `mosp.security.request_limits` and `app/mosp_hooks.body_limit`: body classes, request targets and cookie screening; `mosp.api.routing.Router` for every router, so JSON bodies are decoded with MOSP's shape limits.
  - `mosp.security.sessions`, `mosp.security.csrf` and `mosp.security.auth.cookie_name`: cookies are read and set under these names, never the bare settings.
  - `api/deps.py`: `DbId`, `OptionalDbId`, `QueryDbId`, `PageLimit`, `PageOffset` and `SearchText` for every path and query parameter; `api/payloads.py`: `DbIdField`, `SortOrder` and `MAX_IDS` for body fields.
  - `tasks/maintenance.py` (MOSP's `housekeeping` and `audit_retention` sweeps), `services/entity_changelog.py` (semantic history), `services/notifications.py` and `services/mailer.py` (the catalogue outbox, delivered by `mosp.services.outbox`), `realtime/notifications.notify_users` (live notices).
  - In the UI: `app.js` (`safeHref`, `escapeHtml`, `can` and the permission helpers built on it, `featureOn`/`gateFeature`, `formatTimestamp`, `applyUiThemePreference`).
- A second copy of a helper is a defect even when it starts out identical. Where a behaviour must be the same everywhere (resolving a client address, validating a repository URL, normalising a same-site path, counting an allowance), give it one shared helper, route every caller through it, and add a contract test that refuses a hand-rolled copy and proves it would catch one.
- Trust declared types. Read typed settings, ORM columns and values the code has just built directly, without `getattr`, `isinstance`, `or ""` or `bool()`/`int()` wrappers. Keep guards where data is untrusted or genuinely optional: upstream scan output, feed payloads, request payloads and nullable columns.
- Every optional area honours its feature switch: routes answer 404 when it is off, gated Celery tasks return a no-op with a reason, and the UI hides it through `featureOn`/`gateFeature` plus `FEATURE_PAGES`.

## Security invariants

- Every HTTP route enters MOSP's authentication, Origin, CSRF and audit middleware, installed in `main.py`. A new route needs a rule in `app/security/route_policy.py` (a write without one is refused for everyone, and the suite fails), an explicit permission or object check, and regression tests against the assembled application. Project ownership object-scopes every write for accounts other than administrators.
- Accounts are administrators, ordinary accounts or inherit their role from their groups; what an ordinary account may do comes from its permissions, granted directly or through its groups. A job (maintainer, architect, engineer) is a set of permissions, never a role.
- Password sign-in, second factors, SSO linking and sessions are MOSP's; a change there is made in MOSP, with its tests, for KEEN, MIDENA and OSPMAE alike.
- Account and group ids are UUIDs; catalogue ids are integers bounded to the database's integer range wherever they arrive.
- Repository URLs validate through `depscan.scan.validate_repo_url` (scheme, host allowlist, userinfo and control-character refusals; error text is redacted through `redact_str`) before `git`, Syft or Grype run. Git children get the fixed `_git_env` environment with redirect following disabled; release feeds parse through `parse_untrusted_xml(strict=True)` within their byte limit. Lockfile parsers read with `_bounded_read` and the traversal caps stay in force. A private project's token reaches only the repository it is bound to.
- Outbound requests go only to fixed or validated destinations: no redirects beyond those validated hop by hop, no proxy environment, bounded answers, provider bodies kept out of errors. Always validate TLS certificates and hostnames; never add `verify=False`, `CERT_NONE` or a fallback after verification fails.
- Use bound SQL parameters and ORM expressions; escape `LIKE` wildcards. Dynamic identifiers and orderings use fixed allowlists or capped lists (`_normalize_csv_ints`). Treat scanner output and package names as untrusted display values (`_clean_display_value`) and payload text as untrusted in the UI (`escapeHtml`/`textContent`).
- Supplied regular expressions pass `check_pattern_shape` when saved and run under `search_within`. Test the costliest accepted input at the largest accepted size.
- Fail closed on authentication or authorisation uncertainty. Keep errors useful without disclosing credentials, tokens or upstream response bodies.
- Exports are attachments with fixed, bounded names; spreadsheet cells neutralise formula prefixes.

## Validation

- Use `.github/workflows/tests.yml`, `tests.sh` and `tests-ui.sh` as the authoritative test workflow. The backend suite runs on PostgreSQL only (`OSPMAE_TEST_DATABASE_URL`, a disposable database; `tests/conftest.py` refuses anything else) and skips nothing; Valkey is an in-memory stand-in (fakeredis). Never point tests at an operational installation. MOSP's own suite covers its sign-in, session and request rules; OSPMAE's tests cover how OSPMAE assembles them and everything OSPMAE adds.
- Shared builders live in `tests/support.py`: enter catalogue data through the API, write scan results as the rows the scan task stores, and replace only what lies outside the application (git, Syft, Grype, the feed host's HTTP transport, the broker). `tests/conftest.py` names the job-shaped permission sets the tests sign in with.
- UI tests need `npm ci --prefix services/ui/tests`. Page tests load the real page HTML and classic scripts into jsdom through `services/ui/tests/support/load-page.mjs`, substituting only `window.OSPMAE` or the network; `support/app-page.mjs` runs a page with the real `app.js` and d3 against an API fixture and supplies only what jsdom has no engine for. Assert what a user sees and what reaches the API. Timestamps from the API are UTC without an offset: format them with `OSPMAE.formatTimestamp`.
- `coverage-requirement.txt` and `coverage-requirement-ui.txt` are ratchets towards 100: raise them with each batch of tests, never lower them.
- For security changes, add a reproducible negative test demonstrating the attack prerequisite and its rejection, through the assembled application where the property is enforced there.
- Update `services/api/pyproject.toml` and `poetry.lock` together. Preserve pinned Actions, image digests and the design-system revision. Pin a new image with `python3 tools/docker_image_pins.py update`; record a reviewed git package with `npm run vendor:record` in `services/ui` after reviewing it.
- Keep `ruff check ../..`, `ruff format --check ../..` and `mypy app` (from `services/api`), `bash lint-ui.sh` and `bash format-ui.sh --check` clean. Keep imports at the top of each module.
- Validate the exact final working tree after formatter or lint fixes. Report what passed, what failed and what could not run.

## Security re-review whenever completing a round of work

Whenever completing a round of work, work through the required security review checklist in SECURITY.md, record evidence and untested limitations, and re-review whether the changes weaken any security property. Example hazards: account takeover, privilege escalation or authorisation bypass, injection, XSS, SSRF, CSRF, trivial DoS or ReDoS, open redirects, unbounded requests, middleware bypass through route nesting, TLS validation gaps, weak OIDC parameter checking, token replay, credential mixing between scan outputs, draft disclosure, stale records, sensitive values in logs or errors, client-trust mistakes, redaction gaps, cryptographic failure, race conditions and missing rate limits.

Fix each confirmed issue across its whole class. Name the property it violates, search the codebase for every path sharing that property (other callers, parsers, limits, routes and tasks of the same shape), fix them all, and enforce the property with a codebase-wide contract test that includes a check proving the test detects the original defect.

## Documentation and delivery

- README.md describes current capabilities and setup. SECURITY.md describes the current security model, realistic risks and reporting policy; keep findings and fix history out of it.
- Write in present tense and British English, without release-update narratives or developer handover instructions in user-facing documentation. Avoid contrastive-negation language.

## Backend architecture

- The request path is middleware → HTTP adapter → domain operation → persistence. Middleware handles cross-cutting request policy for every route in one place; keep it generic.
- `app/api/routes/` owns HTTP adapters; MOSP's routers serve signing in and out, second factors, single sign-on and the account's own password and SSO addresses. `app/security/` owns OSPMAE's route policy, permissions and catalogue security. `app/db/` owns models (MOSP's account mixins and OSPMAE's own tables) and session setup, `app/depscan/` and `app/tasks/` own scanning and background work, `app/services/` owns mail and domain services, `app/realtime/` owns OSPMAE's live notices over MOSP's hub.
- Scans and feeds stay honest about cost: lockfile parsing, feed fetches, clones and grype/syft runs each carry their configured budgets.
- Migrations live in `alembic/versions/` as explicit DDL; never `create_all` or an import of `app`. Write the model change, the migration and a test touching both together; `tests/test_migrations.py` checks that upgrading matches the models.
- A request's session discards whatever it has not committed. Queue mail in the transaction of the change it reports; a sender that reports a change already committed ends with `commit_and_kick(db)`. Tests read mail through the `outbox` fixture, which counts committed rows only.

## Frontend

- The build vendors pinned third-party assets into `public/vendor/` (`npm run build` in `services/ui`, installed with `--ignore-scripts`), and nginx serves `dist/` with the policy in `services/ui/nginx/default.conf`. Pages load `theme-boot.js` in `<head>` after `mosp-ui-config.js` so the saved palette applies before first paint.
- Keep first-party pages token-driven through the design system's variables; palette-specific values live in the design system.
- Pages opt out of features with `gateFeature('manifests')`-style checks at init; nav visibility follows the account's permissions and the feature switches. Keep the same guard on every page a feature owns.
