# Security policy and threat model

## Reporting a vulnerability

Please report suspected vulnerabilities through this project's GitHub repository. Prefer **Security → Advisories → Report a vulnerability** for a private report. If private reporting is unavailable, open an issue asking for a private reporting channel and keep exploit details, credentials and sensitive data out of the public issue.

Every report must include a reproducible proof of concept demonstrating the issue. Include:

- The OSPMAE version or commit, deployment configuration relevant to the issue, and affected component.
- The attacker's required access, permissions and other prerequisites.
- Minimal reproduction steps or a script, expected and actual results, and evidence of the security impact.
- Synthetic test data and redacted logs or screenshots where useful.

Test on an installation you own or have explicit permission to assess. Use the smallest demonstration that establishes the issue, preserve other people's data, and avoid disruptive testing against public or hosted instances.

Our goal is to provide a preliminary response within **72 hours**. This is an acknowledgement and initial assessment target; investigation and remediation time depends on the report. OSPMAE offers **no monetary bounties**. Authors of validated reports will be credited, using their preferred name or handle, unless they request anonymity. We coordinate disclosure with reporters after assessing impact and remediation.

## Scope and trust boundaries

### What OSPMAE protects

OSPMAE stores the project catalogue: projects, releases, capability and framework mappings, manifests, dependency and vulnerability records, questions and subscriptions, plus user accounts and preferences. These records can carry an adopter's internal architecture or a maintainer's unreleased data, and several surfaces (draft releases, manifests, shared groups, subscription addresses) express who may read what. Security objectives include controlling who reads or changes each record, keeping scan credentials within their configured pipeline, preserving the integrity of dependency and vulnerability data once recorded, and maintaining service availability.

An OSPMAE installation is an organisational trust boundary. Users inside it receive access through roles, groups and permissions; project ownership (creator and owner groups) scopes writes for every role except administrator. Hosting mutually distrustful organisations requires isolated installations, databases and secrets.

### Actors

The threat model includes an unauthenticated Internet client, a malicious website visited by a signed-in user, a user acting beyond their assigned permissions, a project owner submitting hostile repository URLs or content, and hostile content returned by a configured release feed or package repository. A granted permission establishes who may act; reviewers still judge the truth of catalogue entries and scan results.

Application administrators are trusted to configure providers, permissions, feature switches and retention. Deployment operators control the executable code, database, broker and environment secrets. Compromise of these privileges can compromise the installation. An administrator's intended ability to delete data or grant permissions is part of that role; escaping the role's intended authority remains a security issue.

Upstream identity providers, Git hosts and package registries are trusted for their specific functions. A compromised provider can assert identities; a compromised Git host can return fabricated repository contents and observe the cloned content. The dependency host allowlist, per-request budgets and the scrubbed clone environment reduce the resulting exposure.

### Hostile scan inputs

A project's repository URL, lockfiles, package names, vulnerability titles and release feeds can all be attacker-shaped. The scan pipeline contains what such input can do to its own run: repository URLs validate against a host allowlist with credential and control-character refusals, clones run in a fixed scrubbed environment with redirects disabled and positional (non-option) refs only, lockfile parsing reads at most the configured bytes per file and caps traversed and matched files, feeds screen entity declarations across the whole bounded payload, one malformed lockfile or finding costs that item alone, and display values are cleaned before storage. Within those limits hostile input can still describe false dependencies or unsafe-looking findings; the catalogue marks their provenance through the recorded source files and commit, and reviewers or adopters verify before asserting anything downstream.

## Authentication

### Sessions

Browser sessions use random, server-generated identifiers stored in the database (`sessions`). The browser receives an HttpOnly session cookie with `SameSite` policy and `Secure` flag from configuration; CSRF protection pairs a separate CSRF cookie with a header check written by `security/csrf.py`. A session ends at its sliding expiry and also at a fixed time after sign-in (`OSPMAE_SESSION_ABSOLUTE_TTL_SECONDS`, 30 days by default), however recently it was used. Signing in issues a fresh identifier and revokes the account's previous sessions; signing out revokes them.

Login budgets: a rolling 5-minute window bounds attempts per client address (`login:{ip}`, 10) and per compared username (`login_fail_user:{name-digest}`, 15). Once the name's allowance is spent, further password verification runs under a small per-(name, address) budget, and each correct password clears the account's attack state, so a flood of failed attempts keeps guessing slow while the legitimate account signs in. Every rejection — unknown, inactive, or wrong password — performs one full PBKDF2 verification (260,000 iterations) against a fixed dummy hash, so response timing carries no account-existence signal. A blank username refuses before any rate-limit or password work.

Password reset: requests answer 204 on every path with a synchronised commit shape, so wall clock separates no outcomes. Tokens are single-use, hashed (SHA-256 over a 256-bit random value) with a one-hour expiry bound to the account, and issuance is rate-limited per address (5/15 min) and per account (3/15 min). Links point at `OSPMAE_PUBLIC_BASE_URL`, which the deployment must set before mail flows start; the printed link carries the configured origin alone. Password change re-verifies the current password under a per-account allowance (5/5 min), and SSO sessions decline it.

Mailbox ownership: an account's addresses in `user_emails` begin unverified when self-asserted; `/v1/me/emails/{id}/verify-request` mails a hashed, 24-hour, single-use verification token, and `/v1/me/emails/verify` consumes it. Verified addresses are stored, and a verified email participates in SSO linking only when the identity provider also marks the address verified, so linking requires proof on both sides. Session trust never derives from `preferred_username` or other selectable provider claims.

### Passwords

Passwords hash with PBKDF2-SHA256 at 260,000 iterations and per-password salts (`security/passwords.py`). Account creation validates the username shape (letters, digits and `._-`, 1–64 characters) because usernames appear in response headers and drive the case-folded identity comparisons above. Roles arrive from the server's role model; local sessions carry their authority from the database, refreshed through the same middleware lookup as every request.

### Local second factor

Local accounts may enrol a TOTP authenticator, WebAuthn security keys/passkeys or both, backed by ten single-use recovery codes. `OSPMAE_MFA_POLICY` decides whom the ceremony demands of on local sign-in (`optional`, `admins`, `all`); a second factor on top of a correct password starts a five-minute challenge whose cookie (`ospmae_mfa_pending`, `__Host-` prefixed over HTTPS) is separate from the session cookie, expires on logout, and dies with any account change: every challenge row records the enrolment version and a digest of the password it was started for.

Every ceremony step re-decides its stage and enforces origin (`Origin` must equal `OSPMAE_PUBLIC_BASE_URL`, HTTPS except plain-localhost), per-address (40/5 min) and per-account (15/5 min) allowances, and an account-level wrong-code counter: five wrong TOTP or recovery codes reject everything for an hour, counted across sign-ins by digest. Recovery codes are stored as SHA-256 hashes and burn on use; TOTP secrets are stored Fernet-encrypted under `OSPMAE_MFA_ENCRYPTION_KEY` and verify only forward through a per-account last-step counter, so a code proves the factor once. WebAuthn verification pins the registered origin, relying-party ID and user handle, rejects cross-origin/cross-site ceremonies, and consumes its challenge in the row before any result commits, so a failed proof never leaves a replayable challenge.

Each enrolment bump increments the account's `mfa_version`; a session row whose recorded version disagrees, or which does not prove the factor while one is enabled or required, is deleted at resolution, so an enrolment change ends every other local session. SSO-created sessions are outside the local ceremony. Removing the last factor turns the enrolment off (and spends the recovery codes), and MFA-required accounts cannot remove their only factor until a replacement proves.

### Single sign-on and account linking

OpenID Connect providers configure client id/secret, endpoints, issuer, JWKS, redirect URI, allowed email domains and per-provider link/provision switches; the same rules apply to the bundled GitHub OAuth2 support. Every enabled provider requires an explicitly configured `REDIRECT_URI`; the callback address never derives from a request host. Authorisation requests use PKCE S256, single-use server-side state with a 10-minute expiry and per-browser binding, and a state row is consumed atomically before the token exchange. Token exchange validates issuer, audience, expiry, nonce and issued-at against configured sources and the JWKS keys; auto-provision places `pending` users pending administrator approval. Automatic linking matches only on a provider-verified email held by exactly one account whose `user_emails` row is verified.

### Trusted remote-user authentication

`OSPMAE_TRUST_REMOTE_USER=true` hands authentication to the configured identity header, which is honoured only when the socket peer sits inside `OSPMAE_TRUSTED_PROXY_CIDRS`, and only for the single configured header name (default `REMOTE_USER`). The supplied nginx clears the client's copies of every identity header and lets deployments that use upstream authentication supply their own proxy configuration that sets the header from the authenticating layer's output. Auto-provisioned users land `pending`.

### Client addresses

`security/client_addr.py` resolves every client address (rate-limit keys, audit records, audit trails in the UI): it walks `X-Forwarded-For` right-to-left while each hop stays inside `OSPMAE_TRUSTED_PROXY_CIDRS` and keeps the socket peer otherwise. Allowance keys count one IPv4 address or one IPv6 /64 network per bucket, so a home or officeIPv6 subscriber stays inside its network's budget. Unset `OSPMAE_TRUSTED_PROXY_CIDRS` trusts loopback only; Compose deployments set their Compose network range explicitly. An untrusted client's forwarded headers cannot change its resolved address.

## Authorisation

### Enforcement

Routes acquire their actor through the session cookie (or trusted header after the peer check above), and pending users stay out of operational `/v1` surfaces apart from account ones. Roles (`security/roles.py`) and permissions (`security/permissions.py`) compose effective authority from the account role, group roles and granted permissions, and project ownership (creator or owner group) object-scopes every non-administrator role: a granted `project.write` widens nothing. Manifests grant read access through explicit owner/group membership, and subscription/question actions check ownership of the named objects. Administrative surfaces (`/v1/admin/*`, audit listing, user management) require the admin role, and the last active administrator resists demotion, deactivation, deletion and access stripping from every supported path.

Feature switches turn optional areas off at the router level (HTTP 404), in Celery tasks/beat schedules (no-op), and in startup seeding, so a disabled install behaves like a small application: authentication, accounts, the project catalogue and the dependency/vulnerability dashboard stay, everything else answer 404.

### Scanning and dependencies

Dependency discovery enqueues per project version from explicit operator or project-owner actions; the `dependency_discovery` host allowlist (`OSPMAE_DISCOVERY_ALLOWED_HOSTS`, github/gitlab/codeberg by default) bounds clone destinations together with the URL validations above; clones cap their duration (`OSPMAE_DEPENDENCY_DISCOVERY_CLONE_TIMEOUT_SECONDS`) and traversal (`OSPMAE_DEPENDENCY_DISCOVERY_MAX_FILES`, `OSPMAE_DEPENDENCY_DISCOVERY_MAX_FILE_BYTES` per file), running grype/syft with configured paths and budgets. Discoveries exclude `.git`, build and vendored directories from traversal, skip symlinks, and clean displayed names/titles. Vulnerability records replay only through the recorded scanners; results stored for one version never name managed secrets, and clone errors echo credentials redacted (`redact_url`).

Release feeds fetch one bounded body per project on each beat poll, following redirects only after re-validating each hop against the private-network screen, rejecting non-HTTPS schemes, applying size/time limits and reading entity-free XML only. Release feed-derived versions inherit capability mappings only from existing published versions of the same project, cap 10 new versions per cycle, and stay consistent with the subscription notifications the project owner configured.

## Browser boundaries

### CSRF, Origin and WebSockets

Unsafe cookie-authenticated requests (everything except login POST) require the CSRF header matching the CSRF cookie, compared in constant time. Browser pages read the CSRF cookie themselves for header injection; the navbar POST/logout flow sends the token as a parameter, and a session-destroying `GET /v1/auth/logout` without matching proof leaves authentication untouched and lands the browser on a harmless page. WebSocket handshake requests require same-origin (or configured public base URL) Origin, complete authentication, and close 4401/4403/4429 on failure; per-account connection caps (8) and per-address handshake budgets (30/min) bound connection churn, and the authentication database session closes at the end of the handshake, spanning no idle connection.

### Rendering, links and navigation

First-party JavaScript renders untrusted text through `escapeHtml`/`textContent`; links run through `safeExternalHref` in the design system and `safeHref` in OSPMAE pages, which drop script, data and forbidden schemes, protocol-relative URLs, backslashes and control characters. Post-authentication destinations (`?next=`, logout redirects, stored navbar shortcuts) validate through one shared helper (`security/url_safety.py safe_relative_route_path`) on both server and client, refusing absolute URLs, `//host`, backslashes and control characters. Markdown export escapes cell text with pipe rules and serves as `text/markdown` attachment; CSV/XLSX exports tabulate with formula-prefix neutralisation (leading `=` `+` `-` `@` and `Tab`) and `attachment` dispositions.

### Request paths through the proxy

The supplied nginx configuration adds the security-header set (X-Content-Type-Options, X-Frame-Options, referrer policy, COOP, HSTS and a `default-src 'self'` CSP) unless the upstream already set one, carries the cache-policy map (immutable vendored assets, fresh HTML and first-party scripts), redirects with relative paths (`absolute_redirect off`), and refuses `//`-prefixed request targets so browsers keep the installation's own origin in echoed paths. The API proxy clears the client-supplied identity headers on `/v1/` and `/ws/`, and websocket upgrades keep their separate connection policy and idle timeout.

### Downloads, exports and caching

Exports (markdown manifest, XLSX/CSV comparison and dependency downloads, PDF report generation in the browser) stream as attachments with fixed, escaped names and carry no secrets beyond what the caller may read. Vendored assets serve immutable cache lifetimes keyed by exact URL paths, which lets a build revision replace their content. JSON API responses carry content types from the framework without HTML rendering at the API layer.

## Background work

Celery workers process scans, release feeds and maintenance sweeps with per-task budgets: clone timeouts, per-file byte caps, per-feed size and time limits, and a beat-scheduled sweeper that deletes expired login states, used/expired reset and verification tokens, aging rate-limit ledger rows and audit rows past `OSPMAE_AUDIT_LOG_RETENTION_DAYS` (90 by default). The git subprocess environment holds the credentials layer of its own path; clone children run with prompts, askpass helpers, system and global git configuration and HTTP redirects disabled, and the workers in general receive only the environment variables their configuration names. Audit trail writes carry a fixed per-address allowance (120/min) so unauthenticated request floods cannot commit unbounded writes; the WS notification hub rejects over-capacity connections before the receive loop begins.

## Secrets and redaction

Runtime secrets (session signing key, database and broker passwords, SMTP credentials, provider client secrets, Grype/Syft configuration on the operator side) live outside the database in `.env` / environment, and Compose requires the critical ones through `:?` guards. The UI container receives the built static image only and keeps the full `.env` inventory out of its runtime.Stored query strings, e-mail subjects, and error text redact credentials through `DEFAULT_SENSITIVE_KEYS` (which include `csrf`, tokens, signatures and authorisation values); clone/grype failures report commands with credentials masked; account e-mail rows validate through `_normalize_email` in `me.py`, and notification recipients resolve through the account's own verified rows.

Redaction is best effort: arbitrary prose, unknown key names and content embedded in URL paths may retain sensitive information. Configure additional sensitive keys via `OSPMAE_SENSITIVE_KEYS`, and keep secrets out of project descriptions, questions, manifest names and scan source labels.

## Provider diagnostics and logging

Request audit rows record client address, method, path, redacted query string, status and duration, with fixed caps (4096 query bytes, 256/512 user-agent/referer bytes) and the per-address write allowance above. Login records record outcomes without echoing attempted names for unknown accounts; security notification payloads carry usernames and reasons as text. Library wire/debug logging stays quiet by default: HTTPX and authlib warnings are the only expected console noise, and new dependency loggers must be reviewed before the app prints their request bodies.

## Deployment posture

The Compose files pin every third-party image by digest (`tools/docker_image_pins.py` keeps them current, with a nightly workflow proposing digest updates through reviewed pull requests). Users and containers run as non-root with an internal network; the API binds to a published port only through the UI service, and the API itself listens on the internal network. `component-api` (uvicorn) and its workers run as the image user with fixed resource budgets per compose memory settings; postgres/valkey hold their own startup ownership. Operators supply `.env` values for secrets, session signing key, mail and provider settings; the API validates provider configs at startup (an enabled provider with an unset `REDIRECT_URI` fails the surface's start with a clear message). Application sessions are database-backed, so restoring a database copy restores authentication state; keep database and environment secrets protected together, and rotate `SECRET_KEY` deliberately (it signs CSRF cookie integrity boundaries for future hardening).

## Post-quantum cryptography

All OSPMAE browser, SMTP and provider traffic relies on TLS alone; its post-quantum posture follows whatever both ends negotiate. Database and broker connections within the Compose network share the deployment trust domain. Authentication factors are classical hashes; stored secrets (passwords, hashed tokens) keep their lifetime safety against quantum attacks because PBKDF2-SHA256 and SHA-256 stay outside the reach of shor-style algebraic attacks.
