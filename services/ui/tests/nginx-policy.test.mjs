// The supplied nginx configuration, read as text: nginx itself is not part
// of the test environment, so these check what the file declares.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const conf = await readFile(
  new URL("../nginx/default.conf", import.meta.url),
  "utf8",
);
const server = conf.slice(conf.indexOf("server {"));

test("every response header is set at server level, so no location drops one", () => {
  const locations = server.slice(server.indexOf("location "));
  assert.doesNotMatch(locations, /\badd_header\b/);
  for (const header of [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Cross-Origin-Opener-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cache-Control",
  ]) {
    assert.match(
      server,
      new RegExp(`add_header ${header} \\$[a-z_]+ always;`),
      header,
    );
  }
});

test("retired XSS auditors are switched off and unused device features are denied", () => {
  assert.match(
    conf,
    /map \$upstream_http_x_xss_protection \$x_xss_protection_value \{\s*default "";\s*"" "0";/,
  );
  assert.match(
    conf,
    /map \$upstream_http_permissions_policy \$permissions_policy_value \{\s*default "";\s*"" "geolocation=\(\), microphone=\(\), camera=\(\)";/,
  );
});

test("browsers check the design system for a newer copy before each use", () => {
  // It changes with OSPMAE at a stable URL (it reads the CSRF cookie the API
  // sets), so a copy cached for a year would outlive an upgrade. nginx
  // applies the first matching pattern, so its rule precedes the vendor rule.
  const policy = conf.slice(conf.indexOf("map $uri $ospmae_cache_control"));
  const designSystem = policy.indexOf(
    '~^/vendor/mosp-design-system/ "no-cache";',
  );
  const vendor = policy.indexOf("~^/vendor/ $ospmae_vendor_cache_control;");
  assert.notEqual(designSystem, -1);
  assert.notEqual(vendor, -1);
  assert.ok(designSystem < vendor);
  // Failed vendor requests stay retryable, and first-party files stay fresh.
  assert.match(
    conf,
    /map \$status \$ospmae_vendor_cache_control\s*\{\s*default "no-store";/,
  );
  for (const path of [
    "/app.js",
    "/mosp-ui-config.js",
    "/mosp-shell.js",
    "/styles.css",
  ]) {
    assert.ok(policy.includes(`${path} "no-store";`), path);
  }
});

// The names authenticating proxies commonly put an identity in. The API's
// default is REMOTE_USER; a deployment that configures another name sets it
// from its own proxy, and these are the ones a client could otherwise send.
const IDENTITY_HEADERS = [
  "REMOTE_USER",
  "Remote-User",
  "X-Remote-User",
  "X-Vouch-User",
  "X-Forwarded-User",
  "X-Forwarded-Preferred-Username",
  "X-Forwarded-Email",
  "X-Auth-Request-User",
  "X-Auth-Request-Email",
  "X-Auth-Request-Preferred-Username",
  "X-Authenticated-User",
  "X-Authentik-Username",
  "X-Webauth-User",
];

function locationBody(opening) {
  const start = server.indexOf(opening);
  assert.notEqual(start, -1, opening);
  const block = server.slice(start);
  return block.slice(0, block.indexOf("\n  }"));
}

test("identity headers a client sends never reach the API", () => {
  for (const opening of [
    "location ^~ /api/ {",
    "location = /_auth_check {",
    "location = /_auth_check_admin {",
  ]) {
    const body = locationBody(opening);
    for (const header of IDENTITY_HEADERS) {
      assert.ok(
        body.includes(`proxy_set_header ${header} "";`),
        `${opening} ${header}`,
      );
    }
  }
  // Every place that clears one clears them all.
  for (const header of IDENTITY_HEADERS) {
    const cleared = conf.split(`proxy_set_header ${header} "";`).length - 1;
    assert.equal(cleared, 3, header);
  }
});

test("an API path is always proxied and never cached, whatever it ends in", () => {
  // As in KEEN, the API and its socket are served under /api/. A prefix
  // location marked ^~ is not handed to a regular-expression location, so
  // /api/v1/x.html is an API request, not a gated page.
  assert.ok(server.includes("location ^~ /api/ {"));
  assert.ok(!/location \^?~? ?\/(v1|ws)\/ \{/.test(server));
  // The API is sent the target as the browser sent it, less the prefix; a
  // target that only normalises to /api/ maps to nothing and is refused.
  assert.ok(conf.includes('"~^/api(/.*)$" $1;'));
  const api = locationBody("location ^~ /api/ {");
  assert.ok(api.includes('if ($ospmae_api_target = "") {\n      return 400;'));
  assert.ok(api.includes("proxy_pass $ospmae_api$ospmae_api_target;"));
  assert.ok(api.includes("proxy_set_header Upgrade $ospmae_upgrade;"));
  // nginx applies the first matching pattern of a map: the API rule comes
  // before the image-suffix rule that would otherwise make /api/v1/x.png
  // public, and the socket's rule before the API's.
  const policy = conf.slice(conf.indexOf("map $uri $ospmae_cache_control"));
  const body = policy.slice(0, policy.indexOf("\n}"));
  const patterns = body
    .split("\n")
    .map((line) => line.trim())
    .filter(
      (line) => line && !line.startsWith("#") && !line.startsWith("map "),
    );
  assert.equal(patterns[0], 'default "";');
  assert.equal(patterns[1], '~^/api/ws/ "";');
  assert.equal(patterns[2], '~^/api/ "no-store";');
  const images = patterns.findIndex((line) => line.includes("png|jpe?g"));
  assert.ok(images > 2);
  assert.match(patterns[images], /"public, max-age=86400";$/);
});

test("the design system is pinned by commit, in the manifest and the lock alike", async () => {
  const read = async (name) =>
    JSON.parse(await readFile(new URL(`../${name}`, import.meta.url), "utf8"));
  const pin = (await read("package.json")).dependencies[
    "@fercbusters/mosp-design-system"
  ];
  const [, commit] = pin.match(
    /^github:FERCBusters\/mosp-design-system#([0-9a-f]{40})$/,
  );
  const lock = await read("package-lock.json");
  assert.equal(
    lock.packages[""].dependencies["@fercbusters/mosp-design-system"],
    pin,
  );
  const locked = lock.packages["node_modules/@fercbusters/mosp-design-system"];
  assert.ok(locked.resolved.endsWith(`#${commit}`));
  assert.match(locked.integrity, /^sha512-/);
});

// One location block of the server, by its exact opening line.
const locationBlock = (opening) => {
  const start = server.indexOf(`  location ${opening} {`);
  assert.notEqual(start, -1, opening);
  return server.slice(start, server.indexOf("\n  }", start));
};

test("pages are served only to a signed-in browser, which nginx asks the API about", () => {
  // Without the gate a signed-out browser receives a page and shows it until
  // the page's own script learns there is no session.
  for (const opening of ["= /", "~* \\.html$", "/"]) {
    const block = locationBlock(opening);
    assert.match(block, /auth_request \/_auth_check;/, opening);
    // A signed-out browser gets the sign-in page in place, as a refusal.
    assert.match(block, /error_page 401 =403 \/login\.html;/, opening);
  }
  // No page is named outside the gate except the sign-in flow's own.
  const ungated = [...server.matchAll(/location (= \S+\.html) \{([^}]*)\}/g)]
    .filter(([, , body]) => !body.includes("auth_request"))
    .map(([, opening]) => opening)
    .sort();
  assert.deepEqual(ungated, [
    "= /login.html",
    "= /mfa.html",
    "= /preferences.html",
    "= /sso-email.html",
  ]);
  // The retired preferences page only redirects to a gated one.
  assert.match(
    locationBlock("= /preferences.html"),
    /return 301 \/account\.html;/,
  );
});

test("the administration page and its scripts go only to administrators", () => {
  for (const opening of [
    "= /admin.html",
    "= /pages/admin.js",
    "= /pages/admin-features.js",
  ]) {
    const block = locationBlock(opening);
    assert.match(block, /auth_request \/_auth_check_admin;/, opening);
    assert.match(block, /error_page 401 =403 \/login\.html;/, opening);
    // Another signed-in account is told the page does not exist.
    assert.match(block, /error_page 403 =404 \/_admin_404;/, opening);
  }
  const hidden = locationBlock("= /_admin_404");
  assert.match(hidden, /internal;/);
  assert.match(hidden, /return 404;/);
});

test("the checks are internal, carry the session cookie and no client identity", () => {
  for (const [opening, route] of [
    ["= /_auth_check", "/v1/auth/check"],
    ["= /_auth_check_admin", "/v1/auth/check-admin"],
  ]) {
    const block = locationBlock(opening);
    // A browser cannot ask for the check's address itself.
    assert.match(block, /internal;/, opening);
    assert.ok(block.includes(`proxy_pass $ospmae_api${route};`), opening);
    assert.ok(block.includes("proxy_set_header Cookie $http_cookie;"), opening);
    // The page request's body is not replayed to the API.
    assert.ok(block.includes("proxy_pass_request_body off;"), opening);
    assert.ok(block.includes('proxy_set_header Content-Length "";'), opening);
    for (const header of [
      "REMOTE_USER",
      "X-Remote-User",
      "X-Vouch-User",
      "X-Forwarded-User",
    ]) {
      assert.ok(
        block.includes(`proxy_set_header ${header} "";`),
        `${opening} ${header}`,
      );
    }
  }
});

test("what the sign-in page loads stays reachable without a session", async () => {
  // Every script and stylesheet the ungated pages name is served by a
  // location with no gate; a gated one would leave the sign-in page bare.
  const open = (path) => {
    if (path.startsWith("/vendor/")) return locationBlock("^~ /vendor/");
    if (path.startsWith("/pages/")) {
      const exact = server.includes(`  location = ${path} {`);
      return locationBlock(exact ? `= ${path}` : "^~ /pages/");
    }
    return locationBlock(`= ${path}`);
  };
  for (const page of ["login.html", "mfa.html", "sso-email.html"]) {
    const html = await readFile(
      new URL(`../public/${page}`, import.meta.url),
      "utf8",
    );
    const assets = [
      ...html.matchAll(/<(?:script|link)[^>]*\s(?:src|href)="(\/[^"]+)"/g),
    ].map(([, path]) => path);
    assert.ok(assets.length > 0, page);
    for (const path of assets)
      assert.doesNotMatch(open(path), /auth_request/, `${page} ${path}`);
  }
});
