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

test("identity headers a client sends never reach the API", () => {
  for (const location of ["/v1/", "/ws/"]) {
    const block = server.slice(server.indexOf(`location ${location} {`));
    const body = block.slice(0, block.indexOf("\n  }"));
    for (const header of [
      "REMOTE_USER",
      "X-Remote-User",
      "X-Vouch-User",
      "X-Forwarded-User",
    ]) {
      assert.ok(
        body.includes(`proxy_set_header ${header} "";`),
        `${location} ${header}`,
      );
    }
  }
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
