import test from "node:test";
import assert from "node:assert/strict";
import { loadApp } from "./_harness.mjs";

const OSPMAE = await loadApp();
assert.ok(OSPMAE, "app.js must expose window.OSPMAE");

test("escapeHtml neutralises HTML-significant characters", () => {
  const esc = OSPMAE.escapeHtml;
  assert.equal(
    esc("<img src=x onerror=alert(1)>"),
    "&lt;img src=x onerror=alert(1)&gt;",
  );
  assert.equal(esc("a&b\"c'd"), "a&amp;b&quot;c&#39;d");
});

test("featureOn fails open for unknown keys, honours the server for known ones", () => {
  assert.equal(OSPMAE.featureOn("frameworks"), true);
  assert.equal(OSPMAE.featureOn("nonexistent-feature"), true);
});

test("gateFeature redirects disabled pages to the dashboard", () => {
  OSPMAE.state.features = { frameworks: false };
  assert.equal(OSPMAE.gateFeature("frameworks"), false);
  OSPMAE.state.features = { frameworks: true };
  assert.equal(OSPMAE.gateFeature("frameworks"), true);
});

test("normalizeHexColor keeps safe hex only", () => {
  const n = OSPMAE.normalizeHexColor;
  assert.equal(n("#aabbcc"), "#aabbcc");
  assert.equal(n("#ABC"), null);
  assert.equal(n("javascript:alert(1)"), null);
  assert.equal(n("#ggg"), null);
  assert.equal(n(""), null);
});

test("preferences normalisation preserves safe start pages", () => {
  const p = OSPMAE.normalizeUserPreferences({
    node_colors: {},
    default_start_page: "/index.html",
    sticky_enabled: true,
  });
  assert.equal(p.default_start_page, "/index.html");
  assert.equal(p.sticky_enabled, true);
});

test("canMaintain/canAnswer follow the effective role", () => {
  assert.equal(OSPMAE.canMaintainProjects(), false);
  assert.equal(OSPMAE.canAnswerQuestions(), false);
});

test("pending users are detected from the me payload", () => {
  OSPMAE.state.me = {
    username: "x",
    role: "pending",
    effective_role: "pending",
  };
  assert.equal(OSPMAE.isPendingUser(), true);
  OSPMAE.state.me = null;
});

test("applyFeatureVisibility hides links of disabled pages", () => {
  OSPMAE.state.features = { manifests: true, frameworks: false };
  // With no document links, the call must be a no-op without throwing.
  OSPMAE.applyFeatureVisibility();
});
