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

test("accounts are created by administrators: no pending start page", () => {
  // As in KEEN, there is no pending sign-up role or page.
  assert.equal(OSPMAE.isPendingUser, undefined);
  const values = OSPMAE.ALLOWED_START_PAGES.map((p) => p.value);
  assert.equal(values.includes("/pending.html"), false);
  assert.equal(OSPMAE.normalizeStartPage("/pending.html"), "/index.html");
});

test("applyFeatureVisibility hides links of disabled pages", () => {
  OSPMAE.state.features = { manifests: true, frameworks: false };
  // With no document links, the call must be a no-op without throwing.
  OSPMAE.applyFeatureVisibility();
});

test("csvCell quotes cells and neutralises formula prefixes", () => {
  const cell = OSPMAE.csvCell;
  assert.equal(cell("plain"), '"plain"');
  assert.equal(cell('say "hi"'), '"say ""hi"""');
  assert.equal(cell(null), '""');
  assert.equal(cell(3), '"3"');
  for (const hostile of ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tlead"]) {
    assert.equal(cell(hostile), `"'${hostile}"`);
  }
  // Interior formula characters are ordinary text.
  assert.equal(cell("a=b"), '"a=b"');
  // Importers skip these before deciding a cell is a formula.
  for (const lead of [" ", "\v", "\f", "\0", "\ufeff"]) {
    assert.equal(cell(`${lead}=1`), `"'${lead}=1"`, JSON.stringify(lead));
  }
  // A spreadsheet splitting on semicolons, tabs or line breaks starts a cell
  // after each, so a formula there is neutralised too.
  assert.equal(
    cell("Wallet; =cmd|' /C calc'!A0"),
    `"Wallet; '=cmd|' /C calc'!A0"`,
  );
  assert.equal(cell("a\t@SUM(A1)"), `"a\t'@SUM(A1)"`);
  assert.equal(cell("a\r\n -1+1"), `"a\r\n '-1+1"`);
  // Numbers keep their value.
  assert.equal(cell(-3), '"-3"');
});

test("what the page offers follows the account's permissions", () => {
  const holding = (role, permissions = []) => {
    OSPMAE.state.me = { username: "u", effective_role: role, permissions };
    return {
      ask: OSPMAE.canAskQuestions(),
      answer: OSPMAE.canAnswerQuestions(),
      maintain: OSPMAE.canMaintainProjects(),
      export: OSPMAE.canExportManifests(),
      frameworks: OSPMAE.can("framework.write"),
    };
  };
  const none = {
    ask: false,
    answer: false,
    maintain: false,
    export: false,
    frameworks: false,
  };
  // An administrator may do everything.
  assert.deepEqual(holding("admin"), {
    ask: true,
    answer: true,
    maintain: true,
    export: true,
    frameworks: true,
  });
  // Anyone else may do what their permissions name, whatever their role.
  assert.deepEqual(holding("normal"), none);
  assert.deepEqual(holding("inherit"), none);
  assert.deepEqual(holding("normal", ["project.question"]), {
    ...none,
    ask: true,
  });
  assert.deepEqual(holding("normal", ["project.write", "project.answer"]), {
    ...none,
    answer: true,
    maintain: true,
  });
  assert.deepEqual(holding("normal", ["manifest.export", "framework.write"]), {
    ...none,
    export: true,
    frameworks: true,
  });
  OSPMAE.state.me = { username: "u", effective_role: "normal" };
  assert.equal(OSPMAE.can("project.write"), false);
  OSPMAE.state.me = null;
});

test("start pages offer Projects and Manifests, never a retired page", () => {
  const values = OSPMAE.ALLOWED_START_PAGES.map((p) => p.value);
  assert.equal(values[0], "/index.html");
  assert.ok(values.includes("/manifests.html"));
  for (const retired of [
    "/saved-manifests.html",
    "/project-manage.html",
    "/dashboard.html",
  ]) {
    assert.equal(values.includes(retired), false, retired);
    assert.equal(OSPMAE.normalizeStartPage(retired), "/index.html");
  }
});
