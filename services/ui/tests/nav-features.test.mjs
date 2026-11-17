// Navbar links follow the installation's features from the first render.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

async function config(t) {
  const page = await loadPage("index.html", "mosp-ui-config.js");
  t.after(page.close);
  return page.window.mospUiConfig;
}

const allowed = (link, me) =>
  (link.requireAny || []).some((flag) => me[flag]) &&
  (link.requireAll || []).every((flag) => me[flag]);

test("switched-off features leave the navbar", async (t) => {
  const cfg = await config(t);
  const me = cfg.mapMe({
    username: "admin",
    effective_role: "admin",
    features: { frameworks: false, manifests: false, comparisons: true },
  });
  assert.deepEqual(
    // Spread into this realm: the page's arrays have their own prototype.
    [...cfg.links].filter((link) => allowed(link, me)).map((link) => link.key),
    ["projects", "dependencies", "comparisons", "admin"],
  );
});

test("an answer without features keeps every link", async (t) => {
  const cfg = await config(t);
  const me = cfg.mapMe({ username: "admin", effective_role: "admin" });
  assert.deepEqual(
    // Spread into this realm: the page's arrays have their own prototype.
    [...cfg.links].filter((link) => allowed(link, me)).map((link) => link.key),
    [
      "projects",
      "manifests",
      "dependencies",
      "comparisons",
      "frameworks",
      "admin",
    ],
  );
});

test("the navigation stays expanded at laptop widths, as in KEEN", async (t) => {
  const cfg = await config(t);
  // The design system's default (navbar-expand-xxl) hides the links behind
  // the menu button below 1400px: every laptop at 100% zoom.
  assert.equal(cfg.nav.expandClass, "navbar-expand-lg");
  // The framework picker is sized by its names, within bounds that leave
  // room for the links; a fixed minimum width would take that room back.
  assert.equal(cfg.framework.selectMinChars, 14);
  assert.equal(cfg.framework.selectMaxChars, 19);
  assert.equal(cfg.framework.selectMinWidthPx, undefined);

  // styles.css fits the expanded bar into that width from the same 992px.
  const { readFile } = await import("node:fs/promises");
  const css = await readFile(
    new URL("../public/styles.css", import.meta.url),
    "utf8",
  );
  const laptop = css.slice(
    css.indexOf("@media (min-width: 992px) {\n  #navbar"),
  );
  assert.match(
    laptop,
    /#navbar \.navbar-keen \.navbar-collapse \{[^}]*flex-wrap: wrap;/,
  );
  assert.match(
    laptop,
    /#navbar \.navbar-keen \.mosp-nav-framework-select \{[^}]*max-width: 11rem;/,
  );
});
