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
