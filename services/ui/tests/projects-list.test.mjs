// The projects dashboard marks what each project follows with an icon: a
// release tag, or a tracked branch.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

const ROWS = [
  {
    id: 1,
    name: "Released",
    machine_name: "released",
    latest: { id: 11, version: "v1.2.0" },
    tracked_branch: null,
  },
  {
    id: 2,
    name: "Tracked",
    machine_name: "tracked",
    latest: { id: 12, version: "main" },
    tracked_branch: "main",
  },
  { id: 3, name: "Empty", machine_name: "empty", latest: null },
];

async function dashboard(t) {
  const page = await loadPage("index.html", "pages/projects.js", {
    ospmae: {
      initAuth: async () => ({}),
      canMaintainProjects: () => true,
      csvCell: (value) => String(value),
      toast: () => {},
      api: async (path) =>
        path.startsWith("/v1/dashboard") ? { projects: ROWS } : [],
    },
  });
  t.after(page.close);
  for (let i = 0; i < 10; i += 1) await page.settle();
  return page;
}

test("releases carry a tag icon and tracked branches a branch icon, without a pill", async (t) => {
  const page = await dashboard(t);
  const cells = [...page.document.querySelectorAll("#rows tr")].map(
    (row) => row.children[2],
  );
  assert.equal(cells.length, 3);

  const [released, tracked, empty] = cells;
  assert.ok(released.querySelector("i.bi-tag"));
  assert.equal(released.querySelector("i.bi-git"), null);
  assert.match(released.textContent, /Release:\s+v1\.2\.0/);

  assert.ok(tracked.querySelector("i.bi-git"));
  assert.equal(tracked.querySelector("i.bi-tag"), null);
  assert.match(tracked.textContent, /Tracked branch:\s+main/);

  // The icon says it; no cell carries a "branch" pill.
  for (const cell of cells) assert.equal(cell.querySelector(".badge"), null);
  assert.equal(empty.textContent, "no release");
  assert.equal(empty.querySelector("i"), null);
});
