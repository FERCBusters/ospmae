// The projects dashboard: the summary cards, one row per project with what
// it follows, its scan state and findings, the organisation filter and the
// CSV export.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage } from "./support/app-page.mjs";

const ROWS = [
  {
    id: 1,
    name: "Released",
    machine_name: "released",
    organisation: "Acme",
    latest: { id: 11, version: "v1.2.0" },
    tracked_branch: null,
    dependencies: { discovery_status: "complete", count: 42 },
    vulnerabilities: {
      by_severity: { critical: 1, high: 2, low: 3, unknown: 4, odd: 9 },
    },
  },
  {
    id: 2,
    name: "Tracked",
    machine_name: "tracked",
    latest: { id: 12, version: "main" },
    tracked_branch: "main",
    dependencies: { discovery_status: "running" },
    vulnerabilities: {},
  },
  { id: 3, name: "Empty", machine_name: "empty", latest: null },
  {
    id: 4,
    name: '=Sum" onmouseover="alert(1)',
    machine_name: "odd",
    latest: { id: 14, version: "<1.0>" },
    dependencies: { discovery_status: "error" },
  },
  {
    id: 5,
    name: "Queued",
    machine_name: "queued",
    latest: { id: 15, version: "2.0" },
    dependencies: { discovery_status: "queued" },
  },
  {
    id: 6,
    name: "Fresh",
    machine_name: "fresh",
    latest: { id: 16, version: "0.1" },
    dependencies: { discovery_status: "something new", count: 0 },
  },
  {
    id: 7,
    name: "Counted",
    machine_name: "counted",
    latest: { id: 17, version: "3.0" },
    dependencies: { discovery_status: "complete" },
  },
];

function dashboard(t, options = {}) {
  const world = { fail: { ...options.fail } };
  return appPage(t, "index.html", "pages/projects.js", {
    ...options,
    api(method, path, body, query) {
      const failure = world.fail[path];
      if (failure) return [failure[0], { detail: failure[1] }];
      if (path === "/v1/dashboard") {
        world.organisation = query.get("organisation_id");
        return [200, options.empty ? {} : { projects: options.rows || ROWS }];
      }
      if (path === "/v1/organisations")
        return [200, [{ id: 50, name: "Acme", project_count: 2 }]];
      return null;
    },
  }).then((page) => ({
    ...page,
    world,
    cells: () =>
      [...page.doc.querySelectorAll("#rows tr")].map((row) =>
        [...row.children].map((cell) =>
          cell.textContent.replace(/\s+/g, " ").trim(),
        ),
      ),
  }));
}

test("releases carry a tag icon and tracked branches a branch icon, without a pill", async (t) => {
  const page = await dashboard(t);
  const cells = [...page.doc.querySelectorAll("#rows tr")].map(
    (row) => row.children[2],
  );
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

test("each row shows its organisation, scan state, dependency count and findings", async (t) => {
  const page = await dashboard(t);
  assert.deepEqual(page.errors, []);
  const rows = page
    .cells()
    .map((row) => [row[0], row[1], row[3], row[4], row[5]]);
  assert.deepEqual(rows, [
    [
      "Released",
      "Acme",
      "Discovery complete",
      "42",
      "critical 1 high 2 low 3 unknown 4",
    ],
    ["Tracked", "—", "Discovering", "discovery running…", "none found"],
    ["Empty", "—", "No release yet", "not scanned yet", "none found"],
    [
      '=Sum" onmouseover="alert(1)',
      "—",
      "Discovery failed",
      "discovery failed",
      "none found",
    ],
    ["Queued", "—", "Discovery queued", "discovery running…", "none found"],
    ["Fresh", "—", "something new", "not scanned yet", "none found"],
    ["Counted", "—", "Discovery complete", "0", "none found"],
  ]);
  assert.deepEqual(
    [
      ...page.doc.querySelectorAll(
        "#rows tr:first-child td:nth-child(6) .badge",
      ),
    ].map((badge) => badge.className.replace("badge ", "")),
    ["text-bg-danger", "text-bg-warning", "text-bg-secondary", "text-bg-light"],
  );
});

test("project names and versions are shown as text, whatever they contain", async (t) => {
  const page = await dashboard(t);
  const row = page.doc.querySelectorAll("#rows tr")[3];
  const link = row.querySelector("td a");
  assert.equal(link.textContent, '=Sum" onmouseover="alert(1)');
  assert.deepEqual(link.getAttributeNames().sort(), ["class", "href"]);
  assert.equal(link.getAttribute("href"), "/project.html?id=4&version_id=14");
  assert.match(row.children[2].textContent, /<1\.0>/);
  assert.equal(row.children[2].querySelector("span span + *"), null);
  // A project without a release has a name and an Open button, no version link.
  const empty = page.doc.querySelectorAll("#rows tr")[2];
  assert.equal(empty.querySelector("td a").hasAttribute("href"), false);
  assert.equal(
    empty.querySelector("td:last-child a").getAttribute("href"),
    "/project.html?id=3",
  );
});

test("the summary counts projects, scanned releases, stale scans and serious findings", async (t) => {
  const page = await dashboard(t);
  assert.deepEqual(
    [...page.doc.querySelectorAll("#summary .card")].map((card) => [
      card.querySelector(".small").textContent,
      card.querySelector(".h4").textContent,
    ]),
    [
      ["Projects", "7"],
      ["Scanned releases", "2"],
      ["Needing a scan", "1"],
      ["Critical + high findings (latest)", "3"],
    ],
  );
});

test("an empty catalogue points at New project", async (t) => {
  const page = await dashboard(t, { empty: true });
  assert.deepEqual(page.cells(), [
    ["No projects in this view yet. Use New project to add one."],
  ]);
  assert.equal(page.doc.querySelector("#summary .h4").textContent, "0");
});

test("the organisation filter narrows the dashboard", async (t) => {
  const page = await dashboard(t);
  assert.deepEqual(
    [...page.$("orgFilter").options].map((o) => o.textContent).slice(-1),
    ["Acme (2)"],
  );
  assert.equal(page.world.organisation, null);
  await page.choose("orgFilter", "50");
  assert.equal(page.world.organisation, "50");
});

test("the dashboard still loads when organisations cannot be listed", async (t) => {
  const page = await dashboard(t, {
    fail: { "/v1/organisations": [500, "Organisations unavailable"] },
  });
  assert.equal(page.cells().length, 7);
  assert.deepEqual(page.toasts(), []);
});

test("a dashboard that fails to load says why", async (t) => {
  const page = await dashboard(t, {
    fail: { "/v1/dashboard": [500, "Dashboard unavailable"] },
  });
  assert.deepEqual(page.toasts(), [["danger", "Dashboard unavailable"]]);
});

test("New project is offered to those who maintain projects", async (t) => {
  const admin = await dashboard(t);
  assert.equal(admin.$("newProjectBtn").hidden, false);
  const viewer = await dashboard(t, { me: account("viewer") });
  assert.equal(viewer.$("newProjectBtn").hidden, true);
});

test("the CSV export lists what the dashboard shows, with formulas defused", async (t) => {
  const page = await dashboard(t);
  await page.click("exportCsv");
  assert.deepEqual(
    page.record.downloads.map((d) => d.name),
    ["ospmae-dependency-dashboard.csv"],
  );
  const lines = (await page.blobText(page.record.blobs[0])).split("\n");
  assert.equal(page.record.blobs[0].type, "text/csv");
  assert.equal(
    lines[0],
    "project,organisation,machine_name,latest_version,scan_state,dependencies,unfixed_total",
  );
  assert.equal(
    lines[1],
    '"Released","Acme","released","v1.2.0","Discovery complete","42","6"',
  );
  assert.equal(lines[3], '"Empty","","empty","","No release yet","","0"');
  assert.equal(
    lines[4],
    '"\'=Sum"" onmouseover=""alert(1)","","odd","<1.0>","Discovery failed","","0"',
  );
  assert.equal(lines.length, 8);
});

test("an export before anything has loaded holds only the heading", async (t) => {
  const page = await dashboard(t, {
    fail: { "/v1/dashboard": [500, "Dashboard unavailable"] },
  });
  await page.click("exportCsv");
  assert.equal(
    (await page.blobText(page.record.blobs[0])).includes("\n"),
    false,
  );
});
