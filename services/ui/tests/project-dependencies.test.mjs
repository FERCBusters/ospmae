// The project page's dependency map: scan state, the four charts, the
// vulnerable-only filter, the findings panel and starting a scan.
import test from "node:test";
import assert from "node:assert/strict";
import {
  account,
  dependencyGraph,
  projectPage,
  PROJECT,
} from "./support/project-page.mjs";

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const drawn = (page) =>
  page.texts("#depGraph svg text").map((text) => text.replace(/\s+/g, " "));
const has = (page, label) => drawn(page).some((text) => text.includes(label));

async function dependencyTab(t, options = {}) {
  const page = await projectPage(t, { hash: "#dependencies", ...options });
  await page.wait();
  return page;
}

test("the dependency tab reports the scan and draws the tree", async (t) => {
  const page = await dependencyTab(t);
  assert.deepEqual(page.errors, []);
  assert.ok(
    page.asked().includes("GET /v1/projects/5/dependency-graph?version_id=12"),
  );
  const badge = page.$("depScanStatus");
  assert.equal(badge.textContent, "Complete");
  assert.ok(badge.classList.contains("text-bg-success"));
  const meta = page.$("depScanMeta").textContent;
  assert.ok(meta.startsWith("commit c0ffee1234 • started "), meta);
  // Scan times are UTC on the wire and shown in the reader's own zone.
  const local = new Date("2026-03-05T10:02:00Z").toLocaleString();
  assert.ok(meta.endsWith(`finished ${local}`), meta);
  assert.equal(
    page.$("depSummary").textContent,
    "4 dependencies • 3 vulnerabilities • npm: 2 • python: 2",
  );
  for (const label of [
    "Wallet Kit",
    "2.0.0",
    "npm",
    "python",
    "@inquirer",
    "confirm@5.1.21",
    "lodash@4.17.21",
    "requests@2.31.0",
    "idna@3.6",
  ])
    assert.ok(has(page, label), `${label} in ${drawn(page).join(" | ")}`);
  assert.equal(page.$("depVisualTypeSelect").value, "tidy-tree");
});

test("every dependency chart type draws the same packages", async (t) => {
  const page = await dependencyTab(t);
  for (const type of ["treemap", "sunburst", "radial-tree", "tidy-tree"]) {
    await page.choose("depVisualTypeSelect", type);
    assert.equal(page.doc.querySelectorAll("#depGraph svg").length, 1, type);
    const marks = page.doc.querySelectorAll(
      "#depGraph svg rect, #depGraph svg path, #depGraph svg circle",
    );
    assert.ok(marks.length >= 4, `${type}: ${marks.length} marks`);
    const titles = page.texts("#depGraph svg title").join(" | ");
    for (const pkg of ["confirm@5.1.21", "requests@2.31.0"])
      assert.ok(titles.includes(pkg) || has(page, pkg), `${type} shows ${pkg}`);
  }
  assert.deepEqual(page.errors, []);
});

test("the vulnerable-only filter prunes clean packages and is remembered", async (t) => {
  const page = await dependencyTab(t);
  assert.equal(page.$("depOnlyVulnToggle").checked, false);
  page.$("depOnlyVulnToggle").checked = true;
  page.$("depOnlyVulnToggle").dispatchEvent(new page.window.Event("change"));
  await page.wait();
  assert.ok(has(page, "confirm@5.1.21"));
  assert.ok(has(page, "requests@2.31.0"));
  assert.ok(!has(page, "lodash@4.17.21"));
  assert.ok(!has(page, "idna@3.6"));
  assert.ok(!has(page, "(unscoped)"));
  assert.equal(
    page.window.localStorage.getItem("ospmae_dep_only_vuln_only"),
    "1",
  );

  // The next visit starts with the filter on.
  const again = await dependencyTab(t, {
    setup: (window) =>
      window.localStorage.setItem("ospmae_dep_only_vuln_only", "1"),
  });
  assert.equal(again.$("depOnlyVulnToggle").checked, true);
  assert.ok(!has(again, "lodash@4.17.21"));

  const clean = dependencyGraph();
  const strip = (node) => {
    node.vulnerability_count = 0;
    (node.children || []).forEach(strip);
  };
  strip(clean.dependency_tree);
  const none = await dependencyTab(t, {
    answers: { dependencies: clean },
    setup: (window) =>
      window.localStorage.setItem("ospmae_dep_only_vuln_only", "1"),
  });
  assert.equal(
    none.$("depGraph").textContent.trim(),
    "No vulnerable dependencies found for this project version.",
  );
});

test("findings are grouped by dependency, worst first, with safe links", async (t) => {
  const page = await dependencyTab(t);
  assert.equal(page.$("depVulnCard").style.display, "");
  assert.equal(page.$("depVulnCountBadge").textContent, "3");
  assert.equal(
    page.$("depVulnSummary").textContent,
    "1 critical • 1 low • 1 other • 2 affected dependencies",
  );
  const items = [...page.doc.querySelectorAll("#depVulnList .accordion-item")];
  assert.deepEqual(
    items.map((item) =>
      item
        .querySelector(".accordion-button")
        .textContent.replace(/\s+/g, " ")
        .trim(),
    ),
    ["CRITICAL @inquirer/confirm@5.1.21 (2)", "VULN requests@2.31.0 (1)"],
  );
  const first = items[0];
  assert.deepEqual(
    [...first.querySelectorAll(".fw-semibold")]
      .slice(1)
      .map((n) => n.textContent),
    ["CVE-2026-0001", "GHSA-aaaa"],
  );
  // The advisory title is text, and only web addresses become links.
  assert.ok(first.textContent.includes("Prompt <injection> • fixed: 5.2.0"));
  assert.equal(first.querySelector("injection"), null);
  const links = [...first.querySelectorAll("a")];
  assert.deepEqual(
    links.map((a) => a.getAttribute("href")),
    ["https://advisories.example/CVE-2026-0001"],
  );
  assert.equal(links[0].getAttribute("rel"), "noopener noreferrer");
  assert.ok(first.textContent.includes("javascript:alert(1)"));
  assert.deepEqual(
    [...first.querySelectorAll(".accordion-body .badge")].map(
      (b) => b.textContent,
    ),
    ["CRITICAL", "LOW"],
  );
  const second = items[1];
  assert.ok(second.textContent.includes("Unknown severity • fixed: 2.32.0"));
  assert.equal(
    second.querySelector(".accordion-body .badge").textContent,
    "UNKNOWN",
  );
});

test("a version with no findings hides the panel", async (t) => {
  const page = await dependencyTab(t, {
    answers: { dependencies: dependencyGraph({ vulnerabilities: [] }) },
  });
  assert.equal(page.$("depVulnCard").style.display, "none");
  assert.equal(page.$("depVulnCountBadge").textContent, "0");
  assert.equal(page.$("depVulnList").innerHTML, "");
});

for (const [status, label, cls] of [
  ["queued", "Queued", "text-bg-info"],
  ["running", "Running", "text-bg-warning"],
  ["error", "Error", "text-bg-danger"],
  ["not_run", "Not run", "text-bg-secondary"],
  [undefined, "Not run", "text-bg-secondary"],
]) {
  test(`a ${status} scan is labelled ${label}`, async (t) => {
    const base = dependencyGraph();
    const page = await dependencyTab(t, {
      answers: {
        dependencies: {
          ...base,
          version: {
            ...base.version,
            dependency_discovery_status: status,
            dependency_discovery_error:
              status === "error" ? "clone failed: " + "x".repeat(200) : null,
            dependency_last_commit: null,
            dependency_discovery_started_at: null,
            dependency_discovery_finished_at: null,
          },
          dependency_tree: null,
          dependencies: [],
          vulnerabilities: [],
          summary: { dependency_count: 0, vulnerability_count: 0 },
        },
      },
    });
    const badge = page.$("depScanStatus");
    assert.equal(badge.textContent, label);
    assert.ok(badge.classList.contains(cls));
    assert.equal(
      page.$("depGraph").textContent.trim(),
      "No dependencies found for this project version yet.",
    );
    assert.equal(page.$("depSummary").textContent, "");
    const meta = page.$("depScanMeta").textContent;
    if (status === "error") {
      assert.ok(meta.startsWith("error: clone failed: "));
      assert.equal(meta.length, "error: ".length + 120);
    } else assert.equal(meta, "");
  });
}

test("the owner starts a scan and sees it queued", async (t) => {
  let scanned = 0;
  const queued = dependencyGraph();
  queued.version = { ...queued.version, dependency_discovery_status: "queued" };
  const page = await dependencyTab(t, {
    me: account("maintainer"),
    api: (method, path, body, answers) => {
      if (
        method === "POST" &&
        path === "/v1/project-versions/12/dependency-discovery"
      ) {
        scanned += 1;
        answers.dependencies = queued;
        return [200, { queued: true, launched: scanned === 1 }];
      }
      return null;
    },
  });
  const button = page.$("depRunDiscoveryBtn");
  assert.equal(button.disabled, false);
  await page.click("depRunDiscoveryBtn");
  assert.ok(
    page
      .asked()
      .includes(
        "POST /v1/project-versions/12/dependency-discovery?run_now=true",
      ),
  );
  assert.equal(page.$("depScanStatus").textContent, "Queued");
  await page.click("depRunDiscoveryBtn");
  assert.deepEqual(page.toasts(), [
    ["success", "Dependency discovery started"],
    ["success", "Dependency discovery queued"],
  ]);
});

test("a refused scan is reported and the state is read again", async (t) => {
  const page = await dependencyTab(t, {
    api: (method, path) =>
      method === "POST" && path.endsWith("/dependency-discovery")
        ? [400, { detail: "This version has no source code URL." }]
        : null,
  });
  const before = page
    .asked()
    .filter((r) => r.includes("dependency-graph")).length;
  await page.click("depRunDiscoveryBtn");
  assert.deepEqual(page.toasts(), [
    ["danger", "This version has no source code URL."],
  ]);
  assert.equal(
    page.asked().filter((r) => r.includes("dependency-graph")).length,
    before + 1,
  );
  assert.equal(page.$("depScanStatus").textContent, "Complete");
});

test("someone who does not own the project cannot start a scan", async (t) => {
  const page = await dependencyTab(t, {
    me: account("maintainer", { id: 99 }),
  });
  const button = page.$("depRunDiscoveryBtn");
  assert.equal(button.disabled, true);
  assert.equal(
    button.title,
    "Only the project owner or admins can run discovery.",
  );
  // Even if the control is re-enabled by hand, the page refuses.
  button.disabled = false;
  await page.click("depRunDiscoveryBtn");
  assert.equal(page.asked().filter((r) => r.startsWith("POST")).length, 0);
  assert.deepEqual(page.toasts(), [
    [
      "danger",
      "Only the project owner or admins can run dependency discovery.",
    ],
  ]);
});

test("another version's dependencies load when it is chosen", async (t) => {
  const page = await dependencyTab(t);
  await page.choose("depVersionSelect", "11");
  assert.ok(
    page.asked().includes("GET /v1/projects/5/dependency-graph?version_id=11"),
  );
  // Returning to the tab reuses what is loaded.
  const loads = page
    .asked()
    .filter((r) => r.includes("dependency-graph")).length;
  await page.click("tabMetadataBtn");
  await page.click("tabDependencyBtn");
  assert.equal(
    page.asked().filter((r) => r.includes("dependency-graph")).length,
    loads,
  );
  assert.equal(page.window.location.hash, "#dependencies");
});

test("a dependency graph that fails to load says why", async (t) => {
  const page = await dependencyTab(t, {
    api: (method, path) =>
      path === "/v1/projects/5/dependency-graph"
        ? [404, { detail: "Project has no versions" }]
        : null,
  });
  assert.equal(
    page.$("depGraph").textContent.trim(),
    "Project has no versions",
  );

  const empty = await dependencyTab(t, {
    answers: { project: { ...PROJECT, versions: [], latest_version: null } },
  });
  assert.equal(
    empty.$("depGraph").textContent.trim(),
    "Project has no versions",
  );
});

test("dependency zoom controls scale and reset the chart", async (t) => {
  const page = await dependencyTab(t);
  const viewport = () =>
    page.doc.querySelector("#depGraph svg > g").getAttribute("transform");
  const scale = () => Number(/scale\(([\d.]+)/.exec(viewport())[1]);
  const home = viewport();
  const start = scale();
  page.$("depZoomInBtn").click();
  await pause(320);
  assert.ok(Math.abs(scale() - start * 1.2) < 0.01, viewport());
  page.$("depZoomOutBtn").click();
  await pause(320);
  assert.ok(Math.abs(scale() - start * 1.02) < 0.01, viewport());
  page.$("depZoomResetBtn").click();
  await pause(360);
  assert.equal(viewport(), home);
});
