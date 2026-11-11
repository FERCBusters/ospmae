// The project page's capability charts, tabs and details: the real page,
// app.js, project.js and d3 against an API fixture.
import test from "node:test";
import assert from "node:assert/strict";
import {
  PROJECT,
  VERSIONS,
  account,
  capabilityGraph,
  projectPage,
} from "./support/project-page.mjs";

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const labels = (page) =>
  page.texts("#graph svg text").map((text) => text.replace(/\s+/g, " "));
const transform = (page) =>
  page.doc.querySelector("#graph svg > g").getAttribute("transform");

test("the page opens on the capability treemap of the latest version", async (t) => {
  const page = await projectPage(t);
  assert.deepEqual(page.errors, []);
  assert.equal(page.$("projectTitle").textContent, "Wallet Kit");
  assert.equal(
    page.$("projectSubTitle").textContent,
    "wallet-kit • Acme • library",
  );
  assert.ok(
    page
      .asked()
      .includes("GET /v1/projects/5/graph?version_id=12&framework_id=3"),
  );
  // Both version pickers offer every version and start on Latest.
  for (const id of ["versionSelect", "depVersionSelect"]) {
    assert.deepEqual(page.texts(`#${id} option`), ["2.0.0 (latest)", "1.0.0"]);
    assert.equal(page.$(id).value, "12");
  }
  assert.equal(page.$("visualTypeSelect").value, "treemap");
  assert.equal(
    page.$("visualSummary").textContent,
    "5 tiles • focus: Capabilities",
  );
  const drawn = labels(page);
  for (const tile of [
    "Issuer1 capability",
    "Wallet2 capabilities",
    "Storage2 capabilities",
    "Keys1 capability",
  ])
    assert.ok(drawn.includes(tile), `${tile} in ${drawn.join(" | ")}`);
  assert.ok(page.$("capabilitiesTab").classList.contains("active"));
  assert.equal(
    page.$("tabCapabilitiesBtn").getAttribute("aria-selected"),
    "true",
  );
});

test("each chart type draws the version's selected branch", async (t) => {
  const page = await projectPage(t);
  const full = "Backup & recovery of credentials";

  await page.choose("visualTypeSelect", "tidy-tree");
  assert.equal(page.$("visualSummary").textContent, "7 nodes, 6 links");
  assert.equal(page.doc.querySelectorAll("#graph svg path").length, 6);
  // A long label is shortened on the chart and kept whole in its tooltip.
  const tidy = [...page.doc.querySelectorAll("#graph svg text")];
  const long = tidy.find((node) => node.textContent.includes(full));
  assert.equal(long.querySelector("title").textContent, full);
  assert.ok(long.textContent.replace(full, "").endsWith("…"));
  assert.ok(labels(page).includes("v2.0.0v2.0.0"));

  await page.choose("visualTypeSelect", "radial-tree");
  assert.equal(page.$("visualSummary").textContent, "7 nodes in radial layout");
  assert.equal(page.doc.querySelectorAll("#graph svg circle").length, 7);

  await page.choose("visualTypeSelect", "bipartite");
  assert.equal(page.$("visualSummary").textContent, "3 mapped capabilities");
  // Only the selected leaves face the version; ancestors are not listed.
  assert.deepEqual(
    labels(page).map((l) => l.replace(/….*$/, "…")),
    ["v2.0.0", "IssuerIssuer", "Backup & recovery…", "KeysKeys"],
  );
  assert.equal(page.doc.querySelectorAll("#graph svg path").length, 3);

  await page.choose("visualTypeSelect", "sunburst");
  assert.equal(page.$("visualSummary").textContent, "6 sunburst segments");
  assert.deepEqual(
    new Set(labels(page)),
    new Set([
      "v2.0.0",
      "Wallet",
      "Issuer",
      "Storage",
      "Backup & recovery of …",
      "Keys",
    ]),
  );
  assert.deepEqual(page.errors, []);
});

test("zoom buttons scale the chart and Reset returns it home", async (t) => {
  const page = await projectPage(t);
  await page.choose("visualTypeSelect", "tidy-tree");
  const home = transform(page);
  assert.match(home, /scale\(1\)/);
  for (const id of ["zoomInBtn", "zoomOutBtn", "zoomResetBtn"])
    assert.equal(page.$(id).disabled, false);

  page.$("zoomInBtn").click();
  await pause(320);
  assert.match(transform(page), /scale\(1\.2\)/);
  page.$("zoomOutBtn").click();
  await pause(320);
  assert.match(transform(page), /scale\(1\.02\)/);
  page.$("zoomResetBtn").click();
  await pause(360);
  assert.equal(transform(page), home);
});

test("choosing another version reloads its graph and details", async (t) => {
  const older = capabilityGraph(VERSIONS[1]);
  older.capability_tree = [];
  older.nodes = older.nodes.slice(0, 2);
  older.links = older.links.slice(0, 1);
  const page = await projectPage(t, {
    api: (method, path) =>
      path === "/v1/projects/5/graph" && page_version(page_requests) === "11"
        ? [200, older]
        : null,
  });
  // The fixture answers by the version the page asks for.
  function page_version(requests) {
    const last = requests()
      .filter((r) => r.includes("/graph"))
      .pop();
    return new URLSearchParams(last.split("?")[1]).get("version_id");
  }
  function page_requests() {
    return page.asked();
  }
  await page.choose("versionSelect", "11");
  assert.ok(
    page
      .asked()
      .includes("GET /v1/projects/5/graph?version_id=11&framework_id=3"),
  );
  // The older version maps nothing, and borrows nothing from the latest.
  for (const tile of ["Issuer", "Keys", "Wallet2", "Storage"])
    assert.ok(!page.$("graph").textContent.includes(tile), tile);
  assert.ok(page.$("graph").textContent.includes("v1.0.0"));
  assert.equal(
    page.$("projectManifestName").value,
    "wallet-kit_1.0.0_manifest",
  );
  // The details follow the chosen version too.
  await page.click("tabMetadataBtn");
  assert.match(
    page.$("projectMetadata").textContent,
    /No capability mappings on this version\./,
  );
});

test("the details tab lists the project, its capabilities and versions", async (t) => {
  const page = await projectPage(t, {
    answers: {
      project: {
        ...PROJECT,
        description: "A <b>wallet</b> toolkit",
        owner_groups: [{ name: "Core" }, { name: "Docs" }],
        versions: [
          ...VERSIONS,
          {
            id: 13,
            version: "3.0.0-rc1",
            is_draft: true,
            is_latest: false,
            status: null,
            release_date: "not a date",
            link_to_source_code: "javascript:alert(1)",
            capability_paths: [],
          },
        ],
      },
    },
  });
  await page.click("tabMetadataBtn");
  assert.ok(page.$("metadataTab").classList.contains("active"));
  assert.equal(page.window.location.hash, "#metadata");
  const body = page.$("projectMetadata");
  const text = body.textContent.replace(/\s+/g, " ");
  for (const fact of [
    "Name: Wallet Kit",
    "Machine name: wallet-kit",
    "Organisation: Acme",
    "Type: library",
    "Languages: Rust, Go",
    "Owner groups: Core, Docs",
  ])
    assert.ok(text.includes(fact), fact);
  // Text from the API is shown as text, never as markup.
  assert.equal(body.querySelector("b"), null);
  assert.ok(text.includes("A <b>wallet</b> toolkit"));
  const pills = [...body.querySelectorAll(".capability-pill")];
  assert.deepEqual(
    pills.map((p) => [p.textContent.trim(), p.getAttribute("title")]),
    [
      ["Keys", "Wallet > Storage > Keys"],
      ["Issuer", "Issuer"],
    ],
  );
  const rows = [...body.querySelectorAll("tbody tr")].map((row) =>
    [...row.children].map((cell) =>
      cell.textContent.replace(/\s+/g, " ").trim(),
    ),
  );
  assert.deepEqual(rows[0].slice(0, 3), [
    "2.0.0 Latest",
    "stable",
    "2026-03-04",
  ]);
  assert.deepEqual(rows[1].slice(0, 3), ["1.0.0", "obsolete", "2025-01-02"]);
  assert.deepEqual(rows[2].slice(0, 3), ["3.0.0-rc1 Draft", "—", "not a date"]);
  const links = [...body.querySelectorAll("tbody a")].map((a) =>
    a.getAttribute("href"),
  );
  // Only a web address becomes a link.
  assert.deepEqual(links, ["https://github.com/example/repo"]);
});

test("a project without versions says so instead of drawing", async (t) => {
  const page = await projectPage(t, {
    answers: {
      project: {
        ...PROJECT,
        display_name: "",
        organisation: null,
        versions: [],
        latest_version: null,
        programming_languages: null,
        owner_group: "Solo",
      },
    },
  });
  assert.equal(page.$("projectTitle").textContent, "wallet-kit");
  assert.equal(page.$("projectSubTitle").textContent, "wallet-kit • library");
  assert.equal(
    page.$("graph").textContent,
    "No graph data available for this version.",
  );
  assert.equal(page.asked().filter((r) => r.includes("/graph")).length, 0);
  await page.click("tabMetadataBtn");
  const text = page.$("projectMetadata").textContent.replace(/\s+/g, " ");
  assert.ok(text.includes("No versions available."));
  assert.ok(text.includes("Languages: —"));
  assert.ok(text.includes("Owner group: Solo"));
});

test("without the chart library the page explains itself", async (t) => {
  const page = await projectPage(t, { d3: false });
  assert.equal(page.$("graph").textContent, "D3 library is unavailable.");
  assert.equal(page.$("projectTitle").textContent, "Wallet Kit");
});

test("a missing or failing project is reported", async (t) => {
  const absent = await projectPage(t, { query: "?id=abc" });
  assert.equal(absent.$("graph").textContent, "Missing or invalid project id");
  assert.equal(
    absent.asked().filter((r) => r.includes("/v1/projects")).length,
    0,
  );

  const refused = await projectPage(t, {
    api: (method, path) =>
      path === "/v1/projects/5" ? [404, { detail: "Project not found" }] : null,
  });
  assert.equal(refused.$("graph").textContent, "Project not found");
});

test("tabs follow the address, older names and the installation's features", async (t) => {
  const deep = await projectPage(t, { hash: "#metadata" });
  assert.ok(deep.$("metadataTab").classList.contains("active"));
  assert.equal(deep.window.location.hash, "#metadata");

  const legacy = await projectPage(t, { query: "?id=5&tab=visualise" });
  assert.ok(legacy.$("capabilitiesTab").classList.contains("active"));
  const unknown = await projectPage(t, { hash: "#nonsense" });
  assert.ok(unknown.$("capabilitiesTab").classList.contains("active"));

  // A back/forward move between tabs follows the address.
  deep.window.location.hash = "#changelog";
  deep.window.dispatchEvent(new deep.window.Event("hashchange"));
  await deep.wait();
  assert.ok(deep.$("changelogTab").classList.contains("active"));
  assert.ok(deep.asked().includes("GET /v1/projects/5/changelog?limit=100"));

  const lean = await projectPage(t, {
    hash: "#dependencies",
    me: account("viewer", {
      features: {
        frameworks: false,
        manifests: false,
        questions: false,
        dependency_scans: false,
        comparisons: true,
        release_feed: true,
      },
    }),
  });
  for (const id of [
    "tabCapabilitiesBtn",
    "tabDependencyBtn",
    "tabQuestionsBtn",
  ])
    assert.equal(lean.$(id).style.display, "none", id);
  // A link to a tab that is switched off lands on the details instead.
  assert.ok(lean.$("metadataTab").classList.contains("active"));
  assert.equal(lean.$("manifestExportField").style.display, "none");
  const asked = lean.asked();
  assert.equal(asked.filter((r) => r.includes("/v1/frameworks")).length, 0);
  assert.equal(asked.filter((r) => r.includes("dependency-graph")).length, 0);
});

test("editing links are offered to those who maintain projects", async (t) => {
  const maintainer = await projectPage(t, { me: account("maintainer") });
  assert.equal(
    maintainer.$("editProjectLink").getAttribute("href"),
    "/project-edit.html?id=5",
  );
  assert.equal(
    maintainer.$("editVersionsLink").getAttribute("href"),
    "/project-edit.html?id=5#versions",
  );
  assert.equal(maintainer.$("editVersionsLink").style.display, "");

  const viewer = await projectPage(t, { me: account("viewer") });
  assert.equal(viewer.$("editProjectLink").style.display, "none");
  assert.equal(viewer.$("editVersionsLink").style.display, "none");
});

test("the changelog loads once, when its tab is first opened", async (t) => {
  const page = await projectPage(t, {
    answers: {
      changelog: {
        total: 1,
        items: [
          {
            id: "a",
            action: "updated",
            entity_title: "Wallet Kit",
            summary: "License changed",
            changed_by_username: "ada",
            changed_at: "2026-03-04T10:00:00",
            changes: [
              {
                field: "license",
                label: "License",
                before: "MIT",
                after: "Apache-2.0",
              },
            ],
          },
        ],
      },
    },
  });
  const loads = () =>
    page.asked().filter((r) => r.includes("/v1/projects/5/changelog")).length;
  assert.equal(loads(), 0);
  await page.click("tabChangelogBtn");
  assert.equal(loads(), 1);
  const text = page.$("projectChangelog").textContent;
  assert.ok(text.includes("License"));
  assert.ok(text.includes("Apache-2.0"));
  await page.click("tabMetadataBtn");
  await page.click("tabChangelogBtn");
  assert.equal(loads(), 1);
});

test("a changelog that fails to load says so", async (t) => {
  const page = await projectPage(t, {
    api: (method, path) =>
      path === "/v1/projects/5/changelog" ? [500, { detail: "boom" }] : null,
  });
  await page.click("tabChangelogBtn");
  assert.match(
    page.$("projectChangelog").textContent,
    /Failed to load changelog|boom/,
  );
});
