// The comparisons page: the cross-project graph under each lens, its
// controls, tooltips, navigation and exports.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage, FEATURES } from "./support/app-page.mjs";

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function graph(lens) {
  const item =
    lens === "dependencies"
      ? [
          {
            id: "d:101",
            type: "dependency_version",
            label: "requests@2.31.0",
            ecosystem: "python",
            dependency_version_id: 101,
            usage_count: 2,
          },
          {
            id: "d:102",
            type: "dependency_version",
            label: "idna@3.6",
            dependency_version_id: 102,
            usage_count: 1,
          },
        ]
      : lens === "capabilities"
        ? [
            {
              id: "c:33",
              type: "capability",
              label: "Taxonomy: Keys",
              framework: "Taxonomy",
              framework_node_id: 33,
              usage_count: 2,
            },
            {
              id: "c:31",
              type: "capability",
              label: "Issuer",
              framework_node_id: 31,
              usage_count: 1,
            },
          ]
        : [
            { id: "l:MIT", type: "license", label: "MIT", usage_count: 2 },
            {
              id: "l:(unknown)",
              type: "license",
              label: "(unknown)",
              usage_count: 1,
            },
          ];
  return {
    nodes: [
      {
        id: "p:12",
        type: "project_version",
        label: "Wallet Kit 2.0.0",
        project_version_id: 12,
        project_id: 5,
      },
      {
        id: "p:20",
        type: "project_version",
        label: "Other <1.0>",
        project_version_id: 20,
        project_id: 6,
      },
      ...item,
    ],
    links: [
      { source: "p:12", target: item[0].id, weight: 1 },
      { source: "p:12", target: item[1].id, weight: 1 },
      { source: "p:20", target: item[0].id, weight: 1 },
    ],
    meta: { lens },
  };
}

function lensPage(t, options = {}) {
  let page;
  const api = (method, path, body) => {
    const custom = options.api?.(method, path, body);
    if (custom) return custom;
    if (path !== "/v1/visualisations/bipartite") return null;
    const asked = page ? page.requests : [];
    const last = asked
      .filter(([, p]) => p.startsWith("/v1/visualisations/bipartite"))
      .pop();
    const lens = last
      ? new URLSearchParams(last[1].split("?")[1]).get("lens")
      : options.firstLens || "capabilities";
    return [200, graph(lens)];
  };
  return appPage(t, "comparisons.html", "pages/comparisons.js", {
    ...options,
    api,
  }).then((p) => (page = p));
}

const queries = (page) =>
  page.requests
    .filter(([, p]) => p.startsWith("/v1/visualisations/bipartite"))
    .map(([, p]) => Object.fromEntries(new URLSearchParams(p.split("?")[1])));
const labels = (page) => page.texts("#bipartiteGraph svg text");
const hover = (
  page,
  node,
  type = "mouseenter",
  at = { clientX: 40, clientY: 50 },
) => node.dispatchEvent(new page.window.MouseEvent(type, at));
const tooltip = (page) => [
  page.$("vizTooltip").style.display,
  page.$("vizTooltipTitle").textContent,
  page.$("vizTooltipBody").textContent,
];
const group = (page, label) =>
  [...page.doc.querySelectorAll("#bipartiteGraph svg g")].find(
    (g) =>
      g.querySelector(":scope > text")?.textContent.includes(label) &&
      g.querySelector(":scope > circle"),
  );

test("the page opens on common capabilities and draws projects against them", async (t) => {
  const page = await lensPage(t);
  assert.deepEqual(page.errors, []);
  assert.equal(page.$("lens").value, "capabilities");
  assert.deepEqual(queries(page), [
    {
      lens: "capabilities",
      latest_only: "true",
      limit_projects: "30",
      limit_items: "80",
      min_usage: "2",
    },
  ]);
  assert.equal(page.$("chartTitle").textContent, "Common capabilities");
  assert.equal(page.$("limitItemsLabel").textContent, "Max capabilities");
  assert.equal(
    page.$("vizMeta").textContent,
    "4 nodes • 3 links • capabilities",
  );
  const drawn = labels(page).join(" | ");
  for (const label of [
    "Wallet Kit 2.0.0",
    "Other <1.0>",
    "Taxonomy: Keys",
    "Issuer",
  ])
    assert.ok(drawn.includes(label), `${label} in ${drawn}`);
  assert.equal(page.doc.querySelectorAll("#bipartiteGraph svg path").length, 3);
  // A label is text, whatever it contains.
  assert.ok(
    [...page.doc.querySelectorAll("#bipartiteGraph svg text")].every(
      (n) => n.children.length <= 1,
    ),
  );
});

test("each lens asks for its own graph and relabels the controls", async (t) => {
  const page = await lensPage(t);
  await page.choose("lens", "licenses");
  assert.equal(page.$("chartTitle").textContent, "Common licenses");
  assert.equal(page.$("limitItemsLabel").textContent, "Max licenses");
  assert.ok(labels(page).join("|").includes("MIT"));
  await page.choose("lens", "dependencies");
  assert.equal(page.$("chartTitle").textContent, "Common dependencies");
  assert.equal(page.$("limitItemsLabel").textContent, "Max dependencies");
  assert.ok(labels(page).join("|").includes("requests@2.31.0"));
  assert.deepEqual(
    queries(page).map((q) => q.lens),
    ["capabilities", "licenses", "dependencies"],
  );

  // The limits travel with Apply; blanks fall back to the defaults.
  page.$("latestOnly").checked = false;
  page.$("limitProjects").value = "10";
  page.$("limitDeps").value = "";
  page.$("minUsage").value = "5";
  await page.click("applyBtn");
  assert.deepEqual(queries(page).at(-1), {
    lens: "dependencies",
    latest_only: "false",
    limit_projects: "10",
    limit_items: "80",
    min_usage: "5",
  });
  await page.click("refreshBtn");
  assert.equal(queries(page).length, 5);
});

test("the address can name the lens; others than administrators lose the dependency lens", async (t) => {
  const named = await lensPage(t, {
    query: "?lens=licenses",
    firstLens: "licenses",
  });
  assert.equal(named.$("lens").value, "licenses");
  const deps = await lensPage(t, {
    query: "?lens=dependencies",
    firstLens: "dependencies",
  });
  assert.equal(deps.$("lens").value, "dependencies");
  const odd = await lensPage(t, { query: "?lens=colour" });
  assert.equal(odd.$("lens").value, "capabilities");

  const viewer = await lensPage(t, {
    me: account("viewer"),
    query: "?lens=dependencies",
  });
  assert.equal(
    viewer.$("lens").querySelector('option[value="dependencies"]'),
    null,
  );
  assert.equal(viewer.$("lens").value, "capabilities");
  assert.equal(queries(viewer)[0].lens, "capabilities");
});

test("hovering explains a project, an item or a connection and dims the rest", async (t) => {
  const page = await lensPage(t);
  const project = group(page, "Wallet Kit 2.0.0");
  const item = group(page, "Taxonomy: Keys");
  const lone = group(page, "Issuer");
  const link = page.doc.querySelector("#bipartiteGraph svg path");

  hover(page, project);
  assert.deepEqual(tooltip(page), ["block", "Project", "Wallet Kit 2.0.0"]);
  // The tooltip follows the pointer, kept inside the window.
  assert.equal(page.$("vizTooltip").style.left, "52px");
  hover(page, project, "mousemove", { clientX: -100, clientY: -100 });
  assert.equal(page.$("vizTooltip").style.left, "14px");
  hover(page, project, "mouseleave");
  assert.equal(tooltip(page)[0], "none");

  hover(page, item);
  assert.deepEqual(tooltip(page), [
    "block",
    "Capability",
    "Taxonomy: Keys\n2 projects • Taxonomy",
  ]);
  // Items the hovered one is not linked with are dimmed.
  const other = group(page, "Other <1.0>");
  assert.equal(other.querySelector("circle").getAttribute("opacity"), "1");
  hover(page, item, "mousemove");
  hover(page, item, "mouseleave");
  hover(page, lone);
  assert.deepEqual(tooltip(page).slice(1), [
    "Capability",
    "Issuer\n1 projects",
  ]);
  assert.equal(other.querySelector("circle").getAttribute("opacity"), "0.2");
  hover(page, lone, "mouseleave");
  assert.notEqual(other.querySelector("circle").getAttribute("opacity"), "0.2");

  hover(page, link);
  assert.equal(tooltip(page)[1], "Connection");
  assert.match(
    tooltip(page)[2],
    /^(Wallet Kit 2\.0\.0|Other <1\.0>) → (Taxonomy: Keys|Issuer)$/,
  );
  hover(page, link, "mousemove");
  hover(page, link, "mouseleave");
  assert.equal(tooltip(page)[0], "none");
});

test("clicking a project or an item opens its page", async (t) => {
  const page = await lensPage(t);
  const click = (node) =>
    node.dispatchEvent(new page.window.MouseEvent("click", { bubbles: true }));
  click(group(page, "Wallet Kit 2.0.0"));
  assert.equal(page.navigations(), 1);
  click(group(page, "Taxonomy: Keys"));
  assert.equal(page.navigations(), 2);

  await page.choose("lens", "dependencies");
  hover(page, group(page, "requests@2.31.0"));
  assert.deepEqual(tooltip(page).slice(1), [
    "Dependency",
    "requests@2.31.0\n2 projects • python",
  ]);
  click(group(page, "requests@2.31.0"));
  assert.equal(page.navigations(), 3);
  // A licence has no page of its own.
  await page.choose("lens", "licenses");
  hover(page, group(page, "MIT"));
  assert.deepEqual(tooltip(page).slice(1), ["License", "MIT\n2 projects"]);
  click(group(page, "MIT"));
  assert.equal(page.navigations(), 3);
});

test("an empty graph and a failed load each say so", async (t) => {
  const empty = await lensPage(t, {
    api: (m, path) =>
      path === "/v1/visualisations/bipartite"
        ? [200, { nodes: [], links: [] }]
        : null,
  });
  assert.match(empty.$("bipartiteGraph").textContent, /^No graph data yet\./);
  assert.equal(
    empty.$("vizMeta").textContent,
    "0 nodes • 0 links • capabilities",
  );

  let down = true;
  const failing = await lensPage(t, {
    api: (m, path) =>
      path === "/v1/visualisations/bipartite" && down
        ? [403, { detail: "Admin role required" }]
        : null,
  });
  assert.deepEqual(failing.toasts(), [["danger", "Admin role required"]]);
  assert.equal(failing.$("bipartiteGraph").textContent, "Admin role required");
  await failing.click("refreshBtn");
  await failing.click("applyBtn");
  await failing.choose("lens", "licenses");
  assert.equal(failing.toasts().length, 4);
  down = false;
  await failing.click("refreshBtn");
  assert.ok(labels(failing).join("|").includes("MIT"));
});

test("the graph exports as an image or PDF named after the lens and the day", async (t) => {
  const page = await lensPage(t);
  const day = new Date().toISOString().slice(0, 10);
  await page.click("exportGraphJpegBtn");
  await pause(20);
  await page.click("exportGraphPdfBtn");
  await pause(20);
  assert.deepEqual(
    page.record.downloads.map((d) => d.name),
    [`visualisations_capabilities_${day}.jpg`],
  );
  assert.deepEqual(
    page.record.pdfs.map((p) => p.name),
    [`visualisations_capabilities_${day}.pdf`],
  );
  const svg = decodeURIComponent(page.record.images[0].split(",")[1]);
  assert.ok(svg.includes("Taxonomy: Keys"));

  const empty = await lensPage(t, {
    pdf: false,
    api: (m, path) =>
      path === "/v1/visualisations/bipartite"
        ? [200, { nodes: [], links: [] }]
        : null,
  });
  await empty.click("exportGraphJpegBtn");
  assert.deepEqual(empty.toasts(), [
    ["danger", "Nothing to export yet (no graph rendered)"],
  ]);

  const noPdf = await lensPage(t, { pdf: false });
  await noPdf.click("exportGraphPdfBtn");
  await pause(20);
  assert.deepEqual(noPdf.toasts(), [
    ["danger", "PDF export library (jsPDF) is not available"],
  ]);

  const broken = await lensPage(t, { imageFails: true });
  await broken.click("exportGraphJpegBtn");
  await pause(20);
  assert.deepEqual(broken.toasts(), [["danger", "decode"]]);
});

test("the graph is redrawn on resize, and the page leaves when the feature is off", async (t) => {
  const page = await lensPage(t);
  const before = page.doc.querySelector("#bipartiteGraph svg");
  page.window.dispatchEvent(new page.window.Event("resize"));
  assert.notEqual(page.doc.querySelector("#bipartiteGraph svg"), before);
  assert.equal(queries(page).length, 1);

  const off = await lensPage(t, {
    me: account("admin", { features: { ...FEATURES, comparisons: false } }),
  });
  assert.equal(off.navigations(), 1);
  assert.equal(queries(off).length, 0);
});
