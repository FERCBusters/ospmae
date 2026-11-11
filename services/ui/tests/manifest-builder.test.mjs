// The manifest builder: the capability treemap as a project filter, the
// project cards and their selection, and exporting or saving the result.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage, FRAMEWORK } from "./support/app-page.mjs";

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const named = (...names) => names.map((name, i) => ({ id: 5 + i, name }));

const ISSUER = {
  id: 11,
  key: "issuer",
  display_name: "Issuer",
  project_count_total: 1,
  project_count_direct: 1,
  projects_total: named("Wallet Kit"),
  projects_direct: named("Wallet Kit"),
};
const KEYS = {
  id: 13,
  key: "keys",
  display_name: "Keys",
  project_count_total: 2,
  project_count_direct: 2,
  projects_total: named("Wallet Kit", "Other"),
};
const WALLET = {
  id: 12,
  key: "wallet",
  display_name: "Wallet",
  project_count_total: 2,
  project_count_descendants: 2,
  projects_total: named("Wallet Kit", "Other"),
  children: [KEYS],
};
const IDENTITY = {
  id: 10,
  key: "identity",
  display_name: "Identity",
  project_count_total: 3,
  project_count_direct: 1,
  project_count_descendants: 2,
  projects_total: [
    ...named("Wallet Kit", "Other", ""),
    { id: -1, name: "+4 more" },
  ],
  projects_direct: named("Bare <b>"),
  children: [ISSUER, WALLET],
};
// Mapped at the parent only: its sub-capability has no projects of its own.
const STORAGE = {
  id: 20,
  key: "storage",
  display_name: "Storage",
  project_count_total: 1,
  project_count_direct: 1,
  project_count_descendants: 0,
  projects_total: named("Wallet Kit"),
  projects_direct: named("Wallet Kit"),
  children: [{ id: 21, key: "backups", display_name: "Backups" }],
};
const ROOT = {
  id: 1,
  key: "taxonomy",
  display_name: "Taxonomy",
  children: [IDENTITY, STORAGE],
};

function flatten(node, parent = null, trail = []) {
  const path = [...trail, node.display_name];
  return [
    { ...node, children: undefined, parent_id: parent, path: path.join(" > ") },
    ...(node.children || []).flatMap((child) => flatten(child, node.id, path)),
  ];
}

const PROJECTS = [
  {
    id: 5,
    display_name: "Wallet Kit",
    machine_name: "wallet-kit",
    organisation: "Acme",
    project_type: "library",
    latest_version: { version: "2.0.0" },
    capability_pairs: [
      { capability_id: 11, capability_path: "Taxonomy > Identity > Issuer" },
      { capability_id: null, capability_path: "" },
    ],
  },
  {
    id: 6,
    machine_name: "other",
    // Paths as some endpoints send them: without the framework root.
    capability_paths: ["Identity / Wallet / Keys", "Somewhere else"],
  },
  { id: 8, display_name: "Bare <b>" },
];

function builder(t, options = {}) {
  const tree = options.tree || [ROOT];
  const api = (method, path, body, query) => {
    const custom = options.api?.(method, path, body, query);
    if (custom) return custom;
    if (path === `/v1/frameworks/${FRAMEWORK.id}/catalogue`)
      return [200, { tree, items: tree.flatMap((root) => flatten(root)) }];
    if (path === "/v1/projects") {
      const node = query.get("node_ids");
      return [
        200,
        {
          items:
            node === "11"
              ? PROJECTS.slice(0, 1)
              : node === "21"
                ? []
                : PROJECTS,
        },
      ];
    }
    if (path === "/v1/manifests/export") return [200, "exported"];
    if (path === "/v1/manifests") return [201, { id: 90 }];
    if (path === "/v1/me/preferences")
      return [200, body || options.preferences || {}];
    return null;
  };
  return appPage(t, "manifests.html", "pages/manifest-builder.js", {
    ...options,
    api,
  }).then((page) => {
    const queries = (route) =>
      page.requests
        .filter(([, path]) => path.split("?")[0] === route)
        .map(([, path]) =>
          Object.fromEntries(new URLSearchParams(path.split("?")[1] || "")),
        );
    const within = (selector, name) =>
      [...page.doc.querySelectorAll(`#capabilityTreemap ${selector}`)].find(
        (g) =>
          g
            .querySelector("title, .t1")
            ?.textContent.split("\n")[0]
            .endsWith(name),
      );
    return {
      ...page,
      queries,
      projectQueries: () => queries("/v1/projects"),
      tile: (name) => within("g.cell", name),
      label: (name) => within("g.container-label", name),
      async press(node) {
        node.dispatchEvent(
          new page.window.MouseEvent("click", { bubbles: true }),
        );
        await page.wait();
      },
      breadcrumb: () =>
        page.doc.querySelector("#capabilityTreemap svg text").textContent,
      cards: () =>
        [...page.doc.querySelectorAll("#projects .project-card")].map(
          (card) => ({
            name: card.querySelector("h3").textContent,
            selected: card.classList.contains("selected"),
            box: card.querySelector("input.project-select")?.checked,
          }),
        ),
      pick(select, ...values) {
        for (const option of page.$(select).options)
          option.selected = values.includes(option.value);
        page
          .$(select)
          .dispatchEvent(new page.window.Event("change", { bubbles: true }));
        return page.wait();
      },
    };
  });
}

test("the builder opens on every project of the active framework", async (t) => {
  const page = await builder(t);
  assert.deepEqual(page.errors, []);
  assert.deepEqual(page.projectQueries(), [{ framework_id: "3" }]);
  assert.equal(page.$("projectsCount").textContent, "3 projects");
  assert.equal(
    page.$("activeFiltersSummary").textContent,
    "No filters active.",
  );
  assert.match(
    page.$("capabilityTreemapMeta").textContent,
    /^Showing all projects · /,
  );
  assert.equal(
    page.$("manifestSelectionInfo").textContent,
    "No projects selected (3 available)",
  );
  assert.equal(page.$("manifestControls").style.display, "");
  assert.equal(page.$("autoApplyFilters").checked, true);
});

test("each project card shows its organisation, type, latest version and capabilities", async (t) => {
  const page = await builder(t);
  const cards = [...page.doc.querySelectorAll("#projects .project-card")];
  const text = (card) => card.textContent.replace(/\s+/g, " ").trim();
  assert.equal(
    text(cards[0]),
    "Wallet Kit Acme Type: library Latest: 2.0.0 Categories: 2 Taxonomy > Identity > Issuer",
  );
  assert.equal(
    text(cards[1]),
    "other — Type: n/a Latest: n/a Categories: 2 Identity / Wallet / KeysSomewhere else",
  );
  assert.equal(
    text(cards[2]),
    "Bare <b> — Type: n/a Latest: n/a Categories: 0 No categories tagged",
  );
  assert.equal(
    cards[0].querySelector("h3 a").getAttribute("href"),
    "/project.html?id=5",
  );
  // A capability the framework knows carries its group's colour, with or
  // without the framework root in its path; an unknown path is left plain.
  const styles = [...page.doc.querySelectorAll("#projects .tag")].map((tag) =>
    tag.getAttribute("style"),
  );
  assert.match(
    styles[0],
    /^background:rgba\(\d+, \d+, \d+, 0\.14\); color:#[0-9a-f]{6};/i,
  );
  assert.equal(styles[1], styles[0]);
  assert.equal(styles[2], null);
});

test("no matching projects is said in the list", async (t) => {
  const page = await builder(t, {
    api: (method, path) =>
      path === "/v1/projects" ? [200, { items: [] }] : null,
  });
  assert.equal(page.$("projectsCount").textContent, "0 projects");
  assert.equal(
    page.$("projects").textContent,
    "No projects found for the current filters.",
  );
  assert.equal(
    page.$("manifestSelectionInfo").textContent,
    "No projects selected (0 available)",
  );
});

test("one project is counted in the singular", async (t) => {
  const page = await builder(t);
  await page.press(page.tile("Issuer"));
  assert.equal(page.$("projectsCount").textContent, "1 project");
});

test("the treemap draws the framework with project counts on its tiles", async (t) => {
  const page = await builder(t);
  assert.equal(page.breadcrumb(), "Taxonomy");
  const titles = page.texts("#capabilityTreemap g.cell title");
  assert.deepEqual(titles.map((title) => title.split(" Total")[0]).sort(), [
    "Taxonomy > Identity",
    "Taxonomy > Identity > Issuer",
    "Taxonomy > Identity > Wallet",
    "Taxonomy > Identity > Wallet > Keys",
    "Taxonomy > Storage",
    "Taxonomy > Storage > Backups",
  ]);
  assert.equal(
    page.tile("Identity").querySelector("title").textContent,
    [
      "Taxonomy > Identity",
      "Total: 3 projects",
      "Projects: Wallet Kit, Other, +4 more +4 more",
      "Direct on this capability: 1",
      "Direct projects: Bare <b>",
    ].join("\n"),
  );
  assert.equal(
    page.tile("Storage").querySelector("title").textContent,
    [
      "Taxonomy > Storage",
      "Total: 1 project",
      "Projects: Wallet Kit",
      "Direct on this capability: 1",
      "Direct projects: Wallet Kit",
      "Note: sub-capabilities may show 0 unless mapped explicitly.",
    ].join("\n"),
  );
  assert.equal(
    page.tile("Backups").querySelector("title").textContent,
    "Taxonomy > Storage > Backups\nTotal: 0 projects",
  );
  // Groups carry a heading with their count; a parent-only mapping says so.
  assert.deepEqual(
    page.texts("#capabilityTreemap g.container-label text").sort(),
    ["Identity3 projects", "Storage1 project (direct)", "Wallet2 projects"],
  );
  assert.equal(page.$("capabilityTreemapDetails").style.display, "none");
});

test("choosing a capability filters the projects and zooms into a group", async (t) => {
  const page = await builder(t);
  await page.press(page.tile("Identity"));
  assert.deepEqual(page.projectQueries().at(-1), {
    framework_id: "3",
    node_ids: "10",
  });
  assert.equal(page.breadcrumb(), "Taxonomy > Identity");
  assert.equal(
    page.$("activeFiltersSummary").textContent,
    "Capability: Taxonomy > Identity",
  );
  assert.match(
    page.$("capabilityTreemapMeta").textContent,
    /^Showing projects for: Taxonomy > Identity · /,
  );
  const details = page.$("capabilityTreemapDetails");
  assert.equal(details.style.display, "");
  assert.equal(
    details.querySelector(".fw-semibold").textContent,
    "Identity: 3 projects",
  );
  assert.deepEqual(
    [...details.querySelectorAll(".badge")].map((badge) => [
      badge.textContent,
      badge.getAttribute("href"),
    ]),
    [
      ["Wallet Kit", "/project.html?id=5"],
      ["Other", "/project.html?id=6"],
      ["+4 more", null],
      ["Bare <b>", "/project.html?id=5"],
    ],
  );
  assert.match(
    details.textContent,
    /Directly mapped to this capability \(1\):/,
  );
  assert.doesNotMatch(details.textContent, /but not any sub-capabilities/);

  // A leaf filters without zooming further.
  await page.press(page.tile("Issuer"));
  assert.equal(page.projectQueries().at(-1).node_ids, "11");
  assert.equal(page.breadcrumb(), "Taxonomy > Identity");
  assert.deepEqual(
    page.cards().map((card) => card.name),
    ["Wallet Kit"],
  );
});

test("a group mapped only at the parent explains its empty sub-capabilities", async (t) => {
  const page = await builder(t);
  await page.press(page.label("Storage"));
  assert.equal(page.breadcrumb(), "Taxonomy > Storage");
  assert.equal(page.projectQueries().at(-1).node_ids, "20");
  assert.match(
    page.$("capabilityTreemapDetails").textContent,
    /^Storage: 1 project.*These projects selected the parent capability but not any sub-capabilities\./,
  );
});

test("the selected tile is outlined once the treemap settles", async (t) => {
  const page = await builder(t);
  await page.press(page.tile("Issuer"));
  await pause(700);
  const stroke = (name) =>
    page.tile(name).querySelector("rect").getAttribute("stroke-width");
  assert.equal(stroke("Issuer"), "2.6");
  assert.equal(stroke("Keys"), "1.2");
  const rect = page.tile("Issuer").querySelector("rect");
  assert.ok(Number(rect.getAttribute("width")) > 0);
  assert.match(rect.getAttribute("fill"), /^rgb\(\d+, \d+, \d+\)$/);
});

test("the background clears the capability and zooms back out", async (t) => {
  const page = await builder(t);
  await page.press(page.tile("Identity"));
  await page.press(page.doc.querySelector("#capabilityTreemap svg"));
  assert.equal(page.breadcrumb(), "Taxonomy");
  assert.deepEqual(page.projectQueries().at(-1), { framework_id: "3" });
  assert.equal(
    page.$("activeFiltersSummary").textContent,
    "No filters active.",
  );
  assert.equal(page.$("capabilityTreemapDetails").style.display, "none");
});

test("a framework with several roots is drawn under one heading", async (t) => {
  const page = await builder(t, { tree: [IDENTITY, STORAGE] });
  assert.equal(page.breadcrumb(), "Capabilities");
  assert.ok(page.tile("Capabilities > Identity"));
  await page.press(page.tile("Wallet"));
  assert.equal(page.breadcrumb(), "Capabilities > Identity > Wallet");
  assert.equal(
    page.$("activeFiltersSummary").textContent,
    "Capability: Identity > Wallet",
  );
});

test("searching capabilities jumps to the first match", async (t) => {
  const page = await builder(t);
  const enter = async (term, key = "Enter") => {
    page.$("capabilitySearch").value = term;
    page
      .$("capabilitySearch")
      .dispatchEvent(
        new page.window.KeyboardEvent("keydown", { key, cancelable: true }),
      );
    await page.wait();
  };
  await enter("keys", "k");
  await enter("  ");
  assert.equal(page.projectQueries().length, 1);

  // A leaf opens its group; a group opens itself.
  await enter("KEYS");
  assert.equal(page.breadcrumb(), "Taxonomy > Identity > Wallet");
  assert.equal(page.projectQueries().at(-1).node_ids, "13");
  await enter("storage");
  assert.equal(page.breadcrumb(), "Taxonomy > Storage");
  assert.equal(page.projectQueries().at(-1).node_ids, "20");

  await enter("nothing like this");
  assert.deepEqual(page.toasts(), [["warning", "No matching capabilities."]]);
  assert.equal(page.projectQueries().length, 3);
});

test("text, language and status filters apply as they change", async (t) => {
  const page = await builder(t);
  await page.type("q", " wallet ");
  assert.equal(page.projectQueries().length, 1);
  await pause(300);
  await page.wait();
  assert.deepEqual(page.projectQueries().at(-1), {
    q: "wallet",
    framework_id: "3",
  });

  await page.pick("languageFilter", "Python", "Go", "Rust", "C", "Java");
  await page.pick("statusFilter", "stable", "beta");
  assert.deepEqual(page.projectQueries().at(-1), {
    q: "wallet",
    framework_id: "3",
    languages: "Python,Go,Rust,C,Java",
    statuses: "stable,beta",
  });
  assert.equal(
    page.$("activeFiltersSummary").textContent,
    "Search: “wallet” · Languages: Python, Go, Rust, C + · Status: stable, beta",
  );
});

test("with auto-apply off, filters wait for Apply", async (t) => {
  const page = await builder(t, {
    preferences: { auto_apply_enabled: false },
  });
  assert.equal(page.$("autoApplyFilters").checked, false);
  await page.type("q", "wallet");
  await page.pick("languageFilter", "Python");
  await page.pick("statusFilter", "stable");
  await pause(300);
  assert.equal(page.projectQueries().length, 1);
  assert.equal(
    page.$("activeFiltersSummary").textContent,
    "Search: “wallet” · Languages: Python · Status: stable",
  );
  await page.click("applyFiltersBtn");
  assert.deepEqual(page.projectQueries().at(-1), {
    q: "wallet",
    framework_id: "3",
    languages: "Python",
    statuses: "stable",
  });
});

test("the auto-apply switch is saved as a preference", async (t) => {
  let refuse = false;
  const page = await builder(t, {
    api: (method, path) =>
      refuse && path === "/v1/me/preferences"
        ? [500, { detail: "Preferences unavailable" }]
        : null,
  });
  page.$("autoApplyFilters").checked = false;
  await page.choose("autoApplyFilters", "on");
  assert.equal(
    page.sent("PUT", "/v1/me/preferences").at(-1).auto_apply_enabled,
    false,
  );
  refuse = true;
  await page.choose("autoApplyFilters", "on");
  assert.deepEqual(page.toasts(), [
    ["success", "Auto-apply preference saved."],
    ["danger", "Preferences unavailable"],
  ]);
});

test("Reset clears every filter, the capability and the selection", async (t) => {
  const page = await builder(t);
  await page.press(page.tile("Identity"));
  await page.type("q", "wallet");
  await page.pick("languageFilter", "Python");
  await page.pick("statusFilter", "stable");
  page.$("capabilitySearch").value = "keys";
  await page.click("selectVisibleBtn");
  await page.click("resetFiltersBtn");
  assert.deepEqual(page.projectQueries().at(-1), { framework_id: "3" });
  assert.equal(page.$("q").value, "");
  assert.equal(page.$("capabilitySearch").value, "");
  assert.equal(page.$("languageFilter").selectedOptions.length, 0);
  assert.equal(page.$("statusFilter").selectedOptions.length, 0);
  assert.equal(page.breadcrumb(), "Taxonomy");
  assert.equal(
    page.$("activeFiltersSummary").textContent,
    "No filters active.",
  );
  assert.equal(
    page.$("manifestSelectionInfo").textContent,
    "No projects selected (3 available)",
  );
});

test("projects are selected by their box, their card, or all at once", async (t) => {
  const page = await builder(t);
  const card = (id) =>
    page.doc.querySelector(`#projects .project-card[data-project-id="${id}"]`);
  await page.click(card(6).querySelector("input.project-select"));
  assert.deepEqual(
    page.cards().map((c) => [c.selected, c.box]),
    [
      [false, false],
      [true, true],
      [false, false],
    ],
  );
  assert.equal(
    page.$("manifestSelectionInfo").textContent,
    "1 of 3 projects selected",
  );

  await page.click(card(8));
  await page.click(card(6));
  assert.deepEqual(
    page.cards().map((c) => c.selected),
    [false, false, true],
  );
  // Following the project's link leaves the selection alone.
  await page.click(card(5).querySelector("h3 a"));
  assert.equal(page.cards()[0].selected, false);

  await page.click(card(8).querySelector("input.project-select"));
  assert.equal(page.cards()[2].selected, false);

  await page.click("selectVisibleBtn");
  assert.equal(
    page.$("manifestSelectionInfo").textContent,
    "3 of 3 projects selected",
  );
  await page.click("clearSelectionBtn");
  assert.deepEqual(
    page.cards().map((c) => c.selected),
    [false, false, false],
  );
});

test("exports carry the filters and the selection, named after the manifest", async (t) => {
  const page = await builder(t);
  await page.press(page.tile("Identity"));
  await page.type("q", "wallet");
  await page.pick("languageFilter", "Python");
  await page.pick("statusFilter", "stable");
  await page.click("selectVisibleBtn");
  page.$("manifestName").value = " q3 review ";
  await page.click("exportJsonBtn");
  await page.click("exportXlsxBtn");
  await page.click("exportMdBtn");
  const shared = {
    name: "q3 review",
    q: "wallet",
    framework_id: "3",
    node_ids: "10",
    languages: "Python",
    statuses: "stable",
    project_ids: "5,6,8",
  };
  assert.deepEqual(page.queries("/v1/manifests/export"), [
    { format: "json", ...shared },
    { format: "xlsx", ...shared },
    { format: "markdown", ...shared },
  ]);
  assert.deepEqual(
    page.record.downloads.map((download) => download.name),
    ["q3 review.json", "q3 review.xlsx", "q3 review.md"],
  );
  assert.deepEqual(page.toasts(), []);
});

test("an export without a name or filters uses the default name", async (t) => {
  const page = await builder(t);
  page.$("manifestName").value = "  ";
  await page.click("exportJsonBtn");
  assert.deepEqual(page.queries("/v1/manifests/export"), [
    { format: "json", name: "project-manifest", framework_id: "3" },
  ]);
  assert.equal(page.record.downloads[0].name, "project-manifest.json");
});

test("a failed export is reported", async (t) => {
  const page = await builder(t, {
    api: (method, path) =>
      path === "/v1/manifests/export"
        ? [403, { detail: "Not allowed to export" }]
        : null,
  });
  await page.click("exportJsonBtn");
  assert.deepEqual(page.toasts(), [["danger", "Not allowed to export"]]);
  assert.deepEqual(page.record.downloads, []);
});

test("saving stores the name, filters and selected projects", async (t) => {
  const page = await builder(t);
  await page.press(page.tile("Issuer"));
  await page.click("selectVisibleBtn");
  page.$("manifestName").value = " Issuers ";
  page.$("manifestDescription").value = " For the review ";
  await page.type("q", "wallet");
  await page.click("saveManifestBtn");
  assert.deepEqual(page.sent("POST", "/v1/manifests"), [
    {
      name: "Issuers",
      description: "For the review",
      q: "wallet",
      framework_id: 3,
      node_ids: [11],
      project_ids: [5],
    },
  ]);
  assert.deepEqual(page.toasts(), [["info", "Manifest saved."]]);

  page.$("manifestDescription").value = "";
  await page.click("resetFiltersBtn");
  await page.click("saveManifestBtn");
  assert.deepEqual(page.sent("POST", "/v1/manifests")[1], {
    name: "Issuers",
    description: null,
    q: null,
    framework_id: 3,
    node_ids: [],
    project_ids: [],
  });
});

test("a manifest needs a name, and a refused save is reported", async (t) => {
  const page = await builder(t, {
    api: (method, path) =>
      method === "POST" && path === "/v1/manifests"
        ? [409, { detail: "A manifest with this name exists" }]
        : null,
  });
  page.$("manifestName").value = "   ";
  await page.click("saveManifestBtn");
  assert.deepEqual(page.sent("POST", "/v1/manifests"), []);
  page.$("manifestName").value = "Issuers";
  await page.click("saveManifestBtn");
  assert.deepEqual(page.toasts(), [
    ["warning", "Please enter a manifest name."],
    ["danger", "A manifest with this name exists"],
  ]);
});

test("without a framework there is no treemap and nothing to save against", async (t) => {
  const page = await builder(t, {
    api: (method, path) =>
      path === "/v1/frameworks" ? [200, { items: [] }] : null,
  });
  assert.equal(
    page.$("capabilityTreemap").textContent,
    "No framework taxonomy loaded.",
  );
  assert.deepEqual(page.projectQueries(), [{}]);
  await page.click("saveManifestBtn");
  assert.deepEqual(page.toasts(), [
    ["warning", "Please pick a framework first."],
  ]);
  assert.deepEqual(page.sent("POST", "/v1/manifests"), []);
});

test("a framework without capabilities says so", async (t) => {
  const page = await builder(t, { tree: [] });
  assert.equal(
    page.$("capabilityTreemap").textContent,
    "No framework taxonomy loaded.",
  );
});

test("without the chart library the projects still list", async (t) => {
  const page = await builder(t, { d3: false });
  assert.equal(
    page.$("capabilityTreemap").textContent,
    "D3 library is unavailable.",
  );
  assert.equal(page.cards().length, 3);
  // Capability search has no treemap to move.
  page.$("capabilitySearch").value = "keys";
  page
    .$("capabilitySearch")
    .dispatchEvent(new page.window.KeyboardEvent("keydown", { key: "Enter" }));
  assert.deepEqual(page.toasts(), [
    ["warning", "Unable to zoom to that capability."],
  ]);
});

test("roles that cannot build manifests browse without the builder", async (t) => {
  const page = await builder(t, { me: account("engineer") });
  assert.equal(page.$("manifestBuilderCard").style.display, "none");
  assert.equal(page.cards().length, 3);
  assert.equal(page.doc.querySelector("#projects input.project-select"), null);
  await page.click(page.doc.querySelector("#projects .project-card"));
  await page.click("selectVisibleBtn");
  assert.deepEqual(
    page.cards().map((card) => card.selected),
    [false, false, false],
  );
});

test("architects and product owners can build manifests", async (t) => {
  for (const role of ["architect", "product_owner"]) {
    const page = await builder(t, { me: account(role) });
    assert.equal(page.$("manifestBuilderCard").style.display, "");
    assert.equal(
      page.doc.querySelectorAll("#projects input.project-select").length,
      3,
    );
  }
});

test("a signed-out visitor is sent to sign in", async (t) => {
  const page = await builder(t, { me: null });
  assert.equal(page.navigations(), 1);
  assert.deepEqual(page.projectQueries(), []);
});

test("a page that cannot load its framework says why", async (t) => {
  const page = await builder(t, {
    api: (method, path) =>
      path.endsWith("/catalogue")
        ? [500, { detail: "Catalogue unavailable" }]
        : null,
  });
  assert.deepEqual(page.toasts(), [["danger", "Catalogue unavailable"]]);
});

test("a project list that fails to refresh is reported", async (t) => {
  let refuse = false;
  const page = await builder(t, {
    api: (method, path) =>
      refuse && path === "/v1/projects"
        ? [500, { detail: "Search unavailable" }]
        : null,
  });
  refuse = true;
  await page.click("applyFiltersBtn");
  assert.deepEqual(page.toasts(), [["danger", "Search unavailable"]]);
  assert.equal(page.cards().length, 3);
});

test("resizing the window redraws the treemap once", async (t) => {
  const page = await builder(t);
  await page.press(page.tile("Issuer"));
  page.window.dispatchEvent(new page.window.Event("resize"));
  await page.wait();
  assert.equal(page.doc.querySelectorAll("#capabilityTreemap svg").length, 1);
  assert.equal(
    page.$("activeFiltersSummary").textContent,
    "Capability: Taxonomy > Identity > Issuer",
  );
});
