// The questions inbox, the manifests page chrome, the dependency browser and
// detail, and the capability detail: real pages against an API fixture.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage, FEATURES } from "./support/app-page.mjs";

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const off = (feature) => ({ features: { ...FEATURES, [feature]: false } });

// --- Questions inbox -------------------------------------------------------

const INBOX = {
  open_count: 2,
  items: [
    {
      thread_id: 4,
      project_id: 5,
      project_display_name: "Wallet <Kit>",
      asked_by: { username: "bob" },
      asked_at: "2026-03-04T09:00:00",
      updated_at: "2026-03-05T10:00:00",
      question_preview: "Is it <i>audited</i>?",
    },
    { thread_id: 3, project_id: 6, asked_by: null, question_preview: null },
  ],
};

function inbox(t, options = {}) {
  return appPage(t, "questions.html", "pages/questions.js", {
    me: account("maintainer"),
    ...options,
    api: (method, path, body) =>
      options.api?.(method, path, body) ||
      (path === "/v1/questions/unanswered" ? [200, INBOX] : null),
  });
}

test("the inbox lists open questions with links to their projects", async (t) => {
  const page = await inbox(t);
  assert.equal(page.$("questionsCount").textContent, "2 open");
  assert.equal(page.$("notPermitted").style.display, "none");
  assert.equal(page.$("whoami").textContent, "ada (maintainer)");
  const rows = [...page.doc.querySelectorAll("#questionsList tbody tr")];
  assert.equal(rows.length, 2);
  const first = [...rows[0].children];
  assert.equal(
    first[0].textContent,
    new Date("2026-03-05T10:00:00Z").toLocaleString(),
  );
  assert.equal(first[1].textContent, "Wallet <Kit>");
  assert.equal(first[2].textContent, "bob");
  assert.equal(first[3].textContent, "Is it <i>audited</i>?");
  assert.equal(
    first[3].getAttribute("title"),
    `Asked: ${new Date("2026-03-04T09:00:00Z").toLocaleString()}`,
  );
  assert.equal(rows[0].querySelector("i"), null);
  assert.deepEqual(
    [...rows[0].querySelectorAll("a")].map((a) => a.getAttribute("href")),
    ["/project.html?id=5&tab=questions", "/project.html?id=5&tab=questions"],
  );
  assert.deepEqual(
    [...rows[1].children].slice(0, 4).map((c) => c.textContent),
    ["—", "Project #6", "unknown", ""],
  );
});

test("the inbox refreshes on request and on live notices", async (t) => {
  const page = await inbox(t);
  const loads = () =>
    page.asked().filter((r) => r === "GET /v1/questions/unanswered").length;
  assert.equal(loads(), 1);
  await page.click("refreshBtn");
  assert.equal(loads(), 2);
  const notify = (detail) => {
    page.window.dispatchEvent(
      new page.window.CustomEvent("ospmae-notification", { detail }),
    );
    return page.wait();
  };
  await notify({ kind: "project_question_created" });
  await notify({ kind: "project_question_replied" });
  assert.equal(loads(), 4);
  await notify({ kind: "manifest_shared" });
  await notify(null);
  assert.equal(loads(), 4);
});

test("an empty inbox, a refusal and a failure each say so", async (t) => {
  const empty = await inbox(t, {
    api: (m, path) =>
      path === "/v1/questions/unanswered"
        ? [200, { items: [], open_count: 0 }]
        : null,
  });
  assert.equal(
    empty.$("questionsList").textContent,
    "No unanswered questions 🎉",
  );
  assert.equal(empty.$("questionsCount").textContent, "");

  const refused = await inbox(t, {
    api: (m, path) =>
      path === "/v1/questions/unanswered"
        ? [403, { detail: "Not permitted to answer project questions" }]
        : null,
  });
  assert.equal(refused.$("notPermitted").style.display, "");
  assert.equal(
    refused.$("notPermitted").textContent,
    "Not permitted to answer project questions",
  );
  assert.equal(refused.$("questionsList").innerHTML, "");

  const broken = await inbox(t, {
    api: (m, path) =>
      path === "/v1/questions/unanswered"
        ? [500, { detail: "Database is down" }]
        : null,
  });
  assert.equal(broken.$("notPermitted").textContent, "Error: Database is down");

  // A role that cannot answer never asks the API.
  const viewer = await inbox(t, { me: account("viewer") });
  assert.equal(
    viewer.$("notPermitted").textContent,
    "Not permitted to view the unanswered questions inbox.",
  );
  assert.equal(
    viewer.asked().filter((r) => r.includes("/v1/questions")).length,
    0,
  );
});

test("the inbox leaves when the questions feature is off", async (t) => {
  const page = await inbox(t, { me: account("maintainer", off("questions")) });
  assert.equal(page.navigations(), 1);
  assert.equal(
    page.asked().filter((r) => r.includes("/v1/questions/unanswered")).length,
    0,
  );
});

// --- Manifests page chrome --------------------------------------------------

function manifests(t, options = {}) {
  return appPage(t, "manifests.html", "pages/manifests.js", options);
}

test("manifest tabs follow the address and a shared-manifest link", async (t) => {
  const plain = await manifests(t);
  assert.equal(plain.$("savedTabItem").hidden, false);
  assert.deepEqual(plain.record.tabs, []);

  const hashed = await manifests(t, { hash: "#SAVED" });
  assert.deepEqual(hashed.record.tabs, ["saved"]);
  assert.equal(hashed.window.location.hash, "#saved");

  // A link from a share e-mail opens the saved tab and keeps its manifest id.
  const shared = await manifests(t, { query: "?id=42", hash: "#builder" });
  assert.deepEqual(shared.record.tabs, ["saved"]);
  assert.equal(shared.window.location.search, "?id=42");
  // Moving to the builder drops the id, which belongs to the saved tab.
  shared.window.location.hash = "#builder";
  await shared.wait();
  assert.deepEqual(shared.record.tabs, ["saved", "builder"]);
  assert.equal(shared.window.location.search, "");
  shared.window.location.hash = "#nowhere";
  await shared.wait();
  assert.equal(shared.record.tabs.length, 2);
});

test("saved manifests are hidden from roles that cannot export", async (t) => {
  const page = await manifests(t, { me: account("engineer"), hash: "#saved" });
  assert.equal(page.$("savedTabItem").hidden, true);
  assert.deepEqual(page.record.tabs, []);

  const gone = await manifests(t, { me: account("admin", off("manifests")) });
  assert.equal(gone.navigations(), 1);
});

// --- Dependency browser ------------------------------------------------------

const INDEX = {
  total: 120,
  limit: 50,
  offset: 0,
  ecosystems: ["npm", "python"],
  dependencies: [
    {
      public_id: "11111111-1111-4111-8111-111111111111",
      name: "<b>left-pad</b>",
      ecosystem: "npm",
      version_count: 3,
      used_by_count: 2,
      vulnerability_count: 4,
    },
    {
      public_id: "22222222-2222-4222-8222-222222222222",
      name: "requests",
      ecosystem: "python",
      version_count: 1,
      used_by_count: 1,
      vulnerability_count: 0,
    },
  ],
};

function browser(t, options = {}) {
  return appPage(
    t,
    "dependencies.html",
    ["pages/deps-browser.js", "pages/dependencies.js"],
    {
      ...options,
      api: (method, path, body) =>
        options.api?.(method, path, body) ||
        (path === "/v1/dependencies" ? [200, INDEX] : null),
    },
  );
}

const queries = (page) =>
  page.requests
    .filter(([, path]) => path.startsWith("/v1/dependencies?"))
    .map(([, path]) =>
      Object.fromEntries(new URLSearchParams(path.split("?")[1])),
    );

test("without an id the page is the dependency browser", async (t) => {
  const page = await browser(t);
  assert.equal(page.doc.querySelectorAll("main").length, 1);
  assert.equal(page.doc.querySelector("main").id, "dep-browser-main");
  assert.deepEqual(queries(page), [{ limit: "50", offset: "0" }]);
  const rows = [...page.doc.querySelectorAll("#depRows tr")];
  assert.deepEqual(
    rows.map((row) =>
      [...row.children].slice(0, 5).map((c) => c.textContent.trim()),
    ),
    [
      ["<b>left-pad</b>", "npm", "3", "2", "4"],
      ["requests", "python", "1", "1", "clean"],
    ],
  );
  assert.equal(rows[0].querySelector("b"), null);
  assert.equal(
    rows[0].querySelector("a").getAttribute("href"),
    "/dependencies.html?id=11111111-1111-4111-8111-111111111111",
  );
  assert.deepEqual(page.texts("#depEcosystem option"), [
    "All ecosystems",
    "npm",
    "python",
  ]);
  assert.equal(
    page.$("depPagerInfo").textContent,
    "120 package(s) matching; showing 1–50",
  );
  assert.equal(page.$("depPrevBtn").disabled, true);
  assert.equal(page.$("depNextBtn").disabled, false);
});

test("the browser pages, filters and searches from the first page", async (t) => {
  const page = await browser(t);
  await page.click("depNextBtn");
  await page.click("depNextBtn");
  assert.equal(
    page.$("depPagerInfo").textContent,
    "120 package(s) matching; showing 101–120",
  );
  assert.equal(page.$("depNextBtn").disabled, true);
  await page.click("depNextBtn"); // past the end: nothing is asked
  await page.click("depPrevBtn");
  assert.deepEqual(
    queries(page).map((q) => q.offset),
    ["0", "50", "100", "50"],
  );

  // A filter starts again from the first page, and the list of ecosystems is not doubled.
  await page.choose("depEcosystem", "npm");
  page.$("depVulnerable").checked = true;
  page.$("depVulnerable").dispatchEvent(new page.window.Event("change"));
  await page.wait();
  assert.deepEqual(queries(page).slice(-1)[0], {
    ecosystem: "npm",
    vulnerable: "true",
    limit: "50",
    offset: "0",
  });
  assert.equal(page.doc.querySelectorAll("#depEcosystem option").length, 3);

  // Typing waits for a pause before asking, once.
  const before = queries(page).length;
  page.$("depSearch").value = "le";
  page.$("depSearch").dispatchEvent(new page.window.Event("input"));
  page.$("depSearch").value = " left ";
  page.$("depSearch").dispatchEvent(new page.window.Event("input"));
  await page.wait();
  assert.equal(queries(page).length, before);
  await pause(340);
  await page.wait();
  assert.equal(queries(page).length, before + 1);
  assert.equal(queries(page).slice(-1)[0].q, "left");
});

test("an empty or failing index says so", async (t) => {
  const empty = await browser(t, {
    api: (m, path) =>
      path === "/v1/dependencies"
        ? [200, { dependencies: [], ecosystems: [] }]
        : null,
  });
  assert.match(empty.$("depRows").textContent, /Nothing matched\./);
  assert.equal(
    empty.$("depPagerInfo").textContent,
    "0 package(s) matching; showing 0–0",
  );
  assert.equal(empty.$("depNextBtn").disabled, true);

  const failing = await browser(t, {
    api: (m, path) =>
      path === "/v1/dependencies"
        ? [500, { detail: "Index unavailable" }]
        : null,
  });
  assert.equal(failing.$("depRows").textContent.trim(), "Failed to load.");
  assert.deepEqual(failing.toasts(), [["danger", "Index unavailable"]]);
});

// --- Dependency detail -------------------------------------------------------

const DETAIL = {
  dependency_version: {
    dependency_version_id: 101,
    dependency_id: 9,
    ecosystem: "NPM",
    name: "@Inquirer/Confirm",
    normalized_name: "@inquirer/confirm",
    version: "5.1.21",
    created_at: "2026-03-01T08:00:00",
  },
  projects: [
    {
      project_id: 5,
      project_name: "Wallet <Kit>",
      project_version_id: 12,
      project_version: "2.0.0",
      is_latest: true,
      is_draft: false,
      is_indirect: true,
    },
    {
      project_id: 5,
      project_name: "Wallet <Kit>",
      project_version_id: 11,
      project_version: "",
      is_latest: false,
      is_draft: true,
      is_indirect: false,
    },
    {
      project_id: 6,
      project_name: "Other",
      project_version_id: 20,
      project_version: "1.0",
      is_latest: true,
      is_draft: false,
      is_indirect: false,
    },
  ],
  vulnerabilities: [
    {
      scanner: "grype",
      vulnerability_id: "CVE-1",
      severity: "critical",
      title: "Bad <script>",
      fixed_version: "5.2.0",
      references: ["https://a.example/1", "r2", "r3", "r4"],
    },
    {
      scanner: null,
      vulnerability_id: "GHSA-2",
      severity: "medium",
      title: null,
      fixed_version: null,
      references: null,
    },
    { vulnerability_id: "X-3", severity: "low" },
    { vulnerability_id: "X-4", severity: null },
  ],
  severity_counts: { CRITICAL: 1, MEDIUM: 1, LOW: 1, UNKNOWN: 1 },
  namespace: {
    scope: "@inquirer",
    ecosystem: "NPM",
    truncated: true,
    packages: [{ name: "@inquirer/confirm" }, { name: "@inquirer/<core>" }],
  },
  package: {
    project_count: 2,
    versions_truncated: true,
    versions: [
      { public_id: "aaaa", version: "5.1.21", project_count: 2, current: true },
      { public_id: "bbbb", version: "", project_count: 0, current: false },
    ],
  },
};

function detail(t, options = {}) {
  return appPage(
    t,
    "dependencies.html",
    ["pages/deps-browser.js", "pages/dependencies.js"],
    {
      query: "?id=101",
      ...options,
      api: (method, path, body) =>
        options.api?.(method, path, body) ||
        (path.startsWith("/v1/dependencies/") ? [200, DETAIL] : null),
    },
  );
}

test("a dependency page shows its users, findings, versions and scope", async (t) => {
  const page = await detail(t);
  assert.deepEqual(page.errors, []);
  // With an id the browser stands aside for the detail view.
  assert.equal(page.$("dep-browser-main"), null);
  assert.ok(page.asked().includes("GET /v1/dependencies/101"));
  assert.equal(page.$("depTitle").textContent, "@Inquirer/Confirm@5.1.21");
  assert.equal(
    page.$("depSubtitle").textContent,
    "npm • dependency version #101",
  );
  assert.equal(
    page.$("depMeta").textContent,
    `normalized: @inquirer/confirm • first seen: ${new Date("2026-03-01T08:00:00Z").toLocaleString()}`,
  );
  assert.deepEqual(page.texts("#depBadges .badge"), ["npm", "id 101"]);
  assert.deepEqual(page.texts("#vulnSummary .badge"), [
    "CRITICAL 1",
    "MEDIUM 1",
    "LOW 1",
    "UNKNOWN 1",
    "Total 4",
  ]);
  assert.equal(page.$("vulnCount").textContent, "4");

  // One row per release; the badge counts distinct projects.
  assert.equal(page.$("usedByCount").textContent, "2");
  const used = [...page.doc.querySelectorAll("#usedByBody tr")];
  assert.equal(used.length, 3);
  assert.equal(used[0].children[0].textContent, "Wallet <Kit>");
  assert.equal(
    used[0].querySelector("a").getAttribute("href"),
    "/project.html?id=5",
  );
  assert.deepEqual(
    used.map((row) =>
      [...row.children]
        .slice(2)
        .map((c) => (c.querySelector(".bi-check-lg") ? "yes" : "—")),
    ),
    [
      ["yes", "—", "yes"],
      ["—", "yes", "—"],
      ["yes", "—", "—"],
    ],
  );

  const vulns = [...page.doc.querySelectorAll("#vulnBody tr")].map((row) =>
    [...row.children].map((c) => c.textContent.replace(/\s+/g, " ").trim()),
  );
  // At most three references are listed beside the title.
  assert.deepEqual(
    [...page.doc.querySelectorAll("#vulnBody tr:first-child .me-2")].map(
      (n) => n.textContent,
    ),
    ["https://a.example/1", "r2", "r3"],
  );
  assert.deepEqual(vulns, [
    [
      "CRITICAL",
      "CVE-1",
      "Bad <script>https://a.example/1r2r3",
      "5.2.0",
      "grype",
    ],
    ["MEDIUM", "GHSA-2", "", "", ""],
    ["LOW", "X-3", "", "", ""],
    ["UNKNOWN", "X-4", "", "", ""],
  ]);
  assert.equal(page.$("vulnBody").querySelector("script"), null);
  assert.deepEqual(
    [...page.doc.querySelectorAll("#vulnBody .badge")].map((b) =>
      b.className.replace("badge ", ""),
    ),
    ["text-bg-danger", "text-bg-warning", "text-bg-info", "text-bg-secondary"],
  );

  assert.equal(page.$("packageVersionsCard").hidden, false);
  assert.equal(
    page.$("packageProjectsBadge").textContent,
    "2 projects, any version",
  );
  assert.equal(page.$("packageVersionsMore").hidden, false);
  const versions = [...page.doc.querySelectorAll("#packageVersionsBody tr")];
  assert.equal(versions[0].textContent, "5.1.21this page2");
  assert.equal(versions[0].querySelector("a"), null);
  assert.equal(
    versions[1].querySelector("a").getAttribute("href"),
    "/dependencies.html?id=bbbb",
  );
  assert.equal(versions[1].textContent, "(unversioned)0");

  assert.equal(page.$("namespaceCard").style.display, "");
  assert.equal(page.$("namespaceBadge").textContent, "@inquirer");
  assert.equal(
    page.$("namespaceHelp").textContent,
    "Other npm packages under @inquirer.",
  );
  assert.deepEqual(page.texts("#namespaceList .text-truncate"), [
    "@inquirer/confirm",
    "@inquirer/<core>",
  ]);
  assert.ok(page.$("namespaceCard").textContent.includes("List truncated."));

  // The usage graph links the dependency to each release that uses it.
  const graph = page.$("depUsageGraph");
  assert.deepEqual(
    [...graph.querySelectorAll("text")].map((n) => n.textContent),
    [
      "@Inquirer/Confirm@5.1.21",
      "Wallet <Kit> 2.0.0",
      "Wallet <Kit>",
      "Other 1.0",
    ],
  );
  const lines = [...graph.querySelectorAll("line")];
  assert.equal(lines.length, 3);
  // Indirect use is drawn dashed.
  assert.deepEqual(
    lines.map((l) => l.getAttribute("stroke-dasharray")),
    ["3,4", null, null],
  );
  await pause(60);
  assert.match(
    graph.querySelector("g g").getAttribute("transform"),
    /^translate\(/,
  );
});

test("a dependency nobody uses, with no findings, says so", async (t) => {
  const page = await detail(t, {
    api: (m, path) =>
      path.startsWith("/v1/dependencies/")
        ? [
            200,
            {
              dependency_version: {
                dependency_version_id: 7,
                ecosystem: "",
                name: "",
                normalized_name: "solo",
                version: "",
              },
              projects: [],
              vulnerabilities: [],
              namespace: null,
              package: { versions: [] },
            },
          ]
        : null,
  });
  assert.equal(page.$("depTitle").textContent, "solo");
  assert.equal(
    page.$("depSubtitle").textContent,
    "ecosystem • dependency version #7",
  );
  assert.equal(page.$("depMeta").textContent, "normalized: solo");
  assert.deepEqual(page.texts("#depBadges .badge"), ["unknown", "id 7"]);
  assert.equal(
    page.$("vulnSummary").textContent,
    "No known vulnerabilities recorded.",
  );
  assert.match(page.$("usedByBody").textContent, /No projects linked/);
  assert.match(page.$("vulnBody").textContent, /No vulnerabilities recorded/);
  assert.equal(page.$("packageVersionsCard").hidden, true);
  assert.equal(page.$("namespaceCard").style.display, "none");
});

test("many users are drawn up to a limit, with a note", async (t) => {
  const projects = Array.from({ length: 65 }, (_, n) => ({
    project_id: n + 1,
    project_name: `P${n}`,
    project_version_id: n + 100,
    project_version: "1",
  }));
  const page = await detail(t, {
    api: (m, path) =>
      path.startsWith("/v1/dependencies/")
        ? [200, { ...DETAIL, projects }]
        : null,
  });
  assert.equal(page.doc.querySelectorAll("#depUsageGraph line").length, 60);
  assert.ok(
    page
      .$("depUsageGraph")
      .textContent.endsWith("Showing 60 of 65 project links."),
  );
  assert.equal(page.$("usedByCount").textContent, "65");
});

test("the dependency page is for administrators and reports failures", async (t) => {
  const viewer = await detail(t, { me: account("viewer") });
  assert.equal(
    viewer.$("notFound").textContent,
    "This page is only available to admins.",
  );
  assert.equal(viewer.$("depSubtitle").textContent, "Not authorised.");
  assert.equal(
    viewer.asked().filter((r) => r.startsWith("GET /v1/dependencies/")).length,
    0,
  );

  let fail = true;
  const page = await detail(t, {
    api: (m, path) =>
      path.startsWith("/v1/dependencies/")
        ? fail
          ? [404, { detail: "Dependency not found" }]
          : [200, DETAIL]
        : null,
  });
  assert.equal(page.$("notFound").style.display, "");
  assert.deepEqual(page.toasts(), [["danger", "Dependency not found"]]);
  // Refresh tries again.
  fail = false;
  await page.click("refreshBtn");
  assert.equal(page.$("notFound").style.display, "none");
  assert.equal(page.$("depTitle").textContent, "@Inquirer/Confirm@5.1.21");
  fail = true;
  await page.click("refreshBtn");
  assert.equal(page.toasts().length, 2);

  // An id that is not a number or a UUID is never sent to the API.
  const odd = await detail(t, { query: "?id=../../etc" });
  assert.equal(
    odd.asked().filter((r) => r.startsWith("GET /v1/dependencies/")).length,
    0,
  );

  const gone = await detail(t, {
    me: account("admin", off("dependency_scans")),
  });
  assert.ok(gone.navigations() >= 1);
});

// --- Capability detail -------------------------------------------------------

const CAPABILITY = {
  capability: {
    framework_node_id: 33,
    framework_display_name: "Taxonomy",
    framework_machine_name: "tax",
    key: "keys",
    display_name: "Keys",
    description: "Key <storage>",
    level: 2,
    path: "Wallet / Storage / Keys",
  },
  projects: [
    {
      project_id: 5,
      project_name: "Wallet <Kit>",
      project_version_id: 12,
      project_version: "2.0.0",
      is_latest: true,
      is_draft: false,
    },
    {
      project_id: 6,
      project_name: "Other",
      project_version_id: 20,
      project_version: "",
      is_latest: false,
      is_draft: true,
    },
  ],
};

function capability(t, options = {}) {
  return appPage(t, "capability.html", "pages/capability.js", {
    query: "?id=33",
    ...options,
    api: (method, path, body) =>
      options.api?.(method, path, body) ||
      (path === "/v1/capabilities/33" ? [200, CAPABILITY] : null),
  });
}

test("a capability page shows its place in the framework and who maps it", async (t) => {
  const page = await capability(t);
  assert.deepEqual(page.errors, []);
  assert.equal(page.$("capTitle").textContent, "Wallet / Storage / Keys");
  assert.equal(page.$("capSubtitle").textContent, "Taxonomy • capability #33");
  assert.equal(
    page.$("capMeta").textContent,
    "key: keys • level: 2 • Key <storage>",
  );
  assert.deepEqual(page.texts("#capBadges .badge"), ["Taxonomy", "id 33"]);
  assert.equal(page.$("capUsage").textContent, "2 projects");
  assert.equal(page.$("usedByCount").textContent, "2");
  const rows = [...page.doc.querySelectorAll("#usedByBody tr")];
  assert.equal(rows[0].children[0].textContent, "Wallet <Kit>");
  assert.equal(
    rows[0].querySelector("a").getAttribute("href"),
    "/project.html?id=5",
  );
  assert.deepEqual(
    rows.map((row) =>
      [...row.children]
        .slice(2)
        .map((c) => (c.querySelector(".bi-check-lg") ? "yes" : "—")),
    ),
    [
      ["yes", "—"],
      ["—", "yes"],
    ],
  );
  assert.deepEqual(
    [...page.doc.querySelectorAll("#capUsageGraph text")].map(
      (n) => n.textContent,
    ),
    ["Wallet / Storage / Keys", "Wallet <Kit> 2.0.0", "Other"],
  );
  assert.equal(page.doc.querySelectorAll("#capUsageGraph line").length, 2);
});

test("an unmapped capability, a missing id and a failure each say so", async (t) => {
  const bare = await capability(t, {
    api: (m, path) =>
      path === "/v1/capabilities/33"
        ? [
            200,
            {
              capability: { framework_node_id: 33, level: null },
              projects: [],
            },
          ]
        : null,
  });
  assert.equal(bare.$("capTitle").textContent, "Capability #33");
  assert.equal(bare.$("capSubtitle").textContent, "framework • capability #33");
  assert.equal(bare.$("capMeta").textContent, "");
  assert.deepEqual(bare.texts("#capBadges .badge"), ["id 33"]);
  assert.match(
    bare.$("usedByBody").textContent,
    /No projects mapped to this capability yet\./,
  );

  for (const query of ["", "?id=abc"]) {
    const missing = await capability(t, { query });
    assert.equal(missing.$("notFound").style.display, "block");
    assert.equal(
      missing.$("capSubtitle").textContent,
      "Missing capability id.",
    );
    assert.equal(
      missing.asked().filter((r) => r.includes("/v1/capabilities")).length,
      0,
    );
  }

  const absent = await capability(t, {
    api: (m, path) =>
      path === "/v1/capabilities/33"
        ? [404, { detail: "Capability not found" }]
        : null,
  });
  assert.equal(absent.$("notFound").style.display, "block");
  assert.equal(absent.$("capSubtitle").textContent, "Capability not found.");
  assert.deepEqual(absent.toasts(), []);

  let down = true;
  const failing = await capability(t, {
    api: (m, path) =>
      path === "/v1/capabilities/33"
        ? down
          ? [500, { detail: "Server error" }]
          : [200, CAPABILITY]
        : null,
  });
  assert.deepEqual(failing.toasts(), [["danger", "Server error"]]);
  await failing.click("refreshBtn");
  assert.equal(failing.toasts().length, 2);
  down = false;
  await failing.click("refreshBtn");
  assert.equal(failing.$("capTitle").textContent, "Wallet / Storage / Keys");
});
