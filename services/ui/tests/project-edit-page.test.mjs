// The project editor: the project form and what it sends, branch tracking
// and private-repository access, versions, publishing a draft, and mapping
// a version to framework capabilities.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage, FRAMEWORK } from "./support/app-page.mjs";

const FRAMEWORKS = [
  FRAMEWORK,
  { id: 4, machine_name: "alt", display_name: "" },
];
const TREE = [
  {
    id: 30,
    key: "root",
    display_name: "Root",
    children: [
      {
        id: 31,
        key: "identity",
        display_name: "Identity",
        children: [{ id: 33, key: "issuer", display_name: "Issuer" }],
      },
      { id: 32, key: "wallet", display_name: "Wallet <w>" },
    ],
  },
];
const FLAT = [
  { id: 30, path: "Root" },
  { id: 31, path: "Root > Identity" },
  { id: 33, path: "Root > Identity > Issuer" },
  { id: 32, display_name: "Wallet <w>" },
  { id: null },
];

const VERSIONS = [
  {
    id: 5,
    version: "1.0.0",
    status: "stable",
    release_date: "2026-01-10T00:00:00",
    link_to_source_code: "https://git.example.org/acme/wallet",
    is_latest: true,
    is_draft: false,
    notes: "First",
    capability_paths: ["Root > Identity"],
  },
  {
    id: 6,
    version: "2.0.0-rc1",
    release_date: "2026-03-04T23:30:00",
    is_latest: false,
    is_draft: true,
  },
  { id: 7, version: "0.9", is_latest: false, is_draft: false },
];

const PROJECT = {
  id: 1,
  machine_name: "wallet",
  display_name: "Wallet Kit",
  organisation: "Acme",
  project_type: "wallet",
  license: "MIT",
  programming_languages: ["Python", "TypeScript"],
  link_to_app: "https://wallet.example.org",
  release_rss_feed_url: "https://git.example.org/acme/wallet/releases.atom",
  release_rss_ignore_patterns: [
    { pattern: "nightly" },
    { pattern: "^v0\\.", match_type: "regex" },
    { pattern: " ", type: "contains" },
  ],
  capability: "Holds credentials",
  supported_profiles: ["OpenID4VCI"],
  supported_formats: ["SD-JWT"],
  supported_issuance_protocols: ["openid4vci"],
  supported_presentation_protocols: ["openid4vp"],
  supported_key_managements: ["jwk"],
  supported_signing_algorithms: ["ES256"],
  versions: VERSIONS,
};

function editor(t, options = {}) {
  const world = {
    project: structuredClone(
      options.project === undefined ? PROJECT : options.project,
    ),
    mapped: { 5: [31], ...options.mapped },
    fail: { ...options.fail },
    scrolls: [],
    focuses: [],
  };
  const api = (method, path, body, query) => {
    const failure = world.fail[`${method} ${path}`];
    if (failure) return [failure[0], { detail: failure[1] }];
    if (path === "/v1/frameworks")
      return [200, { items: options.frameworks || FRAMEWORKS }];
    if (/^\/v1\/frameworks\/\d+\/nodes$/.test(path))
      return [200, path.includes("/3/") ? { tree: TREE, items: FLAT } : {}];
    if (path === "/v1/projects" && method === "POST") {
      world.project = { id: 9, versions: [], ...body };
      return [201, world.project];
    }
    if (/^\/v1\/projects\/\d+$/.test(path)) {
      if (method === "PUT") Object.assign(world.project, body);
      if (method === "GET")
        world.asked = [...(world.asked || []), query.get("framework_id")];
      return [200, world.project];
    }
    if (/^\/v1\/projects\/\d+\/versions$/.test(path)) {
      const created = { id: 20, ...body };
      world.project.versions.push(created);
      return [201, created];
    }
    const nodes = path.match(
      /^\/v1\/project-versions\/(\d+)\/framework-nodes$/,
    );
    if (nodes) {
      if (method === "PUT") world.mapped[nodes[1]] = body.node_ids;
      return [
        200,
        query.get("framework_id") === "4"
          ? {}
          : { node_ids: world.mapped[nodes[1]] || [] },
      ];
    }
    const version = path.match(/^\/v1\/project-versions\/(\d+)$/);
    if (version) {
      const id = Number(version[1]);
      const stored = world.project.versions.find((v) => v.id === id);
      if (method === "DELETE") {
        world.project.versions = world.project.versions.filter(
          (v) => v !== stored,
        );
        return [200, {}];
      }
      Object.assign(stored, body);
      return [200, stored];
    }
    return null;
  };
  return appPage(t, "project-edit.html", "pages/project-edit.js", {
    query: options.project === null ? "" : "?id=1",
    ...options,
    api,
    setup(window) {
      // jsdom has no layout to scroll; what the page asked for is kept.
      window.Element.prototype.scrollIntoView = function (how) {
        if (how && options.plainScroll) throw new TypeError("no options");
        world.scrolls.push(how ? { ...how } : "plain");
      };
      const focus = window.HTMLElement.prototype.focus;
      window.HTMLElement.prototype.focus = function (how) {
        if (how && options.plainScroll) throw new TypeError("no options");
        world.focuses.push(this.id);
        return focus.call(this);
      };
    },
  }).then((page) => {
    const tree = () => page.$("capabilityTree");
    return {
      ...page,
      world,
      pick(select, ...values) {
        for (const option of page.$(select).options)
          option.selected = values.includes(option.value);
      },
      versions: () =>
        [...page.doc.querySelectorAll("#versionsList .version-row")].map(
          (row) => row.textContent.replace(/\s+/g, " ").trim(),
        ),
      edit: (id) =>
        page.click(page.doc.querySelector(`#versionsList [data-id="${id}"]`)),
      pill: (id) =>
        tree().querySelector(`.cap-node-row [data-node-id="${id}"]`),
      shown: () =>
        [...tree().querySelectorAll(".cap-node-row .pill-label")].map(
          (label) => label.textContent,
        ),
      selected: () =>
        [...tree().querySelectorAll(".selected-pills .pill-label")].map(
          (label) => label.textContent,
        ),
      async tick(id, checked) {
        page.$(id).checked = checked;
        await page.choose(id, "on");
      },
    };
  });
}

test("the form shows the project as it is stored", async (t) => {
  const page = await editor(t);
  assert.deepEqual(page.errors, []);
  assert.equal(page.$("formTitle").textContent, "Edit project: Wallet Kit");
  const value = (id) => page.$(id).value;
  assert.deepEqual(
    [
      "machine_name",
      "display_name",
      "organisation",
      "project_type",
      "license",
      "link_to_app",
      "capability",
    ].map(value),
    [
      "wallet",
      "Wallet Kit",
      "Acme",
      "wallet",
      "MIT",
      "https://wallet.example.org",
      "Holds credentials",
    ],
  );
  assert.equal(value("release_rss_ignore_patterns"), "nightly\nregex:^v0\\.");
  assert.deepEqual(
    [...page.$("programming_languages").selectedOptions].map((o) => o.value),
    ["Python", "TypeScript"],
  );
  assert.equal(page.$("releaseFields").hidden, false);
  assert.equal(page.$("branchFields").hidden, true);
  assert.equal(page.$("repoAccessFields").hidden, true);
  assert.equal(page.$("deleteProjectBtn").style.display, "");
  assert.equal(page.world.asked[0], "3");
});

test("saving sends the whole form, without branch or token settings that are off", async (t) => {
  const page = await editor(t);
  page.$("display_name").value = " Wallet Kit 2 ";
  page.$("organisation").value = "";
  page.$("release_rss_ignore_patterns").value =
    "nightly\nNIGHTLY\ncontains: beta \nregex: ^v0\\. \ncontains:\n\n";
  page.pick("programming_languages", "Go");
  page.$("tracked_repo_url").value = "half typed";
  page.$("repo_token").value = "left over";
  await page.click("saveProjectBtn");
  assert.deepEqual(page.sent("PUT", "/v1/projects/1"), [
    {
      machine_name: "wallet",
      display_name: "Wallet Kit 2",
      organisation: null,
      project_type: "wallet",
      license: "MIT",
      programming_languages: ["Go"],
      link_to_app: "https://wallet.example.org",
      release_rss_feed_url: "https://git.example.org/acme/wallet/releases.atom",
      release_rss_ignore_patterns: [
        { match_type: "contains", pattern: "nightly", case_sensitive: false },
        { match_type: "contains", pattern: "beta", case_sensitive: false },
        { match_type: "regex", pattern: "^v0\\.", case_sensitive: false },
      ],
      track_branch: false,
      repo_private: false,
      capability: "Holds credentials",
      supported_profiles: ["OpenID4VCI"],
      supported_formats: ["SD-JWT"],
      supported_issuance_protocols: ["openid4vci"],
      supported_presentation_protocols: ["openid4vp"],
      supported_key_managements: ["jwk"],
      supported_signing_algorithms: ["ES256"],
    },
  ]);
  assert.deepEqual(page.toasts(), [["info", "Project updated."]]);
  assert.equal(page.$("formTitle").textContent, "Edit project: Wallet Kit 2");
});

test("an ignore rule that is not a regular expression stops the save", async (t) => {
  const page = await editor(t);
  page.$("release_rss_ignore_patterns").value = "regex:([a-z";
  await page.click("saveProjectBtn");
  assert.deepEqual(page.sent("PUT", "/v1/projects/1"), []);
  const [[level, text]] = page.toasts();
  assert.equal(level, "warning");
  assert.match(text, /^Invalid release ignore regex "\(\[a-z": /);
});

test("a refused save is reported", async (t) => {
  const page = await editor(t, {
    fail: { "PUT /v1/projects/1": [409, "machine_name already exists"] },
  });
  await page.click("saveProjectBtn");
  assert.deepEqual(page.toasts(), [["danger", "machine_name already exists"]]);
  assert.equal(page.$("saveProjectBtn").disabled, false);
});

test("tracking a branch swaps the release fields for required branch fields", async (t) => {
  const page = await editor(t);
  await page.tick("track_branch", true);
  assert.equal(page.$("releaseFields").hidden, true);
  assert.equal(page.$("branchFields").hidden, false);
  assert.deepEqual(
    ["tracked_repo_url", "tracked_branch", "branch_poll_interval_hours"].map(
      (id) => page.$(id).required,
    ),
    [true, true, true],
  );
  assert.equal(page.$("branch_poll_interval_hours").value, "24");
  page.$("tracked_repo_url").value = " https://git.example.org/acme/wallet ";
  page.$("tracked_branch").value = "main";
  page.$("branch_poll_interval_hours").value = "6";
  await page.click("saveProjectBtn");
  const sent = page.sent("PUT", "/v1/projects/1")[0];
  assert.deepEqual(
    [
      sent.track_branch,
      sent.tracked_repo_url,
      sent.tracked_branch,
      sent.branch_poll_interval_hours,
    ],
    [true, "https://git.example.org/acme/wallet", "main", 6],
  );
  // The saved project now follows its branch: releases are no longer staged.
  assert.equal(page.$("autoPublishField").hidden, true);
  assert.equal(page.$("newVersionBtn").hidden, true);
  assert.match(
    page.$("versionsBranchNotice").textContent,
    /^This project tracks branch main: .* re-scanned every 6/,
  );

  await page.tick("track_branch", false);
  assert.equal(page.$("tracked_branch").required, false);
});

test("a private repository asks for a host and token, suggested from what is known", async (t) => {
  const page = await editor(t);
  await page.tick("repo_private", true);
  assert.equal(page.$("repoAccessFields").hidden, false);
  // No tracked repository yet: the Latest version's source host is offered.
  assert.equal(page.$("repo_token_host").value, "git.example.org");
  assert.equal(page.$("repo_token").required, true);
  assert.equal(page.$("repoTokenRequired").hidden, false);
  assert.match(
    page.$("repoTokenStatus").textContent,
    /^A read-only token for this repository/,
  );

  page.$("repo_token").value = " secret ";
  page.$("repo_token_username").value = " bot ";
  await page.click("saveProjectBtn");
  const sent = page.sent("PUT", "/v1/projects/1")[0];
  assert.deepEqual(
    [
      sent.repo_private,
      sent.repo_token_host,
      sent.repo_token_username,
      sent.repo_token,
    ],
    [true, "git.example.org", "bot", "secret"],
  );
  // The token is write-only: the form comes back without it.
  assert.equal(page.$("repo_token").value, "");
});

test("a saved token is kept unless the host changes", async (t) => {
  const page = await editor(t, {
    project: {
      ...PROJECT,
      track_branch: true,
      tracked_repo_url: "https://code.example.net/acme/wallet",
      tracked_branch: "main",
      branch_poll_interval_hours: 12,
      repo_private: true,
      repo_token_set: true,
      repo_token_host: "code.example.net",
      repo_token_username: "bot",
    },
  });
  assert.equal(page.$("repo_token").required, false);
  assert.equal(
    page.$("repo_token").placeholder,
    "Leave empty to keep the saved token",
  );
  assert.equal(page.$("repoTokenRequired").hidden, true);
  assert.match(
    page.$("repoTokenStatus").textContent,
    /^A token is saved for this host\./,
  );

  await page.type("repo_token_host", "Other.example.net");
  assert.equal(page.$("repo_token").required, true);
  assert.equal(page.$("repo_token").placeholder, "");
  assert.match(
    page.$("repoTokenStatus").textContent,
    /^The saved token is for another host/,
  );

  await page.click("saveProjectBtn");
  const sent = page.sent("PUT", "/v1/projects/1")[0];
  assert.equal(sent.repo_token_host, "Other.example.net");
  assert.equal("repo_token" in sent, false);
});

test("the host suggestion prefers the tracked repository and ignores non-https addresses", async (t) => {
  const page = await editor(t, {
    project: {
      ...PROJECT,
      versions: [
        { ...VERSIONS[0], link_to_source_code: "http://plain.example.org/x" },
      ],
    },
  });
  await page.tick("repo_private", true);
  assert.equal(page.$("repo_token_host").value, "");
  await page.tick("repo_private", false);
  page.$("tracked_repo_url").value = "https://Code.Example.net/acme/wallet";
  await page.tick("repo_private", true);
  assert.equal(page.$("repo_token_host").value, "code.example.net");
});

test("branch tracking is hidden without dependency scans unless already in use", async (t) => {
  const features = { ...account().features, dependency_scans: false };
  const off = await editor(t, { me: account("admin", { features }) });
  assert.equal(off.$("trackBranchField").hidden, true);
  const tracking = await editor(t, {
    me: account("admin", { features }),
    project: { ...PROJECT, track_branch: true, tracked_branch: "main" },
  });
  assert.equal(tracking.$("trackBranchField").hidden, false);
});

test("a new project needs its names, then opens for editing once created", async (t) => {
  const page = await editor(t, { project: null });
  assert.equal(page.$("formTitle").textContent, "Create project");
  assert.equal(page.$("deleteProjectBtn").style.display, "none");
  assert.equal(
    page.$("versionsList").textContent,
    "Create the project first to add versions.",
  );

  await page.click("saveProjectBtn");
  page.$("machine_name").value = "fresh";
  await page.click("saveProjectBtn");
  assert.deepEqual(page.toasts(), [
    ["warning", "machine_name is required"],
    ["warning", "display_name is required"],
  ]);
  assert.deepEqual(page.sent("POST", "/v1/projects"), []);

  page.$("display_name").value = "Fresh";
  await page.click("saveProjectBtn");
  const [sent] = page.sent("POST", "/v1/projects");
  assert.deepEqual(
    [
      sent.machine_name,
      sent.display_name,
      sent.organisation,
      sent.track_branch,
    ],
    ["fresh", "Fresh", null, false],
  );
  assert.equal(page.window.location.search, "?id=9");
  assert.equal(page.$("formTitle").textContent, "Edit project: Fresh");
  assert.equal(page.$("editorTabs").hidden, false);
  assert.equal(page.$("versionsList").textContent, "No versions created yet.");
  assert.deepEqual(page.toasts().at(-1), [
    "info",
    "Project created. Versions can be added on the Versions tab.",
  ]);
});

test("deleting the project asks first and returns to the catalogue", async (t) => {
  const kept = await editor(t, { confirm: false });
  await kept.click("deleteProjectBtn");
  assert.deepEqual(kept.record.confirms, [
    "Delete this project and all versions? This cannot be undone.",
  ]);
  assert.deepEqual(kept.sent("DELETE", "/v1/projects/1"), []);

  const page = await editor(t);
  await page.click("deleteProjectBtn");
  assert.deepEqual(page.sent("DELETE", "/v1/projects/1"), [undefined]);
  assert.deepEqual(page.toasts(), [["info", "Project deleted."]]);
  assert.equal(page.navigations(), 1);

  const refused = await editor(t, {
    fail: { "DELETE /v1/projects/1": [403, "Only owners may delete"] },
  });
  await refused.click("deleteProjectBtn");
  assert.deepEqual(refused.toasts(), [["danger", "Only owners may delete"]]);
  assert.equal(refused.navigations(), 0);
});

test("only project maintainers reach the editor", async (t) => {
  const page = await editor(t, { me: account("engineer") });
  assert.equal(page.navigations(), 1);
  assert.equal(page.$("formTitle").textContent.includes("Wallet Kit"), false);
  const out = await editor(t, { me: null });
  assert.equal(out.navigations(), 1);
});

test("a project that cannot be read says why", async (t) => {
  const page = await editor(t, {
    fail: { "GET /v1/projects/1": [404, "Project not found"] },
  });
  assert.deepEqual(page.toasts(), [["danger", "Project not found"]]);
});

test("versions are listed newest first with their state", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  assert.deepEqual(page.versions(), [
    "2.0.0-rc1Draft 2026-03-04 · Categories (current framework): 0 Edit",
    "1.0.0Latest 2026-01-10 · Categories (current framework): 1 Edit",
    "0.9 — · Categories (current framework): 0 Edit",
  ]);
  assert.equal(page.$("newVersionBtn").hidden, false);
  assert.equal(page.$("versionsBranchNotice").hidden, true);
  assert.equal(page.$("versionEditor").style.display, "none");
});

test("opening a version fills its form and shows its mapped capabilities", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  await page.edit(5);
  assert.equal(page.$("versionEditor").style.display, "");
  assert.equal(page.$("versionFormTitle").textContent, "Edit version: 1.0.0");
  assert.deepEqual(
    ["version", "status", "release_date", "link_to_source_code", "notes"].map(
      (id) => page.$(id).value,
    ),
    [
      "1.0.0",
      "stable",
      "2026-01-10",
      "https://git.example.org/acme/wallet",
      "First",
    ],
  );
  assert.equal(page.$("is_latest").checked, true);
  assert.equal(page.$("is_draft").checked, false);
  assert.match(page.versions()[1], /^1\.0\.0LatestEditing now .* Editing$/);
  assert.match(
    page.$("versionEditContext").textContent.replace(/\s+/g, " "),
    /Editing 1\.0\.0 ?Latest Current latest: 1\.0\.0\. Save changes/,
  );
  assert.equal(page.$("deleteVersionBtn").style.display, "");
  assert.deepEqual(page.selected(), ["Identity"]);
  assert.deepEqual(page.shown(), ["Root", "Identity", "Wallet <w>"]);
  assert.equal(page.pill(31).classList.contains("selected"), true);
  assert.deepEqual(page.world.scrolls, [
    { behavior: "smooth", block: "center" },
  ]);
  await new Promise((resolve) => setTimeout(resolve, 400));
  assert.deepEqual(page.world.focuses, ["version"]);
});

test("the editor still comes into view where smooth scrolling is not supported", async (t) => {
  const page = await editor(t, { hash: "#versions", plainScroll: true });
  await page.edit(5);
  assert.deepEqual(page.world.scrolls, ["plain"]);
  await new Promise((resolve) => setTimeout(resolve, 400));
  assert.deepEqual(page.world.focuses, ["version"]);
});

test("the capability tree folds, filters and toggles selections", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  await page.edit(5);
  const toggle = (id) =>
    page.$("capabilityTree").querySelector(`[data-toggle-node="${id}"]`);
  await page.click(toggle(31));
  assert.deepEqual(page.shown(), ["Root", "Identity", "Issuer", "Wallet <w>"]);
  await page.click(toggle(30));
  assert.deepEqual(page.shown(), ["Root"]);

  // A search opens every branch that leads to a match.
  await page.type("capabilitySearch", "ISSUER");
  assert.deepEqual(page.shown(), ["Root", "Identity", "Issuer"]);
  await page.type("capabilitySearch", "wallet");
  assert.deepEqual(page.shown(), ["Root", "Wallet <w>"]);
  await page.type("capabilitySearch", "");

  await page.click(toggle(30));
  await page.click(page.pill(32));
  assert.deepEqual(page.selected(), ["Identity", "Wallet <w>"]);
  // A selected pill above the tree removes its capability.
  await page.click(
    page
      .$("capabilityTree")
      .querySelector('.selected-pills [data-node-id="31"]'),
  );
  assert.deepEqual(page.selected(), ["Wallet <w>"]);
  await page.click(page.pill(32));
  assert.match(
    page.$("capabilityTree").textContent,
    /No categories selected for this framework\./,
  );
});

test("saving a version sends its fields and its capability mapping", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  await page.edit(7);
  page.$("status").value = "beta";
  page.$("release_date").value = "2025-12-01";
  page.$("notes").value = " Older ";
  await page.click(page.pill(32));
  await page.click("saveVersionBtn");
  assert.deepEqual(page.sent("PUT", "/v1/project-versions/7"), [
    {
      version: "0.9",
      status: "beta",
      release_date: "2025-12-01",
      link_to_source_code: null,
      is_draft: false,
      notes: "Older",
    },
  ]);
  assert.deepEqual(page.sent("PUT", "/v1/project-versions/7/framework-nodes"), [
    { framework_id: 3, node_ids: [32] },
  ]);
  assert.deepEqual(page.toasts(), [["info", "Version updated."]]);
  // The list is reread and the editor closes until a version is chosen.
  assert.equal(page.$("versionEditor").style.display, "none");
  assert.match(page.versions()[2], /^0\.9 2025-12-01/);
});

test("Latest is sent when it is switched on, and when it is switched off", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  await page.edit(7);
  await page.tick("is_latest", true);
  await page.click("saveVersionBtn");
  assert.equal(page.sent("PUT", "/v1/project-versions/7")[0].is_latest, true);

  await page.edit(7);
  await page.tick("is_latest", false);
  await page.click("saveVersionBtn");
  assert.equal(page.sent("PUT", "/v1/project-versions/7")[1].is_latest, false);

  // Left alone on a version that is not Latest, the field is not sent.
  await page.edit(7);
  await page.click("saveVersionBtn");
  assert.equal(
    "is_latest" in page.sent("PUT", "/v1/project-versions/7")[2],
    false,
  );
});

test("a draft cannot be Latest, and publishing one is confirmed first", async (t) => {
  const page = await editor(t, { hash: "#versions", confirm: false });
  await page.edit(6);
  assert.equal(page.$("is_draft").checked, true);
  assert.equal(page.$("is_latest").disabled, true);
  assert.equal(page.$("versionDraftNotice").style.display, "none");
  assert.match(
    page.$("versionEditContext").textContent.replace(/\s+/g, " "),
    /Editing 2\.0\.0-rc1 ?Draft/,
  );

  await page.tick("is_draft", false);
  assert.equal(page.$("is_latest").disabled, false);
  assert.match(
    page.$("versionDraftNotice").textContent.replace(/\s+/g, " "),
    /Publishing draft 2\.0\.0-rc1 .* The current latest version is 1\.0\.0\./,
  );
  await page.type("version", "2.0.0");
  assert.match(
    page.$("versionDraftNotice").textContent,
    /Publishing draft 2\.0\.0\s/,
  );

  await page.click("saveVersionBtn");
  assert.deepEqual(page.record.confirms, [
    "Publish draft 2.0.0? Current latest: 1.0.0. OSPMAE will only elevate it automatically if it is newer than the current latest semantic version.",
  ]);
  assert.deepEqual(page.sent("PUT", "/v1/project-versions/6"), []);

  await page.tick("is_draft", true);
  assert.equal(page.$("is_latest").checked, false);
  assert.equal(page.$("versionDraftNotice").style.display, "none");
});

test("a draft published as Latest says so in its confirmation", async (t) => {
  const page = await editor(t, {
    hash: "#versions",
    project: { ...PROJECT, versions: [VERSIONS[1]] },
  });
  await page.edit(6);
  await page.tick("is_draft", false);
  assert.match(
    page.$("versionDraftNotice").textContent,
    /There is currently no published latest version for this project\./,
  );
  assert.match(
    page.$("versionEditContext").textContent,
    /No published latest version yet/,
  );
  await page.tick("is_latest", true);
  await page.click("saveVersionBtn");
  assert.deepEqual(page.record.confirms, [
    "Publish draft 2.0.0-rc1? There is currently no published latest version. You have explicitly marked it as Latest.",
  ]);
  assert.deepEqual(page.sent("PUT", "/v1/project-versions/6")[0], {
    version: "2.0.0-rc1",
    status: null,
    release_date: "2026-03-04",
    link_to_source_code: null,
    is_draft: false,
    notes: null,
    is_latest: true,
  });
});

test("a new version needs a version string and is created with its mapping", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  await page.click("newVersionBtn");
  assert.equal(page.$("versionFormTitle").textContent, "Create new version");
  assert.equal(page.$("deleteVersionBtn").style.display, "none");
  assert.match(
    page.$("versionEditContext").textContent,
    /Creating\s+new version/,
  );
  assert.deepEqual(page.selected(), []);

  await page.click("saveVersionBtn");
  assert.deepEqual(page.toasts(), [["danger", "version is required"]]);

  page.$("version").value = " 3.0.0 ";
  await page.click(page.pill(31));
  await page.click("saveVersionBtn");
  assert.deepEqual(page.sent("POST", "/v1/projects/1/versions"), [
    {
      version: "3.0.0",
      status: null,
      release_date: null,
      link_to_source_code: null,
      is_draft: false,
      notes: null,
    },
  ]);
  assert.deepEqual(
    page.sent("PUT", "/v1/project-versions/20/framework-nodes"),
    [{ framework_id: 3, node_ids: [31] }],
  );
  assert.deepEqual(page.toasts().at(-1), ["info", "Version created."]);
  assert.equal(page.versions().length, 4);
});

test("deleting a version asks first", async (t) => {
  const kept = await editor(t, { hash: "#versions", confirm: false });
  await kept.edit(7);
  await kept.click("deleteVersionBtn");
  assert.deepEqual(kept.record.confirms, [
    "Delete this version? This cannot be undone.",
  ]);
  assert.equal(kept.versions().length, 3);

  const page = await editor(t, { hash: "#versions" });
  await page.edit(7);
  await page.click("deleteVersionBtn");
  assert.deepEqual(page.sent("DELETE", "/v1/project-versions/7"), [undefined]);
  assert.deepEqual(page.toasts(), [["info", "Version deleted."]]);
  assert.equal(page.versions().length, 2);
  assert.equal(page.$("versionEditor").style.display, "none");
});

test("version failures are reported", async (t) => {
  const page = await editor(t, {
    hash: "#versions",
    fail: {
      "PUT /v1/project-versions/7": [409, "Version already exists"],
      "DELETE /v1/project-versions/7": [403, "Not yours to delete"],
      "GET /v1/project-versions/6/framework-nodes": [
        500,
        "Mapping unavailable",
      ],
    },
  });
  await page.edit(7);
  await page.click("saveVersionBtn");
  await page.click("deleteVersionBtn");
  await page.edit(6);
  assert.deepEqual(page.toasts(), [
    ["danger", "Version already exists"],
    ["danger", "Not yours to delete"],
    ["danger", "Mapping unavailable"],
  ]);
});

test("cancelling an edit with unsaved mapping changes asks before discarding", async (t) => {
  const page = await editor(t, { hash: "#versions", confirm: false });
  await page.edit(5);
  await page.click(page.pill(32));
  await page.click("cancelVersionBtn");
  assert.deepEqual(page.record.confirms, [
    "Discard unsaved category mapping changes?",
  ]);
  assert.equal(page.$("versionEditor").style.display, "");
  // The header link asks the same before leaving.
  const leave = new page.window.MouseEvent("click", { cancelable: true });
  page.$("btnBack").dispatchEvent(leave);
  assert.equal(leave.defaultPrevented, true);
  // So does switching framework, which then stays where it was.
  await page.choose("frameworkSelect", "alt");
  assert.equal(page.$("frameworkSelect").value, "tax");
  assert.equal(page.record.confirms.length, 3);

  const clean = await editor(t, { hash: "#versions" });
  await clean.edit(5);
  await clean.click("cancelVersionBtn");
  assert.equal(clean.record.confirms, undefined);
  assert.equal(clean.$("versionEditor").style.display, "none");
  assert.equal(clean.$("versionEditContext").textContent, "");
  assert.doesNotMatch(clean.versions()[1], /Editing/);
});

test("switching framework keeps the version open and rereads its mapping", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  await page.edit(5);
  page.$("notes").value = "typed and not yet saved";
  await page.choose("frameworkSelect", "alt");
  assert.equal(page.$("versionEditor").style.display, "");
  assert.equal(page.$("notes").value, "typed and not yet saved");
  assert.equal(page.world.asked.at(-1), "4");
  assert.match(
    page.$("capabilityTree").textContent,
    /No categories available\./,
  );
  assert.deepEqual(page.selected(), []);
  assert.match(page.versions()[1], /Editing now/);

  await page.choose("frameworkSelect", "tax");
  assert.deepEqual(page.selected(), ["Identity"]);
});

test("switching framework with no version open clears the selection quietly", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  await page.click("newVersionBtn");
  await page.click(page.pill(31));
  await page.click("cancelVersionBtn");
  await page.choose("frameworkSelect", "alt");
  assert.equal(page.record.confirms.length, 1);
  // Nothing is left to discard, so leaving the page asks nothing.
  const leave = new page.window.MouseEvent("click", { cancelable: true });
  page.$("btnBack").dispatchEvent(leave);
  assert.equal(leave.defaultPrevented, false);
});

test("a framework that cannot be read is reported", async (t) => {
  const page = await editor(t, { hash: "#versions" });
  page.world.fail["GET /v1/frameworks/4/nodes"] = [500, "Nodes unavailable"];
  await page.choose("frameworkSelect", "alt");
  assert.deepEqual(page.toasts(), [["danger", "Nodes unavailable"]]);
});

test("a version needs a framework to map against", async (t) => {
  const page = await editor(t, { hash: "#versions", frameworks: [] });
  assert.equal(page.$("frameworkSelect").options.length, 0);
  await page.edit(7);
  assert.match(
    page.$("capabilityTree").textContent,
    /No categories available\./,
  );
  await page.click("saveVersionBtn");
  assert.deepEqual(page.toasts(), [["warning", "Pick a framework first."]]);
  assert.deepEqual(page.sent("PUT", "/v1/project-versions/7"), []);
});

test("the tracked branch's own version cannot be renamed or drafted", async (t) => {
  const page = await editor(t, {
    hash: "#versions",
    project: {
      ...PROJECT,
      track_branch: true,
      tracked_branch: "main",
      branch_poll_interval_hours: 12,
      versions: [{ id: 8, version: "main", is_latest: true }, VERSIONS[2]],
    },
  });
  await page.edit(8);
  assert.deepEqual(
    ["version", "link_to_source_code", "is_draft"].map(
      (id) => page.$(id).disabled,
    ),
    [true, true, true],
  );
  assert.equal(page.$("versionBranchNotice").hidden, false);
  await page.edit(7);
  assert.equal(page.$("version").disabled, false);
  assert.equal(page.$("versionBranchNotice").hidden, true);
});

test("automatic publishing needs a release feed and reports a failed save", async (t) => {
  const without = await editor(t, {
    project: { ...PROJECT, release_rss_feed_url: "" },
  });
  assert.equal(without.$("autoPublishField").hidden, false);
  assert.equal(without.$("release_auto_publish").disabled, true);
  assert.equal(
    without.$("autoPublishHint").textContent,
    "Add a release RSS feed on the Project tab to use this.",
  );

  const page = await editor(t, {
    fail: { "PUT /v1/projects/1": [500, "Could not save"] },
  });
  await page.tick("release_auto_publish", true);
  assert.deepEqual(page.toasts(), [["danger", "Could not save"]]);
  // The switch returns to what is stored.
  assert.equal(page.$("release_auto_publish").checked, false);
  assert.equal(page.$("release_auto_publish").disabled, false);
});
