// Saved manifests: the list, a manifest's details, sharing, copying, export
// and deletion, against an API fixture that keeps what is changed.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage, FEATURES, FRAMEWORK } from "./support/app-page.mjs";

const NODES = {
  tree: [],
  items: [
    {
      id: 30,
      key: "wallet",
      display_name: "Wallet",
      parent_id: null,
      level: 0,
      path: "Wallet",
    },
    {
      id: 32,
      key: "storage",
      display_name: "Storage",
      parent_id: 30,
      level: 1,
      path: "Wallet > Storage",
    },
    {
      id: 33,
      key: "keys",
      display_name: "Keys",
      parent_id: 32,
      level: 2,
      path: "Wallet > Storage > Keys",
    },
    {
      id: 31,
      key: "issuer",
      display_name: "Issuer",
      parent_id: null,
      level: 0,
      path: null,
    },
  ],
};

function store() {
  const manifests = [
    {
      id: 1,
      name: "Board <pack>",
      description: "For the <board>",
      updated_at: "2026-03-01T00:00:00",
      created_by_user_id: 7,
      created_by_username: "ada",
      framework_id: 3,
      owner_group_id: null,
      owner_group_name: null,
      is_public: false,
      filters_json: {
        q: "wallet <x>",
        node_ids: [33, 31, 999],
        project_ids: [5, 6],
      },
      node_count: 2,
      project_count: 2,
      can_manage: true,
      can_delete: true,
      can_clone: false,
      items: [
        {
          project_id: 5,
          display_name: "Wallet <Kit>",
          machine_name: "wallet-kit",
          organisation: "Acme",
          project_type: "library",
          latest_version: "2.0.0",
        },
        {
          project_id: null,
          display_name: "",
          machine_name: "gone",
          organisation: null,
          project_type: null,
          latest_version: null,
        },
      ],
    },
    {
      id: 2,
      name: "Shared plan",
      description: null,
      updated_at: "2026-03-05T00:00:00",
      created_by_user_id: 99,
      created_by_username: "bob",
      framework_id: null,
      framework_machine_name: "legacy",
      owner_group_id: 8,
      owner_group_name: "Team",
      is_public: false,
      filters: {},
      can_manage: false,
      can_delete: false,
      can_clone: true,
      items: [],
    },
    {
      id: 3,
      name: "Open",
      updated_at: null,
      created_by_user_id: null,
      framework_id: 77,
      is_public: true,
      filters_json: { node_ids: [1], project_ids: [] },
      can_manage: false,
      can_delete: false,
      can_clone: true,
      items: [],
    },
  ];
  return { manifests };
}

async function saved(t, options = {}) {
  const data = store();
  const groups = options.groups ?? [{ id: 8, name: "Team <A>" }];
  const page = await appPage(t, "manifests.html", "pages/saved-manifests.js", {
    me: account("architect"),
    ...options,
    api: (method, path, body) => {
      const hooked = options.hooks?.[`${method} ${path}`];
      if (hooked) return hooked(body, data);
      if (path === "/v1/me/groups") return [200, { items: groups }];
      if (path === "/v1/frameworks/3/nodes") return [200, NODES];
      if (path === "/v1/manifests" && method === "GET")
        return [200, { items: data.manifests }];
      const one = /^\/v1\/manifests\/(\d+)$/.exec(path);
      if (one && method === "GET") {
        const found = data.manifests.find((m) => m.id === Number(one[1]));
        return found ? [200, found] : [404, { detail: "Manifest not found" }];
      }
      if (one && method === "DELETE") {
        data.manifests = data.manifests.filter((m) => m.id !== Number(one[1]));
        return [200, {}];
      }
      const share = /^\/v1\/manifests\/(\d+)\/sharing$/.exec(path);
      if (share) {
        Object.assign(
          data.manifests.find((m) => m.id === Number(share[1])),
          body,
          {
            owner_group_name: body.owner_group_id ? "Team" : null,
          },
        );
        return [200, {}];
      }
      const clone = /^\/v1\/manifests\/(\d+)\/clone$/.exec(path);
      if (clone) {
        const source = data.manifests.find((m) => m.id === Number(clone[1]));
        data.manifests.push({
          ...source,
          id: 10,
          name: `${source.name} (copy)`,
          created_by_user_id: 7,
          can_manage: true,
          can_delete: true,
          can_clone: false,
          owner_group_id: null,
          owner_group_name: null,
        });
        return [200, { id: 10 }];
      }
      if (/^\/v1\/manifests\/\d+\/export$/.test(path))
        return [200, "file-body"];
      return null;
    },
  });
  return Object.assign(page, { data });
}

const cards = (page) =>
  [...page.doc.querySelectorAll("#manifestList .card")].map((card) =>
    card.textContent.replace(/\s+/g, " ").trim(),
  );
const open = async (page, id) =>
  page.click(page.doc.querySelector(`#manifestList button[data-id="${id}"]`));

test("the list shows each manifest's visibility, owner and size, newest first", async (t) => {
  const page = await saved(t);
  assert.deepEqual(page.errors, []);
  assert.deepEqual(cards(page), [
    "Shared plan Group Framework: legacy · Categories: 0 · Projects: 0 Owner: bob Open",
    "Board <pack> Private Framework: Taxonomy · Categories: 2 · Projects: 2 Owner: You Search: “wallet <x>” Open",
    "Open Public Framework: — · Categories: 1 · Projects: 0 Owner: — Open",
  ]);
  assert.equal(page.$("manifestList").querySelector("pack"), null);
  assert.deepEqual(
    [...page.doc.querySelectorAll("#manifestList .badge")].map((b) =>
      b.className.replace("badge ", ""),
    ),
    ["bg-primary", "bg-secondary", "bg-success"],
  );
  assert.equal(page.$("manifestDetailsCard").style.display, "none");
});

test("opening a manifest shows what was saved and what the owner may do", async (t) => {
  const page = await saved(t);
  await open(page, 1);
  assert.equal(page.$("manifestList").style.display, "none");
  assert.equal(page.$("manifestDetailsCard").style.display, "");
  assert.equal(page.$("manifestDetailsTitle").textContent, "Board <pack>");
  assert.deepEqual(page.texts("#manifestDetailsMeta div"), [
    "Framework: Taxonomy",
    "Owner: You",
    "Visibility: Private",
    "Search: “wallet <x>”",
    "For the <board>",
  ]);
  assert.equal(page.$("manifestDetailsMeta").querySelector("board"), null);
  // Saved categories that still exist, by path; one deleted since is skipped.
  const pills = [
    ...page.doc.querySelectorAll("#manifestDetailsFilters .capability-pill"),
  ];
  assert.deepEqual(
    pills.map((p) => [p.textContent.trim(), p.getAttribute("title")]),
    [
      ["Issuer", "Issuer"],
      ["Keys", "Wallet > Storage > Keys"],
    ],
  );
  const rows = [
    ...page.doc.querySelectorAll("#manifestDetailsProjects tbody tr"),
  ];
  assert.deepEqual(
    rows.map((row) => [...row.children].map((c) => c.textContent.trim())),
    [
      ["Wallet <Kit>", "Acme", "library", "2.0.0"],
      ["gone", "—", "—", "—"],
    ],
  );
  assert.equal(
    rows[0].querySelector("a").getAttribute("href"),
    "/project.html?id=5",
  );
  // A project deleted since the snapshot is named without a dead link.
  assert.equal(rows[1].querySelector("a"), null);
  assert.equal(page.$("deleteManifestBtn").style.display, "");
  assert.equal(page.$("cloneManifestBtn").style.display, "none");
  assert.ok(
    page
      .$("manifestSharingArea")
      .textContent.includes("Share with group: Team <A>"),
  );

  await page.click("backToListBtn");
  assert.equal(page.$("manifestDetailsCard").style.display, "none");
  assert.equal(page.$("manifestList").style.display, "");
});

test("a manifest shared with the reader can be copied but not managed", async (t) => {
  const page = await saved(t);
  await open(page, 2);
  assert.deepEqual(page.texts("#manifestDetailsMeta div"), [
    "Framework: legacy",
    "Owner: bob",
    "Visibility: Group (Team)",
    "No search query.",
  ]);
  assert.match(
    page.$("manifestDetailsFilters").textContent,
    /No categories saved/,
  );
  assert.match(
    page.$("manifestDetailsProjects").textContent,
    /No projects matched when this manifest was saved\./,
  );
  assert.equal(page.$("manifestSharingArea").innerHTML, "");
  assert.equal(page.$("deleteManifestBtn").style.display, "none");
  assert.equal(page.$("cloneManifestBtn").style.display, "");

  await page.click("cloneManifestBtn");
  assert.deepEqual(page.sent("POST", "/v1/manifests/2/clone"), [{}]);
  assert.deepEqual(page.toasts(), [
    ["info", "Manifest cloned to your saved manifests."],
  ]);
  // The copy is opened, and is the reader's own.
  assert.equal(
    page.$("manifestDetailsTitle").textContent,
    "Shared plan (copy)",
  );
  assert.equal(page.$("deleteManifestBtn").style.display, "");
  assert.equal(cards(page).length, 4);
});

test("sharing with one group is a tick box; saving reloads the manifest", async (t) => {
  const page = await saved(t);
  await open(page, 1);
  const group = page.$("shareWithGroupChk");
  assert.equal(group.checked, false);
  assert.equal(page.$("makePublicChk").checked, false);
  group.checked = true;
  page.$("makePublicChk").checked = true;
  await page.click("saveSharingBtn");
  assert.deepEqual(page.sent("PATCH", "/v1/manifests/1/sharing"), [
    { owner_group_id: 8, is_public: true },
  ]);
  assert.deepEqual(page.toasts(), [["info", "Sharing updated."]]);
  assert.ok(
    page
      .texts("#manifestDetailsMeta div")
      .includes("Visibility: Public (Team)"),
  );
  assert.equal(page.$("shareWithGroupChk").checked, true);
  assert.equal(page.$("makePublicChk").checked, true);

  page.$("shareWithGroupChk").checked = false;
  page.$("makePublicChk").checked = false;
  await page.click("saveSharingBtn");
  assert.deepEqual(page.sent("PATCH", "/v1/manifests/1/sharing")[1], {
    owner_group_id: null,
    is_public: false,
  });
});

test("several groups become a list; none leaves only the public choice", async (t) => {
  const many = await saved(t, {
    groups: [
      { id: 8, name: "Team" },
      { id: 9, name: "Docs" },
    ],
  });
  await open(many, 1);
  assert.deepEqual(many.texts("#shareGroupSelect option"), [
    "Not shared (private)",
    "Team",
    "Docs",
  ]);
  assert.equal(many.$("shareGroupSelect").value, "0");
  many.$("shareGroupSelect").value = "9";
  await many.click("saveSharingBtn");
  assert.deepEqual(many.sent("PATCH", "/v1/manifests/1/sharing"), [
    { owner_group_id: 9, is_public: false },
  ]);
  assert.equal(many.$("shareGroupSelect").value, "9");
  many.$("shareGroupSelect").value = "0";
  await many.click("saveSharingBtn");
  assert.equal(
    many.sent("PATCH", "/v1/manifests/1/sharing")[1].owner_group_id,
    null,
  );

  const none = await saved(t, { groups: [] });
  await open(none, 1);
  assert.ok(
    none
      .$("manifestSharingArea")
      .textContent.includes("You are not a member of any group."),
  );
  none.$("makePublicChk").checked = true;
  await none.click("saveSharingBtn");
  assert.deepEqual(none.sent("PATCH", "/v1/manifests/1/sharing"), [
    { owner_group_id: null, is_public: true },
  ]);
});

test("a manifest exports under its own name in each format", async (t) => {
  const page = await saved(t);
  await open(page, 1);
  for (const id of [
    "savedExportJsonBtn",
    "savedExportXlsxBtn",
    "savedExportMdBtn",
  ])
    await page.click(id);
  assert.deepEqual(
    page.asked().filter((r) => r.includes("/export")),
    ["json", "xlsx", "markdown"].map(
      (f) => `GET /v1/manifests/1/export?format=${f}`,
    ),
  );
  // The file name keeps only characters safe in a file name.
  assert.deepEqual(
    page.record.downloads.map((d) => d.name),
    ["Board-pack-.json", "Board-pack-.xlsx", "Board-pack-.md"],
  );
});

test("deleting asks first, then returns to the list", async (t) => {
  const kept = await saved(t, { confirm: false });
  await open(kept, 1);
  await kept.click("deleteManifestBtn");
  assert.deepEqual(kept.record.confirms, ["Delete this saved manifest?"]);
  assert.equal(kept.asked().filter((r) => r.startsWith("DELETE")).length, 0);

  const page = await saved(t);
  await open(page, 1);
  await page.click("deleteManifestBtn");
  assert.deepEqual(page.toasts(), [["info", "Manifest deleted."]]);
  assert.equal(page.$("manifestDetailsCard").style.display, "none");
  assert.equal(cards(page).length, 2);
});

test("a refused action is reported instead of failing silently", async (t) => {
  const refuse = (detail) => () => [403, { detail }];
  const page = await saved(t, {
    hooks: {
      "GET /v1/manifests/1/export": refuse("Export not allowed"),
      "DELETE /v1/manifests/1": refuse("Delete not allowed"),
      "PATCH /v1/manifests/1/sharing": refuse(
        "Cannot share with a group you are not part of",
      ),
      "POST /v1/manifests/2/clone": refuse("Clone not allowed"),
      "GET /v1/manifests/3": refuse(
        "You do not have permission to modify this manifest",
      ),
    },
  });
  await open(page, 1);
  await page.click("savedExportJsonBtn");
  await page.click("deleteManifestBtn");
  await page.click("saveSharingBtn");
  await page.click("backToListBtn");
  await open(page, 2);
  await page.click("cloneManifestBtn");
  await page.click("backToListBtn");
  await open(page, 3);
  assert.deepEqual(page.toasts(), [
    ["danger", "Export not allowed"],
    ["danger", "Delete not allowed"],
    ["danger", "Cannot share with a group you are not part of"],
    ["danger", "Clone not allowed"],
    ["danger", "You do not have permission to modify this manifest"],
  ]);
  assert.equal(page.record.downloads.length, 0);
  assert.equal(cards(page).length, 3);
});

test("refresh rereads the list and the open manifest", async (t) => {
  const page = await saved(t);
  const count = (path) =>
    page.asked().filter((r) => r === `GET ${path}`).length;
  await page.click("savedRefreshBtn");
  assert.equal(count("/v1/manifests"), 2);
  assert.equal(count("/v1/manifests/1"), 0);
  await open(page, 1);
  page.data.manifests[0].name = "Renamed elsewhere";
  // The builder saves into this list, so showing the tab reloads it too.
  page.$("tabBtnSaved").dispatchEvent(new page.window.Event("shown.bs.tab"));
  await page.wait();
  assert.equal(count("/v1/manifests"), 3);
  assert.equal(count("/v1/manifests/1"), 2);
  assert.equal(page.$("manifestDetailsTitle").textContent, "Renamed elsewhere");
});

test("a shared link opens its manifest straight away", async (t) => {
  const page = await saved(t, { query: "?id=2" });
  assert.equal(page.$("manifestDetailsTitle").textContent, "Shared plan");
  assert.equal(page.$("manifestList").style.display, "none");

  const missing = await saved(t, { query: "?id=404" });
  assert.deepEqual(missing.toasts(), [["danger", "Manifest not found"]]);
  const odd = await saved(t, { query: "?id=abc" });
  assert.equal(
    odd.asked().filter((r) => /\/v1\/manifests\/\w/.test(r)).length,
    0,
  );
});

test("an empty list, a role without access and a switched-off feature", async (t) => {
  const empty = await saved(t, {
    hooks: { "GET /v1/manifests": () => [200, { items: [] }] },
  });
  assert.equal(
    empty.$("manifestList").textContent.trim(),
    "No saved manifests yet.",
  );

  const engineer = await saved(t, { me: account("engineer") });
  assert.equal(
    engineer.asked().filter((r) => r.includes("/v1/manifests")).length,
    0,
  );

  const off = await saved(t, {
    me: account("architect", { features: { ...FEATURES, manifests: false } }),
  });
  assert.equal(off.navigations(), 1);
  assert.equal(
    off.asked().filter((r) => r.includes("/v1/manifests")).length,
    0,
  );
  assert.equal(FRAMEWORK.id, 3);
});
