// Framework administration: the framework list, its details, and the
// taxonomy editor, against an API fixture that keeps what is saved.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage, FEATURES } from "./support/app-page.mjs";

function catalogue() {
  const frameworks = [
    {
      id: 3,
      machine_name: "tax",
      display_name: "Taxonomy",
      description: "Main <one>",
      created_by_user_id: 7,
    },
    {
      id: 4,
      machine_name: "other",
      display_name: "",
      description: null,
      created_by_user_id: 99,
    },
  ];
  const nodes = {
    3: [
      {
        id: 30,
        key: "wallet",
        display_name: "Wallet",
        description: "Holder",
        parent_id: null,
        level: 0,
        sort_order: 2,
        path: "Wallet",
      },
      {
        id: 32,
        key: "storage",
        display_name: "Storage",
        description: null,
        parent_id: 30,
        level: 1,
        sort_order: 0,
        path: "Wallet > Storage",
      },
      {
        id: 33,
        key: "keys",
        display_name: "Keys",
        description: null,
        parent_id: 32,
        level: 2,
        sort_order: 0,
        path: "Wallet > Storage > Keys",
      },
      {
        id: 31,
        key: "issuer",
        display_name: "Issuer",
        description: null,
        parent_id: null,
        level: 0,
        sort_order: 1,
        path: "Issuer",
      },
    ],
    4: [],
  };
  const tree = (items, parent = null) =>
    items
      .filter((n) => n.parent_id === parent)
      .map((n) => ({ ...n, children: tree(items, n.id) }));
  return {
    frameworks,
    nodes,
    answer(method, path, body, hooks = {}) {
      const hooked = hooks[`${method} ${path}`];
      if (hooked) return hooked(body);
      if (path === "/v1/frameworks" && method === "GET")
        return [200, { items: frameworks }];
      if (path === "/v1/frameworks" && method === "POST") {
        const created = { id: 9, created_by_user_id: 7, ...body };
        frameworks.push(created);
        nodes[9] = [];
        return [200, created];
      }
      const fw = /^\/v1\/frameworks\/(\d+)$/.exec(path);
      if (fw && method === "PUT") {
        const row = frameworks.find((f) => f.id === Number(fw[1]));
        Object.assign(row, body);
        return [200, row];
      }
      if (fw && method === "DELETE") {
        frameworks.splice(
          frameworks.findIndex((f) => f.id === Number(fw[1])),
          1,
        );
        return [200, { ok: true }];
      }
      const list = /^\/v1\/frameworks\/(\d+)\/nodes$/.exec(path);
      if (list && method === "GET") {
        const items = nodes[list[1]] || [];
        return [200, { tree: tree(items), items }];
      }
      if (list && method === "POST") {
        nodes[list[1]].push({
          id: 50,
          level: 0,
          path: body.display_name,
          ...body,
        });
        return [200, { id: 50 }];
      }
      const node = /^\/v1\/framework-nodes\/(\d+)$/.exec(path);
      if (node && method === "PUT") {
        Object.assign(
          nodes[3].find((n) => n.id === Number(node[1])),
          body,
        );
        return [200, {}];
      }
      if (node && method === "DELETE") {
        nodes[3] = nodes[3].filter((n) => n.id !== Number(node[1]));
        return [200, { ok: true }];
      }
      return null;
    },
  };
}

async function manage(t, options = {}) {
  const data = catalogue();
  const page = await appPage(
    t,
    "framework-manage.html",
    "pages/framework-manage.js",
    {
      ...options,
      api: (method, path, body) =>
        data.answer(method, path, body, options.hooks),
    },
  );
  return Object.assign(page, { data });
}

const tree = (page) => page.texts("#nodeTree [data-pick]");
const msg = (page, id) => [page.$(id).textContent, page.$(id).className];

test("the page lists frameworks and opens the first with its taxonomy", async (t) => {
  const page = await manage(t);
  assert.deepEqual(page.errors, []);
  const rows = [...page.doc.querySelectorAll("#frameworkList tbody tr")];
  assert.deepEqual(
    rows.map((row) =>
      [...row.children].map((c) => c.textContent.replace(/\s+/g, " ").trim()),
    ),
    [
      ["TaxonomyMain <one>", "tax", "you"],
      ["other", "other", "user:99"],
    ],
  );
  assert.equal(rows[0].querySelector("one"), null);
  assert.equal(page.$("selectedFrameworkEmpty").style.display, "none");
  assert.equal(page.$("fwTitle").textContent, "Taxonomy");
  assert.equal(page.$("fwMeta").textContent, "id 3 • machine tax");
  assert.deepEqual(
    ["fwMachine", "fwDisplay", "fwDescription"].map((id) => page.$(id).value),
    ["tax", "Taxonomy", "Main <one>"],
  );
  // The whole taxonomy starts expanded, in a single-selection browser.
  assert.deepEqual(tree(page), [
    "Wallet",
    "Wallet > Storage",
    "Wallet > Storage > Keys",
    "Issuer",
  ]);
  assert.equal(page.record.taxonomy.selectionMode, "single");
  assert.equal(page.record.taxonomy.selectedId, null);
  assert.deepEqual(page.texts("#nodeParent option"), [
    "(no parent)",
    "Issuer",
    "Wallet",
    "Wallet > Storage",
    "Wallet > Storage > Keys",
  ]);
  assert.equal(page.$("nodeDeleteBtn").disabled, true);
});

test("choosing a node loads it for editing and bars it from its own subtree", async (t) => {
  const page = await manage(t);
  await page.click(page.doc.querySelector('[data-pick="32"]'));
  assert.deepEqual(
    ["nodeKey", "nodeDisplay", "nodeDescription", "nodeSort", "nodeParent"].map(
      (id) => page.$(id).value,
    ),
    ["storage", "Storage", "", "0", "30"],
  );
  assert.equal(page.$("nodePath").textContent, "Wallet > Storage");
  assert.equal(page.$("nodeDeleteBtn").disabled, false);
  assert.equal(page.record.taxonomy.selectedId, 32);
  // Neither the node nor its descendants can become its parent.
  assert.deepEqual(page.texts("#nodeParent option"), [
    "(no parent)",
    "Issuer",
    "Wallet",
  ]);

  page.$("nodeKey").value = " store ";
  page.$("nodeDisplay").value = " Store ";
  page.$("nodeDescription").value = " Where things live ";
  page.$("nodeSort").value = "5";
  page.$("nodeParent").value = "";
  await page.click("nodeSaveBtn");
  assert.deepEqual(page.sent("PUT", "/v1/framework-nodes/32"), [
    {
      key: "store",
      display_name: "Store",
      description: "Where things live",
      parent_id: null,
      sort_order: 5,
    },
  ]);
  assert.deepEqual(msg(page, "nodeMsg"), [
    "Node updated.",
    "small msg-success",
  ]);
  // The tree is read again and the editor returns to "new".
  assert.equal(
    page.asked().filter((r) => r === "GET /v1/frameworks/3/nodes").length,
    2,
  );
  assert.equal(page.$("nodeKey").value, "");
  assert.equal(page.$("nodeDeleteBtn").disabled, true);
});

test("a new node needs a key, a name and a numeric order", async (t) => {
  const page = await manage(t);
  await page.click(page.doc.querySelector('[data-pick="30"]'));
  await page.click("nodeNewBtn");
  assert.deepEqual(msg(page, "nodeMsg"), ["Creating a new node.", "small"]);
  assert.equal(page.$("nodeKey").value, "");
  assert.equal(page.texts("#nodeParent option").length, 5);

  await page.click("nodeSaveBtn");
  assert.deepEqual(msg(page, "nodeMsg"), [
    "Node key and display name are required.",
    "small msg-error",
  ]);
  page.$("nodeKey").value = "verifier";
  page.$("nodeDisplay").value = "Verifier";
  page.$("nodeSort").value = "soon";
  await page.click("nodeSaveBtn");
  assert.deepEqual(msg(page, "nodeMsg"), [
    "Sort order must be a number.",
    "small msg-error",
  ]);
  assert.equal(page.asked().filter((r) => r.startsWith("POST")).length, 0);

  page.$("nodeSort").value = "";
  page.$("nodeParent").value = "31";
  await page.click("nodeSaveBtn");
  assert.deepEqual(page.sent("POST", "/v1/frameworks/3/nodes"), [
    {
      key: "verifier",
      display_name: "Verifier",
      description: null,
      parent_id: 31,
      sort_order: 0,
    },
  ]);
  assert.deepEqual(msg(page, "nodeMsg"), [
    "Node created.",
    "small msg-success",
  ]);
  assert.ok(tree(page).includes("Verifier"));
});

test("node saves and deletions the API refuses are shown beside the editor", async (t) => {
  const page = await manage(t, {
    hooks: {
      "PUT /v1/framework-nodes/31": () => [
        409,
        { detail: "Node key already exists in this framework" },
      ],
      "DELETE /v1/framework-nodes/30": () => [
        409,
        { detail: "Node has children; delete/move children first" },
      ],
    },
  });
  await page.click(page.doc.querySelector('[data-pick="31"]'));
  await page.click("nodeSaveBtn");
  assert.deepEqual(msg(page, "nodeMsg"), [
    "Node key already exists in this framework",
    "small msg-error",
  ]);

  await page.click(page.doc.querySelector('[data-pick="30"]'));
  await page.click("nodeDeleteBtn");
  assert.deepEqual(page.record.confirms, [
    "Delete this node? This cannot be undone.",
  ]);
  assert.deepEqual(msg(page, "nodeMsg"), [
    "Node has children; delete/move children first",
    "small msg-error",
  ]);

  await page.click(page.doc.querySelector('[data-pick="33"]'));
  await page.click("nodeDeleteBtn");
  assert.deepEqual(page.toasts(), [["info", "Node deleted"]]);
  assert.deepEqual(tree(page), ["Wallet", "Wallet > Storage", "Issuer"]);
});

test("declining the confirmation deletes nothing", async (t) => {
  const page = await manage(t, { confirm: false });
  await page.click(page.doc.querySelector('[data-pick="33"]'));
  await page.click("nodeDeleteBtn");
  await page.click("fwDeleteBtn");
  assert.equal(page.asked().filter((r) => r.startsWith("DELETE")).length, 0);
  assert.equal(page.record.confirms.length, 2);
  assert.match(page.record.confirms[1], /^Delete framework "Taxonomy"\?/);
});

test("the tree folds, unfolds and filters", async (t) => {
  const page = await manage(t);
  await page.click("nodeCollapseAllBtn");
  assert.deepEqual(tree(page), ["Wallet", "Issuer"]);
  // Opening one branch keeps the others as they were.
  await page.click(page.doc.querySelector('[data-fold="30"]'));
  assert.deepEqual(tree(page), ["Wallet", "Wallet > Storage", "Issuer"]);
  await page.click(page.doc.querySelector('[data-fold="30"]'));
  assert.deepEqual(tree(page), ["Wallet", "Issuer"]);
  await page.click("nodeExpandAllBtn");
  assert.equal(tree(page).length, 4);
  await page.type("nodeSearch", "  keys ");
  assert.equal(page.record.taxonomy.searchTerm, "keys");
  // Colours come from the branch a node sits under, namespaced by framework.
  const colours = [30, 32, 33, 31].map((id) =>
    page.record.taxonomy.colorForNode({ id }),
  );
  assert.equal(colours[1], colours[2]);
  assert.equal(
    page.record.taxonomy.colorForNode({ id: 999 }),
    page.record.taxonomy.colorForNode(undefined),
  );
});

test("a framework is created, opened, renamed and deleted", async (t) => {
  const page = await manage(t);
  await page.click("fwCreateBtn");
  assert.deepEqual(msg(page, "fwCreateMsg"), [
    "Machine name and display name are required.",
    "small msg-error",
  ]);
  page.$("fwCreateMachine").value = " new ";
  page.$("fwCreateDisplay").value = " New one ";
  await page.click("fwCreateBtn");
  assert.deepEqual(page.sent("POST", "/v1/frameworks"), [
    { machine_name: "new", display_name: "New one", description: null },
  ]);
  assert.deepEqual(msg(page, "fwCreateMsg"), [
    "Framework created.",
    "small msg-success",
  ]);
  assert.equal(page.$("fwCreateMachine").value, "");
  // The new framework is selected, with its (empty) taxonomy.
  assert.equal(page.$("fwTitle").textContent, "New one");
  assert.deepEqual(tree(page), []);
  assert.equal(page.doc.querySelectorAll("#frameworkList tbody tr").length, 3);

  page.$("fwDisplay").value = "  ";
  await page.click("fwSaveBtn");
  assert.deepEqual(msg(page, "fwSaveMsg"), [
    "Machine name and display name are required.",
    "small msg-error",
  ]);
  page.$("fwDisplay").value = "Renamed";
  page.$("fwDescription").value = " notes ";
  await page.click("fwSaveBtn");
  assert.deepEqual(page.sent("PUT", "/v1/frameworks/9"), [
    { machine_name: "new", display_name: "Renamed", description: "notes" },
  ]);
  assert.equal(page.$("fwTitle").textContent, "Renamed");
  assert.ok(page.$("frameworkList").textContent.includes("Renamed"));

  await page.click("fwDeleteBtn");
  assert.deepEqual(page.toasts(), [["success", "Framework deleted"]]);
  assert.equal(page.$("selectedFrameworkPanel").style.display, "none");
  assert.equal(page.$("selectedFrameworkEmpty").style.display, "");
  assert.equal(page.doc.querySelectorAll("#frameworkList tbody tr").length, 2);
});

test("a framework in use is deleted only after a second confirmation", async (t) => {
  let forced = 0;
  const page = await manage(t, {
    hooks: {
      "DELETE /v1/frameworks/3": () => {
        forced += 1;
        return forced === 1
          ? [
              409,
              {
                detail:
                  "Framework is referenced by 2 project mappings and 1 manifests.",
              },
            ]
          : [200, { ok: true }];
      },
    },
  });
  await page.click("fwDeleteBtn");
  assert.equal(page.record.confirms.length, 2);
  assert.match(
    page.record.confirms[1],
    /^Framework is referenced by 2 project mappings/,
  );
  assert.deepEqual(
    page.asked().filter((r) => r.startsWith("DELETE")),
    ["DELETE /v1/frameworks/3", "DELETE /v1/frameworks/3?force=true"],
  );
  assert.deepEqual(page.toasts(), [["success", "Framework deleted"]]);
});

test("failures while saving or deleting a framework are reported", async (t) => {
  const page = await manage(t, {
    hooks: {
      "PUT /v1/frameworks/3": () => [
        409,
        { detail: "Framework machine_name already exists" },
      ],
      "DELETE /v1/frameworks/3": () => [500, { detail: "Server error" }],
      "POST /v1/frameworks": () => [
        409,
        { detail: "Framework machine_name already exists" },
      ],
    },
  });
  await page.click("fwSaveBtn");
  assert.deepEqual(msg(page, "fwSaveMsg"), [
    "Framework machine_name already exists",
    "small msg-error",
  ]);
  page.$("fwCreateMachine").value = "tax";
  page.$("fwCreateDisplay").value = "Again";
  await page.click("fwCreateBtn");
  assert.deepEqual(msg(page, "fwCreateMsg"), [
    "Framework machine_name already exists",
    "small msg-error",
  ]);
  await page.click("fwDeleteBtn");
  assert.deepEqual(page.toasts(), [["danger", "Server error"]]);
  assert.equal(page.$("fwTitle").textContent, "Taxonomy");
});

test("a framework administrator deletes only their own frameworks", async (t) => {
  const page = await manage(t, { me: account("framework_admin") });
  assert.equal(page.$("fwDeleteBtn").disabled, false);
  await page.click(page.doc.querySelector('[data-framework-id="4"] td'));
  assert.equal(page.$("fwTitle").textContent, "other");
  const button = page.$("fwDeleteBtn");
  assert.equal(button.disabled, true);
  assert.equal(
    button.title,
    "Only the framework owner or an admin can delete this framework.",
  );
  // Even with the control re-enabled by hand the page refuses.
  button.disabled = false;
  await page.click("fwDeleteBtn");
  assert.deepEqual(page.toasts(), [
    [
      "danger",
      "Only the framework owner or an admin can delete this framework.",
    ],
  ]);
  assert.equal(page.asked().filter((r) => r.startsWith("DELETE")).length, 0);
  // Clicking outside a row selects nothing new.
  await page.click(page.doc.querySelector("#frameworkList thead th"));
  assert.equal(page.$("fwTitle").textContent, "other");
});

test("refresh and reload read the lists again", async (t) => {
  const page = await manage(t);
  const count = (path) =>
    page.asked().filter((r) => r === `GET ${path}`).length;
  await page.click("refreshFrameworksBtn");
  assert.equal(count("/v1/frameworks"), 2);
  await page.click("fwReloadNodesBtn");
  assert.equal(count("/v1/frameworks/3/nodes"), 2);
});

test("other roles are turned away, and the page leaves when the feature is off", async (t) => {
  const viewer = await manage(t, { me: account("maintainer") });
  assert.deepEqual(viewer.toasts(), [
    ["danger", "You do not have access to framework administration."],
  ]);
  assert.equal(viewer.navigations(), 1);
  assert.equal(viewer.doc.querySelectorAll("#frameworkList tr").length, 0);
  assert.equal(
    viewer.asked().filter((r) => r.includes("/v1/frameworks")).length,
    0,
  );

  const off = await manage(t, {
    me: account("admin", { features: { ...FEATURES, frameworks: false } }),
  });
  assert.equal(off.navigations(), 1);
  assert.equal(
    off.asked().filter((r) => r.includes("/v1/frameworks")).length,
    0,
  );
});

test("with no frameworks the list says so", async (t) => {
  const page = await manage(t, {
    hooks: { "GET /v1/frameworks": () => [200, { items: [] }] },
  });
  assert.equal(
    page.$("frameworkList").textContent.trim(),
    "No frameworks found.",
  );
  assert.equal(page.$("selectedFrameworkPanel").style.display, "none");
});

test("without the taxonomy widget the tree says it cannot load", async (t) => {
  const page = await manage(t, { setup: (window) => delete window.mospUi });
  assert.equal(page.$("nodeTree").textContent, "Unable to load taxonomy UI.");
});
