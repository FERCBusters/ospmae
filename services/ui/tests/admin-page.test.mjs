// The Administration page: accounts, groups and their access, the audit
// trail and changelog, organisations, the mail outbox and release feeds.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage } from "./support/app-page.mjs";

const local = (text) => new Date(`${text}Z`).toLocaleString();

const USERS = [
  {
    id: 7,
    username: "ada",
    email: "ada@example.org",
    role: "admin",
    effective_role: "admin",
    is_active: true,
    last_login_at: "2026-03-04T10:00:00",
  },
  {
    id: 9,
    username: "bob <b>",
    email: null,
    role: "inherit",
    effective_role: "engineer",
    is_active: false,
    last_login_at: null,
  },
];
const GROUPS = [
  {
    id: 4,
    name: "Reviewers",
    description: "Second pair of eyes",
    role: "engineer",
    member_count: 2,
    permission_count: 1,
  },
  { id: 5, name: "Guests", description: null, role: null },
];
const PERMISSIONS = [
  { id: 21, code: "projects.write", description: "Edit projects" },
  { id: 22, code: "frameworks.write", description: "" },
];

function auditRows(count, start = 0) {
  return Array.from({ length: count }, (_, i) => ({
    ts: "2026-03-04T10:00:00",
    username: i === 0 ? null : "ada",
    method: "GET",
    path: `/v1/projects/${start + i}`,
    query_string: i === 0 ? "q=<x>" : "",
    status_code: [200, 302, 404, 500][i % 4],
    duration_ms: i === 0 ? null : 12,
    client_ip: i === 0 ? null : "10.0.0.1",
    user_agent: i === 0 ? null : "curl/8",
  }));
}

// The administration API as one in-memory installation.
function admin(t, options = {}) {
  const world = {
    users: structuredClone(options.users || USERS),
    groups: structuredClone(options.groups || GROUPS),
    organisations: structuredClone(options.organisations || []),
    auditTotal: options.auditTotal ?? 3,
    changelogTotal: options.changelogTotal ?? 1,
    fail: { ...options.fail },
  };
  const prompts = [];
  const api = (method, route, body, params) => {
    const failure = world.fail[`${method} ${route}`];
    if (failure) return [failure[0], { detail: failure[1] }];
    if (route === "/v1/admin/users" && method === "GET")
      return [200, { items: world.users }];
    if (route === "/v1/admin/users" && method === "POST") {
      world.users.push({
        id: 30,
        ...body,
        effective_role: body.role,
        is_active: true,
      });
      return [201, {}];
    }
    if (route === "/v1/admin/groups" && method === "GET")
      return [200, { items: world.groups }];
    if (route === "/v1/admin/groups" && method === "POST") {
      world.groups.push({ id: 31, ...body });
      return [201, {}];
    }
    if (route === "/v1/admin/permissions") return [200, { items: PERMISSIONS }];
    const user = route.match(/^\/v1\/admin\/users\/(\d+)(\/\w+)?$/);
    if (user) {
      const id = Number(user[1]);
      if (user[2] === "/access" && method === "GET")
        return [
          200,
          {
            user_id: id,
            group_ids: [4],
            permission_ids: [22],
            available_groups: world.groups,
            available_permissions: PERMISSIONS,
          },
        ];
      if (method === "PATCH")
        Object.assign(
          world.users.find((u) => u.id === id),
          body,
        );
      if (method === "DELETE")
        world.users = world.users.filter((u) => u.id !== id);
      return [200, {}];
    }
    const group = route.match(/^\/v1\/admin\/groups\/(\d+)(\/\w+)?$/);
    if (group) {
      const id = Number(group[1]);
      if (group[2] === "/permissions" && method === "GET")
        return [
          200,
          {
            group_id: id,
            permission_ids: [21],
            available_permissions: PERMISSIONS,
          },
        ];
      if (method === "PATCH")
        Object.assign(
          world.groups.find((g) => g.id === id),
          body,
        );
      if (method === "DELETE")
        world.groups = world.groups.filter((g) => g.id !== id);
      return [200, {}];
    }
    if (route === "/v1/admin/audit") {
      const offset = Number(params.get("offset"));
      const limit = Number(params.get("limit"));
      return [
        200,
        {
          items: auditRows(Math.min(limit, world.auditTotal - offset), offset),
          total: world.auditTotal,
          limit,
          offset,
        },
      ];
    }
    if (route === "/v1/admin/entity-changelog") {
      const offset = Number(params.get("offset"));
      const limit = Number(params.get("limit"));
      const shown = Math.max(0, Math.min(limit, world.changelogTotal - offset));
      return [
        200,
        {
          items: Array.from({ length: shown }, (_, i) => ({
            summary: `Change ${offset + i}`,
            entity_type: "project",
            entity_title: "Wallet Kit",
            changed_by_username: "ada",
            changed_at: "2026-03-04T10:00:00",
            changes: [{ label: "Name", before: "Old", after: "New" }],
          })),
          total: world.changelogTotal,
          limit,
          offset,
        },
      ];
    }
    if (route === "/v1/organisations") return [200, world.organisations];
    if (route === "/v1/admin/organisations" && method === "POST") {
      world.organisations.push({ id: 60, project_count: 0, ...body });
      return [201, {}];
    }
    const org = route.match(/^\/v1\/admin\/organisations\/(\d+)$/);
    if (org) {
      Object.assign(
        world.organisations.find((o) => o.id === Number(org[1])),
        body,
      );
      return [200, {}];
    }
    if (route === "/v1/admin/notifications")
      return [
        200,
        options.outbox || { pending: 0, failed: 0, notifications: [] },
      ];
    if (route === "/v1/admin/release-feeds/discover-all")
      return [200, { enqueued: 3, pending_notifications: 2 }];
    return null;
  };
  return appPage(t, "admin.html", "pages/admin.js", {
    ...options,
    api,
    setup(window) {
      window.prompt = (message) => {
        prompts.push(message);
        return options.password ?? "correct horse";
      };
    },
  }).then((page) => ({
    ...page,
    world,
    prompts,
    message: () => [page.$("msg").textContent, page.$("msg").className],
    button: (table, action, id) =>
      page
        .$(table)
        .querySelector(
          `button[data-action="${action}"]` +
            (id
              ? `[data-${table === "usersTable" ? "user" : "group"}-id="${id}"]`
              : ""),
        ),
    field: (table, name, id) =>
      page
        .$(table)
        .querySelector(
          `[data-field="${name}"][data-${table === "usersTable" ? "user" : "group"}-id="${id}"]`,
        ),
    async submit(form) {
      page
        .$(form)
        .dispatchEvent(
          new page.window.Event("submit", { bubbles: true, cancelable: true }),
        );
      await page.wait();
    },
  }));
}

const userRows = (page) =>
  [...page.$("usersTable").querySelectorAll("tbody tr")]
    .filter((row) => row.children.length > 1)
    .map((row) => [
      row.children[0].textContent,
      row.querySelector('[data-field="email"]').value,
      row.querySelector('[data-field="role"]').value,
      row.children[3].textContent,
      row.querySelector('[data-field="active"]').checked,
      row.children[5].textContent,
    ]);

test("anyone other than an administrator is sent back to the home page", async (t) => {
  const page = await admin(t, { me: account("maintainer") });
  assert.equal(page.navigations(), 1);
  assert.deepEqual(
    page.asked().filter((call) => call.includes("/v1/admin/")),
    [],
  );
  assert.equal(page.$("usersTable").innerHTML, "");
});

test("accounts are listed with their role, state and last sign-in", async (t) => {
  const page = await admin(t);
  assert.deepEqual(page.errors, []);
  assert.deepEqual(userRows(page), [
    [
      "ada",
      "ada@example.org",
      "admin",
      "admin",
      true,
      local("2026-03-04T10:00:00"),
    ],
    ["bob <b>", "", "inherit", "engineer", false, "—"],
  ]);
  // An administrator cannot deactivate or delete their own account.
  assert.equal(page.field("usersTable", "active", 7).disabled, true);
  assert.equal(page.button("usersTable", "delete-user", 7).disabled, true);
  assert.equal(page.field("usersTable", "active", 9).disabled, false);
  assert.equal(page.button("usersTable", "delete-user", 9).disabled, false);
});

test("an installation without accounts or groups says so", async (t) => {
  const page = await admin(t, { users: [], groups: [] });
  assert.deepEqual(page.texts("#usersTable tbody td"), ["No users found."]);
  assert.deepEqual(page.texts("#groupsTable tbody td"), ["No groups found."]);
});

test("creating an account sends the form and lists the new account", async (t) => {
  const page = await admin(t);
  page.$("cu-username").value = "  carol ";
  page.$("cu-email").value = " ";
  page.$("cu-password").value = "long enough";
  page.$("cu-role").value = "engineer";
  await page.submit("createUserForm");
  assert.deepEqual(page.sent("POST", "/v1/admin/users"), [
    {
      username: "carol",
      email: null,
      password: "long enough",
      role: "engineer",
    },
  ]);
  assert.deepEqual(page.message(), ["User created.", "small msg-success"]);
  assert.equal(page.$("cu-username").value, "");
  assert.deepEqual(
    userRows(page).map((row) => row[0]),
    ["ada", "bob <b>", "carol"],
  );
});

test("a refused account keeps the form and shows the reason", async (t) => {
  const page = await admin(t, {
    fail: { "POST /v1/admin/users": [409, "Username already exists"] },
  });
  page.$("cu-username").value = "ada";
  page.$("cu-password").value = "long enough";
  await page.submit("createUserForm");
  assert.deepEqual(page.message(), [
    "Username already exists",
    "small msg-error",
  ]);
  assert.equal(page.$("cu-username").value, "ada");
  assert.equal(userRows(page).length, 2);
});

test("saving a row sends its email, role and active state", async (t) => {
  const page = await admin(t);
  page.field("usersTable", "email", 9).value = " bob@example.org ";
  page.field("usersTable", "role", 9).value = "maintainer";
  page.field("usersTable", "active", 9).checked = true;
  await page.click(page.button("usersTable", "save-user", 9));
  assert.deepEqual(page.sent("PATCH", "/v1/admin/users/9"), [
    { role: "maintainer", is_active: true, email: "bob@example.org" },
  ]);
  assert.deepEqual(page.message(), ["User #9 updated.", "small msg-success"]);
  assert.deepEqual(userRows(page)[1].slice(1, 3), [
    "bob@example.org",
    "maintainer",
  ]);

  // Emptying the address clears it on the account.
  page.field("usersTable", "email", 9).value = "";
  await page.click(page.button("usersTable", "save-user", 9));
  assert.equal(page.sent("PATCH", "/v1/admin/users/9")[1].email, "");
});

test("a password reset asks for the new password and sends it", async (t) => {
  const page = await admin(t);
  await page.click(page.button("usersTable", "reset-password", 9));
  assert.deepEqual(page.prompts, ["Set a new password for bob <b>:"]);
  assert.deepEqual(page.sent("POST", "/v1/admin/users/9/password"), [
    { new_password: "correct horse" },
  ]);
  assert.deepEqual(page.message(), [
    "Password updated for bob <b>.",
    "small msg-success",
  ]);
});

test("a password reset left empty changes nothing", async (t) => {
  const page = await admin(t, { password: "" });
  await page.click(page.button("usersTable", "reset-password", 9));
  assert.equal(page.prompts.length, 1);
  assert.deepEqual(page.sent("POST", "/v1/admin/users/9/password"), []);
  assert.equal(page.message()[0], "");
});

test("deleting an account asks first and removes the row", async (t) => {
  const page = await admin(t);
  await page.click(page.button("usersTable", "delete-user", 9));
  assert.match(
    page.record.confirms[0],
    /^Delete user “bob <b>”\? This is permanent/,
  );
  assert.deepEqual(page.sent("DELETE", "/v1/admin/users/9"), [undefined]);
  assert.deepEqual(page.message(), [
    "User “bob <b>” deleted.",
    "small msg-success",
  ]);
  assert.deepEqual(
    userRows(page).map((row) => row[0]),
    ["ada"],
  );
});

test("declining the confirmation keeps the account", async (t) => {
  const page = await admin(t, { confirm: false });
  await page.click(page.button("usersTable", "delete-user", 9));
  assert.equal(page.record.confirms.length, 1);
  assert.deepEqual(page.sent("DELETE", "/v1/admin/users/9"), []);
  assert.equal(userRows(page).length, 2);
});

test("a failed account change is reported beside the tables", async (t) => {
  const page = await admin(t, {
    fail: { "DELETE /v1/admin/users/9": [400, "Cannot delete the last admin"] },
  });
  await page.click(page.button("usersTable", "delete-user", 9));
  assert.deepEqual(page.message(), [
    "Cannot delete the last admin",
    "small msg-error",
  ]);
  assert.equal(userRows(page).length, 2);
});

test("an account's groups and direct permissions are edited in place", async (t) => {
  const page = await admin(t);
  await page.click(page.button("usersTable", "edit-user-access", 9));
  const boxes = () =>
    [...page.$("usersTable").querySelectorAll("input[data-kind]")].map(
      (box) => [
        box.dataset.kind,
        box.value,
        box.checked,
        box.parentElement.textContent.trim(),
      ],
    );
  assert.deepEqual(boxes(), [
    ["group", "4", true, "Reviewers (engineer)"],
    ["group", "5", false, "Guests"],
    ["perm", "21", false, "projects.write — Edit projects"],
    ["perm", "22", true, "frameworks.write"],
  ]);
  assert.match(page.$("usersTable").textContent, /Edit access for user #9/);

  const [reviewers, guests, write] = page
    .$("usersTable")
    .querySelectorAll("input[data-kind]");
  reviewers.checked = false;
  guests.checked = true;
  write.checked = true;
  await page.click(page.button("usersTable", "save-user-access", 9));
  assert.deepEqual(page.sent("PUT", "/v1/admin/users/9/access"), [
    { group_ids: [5], permission_ids: [21, 22] },
  ]);
  assert.deepEqual(page.message(), [
    "Access updated for user #9.",
    "small msg-success",
  ]);
  assert.equal(page.$("usersTable").querySelector("input[data-kind]"), null);
});

test("closing the access editor leaves the account as it was", async (t) => {
  const page = await admin(t);
  await page.click(page.button("usersTable", "edit-user-access", 9));
  assert.ok(page.$("usersTable").querySelector("input[data-kind]"));
  await page.click(page.button("usersTable", "cancel-user-access"));
  assert.equal(page.$("usersTable").querySelector("input[data-kind]"), null);
  assert.deepEqual(page.sent("PUT", "/v1/admin/users/9/access"), []);
});

test("groups are listed with their role and counts", async (t) => {
  const page = await admin(t);
  const rows = [...page.$("groupsTable").querySelectorAll("tbody tr")]
    .filter((row) => row.children.length > 1)
    .map((row) => [
      row.children[0].textContent,
      row.querySelector('[data-field="group-name"]').value,
      row.querySelector('[data-field="group-description"]').value,
      row.querySelector('[data-field="group-role"]').value,
      row.children[4].textContent,
      row.children[5].textContent,
    ]);
  assert.deepEqual(rows, [
    ["Reviewers", "Reviewers", "Second pair of eyes", "engineer", "2", "1"],
    ["Guests", "Guests", "", "", "0", "0"],
  ]);
});

test("creating a group sends its name and optional role", async (t) => {
  const page = await admin(t);
  page.$("cg-name").value = " Auditors ";
  page.$("cg-role").value = "";
  await page.submit("createGroupForm");
  assert.deepEqual(page.sent("POST", "/v1/admin/groups"), [
    { name: "Auditors", role: null },
  ]);
  assert.deepEqual(page.message(), ["Group created.", "small msg-success"]);
  assert.equal(page.$("cg-name").value, "");
  assert.equal(page.field("groupsTable", "group-name", 31).value, "Auditors");
});

test("a refused group shows the reason", async (t) => {
  const page = await admin(t, {
    fail: { "POST /v1/admin/groups": [409, "Group already exists"] },
  });
  page.$("cg-name").value = "Guests";
  await page.submit("createGroupForm");
  assert.deepEqual(page.message(), ["Group already exists", "small msg-error"]);
});

test("saving a group sends its name, description and role", async (t) => {
  const page = await admin(t);
  page.field("groupsTable", "group-name", 5).value = " Visitors ";
  page.field("groupsTable", "group-description", 5).value = " Read only ";
  page.field("groupsTable", "group-role", 5).value = "viewer";
  await page.click(page.button("groupsTable", "save-group", 5));
  page.field("groupsTable", "group-description", 4).value = "";
  page.field("groupsTable", "group-role", 4).value = "";
  await page.click(page.button("groupsTable", "save-group", 4));
  assert.deepEqual(page.sent("PATCH", "/v1/admin/groups/5"), [
    { name: "Visitors", description: "Read only", role: "viewer" },
  ]);
  assert.deepEqual(page.sent("PATCH", "/v1/admin/groups/4"), [
    { name: "Reviewers", description: null, role: null },
  ]);
  assert.deepEqual(page.message(), ["Group #4 updated.", "small msg-success"]);
});

test("deleting a group asks first, and a decline keeps it", async (t) => {
  const kept = await admin(t, { confirm: false });
  await kept.click(kept.button("groupsTable", "delete-group", 4));
  assert.deepEqual(kept.sent("DELETE", "/v1/admin/groups/4"), []);

  const page = await admin(t);
  await page.click(page.button("groupsTable", "delete-group", 4));
  assert.match(
    page.record.confirms[0],
    /^Delete group “Reviewers”\? This is permanent/,
  );
  assert.deepEqual(page.sent("DELETE", "/v1/admin/groups/4"), [undefined]);
  assert.deepEqual(page.message(), [
    "Group “Reviewers” deleted.",
    "small msg-success",
  ]);
  assert.equal(page.field("groupsTable", "group-name", 4), null);
});

test("a group's permissions are edited in place", async (t) => {
  const page = await admin(t);
  await page.click(page.button("groupsTable", "edit-group-perms", 4));
  const boxes = [...page.$("groupsTable").querySelectorAll("input[data-kind]")];
  assert.deepEqual(
    boxes.map((box) => [box.value, box.checked]),
    [
      ["21", true],
      ["22", false],
    ],
  );
  boxes[1].checked = true;
  await page.click(page.button("groupsTable", "save-group-perms", 4));
  assert.deepEqual(page.sent("PUT", "/v1/admin/groups/4/permissions"), [
    { permission_ids: [21, 22] },
  ]);
  assert.deepEqual(page.message(), [
    "Permissions updated for group #4.",
    "small msg-success",
  ]);
  assert.equal(page.$("groupsTable").querySelector("input[data-kind]"), null);

  await page.click(page.button("groupsTable", "edit-group-perms", 5));
  await page.click(page.button("groupsTable", "cancel-group-perms"));
  assert.equal(page.$("groupsTable").querySelector("input[data-kind]"), null);
  assert.deepEqual(page.sent("PUT", "/v1/admin/groups/5/permissions"), []);
});

test("a failed group change is reported", async (t) => {
  const page = await admin(t, {
    fail: { "PATCH /v1/admin/groups/4": [409, "Name is taken"] },
  });
  await page.click(page.button("groupsTable", "save-group", 4));
  assert.deepEqual(page.message(), ["Name is taken", "small msg-error"]);
});

test("accounts that fail to load are reported and the other tabs still fill", async (t) => {
  const page = await admin(t, {
    fail: { "GET /v1/admin/users": [500, "Database unavailable"] },
  });
  assert.deepEqual(page.message(), ["Database unavailable", "small msg-error"]);
  assert.equal(page.$("auditMsg").textContent, "Showing 1–3 of 3");
});

test("the audit trail lists requests with their outcome", async (t) => {
  const page = await admin(t, { auditTotal: 4 });
  const cells = [...page.$("auditTable").querySelectorAll("tbody tr")].map(
    (row) => [...row.children].map((cell) => cell.textContent.trim()),
  );
  assert.deepEqual(cells[0], [
    local("2026-03-04T10:00:00"),
    "anonymous",
    "GET",
    "/v1/projects/0?q=<x>",
    "200",
    "— ms",
    "—",
    "—",
  ]);
  assert.deepEqual(cells[1].slice(1), [
    "ada",
    "GET",
    "/v1/projects/1",
    "302",
    "12 ms",
    "10.0.0.1",
    "curl/8",
  ]);
  assert.deepEqual(
    [...page.$("auditTable").querySelectorAll("td:nth-child(5) .badge")].map(
      (badge) => badge.className.replace("badge text-bg-", ""),
    ),
    ["success", "info", "warning", "danger"],
  );
  assert.equal(page.$("auditMsg").textContent, "Showing 1–4 of 4");
  assert.equal(page.$("auditPrevBtn").disabled, true);
  assert.equal(page.$("auditNextBtn").disabled, true);
});

test("an empty audit trail says so", async (t) => {
  const page = await admin(t, { auditTotal: 0 });
  assert.deepEqual(page.texts("#auditTable tbody td"), [
    "No audit entries found.",
  ]);
  assert.equal(page.$("auditMsg").textContent, "Showing 0–0 of 0");
});

const auditQueries = (page, route = "/v1/admin/audit") =>
  page.requests
    .filter(([, path]) => path.startsWith(`${route}?`))
    .map(([, path]) =>
      Object.fromEntries(new URLSearchParams(path.split("?")[1])),
    );

test("the audit trail pages forwards and back, and filters start again from the first page", async (t) => {
  const page = await admin(t, { auditTotal: 120 });
  assert.equal(page.$("auditMsg").textContent, "Showing 1–50 of 120");
  assert.equal(page.$("auditNextBtn").disabled, false);

  await page.click("auditNextBtn");
  await page.click("auditNextBtn");
  assert.equal(page.$("auditMsg").textContent, "Showing 101–120 of 120");
  assert.equal(page.$("auditNextBtn").disabled, true);
  assert.equal(page.$("auditPrevBtn").disabled, false);

  await page.click("auditPrevBtn");
  assert.equal(page.$("auditMsg").textContent, "Showing 51–100 of 120");

  page.$("audit-username").value = " ada ";
  page.$("audit-method").value = "POST";
  page.$("audit-status-min").value = "400";
  await page.submit("auditFilters");
  await page.click("refreshAuditBtn");
  assert.deepEqual(auditQueries(page), [
    { limit: "50", offset: "0" },
    { limit: "50", offset: "50" },
    { limit: "50", offset: "100" },
    { limit: "50", offset: "50" },
    {
      username: "ada",
      method: "POST",
      status_min: "400",
      limit: "50",
      offset: "0",
    },
    {
      username: "ada",
      method: "POST",
      status_min: "400",
      limit: "50",
      offset: "0",
    },
  ]);
});

test("stepping back from the first audit page asks for nothing", async (t) => {
  const page = await admin(t);
  page.$("auditPrevBtn").disabled = false;
  await page.click("auditPrevBtn");
  assert.equal(auditQueries(page).length, 1);
});

test("a failed audit request leaves the page that was showing", async (t) => {
  const page = await admin(t, { auditTotal: 120 });
  await page.click("auditNextBtn");
  const shown = page.texts("#auditTable tbody code");
  page.world.fail["GET /v1/admin/audit"] = [500, "Audit store offline"];
  for (const step of [
    () => page.click("refreshAuditBtn"),
    () => page.click("auditNextBtn"),
    () => page.click("auditPrevBtn"),
    () => page.submit("auditFilters"),
  ]) {
    page.$("auditMsg").textContent = "";
    await step();
    assert.equal(page.$("auditMsg").textContent, "Audit store offline");
    assert.deepEqual(page.texts("#auditTable tbody code"), shown);
  }
  // The pager still stands on the second page: back goes to the first.
  page.world.fail = {};
  await page.click("auditPrevBtn");
  assert.equal(page.$("auditMsg").textContent, "Showing 1–50 of 120");
});

test("the changelog lists changes and pages like the audit trail", async (t) => {
  const page = await admin(t, { changelogTotal: 70 });
  assert.equal(page.$("entityChangelogMsg").textContent, "Showing 1–50 of 70");
  assert.equal(
    page.texts("#entityChangelogList .card .fw-semibold")[0],
    "Change 0",
  );
  assert.deepEqual(
    page.texts("#entityChangelogList .card:first-child tbody td"),
    ["Name", "Old", "New"],
  );
  await page.click("entityChangelogNextBtn");
  assert.equal(page.$("entityChangelogMsg").textContent, "Showing 51–70 of 70");
  assert.equal(page.$("entityChangelogNextBtn").disabled, true);
  await page.click("entityChangelogPrevBtn");
  page.$("entity-type").value = "project";
  page.$("entity-q").value = "wallet";
  await page.submit("entityChangelogFilters");
  await page.click("refreshEntityChangelogBtn");
  assert.deepEqual(auditQueries(page, "/v1/admin/entity-changelog"), [
    { limit: "50", offset: "0" },
    { limit: "50", offset: "50" },
    { limit: "50", offset: "0" },
    { entity_type: "project", q: "wallet", limit: "50", offset: "0" },
    { entity_type: "project", q: "wallet", limit: "50", offset: "0" },
  ]);
});

test("an empty or failing changelog says so", async (t) => {
  const page = await admin(t, { changelogTotal: 0 });
  assert.deepEqual(page.texts("#entityChangelogList"), [
    "No entity changelog entries found.",
  ]);
  page.world.fail["GET /v1/admin/entity-changelog"] = [
    500,
    "Changelog offline",
  ];
  for (const step of [
    () => page.click("refreshEntityChangelogBtn"),
    () => page.submit("entityChangelogFilters"),
  ]) {
    page.$("entityChangelogMsg").textContent = "";
    await step();
    assert.equal(page.$("entityChangelogMsg").textContent, "Changelog offline");
  }
});

test("a failed changelog request leaves the page that was showing", async (t) => {
  const page = await admin(t, { changelogTotal: 120 });
  await page.click("entityChangelogNextBtn");
  const shown = page.texts("#entityChangelogList .card .fw-semibold");
  assert.equal(shown[0], "Change 50");
  page.world.fail["GET /v1/admin/entity-changelog"] = [
    500,
    "Changelog offline",
  ];
  for (const id of ["entityChangelogNextBtn", "entityChangelogPrevBtn"]) {
    page.$("entityChangelogMsg").textContent = "";
    await page.click(id);
    assert.equal(page.$("entityChangelogMsg").textContent, "Changelog offline");
    assert.deepEqual(
      page.texts("#entityChangelogList .card .fw-semibold"),
      shown,
    );
  }
  page.world.fail = {};
  await page.click("entityChangelogNextBtn");
  assert.equal(
    page.$("entityChangelogMsg").textContent,
    "Showing 101–120 of 120",
  );
});

test("the address opens the matching tab and the changelog view", async (t) => {
  const page = await admin(t, { hash: "#changelog" });
  assert.deepEqual(page.record.tabs, ["tab-audit"]);
  assert.equal(page.$("auditView").hidden, true);
  assert.equal(page.$("changelogView").hidden, false);
  assert.equal(page.$("subtab-changelog").classList.contains("active"), true);
  assert.equal(page.$("subtab-audit").classList.contains("active"), false);

  await page.click("subtab-audit");
  assert.equal(page.$("auditView").hidden, false);
  assert.equal(page.$("changelogView").hidden, true);
  await page.click("subtab-changelog");
  assert.equal(page.$("changelogView").hidden, false);

  page.window.location.hash = "#groups";
  await page.wait();
  assert.deepEqual(page.record.tabs, ["tab-audit", "tab-access"]);
});

test("showing a tab records it in the address, and unknown addresses open nothing", async (t) => {
  const page = await admin(t, { hash: "#nowhere" });
  assert.deepEqual(page.record.tabs, []);
  page
    .$("tab-audit")
    .dispatchEvent(new page.window.Event("shown.bs.tab", { bubbles: true }));
  assert.equal(page.window.location.hash, "#audit");
  // Tabs without an address of their own leave it alone.
  page
    .$("tab-mail")
    .dispatchEvent(new page.window.Event("shown.bs.tab", { bubbles: true }));
  assert.equal(page.window.location.hash, "#audit");
});

const ORGS = [
  {
    id: 50,
    name: "Acme <Labs>",
    description: "Makers",
    website: "https://acme.example/",
    project_count: 2,
  },
  {
    id: 51,
    name: "Shady",
    description: null,
    website: "javascript:alert(1)",
    project_count: 0,
  },
  { id: 52, name: "Quiet", description: null, website: null, project_count: 1 },
];

test("organisations are listed, and only web addresses become links", async (t) => {
  const page = await admin(t, { organisations: ORGS });
  assert.deepEqual(page.texts("#orgList .fw-bold"), [
    "Acme <Labs>",
    "Shady",
    "Quiet",
  ]);
  assert.deepEqual(
    [...page.$("orgList").querySelectorAll("a")].map((a) => [
      a.getAttribute("href"),
      a.rel,
    ]),
    [["https://acme.example/", "noopener noreferrer"]],
  );
  assert.match(page.$("orgList").textContent, /javascript:alert\(1\)/);
  assert.match(page.$("orgList").textContent, /· 2 project\(s\)/);
  assert.equal(page.$("orgMsg").textContent, "");
});

test("an installation without organisations explains where they come from", async (t) => {
  const page = await admin(t);
  assert.match(page.$("orgList").textContent, /^No organisations yet\./);
});

test("a new organisation is created from the form", async (t) => {
  const page = await admin(t);
  await page.click("orgCreateBtn");
  assert.equal(page.$("orgForm").classList.contains("d-none"), false);

  await page.submit("orgForm");
  assert.equal(page.$("orgMsg").textContent, "Name is required.");
  assert.deepEqual(page.sent("POST", "/v1/admin/organisations"), []);

  page.$("org-name").value = " Acme ";
  page.$("org-site").value = " https://acme.example ";
  await page.submit("orgForm");
  assert.deepEqual(page.sent("POST", "/v1/admin/organisations"), [
    { name: "Acme", description: null, website: "https://acme.example" },
  ]);
  assert.deepEqual(page.message(), [
    "Organisation saved.",
    "small msg-success",
  ]);
  assert.equal(page.$("orgForm").classList.contains("d-none"), true);
  assert.deepEqual(page.texts("#orgList .fw-bold"), ["Acme"]);
});

test("editing an organisation fills the form and saves to that organisation", async (t) => {
  const page = await admin(t, { organisations: ORGS });
  await page.click(page.$("orgList").querySelector('[data-org-edit="50"]'));
  assert.deepEqual(
    ["org-name", "org-desc", "org-site"].map((id) => page.$(id).value),
    ["Acme <Labs>", "Makers", "https://acme.example/"],
  );
  page.$("org-desc").value = "";
  await page.submit("orgForm");
  assert.deepEqual(page.sent("PATCH", "/v1/admin/organisations/50"), [
    {
      name: "Acme <Labs>",
      description: null,
      website: "https://acme.example/",
    },
  ]);

  // Cancelling an edit leaves the next save as a new organisation.
  await page.click(page.$("orgList").querySelector('[data-org-edit="52"]'));
  await page.click("orgCancelBtn");
  assert.equal(page.$("orgForm").classList.contains("d-none"), true);
  await page.click("orgCreateBtn");
  assert.equal(page.$("org-name").value, "");
  page.$("org-name").value = "Fresh";
  await page.submit("orgForm");
  assert.equal(page.sent("POST", "/v1/admin/organisations").length, 1);
});

test("organisation failures are shown beside the form", async (t) => {
  const page = await admin(t, {
    fail: {
      "POST /v1/admin/organisations": [409, "Organisation already exists"],
    },
  });
  await page.click("orgCreateBtn");
  page.$("org-name").value = "Acme";
  await page.submit("orgForm");
  assert.equal(page.$("orgMsg").textContent, "Organisation already exists");
  assert.equal(page.$("orgForm").classList.contains("d-none"), false);

  const broken = await admin(t, {
    fail: { "GET /v1/organisations": [500, "No organisations for you"] },
  });
  assert.equal(broken.$("orgMsg").textContent, "No organisations for you");
});

test("the outbox shows each message with its delivery state", async (t) => {
  const page = await admin(t, {
    outbox: {
      pending: 1,
      failed: 1,
      notifications: [
        {
          created_at: "2026-03-04T10:00:00",
          recipient: "ada@example.org",
          subject: "Wallet Kit 2.0.0 <released>",
          status: "sent",
          attempts: 1,
          last_error: null,
        },
        {
          created_at: "2026-03-04T11:00:00",
          recipient: "bob@example.org",
          subject: "Welcome",
          status: "failed",
          attempts: 3,
          last_error: "Connection refused",
        },
        {
          created_at: null,
          recipient: "carol@example.org",
          subject: "Welcome",
          status: "pending",
          attempts: 0,
          last_error: null,
        },
      ],
    },
  });
  assert.equal(
    page.$("mailSummary").textContent,
    "1 pending · 1 failed · 3 rows shown",
  );
  const rows = [...page.$("mailTable").querySelectorAll("tbody tr")].map(
    (row) => [...row.children].map((cell) => cell.textContent.trim()),
  );
  assert.deepEqual(rows, [
    [
      local("2026-03-04T10:00:00"),
      "ada@example.org",
      "Wallet Kit 2.0.0 <released>",
      "sent",
      "1",
      "",
    ],
    [
      local("2026-03-04T11:00:00"),
      "bob@example.org",
      "Welcome",
      "failed",
      "3",
      "Connection refused",
    ],
    ["—", "carol@example.org", "Welcome", "pending", "0", ""],
  ]);
  assert.deepEqual(
    [...page.$("mailTable").querySelectorAll(".badge")].map((badge) =>
      badge.className.replace("badge text-bg-", ""),
    ),
    ["success", "danger", "secondary"],
  );
});

test("an empty outbox says so, and refreshing reports a failure", async (t) => {
  const page = await admin(t);
  assert.equal(
    page.$("mailSummary").textContent,
    "0 pending · 0 failed · 0 rows shown",
  );
  assert.match(page.$("mailTable").textContent, /^Nothing queued\./);
  page.world.fail["GET /v1/admin/notifications"] = [500, "Outbox offline"];
  await page.click("refreshMailBtn");
  assert.equal(page.$("mailSummary").textContent, "Outbox offline");
});

test("ingesting all release feeds reports what was queued", async (t) => {
  const page = await admin(t);
  await page.click("discoverAllBtn");
  assert.deepEqual(page.sent("POST", "/v1/admin/release-feeds/discover-all"), [
    undefined,
  ]);
  assert.equal(
    page.$("feedMsg").textContent,
    "Queued 3 release feed discovery task(s); pending outbox rows: 2.",
  );
  assert.deepEqual(page.toasts(), [["success", "Queued 3 feed(s)."]]);
  assert.equal(page.$("discoverAllBtn").disabled, false);
});

test("a failed ingestion is reported and the button comes back", async (t) => {
  const page = await admin(t, {
    fail: {
      "POST /v1/admin/release-feeds/discover-all": [503, "Queue unavailable"],
    },
  });
  await page.click("discoverAllBtn");
  assert.deepEqual(page.toasts(), [["danger", "Queue unavailable"]]);
  assert.equal(page.$("discoverAllBtn").disabled, false);
});
