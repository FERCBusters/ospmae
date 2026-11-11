// The account page: profile, preferences and category colours,
// subscriptions, the asker's questions, shortcuts, and the password tab.
import test from "node:test";
import assert from "node:assert/strict";
import { account, appPage } from "./support/app-page.mjs";

const local = (text) => new Date(`${text}Z`).toLocaleString();

const FRAMEWORKS = [
  { id: 3, machine_name: "tax", display_name: "Taxonomy" },
  { id: 4, machine_name: "alt", display_name: "" },
];
const NODES = {
  3: [
    { id: 30, key: "root", display_name: "Root", parent_id: null, level: 0 },
    { id: 32, key: "wallet", display_name: "Wallet", parent_id: 30, level: 1 },
    {
      id: 31,
      key: "identity",
      display_name: "Identity",
      parent_id: 30,
      level: 1,
    },
    { id: 33, key: "keys", display_name: "Keys", parent_id: 32, level: 2 },
  ],
  4: [],
};
const SUBSCRIPTIONS = [
  {
    project_id: 5,
    project_name: "Wallet <Kit>",
    organisation: "Acme",
    project_type: "library",
    notify_new_versions: true,
    notify_questions: false,
  },
  { project_id: 6, project_machine_name: "other", notify_questions: true },
  { project_id: 8, notify_new_versions: false },
];

function local_account(role = "engineer", extra = {}) {
  return account(role, {
    email: "ada@example.org",
    auth_method: "local",
    password_features_enabled: true,
    ...extra,
  });
}

function accountPage(t, options = {}) {
  const world = {
    preferences: { ...options.preferences },
    shortcuts: structuredClone(options.shortcuts || []),
    subscriptions: structuredClone(options.subscriptions || []),
    fail: { ...options.fail },
  };
  const themes = [];
  const api = (method, path, body) => {
    const failure = world.fail[`${method} ${path}`];
    if (failure) return [failure[0], { detail: failure[1] }];
    if (path === "/v1/frameworks")
      return [200, { items: options.frameworks || FRAMEWORKS }];
    const nodes = path.match(/^\/v1\/frameworks\/(\d+)\/nodes$/);
    if (nodes) return [200, { tree: [], items: NODES[nodes[1]] }];
    if (path === "/v1/me/preferences") {
      if (method === "PUT") Object.assign(world.preferences, body);
      return [200, world.preferences];
    }
    if (path === "/v1/me/sso-emails")
      return [200, { smtp_configured: false, addresses: [] }];
    if (path === "/v1/me/mfa")
      return [
        200,
        options.mfa || {
          local_enabled: true,
          enabled: false,
          totp: false,
          credentials: [],
        },
      ];
    if (path === "/v1/me/notifications") return [200, options.mail || []];
    if (path === "/v1/me/subscriptions")
      return [200, { items: world.subscriptions }];
    const subscription = path.match(/^\/v1\/projects\/(\d+)\/subscription$/);
    if (subscription)
      return [
        200,
        {
          subscribed: body.notify_new_versions || body.notify_questions,
          ...body,
        },
      ];
    if (path === "/v1/me/shortcuts" && method === "GET")
      return [
        200,
        options.shortcutsAsList ? world.shortcuts : { items: world.shortcuts },
      ];
    if (path === "/v1/me/shortcuts" && method === "POST") {
      world.shortcuts.push({ id: 70 + world.shortcuts.length, ...body });
      return [201, {}];
    }
    const shortcut = path.match(/^\/v1\/me\/shortcuts\/(.+)$/);
    if (shortcut) {
      world.shortcuts = world.shortcuts.filter(
        (s) => String(s.id) !== decodeURIComponent(shortcut[1]),
      );
      return [200, {}];
    }
    if (path === "/v1/me/questions")
      return [200, { items: options.questions || [] }];
    return null;
  };
  return appPage(t, "account.html", "pages/account.js", {
    me: local_account(),
    ...options,
    api,
    setup(window) {
      if (options.designSystem) {
        window.mospUi.THEMES = [
          { id: "ink", name: "Ink" },
          { id: "paper", name: "Paper" },
        ];
        window.mospUi.applyTheme = (id) => themes.push(id);
      }
    },
  }).then((page) => ({
    ...page,
    world,
    themes,
    async submit(form) {
      page
        .$(form)
        .dispatchEvent(
          new page.window.Event("submit", { bubbles: true, cancelable: true }),
        );
      await page.wait();
    },
    colours: () =>
      [...page.doc.querySelectorAll("#colorRows [data-full-key]")].map(
        (row) => [
          row.dataset.fullKey,
          row.querySelector(".fw-semibold").textContent,
          row.querySelector("input").value,
          row.querySelector(".badge").textContent,
        ],
      ),
    subscriptionRows: () =>
      [
        ...page.doc.querySelectorAll("#subscriptionsList [data-project-id]"),
      ].map((row) => [
        row.querySelector("a").textContent,
        row.querySelector("a").getAttribute("href"),
        row.querySelector(".text-muted")?.textContent || "",
        row.querySelector('[data-sub-field="notify_new_versions"]').checked,
        row.querySelector('[data-sub-field="notify_questions"]').checked,
        row.querySelector("[data-sub-status]").textContent,
      ]),
  }));
}

test("the profile shows who is signed in and their role", async (t) => {
  const page = await accountPage(t);
  assert.deepEqual(page.errors, []);
  assert.deepEqual(
    ["profileUser", "profileUsername", "profileRole", "profileEmail"].map(
      (id) => page.$(id).textContent,
    ),
    ["ada", "ada", "engineer", "ada@example.org"],
  );
  const bare = await accountPage(t, {
    me: local_account("viewer", { email: null, effective_role: undefined }),
  });
  assert.equal(bare.$("profileEmail").textContent, "Not set");
  assert.equal(bare.$("profileRole").textContent, "viewer");
});

test("a signed-out visitor is sent to sign in", async (t) => {
  const page = await accountPage(t, { me: null });
  assert.equal(page.navigations(), 1);
  assert.equal(page.$("profileUser").textContent, "");
});

test("the address opens the matching tab, and showing a tab records it", async (t) => {
  const page = await accountPage(t, { hash: "#Shortcuts" });
  assert.deepEqual(page.record.tabs, ["shortcuts", "shortcuts"]);
  page
    .$("tabBtnPreferences")
    .dispatchEvent(new page.window.Event("shown.bs.tab", { bubbles: true }));
  assert.equal(page.window.location.hash, "#preferences");

  const unknown = await accountPage(t, { hash: "#nowhere" });
  assert.deepEqual(unknown.record.tabs, []);
});

test("start pages are offered by role and the saved one is selected", async (t) => {
  const options = (page) =>
    [...page.$("defaultStartPage").options].map((option) => option.value);
  const engineer = await accountPage(t, {
    preferences: { default_start_page: "/admin.html" },
  });
  assert.deepEqual(options(engineer), [
    "/index.html",
    "/manifests.html",
    "/account.html",
  ]);
  // A saved page this role may not open falls back to the first offered.
  assert.equal(engineer.$("defaultStartPage").value, "/index.html");

  const admin = await accountPage(t, {
    me: local_account("admin"),
    preferences: { default_start_page: "/admin.html" },
  });
  assert.deepEqual(options(admin), [
    "/index.html",
    "/manifests.html",
    "/framework-manage.html",
    "/account.html",
    "/admin.html",
  ]);
  assert.equal(admin.$("defaultStartPage").value, "/admin.html");

  const frameworks = await accountPage(t, {
    me: local_account("framework_admin"),
  });
  assert.equal(options(frameworks).includes("/framework-manage.html"), true);
  assert.equal(options(frameworks).includes("/admin.html"), false);
});

test("changing the start page saves it with the current preferences", async (t) => {
  const page = await accountPage(t, {
    preferences: { node_colors: { "tax:wallet": "#112233" } },
  });
  await page.choose("defaultStartPage", "/manifests.html");
  const sent = page.sent("PUT", "/v1/me/preferences");
  assert.equal(sent.length, 1);
  assert.equal(sent[0].default_start_page, "/manifests.html");
  assert.deepEqual(sent[0].node_colors, { "tax:wallet": "#112233" });
  assert.deepEqual(page.toasts(), [["info", "Preferences saved."]]);

  page.world.fail["PUT /v1/me/preferences"] = [500, "Preferences unavailable"];
  await page.choose("defaultStartPage", "/account.html");
  assert.deepEqual(page.toasts().at(-1), ["danger", "Preferences unavailable"]);
});

test("the sticky and auto-apply switches show and save their preference", async (t) => {
  const page = await accountPage(t, {
    preferences: { sticky_enabled: false, auto_apply_enabled: false },
  });
  assert.equal(page.$("prefSticky").checked, false);
  assert.equal(page.$("prefAutoApply").checked, false);
  page.$("prefSticky").checked = true;
  await page.choose("prefSticky", "on");
  page.$("prefAutoApply").checked = true;
  await page.choose("prefAutoApply", "on");
  assert.deepEqual(page.sent("PUT", "/v1/me/preferences"), [
    { sticky_enabled: true },
    { auto_apply_enabled: true },
  ]);
  assert.deepEqual(page.toasts(), [
    ["success", "Sticky preference saved."],
    ["success", "Auto-apply preference saved."],
  ]);

  page.world.fail["PUT /v1/me/preferences"] = [500, "Preferences unavailable"];
  await page.choose("prefSticky", "on");
  await page.choose("prefAutoApply", "on");
  assert.deepEqual(page.toasts().slice(2), [
    ["danger", "Preferences unavailable"],
    ["danger", "Preferences unavailable"],
  ]);
});

test("themes come from the design system and apply as they are chosen", async (t) => {
  const page = await accountPage(t, {
    designSystem: true,
    preferences: { theme: "paper" },
  });
  assert.deepEqual(
    [...page.$("prefTheme").options].map((o) => [o.value, o.textContent]),
    [
      ["ink", "Ink"],
      ["paper", "Paper"],
    ],
  );
  assert.equal(page.$("prefTheme").value, "paper");
  await page.choose("prefTheme", "ink");
  assert.equal(page.themes.at(-1), "ink");
  assert.deepEqual(page.sent("PUT", "/v1/me/preferences"), [{ theme: "ink" }]);
  assert.deepEqual(page.toasts(), [["success", "Theme updated."]]);

  page.world.fail["PUT /v1/me/preferences"] = [500, "Preferences unavailable"];
  await page.choose("prefTheme", "paper");
  assert.deepEqual(page.toasts().at(-1), ["danger", "Preferences unavailable"]);
});

test("a deployment's own theme list wins, and the page themes itself without the design system", async (t) => {
  const page = await accountPage(t, {
    me: local_account("engineer", {
      available_themes: [
        { id: "ink", name: "Ink" },
        { id: "dusk", name: "Dusk <dark>" },
      ],
    }),
  });
  assert.deepEqual(
    [...page.$("prefTheme").options].map((o) => o.textContent),
    ["Ink", "Dusk <dark>"],
  );
  assert.equal(page.doc.documentElement.dataset.theme, "ink");
  await page.choose("prefTheme", "dusk");
  assert.equal(page.doc.documentElement.dataset.theme, "dusk");
  assert.equal(page.window.localStorage.getItem("keen_theme"), "dusk");

  // With neither list, the one built-in theme is offered.
  const plain = await accountPage(t);
  assert.deepEqual(
    [...plain.$("prefTheme").options].map((o) => o.value),
    ["ink"],
  );
});

test("category colours list the framework's top-level categories by name", async (t) => {
  const page = await accountPage(t, {
    preferences: { node_colors: { "tax:wallet": "#112233" } },
  });
  assert.deepEqual(
    [...page.$("frameworkSelect").options].map((o) => [o.value, o.textContent]),
    [
      ["tax", "Taxonomy"],
      ["alt", "alt"],
    ],
  );
  const colours = page.colours();
  assert.deepEqual(
    colours.map((row) => [row[0], row[1], row[3]]),
    [
      ["tax:identity", "Identity", "default"],
      ["tax:wallet", "Wallet", "custom"],
    ],
  );
  assert.equal(colours[1][2], "#112233");
  assert.match(colours[0][2], /^#[0-9a-f]{6}$/);
  assert.match(
    page.doc.querySelector('[data-full-key="tax:identity"] .text-muted')
      .textContent,
    /^Key: tax:identity \(default #[0-9a-f]{6}\)$/,
  );
});

test("colours are picked, reset one by one, and saved together", async (t) => {
  const page = await accountPage(t, {
    preferences: { node_colors: { "tax:wallet": "#112233" } },
  });
  const row = (key) => page.doc.querySelector(`[data-full-key="${key}"]`);
  await page.type(row("tax:identity").querySelector("input"), "#abcdef");
  await page.click(row("tax:wallet").querySelector('[data-action="reset"]'));
  assert.equal(page.colours()[1][3], "default");
  assert.notEqual(page.colours()[1][2], "#112233");
  assert.equal(page.colours()[0][3], "custom");

  await page.click("saveColorsBtn");
  assert.deepEqual(page.sent("PUT", "/v1/me/preferences").at(-1).node_colors, {
    "tax:identity": "#abcdef",
  });
  assert.deepEqual(page.toasts(), [["info", "Preferences saved."]]);

  page.world.fail["PUT /v1/me/preferences"] = [500, "Preferences unavailable"];
  await page.click("saveColorsBtn");
  assert.deepEqual(page.toasts().at(-1), ["danger", "Preferences unavailable"]);
});

test("resetting all colours asks first", async (t) => {
  const declined = await accountPage(t, {
    confirm: false,
    preferences: { node_colors: { "tax:wallet": "#112233" } },
  });
  await declined.click("resetColorsBtn");
  assert.deepEqual(declined.record.confirms, ["Reset all custom colours?"]);
  assert.deepEqual(declined.sent("PUT", "/v1/me/preferences"), []);
  assert.equal(declined.colours()[1][3], "custom");

  const page = await accountPage(t, {
    preferences: { node_colors: { "tax:wallet": "#112233" } },
  });
  const untouched = page.colours()[0][2];
  await page.click("resetColorsBtn");
  assert.deepEqual(page.sent("PUT", "/v1/me/preferences")[0].node_colors, {});
  assert.deepEqual(page.colours()[1].slice(2), [
    page.window.OSPMAE.defaultNodeColor("tax:wallet"),
    "default",
  ]);
  assert.equal(page.colours()[0][2], untouched);

  page.world.fail["PUT /v1/me/preferences"] = [500, "Preferences unavailable"];
  await page.click("resetColorsBtn");
  assert.deepEqual(page.toasts().at(-1), ["danger", "Preferences unavailable"]);
});

test("switching framework shows that framework's categories", async (t) => {
  const page = await accountPage(t);
  await page.choose("frameworkSelect", "alt");
  assert.equal(
    page.$("colorRows").textContent,
    "No categories found for this framework.",
  );
  page.world.fail["GET /v1/frameworks/3/nodes"] = [500, "Nodes unavailable"];
  await page.choose("frameworkSelect", "tax");
  // The categories read once are kept, so the list returns without a request.
  assert.equal(page.colours().length, 2);
});

test("a framework whose categories cannot be read is reported", async (t) => {
  const page = await accountPage(t, {
    fail: { "GET /v1/frameworks/4/nodes": [500, "Nodes unavailable"] },
  });
  await page.choose("frameworkSelect", "alt");
  assert.deepEqual(page.toasts(), [["danger", "Nodes unavailable"]]);
});

test("an installation without frameworks has no colours to set", async (t) => {
  const page = await accountPage(t, { frameworks: [] });
  assert.equal(page.$("colorRows").textContent, "No frameworks available.");
  assert.equal(page.$("frameworkSelect").options.length, 0);
});

test("subscriptions list each project with its notification switches", async (t) => {
  const page = await accountPage(t, { subscriptions: SUBSCRIPTIONS });
  assert.deepEqual(page.subscriptionRows(), [
    ["Wallet <Kit>", "/project.html?id=5", "Acme · library", true, false, ""],
    ["other", "/project.html?id=6", "", true, true, ""],
    ["Project 8", "/project.html?id=8", "", false, false, ""],
  ]);
  const none = await accountPage(t);
  assert.equal(
    none.$("subscriptionsList").textContent,
    "You are not subscribed to any projects.",
  );
});

test("a notification switch saves that project's subscription", async (t) => {
  const page = await accountPage(t, { subscriptions: SUBSCRIPTIONS });
  const box = page.$("sub_nq_5");
  box.checked = true;
  await page.choose(box, "on");
  assert.deepEqual(page.sent("POST", "/v1/projects/5/subscription"), [
    { notify_new_versions: true, notify_questions: true },
  ]);
  assert.equal(page.subscriptionRows()[0][5], "Saved.");
  assert.equal(box.disabled, false);
  assert.deepEqual(page.toasts(), [["success", "Subscription updated."]]);
});

test("switching both notifications off, or unsubscribing, removes the project", async (t) => {
  const page = await accountPage(t, { subscriptions: SUBSCRIPTIONS });
  const row = (id) =>
    page.doc.querySelector(`#subscriptionsList [data-project-id="${id}"]`);
  await page.click(row(5).querySelector('[data-action="unsubscribe"]'));
  assert.deepEqual(page.sent("POST", "/v1/projects/5/subscription"), [
    { notify_new_versions: false, notify_questions: false },
  ]);
  assert.deepEqual(
    page.subscriptionRows().map((r) => r[0]),
    ["other", "Project 8"],
  );
  page.$("sub_nq_6").checked = false;
  page.$("sub_nv_6").checked = false;
  await page.choose("sub_nv_6", "on");
  assert.deepEqual(
    page.subscriptionRows().map((r) => r[0]),
    ["Project 8"],
  );
  assert.deepEqual(page.toasts(), [
    ["success", "Unsubscribed."],
    ["success", "Unsubscribed."],
  ]);
});

test("a subscription that fails to save says so on its row", async (t) => {
  const page = await accountPage(t, {
    subscriptions: SUBSCRIPTIONS,
    fail: { "POST /v1/projects/5/subscription": [500, "Mail is switched off"] },
  });
  await page.choose("sub_nv_5", "on");
  assert.equal(page.subscriptionRows()[0][5], "Mail is switched off");
  assert.equal(page.$("sub_nv_5").disabled, false);
  assert.deepEqual(page.toasts(), [["danger", "Mail is switched off"]]);
});

test("subscriptions that fail to load are reported in place", async (t) => {
  const page = await accountPage(t, {
    fail: { "GET /v1/me/subscriptions": [500, "Subscriptions unavailable"] },
  });
  assert.equal(
    page.$("subscriptionsMsg").textContent,
    "Subscriptions unavailable",
  );
  assert.equal(
    page.$("subscriptionsList").textContent,
    "You are not subscribed to any projects.",
  );
});

const QUESTIONS = [
  {
    project_id: 5,
    project_display_name: "Wallet <Kit>",
    status: "answered",
    updated_at: "2026-03-04T10:00:00",
    posts: [
      { body: "First" },
      { body: `  Is it\n maintained? ${"x".repeat(200)}` },
    ],
  },
  {
    project_id: 6,
    status: "open",
    updated_at: "2026-03-05T10:00:00",
    posts: [],
  },
];

test("an asker's questions load when the tab is first shown", async (t) => {
  const page = await accountPage(t, { questions: QUESTIONS });
  assert.equal(page.$("questionsTabItem").hidden, false);
  assert.deepEqual(page.sent("GET", "/v1/me/questions"), []);
  page
    .$("tabBtnQuestions")
    .dispatchEvent(new page.window.Event("shown.bs.tab", { bubbles: true }));
  await page.wait();
  assert.equal(page.$("myQuestionsCount").textContent, "2");
  assert.equal(page.$("myQuestionsEmpty").hidden, true);
  assert.equal(page.$("myQuestionsTableWrap").hidden, false);
  const rows = [...page.$("myQuestionsBody").querySelectorAll("tr")].map(
    (row) => [
      ...[...row.children].slice(0, 4).map((cell) => cell.textContent),
      row.querySelector("a").getAttribute("href"),
    ],
  );
  assert.deepEqual(rows[0].slice(0, 3), [
    local("2026-03-04T10:00:00"),
    "Wallet <Kit>",
    "answered",
  ]);
  assert.equal(rows[0][3], `Is it maintained? ${"x".repeat(121)}…`);
  assert.equal(rows[0][4], "/project.html?id=5&tab=questions");
  assert.deepEqual(rows[1].slice(1), [
    "Project #6",
    "open",
    "—",
    "/project.html?id=6&tab=questions",
  ]);
});

test("no questions, and a failed refresh, each say so", async (t) => {
  const page = await accountPage(t, { hash: "#questions" });
  assert.deepEqual(page.record.tabs, ["questions"]);
  assert.equal(page.$("myQuestionsEmpty").hidden, false);
  assert.equal(page.$("myQuestionsTableWrap").hidden, true);
  page.world.fail["GET /v1/me/questions"] = [500, "Questions unavailable"];
  await page.click("myQuestionsRefreshBtn");
  assert.equal(page.$("myQuestionsStatus").hidden, false);
  assert.equal(
    page.$("myQuestionsStatus").textContent,
    "Questions unavailable",
  );
  page.world.fail = {};
  await page.click("myQuestionsRefreshBtn");
  assert.equal(page.$("myQuestionsStatus").hidden, true);
});

test("the questions tab is hidden from viewers and when the feature is off", async (t) => {
  const viewer = await accountPage(t, {
    me: local_account("viewer"),
    hash: "#questions",
  });
  assert.equal(viewer.$("questionsTabItem").hidden, true);
  assert.deepEqual(viewer.record.tabs, []);
  const off = await accountPage(t, {
    me: local_account("engineer", {
      features: { ...account().features, questions: false },
    }),
  });
  assert.equal(off.$("questionsTabItem").hidden, true);
});

const SHORTCUTS = [
  { id: 71, name: "Zebra", url: "https://example.org/z" },
  { id: 72, name: "", url: "/manifests.html?q=wallet" },
  { id: 73, name: "Broken", href: "javascript:alert(1)" },
];

test("shortcuts are listed by name, and only safe addresses become links", async (t) => {
  const page = await accountPage(t, {
    shortcuts: SHORTCUTS,
    shortcutsAsList: true,
  });
  assert.deepEqual(page.texts("#shortcutsList .fw-semibold"), [
    "Shortcut",
    "Broken",
    "Zebra",
  ]);
  assert.deepEqual(
    [...page.$("shortcutsList").querySelectorAll("a")].map((a) => [
      a.getAttribute("href"),
      a.getAttribute("target"),
    ]),
    [["https://example.org/z", "_blank"]],
  );
  assert.match(page.$("shortcutsList").textContent, /javascript:alert\(1\)/);
  const none = await accountPage(t);
  assert.equal(none.$("shortcutsList").textContent, "No shortcuts saved yet.");
});

test("a shortcut needs a name and a safe address before it is saved", async (t) => {
  const page = await accountPage(t);
  await page.click("addShortcutBtn");
  page.$("shortcutName").value = "Mine";
  page.$("shortcutUrl").value = "javascript:alert(1)";
  await page.click("addShortcutBtn");
  assert.deepEqual(page.sent("POST", "/v1/me/shortcuts"), []);
  assert.deepEqual(page.toasts(), [
    ["danger", "Please provide both a name and a URL."],
    [
      "danger",
      "Invalid or unsafe URL. Use an http(s) URL or a same-site path (starting with /).",
    ],
  ]);

  page.$("shortcutUrl").value = " https://example.org/mine ";
  page
    .$("shortcutUrl")
    .dispatchEvent(new page.window.KeyboardEvent("keydown", { key: "a" }));
  page.$("shortcutUrl").dispatchEvent(
    new page.window.KeyboardEvent("keydown", {
      key: "Enter",
      cancelable: true,
    }),
  );
  await page.wait();
  assert.deepEqual(page.sent("POST", "/v1/me/shortcuts"), [
    { name: "Mine", url: "https://example.org/mine" },
  ]);
  assert.equal(page.$("shortcutName").value, "");
  assert.equal(page.$("shortcutUrl").value, "");
  assert.deepEqual(page.texts("#shortcutsList .fw-semibold"), ["Mine"]);
  assert.deepEqual(page.toasts().at(-1), ["success", "Shortcut saved."]);
});

test("a refused shortcut is reported from the button and from Enter", async (t) => {
  const page = await accountPage(t, {
    fail: { "POST /v1/me/shortcuts": [400, "Too many shortcuts"] },
  });
  page.$("shortcutName").value = "Mine";
  page.$("shortcutUrl").value = "https://example.org/mine";
  await page.click("addShortcutBtn");
  page
    .$("shortcutUrl")
    .dispatchEvent(new page.window.KeyboardEvent("keydown", { key: "Enter" }));
  await page.wait();
  assert.deepEqual(page.toasts(), [
    ["danger", "Too many shortcuts"],
    ["danger", "Too many shortcuts"],
  ]);
  assert.equal(page.$("shortcutName").value, "Mine");
});

test("removing a shortcut asks first", async (t) => {
  const declined = await accountPage(t, {
    shortcuts: SHORTCUTS,
    confirm: false,
  });
  await declined.click(declined.doc.querySelector('[data-del="71"]'));
  assert.deepEqual(declined.record.confirms, ["Remove this shortcut?"]);
  assert.deepEqual(declined.sent("DELETE", "/v1/me/shortcuts/71"), []);

  const page = await accountPage(t, { shortcuts: SHORTCUTS });
  await page.click(page.doc.querySelector('[data-del="71"]'));
  assert.deepEqual(page.sent("DELETE", "/v1/me/shortcuts/71"), [undefined]);
  assert.deepEqual(page.texts("#shortcutsList .fw-semibold"), [
    "Shortcut",
    "Broken",
  ]);
  assert.deepEqual(page.toasts(), [["success", "Shortcut removed."]]);

  page.world.fail["DELETE /v1/me/shortcuts/72"] = [500, "Could not remove"];
  await page.click(page.doc.querySelector('[data-del="72"]'));
  assert.deepEqual(page.toasts().at(-1), ["danger", "Could not remove"]);
});

test("the password form checks its fields before sending", async (t) => {
  const page = await accountPage(t);
  assert.equal(page.$("passwordCard").classList.contains("d-none"), false);
  assert.equal(page.$("passwordUnavailableMsg").textContent, "");
  const attempt = async (current, next, again) => {
    page.$("currentPassword").value = current;
    page.$("newPassword").value = next;
    page.$("confirmPassword").value = again;
    await page.submit("changePasswordForm");
    return [page.$("passwordMsg").textContent, page.$("passwordMsg").className];
  };
  assert.deepEqual(
    await attempt("", "longer than eight", "longer than eight"),
    ["Please fill in all fields.", "small mt-2 text-danger"],
  );
  assert.equal(
    (await attempt("old", "short", "short"))[0],
    "New password must be at least 8 characters.",
  );
  assert.equal(
    (await attempt("old", "longer than eight", "different"))[0],
    "Passwords do not match.",
  );
  assert.deepEqual(page.sent("POST", "/v1/auth/change-password"), []);

  page.world.fail["POST /v1/auth/change-password"] = [
    400,
    "Current password is wrong",
  ];
  assert.deepEqual(
    await attempt("old", "longer than eight", "longer than eight"),
    ["Current password is wrong", "small mt-2 text-danger"],
  );
  assert.deepEqual(page.toasts(), [["danger", "Current password is wrong"]]);
  assert.equal(page.$("newPassword").value, "longer than eight");
});

test("accounts signed in elsewhere have no password, second factor or mail cards", async (t) => {
  const page = await accountPage(t, {
    me: local_account("engineer", { auth_method: "oidc" }),
  });
  for (const id of ["passwordCard", "mfaCard", "mailCard"])
    assert.equal(page.$(id).classList.contains("d-none"), true, id);
  assert.match(
    page.$("passwordUnavailableMsg").textContent,
    /^Password changes are only available for local accounts/,
  );
  assert.deepEqual(page.sent("GET", "/v1/me/mfa"), []);
  assert.deepEqual(page.sent("GET", "/v1/me/notifications"), []);
});

test("the second-factor summary describes the account's state", async (t) => {
  const summary = async (mfa, fail) =>
    (await accountPage(t, { mfa, fail })).$("securitySummary").textContent;
  assert.equal(
    await summary(),
    "Two-factor authentication is not configured for password sign-in.",
  );
  assert.match(
    await summary({
      local_enabled: true,
      enabled: true,
      totp: true,
      credentials: [{}, {}],
      required: true,
    }),
    /^Two-factor authentication is enabled\. Authenticator app; 2 security keys\/passkeys.* Your administrator requires a second factor\.$/,
  );
  assert.match(
    await summary({
      local_enabled: true,
      enabled: true,
      totp: false,
      credentials: [],
    }),
    /^Two-factor authentication is enabled\. 0 security keys/,
  );
  assert.equal(
    await summary(undefined, {
      "GET /v1/me/mfa": [500, "Security unavailable"],
    }),
    "Security unavailable",
  );
  const provider = await accountPage(t, { mfa: { local_enabled: false } });
  assert.match(
    provider.$("securitySummary").textContent,
    /^Password sign-in is disabled\./,
  );
  assert.equal(provider.$("securityForm").classList.contains("d-none"), true);
});

test("managing the second factor confirms the password first", async (t) => {
  const page = await accountPage(t);
  await page.submit("securityForm");
  assert.deepEqual(
    [page.$("mfaMsg").textContent, page.$("mfaMsg").className],
    ["Enter your current password.", "small mt-2 text-danger"],
  );
  assert.deepEqual(page.sent("POST", "/v1/auth/mfa/manage/start"), []);

  page.world.fail["POST /v1/auth/mfa/manage/start"] = [403, "Wrong password"];
  page.$("securityPassword").value = "guess";
  await page.submit("securityForm");
  assert.equal(page.$("mfaMsg").textContent, "Wrong password");
  assert.equal(page.$("securityPassword").value, "");
  assert.equal(page.$("manageMfaBtn").disabled, false);
  assert.equal(page.navigations(), 0);

  page.world.fail = {};
  page.$("securityPassword").value = "correct horse";
  await page.submit("securityForm");
  assert.deepEqual(page.sent("POST", "/v1/auth/mfa/manage/start").at(-1), {
    password: "correct horse",
  });
  assert.equal(page.$("securityPassword").value, "");
  assert.equal(page.navigations(), 1);
});

test("mail sent to the account is listed with its delivery state", async (t) => {
  const page = await accountPage(t, {
    mail: [
      {
        subject: "Wallet Kit <2.0.0>",
        recipient: "ada@example.org",
        status: "sent",
      },
      { subject: "Welcome", recipient: "ada@example.org", status: "failed" },
      { subject: "Reminder", recipient: "ada@example.org", status: "pending" },
    ],
  });
  assert.equal(page.$("mailCard").classList.contains("d-none"), false);
  assert.equal(page.$("mailSummary").textContent, "3 queued e-mail(s)");
  assert.deepEqual(
    [...page.$("mailList").querySelectorAll(".badge")].map((badge) => [
      badge.textContent.trim(),
      badge.className.replace("badge text-bg-", ""),
    ]),
    [
      ["sent", "success"],
      ["failed", "danger"],
      ["pending", "secondary"],
    ],
  );
  assert.match(
    page.$("mailList").textContent,
    /Wallet Kit <2\.0\.0> → ada@example\.org/,
  );

  const none = await accountPage(t);
  assert.match(
    none.$("mailSummary").textContent,
    /^Nothing has been emailed to this account/,
  );
  const failed = await accountPage(t, {
    fail: { "GET /v1/me/notifications": [500, "Mail history unavailable"] },
  });
  assert.equal(failed.$("mailSummary").textContent, "Mail history unavailable");
});

test("a page that cannot load its shortcuts says why", async (t) => {
  const page = await accountPage(t, {
    fail: { "GET /v1/me/shortcuts": [500, "Shortcuts unavailable"] },
  });
  assert.deepEqual(page.toasts(), [["danger", "Shortcuts unavailable"]]);
});
