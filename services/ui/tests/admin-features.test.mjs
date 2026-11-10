// The Features tab on the Administration page: switches, the deployment
// ceiling, saving against a revision, and recovering from a refused save.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

const ITEMS = [
  {
    key: "frameworks",
    label: "Frameworks and capability mapping",
    parent: null,
  },
  { key: "manifests", label: "Manifests", parent: null },
  { key: "release_feed", label: "Release feeds", parent: "manifests" },
];

function config(overrides = {}) {
  const on = { frameworks: true, manifests: true, release_feed: true };
  return {
    version: 3,
    items: ITEMS,
    configured: { ...on },
    enabled: { ...on },
    deployment: { ...on },
    ...overrides,
  };
}

async function features(t, { responses, isAdmin = true, hash = "#features" }) {
  const calls = [];
  const applied = [];
  const page = await loadPage("admin.html", "pages/admin-features.js", {
    url: `https://ospmae.example/admin.html${hash}`,
    ospmae: {
      isAdmin: () => isAdmin,
      setFeatures: (enabled) => applied.push(enabled),
      api: async (path, options = {}) => {
        // Bodies are built in the page's realm; compare them as JSON.
        const body =
          options.body === undefined
            ? undefined
            : JSON.parse(JSON.stringify(options.body));
        calls.push([options.method || "GET", path, body]);
        const next = responses.shift();
        if (next instanceof Error) throw next;
        return structuredClone(next);
      },
    },
  });
  t.after(page.close);
  await page.settle();
  await page.settle();
  return { ...page, calls, applied };
}

const rows = (document) =>
  [...document.querySelectorAll("#feature-settings .form-check")].map((row) => {
    const input = row.querySelector("input");
    return {
      key: input.id.replace("feature-", ""),
      checked: input.checked,
      disabled: input.disabled,
      note: row.querySelector(".form-text")?.textContent || "",
      nested: row.classList.contains("ms-4"),
    };
  });

test("the open tab loads every switch with its revision", async (t) => {
  const { document, calls } = await features(t, { responses: [config()] });
  assert.deepEqual(calls, [["GET", "/v1/admin/features", undefined]]);
  assert.deepEqual(rows(document), [
    {
      key: "frameworks",
      checked: true,
      disabled: false,
      note: "",
      nested: false,
    },
    {
      key: "manifests",
      checked: true,
      disabled: false,
      note: "",
      nested: false,
    },
    {
      key: "release_feed",
      checked: true,
      disabled: false,
      note: "",
      nested: true,
    },
  ]);
  assert.equal(
    document.getElementById("feature-version").textContent,
    "Configuration revision 3",
  );
  assert.equal(document.getElementById("feature-status").hidden, true);
  assert.equal(
    document.querySelector("#feature-frameworks + label").textContent,
    "Frameworks and capability mapping",
  );
});

test("the deployment ceiling and an off parent disable switches with a reason", async (t) => {
  const { document } = await features(t, {
    responses: [
      config({
        deployment: { frameworks: false, manifests: true, release_feed: true },
        enabled: { frameworks: false, manifests: false, release_feed: false },
        configured: { frameworks: true, manifests: false, release_feed: true },
      }),
    ],
  });
  const [frameworks, manifests, feeds] = rows(document);
  assert.deepEqual(frameworks, {
    key: "frameworks",
    checked: false,
    disabled: true,
    note: "Turned off for this deployment (OSPMAE_FEATURE_FRAMEWORKS=false).",
    nested: false,
  });
  assert.equal(manifests.disabled, false);
  assert.equal(manifests.checked, false);
  assert.equal(feeds.disabled, true);
  assert.equal(
    feeds.note,
    "Unavailable while its parent feature is off. Your setting is preserved.",
  );
  assert.equal(
    document
      .getElementById("feature-release_feed")
      .getAttribute("aria-describedby"),
    "feature-release_feed-help",
  );
});

test("a change saves against the loaded revision and applies to the page", async (t) => {
  const saved = config({
    version: 4,
    configured: { frameworks: false, manifests: true, release_feed: true },
    enabled: { frameworks: false, manifests: true, release_feed: true },
  });
  const { document, window, calls, applied } = await features(t, {
    responses: [config(), saved],
  });
  const input = document.getElementById("feature-frameworks");
  input.checked = false;
  input.dispatchEvent(new window.Event("change"));
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(calls[1], [
    "PUT",
    "/v1/admin/features",
    { version: 3, changes: { frameworks: false } },
  ]);
  assert.deepEqual(applied, [saved.enabled]);
  const status = document.getElementById("feature-status");
  assert.equal(status.hidden, false);
  assert.match(status.className, /alert-success/);
  assert.equal(
    status.textContent,
    "Frameworks and capability mapping disabled. Settings saved. Reload the page to refresh navigation.",
  );
  assert.equal(document.getElementById("feature-frameworks").checked, false);
  assert.equal(
    document.getElementById("feature-version").textContent,
    "Configuration revision 4",
  );
  assert.equal(document.activeElement?.id, "feature-frameworks");
});

test("a refused save reports why and shows the stored settings again", async (t) => {
  const stored = config({ version: 5 });
  const { document, window, calls } = await features(t, {
    responses: [
      config(),
      new Error("Features changed in another session."),
      stored,
    ],
  });
  const input = document.getElementById("feature-manifests");
  input.checked = false;
  input.dispatchEvent(new window.Event("change"));
  for (let i = 0; i < 4; i += 1) await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(
    calls.map(([method]) => method),
    ["GET", "PUT", "GET"],
  );
  const status = document.getElementById("feature-status");
  assert.match(status.className, /alert-danger/);
  assert.equal(
    status.textContent,
    "Could not save: Features changed in another session.. Reload settings before trying again.",
  );
  assert.equal(document.getElementById("feature-manifests").checked, true);
  assert.equal(
    document.getElementById("feature-version").textContent,
    "Configuration revision 5",
  );
});

test("a failed load offers a retry, and Reload settings retries", async (t) => {
  const { document, window, calls } = await features(t, {
    responses: [new Error("offline"), config()],
  });
  const status = document.getElementById("feature-status");
  assert.equal(
    status.textContent,
    "Could not load features: offline. Use Reload settings to retry.",
  );
  assert.equal(rows(document).length, 0);
  document.getElementById("features-reload").click();
  for (let i = 0; i < 3; i += 1) await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls.length, 2);
  assert.equal(rows(document).length, 3);
  assert.equal(status.hidden, true);
});

test("another tab loads nothing until Features is shown", async (t) => {
  const { document, window, calls } = await features(t, {
    responses: [config()],
    hash: "#audit",
  });
  assert.deepEqual(calls, []);
  document
    .getElementById("tab-features")
    .dispatchEvent(new window.Event("shown.bs.tab"));
  for (let i = 0; i < 3; i += 1) await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls.length, 1);
  assert.equal(rows(document).length, 3);
});

test("non-administrators get no feature controls", async (t) => {
  const { document, calls } = await features(t, {
    responses: [],
    isAdmin: false,
  });
  assert.deepEqual(calls, []);
  assert.equal(document.getElementById("feature-settings").children.length, 0);
});
