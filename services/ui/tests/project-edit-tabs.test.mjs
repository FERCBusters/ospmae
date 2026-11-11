// The project editor's tabs, its header link and the automatic-publishing
// switch: the real app.js and editor script against a fake API.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

const FEATURES = {
  frameworks: false,
  manifests: false,
  comparisons: true,
  questions: true,
  dependency_scans: true,
  release_feed: true,
};

const PROJECT = {
  id: 1,
  machine_name: "wallet",
  display_name: "Wallet",
  release_rss_feed_url: "https://example.org/releases.atom",
  release_auto_publish: false,
  versions: [{ id: 5, version: "1.0.0", is_latest: true, is_draft: false }],
  programming_languages: [],
  supported_profiles: [],
  supported_formats: [],
  release_rss_ignore_patterns: [],
};

async function editor(
  t,
  { url = "project-edit.html?id=1", project = PROJECT, put } = {},
) {
  const page = await loadPage("project-edit.html", "pages/project-edit.js", {
    url: `https://ospmae.example/${url}`,
    withApp: true,
    api: async (method, path, body) => {
      if (path === "/v1/me")
        return [
          200,
          {
            username: "admin",
            role: "admin",
            effective_role: "admin",
            csrf_token: "token",
            preferences: {},
            features: FEATURES,
          },
        ];
      if (path === "/v1/system/features") return [200, FEATURES];
      if (path.startsWith("/v1/frameworks"))
        return [404, { detail: "Feature not available" }];
      if (path === "/v1/projects/1" && method === "GET") return [200, project];
      if (path === "/v1/projects/1" && method === "PUT")
        return put ? put(body) : [200, { ...project, ...body }];
      return [200, {}];
    },
  });
  t.after(page.close);
  for (let i = 0; i < 20; i += 1) await page.settle();
  return page;
}

function shown(page) {
  const active = (id) =>
    page.document.getElementById(id).classList.contains("active");
  return { project: active("projectTab"), versions: active("versionsTab") };
}

test("an existing project opens on its form with a Versions tab beside it", async (t) => {
  const page = await editor(t);
  const doc = page.document;
  assert.equal(doc.getElementById("editorTabs").hidden, false);
  assert.deepEqual(shown(page), { project: true, versions: false });
  // The version list lives on the Versions tab, outside the project form.
  assert.ok(
    doc
      .getElementById("versionsTab")
      .contains(doc.getElementById("versionsList")),
  );
  assert.ok(
    doc
      .getElementById("projectTab")
      .contains(doc.getElementById("saveProjectBtn")),
  );

  doc.getElementById("tabVersionsBtn").click();
  assert.deepEqual(shown(page), { project: false, versions: true });
  assert.equal(
    doc.getElementById("tabVersionsBtn").getAttribute("aria-selected"),
    "true",
  );
  assert.equal(page.window.location.hash, "#versions");
  assert.match(doc.getElementById("versionsList").textContent, /1\.0\.0/);

  doc.getElementById("tabProjectBtn").click();
  assert.deepEqual(shown(page), { project: true, versions: false });
  assert.equal(page.window.location.hash, "");
});

test("#versions opens the Versions tab directly", async (t) => {
  const page = await editor(t, { url: "project-edit.html?id=1#versions" });
  assert.deepEqual(shown(page), { project: false, versions: true });
  // Reading the address rewrites nothing.
  assert.equal(page.window.location.hash, "#versions");
});

test("the header link names the project, apart from the wizard's Back", async (t) => {
  const page = await editor(t);
  const back = page.document.getElementById("btnBack");
  assert.equal(back.textContent, "← Return to project");
  assert.equal(back.getAttribute("href"), "/project.html?id=1");
  assert.equal(page.document.getElementById("wizardPrev").textContent, "Back");
});

test("a project being created shows the form alone", async (t) => {
  const page = await editor(t, { url: "project-edit.html#versions" });
  const doc = page.document;
  assert.equal(doc.getElementById("editorTabs").hidden, true);
  assert.deepEqual(shown(page), { project: true, versions: false });
  assert.equal(
    doc.getElementById("btnBack").textContent,
    "← Return to projects",
  );
  assert.equal(
    doc.getElementById("btnBack").getAttribute("href"),
    "/index.html",
  );
  assert.equal(doc.getElementById("autoPublishField").hidden, true);
});

test("the automatic-publishing switch saves on its own", async (t) => {
  const page = await editor(t);
  const doc = page.document;
  const toggle = doc.getElementById("release_auto_publish");
  assert.equal(doc.getElementById("autoPublishField").hidden, false);
  assert.equal(toggle.checked, false);
  assert.equal(toggle.disabled, false);

  toggle.checked = true;
  toggle.dispatchEvent(new page.window.Event("change"));
  for (let i = 0; i < 10; i += 1) await page.settle();
  const saves = page.requests.filter(([method]) => method === "PUT");
  // Only the switch travels: the project form is not saved with it.
  assert.deepEqual(saves, [
    ["PUT", "/v1/projects/1", { release_auto_publish: true }],
  ]);
  assert.equal(toggle.checked, true);
  assert.equal(toggle.disabled, false);
});

test("a refused switch returns to what is stored", async (t) => {
  const page = await editor(t, {
    put: () => [403, { detail: "Not your project" }],
  });
  const toggle = page.document.getElementById("release_auto_publish");
  toggle.checked = true;
  toggle.dispatchEvent(new page.window.Event("change"));
  for (let i = 0; i < 10; i += 1) await page.settle();
  assert.equal(toggle.checked, false);
  assert.equal(toggle.disabled, false);
});

test("the switch waits for a release feed and hides for a tracked branch", async (t) => {
  const noFeed = await editor(t, {
    project: { ...PROJECT, release_rss_feed_url: null },
  });
  const toggle = noFeed.document.getElementById("release_auto_publish");
  assert.equal(toggle.disabled, true);
  assert.match(
    noFeed.document.getElementById("autoPublishHint").textContent,
    /release RSS feed/,
  );

  const tracked = await editor(t, {
    project: {
      ...PROJECT,
      track_branch: true,
      tracked_branch: "main",
      tracked_repo_url: "https://github.com/example/repo",
      branch_poll_interval_hours: 24,
    },
  });
  assert.equal(
    tracked.document.getElementById("autoPublishField").hidden,
    true,
  );
});
