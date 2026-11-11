// The project editor with optional features switched off: the real app.js
// and editor script against a fake API.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

const OFF = {
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
  versions: [],
  programming_languages: [],
  supported_profiles: [],
  supported_formats: [],
  release_rss_ignore_patterns: [],
};

async function editor(t, features = OFF) {
  const page = await loadPage("project-edit.html", "pages/project-edit.js", {
    url: "https://ospmae.example/project-edit.html?id=1",
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
            features,
          },
        ];
      if (path === "/v1/system/features") return [200, features];
      if (path.startsWith("/v1/frameworks"))
        return [404, { detail: "Feature not available" }];
      if (path === "/v1/projects/1" && method === "GET") return [200, PROJECT];
      if (path === "/v1/projects/1" && method === "PUT")
        return [200, { ...PROJECT, ...body }];
      if (path === "/v1/projects/1/versions" && method === "POST")
        return [200, { id: 7, project_id: 1, ...body }];
      return [200, {}];
    },
  });
  t.after(page.close);
  for (let i = 0; i < 20; i += 1) await page.settle();
  return page;
}

test("the editor opens without asking for frameworks", async (t) => {
  const page = await editor(t);
  const asked = page.requests.map(([method, path]) => `${method} ${path}`);
  assert.ok(asked.includes("GET /v1/projects/1"), asked.join(", "));
  assert.equal(
    asked.filter((r) => r.includes("/v1/frameworks")).length,
    0,
    asked.join(", "),
  );
  assert.equal(page.document.getElementById("display_name").value, "Wallet");
  // The capability mapping card belongs to the frameworks feature.
  assert.equal(
    page.document.querySelector('[data-feature="frameworks"]').hidden,
    true,
  );
});

test("saving a project works with frameworks and manifests off", async (t) => {
  const page = await editor(t);
  page.document.getElementById("display_name").value = "Wallet two";
  page.document.getElementById("saveProjectBtn").click();
  for (let i = 0; i < 20; i += 1) await page.settle();
  const saves = page.requests.filter(
    ([method, path]) => method === "PUT" && path === "/v1/projects/1",
  );
  assert.equal(saves.length, 1);
  assert.equal(saves[0][2].display_name, "Wallet two");
});

test("a version saves without capability mappings when frameworks are off", async (t) => {
  const page = await editor(t);
  page.document.getElementById("newVersionBtn").click();
  for (let i = 0; i < 5; i += 1) await page.settle();
  page.document.getElementById("version").value = "1.0.0";
  page.document.getElementById("saveVersionBtn").click();
  for (let i = 0; i < 20; i += 1) await page.settle();
  const writes = page.requests
    .filter(([method]) => method !== "GET")
    .map(([method, path, body]) => [method, path, body?.version]);
  assert.deepEqual(writes, [["POST", "/v1/projects/1/versions", "1.0.0"]]);
});
