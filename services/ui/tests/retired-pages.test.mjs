import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

// Pages that moved: the Projects dashboard is /index.html, the Manifest
// Builder and Saved Manifests share /manifests.html, My Questions is an
// Account tab and projects are edited at /project-edit.html. A link left on
// a retired page is a 404 for whoever follows it, so first-party UI and API
// sources must not name one.

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");
const RETIRED = [
  "/dashboard.html",
  "/saved-manifests.html",
  "/my-questions.html",
  "/project-manage.html",
];

function files(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (name === "vendor" || name === "node_modules" || name === "__pycache__")
      continue;
    if (statSync(path).isDirectory()) files(path, out);
    else if (/\.(html|js|mjs|py|conf)$/.test(name)) out.push(path);
  }
  return out;
}

function offenders(paths) {
  const found = [];
  for (const path of paths) {
    const source = readFileSync(path, "utf8");
    for (const page of RETIRED) {
      if (source.includes(page)) found.push(`${relative(repo, path)}: ${page}`);
    }
  }
  return found;
}

test("retired pages are gone from the UI bundle", () => {
  for (const page of RETIRED) {
    assert.equal(
      existsSync(join(repo, "services", "ui", "public", page)),
      false,
      page,
    );
  }
});

test("no first-party source links to a retired page", () => {
  const sources = [
    ...files(join(repo, "services", "ui", "public")),
    ...files(join(repo, "services", "ui", "nginx")),
    ...files(join(repo, "services", "api", "app")),
  ];
  assert.deepEqual(offenders(sources), []);
});

test("the contract would catch a stale link", () => {
  const probe = join(here, "retired-pages.test.mjs");
  // This file names every retired page, so scanning it must flag them all.
  assert.equal(offenders([probe]).length, RETIRED.length);
});
