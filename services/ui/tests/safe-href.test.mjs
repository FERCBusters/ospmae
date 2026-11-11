// The shared safe-link check (OSPMAE.safeHref) stays strict, with and
// without the design system's own check loaded.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadApp } from "./_harness.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const OSPMAE = await loadApp();
const safeHref = OSPMAE.safeHref;

test("absolute http(s) addresses and same-site paths are kept", () => {
  assert.equal(safeHref("https://example.com/x"), "https://example.com/x");
  assert.equal(safeHref(" http://example.com "), "http://example.com/");
  assert.equal(safeHref("/project.html"), "/project.html");
});

test("script schemes and protocol-relative addresses are dropped", () => {
  assert.equal(safeHref("javascript:alert(1)"), "");
  assert.equal(safeHref("data:text/html,<script>"), "");
  assert.equal(safeHref("vbscript: crash"), "");
  assert.equal(safeHref("//evil.example.com"), "");
});

test("backslashes and control characters are dropped", () => {
  assert.equal(safeHref("/\\evil.com"), "");
  assert.equal(safeHref("/a\u001fb"), "");
});

test("other schemes, bare words and nothing at all are dropped", () => {
  assert.equal(safeHref("ftp://example.com/x"), "");
  assert.equal(safeHref("mailto:ada@example.org"), "");
  assert.equal(safeHref("example.com"), "");
  assert.equal(safeHref(""), "");
  assert.equal(safeHref(null), "");
});

test("the design system's check decides once the shell has loaded it", () => {
  const asked = [];
  globalThis.window.mospUi = {
    safeExternalHref: (value) => {
      asked.push(value);
      return value === "https://ok.example/" ? value : null;
    },
  };
  try {
    assert.equal(safeHref("https://ok.example/"), "https://ok.example/");
    assert.equal(safeHref("/project.html"), "");
    assert.deepEqual(asked, ["https://ok.example/", "/project.html"]);
  } finally {
    delete globalThis.window.mospUi;
  }
});

// The navbar shortcut changehandler in app.js refuses the same shapes.
test("app.js shortcut handler rejects unsafe values", () => {
  const src = readFileSync(
    path.resolve(here, "..", "public", "app.js"),
    "utf8",
  );
  const start = src.indexOf('addEventListener("change"');
  assert.ok(start > 0, "shortcut change handler must exist");
  const body = src.slice(start, start + 700);
  assert.ok(body.includes("startsWith"), "relative routes only");
  assert.ok(body.includes("u0000"), "control characters rejected");
  assert.ok(
    body.includes("\\") || body.includes("u007f"),
    "backslashes rejected",
  );
  assert.ok(body.includes("quickAndDirty") === false, "no bypass");
});
