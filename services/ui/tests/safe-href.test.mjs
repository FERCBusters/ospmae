// The shared safe-link check (OSPMAE.safeHref) stays strict, with and
// without the design system's own check loaded.

import test from "node:test";
import assert from "node:assert/strict";
import { loadApp } from "./_harness.mjs";

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
