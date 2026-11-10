// safeHref fallbacks on the account and project pages stay strict.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));

function extractSafeHref(file) {
  const src = readFileSync(
    path.resolve(here, "..", "public", "pages", file),
    "utf8",
  );
  // Cut from the declaration to the first balanced close brace.
  const start = src.indexOf("function safeHref(");
  assert.ok(start >= 0, `safeHref must exist in ${file}`);
  let depth = 0;
  let end = start;
  for (let i = start; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  const body = src.slice(start, end);
  const fn = new Function("window", `${body}\n return safeHref;`);
  return fn({}); // no mospUi safeExternalHref deployed in tests
}

for (const file of ["account.js", "project.js"]) {
  const safeHref = extractSafeHref(file);

  test(`${file}: absolut http(s) urls are kept`, () => {
    assert.equal(safeHref("https://example.com/x"), "https://example.com/x");
    assert.equal(safeHref("/project.html"), "/project.html");
  });

  test(`${file}: script schemes and protocol-relative are dropped`, () => {
    assert.equal(safeHref("javascript:alert(1)"), "");
    assert.equal(safeHref("data:text/html,<script>"), "");
    assert.equal(safeHref("vbscript: crash"), "");
    assert.equal(safeHref("//evil.example.com"), "");
  });

  test(`${file}: backslash and control characters are dropped`, () => {
    assert.equal(safeHref("/\\evil.com"), "");
    assert.equal(safeHref("/a\u001fb"), "");
  });
}

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
