import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// The dependency browser determination lives and dies on one id: the
// section it prepends must carry id="dep-browser-main", because the code
// excludes itself from its own selector through :not(#dep-browser-main).
// When the id went missing, the browser matched its own selector, deleted
// the section it had just added, and every control lookup returned null —
// the page then hung at the detail subtitle forever. These checks pin both
// halves of that scheme to each other.

const source = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "public",
    "pages",
    "deps-browser.js",
  ),
  "utf8",
);

test("browser section carries the id it later excludes", () => {
  assert.match(
    source,
    /section\.id\s*=\s*"dep-browser-main"/,
    "the prepended browser main must set section.id = 'dep-browser-main'",
  );
});

test("the exclusion selector references the same id", () => {
  assert.match(
    source,
    /:not\(#dep-browser-main\)/,
    "the self-exclusion selector must reference the browser main id",
  );
});
