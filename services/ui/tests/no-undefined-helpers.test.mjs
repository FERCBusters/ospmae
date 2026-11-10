import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// The shared helpers live on window.OSPMAE (app.js). A page script that
// calls api(, toast( or escapeHtml( without first destructuring or
// aliasing them throws "ReferenceError" in production, which is exactly
// how the organisation pane once rendered "api is not defined". This
// contract fails any page script that uses a helper it does not bind.

const pagesDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "public",
  "pages",
);

const HELPERS = ["api", "toast", "escapeHtml"];

function unboundHelpers(source) {
  const used = HELPERS.filter((helper) =>
    new RegExp(`(^|[^\\w.$'"-])${helper}\\s*\\(`).test(source),
  );
  return used.filter((helper) => {
    const binding = new RegExp(`[,{\\s]${helper}\\s*[,}:]`);
    const ospmaeForm = new RegExp(`\\bOSPMAE\\.${helper}\\b`);
    const localDef = new RegExp(`(const|function)\\s+${helper}\\b`);
    const windowForm = new RegExp(
      `window\\.${helper}\\s*=|\\.escapeHtml\\s*=?\\s*(\\(s\\))?\s*=`,
    );
    return !(
      binding.test(source) ||
      ospmaeForm.test(source) ||
      localDef.test(source) ||
      windowForm.test(source)
    );
  });
}

function scriptFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      out.push(...scriptFiles(path));
    } else if (name.endsWith(".js")) {
      out.push(path);
    }
  }
  return out;
}

const offenders = [];
for (const path of scriptFiles(pagesDir)) {
  const source = readFileSync(path, "utf8");
  const warns = unboundHelpers(source);
  if (warns.length) offenders.push(`${path}: ${warns.join(", ")}`);
}

test("page scripts never call unbound UI helpers", () => {
  assert.deepEqual(
    offenders,
    [],
    "page scripts call helpers they never bind; they would throw ReferenceError in production",
  );
});

test("helper scan detects the original unbound-call defect", () => {
  // api( with no binding is caught...
  assert.deepEqual(unboundHelpers("api('/x');"), ["api"]);
  // ... OSPMAE.api( is not a bare call and never flagged...
  assert.deepEqual(unboundHelpers("OSPMAE.api('/x');"), []);
  // ...a proper destructuring binds both helpers...
  assert.deepEqual(
    unboundHelpers("const { api, toast } = OSPMAE;\napi('/x');\ntoast('ok');"),
    [],
  );
  // ...and a local definition or window binding satisfies the scan.
  assert.deepEqual(
    unboundHelpers("function toast() {}\nwindow.escapeHtml = (s) => s;"),
    [],
  );
});
