// login page sanitisation and navigation safety without a browser.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = readFileSync(
  path.resolve(here, "..", "public", "pages", "login.js"),
  "utf8",
);

// Extract the sanitizeNext function body from the page script: it is a plain
// function expression inside an IIFE, so it can be evaluated directly.
const match = source.match(/function sanitizeNext\(rawNext\) \{[\s\S]*?\n  \}/);
assert.ok(match, "sanitizeNext must exist as a plain function");

function withStubs(fnSource, allowedHosts = []) {
  const fn = new Function(
    "redirectAllowedHosts",
    "window",
    `${fnSource}\n return sanitizeNext;`,
  );
  return fn(allowedHosts, {
    location: { origin: "https://ospmae.test", replace: () => {} },
  });
}

const sanitizeNext = withStubs(match[0]);

test("same-origin relative paths survive sanitisation", () => {
  assert.equal(sanitizeNext("/index.html"), "/index.html");
  assert.equal(sanitizeNext("/project.html?id=3"), "/project.html?id=3");
});

test("protocol-relative and absolute foreign URLs fall back", () => {
  assert.equal(sanitizeNext("//evil.example.com"), "/index.html");
  assert.equal(sanitizeNext("https://evil.example.com"), "/index.html");
  assert.equal(sanitizeNext("http://gui.dsí"), "/index.html");
});

test("backslash and control-character bypasses fall back", () => {
  assert.equal(sanitizeNext("/\\evil.com"), "/index.html");
  assert.equal(sanitizeNext("/a\u0000b"), "/index.html");
  assert.equal(sanitizeNext(""), "/index.html");
});

test("allowed hosts still permit absolute same-protocol redirects", () => {
  // In the page, redirectAllowedHosts is a mutable closure variable normally
  // filled from /v1/auth/methods; the harness feeds it via argument.
  const allow = withStubs(match[0], ["partner.example.com"]);
  assert.ok(
    allow("https://partner.example.com/ok").startsWith(
      "https://partner.example.com",
    ),
    "allowlisted hosts keep cross-origin redirects",
  );
  const deny = withStubs(match[0], []);
  assert.equal(deny("https://partner.example.com/ok"), "/index.html");
});
