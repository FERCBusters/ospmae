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

// The destination helpers are plain functions in the same IIFE; they are
// evaluated together against a stand-in for the address the page is shown at.
const grab = (signature) => {
  const start = source.indexOf(`  function ${signature} {`);
  assert.notEqual(start, -1, signature);
  return source.slice(start, source.indexOf("\n  }", start) + 4);
};

function destinations(href) {
  const at = new URL(href);
  const fn = new Function(
    "redirectAllowedHosts",
    "window",
    `${match[0]}\n${grab("getNextParam()")}\n${grab("secondFactorUrl()")}
     return { getNextParam, secondFactorUrl, sanitizeNext };`,
  );
  return fn([], {
    location: { origin: at.origin, pathname: at.pathname, search: at.search },
  });
}

test("an explicit next names the destination wherever the page is shown", () => {
  for (const href of [
    "https://ospmae.test/login.html?next=%2Fproject.html%3Fid%3D3",
    "https://ospmae.test/admin.html?next=%2Fproject.html%3Fid%3D3",
  ]) {
    assert.equal(destinations(href).getNextParam(), "/project.html?id=3", href);
  }
});

test("the sign-in page shown in place of another page returns to that page", () => {
  // nginx gives a signed-out browser this page at the address it asked for.
  const inPlace = destinations(
    "https://ospmae.test/project.html?id=7&tab=deps",
  );
  assert.equal(inPlace.getNextParam(), "/project.html?id=7&tab=deps");
  assert.equal(
    inPlace.sanitizeNext(inPlace.getNextParam()),
    "/project.html?id=7&tab=deps",
  );
  // The site root is a page like any other.
  assert.equal(destinations("https://ospmae.test/").getNextParam(), "/");
  // At its own address the page has nowhere to return to.
  const own = destinations("https://ospmae.test/login.html");
  assert.equal(own.getNextParam(), "");
  assert.equal(own.sanitizeNext(own.getNextParam()), "/index.html");
});

test("the second factor page is told the destination, already made safe", () => {
  assert.equal(
    destinations("https://ospmae.test/login.html").secondFactorUrl(),
    "/mfa.html",
  );
  assert.equal(
    destinations(
      "https://ospmae.test/project.html?id=7&tab=deps",
    ).secondFactorUrl(),
    "/mfa.html?next=%2Fproject.html%3Fid%3D7%26tab%3Ddeps",
  );
  // A destination naming another site is replaced before it is handed on.
  for (const hostile of [
    "//evil.example",
    "/\\evil.example",
    "/\t/evil.example",
  ]) {
    assert.equal(
      destinations(
        `https://ospmae.test/login.html?next=${encodeURIComponent(hostile)}`,
      ).secondFactorUrl(),
      "/mfa.html?next=%2Findex.html",
      hostile,
    );
  }
});

// The second factor page finishes a sign-in at the address in its own next
// parameter, through its own check.
const mfaSource = readFileSync(
  path.resolve(here, "..", "public", "pages", "mfa.js"),
  "utf8",
);
const safeNextSource = mfaSource.match(
  /function safeNext\(raw\) \{[\s\S]*?\n  \}/,
);
assert.ok(safeNextSource, "safeNext must exist as a plain function");
const safeNext = new Function(
  "window",
  `${safeNextSource[0]}\n return safeNext;`,
)({ location: { origin: "https://ospmae.test" } });

test("the second factor page continues only to OSPMAE's own pages", () => {
  assert.equal(safeNext("/project.html?id=3"), "/project.html?id=3");
  assert.equal(safeNext("/account.html#password"), "/account.html#password");
  assert.equal(
    safeNext("https://ospmae.test/account.html?x=1#y"),
    "/account.html?x=1#y",
  );
  for (const hostile of [
    "//evil.example",
    "https://evil.example/",
    "javascript:alert(1)",
    "http://[",
  ]) {
    assert.equal(safeNext(hostile), "/index.html", hostile);
  }
  // Nothing to continue to resolves to the site's own root.
  assert.equal(safeNext(""), "/");
});

test("the second factor page refuses addresses a browser reads as another site", () => {
  // A browser turns each of these into //evil.example before navigating:
  // a backslash counts as a slash, and tabs and line breaks are dropped.
  for (const hostile of [
    "/\\evil.example",
    "/\\/evil.example",
    "/\t/evil.example",
    "/\n/evil.example",
    "/\r/evil.example",
    "/a\u0000b",
    "/a\u007fb",
  ]) {
    assert.equal(safeNext(hostile), "/index.html", JSON.stringify(hostile));
  }
  // What two of them would have named, unchecked.
  assert.equal(
    new URL("/\\evil.example", "https://ospmae.test").origin,
    "https://evil.example",
  );
  assert.equal(
    new URL("/\t/evil.example", "https://ospmae.test").origin,
    "https://evil.example",
  );
});
