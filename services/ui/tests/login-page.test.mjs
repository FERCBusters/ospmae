// The sign-in page: providers, a password-free installation, messages and
// the server's reasons for a refused sign-in.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

async function signIn(
  t,
  { methods = {}, login, me = null, next = "/project.html?id=3" } = {},
) {
  const calls = [];
  const page = await loadPage("login.html", "pages/login.js", {
    url: `https://ospmae.example/login.html?next=${encodeURIComponent(next)}`,
    ospmae: {
      api: async (path, options = {}) => {
        const body =
          options.body === undefined
            ? undefined
            : JSON.parse(JSON.stringify(options.body));
        calls.push([options.method || "GET", path, body]);
        if (path === "/v1/auth/methods") {
          if (methods instanceof Error) throw methods;
          return structuredClone(methods);
        }
        if (path === "/v1/me") {
          if (me instanceof Error) throw me;
          return me;
        }
        if (login instanceof Error) throw login;
        return structuredClone(login);
      },
    },
  });
  t.after(page.close);
  for (let i = 0; i < 3; i += 1) await page.settle();
  return { ...page, calls };
}

async function submit(page, username, password) {
  page.document.getElementById("username").value = username;
  page.document.getElementById("password").value = password;
  page.document
    .getElementById("loginForm")
    .dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  for (let i = 0; i < 3; i += 1) await page.settle();
}

const message = (document) => {
  const msg = document.getElementById("msg");
  return {
    hidden: msg.hidden,
    className: msg.className,
    text: msg.textContent,
  };
};

test("the page starts with no message and asks for the sign-in methods", async (t) => {
  const { document, calls } = await signIn(t);
  assert.deepEqual(message(document), {
    hidden: true,
    className: "alert alert-info",
    text: "",
  });
  assert.deepEqual(
    calls.map(([method, path]) => [method, path]),
    [
      ["GET", "/v1/auth/methods"],
      ["GET", "/v1/me"],
    ],
  );
  assert.ok(document.getElementById("ssoSection").classList.contains("d-none"));
  // Passwords are reset by an administrator, as in KEEN: no reset link.
  assert.equal(document.querySelector('a[href*="password"]'), null);
});

test("the fields open, and take focus, once the page can submit them", async (t) => {
  const { document } = await signIn(t);
  assert.equal(document.getElementById("loginFields").disabled, false);
  assert.equal(document.getElementById("loginLoading").hidden, true);
  assert.equal(document.activeElement?.id, "username");
  // A native submission could only post, never put a password in an address.
  assert.equal(
    document.getElementById("loginForm").getAttribute("method"),
    "post",
  );
});

test("providers become buttons whose labels are text, never markup", async (t) => {
  const { document } = await signIn(t, {
    methods: {
      sso_providers: [
        {
          key: "github",
          label: "GitHub",
          start_url: "/v1/auth/sso/github/start",
        },
        { key: "corp", label: '<img src=x onerror="alert(1)">' },
      ],
    },
  });
  const buttons = [...document.querySelectorAll("#ssoButtons button")];
  assert.deepEqual(
    buttons.map((b) => [b.textContent, b.querySelector("i").className]),
    [
      ["Continue with GitHub", "bi bi-github me-1"],
      [
        'Continue with <img src=x onerror="alert(1)">',
        "bi bi-shield-lock me-1",
      ],
    ],
  );
  assert.equal(document.querySelector("#ssoButtons img"), null);
  assert.equal(
    document.getElementById("ssoSection").classList.contains("d-none"),
    false,
  );
});

test("without local passwords only the providers remain", async (t) => {
  const { document } = await signIn(t, {
    methods: {
      local_enabled: false,
      oidc_enabled: true,
      oidc: { label: "Company login" },
    },
  });
  assert.ok(document.getElementById("loginForm").classList.contains("d-none"));
  assert.ok(
    document.querySelector("[data-sso-divider]").classList.contains("d-none"),
  );
  assert.equal(
    document.querySelector("#ssoButtons button").textContent,
    "Continue with Company login",
  );
  assert.deepEqual(message(document), {
    hidden: false,
    className: "alert alert-info",
    text: "Sign in using one of the enabled single sign-on providers.",
  });
});

test("a blank form is refused before any request", async (t) => {
  const page = await signIn(t);
  await submit(page, "  ", "secret");
  assert.deepEqual(message(page.document), {
    hidden: false,
    className: "alert alert-danger",
    text: "Please provide username and password.",
  });
  assert.equal(page.calls.length, 2);
  assert.equal(page.document.getElementById("loginBtn").disabled, false);
});

test("a refused sign-in shows the server's reason", async (t) => {
  const page = await signIn(t, {
    login: new Error("Too many login attempts. Please try again later."),
  });
  await submit(page, " alice ", "pw");
  assert.deepEqual(page.calls.at(-1), [
    "POST",
    "/v1/auth/login",
    { username: "alice", password: "pw" },
  ]);
  assert.deepEqual(message(page.document), {
    hidden: false,
    className: "alert alert-danger",
    text: "Too many login attempts. Please try again later.",
  });
  assert.equal(page.document.getElementById("loginBtn").disabled, false);
});

test("a password that needs a second factor says so", async (t) => {
  const page = await signIn(t, {
    login: { mfa_required: true, next: "/mfa.html" },
  });
  await submit(page, "alice", "pw");
  assert.deepEqual(message(page.document), {
    hidden: false,
    className: "alert alert-info",
    text: "Second factor required. Redirecting…",
  });
});

// jsdom cannot leave the page: each move to another address is reported as
// an error, which is how these count where the page tried to go.
const departures = (page) =>
  page.errors.filter((error) => /navigation/i.test(String(error?.message)))
    .length;

test("a visitor who is already signed in is sent on without the form", async (t) => {
  const page = await signIn(t, { me: { username: "alice" } });
  assert.equal(departures(page), 1);
  const stays = await signIn(t, { me: { detail: "Not authenticated" } });
  assert.equal(departures(stays), 0);
  const offline = await signIn(t, { me: new Error("offline") });
  assert.equal(departures(offline), 0);
});

test("a successful sign-in says so and moves on once", async (t) => {
  const page = await signIn(t, { login: { username: "alice" } });
  await submit(page, " alice ", "pw");
  assert.deepEqual(page.calls.at(-1), [
    "POST",
    "/v1/auth/login",
    { username: "alice", password: "pw" },
  ]);
  assert.deepEqual(message(page.document), {
    hidden: false,
    className: "alert alert-info",
    text: "Signed in. Redirecting…",
  });
  assert.equal(departures(page), 1);
  assert.equal(page.document.getElementById("loginBtn").disabled, false);
});

test("an empty answer to a sign-in is a failure, and nothing moves", async (t) => {
  const page = await signIn(t, { login: null });
  await submit(page, "alice", "pw");
  assert.deepEqual(message(page.document), {
    hidden: false,
    className: "alert alert-danger",
    text: "Login failed.",
  });
  assert.equal(departures(page), 0);
});

test("a failure without a reason falls back to a general message", async (t) => {
  const failure = new Error("");
  const page = await signIn(t, { login: failure });
  await submit(page, "alice", "pw");
  assert.equal(
    message(page.document).text,
    "Login failed. Please check your credentials.",
  );
});

test("a provider button starts that provider's sign-in", async (t) => {
  // Each return address here is one the page accepts or replaces before
  // handing it on: its own pages, an allowed host, and shapes it refuses.
  for (const next of [
    "/project.html?id=3",
    "",
    "//evil.example",
    "/a\\b",
    "javascript:alert(1)",
    "https://ospmae.example/account.html#shortcuts",
    "https://partner.example/landing",
    "https://evil.example/",
    "http://[",
  ]) {
    const page = await signIn(t, {
      next,
      methods: {
        redirect_allowed_hosts: [
          " Partner.Example ",
          "",
          null,
          "https://scheme.example",
          "path.example/x",
          "back\\slash",
        ],
        sso_providers: [{ key: "Google", label: " ", start_url: "" }],
      },
    });
    const button = page.document.querySelector("#ssoButtons button");
    assert.equal(button.textContent, "Continue with single sign-on");
    assert.equal(button.querySelector("i").className, "bi bi-google me-1");
    button.click();
    assert.equal(departures(page), 1, next);
  }
});

test("sign-in methods that cannot be read leave the password form in place", async (t) => {
  const page = await signIn(t, { methods: new Error("offline") });
  assert.equal(
    page.document.getElementById("loginForm").classList.contains("d-none"),
    false,
  );
  assert.ok(
    page.document.getElementById("ssoSection").classList.contains("d-none"),
  );
  const none = await signIn(t, { methods: null });
  assert.equal(none.document.querySelectorAll("#ssoButtons button").length, 0);
});
