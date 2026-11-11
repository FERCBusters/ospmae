// SSO email addresses, as KEEN manages them: the account page's list and
// request form, and the page that confirms a mailed link.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

const ME = {
  id: 7,
  username: "roamer",
  email: "roamer@x.test",
  role: "viewer",
  effective_role: "viewer",
  auth_method: "local",
  password_features_enabled: true,
  csrf_token: "token",
  preferences: {},
  features: {},
};

function accountApi(addresses, answers = {}) {
  return async (method, path, body) => {
    const key = `${method} ${path}`;
    if (answers[key]) return answers[key](body);
    if (path === "/v1/me") return [200, ME];
    if (path === "/v1/me/sso-emails")
      return [
        200,
        { smtp_configured: true, primary_email: ME.email, addresses },
      ];
    if (path === "/v1/me/mfa")
      return [200, { enabled: false, totp: false, credentials: [] }];
    if (path === "/v1/me/notifications") return [200, []];
    if (path === "/v1/me/subscriptions") return [200, { items: [] }];
    if (path === "/v1/me/shortcuts") return [200, []];
    if (path === "/v1/me/questions") return [200, { items: [] }];
    if (path.startsWith("/v1/frameworks")) return [200, { items: [] }];
    return [200, {}];
  };
}

async function account(t, addresses, answers) {
  const page = await loadPage("account.html", "pages/account.js", {
    withApp: true,
    api: accountApi(addresses, answers),
  });
  t.after(page.close);
  for (let i = 0; i < 20; i += 1) await page.settle();
  return page;
}

test("the account page shows the admin-set email and the verified addresses", async (t) => {
  const { document } = await account(t, [
    { email: "work@x.test", verified_at: "2026-11-11T00:00:00" },
  ]);
  assert.equal(
    document.getElementById("profileEmail").textContent,
    "roamer@x.test",
  );
  // The account email is not editable here: an administrator sets it.
  assert.equal(document.querySelector("#tabProfile input[type=email]"), null);
  const items = [...document.querySelectorAll("#ssoEmailList li")];
  assert.deepEqual(
    items.map((li) => li.querySelector("span").textContent),
    ["work@x.test - verified"],
  );
  assert.match(
    document.getElementById("ssoEmailStatus").textContent,
    /sign-in within the last five minutes/,
  );
});

test("requesting a link and removing an address reach the KEEN routes", async (t) => {
  const removed = [];
  const page = await account(
    t,
    [{ email: "work@x.test", verified_at: "2026-11-11T00:00:00" }],
    {
      "POST /v1/me/sso-emails/request": () => [200, { ok: true }],
      "POST /v1/me/sso-emails/remove": (body) => {
        removed.push(body.email);
        return [200, { ok: true }];
      },
    },
  );
  const { document, window, requests } = page;
  document.getElementById("ssoEmail").value = "home@x.test";
  document
    .getElementById("ssoEmailForm")
    .dispatchEvent(new window.Event("submit", { cancelable: true }));
  for (let i = 0; i < 5; i += 1) await page.settle();
  assert.ok(
    requests.some(
      ([method, path, body]) =>
        method === "POST" &&
        path === "/v1/me/sso-emails/request" &&
        body.email === "home@x.test",
    ),
  );
  assert.match(
    document.getElementById("ssoEmailStatus").textContent,
    /Verification email sent/,
  );

  window.confirm = () => true;
  document.querySelector("#ssoEmailList button").click();
  for (let i = 0; i < 5; i += 1) await page.settle();
  assert.deepEqual(removed, ["work@x.test"]);
});

test("a refused request shows the server's reason", async (t) => {
  const page = await account(t, [], {
    "POST /v1/me/sso-emails/request": () => [
      403,
      {
        detail:
          "Sign out and sign in again, then manage SSO email addresses within five minutes",
      },
    ],
  });
  const { document, window } = page;
  assert.equal(
    document.querySelector("#ssoEmailList li").textContent,
    "No verified SSO email addresses.",
  );
  document.getElementById("ssoEmail").value = "home@x.test";
  document
    .getElementById("ssoEmailForm")
    .dispatchEvent(new window.Event("submit", { cancelable: true }));
  for (let i = 0; i < 5; i += 1) await page.settle();
  assert.match(
    document.getElementById("ssoEmailStatus").textContent,
    /within five minutes/,
  );
});

async function confirmPage(t, url, api) {
  const page = await loadPage("sso-email.html", "pages/sso-email-confirm.js", {
    url,
    ospmae: { api },
  });
  t.after(page.close);
  return page;
}

test("the confirmation page sends the mailed token once and clears it", async (t) => {
  const sent = [];
  const page = await confirmPage(
    t,
    "https://ospmae.example/sso-email.html#token=abcdefghijklmnopqrstuvwxyz",
    async (path, options) => {
      sent.push([path, options.body]);
      return { ok: true, email: "work@x.test" };
    },
  );
  const { document, window } = page;
  // The token leaves the address bar before anything else.
  assert.equal(window.location.hash, "");
  document.getElementById("confirmEmail").click();
  await page.settle();
  assert.deepEqual(JSON.parse(JSON.stringify(sent)), [
    ["/v1/me/sso-emails/confirm", { token: "abcdefghijklmnopqrstuvwxyz" }],
  ]);
  assert.equal(
    document.getElementById("emailProofStatus").textContent,
    "work@x.test is verified and available for SSO linking.",
  );
  assert.equal(document.getElementById("confirmEmail").hidden, true);
});

test("a stale link explains how to get a fresh one", async (t) => {
  const page = await confirmPage(
    t,
    "https://ospmae.example/sso-email.html#token=abcdefghijklmnopqrstuvwxyz",
    async () => {
      throw new Error("Verification link is invalid or expired");
    },
  );
  const { document } = page;
  document.getElementById("confirmEmail").click();
  await page.settle();
  assert.match(
    document.getElementById("emailProofStatus").textContent,
    /^Verification link is invalid or expired Sign into the requesting account/,
  );
  assert.equal(document.getElementById("confirmEmail").disabled, false);
});

test("without a token the page only explains", async (t) => {
  const { document } = await confirmPage(
    t,
    "https://ospmae.example/sso-email.html",
    async () => {
      throw new Error("not called");
    },
  );
  assert.equal(document.getElementById("confirmEmail").hidden, true);
  assert.match(
    document.getElementById("emailProofStatus").textContent,
    /Open the verification link/,
  );
});

test("a password change signs the browser out, as KEEN's does", async (t) => {
  const page = await account(t, [], {
    "POST /v1/auth/change-password": () => [204, undefined],
  });
  const { document, window, requests } = page;
  document.getElementById("currentPassword").value = "Old-password-1";
  document.getElementById("newPassword").value = "New-password-2";
  document.getElementById("confirmPassword").value = "New-password-2";
  document
    .getElementById("changePasswordForm")
    .dispatchEvent(new window.Event("submit", { cancelable: true }));
  for (let i = 0; i < 5; i += 1) await page.settle();
  assert.ok(
    requests.some(
      ([method, path]) =>
        method === "POST" && path === "/v1/auth/change-password",
    ),
  );
  assert.equal(
    document.getElementById("passwordMsg").textContent,
    "Password updated. Sign in again to continue.",
  );
});

test("the security tab reads the account's second-factor state", async (t) => {
  const page = await account(t, [], {
    "GET /v1/me/mfa": () => [
      200,
      {
        local_enabled: true,
        enabled: true,
        totp: true,
        credentials: [{ id: 1 }],
        recovery_codes_remaining: 9,
        required: false,
      },
    ],
  });
  assert.equal(
    page.document.getElementById("securitySummary").textContent,
    "Two-factor authentication is enabled. Authenticator app; 1 security keys/passkeys; 9 recovery codes remaining.",
  );
});
