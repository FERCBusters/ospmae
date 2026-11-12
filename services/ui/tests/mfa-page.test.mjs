// The second-factor page: verifying at sign-in and managing factors, with
// the browser's WebAuthn, clipboard and dialogs as recorded stand-ins.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

const b64 = (text) => Buffer.from(text).toString("base64url");
const bytes = (text) => Uint8Array.from(Buffer.from(text));

const BASE = {
  username: "ada",
  purpose: "login",
  stage: "verify",
  totp: true,
  required: false,
  credentials: [],
  recovery_codes_remaining: 8,
};

// options.state: the server's view, mutated by the answers below.
async function mfa(t, options = {}) {
  const server = { ...BASE, ...(options.state || {}) };
  const browser = {
    gets: [],
    creates: [],
    copied: [],
    prompts: [],
    confirms: [],
    navigations: 0,
  };
  const page = await loadPage("mfa.html", "pages/mfa.js", {
    url: `https://ospmae.example/mfa.html${options.query || ""}`,
    setup(window) {
      window.document.cookie = options.cookies ?? "ospmae_csrf=tok%3Den";
      if (options.saved)
        window.localStorage.setItem("ospmae.mfa.method:ada", options.saved);
      if (options.webauthn !== false) {
        window.PublicKeyCredential = function PublicKeyCredential() {};
        const credential = {
          id: "cred-1",
          rawId: bytes("raw"),
          type: "public-key",
          response: {
            clientDataJSON: bytes("client"),
            authenticatorData: bytes("auth"),
            signature: bytes("sig"),
            getTransports: () => ["usb"],
          },
          getClientExtensionResults: () => ({}),
        };
        Object.defineProperty(window.navigator, "credentials", {
          configurable: true,
          value: {
            get: async (request) => {
              browser.gets.push(request);
              if (options.keyError) throw options.keyError;
              return options.noCredential ? null : credential;
            },
            create: async (request) => {
              browser.creates.push(request);
              return options.noCredential ? null : credential;
            },
          },
        });
      }
      Object.defineProperty(window.navigator, "clipboard", {
        configurable: true,
        value: { writeText: async (text) => void browser.copied.push(text) },
      });
      window.prompt = (question, suggestion) => {
        browser.prompts.push([question, suggestion]);
        return options.promptAnswer === undefined
          ? suggestion
          : options.promptAnswer;
      };
      window.confirm = (question) => {
        browser.confirms.push(question);
        return options.confirm !== false;
      };
    },
    api: async (method, path, body) => {
      const step = path.replace("/v1/auth/mfa/", "");
      const custom = options.api?.(step, body, server);
      if (custom) return custom;
      if (step === "state") return [200, server];
      if (step === "verify-code") {
        server.stage = "ready";
        return [200, {}];
      }
      if (step === "webauthn/options")
        return [
          200,
          {
            challenge: b64("challenge"),
            allowCredentials: [{ id: b64("raw"), type: "public-key" }],
          },
        ];
      if (step === "webauthn/verify") {
        server.stage = "ready";
        return [200, {}];
      }
      if (step === "webauthn/register-options")
        return [
          200,
          {
            challenge: b64("challenge"),
            user: { id: b64("user"), name: "ada" },
            excludeCredentials: [],
          },
        ];
      if (step === "webauthn/register") {
        server.credentials = [
          ...server.credentials,
          { id: "cred-1", name: body.name },
        ];
        return [200, { recovery_codes: ["aaaa-1111", "bbbb-2222"] }];
      }
      if (step === "totp/start")
        return [200, { qr: "data:image/png;base64,QR", secret: "JBSWY3DP" }];
      if (step === "totp/confirm") {
        server.totp = true;
        return [200, { recovery_codes: ["cccc-3333"] }];
      }
      if (step === "recovery/regenerate") {
        server.recovery_codes_remaining = 10;
        return [200, { recovery_codes: ["dddd-4444"] }];
      }
      if (step === "remove") {
        if (body.id === "totp") server.totp = false;
        else
          server.credentials = server.credentials.filter(
            (c) => c.id !== body.id,
          );
        return [200, {}];
      }
      return [200, {}];
    },
  });
  t.after(page.close);
  const wait = async (turns = 30) => {
    for (let i = 0; i < turns; i += 1) await page.settle();
  };
  await wait();
  const $ = (id) => page.document.getElementById(id);
  return {
    ...page,
    $,
    wait,
    server,
    browser,
    steps: () =>
      page.requests.map(([, path]) => path.replace("/v1/auth/mfa/", "")),
    sent: (step) =>
      page.requests
        .filter(([, path]) => path.endsWith("/" + step))
        .map(([, , body]) => body),
    alert: () => [$("message").textContent, $("message").className],
    navigations: () =>
      page.errors.filter((e) => /navigation/i.test(String(e?.message || e)))
        .length,
    async click(id) {
      $(id).click();
      await wait();
    },
    async submit(id) {
      $(id).dispatchEvent(
        new page.window.Event("submit", { cancelable: true }),
      );
      await wait();
    },
  };
}

test("sign-in asks for the authenticator code and continues once verified", async (t) => {
  const page = await mfa(t, { query: "?next=/project.html%3Fid%3D5" });
  assert.equal(
    page.$("intro").textContent,
    "Enter the code from your authenticator app.",
  );
  assert.equal(page.$("verify").hidden, false);
  assert.equal(page.$("codeForm").hidden, false);
  assert.equal(page.$("keyPrompt").hidden, true);
  assert.equal(page.$("codeLabel").textContent, "Six-digit authenticator code");
  assert.equal(page.$("code").inputMode, "numeric");
  assert.equal(page.$("manage").hidden, true);

  page.$("code").value = "123456";
  await page.submit("codeForm");
  assert.deepEqual(page.sent("verify-code"), [
    { kind: "totp", code: "123456" },
  ]);
  assert.deepEqual(page.steps(), ["state", "verify-code", "state", "finish"]);
  // The method is remembered for next time, and the browser moves on.
  assert.equal(
    page.window.localStorage.getItem("ospmae.mfa.method:ada"),
    "totp",
  );
  assert.equal(page.navigations(), 1);
});

test("every write carries the CSRF token, wherever its cookie sits", async (t) => {
  // Another cookie is set first, so the token is not the first one listed.
  const page = await mfa(t, { cookies: "theme=ink" });
  page.window.document.cookie = "ospmae_csrf=tok%3Den";
  assert.equal(page.window.document.cookie, "theme=ink; ospmae_csrf=tok%3Den");
  page.$("code").value = "123456";
  await page.submit("codeForm");
  const headers = page.requestHeaders[page.requestHeaders.length - 1];
  assert.equal(headers["X-CSRF-Token"], "tok=en");
  assert.equal(headers["Content-Type"], "application/json");
  const none = await mfa(t, { cookies: "theme=ink" });
  assert.equal("X-CSRF-Token" in none.requestHeaders[0], false);
});

test("the host-bound CSRF cookie is read ahead of one a sibling site could plant", async (t) => {
  const page = await mfa(t, { cookies: "ospmae_csrf=planted" });
  page.window.document.cookie = "__Host-ospmae_csrf=iss%3Dued; Secure; Path=/";
  assert.match(page.window.document.cookie, /ospmae_csrf=planted/);
  page.$("code").value = "123456";
  await page.submit("codeForm");
  const headers = page.requestHeaders[page.requestHeaders.length - 1];
  assert.equal(headers["X-CSRF-Token"], "iss=ued");
  // A cookie whose name only ends with the expected one gives no token.
  const other = await mfa(t, { cookies: "my_ospmae_csrf=other" });
  assert.equal("X-CSRF-Token" in other.requestHeaders[0], false);
});

test("a wrong code offers the other methods", async (t) => {
  const page = await mfa(t, {
    state: { credentials: [{ id: "cred-1", name: "YubiKey" }] },
    saved: "totp",
    api: (step) =>
      step === "verify-code"
        ? [400, { detail: "That code is not valid." }]
        : null,
  });
  // The remembered method wins over the security key.
  assert.equal(page.$("codeForm").hidden, false);
  assert.equal(page.browser.gets.length, 0);
  page.$("code").value = "000000";
  await page.submit("codeForm");
  assert.deepEqual(page.alert(), [
    "That code is not valid.",
    "alert alert-danger",
  ]);
  assert.equal(page.$("alternatives").hidden, false);
  assert.deepEqual(
    ["chooseKey", "chooseTotp", "chooseRecovery"].map(
      (id) => page.$(id).hidden,
    ),
    [false, false, false],
  );

  await page.click("chooseRecovery");
  assert.equal(
    page.$("intro").textContent,
    "Enter one of your unused recovery codes.",
  );
  assert.equal(page.$("codeLabel").textContent, "Recovery code");
  assert.equal(page.$("code").inputMode, "text");
  assert.equal(page.$("message").className, "alert d-none");
  assert.equal(page.$("alternatives").hidden, true);
  await page.click("showAlternatives");
  assert.equal(page.$("alternatives").hidden, false);
  await page.click("chooseTotp");
  assert.equal(page.$("codeLabel").textContent, "Six-digit authenticator code");
});

test("a recovery code signs in but is never remembered as the usual method", async (t) => {
  const page = await mfa(t, { state: { totp: false, purpose: "manage" } });
  assert.equal(
    page.$("intro").textContent,
    "Enter one of your unused recovery codes.",
  );
  page.$("code").value = "aaaa-1111";
  await page.submit("codeForm");
  assert.deepEqual(page.sent("verify-code"), [
    { kind: "recovery", code: "aaaa-1111" },
  ]);
  assert.equal(page.window.localStorage.getItem("ospmae.mfa.method:ada"), null);
  // Managing factors does not leave the page by itself.
  assert.equal(page.navigations(), 0);
  assert.equal(page.$("intro").textContent, "Verification complete.");
  assert.equal(page.$("finish").hidden, false);
});

test("a security key is tried straight away when one is registered", async (t) => {
  const page = await mfa(t, {
    state: { credentials: [{ id: "cred-1", name: "YubiKey" }] },
  });
  assert.equal(page.browser.gets.length, 1);
  // The challenge and credential ids reach the browser as bytes.
  const request = page.browser.gets[0].publicKey;
  assert.equal(Buffer.from(request.challenge).toString(), "challenge");
  assert.equal(Buffer.from(request.allowCredentials[0].id).toString(), "raw");
  assert.deepEqual(page.sent("webauthn/verify"), [
    {
      credential: {
        id: "cred-1",
        rawId: b64("raw"),
        type: "public-key",
        response: {
          clientDataJSON: b64("client"),
          authenticatorData: b64("auth"),
          signature: b64("sig"),
          transports: ["usb"],
        },
        clientExtensionResults: {},
      },
    },
  ]);
  assert.equal(
    page.window.localStorage.getItem("ospmae.mfa.method:ada"),
    "webauthn",
  );
  assert.equal(page.navigations(), 1);
});

test("a cancelled, missing or unsupported security key explains and offers alternatives", async (t) => {
  const cancelled = Object.assign(new Error("The operation was aborted"), {
    name: "NotAllowedError",
  });
  const page = await mfa(t, {
    state: { credentials: [{ id: "cred-1", name: "YubiKey" }] },
    keyError: cancelled,
  });
  assert.equal(page.$("keyPrompt").hidden, false);
  assert.deepEqual(page.alert(), [
    "Security key verification was cancelled or timed out. Try again or choose another method.",
    "alert alert-danger",
  ]);
  assert.equal(page.$("alternatives").hidden, false);
  await page.click("useKey");
  await page.click("chooseKey");
  assert.equal(page.browser.gets.length, 3);
  assert.equal(page.navigations(), 0);

  const nothing = await mfa(t, {
    state: { credentials: [{ id: "cred-1", name: "YubiKey" }] },
    noCredential: true,
  });
  assert.equal(
    nothing.alert()[0],
    "Verification was cancelled. Try again or choose another method.",
  );

  const old = await mfa(t, {
    state: { credentials: [{ id: "cred-1", name: "YubiKey" }] },
    webauthn: false,
  });
  assert.equal(
    old.alert()[0],
    "This browser cannot use security keys/passkeys. Choose another method.",
  );
  assert.equal(old.steps().filter((s) => s.startsWith("webauthn")).length, 0);
});

test("managing factors lists them and removes one after confirmation", async (t) => {
  const page = await mfa(t, {
    state: {
      stage: "manage",
      purpose: "manage",
      credentials: [{ id: "cred-9", name: "Work <key>" }],
    },
  });
  assert.equal(
    page.$("intro").textContent,
    "Choose an authenticator for your local OSPMAE account.",
  );
  assert.equal(page.$("manage").hidden, false);
  assert.equal(page.$("verify").hidden, true);
  assert.equal(page.$("remaining").textContent, "8 recovery codes remaining.");
  assert.equal(page.$("addTotp").hidden, true);
  assert.equal(page.$("regenerate").hidden, false);
  const rows = [...page.$("factors").children];
  assert.deepEqual(
    rows.map((row) => row.querySelector("span").textContent),
    ["Authenticator app", "Work <key>"],
  );
  assert.equal(page.$("factors").querySelector("key"), null);

  rows[1].querySelector("button").click();
  await page.wait();
  assert.match(page.browser.confirms[0], /^Remove Work <key>\?/);
  assert.deepEqual(page.sent("remove"), [{ id: "cred-9" }]);
  assert.equal(page.$("factors").children.length, 1);
  page.$("factors").querySelector("button").click();
  await page.wait();
  assert.deepEqual(page.sent("remove")[1], { id: "totp" });
  assert.equal(page.$("factors").children.length, 0);
  assert.equal(page.$("addTotp").hidden, false);
  assert.equal(page.$("regenerate").hidden, true);
});

test("declining a confirmation changes nothing", async (t) => {
  const page = await mfa(t, {
    state: { stage: "manage", purpose: "manage" },
    confirm: false,
  });
  page.$("factors").querySelector("button").click();
  await page.wait();
  await page.click("regenerate");
  assert.equal(page.browser.confirms.length, 2);
  assert.deepEqual(page.steps(), ["state"]);
});

test("setting up an authenticator app shows the secret, then the recovery codes", async (t) => {
  const page = await mfa(t, {
    state: {
      stage: "enrol",
      purpose: "manage",
      totp: false,
      recovery_codes_remaining: 0,
      required: true,
    },
  });
  // Nothing to finish with while a factor is required and none exists.
  assert.equal(page.$("finish").hidden, true);
  assert.equal(page.$("chooseRecovery").hidden, true);
  await page.click("addTotp");
  assert.equal(page.$("totpSetup").hidden, false);
  assert.equal(page.$("secret").textContent, "JBSWY3DP");
  const qr = page.$("qr");
  assert.equal(qr.getAttribute("src"), "data:image/png;base64,QR");
  assert.equal(qr.hidden, true);
  qr.dispatchEvent(new page.window.Event("load"));
  assert.equal(qr.hidden, false);

  page.$("confirmCode").value = "654321";
  await page.submit("confirmForm");
  assert.deepEqual(page.sent("totp/confirm"), [{ code: "654321" }]);
  assert.equal(page.$("totpSetup").hidden, true);
  assert.equal(page.$("secret").textContent, "");
  assert.equal(qr.hasAttribute("src"), false);
  assert.equal(page.$("codesPanel").hidden, false);
  assert.equal(page.$("recoveryCodes").textContent, "cccc-3333");

  // The codes must be acknowledged before the page lets go.
  page.server.stage = "manage";
  await page.click("regenerate");
  assert.equal(page.$("recoveryCodes").textContent, "dddd-4444");
  assert.equal(page.$("finish").hidden, false);
  assert.equal(page.$("finish").disabled, true);
  await page.click("copyCodes");
  assert.deepEqual(page.browser.copied, ["dddd-4444"]);
  assert.deepEqual(page.alert(), [
    "Recovery codes copied. Store them securely.",
    "alert alert-success",
  ]);
  page.$("savedCodes").checked = true;
  page.$("savedCodes").dispatchEvent(new page.window.Event("change"));
  assert.equal(page.$("finish").disabled, false);
  await page.click("finish");
  assert.equal(page.steps().at(-1), "finish");
  assert.equal(page.navigations(), 1);
});

test("adding a security key names it and registers the credential", async (t) => {
  const page = await mfa(t, {
    state: { stage: "manage", purpose: "manage" },
    promptAnswer: "Desk key",
  });
  await page.click("addKey");
  assert.equal(page.browser.prompts[0][1], "Security key / passkey");
  const request = page.browser.creates[0].publicKey;
  assert.equal(Buffer.from(request.user.id).toString(), "user");
  assert.equal(page.sent("webauthn/register")[0].name, "Desk key");
  assert.equal(page.sent("webauthn/register")[0].credential.id, "cred-1");
  assert.equal(page.$("recoveryCodes").textContent, "aaaa-1111\nbbbb-2222");
  assert.deepEqual(
    [...page.$("factors").children].map(
      (row) => row.querySelector("span").textContent,
    ),
    ["Authenticator app", "Desk key"],
  );

  const unnamed = await mfa(t, {
    state: { stage: "manage", purpose: "manage" },
    promptAnswer: "",
  });
  await unnamed.click("addKey");
  assert.equal(unnamed.browser.creates.length, 0);

  const cancelled = await mfa(t, {
    state: { stage: "manage", purpose: "manage" },
    noCredential: true,
  });
  await cancelled.click("addKey");
  assert.deepEqual(cancelled.alert(), [
    "Registration was cancelled.",
    "alert alert-danger",
  ]);

  const old = await mfa(t, {
    state: { stage: "manage", purpose: "manage" },
    webauthn: false,
  });
  await old.click("addKey");
  assert.deepEqual(old.alert(), [
    "Use a browser supporting WebAuthn over HTTPS.",
    "alert alert-danger",
  ]);
});

test("server refusals are shown, in the server's words when it gives them", async (t) => {
  const page = await mfa(t, {
    state: { stage: "manage", purpose: "manage", totp: false },
    api: (step) => {
      if (step === "totp/start")
        return [429, { detail: "Too many attempts. Try again later." }];
      if (step === "cancel") return [400, { detail: [{ msg: "structured" }] }];
      return null;
    },
  });
  await page.click("addTotp");
  assert.deepEqual(page.alert(), [
    "Too many attempts. Try again later.",
    "alert alert-danger",
  ]);
  assert.equal(page.$("totpSetup").hidden, true);
  // Controls come back after a failure.
  assert.equal(page.$("addTotp").disabled, false);
  await page.click("cancel");
  assert.deepEqual(page.alert(), [
    "Verification failed. Please start again.",
    "alert alert-danger",
  ]);
  assert.equal(page.navigations(), 0);
});

test("cancel ends the ceremony and returns to sign in", async (t) => {
  const page = await mfa(t);
  await page.click("cancel");
  assert.equal(page.steps().at(-1), "cancel");
  assert.equal(page.navigations(), 1);
});
