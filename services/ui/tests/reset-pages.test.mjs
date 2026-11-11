// The password reset pages open their fields, focused, once they can submit.
import test from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./support/load-page.mjs";

for (const [html, script, first, form] of [
  [
    "forgot-password.html",
    "pages/forgot-password.js",
    "identifier",
    "resetRequestForm",
  ],
  [
    "reset-password.html",
    "pages/reset-password.js",
    "newPassword",
    "resetForm",
  ],
]) {
  test(`${html} starts closed and opens focused`, async (t) => {
    const page = await loadPage(html, script, {
      url: `https://ospmae.example/${html}?token=abc`,
      ospmae: { api: async () => ({ password_reset_enabled: true }) },
    });
    t.after(page.close);
    await page.settle();
    const { document } = page;
    assert.equal(document.getElementById("formFields").disabled, false);
    assert.equal(document.getElementById("formLoading").hidden, true);
    assert.equal(document.activeElement?.id, first);
    assert.equal(document.getElementById(form).getAttribute("method"), "post");
  });
}
