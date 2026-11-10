(() => {
  const msgEl = document.getElementById("msg");
  const form = document.getElementById("resetRequestForm");
  const btn = document.getElementById("sendBtn");

  function setMsg(text, kind = "info") {
    if (!msgEl) return;
    msgEl.textContent = text || "";
    msgEl.className =
      "small mb-2 " + (kind === "error" ? "text-danger" : "text-secondary");
  }

  async function ensureEnabled() {
    try {
      const methods = await window.OSPMAE?.api?.("/v1/auth/methods", {
        allowErrorStatuses: [404, 500],
      });
      if (!methods || !methods.password_reset_enabled) {
        window.location.replace("/login.html");
      }
    } catch {
      window.location.replace("/login.html");
    }
  }

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    btn.disabled = true;
    setMsg("Sending…");

    const identifier = String(
      document.getElementById("identifier")?.value || "",
    ).trim();
    if (!identifier) {
      setMsg("Please enter your email or username.", "error");
      btn.disabled = false;
      return;
    }

    try {
      await window.OSPMAE?.api?.("/v1/auth/request-password-reset", {
        method: "POST",
        body: { identifier },
        allowErrorStatuses: [204],
      });
      setMsg(
        "If your account exists, a reset link has been sent. Check your inbox.",
        "info",
      );
    } catch (err) {
      console.error(err);
      // Don't leak details; keep message generic.
      setMsg(
        "If your account exists, a reset link has been sent. Check your inbox.",
        "info",
      );
    } finally {
      btn.disabled = false;
    }
  });

  ensureEnabled();
})();
