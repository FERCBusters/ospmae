(() => {
  const msgEl = document.getElementById("msg");
  const form = document.getElementById("resetForm");
  const btn = document.getElementById("resetBtn");

  function setMsg(text, kind = "info") {
    if (!msgEl) return;
    msgEl.textContent = text || "";
    msgEl.className =
      "small mb-2 " + (kind === "error" ? "text-danger" : "text-secondary");
  }

  function getToken() {
    return new URLSearchParams(window.location.search).get("token") || "";
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

    const token = getToken();
    const new_password = String(
      document.getElementById("newPassword")?.value || "",
    );
    const confirm_password = String(
      document.getElementById("confirmPassword")?.value || "",
    );

    if (!token) {
      setMsg("Missing reset token. Please request a new reset link.", "error");
      btn.disabled = false;
      return;
    }
    if (!new_password || new_password.length < 8) {
      setMsg("Password must be at least 8 characters.", "error");
      btn.disabled = false;
      return;
    }
    if (new_password !== confirm_password) {
      setMsg("Passwords do not match.", "error");
      btn.disabled = false;
      return;
    }

    try {
      setMsg("Resetting password…");
      await window.OSPMAE?.api?.("/v1/auth/reset-password", {
        method: "POST",
        body: { token, new_password, confirm_password },
      });
      setMsg("Password updated. Redirecting…");
      window.setTimeout(() => window.location.replace("/login.html"), 800);
    } catch (err) {
      console.error(err);
      setMsg(
        err?.message || "Reset failed. The link may have expired.",
        "error",
      );
    } finally {
      btn.disabled = false;
    }
  });

  // Fields start disabled, so nothing can be submitted natively (which would
  // put what was typed in the page's own request) until this handler exists.
  // An autofocus attribute is lost while they are disabled, so focus the
  // first field here and typing can start straight away; as on KEEN's page.
  if (form) {
    document.getElementById("formFields").disabled = false;
    document.getElementById("formLoading").hidden = true;
    document.getElementById("newPassword")?.focus();
  }

  ensureEnabled();
})();
