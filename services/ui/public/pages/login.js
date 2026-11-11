(() => {
  const msgEl = document.getElementById("msg");
  const form = document.getElementById("loginForm");
  const btn = document.getElementById("loginBtn");
  const forgotWrap = document.getElementById("forgotWrap");

  const ssoSection = document.getElementById("ssoSection");
  const ssoButtons = document.getElementById("ssoButtons");

  let redirectAllowedHosts = [];

  function _normalizeAllowedHosts(raw) {
    if (!Array.isArray(raw)) return [];
    const out = [];
    for (const v of raw) {
      const h = String(v || "")
        .trim()
        .toLowerCase();
      if (!h) continue;
      if (h.includes("://") || h.includes("/") || h.includes("\\")) continue;
      out.push(h);
    }
    return out;
  }

  function sanitizeNext(rawNext) {
    const raw = String(rawNext || "").trim();
    if (!raw) return "/index.html";
    if (raw.startsWith("//")) return "/index.html";
    // Browsers resolve backslashes and control characters before a navigation
    // leaves the page; a next value containing either never replays as-is.
    if (/[\\\u0000-\u001f\u007f]/.test(raw)) return "/index.html";
    if (raw.startsWith("/") && !raw.includes("://")) return raw;

    let u;
    try {
      u = new URL(raw, window.location.origin);
    } catch (_) {
      return "/index.html";
    }

    if (u.protocol !== "http:" && u.protocol !== "https:") return "/index.html";
    if (u.origin === window.location.origin)
      return u.pathname + u.search + u.hash;

    const host = String(u.hostname || "")
      .trim()
      .toLowerCase();
    if (u.protocol === "https:" && host && redirectAllowedHosts.includes(host))
      return u.toString();
    return "/index.html";
  }

  function getNextParam() {
    return new URLSearchParams(window.location.search).get("next") || "";
  }

  // Messages show as an alert above the form, as on KEEN's sign-in page.
  function setMsg(text, kind = "info") {
    if (!msgEl) return;
    msgEl.textContent = text || "";
    msgEl.className = `alert ${kind === "error" ? "alert-danger" : "alert-info"}`;
    msgEl.hidden = !text;
  }

  function iconForProvider(key) {
    const k = String(key || "").toLowerCase();
    if (k === "github") return "bi-github";
    if (k === "google") return "bi-google";
    return "bi-shield-lock";
  }

  function renderSsoButtons(methods) {
    if (!ssoSection || !ssoButtons) return;

    let providers = Array.isArray(methods?.sso_providers)
      ? methods.sso_providers
      : [];
    if (!providers.length && methods?.oidc_enabled && methods?.oidc) {
      providers = [
        {
          key: "oidc",
          label: methods.oidc.label || "Single sign-on",
          start_url: methods.oidc.start_url || "/v1/auth/oidc/start",
        },
      ];
    }
    if (!providers.length) return;

    ssoButtons.replaceChildren();
    for (const provider of providers) {
      const label =
        String(provider?.label || "single sign-on").trim() || "single sign-on";
      const key = String(provider?.key || "")
        .trim()
        .toLowerCase();
      const startUrl =
        String(provider?.start_url || "").trim() || "/v1/auth/oidc/start";

      const button = document.createElement("button");
      button.className = "btn btn-outline-primary w-100";
      button.type = "button";
      const icon = document.createElement("i");
      icon.className = `bi ${iconForProvider(key)} me-1`;
      const text = document.createElement("span");
      text.textContent = `Continue with ${label}`;
      button.append(icon, text);
      button.addEventListener("click", () => {
        const next = sanitizeNext(getNextParam());
        const u = new URL(startUrl, window.location.origin);
        if (next) u.searchParams.set("next", next);
        window.location.assign(u.pathname + u.search);
      });
      ssoButtons.appendChild(button);
    }
    ssoSection.classList.remove("d-none");
  }

  async function initAuthMethods() {
    try {
      const methods = await window.OSPMAE?.api?.("/v1/auth/methods", {
        allowErrorStatuses: [404, 500],
      });
      if (!methods) return null;

      redirectAllowedHosts = _normalizeAllowedHosts(
        methods.redirect_allowed_hosts,
      );
      renderSsoButtons(methods);

      if (methods.local_enabled === false && form) {
        form.classList.add("d-none");
        const divider = ssoSection?.querySelector("[data-sso-divider]");
        if (divider) divider.classList.add("d-none");
        setMsg("Sign in using one of the enabled single sign-on providers.");
      }

      if (methods.password_reset_enabled && forgotWrap)
        forgotWrap.classList.remove("d-none");
      return methods;
    } catch (err) {
      console.warn("Auth methods unavailable", err);
      return null;
    }
  }

  async function pingMe() {
    try {
      const me = await window.OSPMAE?.api?.("/v1/me", {
        allowErrorStatuses: [401],
      });
      if (me && me.username) {
        const role = String(me.effective_role || me.role || "").toLowerCase();
        window.location.replace(
          role === "pending" ? "/pending.html" : sanitizeNext(getNextParam()),
        );
      }
    } catch (_) {
      // not signed in
    }
  }

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    btn.disabled = true;
    setMsg("Signing in…");

    const username = String(
      document.getElementById("username")?.value || "",
    ).trim();
    const password = String(document.getElementById("password")?.value || "");

    try {
      if (!username || !password) {
        setMsg("Please provide username and password.", "error");
        return;
      }

      const res = await window.OSPMAE?.api?.("/v1/auth/login", {
        method: "POST",
        body: { username, password },
      });
      if (!res) {
        setMsg("Login failed.", "error");
        return;
      }

      if (res.mfa_required) {
        setMsg("Second factor required. Redirecting…");
        window.location.replace("/mfa.html");
        return;
      }

      setMsg("Signed in. Redirecting…");
      const role = String(res.effective_role || res.role || "").toLowerCase();
      window.location.replace(
        role === "pending" ? "/pending.html" : sanitizeNext(getNextParam()),
      );
    } catch (err) {
      // The server's own reason, such as a wrong password or a wait after
      // too many attempts.
      setMsg(
        err?.message || "Login failed. Please check your credentials.",
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
    document.getElementById("loginFields").disabled = false;
    document.getElementById("loginLoading").hidden = true;
    document.getElementById("username")?.focus();
  }

  (async () => {
    await initAuthMethods();
    await pingMe();
  })();
})();
