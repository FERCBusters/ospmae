(() => {
  const OSPMAE = window.OSPMAE;
  if (!OSPMAE) {
    console.error("OSPMAE global not found. Did /app.js load?");
    return;
  }

  const {
    initAuth,
    loadFrameworks,
    getFrameworks,
    getActiveFramework,
    setActiveFrameworkByMachineName,
    loadFrameworkNodes,
    getUserPreferences,
    saveUserPreferences,
    nodeColor,
    getNodeColorOverrides,
    DEFAULT_NODE_COLORS,
    ALLOWED_START_PAGES,
    canMaintainProjects,
    canExportManifests,
    toast,
    api,
  } = OSPMAE;

  // Theme palettes come from the shared design system; the server may narrow
  // them per deployment through available_themes on /v1/me.
  const THEMES =
    window.mospUi &&
    Array.isArray(window.mospUi.THEMES) &&
    window.mospUi.THEMES.length
      ? window.mospUi.THEMES
      : [{ id: "ink", name: "Ink" }];

  const state = {
    me: null,
    frameworks: [],
    activeFramework: null,
    paletteNodes: [],
    overrides: {},
    prefs: {},
    shortcuts: [],
    subscriptions: [],
    emails: [],
  };

  const el = {
    profileUser: document.getElementById("profileUser"),
    profileUsername: document.getElementById("profileUsername"),
    profileRole: document.getElementById("profileRole"),
    profileEmailInput: document.getElementById("profileEmailInput"),
    saveEmailBtn: document.getElementById("saveEmailBtn"),
    profileEmailMsg: document.getElementById("profileEmailMsg"),
    linkedEmailInput: document.getElementById("linkedEmailInput"),
    linkedEmailPrimary: document.getElementById("linkedEmailPrimary"),
    addLinkedEmailBtn: document.getElementById("addLinkedEmailBtn"),
    linkedEmailsList: document.getElementById("linkedEmailsList"),
    linkedEmailMsg: document.getElementById("linkedEmailMsg"),
    prefTheme: document.getElementById("prefTheme"),
    prefSticky: document.getElementById("prefSticky"),
    prefAutoApply: document.getElementById("prefAutoApply"),
    defaultStartPage: document.getElementById("defaultStartPage"),
    frameworkSelect: document.getElementById("frameworkSelect"),
    colorRows: document.getElementById("colorRows"),
    saveColorsBtn: document.getElementById("saveColorsBtn"),
    resetColorsBtn: document.getElementById("resetColorsBtn"),
    shortcutsList: document.getElementById("shortcutsList"),
    shortcutName: document.getElementById("shortcutName"),
    shortcutUrl: document.getElementById("shortcutUrl"),
    addShortcutBtn: document.getElementById("addShortcutBtn"),
    subscriptionsList: document.getElementById("subscriptionsList"),
    subscriptionsMsg: document.getElementById("subscriptionsMsg"),
    passwordCard: document.getElementById("passwordCard"),
    passwordUnavailableMsg: document.getElementById("passwordUnavailableMsg"),
    mfaCard: document.getElementById("mfaCard"),
    mailCard: document.getElementById("mailCard"),
    mailSummary: document.getElementById("mailSummary"),
    mailList: document.getElementById("mailList"),
    securitySummary: document.getElementById("securitySummary"),
    securityForm: document.getElementById("securityForm"),
    securityPassword: document.getElementById("securityPassword"),
    manageMfaBtn: document.getElementById("manageMfaBtn"),
    mfaMsg: document.getElementById("mfaMsg"),
    changePasswordForm: document.getElementById("changePasswordForm"),
    currentPassword: document.getElementById("currentPassword"),
    newPassword: document.getElementById("newPassword"),
    confirmPassword: document.getElementById("confirmPassword"),
    passwordMsg: document.getElementById("passwordMsg"),
  };

  function initAccountTabs() {
    // Optional hash-based navigation: #profile, #preferences, #subscriptions, #shortcuts, #password
    const hash = String(window.location.hash || "")
      .replace("#", "")
      .trim()
      .toLowerCase();
    if (hash) {
      const btn = document.querySelector(
        `#accountTabs button[data-hash="${hash}"]`,
      );
      if (btn && window.bootstrap?.Tab) {
        try {
          const tab = new window.bootstrap.Tab(btn);
          tab.show();
        } catch {}
      }
    }

    document
      .querySelectorAll('#accountTabs button[data-bs-toggle="tab"]')
      .forEach((btn) => {
        btn.addEventListener("shown.bs.tab", (e) => {
          const target = e?.target?.getAttribute?.("data-hash");
          if (!target) return;
          try {
            history.replaceState(null, "", `#${target}`);
          } catch {}
        });
      });
  }

  async function saveEmail() {
    const raw = String(el.profileEmailInput?.value || "").trim();
    const email = raw || null;
    const emailEditable = state?.me?.email_editable !== false;
    if (!emailEditable) {
      toast(
        "Email is managed by single sign-on and cannot be changed here.",
        "error",
      );
      return;
    }
    try {
      const res = await api("/v1/me/profile", {
        method: "PUT",
        body: { email },
      });
      state.me.email = res?.email ?? email;
      if (el.profileEmailMsg) {
        el.profileEmailMsg.textContent = "Saved.";
      }
      toast("Email saved", "success");
    } catch (err) {
      console.error(err);
      if (el.profileEmailMsg) {
        el.profileEmailMsg.textContent =
          err?.message || "Failed to save email.";
      }
      toast(err?.message || "Failed to save email", "error");
    }
  }

  function esc(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }
  function renderLinkedEmails() {
    if (!el.linkedEmailsList) return;
    const items = Array.isArray(state.emails) ? state.emails : [];
    if (!items.length) {
      el.linkedEmailsList.innerHTML =
        '<div class="small text-muted">No linked emails yet.</div>';
      return;
    }
    el.linkedEmailsList.innerHTML = `
      <div class="table-responsive">
        <table class="table table-sm align-middle mb-0">
          <thead><tr><th>Email</th><th>Source</th><th>Status</th><th class="text-end">Actions</th></tr></thead>
          <tbody>
            ${items
              .map((item) => {
                const id = Number(item.id || 0);
                const primary = item.is_primary
                  ? '<span class="badge text-bg-primary ms-1">Primary</span>'
                  : "";
                const verified = item.is_verified
                  ? '<span class="badge text-bg-success">Trusted</span>'
                  : '<span class="badge text-bg-secondary">Unverified</span>';
                const source = String(item.source || "user").replace(
                  /^sso:/,
                  "SSO: ",
                );
                return `
                <tr data-email-id="${id}">
                  <td class="font-monospace">${esc(item.email || "")}${primary}</td>
                  <td>${esc(source)}</td>
                  <td>${verified}</td>
                  <td class="text-end">
                    <div class="btn-group btn-group-sm">
                      <button class="btn btn-outline-secondary" type="button" data-action="primary" ${item.is_primary ? "disabled" : ""}>Make primary</button>
                      <button class="btn btn-outline-secondary" type="button" data-action="verify">Send verification</button>
                      <button class="btn btn-outline-danger" type="button" data-action="delete"><i class="bi bi-trash"></i></button>
                    </div>
                  </td>
                </tr>`;
              })
              .join("")}
          </tbody>
        </table>
      </div>`;
  }

  async function loadLinkedEmails() {
    const data = await api("/v1/me/emails");
    state.emails = Array.isArray(data?.items) ? data.items : [];
    renderLinkedEmails();
  }

  async function addLinkedEmail() {
    const email = String(el.linkedEmailInput?.value || "").trim();
    if (!email) {
      toast("Enter an email address to add.", "error");
      return;
    }
    const item = await api("/v1/me/emails", {
      method: "POST",
      body: { email, is_primary: Boolean(el.linkedEmailPrimary?.checked) },
    });
    if (el.linkedEmailInput) el.linkedEmailInput.value = "";
    if (el.linkedEmailPrimary) el.linkedEmailPrimary.checked = false;
    await loadLinkedEmails();
    if (item?.is_primary && el.profileEmailInput)
      el.profileEmailInput.value = item.email || "";
    toast("Email linked.", "success");
  }

  async function makeLinkedEmailPrimary(id) {
    const item = await api(`/v1/me/emails/${encodeURIComponent(id)}/primary`, {
      method: "POST",
    });
    await loadLinkedEmails();
    if (item?.email && el.profileEmailInput)
      el.profileEmailInput.value = item.email;
    toast("Primary email updated.", "success");
  }

  async function deleteLinkedEmail(id) {
    await api(`/v1/me/emails/${encodeURIComponent(id)}`, { method: "DELETE" });
    await loadLinkedEmails();
    toast("Email removed.", "success");
  }

  async function requestEmailVerification(id) {
    await api(`/v1/me/emails/${encodeURIComponent(id)}/verify-request`, {
      method: "POST",
    });
    await loadLinkedEmails();
    toast("Verification email sent.", "success");
  }

  async function completePendingEmailVerification() {
    const token = new URLSearchParams(window.location.search).get(
      "verify_email",
    );
    if (!token) return;
    try {
      const res = await api("/v1/me/emails/verify", {
        method: "POST",
        body: { token },
      });
      toast(`Email ${res?.verified || ""} verified.`, "success");
      await loadLinkedEmails();

      await loadMfaStatus();
    } catch (err) {
      toast(err?.message || "Verification link invalid or expired", "error");
    }
    // Strip the one-time token from the address bar once it is used.
    const url = new URL(window.location.href);
    url.searchParams.delete("verify_email");
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
  }

  function safeHref(url) {
    const fn =
      window.mospUi && typeof window.mospUi.safeExternalHref === "function"
        ? window.mospUi.safeExternalHref
        : null;
    if (fn) return fn(url) || "";
    const raw = String(url ?? "").trim();
    if (!raw) return "";
    if (/^(?:javascript|data|vbscript):/i.test(raw)) return "";
    if (raw.startsWith("//")) return "";
    if (/[\\\u0000-\u001f\u007f]/.test(raw)) return "";
    if (raw.startsWith("/")) return raw;
    try {
      const u = new URL(raw);
      const p = String(u.protocol || "").toLowerCase();
      if (p === "http:" || p === "https:") return u.href;
    } catch (_) {
      // ignore
    }
    return "";
  }

  function renderSubscriptions() {
    if (!el.subscriptionsList) return;
    const items = Array.isArray(state.subscriptions) ? state.subscriptions : [];
    if (!items.length) {
      el.subscriptionsList.innerHTML =
        '<div class="text-muted">You are not subscribed to any projects.</div>';
      return;
    }

    el.subscriptionsList.innerHTML = items
      .map((s) => {
        const pid = Number(s.project_id);
        const name =
          s.project_name || s.project_machine_name || `Project ${pid}`;
        const meta = [s.organisation, s.project_type]
          .filter(Boolean)
          .join(" · ");
        const nv = s.notify_new_versions !== false;
        const nq = s.notify_questions === true;
        return `
          <div class="border rounded-3 p-2 mb-2" data-project-id="${pid}">
            <div class="d-flex flex-wrap gap-3 align-items-center justify-content-between">
              <div class="me-2">
                <div class="fw-semibold">
                  <a href="/project.html?id=${pid}" class="text-decoration-none">${esc(name)}</a>
                </div>
                ${meta ? `<div class="small text-muted">${esc(meta)}</div>` : ""}
              </div>
              <div class="d-flex flex-wrap gap-3 align-items-center">
                <div class="form-check form-switch m-0">
                  <input class="form-check-input" type="checkbox" data-sub-field="notify_new_versions" id="sub_nv_${pid}" ${nv ? "checked" : ""} />
                  <label class="form-check-label" for="sub_nv_${pid}">New versions</label>
                </div>
                <div class="form-check form-switch m-0">
                  <input class="form-check-input" type="checkbox" data-sub-field="notify_questions" id="sub_nq_${pid}" ${nq ? "checked" : ""} />
                  <label class="form-check-label" for="sub_nq_${pid}">Questions &amp; replies</label>
                </div>
                <button class="btn btn-sm btn-outline-danger" type="button" data-action="unsubscribe"><i class="bi bi-bell-slash"></i> Unsubscribe</button>
              </div>
            </div>
            <div class="small text-secondary mt-1" data-sub-status="1"></div>
          </div>
        `;
      })
      .join("");
  }

  async function loadSubscriptions() {
    try {
      const res = await api("/v1/me/subscriptions");
      state.subscriptions = Array.isArray(res?.items) ? res.items : [];
      if (el.subscriptionsMsg) el.subscriptionsMsg.textContent = "";
    } catch (err) {
      console.error(err);
      state.subscriptions = [];
      if (el.subscriptionsMsg)
        el.subscriptionsMsg.textContent =
          err?.message || "Failed to load subscriptions.";
    }
  }

  function _rowStatus(row, msg) {
    const elMsg = row?.querySelector?.("[data-sub-status]");
    if (elMsg) elMsg.textContent = msg || "";
  }

  async function saveSubscriptionFromRow(row) {
    const pid = Number(row?.dataset?.projectId);
    if (!pid) return;
    const nv = !!row.querySelector(
      'input[data-sub-field="notify_new_versions"]',
    )?.checked;
    const nq = !!row.querySelector('input[data-sub-field="notify_questions"]')
      ?.checked;

    const inputs = Array.from(row.querySelectorAll("input,button"));
    inputs.forEach((x) => (x.disabled = true));
    _rowStatus(row, "Saving…");

    try {
      const res = await api(`/v1/projects/${pid}/subscription`, {
        method: "POST",
        body: {
          notify_new_versions: nv,
          notify_questions: nq,
        },
      });

      const subscribed = !!res?.subscribed;
      if (!subscribed) {
        // Removed
        row.remove();
        state.subscriptions = (state.subscriptions || []).filter(
          (s) => Number(s.project_id) !== pid,
        );
        renderSubscriptions();
        toast("Unsubscribed.", "success");
        return;
      }

      // Update local state
      const item = (state.subscriptions || []).find(
        (s) => Number(s.project_id) === pid,
      );
      if (item) {
        item.notify_new_versions = !!res?.notify_new_versions;
        item.notify_questions = !!res?.notify_questions;
      }
      _rowStatus(row, "Saved.");
      toast("Subscription updated.", "success");
    } catch (err) {
      console.error(err);
      _rowStatus(row, err?.message || "Failed to save.");
      toast(err?.message || "Failed to update subscription", "error");
    } finally {
      inputs.forEach((x) => (x.disabled = false));
    }
  }

  function roleOf(me) {
    return me?.effective_role || me?.role || "viewer";
  }

  function canMaintainFrameworks(me) {
    const role = roleOf(me);
    return role === "admin" || role === "framework_admin";
  }

  function buildStartPageOptions(me) {
    const role = roleOf(me);
    const opts = [];
    for (const page of ALLOWED_START_PAGES || []) {
      if (page.permission === "public") {
        opts.push(page);
        continue;
      }
      if (page.permission === "manifests") {
        if (canExportManifests()) opts.push(page);
        continue;
      }
      if (page.permission === "project_admin") {
        if (canMaintainProjects()) opts.push(page);
        continue;
      }
      if (page.permission === "framework_admin") {
        if (canMaintainFrameworks(me)) opts.push(page);
        continue;
      }
      if (page.permission === "admin") {
        if (role === "admin") opts.push(page);
      }
    }
    return opts;
  }

  function getTheme() {
    // The account preference is authoritative; fall back to the shared
    // design system default.
    const saved = String(state.prefs?.theme || "").trim();
    return saved || "ink";
  }

  function applyTheme(id) {
    if (window.mospUi && typeof window.mospUi.applyTheme === "function") {
      // The design system keeps the browser in step for the pre-paint boot.
      window.mospUi.applyTheme(id);
      return;
    }
    const themeId = (id || "").trim() || "ink";
    document.documentElement.dataset.theme = themeId;
    try {
      localStorage.setItem("keen_theme", themeId);
    } catch {}
  }

  function renderThemeSelect(meObj) {
    if (!el.prefTheme) return;
    const avail =
      meObj?.available_themes && Array.isArray(meObj.available_themes)
        ? meObj.available_themes
        : THEMES;
    el.prefTheme.innerHTML = avail
      .map(
        (t) =>
          `<option value="${esc(String(t.id))}">${esc(String(t.name))}</option>`,
      )
      .join("");
    el.prefTheme.value = getTheme();
  }

  async function saveStartPage() {
    const payload = {
      ...state.prefs,
      default_start_page:
        el.defaultStartPage?.value ||
        state.prefs?.default_start_page ||
        "/index.html",
      node_colors: state.overrides,
    };
    const saved = await saveUserPreferences(payload);
    state.prefs = saved;
    toast("Preferences saved.");
  }

  function renderStartPageSelect() {
    if (!el.defaultStartPage) return;
    const options = buildStartPageOptions(state.me);
    el.defaultStartPage.innerHTML = options
      .map((p) => `<option value="${esc(p.value)}">${esc(p.label)}</option>`)
      .join("");

    const current = state.prefs?.default_start_page || "";
    if (current && options.some((o) => o.value === current)) {
      el.defaultStartPage.value = current;
    } else {
      el.defaultStartPage.value = options[0]?.value || "/index.html";
    }
  }

  function renderFrameworkSelect() {
    if (!el.frameworkSelect) return;
    el.frameworkSelect.innerHTML = state.frameworks
      .map(
        (f) =>
          `<option value="${esc(f.machine_name)}">${esc(f.display_name || f.machine_name)}</option>`,
      )
      .join("");
    if (state.activeFramework?.machine_name) {
      el.frameworkSelect.value = state.activeFramework.machine_name;
    }
  }

  function computePaletteNodes(flat) {
    const items = (flat || []).map((n) => ({
      id: Number(n.id),
      key: n.key,
      display_name: n.display_name,
      parent_id: n.parent_id,
      level: n.level,
    }));
    return items
      .filter((n) => n.level === 1)
      .sort((a, b) =>
        (a.display_name || "").localeCompare(b.display_name || ""),
      );
  }

  function fullKeyFor(node) {
    const fw = state.activeFramework;
    const prefix = fw?.machine_name ? `${fw.machine_name}:` : "";
    return `${prefix}${node.key}`;
  }

  function renderColorRows() {
    if (!el.colorRows) return;
    if (!state.activeFramework) {
      el.colorRows.innerHTML =
        '<div class="text-muted">No frameworks available.</div>';
      return;
    }
    if (!state.paletteNodes.length) {
      el.colorRows.innerHTML =
        '<div class="text-muted">No categories found for this framework.</div>';
      return;
    }

    const overrides = state.overrides || {};
    el.colorRows.innerHTML = state.paletteNodes
      .map((node) => {
        const fullKey = fullKeyFor(node);
        const effective = nodeColor(fullKey);
        const explicit = overrides[fullKey];
        const defaultColor = DEFAULT_NODE_COLORS?.[fullKey] || effective;
        const badge = explicit
          ? '<span class="badge text-bg-primary">custom</span>'
          : '<span class="badge text-bg-light">default</span>';
        return `
          <div class="d-flex flex-wrap gap-3 align-items-center justify-content-between border rounded-3 p-2 mb-2" data-full-key="${esc(fullKey)}">
            <div class="me-2">
              <div class="fw-semibold">${esc(node.display_name || node.key)}</div>
              <div class="small text-muted">Key: <code>${esc(fullKey)}</code>${defaultColor ? ` <span class="ms-2 text-muted">(default ${esc(defaultColor)})</span>` : ""}</div>
            </div>
            <div class="d-flex gap-2 align-items-center">
              <input type="color" class="form-control form-control-color" value="${esc(explicit || effective || "#64748b")}" data-color-input="1" aria-label="Colour" />
              <button type="button" class="btn btn-sm btn-outline-secondary" data-action="reset">Reset</button>
              ${badge}
            </div>
          </div>
        `;
      })
      .join("");

    el.colorRows
      .querySelectorAll("input[data-color-input]")
      .forEach((input) => {
        input.addEventListener("input", () => {
          const row = input.closest("[data-full-key]");
          const fullKey = row?.dataset?.fullKey;
          if (!fullKey) return;
          state.overrides[fullKey] = input.value;
        });
      });

    el.colorRows
      .querySelectorAll('button[data-action="reset"]')
      .forEach((btn) => {
        btn.addEventListener("click", () => {
          const row = btn.closest("[data-full-key]");
          const fullKey = row?.dataset?.fullKey;
          if (!fullKey) return;
          delete state.overrides[fullKey];
          renderColorRows();
        });
      });
  }

  async function refreshPaletteForFramework() {
    const fw = state.activeFramework;
    if (!fw?.id) {
      state.paletteNodes = [];
      renderColorRows();
      return;
    }
    const { flat } = await loadFrameworkNodes(fw.id);
    state.paletteNodes = computePaletteNodes(flat);
    renderColorRows();
  }

  async function savePreferences() {
    const payload = {
      ...state.prefs,
      default_start_page:
        el.defaultStartPage?.value ||
        state.prefs?.default_start_page ||
        "/index.html",
      node_colors: state.overrides,
    };
    const saved = await saveUserPreferences(payload);
    state.prefs = saved;
    toast("Preferences saved.");
  }

  async function resetColors() {
    if (!confirm("Reset all custom colours?")) return;
    state.overrides = {};
    renderColorRows();
    await savePreferences();
  }

  async function loadShortcuts() {
    const data = await api("/v1/me/shortcuts");
    state.shortcuts = Array.isArray(data?.items)
      ? data.items
      : Array.isArray(data)
        ? data
        : [];
  }

  function renderShortcuts() {
    if (!el.shortcutsList) return;
    if (!state.shortcuts.length) {
      el.shortcutsList.innerHTML =
        '<div class="text-muted">No shortcuts saved yet.</div>';
      return;
    }
    el.shortcutsList.innerHTML = `
      <div class="list-group">
        ${state.shortcuts
          .slice()
          .sort((a, b) =>
            String(a.name || "").localeCompare(String(b.name || "")),
          )
          .map((s) => {
            const href = s.url || s.href || "#";
            const safe = safeHref(href);
            const isExternal = /^https?:\/\//i.test(safe);
            const linkHtml = safe
              ? `<a class="text-decoration-none font-monospace small text-break" href="${esc(safe)}"${isExternal ? ' target="_blank" rel="noopener noreferrer"' : ""}>${esc(href)}</a>`
              : `<span class="text-muted font-monospace small text-break">${esc(href)}</span>`;
            return `
              <div class="list-group-item d-flex flex-wrap gap-2 align-items-center justify-content-between">
                <div class="me-2">
                  <div class="fw-semibold">${esc(s.name || "Shortcut")}</div>
                  <div class="small">${linkHtml}</div>
                </div>
                <button type="button" class="btn btn-sm btn-outline-danger" data-del="${esc(s.id)}"><i class="bi bi-trash"></i> Remove</button>
              </div>
            `;
          })
          .join("")}
      </div>
    `;

    el.shortcutsList.querySelectorAll("button[data-del]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-del");
        if (!id) return;
        if (!confirm("Remove this shortcut?")) return;
        try {
          await api(`/v1/me/shortcuts/${encodeURIComponent(id)}`, {
            method: "DELETE",
          });
          await loadShortcuts();
          renderShortcuts();
          toast("Shortcut removed.", "success");
        } catch (err) {
          toast(err?.message || "Failed to remove shortcut", "error");
        }
      });
    });
  }

  async function addShortcut() {
    const name = (el.shortcutName?.value || "").trim();
    const url = (el.shortcutUrl?.value || "").trim();
    const safe = safeHref(url);
    if (!safe) {
      toast(
        "Invalid or unsafe URL. Use an http(s) URL or a same-site path (starting with /).",
        "error",
      );
      return;
    }
    if (!name || !url) {
      toast("Please provide both a name and a URL.", "error");
      return;
    }
    await api("/v1/me/shortcuts", { method: "POST", body: { name, url } });
    el.shortcutName.value = "";
    el.shortcutUrl.value = "";
    await loadShortcuts();
    renderShortcuts();
    toast("Shortcut saved.", "success");
  }

  function setPasswordMsg(text, kind = "info") {
    if (!el.passwordMsg) return;
    el.passwordMsg.textContent = text || "";
    el.passwordMsg.className =
      "small mt-2 " + (kind === "error" ? "text-danger" : "text-secondary");
  }

  async function submitChangePassword() {
    const current_password = String(el.currentPassword?.value || "");
    const new_password = String(el.newPassword?.value || "");
    const confirm_password = String(el.confirmPassword?.value || "");

    if (!current_password || !new_password) {
      setPasswordMsg("Please fill in all fields.", "error");
      return;
    }
    if (new_password.length < 8) {
      setPasswordMsg("New password must be at least 8 characters.", "error");
      return;
    }
    if (new_password !== confirm_password) {
      setPasswordMsg("Passwords do not match.", "error");
      return;
    }

    await api("/v1/auth/change-password", {
      method: "POST",
      body: { current_password, new_password, confirm_password },
    });

    if (el.currentPassword) el.currentPassword.value = "";
    if (el.newPassword) el.newPassword.value = "";
    if (el.confirmPassword) el.confirmPassword.value = "";

    setPasswordMsg("Password updated.", "info");
    toast("Password updated.", "success");
  }

  function setMfaMsg(text, kind = "info") {
    if (!el.mfaMsg) return;
    el.mfaMsg.textContent = text || "";
    el.mfaMsg.className =
      "small mt-2 " + (kind === "error" ? "text-danger" : "text-secondary");
  }

  async function loadMyMail() {
    if (!el.mailList) return;
    try {
      const body = await api("/v1/me/notifications");
      if (!body.length) {
        el.mailSummary.textContent =
          "Nothing has been emailed to this account from the current configuration yet.";
        return;
      }
      const escapeHtml = window.escapeHtml ? window.escapeHtml : (s) => s;
      el.mailSummary.textContent = `${body.length} queued e-mail(s)`;
      el.mailList.innerHTML = body
        .map(
          (
            n,
          ) => `<div class="d-flex justify-content-between border-bottom py-2 small">
          <div>${escapeHtml(n.subject)} <span class="text-secondary">→ ${escapeHtml(n.recipient)}</span></div>
          <div><span class="badge ${n.status === "sent" ? "text-bg-success" : n.status === "failed" ? "text-bg-danger" : "text-bg-secondary"}">${n.status}</span></div>
          </div>`,
        )
        .join("");
    } catch (err) {
      el.mailSummary.textContent =
        err?.message || "Could not load e-mail history.";
    }
  }

  async function loadMfaStatus() {
    if (!el.securitySummary) return;
    try {
      const state2 = await api("/v1/me/mfa");
      if (!state2.local_enabled) {
        el.securitySummary.textContent =
          "Password sign-in is disabled. Manage multi-factor authentication with your sign-in provider.";
        if (el.securityForm) el.securityForm.classList.add("d-none");
        return;
      }
      el.securitySummary.textContent = state2.enabled
        ? `Two-factor authentication is enabled. ${state2.totp ? "Authenticator app; " : ""}${state2.credentials.length} security keys/passkeys; ${state2.recovery_codes_remaining} recovery codes remaining.`
        : "Two-factor authentication is not configured for password sign-in.";
      if (state2.required) {
        el.securitySummary.textContent +=
          " Your administrator requires a second factor.";
      }
      setMfaMsg("");
    } catch (err) {
      el.securitySummary.textContent =
        err?.message || "Could not load security settings.";
    }
  }

  async function submitMfaManage() {
    const password = String(el.securityPassword?.value || "");
    if (!password) {
      setMfaMsg("Enter your current password.", "error");
      return;
    }
    if (el.manageMfaBtn) el.manageMfaBtn.disabled = true;
    try {
      await api("/v1/auth/mfa/manage/start", {
        method: "POST",
        body: { password },
      });
      if (el.securityPassword) el.securityPassword.value = "";
      window.location.assign("/mfa.html");
    } catch (err) {
      setMfaMsg(err?.message || "Verification failed.", "error");
      if (el.securityPassword) el.securityPassword.value = "";
    } finally {
      if (el.manageMfaBtn) el.manageMfaBtn.disabled = false;
    }
  }

  function wireEvents() {
    el.saveEmailBtn?.addEventListener("click", () => {
      saveEmail();
    });

    el.profileEmailInput?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        saveEmail();
      }
    });

    el.addLinkedEmailBtn?.addEventListener("click", () => {
      addLinkedEmail().catch((err) =>
        toast(err?.message || "Failed to link email", "error"),
      );
    });

    el.linkedEmailInput?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        addLinkedEmail().catch((err) =>
          toast(err?.message || "Failed to link email", "error"),
        );
      }
    });

    el.linkedEmailsList?.addEventListener("click", (e) => {
      const t = e?.target;
      if (!(t instanceof HTMLElement)) return;
      const btn = t.closest("button[data-action]");
      if (!btn) return;
      const row = btn.closest("[data-email-id]");
      const id = row?.getAttribute("data-email-id");
      if (!id) return;
      const action = btn.getAttribute("data-action");
      if (action === "primary") {
        makeLinkedEmailPrimary(id).catch((err) =>
          toast(err?.message || "Failed to update primary email", "error"),
        );
      } else if (action === "verify") {
        requestEmailVerification(id).catch((err) =>
          toast(err?.message || "Failed to send verification", "error"),
        );
      } else if (action === "delete") {
        deleteLinkedEmail(id).catch((err) =>
          toast(err?.message || "Failed to remove email", "error"),
        );
      }
    });

    el.changePasswordForm?.addEventListener("submit", (e) => {
      e.preventDefault();
      submitChangePassword().catch((err) => {
        console.error(err);
        setPasswordMsg(err?.message || "Failed to change password", "error");
        toast(err?.message || "Failed to change password", "error");
      });
    });

    el.securityForm?.addEventListener("submit", (e) => {
      e.preventDefault();
      submitMfaManage().catch((err) => {
        console.error(err);
        setMfaMsg(
          err?.message || "Failed to start account security management",
          "error",
        );
      });
    });

    el.prefTheme?.addEventListener("change", async () => {
      applyTheme(el.prefTheme.value);
      try {
        state.prefs = await saveUserPreferences({ theme: el.prefTheme.value });
        toast("Theme updated.", "success");
      } catch (err) {
        toast(err?.message || "Failed to save theme preference", "error");
      }
    });

    el.defaultStartPage?.addEventListener("change", () => {
      saveStartPage().catch((err) =>
        toast(err?.message || "Failed to save preferences", "error"),
      );
    });

    el.prefSticky?.addEventListener("change", async () => {
      try {
        state.prefs = await saveUserPreferences({
          sticky_enabled: el.prefSticky.checked,
        });
        toast("Sticky preference saved.", "success");
      } catch (err) {
        toast(err?.message || "Failed to save sticky preference", "error");
      }
    });

    el.prefAutoApply?.addEventListener("change", async () => {
      try {
        state.prefs = await saveUserPreferences({
          auto_apply_enabled: el.prefAutoApply.checked,
        });
        toast("Auto-apply preference saved.", "success");
      } catch (err) {
        toast(err?.message || "Failed to save auto-apply preference", "error");
      }
    });

    el.frameworkSelect?.addEventListener("change", async () => {
      const machine = el.frameworkSelect.value;
      state.activeFramework = setActiveFrameworkByMachineName(machine);
      await refreshPaletteForFramework();
    });

    el.saveColorsBtn?.addEventListener("click", () => {
      savePreferences().catch((err) =>
        toast(err?.message || "Failed to save preferences", "error"),
      );
    });

    el.resetColorsBtn?.addEventListener("click", () => {
      resetColors().catch((err) =>
        toast(err?.message || "Failed to reset colours", "error"),
      );
    });

    el.addShortcutBtn?.addEventListener("click", () => {
      addShortcut().catch((err) =>
        toast(err?.message || "Failed to add shortcut", "error"),
      );
    });

    el.shortcutUrl?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        addShortcut().catch((err) =>
          toast(err?.message || "Failed to add shortcut", "error"),
        );
      }
    });

    el.subscriptionsList?.addEventListener("change", (e) => {
      const t = e?.target;
      if (!(t instanceof HTMLElement)) return;
      if (!t.matches("input[data-sub-field]")) return;
      const row = t.closest("[data-project-id]");
      if (!row) return;
      saveSubscriptionFromRow(row);
    });

    el.subscriptionsList?.addEventListener("click", (e) => {
      const t = e?.target;
      if (!(t instanceof HTMLElement)) return;
      const btn = t.closest('button[data-action="unsubscribe"]');
      if (!btn) return;
      const row = btn.closest("[data-project-id]");
      if (!row) return;
      const nv = row.querySelector(
        'input[data-sub-field="notify_new_versions"]',
      );
      const nq = row.querySelector('input[data-sub-field="notify_questions"]');
      if (nv) nv.checked = false;
      if (nq) nq.checked = false;
      saveSubscriptionFromRow(row);
    });
  }

  async function init() {
    initAccountTabs();
    state.me = await initAuth({ redirectOnFail: true });
    if (!state.me) return;

    const role = roleOf(state.me);
    if (el.profileUser) el.profileUser.textContent = state.me.username || "";
    if (el.profileUsername)
      el.profileUsername.textContent = state.me.username || "";
    if (el.profileRole) el.profileRole.textContent = role;
    const emailEditable = state.me?.email_editable !== false;

    if (el.profileEmailInput) {
      el.profileEmailInput.value = state.me.email || "";
      if (!emailEditable) {
        el.profileEmailInput.setAttribute("readonly", "readonly");
      } else {
        el.profileEmailInput.removeAttribute("readonly");
      }
    }

    if (el.saveEmailBtn) {
      if (!emailEditable) {
        el.saveEmailBtn.classList.add("d-none");
      } else {
        el.saveEmailBtn.classList.remove("d-none");
      }
    }

    if (el.profileEmailMsg) {
      el.profileEmailMsg.textContent = emailEditable
        ? ""
        : "Primary email is managed through linked email addresses for SSO sessions.";
    }
    // Password change is only available for local-auth deployments when OIDC is disabled.
    const canChangePassword =
      Boolean(state.me?.password_features_enabled) &&
      String(state.me?.auth_method || "local") === "local";
    if (el.passwordCard) {
      if (canChangePassword) {
        el.passwordCard.classList.remove("d-none");
      } else {
        el.passwordCard.classList.add("d-none");
      }
    }
    if (el.passwordUnavailableMsg) {
      el.passwordUnavailableMsg.textContent = canChangePassword
        ? ""
        : "Password changes are only available for local accounts when external single sign-on is disabled.";
    }
    if (el.mfaCard) {
      if (canChangePassword) {
        el.mfaCard.classList.remove("d-none");
      } else {
        el.mfaCard.classList.add("d-none");
      }
    }
    if (el.mailCard) {
      if (canChangePassword) {
        el.mailCard.classList.remove("d-none");
        await loadMyMail();
      } else {
        el.mailCard.classList.add("d-none");
      }
    }

    state.prefs = getUserPreferences() || {};
    state.overrides = { ...(getNodeColorOverrides() || {}) };

    if (el.prefSticky)
      el.prefSticky.checked = state.prefs?.sticky_enabled !== false;
    if (el.prefAutoApply)
      el.prefAutoApply.checked = state.prefs?.auto_apply_enabled !== false;

    renderThemeSelect(state.me);
    applyTheme(getTheme());
    renderStartPageSelect();

    await loadFrameworks();
    state.frameworks = getFrameworks();
    state.activeFramework = getActiveFramework();
    renderFrameworkSelect();

    wireEvents();
    await refreshPaletteForFramework();

    await loadLinkedEmails();

    await loadShortcuts();
    renderShortcuts();

    await loadSubscriptions();
    renderSubscriptions();
  }

  document.addEventListener("DOMContentLoaded", () => {
    init()
      .then(completePendingEmailVerification)
      .catch((err) => {
        console.error(err);
        toast(err?.message || "Failed to load account page", "error");
      });
  });
})();
