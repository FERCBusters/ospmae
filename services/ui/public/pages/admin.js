(() => {
  const state = {
    users: [],
    groups: [],
    permissions: [],
    editingUserAccess: null,
    editingGroupPerms: null,
    audit: { items: [], total: 0, limit: 50, offset: 0 },
    entityChangelog: { items: [], total: 0, limit: 50, offset: 0 },
  };

  const el = {
    createUserForm: document.getElementById("createUserForm"),
    createGroupForm: document.getElementById("createGroupForm"),
    usersTable: document.getElementById("usersTable"),
    groupsTable: document.getElementById("groupsTable"),
    msg: document.getElementById("msg"),
    auditFilters: document.getElementById("auditFilters"),
    auditTable: document.getElementById("auditTable"),
    auditMsg: document.getElementById("auditMsg"),
    refreshAuditBtn: document.getElementById("refreshAuditBtn"),
    auditPrevBtn: document.getElementById("auditPrevBtn"),
    auditNextBtn: document.getElementById("auditNextBtn"),
    entityChangelogFilters: document.getElementById("entityChangelogFilters"),
    entityChangelogList: document.getElementById("entityChangelogList"),
    entityChangelogMsg: document.getElementById("entityChangelogMsg"),
    refreshEntityChangelogBtn: document.getElementById(
      "refreshEntityChangelogBtn",
    ),
    entityChangelogPrevBtn: document.getElementById("entityChangelogPrevBtn"),
    entityChangelogNextBtn: document.getElementById("entityChangelogNextBtn"),
  };

  function setMessage(message, level = "info") {
    if (!el.msg) return;
    el.msg.textContent = message || "";
    el.msg.className = `small msg-${level}`;
  }

  function roleOptions(selected) {
    const roles = [
      "pending",
      "viewer",
      "engineer",
      "contributor",
      "product_owner",
      "architect",
      "maintainer",
      "admin",
      "inherit",
    ];
    return roles
      .map(
        (r) =>
          `<option value="${r}" ${selected === r ? "selected" : ""}>${r}</option>`,
      )
      .join("");
  }

  function fmtDate(value) {
    if (!value) return "—";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    return d.toLocaleString();
  }

  const ADMIN_TAB_HASH_TO_ID = Object.freeze({
    "#access": "tab-access",
    "#users": "tab-access",
    "#groups": "tab-access",
    "#permissions": "tab-access",
    "#audit": "tab-audit",
    "#changelog": "tab-audit",
    "#entity-changelog": "tab-audit",
  });

  function activateAdminTabFromHash() {
    const tabId =
      ADMIN_TAB_HASH_TO_ID[(window.location.hash || "").toLowerCase()];
    if (!tabId) return;
    const tab = document.getElementById(tabId);
    if (!tab || !window.bootstrap?.Tab) return;
    try {
      window.bootstrap.Tab.getOrCreateInstance(tab).show();
    } catch (_) {
      // ignore tab activation failures
    }
  }

  function initAdminTabs() {
    document
      .querySelectorAll('#adminTabs button[data-bs-toggle="tab"]')
      .forEach((button) => {
        button.addEventListener("shown.bs.tab", (event) => {
          const id = event.target?.id;
          const entry = Object.entries(ADMIN_TAB_HASH_TO_ID).find(
            ([, value]) => value === id,
          );
          if (!entry) return;
          const [hash] = entry;
          if (window.location.hash !== hash) {
            window.history.replaceState(null, "", hash);
          }
        });
      });
    activateAdminTabFromHash();
    window.addEventListener("hashchange", activateAdminTabFromHash);
  }

  function paramsFromForm(form, extra = {}) {
    const params = new URLSearchParams();
    if (form) {
      const fd = new FormData(form);
      fd.forEach((value, key) => {
        const text = String(value || "").trim();
        if (text) params.set(key, text);
      });
    }
    Object.entries(extra).forEach(([key, value]) => {
      if (
        value !== undefined &&
        value !== null &&
        String(value).trim() !== ""
      ) {
        params.set(key, String(value));
      }
    });
    return params;
  }

  function statusBadge(status) {
    const code = Number(status || 0);
    const cls =
      code >= 500
        ? "danger"
        : code >= 400
          ? "warning"
          : code >= 300
            ? "info"
            : "success";
    return `<span class="badge text-bg-${cls}">${OSPMAE.escapeHtml(code || "—")}</span>`;
  }

  function paginationRangeText({ total = 0, offset = 0, items = [] } = {}) {
    const totalCount = Number(total || 0);
    const shown = Array.isArray(items) ? items.length : 0;
    const from =
      totalCount && shown ? Math.min(Number(offset || 0) + 1, totalCount) : 0;
    const to =
      totalCount && shown
        ? Math.min(Number(offset || 0) + shown, totalCount)
        : 0;
    return `Showing ${from}–${to} of ${totalCount}`;
  }

  function updatePager({ prevBtn, nextBtn, page }) {
    if (!page) return;
    const offset = Number(page.offset || 0);
    const limit = Math.max(1, Number(page.limit || 50));
    const shown = Array.isArray(page.items) ? page.items.length : 0;
    const total = Number(page.total || 0);
    if (prevBtn) prevBtn.disabled = offset <= 0;
    if (nextBtn) nextBtn.disabled = offset + shown >= total || shown === 0;
  }

  async function loadAuditTrail() {
    if (!el.auditTable) return;
    el.auditTable.innerHTML =
      '<div class="small text-muted">Loading audit trail…</div>';
    const params = paramsFromForm(el.auditFilters, {
      limit: state.audit.limit,
      offset: state.audit.offset,
    });
    const data = await OSPMAE.api(`/v1/admin/audit?${params.toString()}`);
    state.audit = {
      items: Array.isArray(data?.items) ? data.items : [],
      total: Number(data?.total || 0),
      limit: Number(data?.limit || 50),
      offset: Number(data?.offset || 0),
    };
    renderAuditTrail();
  }

  function renderAuditTrail() {
    if (!el.auditTable) return;
    const rows = state.audit.items
      .map((item) => {
        const path = item.query_string
          ? `${item.path}?${item.query_string}`
          : item.path;
        return `
        <tr>
          <td class="text-nowrap">${OSPMAE.escapeHtml(fmtDate(item.ts))}</td>
          <td>${OSPMAE.escapeHtml(item.username || "anonymous")}</td>
          <td><span class="badge text-bg-secondary">${OSPMAE.escapeHtml(item.method || "—")}</span></td>
          <td class="admin-audit-path-cell"><code class="admin-audit-path-code">${OSPMAE.escapeHtml(path || "—")}</code></td>
          <td>${statusBadge(item.status_code)}</td>
          <td class="text-nowrap">${OSPMAE.escapeHtml(item.duration_ms ?? "—")} ms</td>
          <td>${OSPMAE.escapeHtml(item.client_ip || "—")}</td>
          <td class="small text-muted">${OSPMAE.escapeHtml(item.user_agent || "—")}</td>
        </tr>
      `;
      })
      .join("");
    el.auditTable.innerHTML = `
      <div class="table-responsive">
        <table class="table table-sm align-middle admin-audit-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>User</th>
              <th>Method</th>
              <th>Path</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Client IP</th>
              <th>User agent</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="8" class="text-muted">No audit entries found.</td></tr>'}</tbody>
        </table>
      </div>
    `;
    if (el.auditMsg) {
      el.auditMsg.textContent = paginationRangeText(state.audit);
    }
    updatePager({
      prevBtn: el.auditPrevBtn,
      nextBtn: el.auditNextBtn,
      page: state.audit,
    });
  }

  async function loadAdminEntityChangelog() {
    if (!el.entityChangelogList) return;
    el.entityChangelogList.innerHTML =
      '<div class="small text-muted">Loading changelog…</div>';
    const params = paramsFromForm(el.entityChangelogFilters, {
      limit: state.entityChangelog.limit,
      offset: state.entityChangelog.offset,
    });
    const data = await OSPMAE.api(
      `/v1/admin/entity-changelog?${params.toString()}`,
    );
    state.entityChangelog = {
      items: Array.isArray(data?.items) ? data.items : [],
      total: Number(data?.total || 0),
      limit: Number(data?.limit || 50),
      offset: Number(data?.offset || 0),
    };
    el.entityChangelogList.innerHTML = OSPMAE.entityChangelogHtml(
      state.entityChangelog.items,
      {
        empty: "No entity changelog entries found.",
      },
    );
    if (el.entityChangelogMsg) {
      el.entityChangelogMsg.textContent = paginationRangeText(
        state.entityChangelog,
      );
    }
    updatePager({
      prevBtn: el.entityChangelogPrevBtn,
      nextBtn: el.entityChangelogNextBtn,
      page: state.entityChangelog,
    });
  }

  async function pageAuditTrail(direction) {
    const limit = Math.max(1, Number(state.audit.limit || 50));
    const nextOffset = Math.max(
      0,
      Number(state.audit.offset || 0) + direction * limit,
    );
    if (nextOffset === state.audit.offset) return;
    state.audit.offset = nextOffset;
    await loadAuditTrail();
  }

  async function pageEntityChangelog(direction) {
    const limit = Math.max(1, Number(state.entityChangelog.limit || 50));
    const nextOffset = Math.max(
      0,
      Number(state.entityChangelog.offset || 0) + direction * limit,
    );
    if (nextOffset === state.entityChangelog.offset) return;
    state.entityChangelog.offset = nextOffset;
    await loadAdminEntityChangelog();
  }

  async function loadUsers() {
    const data = await OSPMAE.api("/v1/admin/users");
    state.users = Array.isArray(data?.items) ? data.items : [];
  }

  async function loadGroups() {
    const data = await OSPMAE.api("/v1/admin/groups");
    state.groups = Array.isArray(data?.items) ? data.items : [];
  }

  async function loadPermissions() {
    const data = await OSPMAE.api("/v1/admin/permissions");
    state.permissions = Array.isArray(data?.items) ? data.items : [];
  }

  function userAccessEditorHtml(userId) {
    if (!state.editingUserAccess || state.editingUserAccess.user_id !== userId)
      return "";

    const access = state.editingUserAccess;
    const groupChecks = access.available_groups
      .map((g) => {
        const checked = access.group_ids.includes(g.id) ? "checked" : "";
        const role = g.role ? ` (${g.role})` : "";
        return `<label class="small" style="display:block"><input type="checkbox" data-kind="group" value="${g.id}" ${checked}/> ${OSPMAE.escapeHtml(g.name)}${OSPMAE.escapeHtml(role)}</label>`;
      })
      .join("");

    const permChecks = access.available_permissions
      .map((p) => {
        const checked = access.permission_ids.includes(p.id) ? "checked" : "";
        const desc = p.description ? ` — ${p.description}` : "";
        return `<label class="small" style="display:block"><input type="checkbox" data-kind="perm" value="${p.id}" ${checked}/> ${OSPMAE.escapeHtml(p.code)}${OSPMAE.escapeHtml(desc)}</label>`;
      })
      .join("");

    return `
      <div class="card mt-2">
        <div class="card-body p-3">
          <div class="d-flex align-items-center justify-content-between mb-2">
            <div class="fw-semibold">Edit access for user #${userId}</div>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-action="cancel-user-access">Close</button>
          </div>
          <div class="row g-3">
            <div class="col-md-4" style="max-height:240px;overflow:auto;">
              <div class="small fw-semibold mb-2">Groups</div>
              ${groupChecks || '<span class="small text-muted">No groups</span>'}
            </div>
            <div class="col-md-8" style="max-height:240px;overflow:auto;">
              <div class="small fw-semibold mb-2">Direct permissions</div>
              ${permChecks || '<span class="small text-muted">No permissions</span>'}
            </div>
          </div>
          <div class="d-flex gap-2 mt-3">
            <button type="button" class="btn btn-sm btn-primary" data-action="save-user-access" data-user-id="${userId}"><i class="bi bi-shield-check"></i> Save access</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-action="cancel-user-access">Cancel</button>
          </div>
        </div>
      </div>
    `;
  }

  function renderUsers() {
    const rows = state.users
      .map((u) => {
        const username = OSPMAE.escapeHtml(u.username);
        const role = String(u.role || "inherit");
        const effective = OSPMAE.escapeHtml(u.effective_role || "viewer");
        const disableSelfToggle =
          OSPMAE.state.me?.id === u.id ? "disabled" : "";
        const disableSelfDelete =
          OSPMAE.state.me?.id === u.id ? "disabled" : "";
        return `
          <tr>
            <td>${username}</td>
            <td>
              <input class="form-control form-control-sm" data-field="email" data-user-id="${u.id}" value="${OSPMAE.escapeHtml(u.email || "")}" placeholder="email (optional)" />
            </td>
            <td>
              <select class="form-select form-select-sm" data-field="role" data-user-id="${u.id}">
                ${roleOptions(role)}
              </select>
            </td>
            <td>${effective}</td>
            <td><input class="form-check-input" type="checkbox" data-field="active" data-user-id="${u.id}" ${u.is_active ? "checked" : ""} ${disableSelfToggle}></td>
            <td>${fmtDate(u.last_login_at)}</td>
            <td>
              <div class="d-flex flex-wrap gap-2">
                <button type="button" class="btn btn-sm btn-primary" data-action="save-user" data-user-id="${u.id}"><i class="bi bi-save"></i> Save</button>
                <button type="button" class="btn btn-sm btn-outline-primary" data-action="edit-user-access" data-user-id="${u.id}"><i class="bi bi-key"></i> Access</button>
                <button type="button" class="btn btn-sm btn-outline-danger" data-action="delete-user" data-user-id="${u.id}" ${disableSelfDelete}><i class="bi bi-trash"></i> Delete</button>
              </div>
            </td>
          </tr>
          <tr>
            <td colspan="7">${userAccessEditorHtml(u.id)}</td>
          </tr>
        `;
      })
      .join("");

    el.usersTable.innerHTML = `
      <div class="table-responsive">
        <table class="table table-sm align-middle">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th style="width:160px;">Role</th>
              <th>Effective</th>
              <th style="width:80px;">Active</th>
              <th>Last login</th>
              <th style="width:280px;">Actions</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="7" class="text-muted">No users found.</td></tr>'}</tbody>
        </table>
      </div>
    `;
  }

  function groupPermEditorHtml(groupId) {
    if (
      !state.editingGroupPerms ||
      state.editingGroupPerms.group_id !== groupId
    )
      return "";
    const payload = state.editingGroupPerms;

    const checks = payload.available_permissions
      .map((p) => {
        const checked = payload.permission_ids.includes(p.id) ? "checked" : "";
        const desc = p.description ? ` — ${p.description}` : "";
        return `<label class="small" style="display:block"><input type="checkbox" data-kind="perm" value="${p.id}" ${checked}/> ${OSPMAE.escapeHtml(p.code)}${OSPMAE.escapeHtml(desc)}</label>`;
      })
      .join("");

    return `
      <div class="card mt-2">
        <div class="card-body p-3">
          <div class="d-flex align-items-center justify-content-between mb-2">
            <div class="fw-semibold">Edit permissions for group #${groupId}</div>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-action="cancel-group-perms">Close</button>
          </div>
          <div style="max-height:240px;overflow:auto;">${checks || '<span class="small text-muted">No permissions</span>'}</div>
          <div class="d-flex gap-2 mt-3">
            <button type="button" class="btn btn-sm btn-primary" data-action="save-group-perms" data-group-id="${groupId}"><i class="bi bi-save"></i> Save permissions</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-action="cancel-group-perms">Cancel</button>
          </div>
        </div>
      </div>
    `;
  }

  function renderGroups() {
    const rows = state.groups
      .map((g) => {
        return `
          <tr>
            <td>${OSPMAE.escapeHtml(g.name)}</td>
            <td>
              <input class="form-control form-control-sm" data-field="group-name" data-group-id="${g.id}" value="${OSPMAE.escapeHtml(g.name)}" />
            </td>
            <td>
              <input class="form-control form-control-sm" data-field="group-description" data-group-id="${g.id}" value="${OSPMAE.escapeHtml(g.description || "")}" placeholder="description (optional)" />
            </td>
            <td>
              <select class="form-select form-select-sm" data-field="group-role" data-group-id="${g.id}">
                <option value="" ${!g.role ? "selected" : ""}>(no role)</option>
                <option value="pending" ${g.role === "pending" ? "selected" : ""}>pending</option>
                <option value="viewer" ${g.role === "viewer" ? "selected" : ""}>viewer</option>
                <option value="engineer" ${g.role === "engineer" ? "selected" : ""}>engineer</option>
                <option value="contributor" ${g.role === "contributor" ? "selected" : ""}>contributor</option>
                <option value="product_owner" ${g.role === "product_owner" ? "selected" : ""}>product_owner</option>
                <option value="architect" ${g.role === "architect" ? "selected" : ""}>architect</option>
                <option value="maintainer" ${g.role === "maintainer" ? "selected" : ""}>maintainer</option>
                <option value="admin" ${g.role === "admin" ? "selected" : ""}>admin</option>
              </select>
            </td>
            <td>${g.member_count ?? 0}</td>
            <td>${g.permission_count ?? 0}</td>
            <td>
              <div class="d-flex flex-wrap gap-2">
                <button type="button" class="btn btn-sm btn-primary" data-action="save-group" data-group-id="${g.id}"><i class="bi bi-save"></i> Save</button>
                <button type="button" class="btn btn-sm btn-outline-primary" data-action="edit-group-perms" data-group-id="${g.id}"><i class="bi bi-sliders"></i> Permissions</button>
                <button type="button" class="btn btn-sm btn-outline-danger" data-action="delete-group" data-group-id="${g.id}"><i class="bi bi-trash"></i> Delete</button>
              </div>
            </td>
          </tr>
          <tr>
            <td colspan="7">${groupPermEditorHtml(g.id)}</td>
          </tr>
        `;
      })
      .join("");

    el.groupsTable.innerHTML = `
      <div class="table-responsive">
        <table class="table table-sm align-middle">
          <thead>
            <tr>
              <th>Display</th>
              <th>Name</th>
              <th>Description</th>
              <th style="width:160px;">Role</th>
              <th style="width:90px;">Members</th>
              <th style="width:80px;">Perms</th>
              <th style="width:280px;">Actions</th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="7" class="text-muted">No groups found.</td></tr>'}</tbody>
        </table>
      </div>
    `;
  }

  async function refreshAll() {
    await Promise.all([loadUsers(), loadGroups(), loadPermissions()]);
    renderUsers();
    renderGroups();
  }

  async function submitCreateUser(form) {
    const fd = new FormData(form);
    const payload = {
      username: String(fd.get("username") || "").trim(),
      email: String(fd.get("email") || "").trim() || null,
      password: String(fd.get("password") || ""),
      role: String(fd.get("role") || "pending"),
    };

    await OSPMAE.api("/v1/admin/users", { method: "POST", body: payload });
    form.reset();
    setMessage("User created.", "success");
    await refreshAll();
  }

  async function submitCreateGroup(form) {
    const fd = new FormData(form);
    const payload = {
      name: String(fd.get("name") || "").trim(),
      role: String(fd.get("role") || "").trim() || null,
    };

    await OSPMAE.api("/v1/admin/groups", { method: "POST", body: payload });
    form.reset();
    setMessage("Group created.", "success");
    await refreshAll();
  }

  async function onUsersTableClick(event) {
    const button = event.target.closest("button");
    if (!button) return;

    const action = button.dataset.action;
    const userId = Number(button.dataset.userId || 0);

    if (action === "save-user" && userId) {
      const emailEl = el.usersTable.querySelector(
        `input[data-field="email"][data-user-id="${userId}"]`,
      );
      const roleEl = el.usersTable.querySelector(
        `select[data-field="role"][data-user-id="${userId}"]`,
      );
      const activeEl = el.usersTable.querySelector(
        `input[data-field="active"][data-user-id="${userId}"]`,
      );
      const payload = {
        role: roleEl?.value || "pending",
        is_active: Boolean(activeEl?.checked),
        email: String(emailEl?.value || "").trim() || null,
      };
      await OSPMAE.api(`/v1/admin/users/${userId}`, {
        method: "PATCH",
        body: payload,
      });
      setMessage(`User #${userId} updated.`, "success");
      await refreshAll();
      return;
    }

    if (action === "delete-user" && userId) {
      const target = state.users.find((x) => Number(x.id) === Number(userId));
      const label = target?.username ? `“${target.username}”` : `#${userId}`;
      if (
        !window.confirm(
          `Delete user ${label}? This is permanent and will remove their sessions, preferences, shortcuts, and question posts.`,
        )
      )
        return;
      await OSPMAE.api(`/v1/admin/users/${userId}`, { method: "DELETE" });
      setMessage(`User ${label} deleted.`, "success");
      await refreshAll();
      return;
    }

    if (action === "edit-user-access" && userId) {
      state.editingUserAccess = await OSPMAE.api(
        `/v1/admin/users/${userId}/access`,
      );
      renderUsers();
      return;
    }

    if (action === "cancel-user-access") {
      state.editingUserAccess = null;
      renderUsers();
      return;
    }

    if (action === "save-user-access" && userId) {
      const panel = button.closest(".card");
      const groupIds = Array.from(
        panel.querySelectorAll('input[data-kind="group"]:checked'),
      ).map((cb) => Number(cb.value));
      const permissionIds = Array.from(
        panel.querySelectorAll('input[data-kind="perm"]:checked'),
      ).map((cb) => Number(cb.value));
      await OSPMAE.api(`/v1/admin/users/${userId}/access`, {
        method: "PUT",
        body: {
          group_ids: groupIds,
          permission_ids: permissionIds,
        },
      });
      state.editingUserAccess = null;
      setMessage(`Access updated for user #${userId}.`, "success");
      await refreshAll();
    }
  }

  async function onGroupsTableClick(event) {
    const button = event.target.closest("button");
    if (!button) return;

    const action = button.dataset.action;
    const groupId = Number(button.dataset.groupId || 0);

    if (action === "save-group" && groupId) {
      const roleEl = el.groupsTable.querySelector(
        `select[data-field="group-role"][data-group-id="${groupId}"]`,
      );
      const nameEl = el.groupsTable.querySelector(
        `input[data-field="group-name"][data-group-id="${groupId}"]`,
      );
      const descEl = el.groupsTable.querySelector(
        `input[data-field="group-description"][data-group-id="${groupId}"]`,
      );
      await OSPMAE.api(`/v1/admin/groups/${groupId}`, {
        method: "PATCH",
        body: {
          name: String(nameEl?.value || "").trim(),
          description: String(descEl?.value || "").trim() || null,
          role: String(roleEl?.value || "").trim() || null,
        },
      });
      setMessage(`Group #${groupId} updated.`, "success");
      await refreshAll();
      return;
    }

    if (action === "delete-group" && groupId) {
      const target = state.groups.find((x) => Number(x.id) === Number(groupId));
      const label = target?.name ? `“${target.name}”` : `#${groupId}`;
      if (
        !window.confirm(
          `Delete group ${label}? This is permanent and will remove its memberships and permissions.`,
        )
      )
        return;
      await OSPMAE.api(`/v1/admin/groups/${groupId}`, { method: "DELETE" });
      setMessage(`Group ${label} deleted.`, "success");
      await refreshAll();
      return;
    }

    if (action === "edit-group-perms" && groupId) {
      state.editingGroupPerms = await OSPMAE.api(
        `/v1/admin/groups/${groupId}/permissions`,
      );
      renderGroups();
      return;
    }

    if (action === "cancel-group-perms") {
      state.editingGroupPerms = null;
      renderGroups();
      return;
    }

    if (action === "save-group-perms" && groupId) {
      const panel = button.closest(".card");
      const permissionIds = Array.from(
        panel.querySelectorAll('input[data-kind="perm"]:checked'),
      ).map((cb) => Number(cb.value));
      await OSPMAE.api(`/v1/admin/groups/${groupId}/permissions`, {
        method: "PUT",
        body: { permission_ids: permissionIds },
      });
      state.editingGroupPerms = null;
      setMessage(`Permissions updated for group #${groupId}.`, "success");
      await refreshAll();
    }
  }

  async function init() {
    await OSPMAE.ensureInitialized();
    initAdminTabs();

    if (!OSPMAE.isAdmin()) {
      window.location.href = "/index.html?forbidden=1";
      return;
    }

    el.createUserForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      setMessage("");
      try {
        await submitCreateUser(event.currentTarget);
      } catch (err) {
        setMessage(err.message || "Failed to create user.", "error");
      }
    });

    el.createGroupForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      setMessage("");
      try {
        await submitCreateGroup(event.currentTarget);
      } catch (err) {
        setMessage(err.message || "Failed to create group.", "error");
      }
    });

    el.usersTable?.addEventListener("click", async (event) => {
      setMessage("");
      try {
        await onUsersTableClick(event);
      } catch (err) {
        setMessage(err.message || "Failed to update user.", "error");
      }
    });

    el.groupsTable?.addEventListener("click", async (event) => {
      setMessage("");
      try {
        await onGroupsTableClick(event);
      } catch (err) {
        setMessage(err.message || "Failed to update group.", "error");
      }
    });

    el.auditFilters?.addEventListener("submit", async (event) => {
      event.preventDefault();
      state.audit.offset = 0;
      try {
        await loadAuditTrail();
      } catch (err) {
        if (el.auditMsg)
          el.auditMsg.textContent =
            err.message || "Failed to load audit trail.";
      }
    });

    el.refreshAuditBtn?.addEventListener("click", async () => {
      try {
        await loadAuditTrail();
      } catch (err) {
        if (el.auditMsg)
          el.auditMsg.textContent =
            err.message || "Failed to load audit trail.";
      }
    });

    el.auditPrevBtn?.addEventListener("click", async () => {
      try {
        await pageAuditTrail(-1);
      } catch (err) {
        if (el.auditMsg)
          el.auditMsg.textContent =
            err.message || "Failed to load previous audit page.";
      }
    });

    el.auditNextBtn?.addEventListener("click", async () => {
      try {
        await pageAuditTrail(1);
      } catch (err) {
        if (el.auditMsg)
          el.auditMsg.textContent =
            err.message || "Failed to load next audit page.";
      }
    });

    el.entityChangelogFilters?.addEventListener("submit", async (event) => {
      event.preventDefault();
      state.entityChangelog.offset = 0;
      try {
        await loadAdminEntityChangelog();
      } catch (err) {
        if (el.entityChangelogMsg)
          el.entityChangelogMsg.textContent =
            err.message || "Failed to load entity changelog.";
      }
    });

    el.refreshEntityChangelogBtn?.addEventListener("click", async () => {
      try {
        await loadAdminEntityChangelog();
      } catch (err) {
        if (el.entityChangelogMsg)
          el.entityChangelogMsg.textContent =
            err.message || "Failed to load entity changelog.";
      }
    });

    el.entityChangelogPrevBtn?.addEventListener("click", async () => {
      try {
        await pageEntityChangelog(-1);
      } catch (err) {
        if (el.entityChangelogMsg)
          el.entityChangelogMsg.textContent =
            err.message || "Failed to load previous changelog page.";
      }
    });

    el.entityChangelogNextBtn?.addEventListener("click", async () => {
      try {
        await pageEntityChangelog(1);
      } catch (err) {
        if (el.entityChangelogMsg)
          el.entityChangelogMsg.textContent =
            err.message || "Failed to load next changelog page.";
      }
    });

    try {
      await refreshAll();
    } catch (err) {
      setMessage(err.message || "Failed to load admin data.", "error");
    }

    try {
      await Promise.all([loadAuditTrail(), loadAdminEntityChangelog()]);
    } catch (err) {
      if (el.auditMsg)
        el.auditMsg.textContent =
          err.message || "Failed to load audit or changelog data.";
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
