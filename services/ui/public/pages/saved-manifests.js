(() => {
  const OSPMAE = window.OSPMAE;
  const {
    api: apiFetch,
    initAuth,
    canExportManifests,
    loadFrameworks,
    getFrameworks,
    loadFrameworkNodes,
    nodeColor,
  } = OSPMAE;

  const state = {
    me: null,
    frameworks: [],
    frameworksById: new Map(),
    manifests: [],
    selectedManifest: null,
    selectedManifestNodes: [],
    nodeIndex: null, // { byId, chain, groupKey }
    userGroups: [],
  };

  const el = {
    whoami: document.getElementById("whoami"),
    refreshBtn: document.getElementById("savedRefreshBtn"),
    savedTabBtn: document.getElementById("tabBtnSaved"),
    list: document.getElementById("manifestList"),
    detailsCard: document.getElementById("manifestDetailsCard"),
    detailsTitle: document.getElementById("manifestDetailsTitle"),
    detailsMeta: document.getElementById("manifestDetailsMeta"),
    sharingArea: document.getElementById("manifestSharingArea"),
    detailsFilters: document.getElementById("manifestDetailsFilters"),
    detailsProjects: document.getElementById("manifestDetailsProjects"),
    exportJsonBtn: document.getElementById("savedExportJsonBtn"),
    exportXlsxBtn: document.getElementById("savedExportXlsxBtn"),
    exportMdBtn: document.getElementById("savedExportMdBtn"),
    cloneManifestBtn: document.getElementById("cloneManifestBtn"),
    deleteManifestBtn: document.getElementById("deleteManifestBtn"),
    backToListBtn: document.getElementById("backToListBtn"),
  };

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function toQueryString(query) {
    const params = new URLSearchParams();
    Object.entries(query || {}).forEach(([k, v]) => {
      if (v === undefined || v === null || v === "") return;
      params.set(k, String(v));
    });
    const s = params.toString();
    return s ? `?${s}` : "";
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function ownerLabel(m) {
    if (!m) return "—";
    if (state.me && m.created_by_user_id === state.me.id) return "You";
    return m.created_by_username || "—";
  }

  function visibilityLabel(m) {
    if (m.is_public) return "Public";
    if (m.owner_group_id) return "Group";
    return "Private";
  }

  function renderBadges(m) {
    const vis = visibilityLabel(m);
    const cls =
      vis === "Public"
        ? "bg-success"
        : vis === "Group"
          ? "bg-primary"
          : "bg-secondary";
    return ` <span class="badge ${cls}" style="vertical-align:middle;">${escapeHtml(vis)}</span>`;
  }

  function buildFrameworkIndex() {
    state.frameworksById = new Map(state.frameworks.map((f) => [f.id, f]));
  }

  function showListView() {
    if (el.detailsCard) el.detailsCard.style.display = "none";
    if (el.list) el.list.style.display = "";
  }

  function showDetailsView() {
    if (el.detailsCard) el.detailsCard.style.display = "";
    if (el.list) el.list.style.display = "none";
  }

  function buildNodeIndex(flat) {
    const byId = new Map();
    (flat || []).forEach((n) =>
      byId.set(Number(n.id), {
        id: Number(n.id),
        key: n.key,
        display_name: n.display_name,
        parent_id: n.parent_id ? Number(n.parent_id) : null,
        level: n.level,
        path: n.path,
      }),
    );

    const chainFor = (id) => {
      const chain = [];
      let current = byId.get(Number(id));
      let safety = 0;
      while (current && safety < 64) {
        chain.push(current);
        if (!current.parent_id) break;
        current = byId.get(current.parent_id);
        safety += 1;
      }
      return chain.reverse();
    };

    const groupKeyFor = (id) => {
      const chain = chainFor(id);
      if (!chain.length) return "technology_capabilities";
      let group = chain[1]?.key || chain[0]?.key || "technology_capabilities";
      if (group === "channel_tier" && chain.length > 2) {
        group = chain[2].key;
      }
      // If root uses a machine key like technology_capabilities and the first child is still root-ish.
      if (group === "technology_capabilities" && chain.length > 2) {
        group = chain[2].key;
      }
      return group;
    };

    return { byId, chainFor, groupKeyFor };
  }

  function colorForNode(manifestFrameworkMachine, groupKey) {
    const prefix = manifestFrameworkMachine
      ? `${manifestFrameworkMachine}:`
      : "";
    return nodeColor(`${prefix}${groupKey}`);
  }

  async function loadMyGroups() {
    const res = await apiFetch("/v1/me/groups");
    state.userGroups = Array.isArray(res?.items) ? res.items : [];
  }

  async function loadManifests() {
    const res = await apiFetch("/v1/manifests");
    state.manifests = Array.isArray(res?.items) ? res.items : [];
  }

  function renderManifestList() {
    if (!state.manifests.length) {
      if (el.list)
        el.list.innerHTML = '<div class="muted">No saved manifests yet.</div>';
      return;
    }

    el.list.innerHTML = state.manifests
      .slice()
      .sort((a, b) =>
        String(b.updated_at || "").localeCompare(String(a.updated_at || "")),
      )
      .map((m) => {
        const fw = m.framework_id
          ? state.frameworksById.get(m.framework_id)
          : null;
        const fwLabel =
          fw?.display_name ||
          fw?.machine_name ||
          m.framework_machine_name ||
          "—";
        const f = m.filters_json || m.filters || {};
        const nodeCount = m.node_count ?? f.node_ids?.length ?? 0;
        const projectCount = m.project_count ?? f.project_ids?.length ?? 0;
        const q = f.q ? `Search: “${escapeHtml(f.q)}”` : "";

        return `
          <div class="card mb-2">
            <div class="card-body">
              <div class="d-flex align-items-start justify-content-between gap-3 flex-wrap">
                <div class="flex-grow-1">
                  <div class="fw-semibold">${escapeHtml(m.name)} ${renderBadges(m)}</div>
                  <div class="small text-secondary">Framework: ${escapeHtml(fwLabel)} · Categories: ${nodeCount} · Projects: ${projectCount}</div>
                  <div class="small text-secondary">Owner: ${escapeHtml(ownerLabel(m))}</div>
                  ${q ? `<div class="small mt-1">${q}</div>` : ""}
                </div>
                <div class="flex-shrink-0">
                  <button class="btn btn-primary btn-sm" data-action="open" data-id="${m.id}">Open</button>
                </div>
              </div>
            </div>
          </div>
        `;
      })
      .join("");

    el.list.querySelectorAll('button[data-action="open"]').forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = Number(btn.dataset.id);
        if (Number.isNaN(id)) return;
        openManifest(id).catch((err) =>
          OSPMAE.toast(err.message || "Failed to open manifest", "error"),
        );
      });
    });
  }

  async function openManifest(manifestId) {
    const m = await apiFetch(`/v1/manifests/${manifestId}`);
    state.selectedManifest = m;

    // Build node paths for display.
    const filters = m.filters_json || m.filters || {};
    const frameworkId = m.framework_id || filters.framework_id;
    const framework = frameworkId
      ? state.frameworksById.get(frameworkId)
      : null;
    const frameworkMachine =
      framework?.machine_name || m.framework_machine_name;

    state.nodeIndex = null;
    state.selectedManifestNodes = [];

    if (frameworkId) {
      const { flat } = await loadFrameworkNodes(frameworkId);
      state.nodeIndex = buildNodeIndex(flat);

      const nodeIds = Array.isArray(filters?.node_ids) ? filters.node_ids : [];
      state.selectedManifestNodes = nodeIds
        .map((id) => state.nodeIndex.byId.get(Number(id)))
        .filter(Boolean)
        .map((node) => ({
          id: node.id,
          path: node.path || node.display_name,
          display_name: node.display_name,
          groupKey: state.nodeIndex.groupKeyFor(node.id),
        }))
        .sort((a, b) =>
          String(a.path || "").localeCompare(String(b.path || "")),
        );
    }

    renderManifestDetails(framework, frameworkMachine);
    showDetailsView();
  }

  function renderManifestDetails(framework, frameworkMachine) {
    const m = state.selectedManifest;
    if (!m) return;

    const fwLabel =
      framework?.display_name ||
      framework?.machine_name ||
      frameworkMachine ||
      "—";

    if (el.detailsTitle) el.detailsTitle.textContent = m.name;

    const filters = m.filters_json || m.filters || {};
    const q = filters.q ? `Search: “${filters.q}”` : "No search query.";

    if (el.detailsMeta)
      el.detailsMeta.innerHTML = `
      <div class="small muted">Framework: ${escapeHtml(fwLabel)}</div>
      <div class="small muted">Owner: ${escapeHtml(ownerLabel(m))}</div>
      <div class="small muted">Visibility: ${escapeHtml(visibilityLabel(m))}${m.owner_group_name ? ` (${escapeHtml(m.owner_group_name)})` : ""} </div>
      <div class="small muted">${escapeHtml(q)}</div>
      ${m.description ? `<div style="margin-top:6px;">${escapeHtml(m.description)}</div>` : ""}
    `;

    // Filters (categories + selected projects)
    const pills = state.selectedManifestNodes.length
      ? state.selectedManifestNodes
          .map((n) => {
            const color = colorForNode(frameworkMachine, n.groupKey);
            return `<span class="capability-pill selected" style="--cap-color:${escapeHtml(color)}" title="${escapeHtml(n.path)}"><span class="pill-label">${escapeHtml(n.display_name)}</span></span>`;
          })
          .join("")
      : '<div class="muted small">No categories saved (or no framework selected when saved).</div>';

    if (el.detailsFilters)
      el.detailsFilters.innerHTML = `
      <div style="font-weight:700; margin-bottom:6px;">Categories</div>
      <div class="selected-pills">${pills}</div>
    `;

    const comps = Array.isArray(m.items) ? m.items : [];
    if (!comps.length) {
      if (el.detailsProjects)
        el.detailsProjects.innerHTML =
          '<div class="muted">No projects matched when this manifest was saved.</div>';
    } else {
      if (el.detailsProjects)
        el.detailsProjects.innerHTML = `
        <table class="table" style="width:100%;">
          <thead>
            <tr>
              <th>Project</th>
              <th>Organisation</th>
              <th>Type</th>
              <th>Latest</th>
            </tr>
          </thead>
          <tbody>
            ${comps
              .map((c) => {
                const latest = c.latest_version || "—";
                return `
                  <tr>
                    <td><a href="/project.html?id=${c.project_id}">${escapeHtml(c.display_name || c.machine_name)}</a></td>
                    <td>${escapeHtml(c.organisation || "—")}</td>
                    <td>${escapeHtml(c.project_type || "—")}</td>
                    <td>${escapeHtml(latest)}</td>
                  </tr>
                `;
              })
              .join("")}
          </tbody>
        </table>
      `;
    }

    // Buttons
    if (el.exportJsonBtn)
      el.exportJsonBtn.onclick = () => exportManifest("json");
    if (el.exportXlsxBtn)
      el.exportXlsxBtn.onclick = () => exportManifest("xlsx");
    if (el.exportMdBtn)
      el.exportMdBtn.onclick = () => exportManifest("markdown");

    if (el.cloneManifestBtn) {
      el.cloneManifestBtn.style.display = m.can_clone ? "" : "none";
      el.cloneManifestBtn.onclick = () => cloneCurrentManifest();
    }

    if (el.deleteManifestBtn) {
      el.deleteManifestBtn.style.display = m.can_delete ? "" : "none";
      el.deleteManifestBtn.onclick = () => deleteManifest();
    }

    renderSharingControls();
  }

  function renderSharingControls() {
    const m = state.selectedManifest;
    if (!el.sharingArea) return;
    if (!m || !m.can_manage) {
      el.sharingArea.innerHTML = "";
      return;
    }

    const groups = Array.isArray(state.userGroups) ? state.userGroups : [];
    const currentGroupId = m.owner_group_id ? Number(m.owner_group_id) : 0;
    const isPublic = !!m.is_public;

    let groupControl =
      '<div class="text-secondary small">You are not a member of any group.</div>';
    if (groups.length === 1) {
      const g = groups[0];
      const checked = currentGroupId === Number(g.id) ? "checked" : "";
      groupControl = `
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="shareWithGroupChk" ${checked}>
          <label class="form-check-label" for="shareWithGroupChk">Share with group: <strong>${escapeHtml(g.name)}</strong></label>
        </div>
      `;
    } else if (groups.length > 1) {
      const options = [
        '<option value="0">Not shared (private)</option>',
      ].concat(
        groups.map(
          (g) =>
            `<option value="${Number(g.id)}" ${Number(g.id) === currentGroupId ? "selected" : ""}>${escapeHtml(g.name)}</option>`,
        ),
      );
      groupControl = `
        <label class="form-label small" for="shareGroupSelect">Share with group</label>
        <select id="shareGroupSelect" class="form-select form-select-sm">${options.join("")}</select>
      `;
    }

    const pubChecked = isPublic ? "checked" : "";

    el.sharingArea.innerHTML = `
      <div class="card" style="padding:12px;">
        <div style="font-weight:700; margin-bottom:8px;">Sharing</div>
        <div class="d-flex flex-column gap-2">
          ${groupControl}
          <div class="form-check">
            <input class="form-check-input" type="checkbox" id="makePublicChk" ${pubChecked}>
            <label class="form-check-label" for="makePublicChk">Make public (all users with manifest access can see it)</label>
          </div>
          <div>
            <button id="saveSharingBtn" class="btn btn-outline-primary btn-sm" type="button">Save sharing</button>
          </div>
          <div class="text-secondary small">Manifests are private by default. Sharing with a group will email the group members.</div>
        </div>
      </div>
    `;

    const btn = document.getElementById("saveSharingBtn");
    if (btn) {
      btn.addEventListener("click", () => {
        saveSharing().catch((err) =>
          OSPMAE.toast(err.message || "Failed to update sharing", "error"),
        );
      });
    }
  }

  async function saveSharing() {
    const m = state.selectedManifest;
    if (!m) return;

    let owner_group_id = null;
    const groups = Array.isArray(state.userGroups) ? state.userGroups : [];
    if (groups.length === 1) {
      const chk = document.getElementById("shareWithGroupChk");
      owner_group_id = chk && chk.checked ? Number(groups[0].id) : null;
    } else if (groups.length > 1) {
      const sel = document.getElementById("shareGroupSelect");
      const v = sel ? Number(sel.value) : 0;
      owner_group_id = v && v > 0 ? v : null;
    }

    const pub = document.getElementById("makePublicChk");
    const is_public = !!(pub && pub.checked);

    await apiFetch(`/v1/manifests/${m.id}/sharing`, {
      method: "PATCH",
      // OSPMAE.api() JSON-stringifies bodies for application/json.
      // Do NOT pre-stringify here (it would be stringified again and become a JSON string).
      body: { owner_group_id, is_public },
    });

    OSPMAE.toast("Sharing updated.");
    await openManifest(m.id);
    await loadManifests();
    renderManifestList();
  }

  async function cloneCurrentManifest() {
    const m = state.selectedManifest;
    if (!m) return;
    const res = await apiFetch(`/v1/manifests/${m.id}/clone`, {
      method: "POST",
      body: {},
    });
    const newId = Number(res?.id);
    OSPMAE.toast("Manifest cloned to your saved manifests.");
    await loadManifests();
    renderManifestList();
    if (!Number.isNaN(newId) && newId > 0) {
      await openManifest(newId);
    }
  }

  async function exportManifest(format) {
    const m = state.selectedManifest;
    if (!m) return;
    const blob = await apiFetch(
      `/v1/manifests/${m.id}/export${toQueryString({ format })}`,
      { responseType: "blob" },
    );
    const base = (m.name || "manifest").replaceAll(/[^a-zA-Z0-9._-]+/g, "-");
    const ext =
      format === "xlsx" ? "xlsx" : format === "markdown" ? "md" : "json";
    downloadBlob(blob, `${base}.${ext}`);
  }

  async function deleteManifest() {
    const m = state.selectedManifest;
    if (!m) return;
    if (!confirm("Delete this saved manifest?")) return;
    await apiFetch(`/v1/manifests/${m.id}`, { method: "DELETE" });
    OSPMAE.toast("Manifest deleted.");
    state.selectedManifest = null;
    await loadManifests();
    renderManifestList();
    showListView();
  }

  function wireEvents() {
    if (el.backToListBtn) {
      el.backToListBtn.addEventListener("click", () => {
        state.selectedManifest = null;
        showListView();
      });
    }

    const refresh = () => {
      (async () => {
        await loadManifests();
        renderManifestList();
        if (state.selectedManifest?.id) {
          await openManifest(state.selectedManifest.id);
        }
      })().catch((err) =>
        OSPMAE.toast(err.message || "Failed to refresh", "error"),
      );
    };
    el.refreshBtn?.addEventListener("click", refresh);
    // The builder tab saves into this list, so it reloads whenever shown.
    el.savedTabBtn?.addEventListener("shown.bs.tab", refresh);
  }

  async function init() {
    state.me = await initAuth({ redirectOnFail: true });
    if (window.OSPMAE && !window.OSPMAE.gateFeature("manifests")) return;
    if (!state.me) return;
    // The Saved Manifests tab stays hidden for roles without manifest
    // access (pages/manifests.js); the API refuses them regardless.
    if (!canExportManifests()) return;

    if (el.whoami) {
      const role = state.me?.effective_role || state.me?.role || "viewer";
      el.whoami.textContent = state.me?.username
        ? `${state.me.username} (${role})`
        : role;
    }

    await loadFrameworks();
    await loadMyGroups();
    state.frameworks = getFrameworks();
    buildFrameworkIndex();

    wireEvents();

    await loadManifests();
    renderManifestList();

    // URL deep-link
    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");
    if (id) {
      const mid = Number(id);
      if (!Number.isNaN(mid)) {
        await openManifest(mid);
      }
    } else {
      showListView();
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    init().catch((err) => {
      console.error(err);
      OSPMAE.toast(err.message || "Failed to load manifests", "error");
    });
  });
})();
