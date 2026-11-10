(() => {
  const OSPMAE = window.OSPMAE;
  const {
    api: apiFetch,
    initAuth,
    canMaintainProjects,
    featureOn,
    loadFrameworks,
    getFrameworks,
    getActiveFramework,
    setActiveFrameworkByMachineName,
    loadFrameworkNodes,
    nodeColor,
  } = OSPMAE;

  const state = {
    me: null,
    frameworks: [],
    activeFramework: null,

    editingProject: null,
    editingVersion: null,
    creatingProject: false,
    creatingVersion: false,

    nodeTree: [],
    nodeById: new Map(),
    nodePathById: new Map(),
    expandedNodeIds: new Set(),

    // Selected nodes for current framework + currently open version
    selectedNodeIds: new Set(),
    dirtyNodeSelection: false,
    latestTouched: false,
  };

  const el = {
    formTitle: document.getElementById("formTitle"),
    btnBack: document.getElementById("btnBack"),

    machine_name: document.getElementById("machine_name"),
    display_name: document.getElementById("display_name"),
    organisation: document.getElementById("organisation"),
    project_type: document.getElementById("project_type"),
    programming_languages: document.getElementById("programming_languages"),
    license: document.getElementById("license"),
    link_to_app: document.getElementById("link_to_app"),
    release_rss_feed_url: document.getElementById("release_rss_feed_url"),
    release_rss_ignore_patterns: document.getElementById(
      "release_rss_ignore_patterns",
    ),
    trackBranchField: document.getElementById("trackBranchField"),
    track_branch: document.getElementById("track_branch"),
    releaseFields: document.getElementById("releaseFields"),
    branchFields: document.getElementById("branchFields"),
    tracked_repo_url: document.getElementById("tracked_repo_url"),
    tracked_branch: document.getElementById("tracked_branch"),
    branch_poll_interval_hours: document.getElementById(
      "branch_poll_interval_hours",
    ),

    capability: document.getElementById("capability"),
    supported_profiles: document.getElementById("supported_profiles"),
    supported_formats: document.getElementById("supported_formats"),
    supported_issuance_protocols: document.getElementById(
      "supported_issuance_protocols",
    ),
    supported_presentation_protocols: document.getElementById(
      "supported_presentation_protocols",
    ),
    supported_key_managements: document.getElementById(
      "supported_key_managements",
    ),
    supported_signing_algorithms: document.getElementById(
      "supported_signing_algorithms",
    ),

    saveProjectBtn: document.getElementById("saveProjectBtn"),
    deleteProjectBtn: document.getElementById("deleteProjectBtn"),

    newVersionBtn: document.getElementById("newVersionBtn"),
    versionsList: document.getElementById("versionsList"),
    versionsBranchNotice: document.getElementById("versionsBranchNotice"),

    versionEditor: document.getElementById("versionEditor"),
    versionFormTitle: document.getElementById("versionFormTitle"),
    versionEditContext: document.getElementById("versionEditContext"),
    versionDraftNotice: document.getElementById("versionDraftNotice"),
    versionBranchNotice: document.getElementById("versionBranchNotice"),

    version: document.getElementById("version"),
    status: document.getElementById("status"),
    release_date: document.getElementById("release_date"),
    link_to_source_code: document.getElementById("link_to_source_code"),
    is_draft: document.getElementById("is_draft"),
    is_latest: document.getElementById("is_latest"),
    notes: document.getElementById("notes"),

    frameworkSelect: document.getElementById("frameworkSelect"),
    capabilitySearch: document.getElementById("capabilitySearch"),
    capabilityTree: document.getElementById("capabilityTree"),

    saveVersionBtn: document.getElementById("saveVersionBtn"),
    deleteVersionBtn: document.getElementById("deleteVersionBtn"),
    cancelVersionBtn: document.getElementById("cancelVersionBtn"),
  };

  function escapeHtml(v) {
    return OSPMAE.escapeHtml
      ? OSPMAE.escapeHtml(v)
      : String(v ?? "")
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

  function setMultiSelectValues(selectEl, values) {
    if (!selectEl) return;
    const wanted = new Set((values || []).map((v) => String(v)));
    for (const opt of Array.from(selectEl.options || [])) {
      opt.selected = wanted.has(String(opt.value));
    }
  }

  function getMultiSelectValues(selectEl) {
    if (!selectEl) return [];
    const vals = Array.from(selectEl.selectedOptions || [])
      .map((o) => String(o.value || "").trim())
      .filter(Boolean);
    // de-dupe while preserving order
    const seen = new Set();
    const out = [];
    for (const v of vals) {
      if (seen.has(v)) continue;
      seen.add(v);
      out.push(v);
    }
    return out;
  }

  function releaseIgnorePatternsToText(patterns) {
    if (!Array.isArray(patterns)) return "";
    return patterns
      .map((rule) => {
        const pattern = String(rule?.pattern || "").trim();
        if (!pattern) return "";
        const matchType = String(rule?.match_type || rule?.type || "contains")
          .trim()
          .toLowerCase();
        return matchType === "regex" ? `regex:${pattern}` : pattern;
      })
      .filter(Boolean)
      .join("\n");
  }

  function releaseIgnorePatternsFromText(value) {
    const lines = String(value || "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    const out = [];
    const seen = new Set();
    for (const line of lines) {
      let matchType = "contains";
      let pattern = line;
      const lower = line.toLowerCase();
      if (lower.startsWith("regex:")) {
        matchType = "regex";
        pattern = line.slice(6).trim();
        try {
          // Validate early so users see the issue before the API rejects it.
          // Matching is case-insensitive server-side unless case_sensitive is true.
          // eslint-disable-next-line no-new
          new RegExp(pattern, "i");
        } catch (err) {
          throw new Error(
            `Invalid release ignore regex "${pattern}": ${err.message || err}`,
          );
        }
      } else if (lower.startsWith("contains:")) {
        pattern = line.slice(9).trim();
      }
      if (!pattern) continue;
      const key = `${matchType}\u0000${pattern.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ match_type: matchType, pattern, case_sensitive: false });
    }
    return out;
  }

  function normalizeNode(raw, level = 0, parentId = null) {
    const node = {
      id: Number(raw.id),
      key: raw.key,
      display_name: raw.display_name,
      level,
      parent_id: parentId,
      children: [],
    };
    node.children = (raw.children || []).map((c) =>
      normalizeNode(c, level + 1, node.id),
    );
    return node;
  }

  function rememberNode(node) {
    state.nodeById.set(node.id, node);
    (node.children || []).forEach(rememberNode);
  }

  function ancestryFor(nodeId) {
    const chain = [];
    let current = state.nodeById.get(nodeId);
    let safety = 0;
    while (current && safety < 48) {
      chain.push(current);
      if (!current.parent_id) break;
      current = state.nodeById.get(current.parent_id);
      safety += 1;
    }
    return chain.reverse();
  }

  function groupKeyForNodeId(nodeId) {
    const chain = ancestryFor(nodeId);
    if (!chain.length) return "technology_capabilities";
    return chain[1]?.key || chain[0]?.key || "technology_capabilities";
  }

  function colorForNodeId(nodeId) {
    const fw = state.activeFramework;
    const groupKey = groupKeyForNodeId(nodeId);
    const prefix = fw?.machine_name ? `${fw.machine_name}:` : "";
    return nodeColor(`${prefix}${groupKey}`);
  }

  // A tracked branch is followed instead of releases: the branch fields
  // replace the release feed fields and become required.
  function syncTrackingFields() {
    const tracking = !!el.track_branch?.checked;
    if (el.releaseFields) el.releaseFields.hidden = tracking;
    if (el.branchFields) el.branchFields.hidden = !tracking;
    for (const input of [
      el.tracked_repo_url,
      el.tracked_branch,
      el.branch_poll_interval_hours,
    ]) {
      if (input) input.required = tracking;
    }
  }

  function isBranchVersion(version) {
    const project = state.editingProject;
    return (
      !!project?.track_branch &&
      !!version &&
      String(version.version || "") === String(project.tracked_branch || "")
    );
  }

  function backHref() {
    const id = state.editingProject?.id;
    return id ? `/project.html?id=${encodeURIComponent(id)}` : "/index.html";
  }

  function parseTags(value) {
    if (!value) return [];
    return String(value)
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  }

  function fmtDateInput(value) {
    if (!value) return "";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return "";
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  }

  function safeJsonParse(text) {
    const raw = String(text || "").trim();
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch (err) {
      throw new Error(`Invalid JSON: ${err.message}`);
    }
  }

  function renderFrameworkSelect() {
    if (!el.frameworkSelect) return;
    const options = getFrameworks();
    el.frameworkSelect.innerHTML = options
      .map(
        (f) =>
          `<option value="${escapeHtml(f.machine_name)}">${escapeHtml(f.display_name || f.machine_name)}</option>`,
      )
      .join("");
    if (state.activeFramework?.machine_name) {
      el.frameworkSelect.value = state.activeFramework.machine_name;
    }
  }

  async function loadTaxonomy() {
    const fw = state.activeFramework;
    if (!fw?.id) {
      state.nodeTree = [];
      state.nodeById.clear();
      state.nodePathById.clear();
      state.expandedNodeIds.clear();
      renderNodeTree();
      return;
    }

    const { tree, flat } = await loadFrameworkNodes(fw.id);
    state.nodeTree = (tree || []).map((n) => normalizeNode(n, 0, null));
    state.nodeById.clear();
    state.nodePathById.clear();
    state.expandedNodeIds.clear();
    state.nodeTree.forEach((root) => {
      rememberNode(root);
      state.expandedNodeIds.add(root.id);
    });
    (flat || []).forEach((n) => {
      if (n?.id)
        state.nodePathById.set(
          Number(n.id),
          n.path || n.display_name || n.key || "",
        );
    });

    // Purge invalid selections
    const valid = new Set(Array.from(state.nodeById.keys()));
    state.selectedNodeIds = new Set(
      Array.from(state.selectedNodeIds).filter((id) => valid.has(id)),
    );

    renderNodeTree();
  }

  function shouldShowNode(node, termLower) {
    if (!termLower) return true;
    const path = state.nodePathById.get(node.id) || "";
    const direct = [node.display_name, node.key, path]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(termLower);
    if (direct) return true;
    return (node.children || []).some((child) =>
      shouldShowNode(child, termLower),
    );
  }

  function renderSelectedNodePills() {
    if (!state.selectedNodeIds.size) {
      return '<div class="small">No categories selected for this framework.</div>';
    }

    const nodes = Array.from(state.selectedNodeIds)
      .map((id) => state.nodeById.get(id))
      .filter(Boolean)
      .sort((a, b) =>
        (a.display_name || "").localeCompare(b.display_name || ""),
      );

    return nodes
      .map((node) => {
        const color = colorForNodeId(node.id);
        const path = state.nodePathById.get(node.id) || node.display_name;
        return `
          <button type="button" class="capability-pill selected selected-removable" data-node-id="${node.id}" style="--cap-color:${escapeHtml(color)}" title="${escapeHtml(path)}">
            <span class="pill-label">${escapeHtml(node.display_name)}</span>
            <span class="remove-x" aria-hidden="true">×</span>
          </button>
        `;
      })
      .join("");
  }

  function renderNodeTree() {
    if (!el.capabilityTree) return;

    const tree = state.nodeTree || [];
    const term = (el.capabilitySearch.value || "").trim().toLowerCase();

    const renderNode = (node, depth = 0) => {
      if (!shouldShowNode(node, term)) return "";
      const hasChildren =
        Array.isArray(node.children) && node.children.length > 0;
      const selected = state.selectedNodeIds.has(node.id);
      const autoExpand = Boolean(term);
      const isExpanded =
        hasChildren && (autoExpand || state.expandedNodeIds.has(node.id));
      const color = colorForNodeId(node.id);
      const path = state.nodePathById.get(node.id) || node.display_name;

      const childrenHtml = isExpanded
        ? (node.children || []).map((c) => renderNode(c, depth + 1)).join("")
        : "";

      return `
        <div class="cap-tree-node depth-${Math.min(depth, 4)}" data-node-id="${node.id}">
          <div class="cap-node-row">
            ${
              hasChildren
                ? `<button type="button" class="cap-toggle ${isExpanded ? "expanded" : ""}" data-toggle-node="${node.id}" aria-label="${isExpanded ? "Collapse" : "Expand"} ${escapeHtml(node.display_name)}">${isExpanded ? "▾" : "▸"}</button>`
                : '<span class="cap-toggle-spacer" aria-hidden="true"></span>'
            }
            <button type="button" class="capability-pill ${selected ? "selected" : ""}" data-node-id="${node.id}" style="--cap-color:${escapeHtml(color)}" title="${escapeHtml(path)}">
              <span class="pill-label">${escapeHtml(node.display_name)}</span>
            </button>
          </div>
          ${childrenHtml ? `<div class="cap-children">${childrenHtml}</div>` : ""}
        </div>
      `;
    };

    el.capabilityTree.innerHTML = `
      <div class="selected-pills" style="margin-bottom:8px;">${renderSelectedNodePills()}</div>
      <div class="capability-tree-wrap">${tree.map((n) => renderNode(n, 0)).join("") || '<div class="small">No categories available.</div>'}</div>
    `;

    el.capabilityTree
      .querySelectorAll("button[data-node-id]")
      .forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = Number(btn.dataset.nodeId);
          if (Number.isNaN(id)) return;
          if (state.selectedNodeIds.has(id)) state.selectedNodeIds.delete(id);
          else state.selectedNodeIds.add(id);
          state.dirtyNodeSelection = true;
          renderNodeTree();
        });
      });

    el.capabilityTree
      .querySelectorAll("button[data-toggle-node]")
      .forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = Number(btn.dataset.toggleNode);
          if (Number.isNaN(id)) return;
          if (state.expandedNodeIds.has(id)) state.expandedNodeIds.delete(id);
          else state.expandedNodeIds.add(id);
          renderNodeTree();
        });
      });
  }

  function fillProjectForm(project) {
    el.machine_name.value = project?.machine_name || "";
    el.display_name.value = project?.display_name || "";
    el.organisation.value = project?.organisation || "";
    el.project_type.value = project?.project_type || "";
    el.license.value = project?.license || "";
    setMultiSelectValues(
      el.programming_languages,
      project?.programming_languages || [],
    );
    el.link_to_app.value = project?.link_to_app || "";
    if (el.release_rss_feed_url)
      el.release_rss_feed_url.value = project?.release_rss_feed_url || "";
    if (el.release_rss_ignore_patterns) {
      el.release_rss_ignore_patterns.value = releaseIgnorePatternsToText(
        project?.release_rss_ignore_patterns || [],
      );
    }
    if (el.track_branch) el.track_branch.checked = !!project?.track_branch;
    if (el.tracked_repo_url)
      el.tracked_repo_url.value = project?.tracked_repo_url || "";
    if (el.tracked_branch)
      el.tracked_branch.value = project?.tracked_branch || "";
    if (el.branch_poll_interval_hours)
      el.branch_poll_interval_hours.value = String(
        project?.branch_poll_interval_hours || 24,
      );
    // Without dependency scans there is nothing to re-scan, so the option
    // only stays visible for a project that already tracks a branch.
    if (el.trackBranchField)
      el.trackBranchField.hidden =
        !featureOn("dependency_scans") && !project?.track_branch;
    syncTrackingFields();

    el.capability.value = project?.capability || "";

    // Multi-select combobox fields
    setMultiSelectValues(
      el.supported_profiles,
      project?.supported_profiles || [],
    );
    setMultiSelectValues(
      el.supported_formats,
      project?.supported_formats || [],
    );
    setMultiSelectValues(
      el.supported_issuance_protocols,
      project?.supported_issuance_protocols || [],
    );
    setMultiSelectValues(
      el.supported_presentation_protocols,
      project?.supported_presentation_protocols || [],
    );
    setMultiSelectValues(
      el.supported_key_managements,
      project?.supported_key_managements || [],
    );
    setMultiSelectValues(
      el.supported_signing_algorithms,
      project?.supported_signing_algorithms || [],
    );
  }

  function buildProjectPayload(isUpdate = false) {
    const payload = {
      machine_name: (el.machine_name.value || "").trim() || undefined,
      display_name: (el.display_name.value || "").trim() || undefined,
      organisation: (el.organisation.value || "").trim() || null,
      project_type: (el.project_type.value || "").trim() || null,
      license: (el.license.value || "").trim() || null,
      programming_languages: getMultiSelectValues(el.programming_languages),
      link_to_app: (el.link_to_app.value || "").trim() || null,
      release_rss_feed_url:
        (el.release_rss_feed_url?.value || "").trim() || null,
      release_rss_ignore_patterns: releaseIgnorePatternsFromText(
        el.release_rss_ignore_patterns?.value || "",
      ),
      track_branch: !!el.track_branch?.checked,
      tracked_repo_url: (el.tracked_repo_url?.value || "").trim() || null,
      tracked_branch: (el.tracked_branch?.value || "").trim() || null,
      branch_poll_interval_hours:
        Number.parseInt(el.branch_poll_interval_hours?.value || "", 10) ||
        undefined,

      capability: (el.capability.value || "").trim() || null,

      supported_profiles: getMultiSelectValues(el.supported_profiles),
      supported_formats: getMultiSelectValues(el.supported_formats),
      supported_issuance_protocols: getMultiSelectValues(
        el.supported_issuance_protocols,
      ),
      supported_presentation_protocols: getMultiSelectValues(
        el.supported_presentation_protocols,
      ),
      supported_key_managements: getMultiSelectValues(
        el.supported_key_managements,
      ),
      supported_signing_algorithms: getMultiSelectValues(
        el.supported_signing_algorithms,
      ),
    };

    if (!payload.track_branch) {
      // Branch settings only travel while tracking is on, so a half-typed
      // value in the hidden fields neither blocks the save nor replaces
      // what is stored.
      delete payload.tracked_repo_url;
      delete payload.tracked_branch;
      delete payload.branch_poll_interval_hours;
    }

    if (isUpdate) {
      // API allows machine_name/display_name optional in updates.
      Object.keys(payload).forEach((k) => {
        if (payload[k] === undefined) delete payload[k];
      });
    } else {
      if (!payload.machine_name) throw new Error("machine_name is required");
      if (!payload.display_name) throw new Error("display_name is required");
    }

    return payload;
  }

  function currentLatestVersion() {
    const versions = state.editingProject?.versions || [];
    return versions.find((v) => !!v.is_latest) || null;
  }

  function versionLabel(version) {
    return String(version?.version || "").trim() || "this version";
  }

  function renderVersionEditorContext(mode = "edit") {
    if (!el.versionEditContext) return;

    if (!state.editingVersion && !state.creatingVersion) {
      el.versionEditContext.classList.remove("active");
      el.versionEditContext.innerHTML = "";
      return;
    }

    const v = state.editingVersion || {};
    const label = state.creatingVersion ? "new version" : versionLabel(v);
    const latest = currentLatestVersion();
    const latestText = latest
      ? `Current latest: ${escapeHtml(latest.version || "—")}`
      : "No published latest version yet";
    const badges = [];
    if (v.is_latest)
      badges.push('<span class="badge text-bg-success ms-2">Latest</span>');
    if (v.is_draft)
      badges.push('<span class="badge text-bg-warning ms-2">Draft</span>');

    el.versionEditContext.classList.add("active");
    el.versionEditContext.innerHTML = `
      <div class="fw-semibold"><i class="bi bi-pencil-square me-1" aria-hidden="true"></i>${state.creatingVersion ? "Creating" : "Editing"} ${escapeHtml(label)}${badges.join("")}</div>
      <div class="small text-secondary">${escapeHtml(latestText)}. Save changes in this form to update this version.</div>
    `;
  }

  function isPublishingDraftFromForm() {
    return (
      !!state.editingVersion?.id &&
      !!state.editingVersion?.is_draft &&
      !el.is_draft?.checked
    );
  }

  function syncLatestSwitchForDraftState() {
    if (!el.is_latest) return;
    const draft = !!el.is_draft?.checked;
    el.is_latest.disabled = draft;
    if (draft) {
      el.is_latest.checked = false;
    }
  }

  function updateDraftPublishNotice() {
    if (!el.versionDraftNotice) return;
    if (!isPublishingDraftFromForm()) {
      el.versionDraftNotice.style.display = "none";
      el.versionDraftNotice.innerHTML = "";
      return;
    }

    const label = (
      el.version.value ||
      state.editingVersion?.version ||
      "this version"
    ).trim();
    const latest = currentLatestVersion();
    const latestPart = latest
      ? ` The current latest version is <strong>${escapeHtml(latest.version || "—")}</strong>.`
      : " There is currently no published latest version for this project.";

    el.versionDraftNotice.innerHTML = `
      <div class="fw-semibold"><i class="bi bi-exclamation-triangle me-1" aria-hidden="true"></i>Publishing draft ${escapeHtml(label)}</div>
      <div class="small">Taking this version out of Draft will make it visible in general browsing.${latestPart} OSPMAE will elevate it to Latest only if it is newer than the current latest semantic version. You can force promotion by ticking Latest before saving.</div>
    `;
    el.versionDraftNotice.style.display = "";
  }

  function surfaceVersionEditor() {
    if (!el.versionEditor) return;
    el.versionEditor.classList.add("version-editor-active");
    el.versionEditor.classList.remove("version-editor-pulse");
    // Restart the highlight animation even when the same version is clicked twice.
    void el.versionEditor.offsetWidth;
    el.versionEditor.classList.add("version-editor-pulse");
    try {
      el.versionEditor.scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (_) {
      el.versionEditor.scrollIntoView();
    }
    window.setTimeout(() => {
      try {
        el.version?.focus({ preventScroll: true });
      } catch (_) {
        el.version?.focus();
      }
    }, 350);
  }

  function renderVersionsList() {
    const versions = state.editingProject?.versions || [];

    const rows = versions
      .slice()
      .sort((a, b) =>
        String(b.release_date || "").localeCompare(
          String(a.release_date || ""),
        ),
      )
      .map((v) => {
        const isSelected = state.editingVersion?.id === v.id;
        const capCount = (v.capability_paths || []).length;
        const latest = v.is_latest
          ? '<span class="badge text-bg-success ms-2">Latest</span>'
          : "";
        const draft = v.is_draft
          ? '<span class="badge text-bg-warning ms-2">Draft</span>'
          : "";
        const editing = isSelected
          ? '<span class="badge text-bg-primary ms-2">Editing now</span>'
          : "";
        const date = v.release_date ? fmtDateInput(v.release_date) : "—";
        const buttonClass = isSelected
          ? "btn btn-primary btn-sm"
          : "btn btn-outline-primary btn-sm";
        const buttonText = isSelected ? "Editing" : "Edit";
        return `
          <div class="card version-row ${isSelected ? "version-row-selected" : ""}" data-version-id="${v.id}">
            <div class="d-flex flex-wrap align-items-start" style="justify-content:space-between; gap:10px;">
              <div>
                <div style="font-weight:700;">${escapeHtml(v.version)}${latest}${draft}${editing}</div>
                <div class="small muted">${escapeHtml(date)} · Categories (current framework): ${capCount}</div>
              </div>
              <button class="${buttonClass}" data-action="edit-version" data-id="${v.id}"><i class="bi bi-pencil"></i> ${buttonText}</button>
            </div>
          </div>
        `;
      })
      .join("");

    el.versionsList.innerHTML =
      rows || '<div class="muted">No versions created yet.</div>';

    const project = state.editingProject;
    const tracking = !!project?.track_branch;
    if (el.newVersionBtn) el.newVersionBtn.hidden = tracking || !project?.id;
    if (el.versionsBranchNotice) {
      el.versionsBranchNotice.hidden = !tracking;
      el.versionsBranchNotice.textContent = tracking
        ? `This project tracks branch ${project.tracked_branch}: its version is kept up to date automatically and re-scanned every ${project.branch_poll_interval_hours} hour(s). Earlier versions stay listed.`
        : "";
    }

    el.versionsList
      .querySelectorAll('button[data-action="edit-version"]')
      .forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = Number(btn.dataset.id);
          if (Number.isNaN(id)) return;
          const v = (state.editingProject.versions || []).find(
            (x) => x.id === id,
          );
          if (v) openVersion(v);
        });
      });
  }

  function fillVersionForm(version) {
    el.version.value = version?.version || "";
    el.status.value = version?.status || "";
    el.release_date.value = fmtDateInput(version?.release_date);
    el.link_to_source_code.value = version?.link_to_source_code || "";
    if (el.is_draft) el.is_draft.checked = !!version?.is_draft;
    if (el.is_latest)
      el.is_latest.checked = !!version?.is_latest && !version?.is_draft;
    state.latestTouched = false;
    syncLatestSwitchForDraftState();
    el.notes.value = version?.notes || "";
    const branchVersion = isBranchVersion(version);
    for (const input of [el.version, el.link_to_source_code, el.is_draft]) {
      if (input) input.disabled = branchVersion;
    }
    if (el.versionBranchNotice) el.versionBranchNotice.hidden = !branchVersion;
    updateDraftPublishNotice();
  }

  function buildVersionPayload(isUpdate = false) {
    const payload = {
      version: (el.version.value || "").trim() || undefined,
      status: (el.status.value || "").trim() || null,
      release_date: (el.release_date.value || "").trim() || null,
      link_to_source_code: (el.link_to_source_code.value || "").trim() || null,
      is_draft: !!el.is_draft?.checked,
      notes: (el.notes.value || "").trim() || null,
    };

    const latestChecked = !!el.is_latest?.checked && !payload.is_draft;
    if (latestChecked) {
      payload.is_latest = true;
    } else if (
      !payload.is_draft &&
      (state.latestTouched || (isUpdate && !!state.editingVersion?.is_latest))
    ) {
      payload.is_latest = false;
    }

    if (!isUpdate) {
      if (!payload.version) throw new Error("version is required");
    } else {
      Object.keys(payload).forEach((k) => {
        if (payload[k] === undefined) delete payload[k];
      });
    }

    return payload;
  }

  async function loadVersionFrameworkNodes(versionId) {
    if (!versionId || !state.activeFramework?.id) {
      state.selectedNodeIds.clear();
      state.dirtyNodeSelection = false;
      renderNodeTree();
      return;
    }

    const res = await apiFetch(
      `/v1/project-versions/${versionId}/framework-nodes${toQueryString({ framework_id: state.activeFramework.id })}`,
    );
    const nodeIds = Array.isArray(res?.node_ids) ? res.node_ids : [];
    state.selectedNodeIds = new Set(nodeIds.map((n) => Number(n)));
    state.dirtyNodeSelection = false;
    renderNodeTree();
  }

  async function openVersion(version) {
    state.editingVersion = version;
    state.creatingVersion = false;
    el.versionEditor.style.display = "";
    el.versionFormTitle.textContent = `Edit version: ${version.version}`;
    fillVersionForm(version);
    renderVersionEditorContext("edit");
    renderVersionsList();
    surfaceVersionEditor();

    await loadTaxonomy();
    await loadVersionFrameworkNodes(version.id);

    el.deleteVersionBtn.style.display = "";
  }

  function startCreateVersion() {
    state.editingVersion = null;
    state.creatingVersion = true;
    el.versionEditor.style.display = "";
    el.versionFormTitle.textContent = "Create new version";
    fillVersionForm({});
    renderVersionEditorContext("create");
    renderVersionsList();
    surfaceVersionEditor();

    // Start with an empty selection.
    state.selectedNodeIds.clear();
    state.dirtyNodeSelection = false;
    renderNodeTree();

    el.deleteVersionBtn.style.display = "none";
  }

  async function openProject(projectId) {
    const fwId = state.activeFramework?.id;
    const full = await apiFetch(
      `/v1/projects/${projectId}${toQueryString({ framework_id: fwId || undefined })}`,
    );
    state.editingProject = full;
    state.creatingProject = false;

    el.formTitle.textContent = `Edit project: ${full.display_name || full.machine_name}`;
    if (el.btnBack) el.btnBack.href = backHref();
    fillProjectForm(full);

    el.deleteProjectBtn.style.display = "";

    // Close version editor until one is selected.
    el.versionEditor.style.display = "none";
    el.versionEditor.classList.remove(
      "version-editor-active",
      "version-editor-pulse",
    );
    state.editingVersion = null;
    state.creatingVersion = false;
    renderVersionEditorContext();
    updateDraftPublishNotice();
    renderVersionsList();

    // Ensure framework selector reflects current framework.
    if (el.frameworkSelect && state.activeFramework?.machine_name) {
      el.frameworkSelect.value = state.activeFramework.machine_name;
    }
  }

  function startCreateProject() {
    state.editingProject = null;
    state.creatingProject = true;

    el.formTitle.textContent = "Create project";
    if (el.btnBack) el.btnBack.href = backHref();
    fillProjectForm({});

    el.deleteProjectBtn.style.display = "none";
    el.newVersionBtn.hidden = true;
    if (el.versionsBranchNotice) el.versionsBranchNotice.hidden = true;

    el.versionsList.innerHTML =
      '<div class="muted">Create the project first to add versions.</div>';

    el.versionEditor.style.display = "none";
    el.versionEditor.classList.remove(
      "version-editor-active",
      "version-editor-pulse",
    );
    state.editingVersion = null;
    state.creatingVersion = false;
    renderVersionEditorContext();
    updateDraftPublishNotice();
  }

  async function saveProject() {
    const isUpdate = Boolean(state.editingProject?.id);
    let payload;
    try {
      payload = buildProjectPayload(isUpdate);
    } catch (err) {
      OSPMAE.toast(err.message || "Invalid project form value.", "warn");
      return;
    }

    let projectId;
    if (isUpdate) {
      const updated = await apiFetch(
        `/v1/projects/${state.editingProject.id}`,
        {
          method: "PUT",
          // app.js apiRequest JSON-encodes plain objects automatically.
          // Passing a pre-stringified body causes the API to receive a JSON string,
          // which FastAPI/Pydantic rejects ("Input should be a valid dictionary...").
          body: payload,
        },
      );
      projectId = updated.id;
      OSPMAE.toast("Project updated.");
    } else {
      const created = await apiFetch("/v1/projects", {
        method: "POST",
        body: payload,
      });
      projectId = created.id;
      // Reloading the page keeps editing the project just created.
      history.replaceState(
        null,
        "",
        `/project-edit.html?id=${encodeURIComponent(projectId)}`,
      );
      OSPMAE.toast("Project created. Versions can be added below.");
    }

    // Saving can add the tracked branch's version, so reload the whole view.
    await openProject(projectId);
  }

  async function deleteProject() {
    if (!state.editingProject?.id) return;
    if (
      !confirm("Delete this project and all versions? This cannot be undone.")
    )
      return;
    await apiFetch(`/v1/projects/${state.editingProject.id}`, {
      method: "DELETE",
    });
    OSPMAE.toast("Project deleted.");
    window.location.href = "/index.html";
  }

  async function saveVersion() {
    if (!state.editingProject?.id) {
      OSPMAE.toast("Save the project first.", "warn");
      return;
    }
    if (!state.activeFramework?.id) {
      OSPMAE.toast("Pick a framework first.", "warn");
      return;
    }

    const isUpdate = Boolean(state.editingVersion?.id);
    const payload = buildVersionPayload(isUpdate);

    if (isPublishingDraftFromForm()) {
      const latest = currentLatestVersion();
      const latestText = latest
        ? ` Current latest: ${latest.version || "—"}.`
        : " There is currently no published latest version.";
      const label =
        payload.version || state.editingVersion?.version || "this version";
      const explicitLatest =
        payload.is_latest === true
          ? " You have explicitly marked it as Latest."
          : " OSPMAE will only elevate it automatically if it is newer than the current latest semantic version.";
      if (!confirm(`Publish draft ${label}?${latestText}${explicitLatest}`)) {
        return;
      }
    }

    let versionId = state.editingVersion?.id;

    if (isUpdate) {
      const updated = await apiFetch(`/v1/project-versions/${versionId}`, {
        method: "PUT",
        body: payload,
      });
      state.editingVersion = { ...state.editingVersion, ...updated };
      state.latestTouched = false;
      OSPMAE.toast("Version updated.");
    } else {
      const created = await apiFetch(
        `/v1/projects/${state.editingProject.id}/versions`,
        {
          method: "POST",
          body: payload,
        },
      );
      versionId = created.id;
      state.editingVersion = created;
      state.latestTouched = false;
      state.creatingVersion = false;
      el.deleteVersionBtn.style.display = "";
      el.versionFormTitle.textContent = `Edit version: ${created.version}`;
      OSPMAE.toast("Version created.");
    }

    // Persist node mappings for the current framework.
    const nodePayload = {
      framework_id: state.activeFramework.id,
      node_ids: Array.from(state.selectedNodeIds).sort((a, b) => a - b),
    };
    await apiFetch(`/v1/project-versions/${versionId}/framework-nodes`, {
      method: "PUT",
      body: nodePayload,
    });
    state.dirtyNodeSelection = false;

    // Refresh the project and its versions.
    await openProject(state.editingProject.id);
  }

  async function deleteVersion() {
    if (!state.editingVersion?.id) return;
    if (!confirm("Delete this version? This cannot be undone.")) return;
    await apiFetch(`/v1/project-versions/${state.editingVersion.id}`, {
      method: "DELETE",
    });
    OSPMAE.toast("Version deleted.");
    await openProject(state.editingProject.id);
  }

  function cancelVersionEdit() {
    if (
      state.dirtyNodeSelection &&
      !confirm("Discard unsaved category mapping changes?")
    ) {
      return;
    }
    el.versionEditor.style.display = "none";
    el.versionEditor.classList.remove(
      "version-editor-active",
      "version-editor-pulse",
    );
    state.editingVersion = null;
    state.creatingVersion = false;
    state.selectedNodeIds.clear();
    state.dirtyNodeSelection = false;
    renderVersionEditorContext();
    updateDraftPublishNotice();
    renderVersionsList();
  }

  async function onFrameworkChange() {
    if (
      state.dirtyNodeSelection &&
      !confirm("Discard unsaved category mapping changes?")
    ) {
      // revert UI selection
      if (el.frameworkSelect && state.activeFramework?.machine_name) {
        el.frameworkSelect.value = state.activeFramework.machine_name;
      }
      return;
    }

    const machine = el.frameworkSelect.value;
    state.activeFramework = setActiveFrameworkByMachineName(machine);

    // Reload taxonomy for this framework.
    await loadTaxonomy();

    // If a version is open, reload its mapping.
    if (state.editingVersion?.id) {
      await loadVersionFrameworkNodes(state.editingVersion.id);
    } else {
      state.selectedNodeIds.clear();
      renderNodeTree();
    }

    // Refresh project details and category counts.
    if (state.editingProject?.id) {
      await openProject(state.editingProject.id);
    }
  }

  function wireEvents() {
    el.btnBack?.addEventListener("click", (e) => {
      if (
        state.dirtyNodeSelection &&
        !confirm("Discard unsaved category mapping changes?")
      )
        e.preventDefault();
    });

    el.track_branch?.addEventListener("change", syncTrackingFields);

    el.saveProjectBtn.addEventListener("click", () => {
      saveProject().catch((err) =>
        OSPMAE.toast(err.message || "Failed to save project", "error"),
      );
    });

    el.deleteProjectBtn.addEventListener("click", () => {
      deleteProject().catch((err) =>
        OSPMAE.toast(err.message || "Failed to delete project", "error"),
      );
    });

    el.newVersionBtn.addEventListener("click", () => {
      startCreateVersion();
    });

    el.saveVersionBtn.addEventListener("click", () => {
      saveVersion().catch((err) =>
        OSPMAE.toast(err.message || "Failed to save version", "error"),
      );
    });

    el.deleteVersionBtn.addEventListener("click", () => {
      deleteVersion().catch((err) =>
        OSPMAE.toast(err.message || "Failed to delete version", "error"),
      );
    });

    el.cancelVersionBtn.addEventListener("click", () => {
      cancelVersionEdit();
    });

    el.is_draft?.addEventListener("change", () => {
      syncLatestSwitchForDraftState();
      updateDraftPublishNotice();
    });
    el.is_latest?.addEventListener("change", () => {
      state.latestTouched = true;
    });
    el.version?.addEventListener("input", updateDraftPublishNotice);
    el.release_date?.addEventListener("change", updateDraftPublishNotice);

    el.frameworkSelect?.addEventListener("change", () => {
      onFrameworkChange().catch((err) =>
        OSPMAE.toast(err.message || "Failed to switch framework", "error"),
      );
    });

    el.capabilitySearch?.addEventListener("input", () => {
      renderNodeTree();
    });
  }

  async function init() {
    state.me = await initAuth({ redirectOnFail: true });
    if (!state.me) return;

    if (!canMaintainProjects()) {
      window.location.replace("/index.html");
      return;
    }

    await loadFrameworks();
    state.frameworks = getFrameworks();
    state.activeFramework = getActiveFramework();
    renderFrameworkSelect();

    wireEvents();

    // ?id= edits that project; without one the page creates a new project.
    const id = Number(new URLSearchParams(window.location.search).get("id"));
    if (Number.isInteger(id) && id > 0) {
      await openProject(id);
    } else {
      startCreateProject();
    }

    // Ensure taxonomy renderer has something when version editor is opened.
    await loadTaxonomy();
  }

  document.addEventListener("DOMContentLoaded", () => {
    init().catch((err) => {
      console.error(err);
      OSPMAE.toast(err.message || "Failed to load page", "error");
    });
  });
})();
