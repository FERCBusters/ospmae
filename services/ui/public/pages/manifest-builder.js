const OSPMAE = window.OSPMAE;
const {
  api: apiFetch,
  initAuth,
  loadFrameworks,
  getFrameworks,
  getActiveFramework,
  nodeColor: nodeColorForKey,
  getAutoApplyEnabled,
  saveUserPreferences,
  toast,
  escapeHtml,
  canExportManifests,
} = OSPMAE;

const state = {
  me: null,
  canBuildManifests: false,
  projects: [],
  frameworks: [],
  activeFramework: null,

  // Framework catalogue
  catalogueTree: [],
  nodeById: new Map(),
  nodePathById: new Map(),
  nodeIdByPath: new Map(),

  selectedNodeId: null,
  selectedProjectIds: new Set(),

  treemapApi: null,
};

const el = {
  q: document.getElementById("q"),
  autoApplyFilters: document.getElementById("autoApplyFilters"),
  capabilitySearch: document.getElementById("capabilitySearch"),
  languageFilter: document.getElementById("languageFilter"),
  statusFilter: document.getElementById("statusFilter"),
  activeFiltersSummary: document.getElementById("activeFiltersSummary"),
  capabilityTreemap: document.getElementById("capabilityTreemap"),
  capabilityTreemapMeta: document.getElementById("capabilityTreemapMeta"),
  capabilityTreemapDetails: document.getElementById("capabilityTreemapDetails"),
  projects: document.getElementById("projects"),
  projectsCount: document.getElementById("projectsCount"),
  applyFiltersBtn: document.getElementById("applyFiltersBtn"),
  resetFiltersBtn: document.getElementById("resetFiltersBtn"),
  manifestBuilderCard: document.getElementById("manifestBuilderCard"),
  manifestControls: document.getElementById("manifestControls"),
  manifestSelectionInfo: document.getElementById("manifestSelectionInfo"),
  manifestName: document.getElementById("manifestName"),
  manifestDescription: document.getElementById("manifestDescription"),
  selectVisibleBtn: document.getElementById("selectVisibleBtn"),
  clearSelectionBtn: document.getElementById("clearSelectionBtn"),
  exportJsonBtn: document.getElementById("exportJsonBtn"),
  exportXlsxBtn: document.getElementById("exportXlsxBtn"),
  exportMdBtn: document.getElementById("exportMdBtn"),
  saveManifestBtn: document.getElementById("saveManifestBtn"),
};

// Requests started by a control report their failure as a toast.
function reporting(action, fallback) {
  return Promise.resolve()
    .then(action)
    .catch((err) => toast(err?.message || fallback, "error"));
}

function refreshProjects() {
  return reporting(loadProjects, "Failed to load projects");
}

function getSelectedLanguages() {
  const opts = el.languageFilter?.selectedOptions
    ? Array.from(el.languageFilter.selectedOptions)
    : [];
  const vals = opts.map((o) => String(o.value || "").trim()).filter(Boolean);
  const seen = new Set();
  const out = [];
  for (const v of vals) {
    const k = v.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  return out;
}

function selectedLanguagesCsv() {
  const langs = getSelectedLanguages();
  return langs.length ? langs.join(",") : "";
}

function getSelectedStatuses() {
  const opts = el.statusFilter?.selectedOptions
    ? Array.from(el.statusFilter.selectedOptions)
    : [];
  const vals = opts.map((o) => String(o.value || "").trim()).filter(Boolean);
  const seen = new Set();
  const out = [];
  for (const v of vals) {
    const k = v.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  return out;
}

function selectedStatusesCsv() {
  const sts = getSelectedStatuses();
  return sts.length ? sts.join(",") : "";
}

function formatStatusSummary(sts, max = 4) {
  const arr = Array.isArray(sts) ? sts : [];
  if (!arr.length) return "";
  const shown = arr.slice(0, max);
  const extra = arr.length > max ? " +" : "";
  return shown.join(", ") + extra;
}

function formatLanguageSummary(langs, max = 4) {
  const arr = Array.isArray(langs) ? langs : [];
  if (!arr.length) return "";
  const shown = arr.slice(0, max);
  const extra = arr.length > max ? ` +` : "";
  return shown.join(", ") + extra;
}

function formatProjectNames(projects, maxNames = 8) {
  const arr = Array.isArray(projects) ? projects : [];
  if (!arr.length) return "";
  const names = [];
  for (const p of arr) {
    if (!p) continue;
    if (Number(p.id) === -1) {
      names.push(String(p.name || "").trim());
      continue;
    }
    const name = String(p.name || "").trim();
    if (name) names.push(name);
    if (names.length >= Number(maxNames || 8)) break;
  }
  const more = arr.find((p) => Number(p?.id) === -1);
  const suffix =
    more && String(more.name || "").trim()
      ? ` ${String(more.name).trim()}`
      : "";
  return names.join(", ") + suffix;
}

function renderProjectBadges(projects, maxBadges = 12) {
  const arr = Array.isArray(projects) ? projects : [];
  if (!arr.length) return "";
  const out = [];
  let shown = 0;
  for (const p of arr) {
    if (!p) continue;
    if (Number(p.id) === -1) {
      out.push(
        `<span class="badge text-bg-light border">${escapeHtml(p.name)}</span>`,
      );
      continue;
    }
    if (shown >= Number(maxBadges || 12)) break;
    const name = String(p.name || "").trim();
    if (!name) continue;
    out.push(
      `<a class="badge text-bg-light border text-decoration-none" href="/project.html?id=${Number(p.id)}">${escapeHtml(name)}</a>`,
    );
    shown += 1;
  }
  const more = arr.find((p) => Number(p?.id) === -1);
  if (
    shown >= Number(maxBadges || 12) &&
    more &&
    String(more.name || "").trim()
  ) {
    out.push(
      `<span class="badge text-bg-light border">${escapeHtml(more.name)}</span>`,
    );
  }
  return out.join(" ");
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

function currentNodeIdsCsv() {
  return state.selectedNodeId ? String(state.selectedNodeId) : "";
}

function currentSelectedProjectIdsCsv() {
  return Array.from(state.selectedProjectIds)
    .sort((a, b) => a - b)
    .join(",");
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

function autoApplyEnabled() {
  return el.autoApplyFilters ? !!el.autoApplyFilters.checked : true;
}

function clamp01(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function clampNum(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function hexToRgb(hex) {
  const raw = String(hex || "").trim();
  if (!raw) return null;
  const m = raw.match(/^#?([0-9a-f]{6})$/i);
  if (!m) return null;
  const v = m[1];
  const r = parseInt(v.slice(0, 2), 16);
  const g = parseInt(v.slice(2, 4), 16);
  const b = parseInt(v.slice(4, 6), 16);
  if (!Number.isFinite(r) || !Number.isFinite(g) || !Number.isFinite(b))
    return null;
  return { r, g, b };
}

function rgbaFromHex(hex, alpha) {
  const rgb = hexToRgb(hex);
  const a = clamp01(alpha);
  if (!rgb) return null;
  return `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${a})`;
}

function splitPathParts(rawPath) {
  return String(rawPath || "")
    .split(/\/|>/g)
    .map((p) => String(p || "").trim())
    .filter(Boolean);
}

function normalizePathKey(rawPath) {
  const parts = splitPathParts(rawPath);
  if (!parts.length) return "";
  return parts.join(" > ").toLowerCase();
}

function nodeIdForCapabilityPath(capabilityPath) {
  const key = normalizePathKey(capabilityPath);
  if (!key) return null;
  return state.nodeIdByPath.get(key) || null;
}

function renderCapabilityTag(capabilityId, capabilityPath) {
  const path = String(capabilityPath || "").trim();
  if (!path) return "";
  const resolvedId = capabilityId || nodeIdForCapabilityPath(path);
  const color = resolvedId ? colorForNodeId(resolvedId) : null;
  if (!color) {
    return `<span class="tag">${escapeHtml(path)}</span>`;
  }
  const bg = rgbaFromHex(color, 0.14) || "";
  const border = rgbaFromHex(color, 0.22) || "";
  const style = bg
    ? ` style="background:${bg}; color:${color}; border:1px solid ${border};"`
    : ` style="color:${color};"`;
  return `<span class="tag"${style}>${escapeHtml(path)}</span>`;
}

function trimLabel(value, maxChars) {
  const s = String(value || "");
  const m = Math.max(4, Number(maxChars) || 24);
  if (s.length <= m) return s;
  return `${s.slice(0, Math.max(0, m - 1))}…`;
}

function _ellipsize(s, maxChars) {
  const str = String(s || "");
  if (maxChars <= 1) return "…";
  if (str.length <= maxChars) return str;
  return `${str.slice(0, Math.max(0, maxChars - 1))}…`;
}

function wrapLabelWords(name, maxCharsPerLine, maxLines) {
  const raw = String(name || "").trim();
  if (!raw) return [""];
  const words = raw.split(/\s+/).filter(Boolean);
  if (!words.length) return [""];

  const lines = [];
  let line = "";
  let usedAllWords = true;

  for (let i = 0; i < words.length; i += 1) {
    const w = words[i];
    const candidate = line ? `${line} ${w}` : w;

    if (!line && candidate.length > maxCharsPerLine) {
      lines.push(_ellipsize(candidate, maxCharsPerLine));
      line = "";
      if (lines.length >= maxLines) {
        usedAllWords = false;
        break;
      }
      continue;
    }

    if (candidate.length <= maxCharsPerLine || !line) {
      line = candidate;
    } else {
      lines.push(line);
      line = w;
      if (lines.length >= maxLines) {
        usedAllWords = false;
        break;
      }
    }
  }

  if (line && lines.length < maxLines) lines.push(line);

  if (!usedAllWords && lines.length) {
    lines[lines.length - 1] = _ellipsize(
      lines[lines.length - 1],
      Math.max(4, maxCharsPerLine),
    );
  }

  return lines.slice(0, Math.max(1, maxLines));
}

function ancestryFor(nodeId) {
  const chain = [];
  let current = state.nodeById.get(Number(nodeId));
  let safety = 0;
  while (current && safety < 64) {
    chain.push(current);
    if (!current.parent_id) break;
    current = state.nodeById.get(Number(current.parent_id));
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
  return nodeColorForKey(`${prefix}${groupKey}`);
}

function treemapNodeColor(d, maxDepth) {
  const base = colorForNodeId(d?.data?.id);
  const d3 = window.d3;
  if (!d3 || typeof d3.hsl !== "function") return base;

  const depth = Number(d?.depth || 0);
  const depthNorm = maxDepth > 0 ? clamp01(depth / maxDepth) : 0;
  const isLeaf = !(d?.children && d.children.length);

  let c;
  try {
    c = d3.hsl(base);
  } catch (_) {
    return base;
  }

  // Similar to project treemap: more saturated + darker to avoid washed-out pastels.
  c.s = clampNum((c.s || 0) * 1.28 + 0.14, 0.26, 1.0);
  const lMul = 0.9 - depthNorm * 0.2 - (isLeaf ? 0.14 : 0.06);
  c.l = clampNum((c.l || 0.5) * lMul, 0.12, isLeaf ? 0.62 : 0.74);
  return typeof c.formatHex === "function" ? c.formatHex() : String(c);
}

function updateSelectionInfo() {
  if (!state.canBuildManifests) {
    if (el.manifestControls) el.manifestControls.style.display = "none";
    return;
  }

  if (el.manifestControls) el.manifestControls.style.display = "";

  const selectedCount = state.selectedProjectIds.size;
  const totalCount = state.projects.length;

  el.manifestSelectionInfo.textContent = selectedCount
    ? `${selectedCount} of ${totalCount} projects selected`
    : `No projects selected (${totalCount} available)`;
}

function renderProjects() {
  const list = state.projects || [];
  el.projectsCount.textContent = `${list.length} project${list.length === 1 ? "" : "s"}`;

  if (!list.length) {
    el.projects.innerHTML =
      '<p class="muted">No projects found for the current filters.</p>';
    updateSelectionInfo();
    return;
  }

  el.projects.innerHTML = list
    .map((c) => {
      const selected = state.selectedProjectIds.has(c.id);
      const capPairs = Array.isArray(c.capability_pairs)
        ? c.capability_pairs
        : [];
      const capPaths = Array.isArray(c.capability_paths)
        ? c.capability_paths
        : [];
      const capCount = capPairs.length ? capPairs.length : capPaths.length;

      const preview = (
        capPairs.length
          ? capPairs
          : capPaths.map((p) => ({ capability_path: p }))
      )
        .slice(0, 6)
        .map((cp) => renderCapabilityTag(cp.capability_id, cp.capability_path))
        .join("");

      const selectBox = state.canBuildManifests
        ? `<input class="form-check-input project-select" type="checkbox" ${selected ? "checked" : ""} data-project-id="${c.id}" title="Select for manifest" />`
        : "";

      return `
        <article class="project-card ${state.canBuildManifests ? "selectable" : ""} ${selected ? "selected" : ""}" data-project-id="${c.id}">
          <header>
            <div class="d-flex align-items-start justify-content-between gap-2">
              <div>
                <h3 class="mb-1"><a href="/project.html?id=${c.id}">${escapeHtml(c.display_name || c.machine_name)}</a></h3>
                <div class="muted small">${escapeHtml(c.organisation || "—")}</div>
              </div>
              ${selectBox}
            </div>
          </header>
          <div class="row" style="gap:12px; justify-content:space-between;">
            <div class="small"><strong>Type:</strong> ${escapeHtml(c.project_type || "n/a")}</div>
            <div class="small"><strong>Latest:</strong> ${escapeHtml(c.latest_version?.version || "n/a")}</div>
          </div>
          <div class="small" style="margin-top:6px;">Categories: ${capCount}</div>
          <div class="tags-row" style="margin-top:6px;">
            ${preview || '<span class="small">No categories tagged</span>'}
          </div>
        </article>
      `;
    })
    .join("");

  // Checkbox toggles (manifest selection)
  el.projects.querySelectorAll("input.project-select").forEach((box) => {
    box.addEventListener("click", (e) => {
      e.stopPropagation();
      const id = Number(box.dataset.projectId);
      if (Number.isNaN(id)) return;
      if (state.selectedProjectIds.has(id)) state.selectedProjectIds.delete(id);
      else state.selectedProjectIds.add(id);
      renderProjects();
      updateSelectionInfo();
    });
  });

  // Card click toggles selection for manifest-capable roles.
  if (state.canBuildManifests) {
    el.projects.querySelectorAll(".project-card.selectable").forEach((card) => {
      card.addEventListener("click", (e) => {
        const link = e.target?.closest?.("a");
        const checkbox = e.target?.closest?.("input.project-select");
        if (link || checkbox) return;
        const id = Number(card.dataset.projectId);
        if (Number.isNaN(id)) return;
        if (state.selectedProjectIds.has(id))
          state.selectedProjectIds.delete(id);
        else state.selectedProjectIds.add(id);
        renderProjects();
        updateSelectionInfo();
      });
    });
  }

  updateSelectionInfo();
}

function updateActiveFilterSummary() {
  const q = (el.q.value || "").trim();
  const selectedPath = state.selectedNodeId
    ? state.nodePathById.get(Number(state.selectedNodeId)) ||
      state.nodeById.get(Number(state.selectedNodeId))?.display_name
    : null;

  const bits = [];
  if (q) bits.push(`Search: “${q}”`);
  if (selectedPath) bits.push(`Capability: ${selectedPath}`);

  const langs = getSelectedLanguages();
  if (langs.length) bits.push(`Languages: ${formatLanguageSummary(langs)}`);

  const sts = getSelectedStatuses();
  if (sts.length) bits.push(`Status: ${formatStatusSummary(sts)}`);

  el.activeFiltersSummary.textContent = bits.length
    ? bits.join(" · ")
    : "No filters active.";

  if (el.capabilityTreemapMeta) {
    const hint =
      "Click a tile to filter projects • Click a tile with children to zoom • Click background to reset";
    const sel = selectedPath
      ? `Showing projects for: ${selectedPath}`
      : "Showing all projects";
    el.capabilityTreemapMeta.textContent = `${sel} · ${hint}`;
  }
}

async function loadProjects() {
  const fwId = state.activeFramework?.id;
  const query = {
    q: (el.q.value || "").trim() || undefined,
    framework_id: fwId || undefined,
    node_ids: currentNodeIdsCsv() || undefined,
    languages: selectedLanguagesCsv() || undefined,
    statuses: selectedStatusesCsv() || undefined,
  };

  const res = await apiFetch(`/v1/projects${toQueryString(query)}`);
  state.projects = Array.isArray(res?.items) ? res.items : [];
  renderProjects();
}

async function exportManifest(format) {
  const name =
    (el.manifestName.value || "project-manifest").trim() || "project-manifest";
  const fwId = state.activeFramework?.id;

  const query = {
    format,
    name,
    q: (el.q.value || "").trim() || undefined,
    framework_id: fwId || undefined,
    node_ids: currentNodeIdsCsv() || undefined,
    languages: selectedLanguagesCsv() || undefined,
    statuses: selectedStatusesCsv() || undefined,
    project_ids: currentSelectedProjectIdsCsv() || undefined,
  };

  const path = `/v1/manifests/export${toQueryString(query)}`;
  const blob = await apiFetch(path, { responseType: "blob" });
  const ext =
    format === "xlsx" ? "xlsx" : format === "markdown" ? "md" : "json";
  downloadBlob(blob, `${name}.${ext}`);
}

async function saveManifest() {
  const name = (el.manifestName.value || "").trim();
  if (!name) {
    toast("Please enter a manifest name.", "warn");
    return;
  }
  if (!state.activeFramework?.id) {
    toast("Please pick a framework first.", "warn");
    return;
  }

  const payload = {
    name,
    description: (el.manifestDescription.value || "").trim() || null,
    q: (el.q.value || "").trim() || null,
    framework_id: state.activeFramework.id,
    node_ids: state.selectedNodeId ? [Number(state.selectedNodeId)] : [],
    project_ids: Array.from(state.selectedProjectIds).sort((a, b) => a - b),
  };

  await apiFetch("/v1/manifests", { method: "POST", body: payload });
  toast("Manifest saved.");
}

function resetFilters() {
  el.q.value = "";
  el.capabilitySearch.value = "";
  if (el.languageFilter) {
    Array.from(el.languageFilter.options || []).forEach((opt) => {
      opt.selected = false;
    });
  }
  if (el.statusFilter) {
    Array.from(el.statusFilter.options || []).forEach((opt) => {
      opt.selected = false;
    });
  }
  state.selectedNodeId = null;
  state.selectedProjectIds.clear();
  updateActiveFilterSummary();
  state.treemapApi?.reset?.();
  refreshProjects();
}

function treemapDimensions() {
  const rect = el.capabilityTreemap.getBoundingClientRect();
  const width = Math.max(960, Math.floor(rect.width || 960));
  const height = Math.max(560, Math.floor(rect.height || 560));
  return { width, height };
}

function renderCatalogueTreemap() {
  const d3 = window.d3;
  if (!d3) {
    el.capabilityTreemap.innerHTML =
      '<div class="small">D3 library is unavailable.</div>';
    return;
  }

  const roots = Array.isArray(state.catalogueTree) ? state.catalogueTree : [];
  if (!roots.length) {
    el.capabilityTreemap.innerHTML =
      '<div class="small">No framework taxonomy loaded.</div>';
    return;
  }

  const { width, height } = treemapDimensions();
  const topPad = 28;
  const innerHeight = Math.max(260, height - topPad - 6);

  const capRoot =
    roots.length === 1
      ? roots[0]
      : {
          id: "cap-root",
          key: "cap-root",
          display_name: "Capabilities",
          children: roots,
        };

  const root = d3
    .hierarchy(capRoot, (d) => d.children)
    // Keep layout similar to per-project treemap: equal area for leaves.
    .sum((d) => (d.children && d.children.length ? 0 : 1))
    .sort((a, b) => (b.value || 0) - (a.value || 0));

  root.eachAfter((d) => {
    const direct = Number(d.data?.project_count_direct || 0);
    const descendants = Number(d.data?.project_count_descendants || 0);
    const total = Number(
      d.data?.project_count_total || direct + descendants || 0,
    );
    d.projectCount = Number.isFinite(total) ? total : 0;
    d.projectCountDirect = Number.isFinite(direct) ? direct : 0;
    d.projectCountDescendants = Number.isFinite(descendants) ? descendants : 0;
  });

  const headerPadFor = (d) => {
    if (!(d.depth > 0 && d.children && d.children.length)) return 0;
    if (d.depth === 1) return 48;
    if (d.depth === 2) return 42;
    return 34;
  };

  const verticalStripWidth = 32;
  const isNarrowTall = (w, h) => {
    const ww = Number(w);
    const hh = Number(h);
    if (!Number.isFinite(ww) || !Number.isFinite(hh)) return false;
    if (ww >= 150) return false;
    if (hh < 110) return false;
    return hh / Math.max(1, ww) >= 1.25;
  };

  const leftPadFor = (d) => {
    if (!(d.depth > 0 && d.children && d.children.length)) return 0;
    const w = (d.x1 ?? 0) - (d.x0 ?? 0);
    const h = (d.y1 ?? 0) - (d.y0 ?? 0);
    return isNarrowTall(w, h) ? verticalStripWidth : 0;
  };

  d3
    .treemap()
    .size([width, innerHeight])
    .paddingInner(4)
    .paddingOuter(6)
    .paddingTop(headerPadFor)
    .paddingLeft(leftPadFor)
    .round(true)(root);

  const svg = d3
    .select(el.capabilityTreemap)
    .html("")
    .append("svg")
    .attr("viewBox", [0, 0, width, height])
    .attr("width", "100%")
    .attr("height", height);

  const viewport = svg.append("g");

  const header = viewport.append("g");
  const breadcrumb = header
    .append("text")
    .attr("x", 10)
    .attr("y", 18)
    .style("font-size", "12px")
    .style("font-weight", 650)
    .text("Capabilities");

  header
    .append("text")
    .attr("x", width - 10)
    .attr("y", 18)
    .attr("text-anchor", "end")
    .style("font-size", "11px")
    .attr("opacity", 0.7)
    .text("Click to zoom/filter • Background resets");

  const cellsLayer = viewport
    .append("g")
    .attr("transform", `translate(0,${topPad})`);
  const labelsLayer = viewport
    .append("g")
    .attr("transform", `translate(0,${topPad})`);

  const keyFor = (d) =>
    d
      .ancestors()
      .map((a) => String(a.data?.id ?? a.data?.key ?? ""))
      .reverse()
      .join("/");

  const safeIdFor = (d) =>
    ("clip_" + keyFor(d)).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 220);

  const pathLabelFor = (d) =>
    d
      .ancestors()
      .map((a) => String(a.data?.display_name || a.data?.key || ""))
      .reverse()
      .join(" > ");

  function updateTreemapDetailsFor(node) {
    if (!el.capabilityTreemapDetails) return;
    if (!node || !node.data || node.depth === 0) {
      el.capabilityTreemapDetails.style.display = "none";
      el.capabilityTreemapDetails.innerHTML = "";
      return;
    }

    const total = Number(node.data.project_count_total || 0);
    const direct = Number(node.data.project_count_direct || 0);
    const desc = Number(node.data.project_count_descendants || 0);
    const totalProjects = Array.isArray(node.data.projects_total)
      ? node.data.projects_total
      : [];
    const directProjects = Array.isArray(node.data.projects_direct)
      ? node.data.projects_direct
      : [];

    const title = escapeHtml(
      String(node.data.display_name || node.data.key || "Capability"),
    );
    const parts = [];

    parts.push(
      `<div class="fw-semibold">${title}: ${total} ${total === 1 ? "project" : "projects"}</div>`,
    );

    const names = renderProjectBadges(totalProjects, 14);
    if (names) {
      parts.push(`<div class="mt-1 d-flex flex-wrap gap-1">${names}</div>`);
    }

    if (node.children && node.children.length && direct > 0) {
      const directNames = renderProjectBadges(directProjects, 14);
      const box = [];
      box.push(
        `<div class="fw-semibold mb-1">Directly mapped to this capability (${direct}):</div>`,
      );
      if (directNames)
        box.push(`<div class="d-flex flex-wrap gap-1">${directNames}</div>`);
      if (desc === 0) {
        box.push(
          `<div class="mt-2 text-success-emphasis">These projects selected the parent capability but not any sub-capabilities. <strong>Sub-capabilities will show 0 unless projects map them explicitly.</strong></div>`,
        );
      }
      parts.push(
        `<div class="mt-2 bg-success-subtle border border-success-subtle rounded-3 p-3 shadow-sm">${box.join("")}</div>`,
      );
    }

    el.capabilityTreemapDetails.innerHTML = parts.join("");
    el.capabilityTreemapDetails.style.display = "";
  }

  let focus = root;
  const depthSpan = 4;

  function countLabelFor(node, w) {
    const total = Number(node?.projectCount || 0);
    const direct = Number(node?.projectCountDirect || 0);
    const desc = Number(node?.projectCountDescendants || 0);
    const isContainer = !!(node?.children && node.children.length);
    const directOnly = isContainer && total > 0 && direct > 0 && desc === 0;

    if (w < 70) return directOnly ? `${total} direct` : String(total);
    if (w < 110) return directOnly ? `${total} direct` : `${total} proj.`;

    let base = `${total} ${total === 1 ? "project" : "projects"}`;
    if (directOnly) base += " (direct)";
    return base;
  }

  function isVerticalOverlayLabel(d, w, h) {
    if (!isNarrowTall(w, h)) return false;
    if (d.children && d.children.length) return true;
    return focus && focus.depth === 0 && d.depth === 1;
  }

  function tileOpacity(d) {
    if (d.depth === 0) return 0;
    const rel = Math.max(1, d.depth - focus.depth);
    const base =
      rel === 1 ? (d.children ? 0.36 : 0.92) : d.children ? 0.56 : 0.95;
    return clamp01(base);
  }

  function setSelectedFromNode(d) {
    const id = d?.data?.id;
    const numeric = Number(id);
    if (!id || Number.isNaN(numeric)) {
      state.selectedNodeId = null;
    } else {
      state.selectedNodeId = numeric;
    }
    updateActiveFilterSummary();
    // Treemap interactions are deliberate; always refresh results immediately.
    refreshProjects();
  }

  function zoomTo(newFocus) {
    focus = newFocus || root;
    const x = d3.scaleLinear().domain([focus.x0, focus.x1]).range([0, width]);
    const y = d3
      .scaleLinear()
      .domain([focus.y0, focus.y1])
      .range([0, innerHeight]);

    const maxDepth = focus.depth + depthSpan;
    const visible = root
      .descendants()
      .filter(
        (d) =>
          d.depth > focus.depth &&
          d.depth <= maxDepth &&
          d.ancestors().includes(focus),
      )
      .sort((a, b) => a.depth - b.depth || (a.value || 0) - (b.value || 0));

    const t = d3.transition().duration(520);
    breadcrumb.text(pathLabelFor(focus));
    updateTreemapDetailsFor(focus);

    const cell = cellsLayer.selectAll("g.cell").data(visible, keyFor);
    const cellEnter = cell.enter().append("g").attr("class", "cell");

    cellEnter
      .append("rect")
      .attr("rx", 10)
      .attr("ry", 10)
      .attr("stroke", "rgba(0,0,0,0.22)")
      .attr("stroke-width", 1.2);

    const cp = cellEnter.append("clipPath").attr("id", (d) => safeIdFor(d));
    cp.append("rect");

    const text = cellEnter
      .append("text")
      .attr("class", "cell-label")
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .style("font-size", "14px")
      .style("font-weight", 750)
      .style("fill", "#ffffff")
      .style("pointer-events", "none");

    text.append("tspan").attr("class", "t1");
    text
      .append("tspan")
      .attr("class", "t2")
      .attr("dy", 14)
      .style("font-weight", 520)
      .attr("opacity", 0.78);

    cellEnter.append("title");

    const merged = cellEnter.merge(cell);

    function zoomTargetFor(node) {
      // Only zoom when the clicked node itself is a container.
      if (!node || !(node.children && node.children.length)) return null;
      if (node === focus) return null;
      return node;
    }

    merged
      .style("cursor", (d) =>
        zoomTargetFor(d) || d?.data?.id ? "pointer" : "default",
      )
      .on("click", (event, d) => {
        event.stopPropagation();
        setSelectedFromNode(d);
        // Redrawing the current view moves the selection outline to a leaf.
        zoomTo(zoomTargetFor(d) || focus);
      });

    merged.select("title").text((d) => {
      const label = pathLabelFor(d);
      const total = Number(d.projectCount || 0);
      const direct = Number(d.projectCountDirect || 0);
      const desc = Number(d.projectCountDescendants || 0);
      const totalNames = formatProjectNames(d.data?.projects_total || [], 10);
      const directNames = formatProjectNames(d.data?.projects_direct || [], 10);

      const lines = [];
      lines.push(label);
      lines.push(`Total: ${total} ${total === 1 ? "project" : "projects"}`);
      if (totalNames) lines.push(`Projects: ${totalNames}`);

      if (d.children && d.children.length && direct > 0) {
        lines.push(`Direct on this capability: ${direct}`);
        if (directNames) lines.push(`Direct projects: ${directNames}`);
        if (desc === 0)
          lines.push(
            "Note: sub-capabilities may show 0 unless mapped explicitly.",
          );
      }
      return lines.join("\n");
    });

    merged
      .select("rect")
      .transition(t)
      .attr("x", (d) => x(d.x0))
      .attr("y", (d) => y(d.y0))
      .attr("width", (d) => Math.max(0, x(d.x1) - x(d.x0)))
      .attr("height", (d) => Math.max(0, y(d.y1) - y(d.y0)))
      .attr("fill", (d) => treemapNodeColor(d, root.height))
      .attr("fill-opacity", (d) => tileOpacity(d))
      .attr("stroke-width", (d) => {
        const sel = Number(d?.data?.id) === Number(state.selectedNodeId);
        return sel ? 2.6 : 1.2;
      })
      .attr("stroke", (d) => {
        const sel = Number(d?.data?.id) === Number(state.selectedNodeId);
        return sel ? "rgba(255,255,255,0.92)" : "rgba(0,0,0,0.22)";
      });

    merged
      .select("clipPath rect")
      .transition(t)
      .attr("x", (d) => x(d.x0))
      .attr("y", (d) => y(d.y0))
      .attr("width", (d) => Math.max(0, x(d.x1) - x(d.x0)))
      .attr("height", (d) => Math.max(0, y(d.y1) - y(d.y0)));

    const containers = root.descendants().filter((d) => {
      if (!(d.depth > focus.depth && d.depth <= focus.depth + 2)) return false;
      if (!d.ancestors().includes(focus)) return false;
      if (d.children && d.children.length) return true;
      if (focus.depth === 0 && d.depth === 1) return true;
      return false;
    });

    const labelKey = (d) => `label:${keyFor(d)}`;
    const labels = labelsLayer
      .selectAll("g.container-label")
      .data(containers, labelKey);

    const labelsEnter = labels
      .enter()
      .append("g")
      .attr("class", "container-label")
      .style("pointer-events", "all");

    labelsEnter
      .append("rect")
      .attr("rx", 8)
      .attr("ry", 8)
      .attr("fill", "rgba(255,255,255,0.62)")
      .attr("stroke", "rgba(0,0,0,0.14)")
      .attr("stroke-width", 1);

    const lcp = labelsEnter
      .append("clipPath")
      .attr("id", (d) => `${safeIdFor(d)}_olab`);
    lcp.append("rect");

    const ltext = labelsEnter
      .append("text")
      .attr("class", "container-label-text")
      .style("font-size", "12px")
      .style("font-weight", 650)
      .attr("dominant-baseline", "hanging")
      .style("pointer-events", "none");

    ltext.append("tspan").attr("class", "t1");
    ltext
      .append("tspan")
      .attr("class", "t2")
      .attr("dy", 14)
      .style("font-weight", 520)
      .attr("opacity", 0.75);

    const labelsMerged = labelsEnter.merge(labels);

    labelsMerged
      .style("cursor", (d) =>
        d.children && d.children.length ? "pointer" : "default",
      )
      .on("click", (event, d) => {
        event.stopPropagation();
        setSelectedFromNode(d);
        zoomTo(d.children && d.children.length ? d : focus);
      });

    labelsMerged.transition(t).attr("opacity", (d) => {
      const w = x(d.x1) - x(d.x0);
      const h = y(d.y1) - y(d.y0);
      const vertical = isVerticalOverlayLabel(d, w, h);
      if (vertical) {
        if (w < 16 || h < 80) return 0;
        return 1;
      }
      if (w < 34 || h < 24) return 0;
      return 1;
    });

    labelsMerged
      .select("rect")
      .transition(t)
      .attr("x", (d) => x(d.x0) + 6)
      .attr("y", (d) => y(d.y0) + 6)
      .attr("width", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        if (isVerticalOverlayLabel(d, w, h))
          return Math.max(0, Math.min(verticalStripWidth - 4, w - 12));
        return Math.max(0, w - 12);
      })
      .attr("height", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        if (isVerticalOverlayLabel(d, w, h)) return Math.max(0, h - 12);
        const showCount = w >= 96 && h >= 58;
        return showCount ? 34 : 22;
      });

    labelsMerged
      .select("clipPath rect")
      .transition(t)
      .attr("x", (d) => x(d.x0) + 6)
      .attr("y", (d) => y(d.y0) + 6)
      .attr("width", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        if (isVerticalOverlayLabel(d, w, h))
          return Math.max(0, Math.min(verticalStripWidth - 4, w - 12));
        return Math.max(0, w - 12);
      })
      .attr("height", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        if (isVerticalOverlayLabel(d, w, h)) return Math.max(0, h - 12);
        const showCount = w >= 96 && h >= 58;
        return showCount ? 34 : 22;
      });

    labelsMerged
      .select("text")
      .transition(t)
      .attr("x", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        return isVerticalOverlayLabel(d, w, h) ? 0 : x(d.x0) + w / 2;
      })
      .attr("y", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        return isVerticalOverlayLabel(d, w, h) ? 0 : y(d.y0) + 10;
      })
      .attr("transform", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        if (!isVerticalOverlayLabel(d, w, h)) return null;
        const stripW = Math.max(0, Math.min(verticalStripWidth - 4, w - 12));
        const tx = x(d.x0) + 6 + stripW / 2;
        const ty = y(d.y0) + 6 + (h - 12) / 2;
        return `translate(${tx},${ty}) rotate(-90)`;
      })
      .attr("dominant-baseline", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        return isVerticalOverlayLabel(d, w, h) ? "central" : "hanging";
      })
      .attr("text-anchor", (d) => {
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        return isVerticalOverlayLabel(d, w, h) ? "middle" : "middle";
      });

    labelsMerged.select("text").attr("clip-path", (d) => {
      const w = x(d.x1) - x(d.x0);
      const h = y(d.y1) - y(d.y0);
      if (isVerticalOverlayLabel(d, w, h)) return null;
      return `url(#${safeIdFor(d)}_olab)`;
    });

    labelsMerged.select("text.container-label-text").each(function (d) {
      const node = d3.select(this);
      const tileW = Math.max(0, x(d.x1) - x(d.x0));
      const tileH = Math.max(0, y(d.y1) - y(d.y0));
      const vertical = isVerticalOverlayLabel(d, tileW, tileH);

      const avail = vertical ? tileH - 24 : tileW - 22;
      const maxChars = Math.max(
        4,
        Math.min(vertical ? 48 : 32, Math.floor(avail / 7)),
      );
      const label = trimLabel(
        String(d.data?.display_name || d.data?.key || ""),
        maxChars,
      );
      node.style("font-size", vertical ? "11px" : "12px");
      node.select("tspan.t1").text(label);

      const t2 = node.select("tspan.t2");
      if (vertical) {
        t2.text("");
        return;
      }

      const showCount = tileW >= 96 && tileH >= 58;
      if (!showCount) {
        t2.text("");
      } else {
        t2.text(countLabelFor(d, tileW - 22));
        t2.attr("x", x(d.x0) + tileW / 2);
      }
    });

    labels.exit().transition(t).attr("opacity", 0).remove();

    merged
      .select("text.cell-label")
      .transition(t)
      .attr("x", (d) => (x(d.x0) + x(d.x1)) / 2)
      .attr("y", (d) => (y(d.y0) + y(d.y1)) / 2)
      .attr("clip-path", (d) => `url(#${safeIdFor(d)})`)
      .attr("opacity", (d) => {
        const rel = d.depth - focus.depth;
        if (rel < 1) return 0;
        if (d.children && d.children.length) return 0;
        if (focus.depth === 0 && rel === 1) return 0;
        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        if (w < 84 || h < 44) return 0;
        return rel === 1 ? 0.98 : 0.95;
      });

    merged.select("text.cell-label").each(function (d) {
      const w = x(d.x1) - x(d.x0);
      const h = y(d.y1) - y(d.y0);
      const rel = Math.max(1, d.depth - focus.depth);
      const base = Math.min(w, h);
      const fs = clampNum(
        Math.floor(base / (rel <= 1 ? 6.8 : 7.8)),
        12,
        rel <= 1 ? 28 : 22,
      );

      const nodeSel = d3.select(this);
      nodeSel
        .style("font-size", `${fs}px`)
        .style("fill", "#ffffff")
        .style("stroke", "none")
        .style("stroke-width", "0px");

      const cx = (x(d.x0) + x(d.x1)) / 2;
      const cy = (y(d.y0) + y(d.y1)) / 2;
      nodeSel.selectAll("tspan").remove();

      const name = String(d.data?.display_name || d.data?.key || "");
      const isLeaf = !(d.children && d.children.length);
      const availW = Math.max(0, w - 18);
      const maxCharsPerLine = clampNum(
        Math.floor(availW / Math.max(1, fs * 0.58)),
        6,
        28,
      );
      const maxLabelLines = h >= 140 && w >= 140 ? 3 : h >= 84 ? 2 : 1;
      const labelLines = wrapLabelWords(name, maxCharsPerLine, maxLabelLines);

      const showCount = isLeaf ? w >= 96 && h >= 54 : w >= 110 && h >= 50;
      const countText = showCount ? countLabelFor(d, w) : "";

      const lineHeightEm = 1.08;
      const totalLines = labelLines.length + (countText ? 1 : 0);
      const startDy = -((totalLines - 1) / 2) * lineHeightEm;

      labelLines.forEach((line, idx) => {
        nodeSel
          .append("tspan")
          .attr("x", cx)
          .attr("dy", `${idx === 0 ? startDy : lineHeightEm}em`)
          .style("font-weight", 800)
          .text(line);
      });

      if (countText) {
        nodeSel
          .append("tspan")
          .attr("x", cx)
          .attr("dy", `${lineHeightEm}em`)
          .style("font-size", `${Math.max(11, Math.floor(fs * 0.78))}px`)
          .style("font-weight", 850)
          .attr("opacity", 0.92)
          .text(countText);
      }

      nodeSel.attr("x", cx).attr("y", cy);
    });

    cell.exit().transition(t).attr("opacity", 0).remove();
  }

  function resetAll() {
    state.selectedNodeId = null;
    updateActiveFilterSummary();
    zoomTo(root);
    updateTreemapDetailsFor(root);
    refreshProjects();
  }

  svg.on("click", () => resetAll());
  zoomTo(root);

  state.treemapApi = {
    reset: resetAll,
    zoomToId: (id) => {
      const target = root
        .descendants()
        .find((d) => Number(d.data?.id) === Number(id));
      if (!target) return false;
      setSelectedFromNode(target);
      if (target.children && target.children.length) {
        zoomTo(target);
      } else if (target.parent) {
        zoomTo(target.parent);
      }
      return true;
    },
  };
}

async function loadFrameworkCatalogue() {
  const fw = state.activeFramework;
  if (!fw?.id) {
    state.catalogueTree = [];
    state.nodeById.clear();
    state.nodePathById.clear();
    state.nodeIdByPath.clear();
    renderCatalogueTreemap();
    return;
  }

  const data = await apiFetch(
    `/v1/frameworks/${fw.id}/catalogue?latest_only=true`,
  );
  state.catalogueTree = Array.isArray(data?.tree) ? data.tree : [];

  state.nodeById.clear();
  state.nodePathById.clear();
  state.nodeIdByPath.clear();
  (Array.isArray(data?.items) ? data.items : []).forEach((n) => {
    if (!n?.id) return;
    state.nodeById.set(Number(n.id), {
      id: Number(n.id),
      key: n.key,
      display_name: n.display_name,
      parent_id: n.parent_id ? Number(n.parent_id) : null,
      description: n.description,
      project_count_direct: Number(n.project_count_direct || 0),
      project_count_descendants: Number(n.project_count_descendants || 0),
      project_count_total: Number(n.project_count_total || 0),
      projects_direct: Array.isArray(n.projects_direct)
        ? n.projects_direct
        : [],
      projects_total: Array.isArray(n.projects_total) ? n.projects_total : [],
    });
    state.nodePathById.set(
      Number(n.id),
      n.path || n.display_name || n.key || String(n.id),
    );

    // Also build a reverse lookup for capability-path colouring in the project list.
    const rawPath = n.path || n.display_name || n.key || String(n.id);
    const parts = splitPathParts(rawPath);
    const fullKey = normalizePathKey(rawPath);
    if (fullKey && !state.nodeIdByPath.has(fullKey))
      state.nodeIdByPath.set(fullKey, Number(n.id));
    // Alias without the root segment (some endpoints omit the framework root in capability_paths).
    if (parts.length > 1) {
      const aliasKey = parts.slice(1).join(" > ").toLowerCase();
      if (aliasKey && !state.nodeIdByPath.has(aliasKey))
        state.nodeIdByPath.set(aliasKey, Number(n.id));
    }
  });

  // If current selection no longer exists, clear it.
  if (
    state.selectedNodeId &&
    !state.nodeById.has(Number(state.selectedNodeId))
  ) {
    state.selectedNodeId = null;
  }

  renderCatalogueTreemap();
}

function wireEvents() {
  let qTimer = null;
  el.q.addEventListener("input", () => {
    updateActiveFilterSummary();
    if (!autoApplyEnabled()) return;
    if (qTimer) window.clearTimeout(qTimer);
    qTimer = window.setTimeout(() => {
      refreshProjects();
    }, 250);
  });

  el.languageFilter?.addEventListener("change", () => {
    updateActiveFilterSummary();
    if (!autoApplyEnabled()) return;
    refreshProjects();
  });

  el.statusFilter?.addEventListener("change", () => {
    updateActiveFilterSummary();
    if (!autoApplyEnabled()) return;
    refreshProjects();
  });

  // Capability search: press Enter to jump/zoom to the first matching capability.
  el.capabilitySearch.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    const term = (el.capabilitySearch.value || "").trim().toLowerCase();
    if (!term) return;

    const matches = Array.from(state.nodePathById.entries())
      .map(([id, path]) => ({ id, path: String(path || "").toLowerCase() }))
      .filter((x) => x.path.includes(term));
    if (!matches.length) {
      toast("No matching capabilities.", "warn");
      return;
    }
    const targetId = matches[0].id;
    const ok = state.treemapApi?.zoomToId?.(targetId);
    if (!ok) toast("Unable to zoom to that capability.", "warn");
  });

  el.applyFiltersBtn.addEventListener("click", () => {
    refreshProjects();
  });

  el.autoApplyFilters?.addEventListener("change", async () => {
    try {
      await saveUserPreferences({
        auto_apply_enabled: !!el.autoApplyFilters.checked,
      });
      toast("Auto-apply preference saved.", "success");
    } catch (err) {
      toast(err?.message || "Failed to save auto-apply preference", "error");
    }
  });

  el.resetFiltersBtn.addEventListener("click", () => {
    resetFilters();
  });

  el.selectVisibleBtn?.addEventListener("click", () => {
    if (!state.canBuildManifests) return;
    state.projects.forEach((c) => state.selectedProjectIds.add(c.id));
    renderProjects();
    updateSelectionInfo();
  });

  el.clearSelectionBtn?.addEventListener("click", () => {
    state.selectedProjectIds.clear();
    renderProjects();
    updateSelectionInfo();
  });

  for (const [button, format] of [
    [el.exportJsonBtn, "json"],
    [el.exportXlsxBtn, "xlsx"],
    [el.exportMdBtn, "markdown"],
  ]) {
    button?.addEventListener("click", () =>
      reporting(() => exportManifest(format), "Failed to export manifest"),
    );
  }
  el.saveManifestBtn?.addEventListener("click", () =>
    reporting(saveManifest, "Failed to save manifest"),
  );

  window.addEventListener("resize", () => {
    // Re-render treemap on resize (layout uses container size).
    renderCatalogueTreemap();
  });
}

async function init() {
  state.me = await initAuth({ redirectOnFail: true });
  if (!state.me) return;

  if (el.autoApplyFilters) {
    el.autoApplyFilters.checked = getAutoApplyEnabled();
  }

  state.canBuildManifests = canExportManifests();

  // Viewers (and other non-privileged roles) should not see the manifest builder at all.
  if (el.manifestBuilderCard && !state.canBuildManifests) {
    el.manifestBuilderCard.style.display = "none";
  }

  await loadFrameworks();
  state.frameworks = getFrameworks();
  state.activeFramework = getActiveFramework();

  wireEvents();

  await loadFrameworkCatalogue();
  updateActiveFilterSummary();
  await loadProjects();
}

document.addEventListener("DOMContentLoaded", () => {
  init().catch((err) => {
    console.error(err);
    toast(err?.message || "Failed to load page", "error");
  });
});
