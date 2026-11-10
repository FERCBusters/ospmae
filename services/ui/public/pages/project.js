const {
  api: apiFetch,
  initAuth,
  canMaintainProjects,
  canExportManifests,
  loadFrameworks,
  getFrameworks,
  getActiveFramework,
  nodeColor: nodeColorForKey,
  toast,
  loadEntityChangelog,
} = window.OSPMAE;

const state = {
  me: null,
  frameworks: [],
  activeFramework: null,
  projectId: null,
  project: null,
  versions: [],
  currentVersionId: null,
  graphData: null,
  activeTab: "visualise",
  svg: null,
  viewport: null,
  zoomBehavior: null,
  homeTransform: null,

  // Manifest save UI
  manifestSuggestedName: null,

  // Dependency map
  depGraphData: null,
  depGraphVersionId: null,
  depSvg: null,
  depViewport: null,
  depZoomBehavior: null,
  depHomeTransform: null,
  depSvgSize: null,
  depOnlyVulnOnly: false,
  canRunDependencyDiscovery: false,
  changelogLoaded: false,
};

const TAB_HASHES = Object.freeze({
  visualise: "visualise",
  dependency: "dependencies",
  questions: "questions",
  metadata: "metadata",
  changelog: "changelog",
});

const TAB_ALIASES = Object.freeze({
  visualise: "visualise",
  visualize: "visualise",
  dependency: "dependency",
  dependencies: "dependency",
  questions: "questions",
  metadata: "metadata",
  changelog: "changelog",
});

function normalizeTabName(value) {
  const raw = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^#/, "");
  return TAB_ALIASES[raw] || null;
}

function tabFromLocation() {
  const fromHash = normalizeTabName(window.location.hash || "");
  if (fromHash) return fromHash;
  try {
    const params = new URLSearchParams(window.location.search || "");
    return normalizeTabName(params.get("tab")) || "visualise";
  } catch (_) {
    return "visualise";
  }
}

function rememberTabInHash(tabName) {
  const normalized = normalizeTabName(tabName) || "visualise";
  const hash = TAB_HASHES[normalized] || normalized;
  const nextUrl = `${window.location.pathname}${window.location.search}#${hash}`;
  if (
    `${window.location.pathname}${window.location.search}${window.location.hash}` ===
    nextUrl
  )
    return;
  try {
    window.history.replaceState(null, "", nextUrl);
  } catch (_) {
    window.location.hash = hash;
  }
}

const el = {
  whoami: document.getElementById("whoami"),
  projectTitle: document.getElementById("projectTitle"),
  projectSubTitle: document.getElementById("projectSubTitle"),
  editProjectLink: document.getElementById("editProjectLink"),
  subscribeBtn: document.getElementById("subscribeBtn"),
  subscriptionModal: document.getElementById("subscriptionModal"),
  subNotifyNewVersions: document.getElementById("subNotifyNewVersions"),
  subNotifyQuestions: document.getElementById("subNotifyQuestions"),
  subscriptionSaveBtn: document.getElementById("subscriptionSaveBtn"),
  subscriptionUnsubscribeBtn: document.getElementById(
    "subscriptionUnsubscribeBtn",
  ),

  tabMetadataBtn: document.getElementById("tabMetadataBtn"),
  tabVisualiseBtn: document.getElementById("tabVisualiseBtn"),
  tabDependencyBtn: document.getElementById("tabDependencyBtn"),
  tabQuestionsBtn: document.getElementById("tabQuestionsBtn"),
  tabChangelogBtn: document.getElementById("tabChangelogBtn"),
  metadataTab: document.getElementById("metadataTab"),
  visualiseTab: document.getElementById("visualiseTab"),
  dependencyTab: document.getElementById("dependencyTab"),
  questionsTab: document.getElementById("questionsTab"),
  changelogTab: document.getElementById("changelogTab"),
  projectChangelog: document.getElementById("projectChangelog"),

  projectMetadata: document.getElementById("projectMetadata"),
  versionSelect: document.getElementById("versionSelect"),
  visualTypeSelect: document.getElementById("visualTypeSelect"),
  visualSummary: document.getElementById("visualSummary"),
  graph: document.getElementById("graph"),
  exportGraphPdfBtn: document.getElementById("exportGraphPdfBtn"),
  exportGraphJpegBtn: document.getElementById("exportGraphJpegBtn"),

  // Manifest export
  manifestExportField: document.getElementById("manifestExportField"),
  exportManifestJsonBtn: document.getElementById("exportManifestJsonBtn"),
  exportManifestXlsxBtn: document.getElementById("exportManifestXlsxBtn"),
  exportManifestMdBtn: document.getElementById("exportManifestMdBtn"),
  saveProjectManifestBtn: document.getElementById("saveProjectManifestBtn"),
  projectManifestName: document.getElementById("projectManifestName"),
  projectManifestDescription: document.getElementById(
    "projectManifestDescription",
  ),

  // Dependency map
  depVersionSelect: document.getElementById("depVersionSelect"),
  depVisualTypeSelect: document.getElementById("depVisualTypeSelect"),
  depOnlyVulnToggle: document.getElementById("depOnlyVulnToggle"),
  depScanStatus: document.getElementById("depScanStatus"),
  depRunDiscoveryBtn: document.getElementById("depRunDiscoveryBtn"),
  depScanMeta: document.getElementById("depScanMeta"),
  depSummary: document.getElementById("depSummary"),
  depGraph: document.getElementById("depGraph"),
  depZoomInBtn: document.getElementById("depZoomInBtn"),
  depZoomOutBtn: document.getElementById("depZoomOutBtn"),
  depZoomResetBtn: document.getElementById("depZoomResetBtn"),
  exportDepPdfBtn: document.getElementById("exportDepPdfBtn"),
  exportDepJpegBtn: document.getElementById("exportDepJpegBtn"),
  depVulnCard: document.getElementById("depVulnCard"),
  depVulnCountBadge: document.getElementById("depVulnCountBadge"),
  depVulnSummary: document.getElementById("depVulnSummary"),
  depVulnList: document.getElementById("depVulnList"),

  // Questions
  questionsMeta: document.getElementById("questionsMeta"),
  questionsInfo: document.getElementById("questionsInfo"),
  questionsList: document.getElementById("questionsList"),
  askQuestionBox: document.getElementById("askQuestionBox"),
  askQuestionForm: document.getElementById("askQuestionForm"),
  askQuestionBody: document.getElementById("askQuestionBody"),

  zoomInBtn: document.getElementById("zoomInBtn"),
  zoomOutBtn: document.getElementById("zoomOutBtn"),
  zoomResetBtn: document.getElementById("zoomResetBtn"),
};

function renderSubscribeBtn() {
  if (!el.subscribeBtn) return;
  // Authenticated users can subscribe (all roles).
  el.subscribeBtn.style.display = "";

  const subscribed = !!state.project?.is_subscribed;
  el.subscribeBtn.classList.toggle("btn-outline-primary", !subscribed);
  el.subscribeBtn.classList.toggle("btn-outline-secondary", subscribed);

  el.subscribeBtn.innerHTML = subscribed
    ? '<i class="bi bi-bell-fill"></i> Subscribed'
    : '<i class="bi bi-bell"></i> Subscribe';
}

let subscriptionModalInstance = null;

function ensureSubscriptionModal() {
  if (!el.subscriptionModal) return null;
  if (!subscriptionModalInstance) {
    subscriptionModalInstance = new bootstrap.Modal(el.subscriptionModal, {
      backdrop: "static",
    });
  }
  return subscriptionModalInstance;
}

async function openSubscriptionModal() {
  if (!state.projectId) return;
  const modal = ensureSubscriptionModal();
  if (!modal) {
    // Fallback to old toggle behaviour if modal missing.
    return toggleSubscriptionLegacy();
  }

  try {
    el.subscribeBtn?.setAttribute("disabled", "disabled");
    const sub = await apiFetch(`/v1/projects/${state.projectId}/subscription`, {
      method: "GET",
    });
    const subscribed = !!sub?.subscribed;

    // Defaults for a new subscription.
    const notifyNew = subscribed ? !!sub?.notify_new_versions : true;
    const notifyQ = subscribed ? !!sub?.notify_questions : false;

    if (el.subNotifyNewVersions) el.subNotifyNewVersions.checked = notifyNew;
    if (el.subNotifyQuestions) el.subNotifyQuestions.checked = notifyQ;

    if (el.subscriptionUnsubscribeBtn) {
      el.subscriptionUnsubscribeBtn.style.display = subscribed ? "" : "none";
    }

    modal.show();
  } catch (err) {
    console.error(err);
    const msg = err?.message || "Failed to load subscription settings.";
    toast(msg, "error");
  } finally {
    el.subscribeBtn?.removeAttribute("disabled");
  }
}

async function saveSubscriptionFromModal() {
  if (!state.projectId) return;
  const notify_new_versions = !!el.subNotifyNewVersions?.checked;
  const notify_questions = !!el.subNotifyQuestions?.checked;

  try {
    el.subscriptionSaveBtn?.setAttribute("disabled", "disabled");
    const res = await apiFetch(`/v1/projects/${state.projectId}/subscription`, {
      method: "POST",
      body: { notify_new_versions, notify_questions },
    });

    const subscribed = !!res?.subscribed;
    state.project.is_subscribed = subscribed;
    renderSubscribeBtn();

    const modal = ensureSubscriptionModal();
    modal?.hide();

    toast(subscribed ? "Subscription saved" : "Unsubscribed", "success");
  } catch (err) {
    console.error(err);
    const msg = err?.message || "Failed to update subscription.";
    toast(msg, "error");
    if ((msg || "").toLowerCase().includes("email")) {
      toast("Tip: set your email address in Account → Profile.", "info", {
        delay: 5200,
      });
    }
  } finally {
    el.subscriptionSaveBtn?.removeAttribute("disabled");
  }
}

async function unsubscribeFromModal() {
  if (!state.projectId) return;
  try {
    el.subscriptionUnsubscribeBtn?.setAttribute("disabled", "disabled");
    await apiFetch(`/v1/projects/${state.projectId}/subscription`, {
      method: "DELETE",
    });
    state.project.is_subscribed = false;
    renderSubscribeBtn();
    ensureSubscriptionModal()?.hide();
    toast("Unsubscribed", "success");
  } catch (err) {
    console.error(err);
    toast(err?.message || "Failed to unsubscribe.", "error");
  } finally {
    el.subscriptionUnsubscribeBtn?.removeAttribute("disabled");
  }
}

// Legacy: old subscribe/unsubscribe toggle (kept as fallback)
async function toggleSubscriptionLegacy() {
  if (!state.projectId) return;
  const subscribed = !!state.project?.is_subscribed;
  try {
    el.subscribeBtn?.setAttribute("disabled", "disabled");
    if (subscribed) {
      await apiFetch(`/v1/projects/${state.projectId}/subscription`, {
        method: "DELETE",
      });
      state.project.is_subscribed = false;
      toast("Unsubscribed", "success");
    } else {
      await apiFetch(`/v1/projects/${state.projectId}/subscription`, {
        method: "POST",
      });
      state.project.is_subscribed = true;
      toast("Subscribed", "success");
    }
    renderSubscribeBtn();
  } catch (err) {
    console.error(err);
    const msg = err?.message || "Failed to update subscription.";
    toast(msg, "error");
    if ((msg || "").toLowerCase().includes("email")) {
      toast("Tip: set your email address in Account → Profile.", "info", {
        delay: 5200,
      });
    }
  } finally {
    el.subscribeBtn?.removeAttribute("disabled");
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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

function renderWebsiteCell(url) {
  const raw = String(url ?? "").trim();
  if (!raw) return "—";
  const safe = safeHref(raw);
  if (safe) {
    return `<a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer">Website</a>`;
  }
  return `<span class="text-secondary">${escapeHtml(raw)}</span>`;
}

function trimLabel(value, max = 8) {
  const v = String(value || "");
  if (v.length <= max) return v;
  return `${v.slice(0, max - 1)}…`;
}

const DEP_ONLY_VULN_KEY = "ospmae_dep_only_vuln_only";

function readBoolStorage(key, fallback = false) {
  try {
    const v = window.localStorage?.getItem?.(key);
    if (v == null) return fallback;
    return v === "1" || v === "true";
  } catch (_) {
    return fallback;
  }
}

function writeBoolStorage(key, value) {
  try {
    window.localStorage?.setItem?.(key, value ? "1" : "0");
  } catch (_) {
    // ignore
  }
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

function suggestProjectManifestName() {
  if (!state.projectId) return "project-manifest";
  const proj = safeFilename(
    state.project?.machine_name ||
      state.project?.display_name ||
      `project_${state.projectId}`,
  );
  const ver = safeFilename(
    state.versions?.find((x) => x.id === state.currentVersionId)?.version ||
      String(state.currentVersionId || "latest"),
  );
  return `${proj}_${ver}_manifest`;
}

function updateProjectManifestNameSuggestion(force = false) {
  if (!el.projectManifestName) return;
  const suggested = suggestProjectManifestName();
  const current = String(el.projectManifestName.value || "").trim();
  if (force || !current || current === state.manifestSuggestedName) {
    el.projectManifestName.value = suggested;
    state.manifestSuggestedName = suggested;
  }
}

async function exportProjectManifest(format) {
  if (!state.projectId) return;

  const name = suggestProjectManifestName();

  const query = {
    format,
    name,
    framework_id: state.activeFramework?.id || undefined,
    version_id: state.currentVersionId || undefined,
  };

  const path = `/v1/projects/${state.projectId}/manifest/export${toQueryString(query)}`;
  try {
    const blob = await apiFetch(path, { responseType: "blob" });
    const ext =
      format === "xlsx" ? "xlsx" : format === "markdown" ? "md" : "json";
    downloadBlob(blob, `${name}.${ext}`);
  } catch (err) {
    console.error(err);
    toast(err?.message || "Failed to export manifest", "error");
  }
}

async function saveProjectManifest() {
  if (!state.projectId) return;

  const suggested = suggestProjectManifestName();
  const name = (el.projectManifestName?.value || "").trim() || suggested;
  const description =
    (el.projectManifestDescription?.value || "").trim() || null;

  const query = {
    framework_id: state.activeFramework?.id || undefined,
    version_id: state.currentVersionId || undefined,
  };

  const body = {
    name,
    description,
    framework_id: state.activeFramework?.id || undefined,
    node_ids: [],
    project_ids: [state.projectId],
    q: null,
    owner_group_id: null,
  };

  const path = `/v1/projects/${state.projectId}/manifest/save${toQueryString(query)}`;

  try {
    const res = await apiFetch(path, { method: "POST", body });
    toast(`Saved manifest “${res?.name || name}”`, "success");
  } catch (err) {
    console.error(err);
    toast(err?.message || "Failed to save manifest", "error");
  }
}

function roleOf(me) {
  return me?.effective_role || me?.role || "viewer";
}

// Local helper (app.js also has a role() helper, but it's inside an IIFE and not global).
function role() {
  return String(roleOf(state.me) || "viewer").toLowerCase();
}

function canRunDependencyDiscovery() {
  const r = role();
  if (r === "admin") return true;
  const ownerId = Number(state.project?.created_by_user_id || 0);
  const meId = Number(state.me?.id || 0);
  if (ownerId > 0 && meId > 0 && ownerId === meId) return true;

  // The API also permits project owner groups. /v1/me does not expose group
  // membership, so the client can only positively identify direct owners here.
  return false;
}

function applyDependencyRunPolicy() {
  const allowed = !!canRunDependencyDiscovery();
  state.canRunDependencyDiscovery = allowed;

  if (el.depRunDiscoveryBtn) {
    el.depRunDiscoveryBtn.disabled = !allowed;
    el.depRunDiscoveryBtn.title = allowed
      ? ""
      : "Only the project owner or admins can run discovery.";
  }
}

function setTab(tabName, options = {}) {
  const normalized = normalizeTabName(tabName) || "visualise";
  state.activeTab = normalized;
  if (options.updateLocation !== false) {
    rememberTabInHash(normalized);
  }

  const isMetadata = normalized === "metadata";
  const isVisualise = normalized === "visualise";
  const isDependency = normalized === "dependency";
  const isQuestions = normalized === "questions";
  const isChangelog = normalized === "changelog";

  // Panels
  el.metadataTab?.classList.toggle("active", isMetadata);
  el.visualiseTab?.classList.toggle("active", isVisualise);
  el.dependencyTab?.classList.toggle("active", isDependency);
  el.questionsTab?.classList.toggle("active", isQuestions);
  el.changelogTab?.classList.toggle("active", isChangelog);

  // Buttons
  el.tabMetadataBtn?.classList.toggle("active", isMetadata);
  el.tabVisualiseBtn?.classList.toggle("active", isVisualise);
  el.tabDependencyBtn?.classList.toggle("active", isDependency);
  el.tabQuestionsBtn?.classList.toggle("active", isQuestions);
  el.tabChangelogBtn?.classList.toggle("active", isChangelog);

  el.tabMetadataBtn?.setAttribute("aria-selected", String(isMetadata));
  el.tabVisualiseBtn?.setAttribute("aria-selected", String(isVisualise));
  el.tabDependencyBtn?.setAttribute("aria-selected", String(isDependency));
  el.tabQuestionsBtn?.setAttribute("aria-selected", String(isQuestions));
  el.tabChangelogBtn?.setAttribute("aria-selected", String(isChangelog));

  if (isVisualise) {
    renderVisualization();
  }

  if (isDependency) {
    ensureDependencyGraphLoaded().catch((err) => {
      console.error(err);
      clearDepGraph(err?.message || "Failed to load dependency graph");
    });
  }

  if (isQuestions) {
    loadQuestionsIfNeeded();
  }

  if (isChangelog) {
    loadProjectChangelog().catch((err) => {
      console.error(err);
      if (el.projectChangelog) {
        el.projectChangelog.innerHTML =
          '<div class="text-danger p-3">Failed to load changelog.</div>';
      }
    });
  }
}

async function loadProjectChangelog() {
  if (!state.projectId || state.changelogLoaded) return;
  await loadEntityChangelog(
    el.projectChangelog,
    `/v1/projects/${encodeURIComponent(String(state.projectId))}/changelog?limit=100`,
    { empty: "No project changelog entries yet." },
  );
  state.changelogLoaded = true;
}

function formatDate(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toISOString().slice(0, 10);
  } catch {
    return String(iso);
  }
}

function listCapabilityPathsForVersion(versionId) {
  if (!state.project || !Array.isArray(state.project.versions)) return [];
  const version = state.project.versions.find((v) => v.id === versionId);
  if (!version) return [];

  // Preferred: per-version capability paths (relational payload).
  const versionPaths = Array.isArray(version.capability_paths)
    ? version.capability_paths.filter(Boolean)
    : [];
  if (versionPaths.length) return versionPaths;

  const paths = Array.isArray(state.project.capability_paths)
    ? state.project.capability_paths.filter(Boolean)
    : [];

  if (!paths.length) return [];

  if (versionId === state.project.latest_version?.id) {
    return paths;
  }

  // For non-latest version we do not always have paths in payload; fallback to latest paths.
  return paths;
}

function slugifyCapabilityPart(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[\/:+(),]/g, " ")
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function colorKeyForCapabilityPath(path) {
  const parts = String(path || "")
    .split(">")
    .map((p) => slugifyCapabilityPart(p))
    .filter(Boolean);

  if (!parts.length) return "technology_capabilities";

  // Under "Channel Tier" the desired color is the first child (e.g., Admin UI, SDK and API).
  if (parts[0] === "channel_tier" && parts[1]) {
    return parts[1];
  }

  // UWRA paths often start with the root "Technology Capabilities".
  if (parts[0] === "technology_capabilities" && parts[1]) {
    return parts[1];
  }

  return parts[0] || "technology_capabilities";
}

function capabilityColorForPath(path) {
  const fw = state.activeFramework;
  const prefix = fw?.machine_name ? `${fw.machine_name}:` : "";
  return nodeColorForKey(`${prefix}${colorKeyForCapabilityPath(path)}`);
}

function pathFromParts(parts) {
  return (parts || []).filter(Boolean).join(" > ");
}

function buildCapabilityTreeFromPaths(paths) {
  const safePaths = Array.isArray(paths)
    ? paths.map((p) => String(p || "").trim()).filter(Boolean)
    : [];

  if (!safePaths.length) return [];

  let seq = 0;
  const root = { children: new Map() };

  for (const rawPath of safePaths) {
    const parts = rawPath
      .split(">")
      .map((p) => p.trim())
      .filter(Boolean);
    if (!parts.length) continue;

    let cursor = root;
    for (let i = 0; i < parts.length; i += 1) {
      const display = parts[i];
      const key = slugifyCapabilityPart(display);

      if (!cursor.children.has(key)) {
        cursor.children.set(key, {
          id: -++seq,
          key,
          display_name: display,
          level: i,
          selected: false,
          children: new Map(),
        });
      }

      const node = cursor.children.get(key);
      if (i === parts.length - 1) {
        node.selected = true;
      }
      cursor = node;
    }
  }

  const toArray = (nodeMap) => {
    const arr = Array.from(nodeMap.values()).map((n) => ({
      id: n.id,
      key: n.key,
      display_name: n.display_name,
      level: n.level,
      selected: n.selected,
      children: toArray(n.children),
    }));

    arr.sort((a, b) =>
      String(a.display_name || "").localeCompare(String(b.display_name || "")),
    );
    return arr;
  };

  return toArray(root.children);
}

function graphHasCapabilities(graphData) {
  if (!graphData || typeof graphData !== "object") return false;
  if (
    Array.isArray(graphData.capability_tree) &&
    graphData.capability_tree.length > 0
  )
    return true;
  if (
    Array.isArray(graphData.capabilities) &&
    graphData.capabilities.length > 0
  )
    return true;
  return false;
}

function normalizeGraphData(graphData, versionId) {
  if (graphHasCapabilities(graphData)) return graphData;

  const fallbackPaths = listCapabilityPathsForVersion(versionId);
  const fallbackTree = buildCapabilityTreeFromPaths(fallbackPaths);
  if (!fallbackTree.length) {
    return graphData || null;
  }

  const version =
    (state.versions || []).find((v) => v.id === versionId) || null;
  return {
    version: {
      id: versionId,
      version: version?.version || null,
      is_latest: Boolean(version?.is_latest),
    },
    capability_tree: fallbackTree,
  };
}

function renderMetadata() {
  if (!state.project) {
    el.projectMetadata.innerHTML =
      '<div class="small">Project not found.</div>';
    return;
  }

  const c = state.project;
  const ownerGroupDisplay =
    Array.isArray(c.owner_groups) && c.owner_groups.length
      ? c.owner_groups
          .map((g) => g && g.name)
          .filter(Boolean)
          .join(", ")
      : c.owner_group || "—";
  const ownerGroupLabel =
    Array.isArray(c.owner_groups) && c.owner_groups.length > 1
      ? "Owner groups"
      : "Owner group";
  const languages = Array.isArray(c.programming_languages)
    ? c.programming_languages
    : [];
  const languageDisplay = languages.length ? languages.join(", ") : "—";
  const versions = Array.isArray(c.versions) ? c.versions : [];
  const capabilities = listCapabilityPathsForVersion(
    state.currentVersionId || c.latest_version?.id,
  );

  const capabilityPills = capabilities.length
    ? capabilities
        .map((path) => {
          const color = capabilityColorForPath(path);
          const short = path.includes(" > ")
            ? path.split(" > ").slice(-1)[0]
            : path;
          return `<span class="capability-pill selected small" style="--cap-color:${escapeHtml(color)}" title="${escapeHtml(path)}"><span class="pill-label">${escapeHtml(short)}</span></span>`;
        })
        .join(" ")
    : '<span class="small">No capability mappings on this version.</span>';

  const versionsRows = versions.length
    ? versions
        .map((v) => {
          const latestBadge = v.is_latest
            ? '<span class="badge text-bg-success ms-1">Latest</span>'
            : "";
          const draftBadge = v.is_draft
            ? '<span class="badge text-bg-warning ms-1">Draft</span>'
            : "";
          return `
          <tr>
            <td>${escapeHtml(v.version || "—")} ${latestBadge}${draftBadge}</td>
            <td>${escapeHtml(v.status || "—")}</td>
            <td>${escapeHtml(formatDate(v.release_date))}</td>
                        <td>${renderWebsiteCell(v.link_to_source_code)}</td>
          </tr>
        `;
        })
        .join("")
    : '<tr><td colspan="4" class="small">No versions available.</td></tr>';

  el.projectMetadata.innerHTML = `
    <div class="grid" style="display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; margin-bottom:12px;">
      <div class="card">
        <div class="card-header">
          <h3 class="h5 mb-0">Overview</h3>
        </div>
        <div class="card-body">
          <div><strong>Name:</strong> ${escapeHtml(c.display_name || c.machine_name)}</div>
          <div><strong>Machine name:</strong> ${escapeHtml(c.machine_name || "—")}</div>
          <div><strong>Organisation:</strong> ${escapeHtml(c.organisation || "—")}</div>
          <div><strong>Type:</strong> ${escapeHtml(c.project_type || "—")}</div>
          <div><strong>Languages:</strong> ${escapeHtml(languageDisplay)}</div>
          <div><strong>${escapeHtml(ownerGroupLabel)}:</strong> ${escapeHtml(ownerGroupDisplay)}</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="h5 mb-0">Description</h3>
        </div>
        <div class="card-body">
          <div class="small" style="white-space:pre-wrap;">${escapeHtml(c.description || "—")}</div>
          <h3 class="h6 mt-3 mb-2">Capabilities</h3>
          <div style="display:flex; flex-wrap:wrap; gap:6px;">${capabilityPills}</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3 class="h5 mb-0">Versions</h3>
      </div>
      <div class="card-body" style="overflow:auto;">
        <table class="table table-sm mb-0">
          <thead>
            <tr><th>Version</th><th>Status</th><th>Release date</th><th>Website</th></tr>
          </thead>
          <tbody>${versionsRows}</tbody>
        </table>
      </div>
    </div>
  `;
}

function buildGraphHierarchy(graphData) {
  if (!graphData) {
    return { name: state.project?.display_name || "Project", children: [] };
  }

  const versionLabel =
    graphData?.version?.version ||
    graphData?.version ||
    state.project?.versions?.find((v) => v.id === state.currentVersionId)
      ?.version ||
    state.project?.latest_version?.version ||
    "latest";

  const root = {
    id: `project-${state.projectId}`,
    name:
      state.project?.display_name || state.project?.machine_name || "Project",
    kind: "project",
    children: [
      {
        id: `version-${versionLabel}`,
        name: `v${versionLabel}`,
        kind: "version",
        children: [],
      },
    ],
  };

  const versionNode = root.children[0];

  if (
    Array.isArray(graphData.capability_tree) &&
    graphData.capability_tree.length
  ) {
    const mapTree = (node, keyPath = []) => {
      const ownKey = slugifyCapabilityPart(
        node.key || node.display_name || node.name || "",
      );
      const currentPath = ownKey ? [...keyPath, ownKey] : keyPath;
      return {
        id: `cap-${node.id ?? node.key ?? Math.random()}`,
        name: node.display_name || node.name || node.key || "Capability",
        kind: "capability",
        key: node.key,
        colorKey: colorKeyForCapabilityPath(pathFromParts(currentPath)),
        selected: Boolean(node.selected),
        level: Number(node.level ?? 0),
        children: Array.isArray(node.children)
          ? node.children.map((child) => mapTree(child, currentPath))
          : [],
      };
    };

    versionNode.children = graphData.capability_tree.map((node) =>
      mapTree(node, []),
    );
  } else if (
    Array.isArray(graphData.capabilities) &&
    graphData.capabilities.length
  ) {
    // Backward-compatible parser for older payload shape.
    const capabilities = graphData.capabilities;
    const byId = new Map();

    capabilities.forEach((cap) => {
      const parent = cap.parent_id ? byId.get(cap.parent_id) : null;
      const ownKey = slugifyCapabilityPart(
        cap.key || cap.name || cap.display_name || "",
      );
      const keyPath = parent?.keyPath ? [...parent.keyPath, ownKey] : [ownKey];

      byId.set(cap.id, {
        id: cap.id,
        name: cap.name || cap.display_name || cap.key || `Capability ${cap.id}`,
        kind: "capability",
        key: cap.key,
        keyPath,
        colorKey: colorKeyForCapabilityPath(pathFromParts(keyPath)),
        path: cap.path,
        level: Number(cap.level ?? 0),
        parent_id: cap.parent_id,
        children: [],
      });
    });

    capabilities.forEach((cap) => {
      const node = byId.get(cap.id);
      const parentId = cap.parent_id;
      if (parentId && byId.has(parentId)) {
        byId.get(parentId).children.push(node);
        return;
      }
      versionNode.children.push(node);
    });

    const stripInternal = (node) => {
      if (!node || typeof node !== "object") return node;
      const out = { ...node };
      delete out.keyPath;
      out.children = Array.isArray(out.children)
        ? out.children.map(stripInternal)
        : [];
      return out;
    };

    versionNode.children = versionNode.children.map(stripInternal);
  }

  const sortTree = (node) => {
    if (!Array.isArray(node.children)) return;
    node.children.sort((a, b) =>
      String(a.name || "").localeCompare(String(b.name || "")),
    );
    node.children.forEach(sortTree);
  };
  sortTree(root);

  return root;
}

function nodeColor(node) {
  const key =
    node?.data?.colorKey ||
    (node?.data?.kind === "version" ? "technology_capabilities" : null) ||
    "technology_capabilities";
  const fw = state.activeFramework;
  const prefix = fw?.machine_name ? `${fw.machine_name}:` : "";
  return nodeColorForKey(`${prefix}${key}`);
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

function parseHexColor(hex) {
  const raw = String(hex || "").trim();
  const m = raw.match(/^#?([0-9a-fA-F]{6})$/);
  if (!m) return null;
  const value = m[1];
  return {
    r: parseInt(value.slice(0, 2), 16),
    g: parseInt(value.slice(2, 4), 16),
    b: parseInt(value.slice(4, 6), 16),
  };
}

function toHexColor(rgb) {
  const toHex = (v) =>
    Math.max(0, Math.min(255, Math.round(v)))
      .toString(16)
      .padStart(2, "0");
  return `#${toHex(rgb.r)}${toHex(rgb.g)}${toHex(rgb.b)}`;
}

function mixColor(baseHex, mixHex, amount) {
  const a = clamp01(amount);
  const base = parseHexColor(baseHex);
  const mix = parseHexColor(mixHex);
  if (!base || !mix) return baseHex;
  return toHexColor({
    r: base.r + (mix.r - base.r) * a,
    g: base.g + (mix.g - base.g) * a,
    b: base.b + (mix.b - base.b) * a,
  });
}

function relativeLuminance(hex) {
  const rgb = parseHexColor(hex);
  if (!rgb) return 0.5;
  // Fast sRGB luminance approximation (good enough for contrast decisions)
  const r = rgb.r / 255;
  const g = rgb.g / 255;
  const b = rgb.b / 255;
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastTextFor(bgHex) {
  const lum = relativeLuminance(bgHex);
  // Pick near-black on light tiles, white on dark tiles.
  return lum >= 0.62 ? "#111111" : "#ffffff";
}

function outlineForTextFill(textFill) {
  // Outline with opposite polarity.
  return relativeLuminance(textFill) >= 0.62
    ? "rgba(0,0,0,0.72)"
    : "rgba(255,255,255,0.78)";
}

function sunburstNodeColor(node, maxDepth) {
  const base = nodeColor(node);
  const depth = Number(node?.depth || 0);
  const depthNorm = maxDepth > 0 ? depth / maxDepth : 0;

  // Depth-aware palette shading while preserving family hue:
  // inner rings slightly darker, outer rings lighter.
  if (depth <= 1) {
    return mixColor(base, "#000000", 0.08);
  }

  const lightAmount = 0.08 + clamp01(depthNorm) * 0.22;
  const leafBoost = node?.children ? 0 : 0.06;
  return mixColor(base, "#ffffff", clamp01(lightAmount + leafBoost));
}

function treemapNodeColor(node, maxDepth) {
  // Treemap wants stronger contrast (less pastel/grungy) while preserving the user's hue family.
  // Use HSL if available (D3 is present in the browser).
  const base = nodeColor(node);
  const d3 = window.d3;
  if (!d3 || typeof d3.hsl !== "function") return base;

  const depth = Number(node?.depth || 0);
  const depthNorm = maxDepth > 0 ? clamp01(depth / maxDepth) : 0;
  const isLeaf = !(node?.children && node.children.length);

  let c;
  try {
    c = d3.hsl(base);
  } catch (_) {
    return base;
  }

  // Boost saturation and pull lightness down (especially for leaves) so
  // white labels remain readable without needing a glow/outline.
  c.s = clampNum((c.s || 0) * 1.28 + 0.14, 0.26, 1.0);
  const lMul = 0.9 - depthNorm * 0.2 - (isLeaf ? 0.14 : 0.06);
  // Cap lightness harder for leaves (they carry the centered labels).
  c.l = clampNum((c.l || 0.5) * lMul, 0.12, isLeaf ? 0.62 : 0.74);

  return typeof c.formatHex === "function" ? c.formatHex() : String(c);
}

function clearGraph(message) {
  state.svg = null;
  state.viewport = null;
  state.zoomBehavior = null;
  state.homeTransform = null;

  if (!window.d3) {
    el.graph.innerHTML = '<div class="small">D3 library is unavailable.</div>';
    return;
  }

  el.graph.innerHTML = message
    ? `<div class="small" style="padding:8px;">${escapeHtml(message)}</div>`
    : "";
}

function graphDimensions() {
  const rect = el.graph.getBoundingClientRect();
  const width = Math.max(960, Math.floor(rect.width || 960));
  const height = Math.max(760, Math.floor(rect.height || 760));
  return { width, height };
}

function applyZoomButtonsEnabled(enabled) {
  [el.zoomInBtn, el.zoomOutBtn, el.zoomResetBtn].forEach((btn) => {
    if (btn) btn.disabled = !enabled;
  });
}

function attachPanZoom(svg, viewport, width, height, options = {}) {
  state.svg = svg;
  state.viewport = viewport;

  const d3 = window.d3;
  const homeTransform =
    options.homeTransform ||
    d3.zoomIdentity.translate(width * 0.08, 24).scale(1);

  const zoomBehavior = d3
    .zoom()
    .scaleExtent([0.2, 4])
    .on("zoom", (event) => {
      viewport.attr("transform", event.transform);
    });

  svg.call(zoomBehavior);
  svg.call(zoomBehavior.transform, homeTransform);
  state.zoomBehavior = zoomBehavior;
  state.homeTransform = homeTransform;
  applyZoomButtonsEnabled(true);
}

function zoomBy(factor) {
  if (!state.svg || !state.zoomBehavior) return;
  state.svg.transition().duration(180).call(state.zoomBehavior.scaleBy, factor);
}

function resetZoom() {
  if (!state.svg || !state.zoomBehavior) return;
  const d3 = window.d3;
  const { width } = graphDimensions();
  const homeTransform =
    state.homeTransform || d3.zoomIdentity.translate(width * 0.08, 24).scale(1);
  state.svg
    .transition()
    .duration(220)
    .call(state.zoomBehavior.transform, homeTransform);
}

function hierarchyFromState() {
  const d3 = window.d3;
  const tree = buildGraphHierarchy(state.graphData);
  const root = d3.hierarchy(tree);
  root.each((node) => {
    node.data.label = String(node.data.name || "");
  });
  return root;
}

function renderTidyTree() {
  const d3 = window.d3;
  const root = hierarchyFromState();
  const { width, height } = graphDimensions();

  const treeLayout = d3.tree().size([height - 80, width - 300]);
  treeLayout(root);

  const svg = d3
    .select(el.graph)
    .html("")
    .append("svg")
    .attr("viewBox", [0, 0, width, height])
    .attr("width", "100%")
    // Use an explicit pixel height so the container can grow and the page can scroll.
    .attr("height", height);

  const viewport = svg.append("g");

  viewport
    .append("g")
    .attr("fill", "none")
    .attr("stroke-opacity", 0.35)
    .attr("stroke-width", 1.4)
    .selectAll("path")
    .data(root.links())
    .join("path")
    .attr("stroke", (d) => nodeColor(d.target))
    .attr(
      "d",
      d3
        .linkHorizontal()
        .x((d) => d.y)
        .y((d) => d.x),
    );

  const nodes = viewport
    .append("g")
    .selectAll("g")
    .data(root.descendants())
    .join("g")
    .attr("transform", (d) => `translate(${d.y},${d.x})`);

  nodes
    .append("circle")
    .attr("r", 4)
    .attr("fill", (d) => sunburstNodeColor(d, root.height));

  nodes
    .append("text")
    .attr("dy", "0.31em")
    .attr("x", (d) => (d.children ? -8 : 8))
    .attr("text-anchor", (d) => (d.children ? "end" : "start"))
    .style("font-size", "11px")
    .text((d) => (d.depth >= 3 ? trimLabel(d.data.label, 12) : d.data.label))
    .append("title")
    .text((d) => d.data.label || "");

  attachPanZoom(svg, viewport, width, height);
  el.visualSummary.textContent = `${root.descendants().length} nodes, ${root.links().length} links`;
}

function renderRadialTree() {
  const d3 = window.d3;
  const root = hierarchyFromState();
  const { width, height } = graphDimensions();

  const radius = Math.min(width, height) / 2 - 48;
  const treeLayout = d3.tree().size([2 * Math.PI, radius]);
  treeLayout(root);

  const svg = d3
    .select(el.graph)
    .html("")
    .append("svg")
    .attr("viewBox", [0, 0, width, height])
    .attr("width", "100%")
    .attr("height", height);

  const zoomLayer = svg.append("g");
  const viewport = zoomLayer
    .append("g")
    .attr("transform", `translate(${width / 2},${height / 2})`);

  const radialPoint = (x, y) => [
    Math.cos(x - Math.PI / 2) * y,
    Math.sin(x - Math.PI / 2) * y,
  ];

  viewport
    .append("g")
    .attr("fill", "none")
    .attr("stroke-opacity", 0.35)
    .attr("stroke-width", 1.1)
    .selectAll("path")
    .data(root.links())
    .join("path")
    .attr("stroke", (d) => nodeColor(d.target))
    .attr("d", (d) => {
      const s = radialPoint(d.source.x, d.source.y);
      const t = radialPoint(d.target.x, d.target.y);
      return `M${s[0]},${s[1]}L${t[0]},${t[1]}`;
    });

  const nodes = viewport
    .append("g")
    .selectAll("g")
    .data(root.descendants())
    .join("g")
    .attr("transform", (d) => {
      const [x, y] = radialPoint(d.x, d.y);
      return `translate(${x},${y})`;
    });

  nodes
    .append("circle")
    .attr("r", 3.6)
    .attr("fill", (d) => nodeColor(d));

  nodes
    .append("text")
    .attr("dy", "0.31em")
    .attr("x", (d) => (d.x < Math.PI ? 8 : -8))
    .attr("text-anchor", (d) => (d.x < Math.PI ? "start" : "end"))
    .attr(
      "transform",
      (d) =>
        `rotate(${(d.x * 180) / Math.PI - 90}) translate(0) rotate(${d.x >= Math.PI ? 180 : 0})`,
    )
    .style("font-size", "10px")
    .text((d) => (d.depth >= 3 ? trimLabel(d.data.label, 8) : d.data.label))
    .append("title")
    .text((d) => d.data.label || "");

  attachPanZoom(svg, zoomLayer, width, height, {
    homeTransform: d3.zoomIdentity,
  });
  el.visualSummary.textContent = `${root.descendants().length} nodes in radial layout`;
}

function capabilityLeaves(rootHierarchy) {
  return rootHierarchy
    .descendants()
    .filter((d) => d.depth >= 2 && (!d.children || d.children.length === 0));
}

function renderBipartite() {
  const d3 = window.d3;
  const root = hierarchyFromState();
  const leaves = capabilityLeaves(root);
  const { width } = graphDimensions();

  // Grow vertically with the number of leaves so labels/links remain readable.
  const topPad = 40;
  const rowHeight = 18;
  const height = Math.max(760, topPad + leaves.length * rowHeight + 120);

  const svg = d3
    .select(el.graph)
    .html("")
    .append("svg")
    .attr("viewBox", [0, 0, width, height])
    .attr("width", "100%")
    .attr("height", height);

  const viewport = svg.append("g");

  const leftX = 160;
  const rightX = width - 280;

  const versionLabel = root.children?.[0]?.data?.label || "Version";

  viewport
    .append("rect")
    .attr("x", leftX - 80)
    .attr("y", height / 2 - 22)
    .attr("rx", 10)
    .attr("ry", 10)
    .attr("width", 160)
    .attr("height", 44)
    .attr(
      "fill",
      (() => {
        const fw = state.activeFramework;
        const prefix = fw?.machine_name ? `${fw.machine_name}:` : "";
        return nodeColorForKey(`${prefix}technology_capabilities`);
      })(),
    )
    .attr("opacity", 0.2);

  viewport
    .append("text")
    .attr("x", leftX)
    .attr("y", height / 2 + 4)
    .attr("text-anchor", "middle")
    .style("font-size", "12px")
    .text(versionLabel);

  const rows = leaves.map((leaf, idx) => ({
    node: leaf,
    y: topPad + idx * rowHeight,
  }));

  viewport
    .append("g")
    .attr("fill", "none")
    .attr("stroke-opacity", 0.28)
    .selectAll("path")
    .data(rows)
    .join("path")
    .attr("stroke", (d) => nodeColor(d.node))
    .attr("d", (d) => {
      const y = d.y;
      return `M${leftX + 80},${height / 2} C${leftX + 160},${height / 2} ${rightX - 160},${y} ${rightX - 8},${y}`;
    });

  viewport
    .append("g")
    .selectAll("circle")
    .data(rows)
    .join("circle")
    .attr("cx", rightX)
    .attr("cy", (d) => d.y)
    .attr("r", 3.2)
    .attr("fill", (d) => nodeColor(d.node));

  viewport
    .append("g")
    .selectAll("text")
    .data(rows)
    .join("text")
    .attr("x", rightX + 10)
    .attr("y", (d) => d.y + 3)
    .style("font-size", "11px")
    .text((d) => trimLabel(d.node.data.label, 18))
    .append("title")
    .text((d) => d.node.data.label || "");

  attachPanZoom(svg, viewport, width, height);
  el.visualSummary.textContent = `${rows.length} mapped capabilities`;
}

function renderSunburst() {
  const d3 = window.d3;
  const hierarchy = d3
    .hierarchy(buildGraphHierarchy(state.graphData))
    .sum((d) => (d.children && d.children.length ? 0 : 1))
    .sort((a, b) => b.value - a.value);

  const { width, height } = graphDimensions();
  const radius = Math.min(width, height) / 2 - 16;

  const partition = d3.partition().size([2 * Math.PI, hierarchy.height + 1]);
  const root = partition(hierarchy);
  root.each((d) => {
    d.current = d;
  });

  const format = d3.format(",d");

  const arc = d3
    .arc()
    .startAngle((d) => d.x0)
    .endAngle((d) => d.x1)
    .padAngle((d) => Math.min((d.x1 - d.x0) / 2, 0.005))
    .padRadius(radius * 1.5)
    .innerRadius((d) => (d.y0 * radius) / (root.height + 1))
    .outerRadius((d) =>
      Math.max(
        (d.y0 * radius) / (root.height + 1),
        (d.y1 * radius) / (root.height + 1) - 1,
      ),
    );

  const svg = d3
    .select(el.graph)
    .html("")
    .append("svg")
    .attr("viewBox", [0, 0, width, height])
    .attr("width", "100%")
    .attr("height", height);

  const viewport = svg
    .append("g")
    .attr("transform", `translate(${width / 2},${height / 2})`);

  const path = viewport
    .append("g")
    .selectAll("path")
    .data(root.descendants().slice(1))
    .join("path")
    .attr("fill", (d) => sunburstNodeColor(d, root.height))
    .attr("fill-opacity", (d) =>
      arcVisible(d.current) ? (d.children ? 0.65 : 0.4) : 0,
    )
    .attr("pointer-events", (d) => (arcVisible(d.current) ? "auto" : "none"))
    .attr("d", (d) => arc(d.current));

  path
    .filter((d) => d.children)
    .style("cursor", "pointer")
    .on("click", (_, p) => clicked(p));

  path.append("title").text(
    (d) =>
      `${d
        .ancestors()
        .map((a) => a.data.name)
        .reverse()
        .join(" > ")}\n${format(d.value)}`,
  );

  const label = viewport
    .append("g")
    .attr("pointer-events", "none")
    .attr("text-anchor", "middle")
    .style("user-select", "none")
    .selectAll("text")
    .data(root.descendants().slice(1))
    .join("text")
    .attr("dy", "0.35em")
    .attr("fill-opacity", (d) => +labelVisible(d.current))
    .attr("transform", (d) => labelTransform(d.current))
    .style("font-size", (d) =>
      d.depth >= 4 ? "9px" : d.depth >= 3 ? "10px" : "11px",
    )
    .text((d) => labelForNode(d));

  const parent = viewport
    .append("circle")
    .datum(root)
    .attr("r", radius / (root.height + 1))
    .attr("fill", "none")
    .attr("pointer-events", "all")
    .on("click", (_, p) => clicked(p));

  function arcVisible(d) {
    return d.y1 <= root.height + 1 && d.y0 >= 1 && d.x1 > d.x0;
  }

  function labelVisible(d) {
    if (!arcVisible(d)) return false;

    // Show labels across all visible depths, based on readable arc length,
    // so users get more detail in the initial zoomed-out view.
    const angle = Math.max(0, d.x1 - d.x0);
    const midRadius = (((d.y0 + d.y1) / 2) * radius) / (root.height + 1);
    const arcLength = angle * Math.max(midRadius, 1);

    // Slightly stricter for outer/deeper bands where slices are thinner.
    const minLength = d.depth >= 4 ? 20 : d.depth >= 3 ? 16 : 12;
    return arcLength >= minLength;
  }

  function labelForNode(d) {
    const name = String(d.data.name || "");
    const curr = d.current || d;

    const angle = Math.max(0, curr.x1 - curr.x0);
    const midRadius = (((curr.y0 + curr.y1) / 2) * radius) / (root.height + 1);
    const arcLength = angle * Math.max(midRadius, 1);

    // Approximate characters that fit on the arc; clamp to keep tidy.
    const maxChars = Math.max(6, Math.min(22, Math.floor(arcLength / 7)));
    return trimLabel(name, maxChars);
  }

  function labelTransform(d) {
    const x = (((d.x0 + d.x1) / 2) * 180) / Math.PI;
    const y = (((d.y0 + d.y1) / 2) * radius) / (root.height + 1);
    return `rotate(${x - 90}) translate(${y},0) rotate(${x < 180 ? 0 : 180})`;
  }

  function clicked(p) {
    parent.datum(p.parent || root);

    root.each((d) => {
      d.target = {
        x0:
          Math.max(0, Math.min(1, (d.x0 - p.x0) / (p.x1 - p.x0))) * 2 * Math.PI,
        x1:
          Math.max(0, Math.min(1, (d.x1 - p.x0) / (p.x1 - p.x0))) * 2 * Math.PI,
        y0: Math.max(0, d.y0 - p.depth),
        y1: Math.max(0, d.y1 - p.depth),
      };
    });

    const t = viewport.transition().duration(650);

    path
      .transition(t)
      .tween("data", (d) => {
        const i = d3.interpolate(d.current, d.target);
        return (tt) => {
          d.current = i(tt);
        };
      })
      .filter(function (d) {
        return +this.getAttribute("fill-opacity") || arcVisible(d.target);
      })
      .attr("fill-opacity", (d) =>
        arcVisible(d.target) ? (d.children ? 0.65 : 0.4) : 0,
      )
      .attr("pointer-events", (d) => (arcVisible(d.target) ? "auto" : "none"))
      .attrTween("d", (d) => () => arc(d.current));

    label
      .filter(function (d) {
        return +this.getAttribute("fill-opacity") || labelVisible(d.target);
      })
      .transition(t)
      .attr("fill-opacity", (d) => +labelVisible(d.target))
      .attrTween("transform", (d) => () => labelTransform(d.current))
      .tween("text", function (d) {
        const node = d3.select(this);
        return () => node.text(labelForNode(d));
      });
  }

  // Sunburst uses click-to-zoom internally; external zoom buttons are disabled.
  state.svg = null;
  state.viewport = null;
  state.zoomBehavior = null;
  applyZoomButtonsEnabled(false);
  el.visualSummary.textContent = `${root.descendants().length - 1} sunburst segments`;
}

function renderTreemap() {
  const d3 = window.d3;
  const { width, height } = graphDimensions();

  const graphTree = buildGraphHierarchy(state.graphData);
  const versionNode = graphTree?.children?.[0] || null;
  const capRoot = versionNode?.children?.length
    ? {
        id: "cap-root",
        name: "Capabilities",
        kind: "capability_root",
        children: versionNode.children,
      }
    : graphTree;

  const topPad = 28;
  const innerHeight = Math.max(240, height - topPad - 6);

  const root = d3
    .hierarchy(capRoot)
    .sum((d) => (d.children && d.children.length ? 0 : 1))
    .sort((a, b) => (b.value || 0) - (a.value || 0));

  // Mark nodes that include a selected leaf (from relational capability paths).
  root.eachAfter((d) => {
    d.anySelected =
      Boolean(d.data?.selected) ||
      (Array.isArray(d.children) && d.children.some((c) => c.anySelected));

    // Useful for tooltips/secondary labels.
    d.leafCount = Array.isArray(d.children)
      ? d.children.reduce((acc, c) => acc + (c.leafCount || 0), 0)
      : 1;
  });

  // Compute the full treemap layout once, then "zoom" by rescaling coordinates.
  // Reserve a "header" strip inside container nodes so overlay labels don't collide
  // with the top-most child tiles. Use deeper padding for higher-level containers
  // (they show a title + count line) to prevent label overlap.
  const headerPadFor = (d) => {
    if (!(d.depth > 0 && d.children && d.children.length)) return 0;
    if (d.depth === 1) return 48; // top categories (e.g. Channel Tier)
    if (d.depth === 2) return 42; // subcategories (e.g. SDK and API)
    return 34;
  };

  // Reserve left padding for narrow/tall container nodes that render a vertical overlay label strip,
  // so the strip doesn't overlap child tiles (e.g., Network Services -> Connectors).
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
    .select(el.graph)
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
    .text("Click a tile to zoom • Click background to reset");

  const cellsLayer = viewport
    .append("g")
    .attr("transform", `translate(0,${topPad})`);

  // A separate overlay layer so focus-level (container) labels remain visible
  // even when we draw grandchildren tiles on top.
  const labelsLayer = viewport
    .append("g")
    .attr("transform", `translate(0,${topPad})`);

  const keyFor = (d) =>
    d
      .ancestors()
      .map((a) => String(a.data?.id ?? a.data?.name ?? ""))
      .reverse()
      .join("/");

  const safeIdFor = (d) =>
    ("clip_" + keyFor(d)).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 220);

  const pathLabelFor = (d) =>
    d
      .ancestors()
      .map((a) => String(a.data?.name || ""))
      .reverse()
      .join(" > ");

  let focus = root;

  // How many levels to show at once (relative to the current focus).
  // depthSpan=4 means: show focus children + (up to) three more levels.
  // At the top-level this lets you see capability tiles without having to click into subcategories.
  const depthSpan = 4;

  function labelFor(d, w) {
    const name = String(d.data?.name || "");
    const maxChars = Math.max(6, Math.min(32, Math.floor((w - 14) / 7)));
    return trimLabel(name, maxChars);
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

      // If a single word is longer than the line budget, hard-cut it.
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

    // If we couldn't fit everything, ellipsize the last line.
    if (!usedAllWords && lines.length) {
      lines[lines.length - 1] = _ellipsize(
        lines[lines.length - 1],
        Math.max(4, maxCharsPerLine),
      );
    }

    return lines.slice(0, Math.max(1, maxLines));
  }

  function countLabelFor(d, w) {
    const leaves = Number(d.leafCount || d.value || 0);
    // Keep counts readable in small tiles by shortening the suffix.
    if (w < 70) return String(leaves);
    if (w < 110) return `${leaves} cap.`;
    return `${leaves} ${leaves === 1 ? "capability" : "capabilities"}`;
  }

  function isVerticalContainerLabel(d, w, h) {
    // Narrow-but-tall container nodes get a vertical title strip (bottom-to-top).
    if (!(d.children && d.children.length)) return false;
    return isNarrowTall(w, h);
  }

  function isVerticalOverlayLabel(d, w, h) {
    // Allow vertical labels for containers, and for top-level skinny leaf categories (so they aren't unlabeled).
    if (!isNarrowTall(w, h)) return false;
    if (d.children && d.children.length) return true;
    return focus && focus.depth === 0 && d.depth === 1;
  }

  function tileOpacity(d) {
    if (d.depth === 0) return 0;

    // Parent "container" tiles (immediate children of focus) should be a little lighter,
    // while deeper tiles can be more saturated.
    const rel = Math.max(1, d.depth - focus.depth);
    // Keep container tiles slightly translucent, but make leaf tiles much more opaque
    // so white labels are readable without a glow/outline.
    const base =
      rel === 1 ? (d.children ? 0.36 : 0.92) : d.children ? 0.56 : 0.95;
    const selBoost = d.anySelected ? 0.1 : 0;
    return clamp01(base + selBoost);
  }

  function zoomTo(newFocus) {
    focus = newFocus || root;

    // Scales that map the focused subtree into the full canvas.
    const x = d3.scaleLinear().domain([focus.x0, focus.x1]).range([0, width]);
    const y = d3
      .scaleLinear()
      .domain([focus.y0, focus.y1])
      .range([0, innerHeight]);

    // Render a *dense* view by showing a few levels at once under the current focus.
    // This keeps the nice "many tiles" default view (including capability tiles), but avoids
    // the old overlap/click issues by not drawing *all* descendants at every zoom level.
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

    // IMPORTANT: use a *global* d3 transition, not a selection-bound transition.
    // A selection-bound transition (e.g. cellsLayer.transition()) only exists on that
    // selection; reusing it for other layers (labelsLayer, etc.) can throw
    // "transition N not found".
    const t = d3.transition().duration(520);

    breadcrumb.text(pathLabelFor(focus));

    const cell = cellsLayer.selectAll("g.cell").data(visible, keyFor);

    const cellEnter = cell.enter().append("g").attr("class", "cell");

    cellEnter
      .append("rect")
      .attr("rx", 10)
      .attr("ry", 10)
      .attr("stroke", "rgba(0,0,0,0.22)")
      .attr("stroke-width", 1.2);

    // Clip text to the tile bounds to prevent label overlap.
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
      .attr("opacity", 0.75);

    cellEnter.append("title");

    const merged = cellEnter.merge(cell);

    function zoomTargetFor(node) {
      let t = node;
      while (t && !(t.children && t.children.length)) {
        t = t.parent;
      }
      if (!t || t === focus) return null;
      return t;
    }

    merged
      .style("cursor", (d) => (zoomTargetFor(d) ? "pointer" : "default"))
      .on("click", (event, d) => {
        event.stopPropagation();
        const target = zoomTargetFor(d);
        if (target) {
          zoomTo(target);
        }
      });

    merged.select("title").text((d) => {
      const label = pathLabelFor(d);
      const leaves = Number(d.leafCount || d.value || 0);
      return `${label}\n${leaves} ${leaves === 1 ? "capability" : "capabilities"}`;
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
      .attr("stroke-width", (d) => (d.anySelected ? 2.2 : 1.2));

    merged
      .select("clipPath rect")
      .transition(t)
      .attr("x", (d) => x(d.x0))
      .attr("y", (d) => y(d.y0))
      .attr("width", (d) => Math.max(0, x(d.x1) - x(d.x0)))
      .attr("height", (d) => Math.max(0, y(d.y1) - y(d.y0)));

    // Overlay labels for container nodes close to the focus so their names stay readable
    // even when we draw deeper tiles on top (dense view).
    // We include focus children *and* the next level of container nodes.
    const containers = root.descendants().filter((d) => {
      if (!(d.depth > focus.depth && d.depth <= focus.depth + 2)) return false;
      if (!d.ancestors().includes(focus)) return false;
      if (d.children && d.children.length) return true;
      // Also label top-level skinny categories even if they have no children in the current tree.
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

    // Clip overlay label text to the label pill/strip bounds.
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
        if (d.children && d.children.length) {
          zoomTo(d);
        }
      });

    labelsMerged.transition(t).attr("opacity", (d) => {
      const w = x(d.x1) - x(d.x0);
      const h = y(d.y1) - y(d.y0);
      const vertical = isVerticalOverlayLabel(d, w, h);
      if (vertical) {
        // Allow very narrow vertical strips as long as there's usable height.
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
        // Vertical title when narrow but tall: bottom-to-top.
        const stripW = Math.max(0, Math.min(verticalStripWidth - 4, w - 12));
        // Center the rotated text within the strip. Using a centered anchor avoids
        // the label being clipped away (which previously produced a blank strip).
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
      // For vertical labels we already trim aggressively; clipping in user space can
      // hide the rotated text entirely.
      if (isVerticalOverlayLabel(d, w, h)) return null;
      return `url(#${safeIdFor(d)}_olab)`;
    });

    // Update label + count after geometry is known (truncate based on available width).
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
      const label = trimLabel(String(d.data?.name || ""), maxChars);

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
        // Center the count under the heading.
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

        // Containers are labeled via the overlay pills/strips.
        if (d.children && d.children.length) return 0;

        // At the very top-level, we already show overlay labels for depth-1 nodes,
        // so avoid duplicating the label inside those tiles.
        if (focus.depth === 0 && rel === 1) return 0;

        const w = x(d.x1) - x(d.x0);
        const h = y(d.y1) - y(d.y0);
        if (w < 84 || h < 44) return 0;

        return rel === 1 ? 0.98 : 0.95;
      });

    // Update text after geometry is known.
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
      // Uniform label color (white) regardless of tile background.
      // We rely on deeper, more opaque tile colors for contrast instead of a glow/outline.
      nodeSel
        .style("font-size", `${fs}px`)
        .style("fill", "#ffffff")
        .style("stroke", "none")
        .style("stroke-width", "0px");

      const cx = (x(d.x0) + x(d.x1)) / 2;
      const cy = (y(d.y0) + y(d.y1)) / 2;

      // Rebuild tspans each time so we can wrap labels cleanly.
      nodeSel.selectAll("tspan").remove();

      const name = String(d.data?.name || "");
      const isLeaf = !(d.children && d.children.length);

      // Wrap label text to avoid truncation in tiles like
      // "Wallet Transfer and Recovery" and "Privacy Preserving".
      const availW = Math.max(0, w - 18);
      const maxCharsPerLine = clampNum(
        Math.floor(availW / Math.max(1, fs * 0.58)),
        6,
        28,
      );
      const maxLabelLines = h >= 140 && w >= 140 ? 3 : h >= 84 ? 2 : 1;
      const labelLines = wrapLabelWords(name, maxCharsPerLine, maxLabelLines);

      // Count line: show in most leaf tiles where it fits.
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

      // Keep the overall text centered.
      nodeSel.attr("x", cx).attr("y", cy);
    });

    cell.exit().transition(t).attr("opacity", 0).remove();

    el.visualSummary.textContent = visible.length
      ? `${visible.length} tiles • focus: ${trimLabel(pathLabelFor(focus), 52)}`
      : `No subcategories under ${trimLabel(pathLabelFor(focus), 52)}`;
  }

  svg.on("click", () => zoomTo(root));
  zoomTo(root);

  // Treemap has its own click-to-zoom; external zoom buttons are disabled.
  state.svg = null;
  state.viewport = null;
  state.zoomBehavior = null;
  applyZoomButtonsEnabled(false);
}

function renderVisualization() {
  if (!window.d3) {
    clearGraph("D3 library is unavailable.");
    return;
  }
  if (!state.graphData) {
    clearGraph("No graph data available for this version.");
    return;
  }

  const visualType = el.visualTypeSelect.value || "treemap";

  try {
    if (visualType === "radial-tree") {
      renderRadialTree();
      return;
    }

    if (visualType === "bipartite") {
      renderBipartite();
      return;
    }

    if (visualType === "sunburst") {
      renderSunburst();
      return;
    }

    if (visualType === "treemap") {
      renderTreemap();
      return;
    }

    renderTidyTree();
  } catch (error) {
    console.error(error);
    clearGraph(error.message || "Failed to render visualisation.");
    OSPMAE.toast(error.message || "Failed to render visualisation", "error");
  }
}

async function loadGraph(versionId) {
  const params = new URLSearchParams();
  if (versionId) params.set("version_id", String(versionId));
  if (state.activeFramework?.id)
    params.set("framework_id", String(state.activeFramework.id));
  const query = params.toString() ? `?${params.toString()}` : "";
  const graphData = await apiFetch(
    `/v1/projects/${state.projectId}/graph${query}`,
  );
  state.graphData = normalizeGraphData(graphData, versionId);
}

function populateVersions() {
  const versions = state.versions || [];

  const fill = (selectEl, selectedId) => {
    if (!selectEl) return selectedId;
    selectEl.innerHTML = "";
    versions.forEach((v) => {
      const option = document.createElement("option");
      option.value = String(v.id);
      const suffix = v.is_draft ? " (draft)" : v.is_latest ? " (latest)" : "";
      option.textContent = `${v.version}${suffix}`;
      selectEl.appendChild(option);
    });

    let chosen = selectedId;
    if (chosen && versions.some((v) => v.id === chosen)) {
      selectEl.value = String(chosen);
      return chosen;
    }

    if (versions.length) {
      const latest = versions.find((v) => v.is_latest) || versions[0];
      chosen = latest.id;
      selectEl.value = String(latest.id);
      return chosen;
    }
    return null;
  };

  state.currentVersionId = fill(el.versionSelect, state.currentVersionId);
  state.depGraphVersionId = fill(
    el.depVersionSelect,
    state.depGraphVersionId || state.currentVersionId,
  );
}

async function loadProject() {
  const params = new URLSearchParams(window.location.search);
  const id = Number(params.get("id"));
  if (Number.isNaN(id) || id <= 0) {
    throw new Error("Missing or invalid project id");
  }

  state.projectId = id;
  const fwId = state.activeFramework?.id;
  state.project = await apiFetch(
    `/v1/projects/${id}${fwId ? `?framework_id=${encodeURIComponent(String(fwId))}` : ""}`,
  );
  state.versions = Array.isArray(state.project.versions)
    ? state.project.versions
    : [];
  state.currentVersionId =
    state.project.latest_version?.id || state.versions[0]?.id || null;
  state.changelogLoaded = false;

  el.projectTitle.textContent =
    state.project.display_name ||
    state.project.machine_name ||
    `Project #${id}`;
  el.projectSubTitle.textContent = [
    state.project.machine_name,
    state.project.organisation,
    state.project.project_type,
  ]
    .filter(Boolean)
    .join(" • ");

  if (canMaintainProjects()) {
    el.editProjectLink.style.display = "";
    el.editProjectLink.href = `/project-edit.html?id=${id}`;
    el.editProjectLink.textContent = "Edit project";
  }

  renderSubscribeBtn();
  applyDependencyRunPolicy();

  populateVersions();
  renderMetadata();
  updateProjectManifestNameSuggestion(true);

  if (state.currentVersionId) {
    await loadGraph(state.currentVersionId);
  } else {
    state.graphData = null;
  }
}

function canAskQuestions() {
  const r = role();
  return (
    r === "admin" ||
    r === "engineer" ||
    r === "product_owner" ||
    r === "architect"
  );
}

function fmtDateTime(iso) {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch (_) {
    return iso;
  }
}

async function loadQuestionsIfNeeded() {
  if (!state.questionsLoaded) {
    await loadQuestions(false);
  }
}

async function loadQuestions(force) {
  if (!state.projectId) return;
  if (state.loadingQuestions && !force) return;
  state.loadingQuestions = true;

  try {
    const res = await apiFetch(`/v1/projects/${state.projectId}/questions`);
    state.questionThreads = Array.isArray(res.items) ? res.items : [];
    state.canAnswerQuestions = !!res.can_answer;
    state.questionsLoaded = true;

    // Show/hide ask box based on role/permission and login state.
    const askAllowed = canAskQuestions();
    el.askQuestionBox.style.display = askAllowed ? "" : "none";

    const visibleCount = state.questionThreads.length;
    const metaBits = [];
    if (askAllowed) metaBits.push("You can ask questions.");
    if (state.canAnswerQuestions || role() === "admin")
      metaBits.push("You can answer questions.");
    el.questionsMeta.textContent = metaBits.join(" ");
    el.questionsInfo.textContent =
      visibleCount === 0 ? "No questions yet." : "";

    renderQuestions();
  } catch (err) {
    console.error(err);
    el.questionsInfo.textContent = err?.message || "Failed to load questions.";
  } finally {
    state.loadingQuestions = false;
  }
}

function renderQuestions() {
  const threads = Array.isArray(state.questionThreads)
    ? state.questionThreads
    : [];
  const meId = state.me?.id;
  const canAnswer = state.canAnswerQuestions || role() === "admin";

  el.questionsList.innerHTML = "";

  threads.forEach((t) => {
    const card = document.createElement("div");
    card.className = "card mt-3";

    const cardBody = document.createElement("div");
    cardBody.className = "card-body";
    card.appendChild(cardBody);

    const status = (t.status || "open").toLowerCase();
    const statusLabel = status === "answered" ? "Answered" : "Open";

    const header = document.createElement("div");
    header.className =
      "d-flex flex-wrap gap-2 align-items-center justify-content-between";

    const left = document.createElement("div");
    left.innerHTML = `<span class="fw-semibold">Thread #${t.id}</span> <span class="text-secondary">• ${statusLabel}</span>`;

    const right = document.createElement("div");
    right.className = "text-secondary small";
    right.textContent = t.updated_at
      ? `Updated ${fmtDateTime(t.updated_at)}`
      : "";

    header.appendChild(left);
    header.appendChild(right);
    cardBody.appendChild(header);

    const posts = Array.isArray(t.posts) ? t.posts : [];
    posts.forEach((p) => {
      const row = document.createElement("div");
      row.className = "mt-3";

      const meta = document.createElement("div");
      meta.className = "text-secondary small";
      meta.textContent = `${p.created_by?.username || "unknown"} • ${fmtDateTime(p.created_at)}`;

      const body = document.createElement("div");
      body.className = "mt-1";
      body.style.whiteSpace = "pre-wrap";
      body.textContent = p.body || "";

      row.appendChild(meta);
      row.appendChild(body);
      cardBody.appendChild(row);
    });

    const isAuthor = Number(t.created_by?.id) === Number(meId);
    const canReply = canAnswer || isAuthor;

    if (canReply) {
      const replyBox = document.createElement("form");
      replyBox.dataset.threadId = t.id;
      replyBox.className = "mt-3 pt-3 border-top";

      replyBox.innerHTML = `
				<div class="mb-2">
					<label class="form-label text-secondary small mb-1">Reply</label>
					<textarea class="form-control" rows="2" placeholder="Write a reply..."></textarea>
				</div>
				<div class="d-flex justify-content-end">
					<button type="submit" class="btn btn-sm btn-primary"><i class="bi bi-send"></i> Send</button>
				</div>
			`;

      replyBox.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const ta = replyBox.querySelector("textarea");
        const body = (ta?.value || "").trim();
        if (!body) return;
        await submitReply(t.id, body);
        ta.value = "";
      });

      cardBody.appendChild(replyBox);
    }

    el.questionsList.appendChild(card);
  });
}

async function submitQuestion(body) {
  if (!state.projectId) return;
  try {
    await apiFetch(`/v1/projects/${state.projectId}/questions`, {
      method: "POST",
      body: { body },
    });
    toast("Question submitted", "success");
    window.OSPMAE?.refreshQuestionBell?.();
    await loadQuestions(true);
  } catch (err) {
    console.error(err);
    toast(err?.message || "Failed to submit question", "error");
  }
}

async function submitReply(threadId, body) {
  try {
    await apiFetch(`/v1/questions/${threadId}/reply`, {
      method: "POST",
      body: { body },
    });
    toast("Reply sent", "success");
    window.OSPMAE?.refreshQuestionBell?.();
    await loadQuestions(true);
  } catch (err) {
    console.error(err);
    toast(err?.message || "Failed to send reply", "error");
  }
}

// -----------------------------------------------------------------------------
// Dependency map (per project version)
// -----------------------------------------------------------------------------

function depGraphDimensions() {
  const rect = el.depGraph?.getBoundingClientRect?.();
  const width = Math.max(360, Math.floor(rect?.width || 900));
  // Keep dependency graphs comfortably tall; container can grow so the page can scroll.
  const height = Math.max(760, Math.floor(rect?.height || 760));
  return { width, height };
}

function clearDepGraph(message) {
  if (el.depGraph) {
    el.depGraph.innerHTML = `
      <div class="p-3 text-secondary">${escapeHtml(message || "No dependency data yet.")}</div>
    `;
  }
  if (el.depSummary) el.depSummary.textContent = "";
}

function setDepStatusBadge(status, meta) {
  const s = String(status || "not_run").toLowerCase();
  const badge = el.depScanStatus;
  if (!badge) return;

  badge.classList.remove(
    "text-bg-secondary",
    "text-bg-success",
    "text-bg-warning",
    "text-bg-danger",
    "text-bg-info",
  );
  let cls = "text-bg-secondary";
  let label = "Not run";

  if (s === "queued") {
    cls = "text-bg-info";
    label = "Queued";
  } else if (s === "running") {
    cls = "text-bg-warning";
    label = "Running";
  } else if (s === "complete") {
    cls = "text-bg-success";
    label = "Complete";
  } else if (s === "error") {
    cls = "text-bg-danger";
    label = "Error";
  }

  badge.classList.add(cls);
  badge.textContent = label;

  if (el.depScanMeta) {
    el.depScanMeta.textContent = meta || "";
  }
}

function severityRank(sev) {
  const s = String(sev || "").toUpperCase();
  if (s === "CRITICAL") return 4;
  if (s === "HIGH") return 3;
  if (s === "MEDIUM") return 2;
  if (s === "LOW") return 1;
  return 0;
}

function severityBadgeClass(sev) {
  const s = String(sev || "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "text-bg-danger";
  if (s === "MEDIUM") return "text-bg-warning";
  if (s === "LOW") return "text-bg-secondary";
  return "text-bg-secondary";
}

function renderDepVulnerabilityPanel(res) {
  if (
    !el.depVulnCard ||
    !el.depVulnList ||
    !el.depVulnCountBadge ||
    !el.depVulnSummary
  )
    return;

  const vulns = Array.isArray(res?.vulnerabilities) ? res.vulnerabilities : [];
  if (!vulns.length) {
    el.depVulnCard.style.display = "none";
    el.depVulnCountBadge.textContent = "0";
    el.depVulnSummary.textContent = "";
    el.depVulnList.innerHTML = "";
    return;
  }

  // Group by dependency label
  const byDep = new Map();
  for (const v of vulns) {
    const key = String(v?.dependency_label || v?.package || "Dependency");
    if (!byDep.has(key)) byDep.set(key, []);
    byDep.get(key).push(v);
  }

  const deps = Array.from(byDep.entries()).sort((a, b) => {
    const aMax = Math.max(0, ...a[1].map((x) => severityRank(x?.severity)));
    const bMax = Math.max(0, ...b[1].map((x) => severityRank(x?.severity)));
    if (aMax !== bMax) return bMax - aMax;
    return String(a[0]).localeCompare(String(b[0]));
  });

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, OTHER: 0 };
  for (const v of vulns) {
    const s = String(v?.severity || "").toUpperCase();
    if (s === "CRITICAL") counts.CRITICAL += 1;
    else if (s === "HIGH") counts.HIGH += 1;
    else if (s === "MEDIUM") counts.MEDIUM += 1;
    else if (s === "LOW") counts.LOW += 1;
    else counts.OTHER += 1;
  }

  const parts = [];
  if (counts.CRITICAL) parts.push(`${counts.CRITICAL} critical`);
  if (counts.HIGH) parts.push(`${counts.HIGH} high`);
  if (counts.MEDIUM) parts.push(`${counts.MEDIUM} medium`);
  if (counts.LOW) parts.push(`${counts.LOW} low`);
  if (counts.OTHER) parts.push(`${counts.OTHER} other`);

  el.depVulnCard.style.display = "";
  el.depVulnCountBadge.textContent = String(vulns.length);
  el.depVulnSummary.textContent = `${parts.join(" • ")} • ${deps.length} affected dependencies`;

  let html = "";
  deps.forEach(([depLabel, items], idx) => {
    const domId = `depVulnItem_${idx}`;
    const maxRank = Math.max(0, ...items.map((x) => severityRank(x?.severity)));
    const maxSev =
      maxRank === 4
        ? "CRITICAL"
        : maxRank === 3
          ? "HIGH"
          : maxRank === 2
            ? "MEDIUM"
            : maxRank === 1
              ? "LOW"
              : "";

    const rows = items
      .slice()
      .sort((a, b) => {
        const ra = severityRank(a?.severity);
        const rb = severityRank(b?.severity);
        if (ra !== rb) return rb - ra;
        return String(a?.vulnerability_id || "").localeCompare(
          String(b?.vulnerability_id || ""),
        );
      })
      .map((v) => {
        const sev = String(v?.severity || "").toUpperCase();
        const sevCls = severityBadgeClass(sev);
        const title = v?.title ? escapeHtml(v.title) : "";
        const fixed = v?.fixed_version
          ? ` • fixed: ${escapeHtml(v.fixed_version)}`
          : "";
        const refs = Array.isArray(v?.references)
          ? v.references.filter(Boolean).slice(0, 3)
          : [];
        const refHtml = refs.length
          ? `<div class="mt-1 small">${refs
              .map((r) => {
                const u = String(r);
                const safe = escapeHtml(u);
                // only linkify absolute URLs
                if (u.startsWith("http://") || u.startsWith("https://")) {
                  return `<a href="${safe}" target="_blank" rel="noopener noreferrer">${trimLabel(safe, 42)}</a>`;
                }
                return `<span class="text-secondary">${trimLabel(safe, 60)}</span>`;
              })
              .join(" • ")}</div>`
          : "";

        return `
          <div class="py-2 border-top">
            <div class="d-flex align-items-start justify-content-between gap-2 flex-wrap">
              <div>
                <div class="fw-semibold">${escapeHtml(v?.vulnerability_id || "Vulnerability")}</div>
                ${title ? `<div class="text-secondary small">${title}${fixed}</div>` : fixed ? `<div class="text-secondary small">${fixed.slice(3)}</div>` : ""}
                ${refHtml}
              </div>
              <span class="badge ${sevCls}">${escapeHtml(sev || "UNKNOWN")}</span>
            </div>
          </div>
        `;
      })
      .join("");

    html += `
      <div class="accordion-item">
        <h2 class="accordion-header" id="${domId}_h">
          <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#${domId}_c" aria-expanded="false" aria-controls="${domId}_c">
            <span class="me-2 badge ${severityBadgeClass(maxSev)}">${escapeHtml(maxSev || "VULN")}</span>
            <span class="fw-semibold">${escapeHtml(depLabel)}</span>
            <span class="ms-2 text-secondary">(${items.length})</span>
          </button>
        </h2>
        <div id="${domId}_c" class="accordion-collapse collapse" aria-labelledby="${domId}_h" data-bs-parent="#depVulnList">
          <div class="accordion-body py-2">${rows}</div>
        </div>
      </div>
    `;
  });

  el.depVulnList.innerHTML = html;
}

async function loadDependencyGraph(versionId) {
  if (!state.projectId || !versionId) return null;
  const params = new URLSearchParams();
  params.set("version_id", String(versionId));
  const res = await apiFetch(
    `/v1/projects/${state.projectId}/dependency-graph?${params.toString()}`,
  );
  state.depGraphData = res;
  state.depGraphVersionId = Number(versionId);

  const v = res?.version || {};
  const status = v.dependency_discovery_status || "not_run";
  const bits = [];
  if (v.dependency_last_commit)
    bits.push(`commit ${String(v.dependency_last_commit).slice(0, 10)}`);
  if (v.dependency_discovery_started_at)
    bits.push(`started ${fmtDateTime(v.dependency_discovery_started_at)}`);
  if (v.dependency_discovery_finished_at)
    bits.push(`finished ${fmtDateTime(v.dependency_discovery_finished_at)}`);
  if (v.dependency_discovery_error)
    bits.push(`error: ${String(v.dependency_discovery_error).slice(0, 120)}`);
  setDepStatusBadge(status, bits.join(" • "));

  const summary = res?.summary || {};
  const depCount = Number(summary.dependency_count || v.dependency_count || 0);
  const vulnCount = Number(
    summary.vulnerability_count || v.vulnerability_count || 0,
  );
  if (el.depSummary) {
    const ecoParts = [];
    const ecos =
      summary.ecosystems && typeof summary.ecosystems === "object"
        ? summary.ecosystems
        : null;
    if (ecos) {
      Object.keys(ecos)
        .sort()
        .forEach((k) => {
          ecoParts.push(`${k}: ${ecos[k]}`);
        });
    }
    el.depSummary.textContent = `${depCount} dependencies • ${vulnCount} vulnerabilities${ecoParts.length ? ` • ${ecoParts.join(" • ")}` : ""}`;
  }

  renderDepVulnerabilityPanel(res);

  return res;
}

function pruneDepTreeToVulnerable(node) {
  if (!node || typeof node !== "object") return null;

  const children = Array.isArray(node.children) ? node.children : [];
  const prunedChildren = children.map(pruneDepTreeToVulnerable).filter(Boolean);

  const own = Number(node.vulnerability_count || 0) || 0;
  if (own > 0 || prunedChildren.length > 0) {
    const copy = { ...node };
    if (prunedChildren.length > 0) copy.children = prunedChildren;
    else delete copy.children;
    return copy;
  }
  return null;
}

function depHierarchy() {
  const tree = state.depGraphData?.dependency_tree;
  let base = null;
  if (tree && typeof tree === "object") base = tree;
  if (!base) {
    const projName =
      state.project?.display_name || state.project?.machine_name || "Project";
    const ver =
      state.versions?.find((x) => x.id === state.depGraphVersionId)?.version ||
      "latest";
    base = { name: projName, children: [{ name: ver, children: [] }] };
  }

  if (!state.depOnlyVulnOnly) return base;
  return pruneDepTreeToVulnerable(base);
}

function depVersionIdFromNode(d) {
  const id = Number(
    d?.data?.dependency_version_id || d?.data?.dependencyVersionId || 0,
  );
  return Number.isFinite(id) && id > 0 ? id : null;
}

function navigateToDependencyFromNode(d) {
  const id = depVersionIdFromNode(d);
  if (!id) return;
  window.location.href = `/dependencies.html?id=${id}`;
}

function initDepSvg(desiredHeight) {
  const d3 = window.d3;
  if (!d3 || !el.depGraph) return null;

  const { width, height: baseHeight } = depGraphDimensions();
  const height = Math.max(baseHeight, Number(desiredHeight || 0) || 0);
  state.depSvgSize = { width, height };

  const svg = d3
    .select(el.depGraph)
    .html("")
    .append("svg")
    .attr("viewBox", [0, 0, width, height])
    .attr("width", "100%")
    .attr("height", height)
    .style("cursor", "grab");

  const viewport = svg.append("g");

  const zoom = d3
    .zoom()
    .scaleExtent([0.2, 8])
    .on("zoom", (event) => {
      viewport.attr("transform", event.transform);
    });

  svg.call(zoom);

  state.depSvg = svg;
  state.depViewport = viewport;
  state.depZoomBehavior = zoom;
  state.depHomeTransform = d3.zoomIdentity;

  el.depZoomInBtn?.removeAttribute("disabled");
  el.depZoomOutBtn?.removeAttribute("disabled");
  el.depZoomResetBtn?.removeAttribute("disabled");

  return { svg, viewport, width, height };
}

function fitDepViewport(padding = 18) {
  const d3 = window.d3;
  if (!state.depSvg || !state.depViewport || !state.depZoomBehavior) return;
  const size = state.depSvgSize || depGraphDimensions();
  const { width, height } = size;
  const node = state.depViewport.node();
  if (!node || !node.getBBox) return;
  const box = node.getBBox();
  if (!(box.width > 0 && box.height > 0)) return;

  const scale = Math.min(
    6,
    Math.max(
      0.2,
      Math.min(
        (width - padding * 2) / box.width,
        (height - padding * 2) / box.height,
      ),
    ),
  );
  const tx = (width - box.width * scale) / 2 - box.x * scale;
  const ty = (height - box.height * scale) / 2 - box.y * scale;
  const t = d3.zoomIdentity.translate(tx, ty).scale(scale);
  state.depHomeTransform = t;
  state.depSvg.call(state.depZoomBehavior.transform, t);
}

function depZoomBy(factor) {
  if (!state.depSvg || !state.depZoomBehavior) return;
  state.depSvg
    .transition()
    .duration(180)
    .call(state.depZoomBehavior.scaleBy, factor);
}

function depResetZoom() {
  if (!state.depSvg || !state.depZoomBehavior) return;
  const d3 = window.d3;
  const t = state.depHomeTransform || d3.zoomIdentity;
  state.depSvg
    .transition()
    .duration(220)
    .call(state.depZoomBehavior.transform, t);
}

// -----------------------------------------------------------------------------
// Export helpers (SVG -> JPEG / PDF)
// -----------------------------------------------------------------------------

function findSvgIn(containerEl) {
  if (!containerEl) return null;
  return containerEl.querySelector("svg");
}

function safeFilename(value) {
  const v = String(value || "export");
  const out = v
    .replace(/[^a-z0-9\-_.]+/gi, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
  return out || "export";
}

function isTransparentColor(value) {
  const v = String(value || "")
    .trim()
    .toLowerCase();
  return (
    v === "transparent" || v === "rgba(0, 0, 0, 0)" || v === "rgba(0,0,0,0)"
  );
}

function effectiveBackgroundColor(containerEl) {
  let cur = containerEl;
  while (cur && cur !== document.documentElement) {
    try {
      const bg = window.getComputedStyle(cur).backgroundColor;
      if (bg && !isTransparentColor(bg)) return bg;
    } catch (_) {
      // ignore
    }
    cur = cur.parentElement;
  }
  return "#ffffff";
}

// Improve export readability: add an outline to SVG text so labels remain legible
// even when exported onto light/pastel fills.
function parseCssColorToRgb(value) {
  const v = String(value || "").trim();
  if (!v) return null;

  // rgb() / rgba()
  let m = v.match(/^rgba?\(([^)]+)\)$/i);
  if (m) {
    const parts = m[1].split(",").map((x) => x.trim());
    if (parts.length >= 3) {
      const r = Number(parts[0]);
      const g = Number(parts[1]);
      const b = Number(parts[2]);
      if ([r, g, b].every((n) => Number.isFinite(n))) return { r, g, b };
    }
  }

  // hex
  m = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (m) {
    const hex = m[1];
    if (hex.length === 3) {
      const r = parseInt(hex[0] + hex[0], 16);
      const g = parseInt(hex[1] + hex[1], 16);
      const b = parseInt(hex[2] + hex[2], 16);
      return { r, g, b };
    }
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    return { r, g, b };
  }

  return null;
}

function relativeLuminanceOfRgb({ r, g, b }) {
  // https://www.w3.org/TR/WCAG20/#relativeluminancedef
  const srgb = [r, g, b].map((n) => {
    const c = (Number(n) || 0) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * srgb[0] + 0.7152 * srgb[1] + 0.0722 * srgb[2];
}

function styleGet(style, prop) {
  const reProp = new RegExp(`${prop}\\s*:\\s*([^;]+)`, "i");
  const m = String(style || "").match(reProp);
  return m ? String(m[1]).trim() : "";
}

function applyExportTextOutline(cloneSvg) {
  try {
    const texts = cloneSvg.querySelectorAll("text");
    texts.forEach((t) => {
      const style = t.getAttribute("style") || "";
      const fill = styleGet(style, "fill") || t.getAttribute("fill") || "";
      const rgb = parseCssColorToRgb(fill);
      if (!rgb) return;

      const lum = relativeLuminanceOfRgb(rgb);
      const fontSizeStr = styleGet(style, "font-size") || "12px";
      const fs = Number.parseFloat(fontSizeStr) || 12;
      const sw = Math.max(1, Math.min(3, fs * 0.14));

      // If label fill is light, outline with a dark stroke; otherwise outline with a light stroke.
      const strokeRgb = lum > 0.6 ? "rgb(0,0,0)" : "rgb(255,255,255)";
      const strokeOpacity = lum > 0.6 ? 0.55 : 0.4;

      const extra = [
        "paint-order:stroke fill",
        "stroke-linejoin:round",
        "stroke-linecap:round",
        `stroke:${strokeRgb}`,
        `stroke-opacity:${strokeOpacity}`,
        `stroke-width:${sw}px`,
      ].join(";");

      t.setAttribute("style", `${style};${extra}`);
    });
  } catch (_) {
    // ignore
  }
}

function cloneSvgForExport(
  svgEl,
  { padding = 24, backgroundColor = "#ffffff" } = {},
) {
  const clone = svgEl.cloneNode(true);

  // Prefer exporting the un-zoomed content (full graph). Remove zoom transform on the first <g>.
  const g = clone.querySelector("g");
  if (g) g.removeAttribute("transform");

  // Compute bbox on the ORIGINAL element (temporarily removing zoom transform).
  let bbox = null;
  try {
    const origG = svgEl.querySelector("g");
    if (origG) {
      const prev = origG.getAttribute("transform");
      origG.removeAttribute("transform");
      bbox = origG.getBBox();
      if (prev) origG.setAttribute("transform", prev);
      else origG.removeAttribute("transform");
    } else {
      bbox = svgEl.getBBox();
    }
  } catch (_) {
    // ignore
  }

  if (!bbox || !(bbox.width > 0 && bbox.height > 0)) {
    // Fallback to existing viewBox.
    const vb = (svgEl.getAttribute("viewBox") || "")
      .trim()
      .split(/\s+/)
      .map(Number);
    if (vb.length === 4 && vb.every((n) => Number.isFinite(n))) {
      bbox = { x: vb[0], y: vb[1], width: vb[2], height: vb[3] };
    } else {
      bbox = { x: 0, y: 0, width: 1200, height: 800 };
    }
  }

  const x = bbox.x - padding;
  const y = bbox.y - padding;
  const w = bbox.width + padding * 2;
  const h = bbox.height + padding * 2;

  clone.setAttribute("viewBox", `${x} ${y} ${w} ${h}`);
  clone.setAttribute("width", String(w));
  clone.setAttribute("height", String(h));

  // Inline computed styles for common SVG elements to avoid missing CSS in exports.
  // IMPORTANT: do this *before* inserting the export background rect, otherwise the
  // node lists get out-of-sync and we end up applying the wrong styles (often
  // resulting in black exports / missing strokes).
  try {
    const selector = "text,path,circle,rect,line,polyline,polygon";
    const origNodes = svgEl.querySelectorAll(selector);
    const cloneNodes = clone.querySelectorAll(selector);
    const n = Math.min(origNodes.length, cloneNodes.length);
    for (let i = 0; i < n; i += 1) {
      const o = origNodes[i];
      const c = cloneNodes[i];
      const cs = window.getComputedStyle(o);
      const s = [
        `font-family:${cs.fontFamily}`,
        `font-size:${cs.fontSize}`,
        `font-weight:${cs.fontWeight}`,
        `fill:${cs.fill}`,
        `stroke:${cs.stroke}`,
        `stroke-width:${cs.strokeWidth}`,
        `stroke-linecap:${cs.strokeLinecap}`,
        `stroke-linejoin:${cs.strokeLinejoin}`,
        `stroke-dasharray:${cs.strokeDasharray}`,
        `opacity:${cs.opacity}`,
      ].join(";");
      c.setAttribute("style", s);
    }
  } catch (_) {
    // ignore
  }

  // Add export background (helps JPEG/PDF and preserves the on-screen background).
  const ns = "http://www.w3.org/2000/svg";
  const bg = document.createElementNS(ns, "rect");
  bg.setAttribute("x", String(x));
  bg.setAttribute("y", String(y));
  bg.setAttribute("width", String(w));
  bg.setAttribute("height", String(h));
  bg.setAttribute("fill", backgroundColor || "#ffffff");
  clone.insertBefore(bg, clone.firstChild);

  // Also force the SVG element background style in case the renderer honours it.
  try {
    clone.style.backgroundColor = backgroundColor || "#ffffff";
  } catch (_) {
    // ignore
  }

  // Make labels readable in exports (PDF/JPEG)
  applyExportTextOutline(clone);

  return { clone, box: { x, y, width: w, height: h } };
}

async function svgToCanvas(
  svgEl,
  { maxDim = 4096, scale = 2, backgroundColor = "#ffffff" } = {},
) {
  const { clone, box } = cloneSvgForExport(svgEl, {
    padding: 24,
    backgroundColor,
  });
  const serializer = new XMLSerializer();
  const svgText = serializer.serializeToString(clone);
  const svgUrl = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svgText)}`;

  const img = new Image();
  img.decoding = "async";

  await new Promise((resolve, reject) => {
    img.onload = resolve;
    img.onerror = reject;
    img.src = svgUrl;
  });

  const targetScale = Math.max(
    0.2,
    Math.min(scale, maxDim / box.width, maxDim / box.height),
  );
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.floor(box.width * targetScale));
  canvas.height = Math.max(1, Math.floor(box.height * targetScale));
  const ctx = canvas.getContext("2d");
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = "high";
  ctx.fillStyle = backgroundColor || "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
  return canvas;
}

function downloadDataUrl(dataUrl, filename) {
  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function exportSvgAsJpeg(svgEl, filenameBase, backgroundColor) {
  const canvas = await svgToCanvas(svgEl, { backgroundColor });
  const url = canvas.toDataURL("image/jpeg", 0.92);
  downloadDataUrl(url, `${filenameBase}.jpg`);
}

async function exportSvgAsPdf(svgEl, filenameBase, backgroundColor) {
  const jsPDF = window.jspdf?.jsPDF;
  if (!jsPDF) {
    toast("PDF export library (jsPDF) is not available", "error");
    return;
  }
  const canvas = await svgToCanvas(svgEl, { backgroundColor });
  const imgData = canvas.toDataURL("image/jpeg", 0.92);

  const orientation = canvas.width >= canvas.height ? "landscape" : "portrait";
  const doc = new jsPDF({ orientation, unit: "mm", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 8;
  const availW = pageW - margin * 2;
  const availH = pageH - margin * 2;

  const imgW = availW;
  let imgH = (canvas.height / canvas.width) * imgW;
  let drawW = imgW;
  let drawH = imgH;
  if (imgH > availH) {
    drawH = availH;
    drawW = (canvas.width / canvas.height) * drawH;
  }
  const x = (pageW - drawW) / 2;
  const y = (pageH - drawH) / 2;
  doc.addImage(imgData, "JPEG", x, y, drawW, drawH, undefined, "FAST");
  doc.save(`${filenameBase}.pdf`);
}

async function exportContainer(containerEl, { filenameBase, format }) {
  const svgEl = findSvgIn(containerEl);
  if (!svgEl) {
    toast("Nothing to export yet (no graph rendered)", "error");
    return;
  }
  const bg = effectiveBackgroundColor(containerEl);
  if (format === "pdf") {
    await exportSvgAsPdf(svgEl, filenameBase, bg);
  } else {
    await exportSvgAsJpeg(svgEl, filenameBase, bg);
  }
}

function renderDepTidyTree() {
  const d3 = window.d3;
  if (!d3) return;

  const base = depGraphDimensions();
  const width = base.width;

  const root = d3.hierarchy(depHierarchy());
  root.sum((d) => (d.children && d.children.length ? 0 : 1));

  // Aggregate vulnerability counts up the tree so we can highlight full branches.
  root.eachAfter((d) => {
    const own = Number(d.data?.vulnerability_count || 0) || 0;
    const child = Array.isArray(d.children)
      ? d.children.reduce((acc, c) => acc + (c.vulnTotal || 0), 0)
      : 0;
    d.vulnTotal = own + child;
  });

  const dx = 18;

  // Clamp the "depth" used for spacing so adding a namespace layer doesn't compress the layout too much.
  const depthForSpacing = Math.min(root.height + 1, 6);
  const dy = Math.max(
    140,
    Math.floor((width - 220) / Math.max(1, depthForSpacing)),
  );

  const tree = d3.tree().nodeSize([dx, dy]);
  tree(root);

  let x0 = Infinity;
  let x1 = -Infinity;
  root.each((d) => {
    if (d.x < x0) x0 = d.x;
    if (d.x > x1) x1 = d.x;
  });

  const desiredHeight = Math.max(base.height, Math.ceil(x1 - x0 + 170));
  const init = initDepSvg(desiredHeight);
  if (!init) return;
  const { height } = init;
  const viewport = state.depViewport;

  const translateY = Math.max(30, (height - (x1 - x0)) / 2 - x0);
  const g = viewport
    .append("g")
    .attr("transform", `translate(44,${translateY})`);

  const link = d3
    .linkHorizontal()
    .x((d) => d.y)
    .y((d) => d.x);

  g.append("g")
    .attr("fill", "none")
    .selectAll("path")
    .data(root.links())
    .join("path")
    .attr("stroke", (d) =>
      (d.target?.vulnTotal || 0) > 0
        ? "var(--bs-danger)"
        : "var(--bs-secondary-color)",
    )
    .attr("stroke-opacity", (d) =>
      (d.target?.vulnTotal || 0) > 0 ? 0.75 : 0.3,
    )
    .attr("stroke-width", (d) => ((d.target?.vulnTotal || 0) > 0 ? 2.2 : 1.2))
    .attr("d", (d) => link({ source: d.source, target: d.target }));

  const node = g
    .append("g")
    .selectAll("g")
    .data(root.descendants())
    .join("g")
    .attr("transform", (d) => `translate(${d.y},${d.x})`)
    .style("cursor", (d) => (depVersionIdFromNode(d) ? "pointer" : null))
    .on("click", (event, d) => {
      const id = depVersionIdFromNode(d);
      if (!id) return;
      event?.stopPropagation?.();
      event?.preventDefault?.();
      navigateToDependencyFromNode(d);
    });

  // Outer halo for vulnerable leaves (very obvious, but still compact).
  node
    .filter((d) => !d.children && (d.vulnTotal || 0) > 0)
    .append("circle")
    .attr("r", 8)
    .attr("fill", "none")
    .attr("stroke", "var(--bs-danger)")
    .attr("stroke-width", 2.6)
    .attr("opacity", 0.95);

  node
    .append("circle")
    .attr("r", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      if (isVuln) return 5.2;
      if (d.children) return 3.4;
      return 2.8;
    })
    .attr("fill", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      if (isVuln) return "var(--bs-danger)";
      return d.children ? "var(--bs-primary)" : "var(--bs-body-color)";
    })
    .attr("stroke", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      if (isVuln) return "var(--bs-danger)";
      if (d.children && (d.vulnTotal || 0) > 0 && d.depth >= 2)
        return "var(--bs-danger)";
      return "none";
    })
    .attr("stroke-width", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      if (isVuln) return 2.2;
      if (d.children && (d.vulnTotal || 0) > 0 && d.depth >= 2) return 1.8;
      return 0;
    })
    .attr("opacity", (d) => (d.depth === 0 ? 0.6 : 0.88));

  const labelSel = node
    .append("text")
    .attr("dy", "0.32em")
    .attr("x", (d) => (d.children ? -8 : 8))
    .attr("text-anchor", (d) => (d.children ? "end" : "start"))
    .style("font-size", "12px")
    .style("font-weight", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      if (isVuln) return 750;
      return d.depth <= 3 ? 650 : 450;
    })
    .attr("fill", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      return isVuln ? "var(--bs-danger)" : "var(--bs-body-color)";
    })
    .text((d) => String(d.data?.name || ""));

  // Background stroke so link lines don't wash labels out.
  labelSel
    .clone(true)
    .lower()
    .attr("stroke", "var(--bs-body-bg)")
    .attr("stroke-width", 3)
    .attr("opacity", 0.95);

  node.append("title").text((d) => {
    const bits = [String(d.data?.name || "")];
    const vc = Number(d.data?.vulnerability_count || 0);
    if (!d.children) {
      const eco = d.data?.ecosystem;
      const ns = d.data?.namespace;
      const pkg = d.data?.package;
      const ver = d.data?.version;
      if (eco) bits.push(`ecosystem: ${eco}`);
      if (ns) bits.push(`namespace: ${ns}`);
      if (pkg) bits.push(`package: ${pkg}`);
      if (ver) bits.push(`version: ${ver}`);
      bits.push(d.data?.is_indirect ? "indirect" : "direct");
      if (vc) bits.push(`${vc} vulnerabilities`);
    } else if ((d.vulnTotal || 0) > 0) {
      bits.push(`${d.vulnTotal} vulnerabilities in subtree`);
    }
    return bits.join("\n");
  });

  fitDepViewport();
}

function renderDepRadialTree() {
  const d3 = window.d3;
  initDepSvg();

  const { width, height } = depGraphDimensions();
  const radius = Math.min(width, height) / 2 - 44;

  const root = d3.hierarchy(depHierarchy());
  root.sum((d) => (d.children && d.children.length ? 0 : 1));

  root.eachAfter((d) => {
    const own = Number(d.data?.vulnerability_count || 0) || 0;
    const child = Array.isArray(d.children)
      ? d.children.reduce((acc, c) => acc + (c.vulnTotal || 0), 0)
      : 0;
    d.vulnTotal = own + child;
  });

  d3.tree().size([2 * Math.PI, radius])(root);

  const viewport = state.depViewport;
  const g = viewport
    .append("g")
    .attr("transform", `translate(${width / 2},${height / 2})`);

  const link = d3
    .linkRadial()
    .angle((d) => d.x)
    .radius((d) => d.y);

  g.append("g")
    .attr("fill", "none")
    .selectAll("path")
    .data(root.links())
    .join("path")
    .attr("stroke", (d) =>
      (d.target?.vulnTotal || 0) > 0
        ? "var(--bs-danger)"
        : "var(--bs-secondary-color)",
    )
    .attr("stroke-opacity", (d) =>
      (d.target?.vulnTotal || 0) > 0 ? 0.72 : 0.3,
    )
    .attr("stroke-width", (d) => ((d.target?.vulnTotal || 0) > 0 ? 2.0 : 1.1))
    .attr("d", (d) => link({ source: d.source, target: d.target }));

  const node = g
    .append("g")
    .selectAll("g")
    .data(root.descendants())
    .join("g")
    .attr(
      "transform",
      (d) => `rotate(${(d.x * 180) / Math.PI - 90}) translate(${d.y},0)`,
    )
    .style("cursor", (d) => (depVersionIdFromNode(d) ? "pointer" : null))
    .on("click", (event, d) => {
      const id = depVersionIdFromNode(d);
      if (!id) return;
      event?.stopPropagation?.();
      event?.preventDefault?.();
      navigateToDependencyFromNode(d);
    });

  node
    .filter((d) => !d.children && (d.vulnTotal || 0) > 0)
    .append("circle")
    .attr("r", 7.2)
    .attr("fill", "none")
    .attr("stroke", "var(--bs-danger)")
    .attr("stroke-width", 2.4)
    .attr("opacity", 0.95);

  node
    .append("circle")
    .attr("r", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      if (isVuln) return 4.8;
      if (d.children) return 3.0;
      return 2.4;
    })
    .attr("fill", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      if (isVuln) return "var(--bs-danger)";
      return d.children ? "var(--bs-primary)" : "var(--bs-body-color)";
    })
    .attr("opacity", (d) => (d.depth === 0 ? 0.6 : 0.88));

  node
    .append("text")
    .attr("dy", "0.32em")
    .attr("x", (d) => (d.x < Math.PI ? 8 : -8))
    .attr("text-anchor", (d) => (d.x < Math.PI ? "start" : "end"))
    .attr("transform", (d) => (d.x >= Math.PI ? "rotate(180)" : null))
    .style("font-size", "11px")
    .style("font-weight", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      if (isVuln) return 750;
      return d.depth <= 3 ? 650 : 450;
    })
    .attr("fill", (d) => {
      const isLeaf = !(d.children && d.children.length);
      const isVuln = isLeaf && (d.vulnTotal || 0) > 0;
      return isVuln ? "var(--bs-danger)" : "var(--bs-body-color)";
    })
    .text((d) => trimLabel(String(d.data?.name || ""), d.depth <= 3 ? 28 : 20));

  node.append("title").text((d) => {
    const bits = [String(d.data?.name || "")];
    if ((d.vulnTotal || 0) > 0) {
      if (!d.children)
        bits.push(
          `${Number(d.data?.vulnerability_count || 0)} vulnerabilities`,
        );
      else bits.push(`${d.vulnTotal} vulnerabilities in subtree`);
    }
    return bits.join("\n");
  });

  fitDepViewport();
}

function renderDepTreemap() {
  const d3 = window.d3;
  initDepSvg();

  const { width, height } = depGraphDimensions();
  const root = d3
    .hierarchy(depHierarchy())
    .sum((d) => (d.children && d.children.length ? 0 : 1))
    .sort((a, b) => (b.value || 0) - (a.value || 0));

  root.eachAfter((d) => {
    const own = Number(d.data?.vulnerability_count || 0) || 0;
    const child = Array.isArray(d.children)
      ? d.children.reduce((acc, c) => acc + (c.vulnTotal || 0), 0)
      : 0;
    d.vulnTotal = own + child;
  });

  d3.treemap().size([width, height]).paddingInner(3).paddingOuter(6)(root);

  const nodes = root.descendants().filter((d) => d.depth > 0);
  const viewport = state.depViewport;
  const g = viewport.append("g");

  const cell = g
    .selectAll("g")
    .data(nodes)
    .join("g")
    .attr("transform", (d) => `translate(${d.x0},${d.y0})`)
    .style("cursor", (d) => (depVersionIdFromNode(d) ? "pointer" : null))
    .on("click", (event, d) => {
      const id = depVersionIdFromNode(d);
      if (!id) return;
      event?.stopPropagation?.();
      event?.preventDefault?.();
      navigateToDependencyFromNode(d);
    });

  cell
    .append("rect")
    .attr("width", (d) => Math.max(0, d.x1 - d.x0))
    .attr("height", (d) => Math.max(0, d.y1 - d.y0))
    .attr("rx", 8)
    .attr("ry", 8)
    .attr("fill", (d) => {
      const vc = Number(d.data?.vulnerability_count || 0);
      if (!d.children && vc > 0) return "var(--bs-danger)";
      if (d.depth === 1) return "var(--bs-primary)"; // version
      if (d.depth === 2) return "var(--bs-secondary)"; // ecosystem
      if (d.depth === 3) return "var(--bs-tertiary-bg)"; // namespace
      return "var(--bs-body-color)"; // package leaves
    })
    .attr("stroke", (d) =>
      (d.vulnTotal || 0) > 0 ? "var(--bs-danger)" : "none",
    )
    .attr("stroke-opacity", (d) => ((d.vulnTotal || 0) > 0 ? 0.7 : 0))
    .attr("stroke-width", (d) => ((d.vulnTotal || 0) > 0 ? 1.6 : 0))
    .attr("opacity", (d) => {
      const vc = Number(d.data?.vulnerability_count || 0);
      if (!d.children && vc > 0) return 0.62;
      return d.children ? 0.16 : 0.22;
    });

  cell
    .append("clipPath")
    .attr("id", (d, i) => `depclip_${i}`)
    .append("rect")
    .attr("width", (d) => Math.max(0, d.x1 - d.x0))
    .attr("height", (d) => Math.max(0, d.y1 - d.y0));

  const depTextFill = (d) => {
    const vc = Number(d.data?.vulnerability_count || 0);
    if (!d.children && vc > 0) return "var(--bs-body-bg)";
    if (d.depth <= 2) return "var(--bs-body-bg)";
    return "var(--bs-body-color)";
  };

  const depTextOutline = (fill) => {
    // If we're filling with body-bg (usually white), outline darker; otherwise outline light.
    return String(fill).includes("body-bg")
      ? "rgba(0,0,0,0.72)"
      : "rgba(255,255,255,0.78)";
  };

  const depText = cell
    .append("text")
    .attr("clip-path", (d, i) => `url(#depclip_${i})`)
    .attr("text-anchor", "middle")
    .attr("dominant-baseline", "central")
    .style("pointer-events", "none")
    .style("paint-order", "stroke fill")
    .style("stroke-linejoin", "round");

  depText.append("tspan").attr("class", "t1");
  depText.append("tspan").attr("class", "t2");

  depText.each(function (d) {
    const node = d3.select(this);
    const w = Math.max(0, d.x1 - d.x0);
    const h = Math.max(0, d.y1 - d.y0);
    const cx = w / 2;
    const cy = h / 2;

    const fs = clampNum(Math.floor(Math.min(w, h) / 7.2), 12, 22);
    const fill = depTextFill(d);
    node
      .attr("x", cx)
      .attr("y", cy)
      .style("font-size", `${fs}px`)
      .style(
        "font-weight",
        !d.children && Number(d.data?.vulnerability_count || 0) > 0
          ? 800
          : d.children
            ? 700
            : 520,
      )
      .attr("fill", fill)
      .style("stroke", depTextOutline(fill))
      .style("stroke-width", `${clampNum(Math.round(fs / 6), 2, 4)}px`);

    const maxChars = Math.max(6, Math.floor((w - 18) / (fs * 0.58)));
    const label = trimLabel(String(d.data?.name || ""), maxChars);

    const vc = Number(d.data?.vulnerability_count || 0);
    const showCount = !d.children && vc > 0 && w >= 110 && h >= 62;

    const t1 = node.select("tspan.t1");
    const t2 = node.select("tspan.t2");

    if (showCount) {
      t1.attr("x", cx).attr("dy", "-0.22em").text(label);
      t2.attr("x", cx)
        .attr("dy", "1.25em")
        .style("font-size", `${Math.max(11, Math.floor(fs * 0.78))}px`)
        .style("font-weight", 900)
        .attr("opacity", 0.94)
        .text(`${vc} ${vc === 1 ? "vuln" : "vulns"}`);
    } else {
      t1.attr("x", cx).attr("dy", "0").text(label);
      t2.text("");
    }
  });

  cell.append("title").text((d) => {
    const bits = [String(d.data?.name || "")];
    const vc = Number(d.data?.vulnerability_count || 0);
    if (!d.children) {
      if (vc) bits.push(`${vc} vulnerabilities`);
      if (d.data?.is_indirect) bits.push("indirect");
    } else if ((d.vulnTotal || 0) > 0) {
      bits.push(`${d.vulnTotal} vulnerabilities in subtree`);
    }
    return bits.join("\n");
  });

  fitDepViewport();
}

function renderDepSunburst() {
  const d3 = window.d3;
  initDepSvg();

  const { width, height } = depGraphDimensions();
  const radius = Math.min(width, height) / 2 - 10;

  const root = d3
    .hierarchy(depHierarchy())
    .sum((d) => (d.children && d.children.length ? 0 : 1));
  root.eachAfter((d) => {
    const own = Number(d.data?.vulnerability_count || 0) || 0;
    const child = Array.isArray(d.children)
      ? d.children.reduce((acc, c) => acc + (c.vulnTotal || 0), 0)
      : 0;
    d.vulnTotal = own + child;
  });

  const partition = d3.partition().size([2 * Math.PI, root.height + 1]);
  partition(root);
  root.each((d) => {
    d.current = d;
  });

  const arc = d3
    .arc()
    .startAngle((d) => d.x0)
    .endAngle((d) => d.x1)
    .padAngle((d) => Math.min((d.x1 - d.x0) / 2, 0.01))
    .padRadius(radius * 1.4)
    .innerRadius((d) => (d.y0 * radius) / (root.height + 1))
    .outerRadius((d) =>
      Math.max(
        (d.y0 * radius) / (root.height + 1),
        (d.y1 * radius) / (root.height + 1) - 1,
      ),
    );

  const viewport = state.depViewport;
  const g = viewport
    .append("g")
    .attr("transform", `translate(${width / 2},${height / 2})`);

  const colorFor = (d) => {
    const vc = Number(d.data?.vulnerability_count || 0);
    if (!d.children && vc > 0) return "var(--bs-danger)";
    if (d.depth === 1) return "var(--bs-primary)"; // version
    if (d.depth === 2) return "var(--bs-secondary)"; // ecosystem
    if (d.depth === 3) return "var(--bs-tertiary-bg)"; // namespace
    return "var(--bs-body-color)"; // package leaves
  };

  const path = g
    .append("g")
    .selectAll("path")
    .data(root.descendants().slice(1))
    .join("path")
    .attr("fill", (d) => colorFor(d))
    .attr("fill-opacity", (d) => {
      const vc = Number(d.data?.vulnerability_count || 0);
      if (!d.children && vc > 0) return 0.78;
      return d.children ? 0.22 : 0.35;
    })
    .attr("stroke", (d) =>
      !d.children && Number(d.data?.vulnerability_count || 0) > 0
        ? "var(--bs-danger)"
        : "none",
    )
    .attr("stroke-width", (d) =>
      !d.children && Number(d.data?.vulnerability_count || 0) > 0 ? 2.0 : 0,
    )
    .attr("d", (d) => arc(d.current))
    .style("cursor", (d) => (depVersionIdFromNode(d) ? "pointer" : null))
    .on("click", (event, d) => {
      const id = depVersionIdFromNode(d);
      if (!id) return;
      event?.stopPropagation?.();
      event?.preventDefault?.();
      navigateToDependencyFromNode(d);
    });

  path.append("title").text((d) => {
    const bits = [String(d.data?.name || "")];
    const vc = Number(d.data?.vulnerability_count || 0);
    if (!d.children) {
      if (d.data?.is_indirect) bits.push("indirect");
      if (vc) bits.push(`${vc} vulnerabilities`);
    } else if ((d.vulnTotal || 0) > 0) {
      bits.push(`${d.vulnTotal} vulnerabilities in subtree`);
    }
    return bits.join("\n");
  });

  g.append("g")
    .attr("pointer-events", "none")
    .attr("text-anchor", "middle")
    .style("font-size", "10px")
    .selectAll("text")
    .data(root.descendants().slice(1))
    .join("text")
    .attr("transform", (d) => {
      const x = (((d.x0 + d.x1) / 2) * 180) / Math.PI;
      const y = (((d.y0 + d.y1) / 2) * radius) / (root.height + 1);
      return `rotate(${x - 90}) translate(${y},0) rotate(${x < 180 ? 0 : 180})`;
    })
    .attr("dy", "0.35em")
    .attr("fill", (d) =>
      !d.children && Number(d.data?.vulnerability_count || 0) > 0
        ? "var(--bs-body-bg)"
        : "var(--bs-body-color)",
    )
    .attr("fill-opacity", (d) => (d.x1 - d.x0 > 0.14 ? 0.9 : 0))
    .text((d) => trimLabel(String(d.data?.name || ""), 18));

  // Keep centered; zoom still works.
  state.depHomeTransform = d3.zoomIdentity;
  depResetZoom();
}

function renderDependencyVisualization() {
  if (!state.depGraphData || !el.depVisualTypeSelect) {
    clearDepGraph("No dependency data found for this project version yet.");
    return;
  }
  const tree = depHierarchy();
  const depCount = Number(state.depGraphData?.summary?.dependency_count || 0);
  if (!tree) {
    clearDepGraph("No vulnerable dependencies found for this project version.");
    return;
  }
  if (!tree || depCount === 0) {
    clearDepGraph("No dependencies found for this project version yet.");
    return;
  }

  const visualType = el.depVisualTypeSelect.value || "tidy-tree";
  try {
    if (visualType === "treemap") return renderDepTreemap();
    if (visualType === "sunburst") return renderDepSunburst();
    if (visualType === "radial-tree") return renderDepRadialTree();
    return renderDepTidyTree();
  } catch (err) {
    console.error(err);
    clearDepGraph(err?.message || "Failed to render dependency visualisation");
    toast(err?.message || "Failed to render dependency visualisation", "error");
  }
}

async function ensureDependencyGraphLoaded() {
  if (!state.projectId) return;
  const vId = Number(el.depVersionSelect?.value || state.currentVersionId || 0);
  if (!vId) {
    clearDepGraph("Project has no versions");
    return;
  }

  if (state.depGraphData && Number(state.depGraphVersionId) === Number(vId)) {
    renderDependencyVisualization();
    return;
  }

  clearDepGraph("Loading dependency data…");
  await loadDependencyGraph(vId);
  renderDependencyVisualization();
}

function bindEvents() {
  // Dependency filter preference
  state.depOnlyVulnOnly = readBoolStorage(DEP_ONLY_VULN_KEY, false);
  if (el.depOnlyVulnToggle)
    el.depOnlyVulnToggle.checked = !!state.depOnlyVulnOnly;

  el.tabMetadataBtn?.addEventListener("click", () => setTab("metadata"));
  el.tabVisualiseBtn?.addEventListener("click", () => setTab("visualise"));
  el.tabDependencyBtn?.addEventListener("click", () => setTab("dependency"));
  el.tabQuestionsBtn?.addEventListener("click", () => setTab("questions"));
  el.tabChangelogBtn?.addEventListener("click", () => setTab("changelog"));

  el.subscribeBtn?.addEventListener("click", () => {
    openSubscriptionModal();
  });

  el.subscriptionSaveBtn?.addEventListener("click", () => {
    saveSubscriptionFromModal();
  });

  el.subscriptionUnsubscribeBtn?.addEventListener("click", () => {
    unsubscribeFromModal();
  });

  el.askQuestionForm?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = (el.askQuestionBody?.value || "").trim();
    if (!body) return;
    await submitQuestion(body);
    el.askQuestionBody.value = "";
  });

  window.addEventListener("ospmae-notification", (ev) => {
    const msg = ev.detail;
    if (!msg || !state.projectId) return;
    if (
      (msg.kind === "project_question_created" ||
        msg.kind === "project_question_replied") &&
      Number(msg.project_id) === Number(state.projectId)
    ) {
      // Refresh in-place if the user is viewing the questions tab; otherwise keep a stale view.
      if (state.activeTab === "questions") {
        loadQuestions(true);
      } else {
        state.questionsLoaded = false;
      }
    }
  });

  window.addEventListener("hashchange", () => {
    setTab(tabFromLocation(), { updateLocation: false });
  });

  el.versionSelect?.addEventListener("change", async () => {
    const id = Number(el.versionSelect.value);
    if (Number.isNaN(id)) return;
    state.currentVersionId = id;
    updateProjectManifestNameSuggestion(false);
    await loadGraph(id);
    renderMetadata();
    if (state.activeTab === "visualise") {
      renderVisualization();
    }
  });

  el.depVersionSelect?.addEventListener("change", async () => {
    const id = Number(el.depVersionSelect.value);
    if (Number.isNaN(id)) return;
    state.depGraphVersionId = id;
    await loadDependencyGraph(id);
    if (state.activeTab === "dependency") {
      renderDependencyVisualization();
    }
  });

  el.depVisualTypeSelect?.addEventListener("change", () => {
    if (state.activeTab === "dependency") {
      renderDependencyVisualization();
    }
  });

  el.depOnlyVulnToggle?.addEventListener("change", () => {
    state.depOnlyVulnOnly = !!el.depOnlyVulnToggle.checked;
    writeBoolStorage(DEP_ONLY_VULN_KEY, state.depOnlyVulnOnly);
    if (state.activeTab === "dependency") {
      renderDependencyVisualization();
    }
  });

  el.depRunDiscoveryBtn?.addEventListener("click", async () => {
    if (!state.canRunDependencyDiscovery) {
      toast(
        "Only the project owner or admins can run dependency discovery.",
        "error",
      );
      return;
    }
    const id = Number(el.depVersionSelect?.value || 0);
    if (!id) return;
    try {
      setDepStatusBadge("queued", "Queued now • you can come back later");
      const res = await apiFetch(
        `/v1/project-versions/${id}/dependency-discovery?run_now=true`,
        { method: "POST" },
      );
      if (res?.launched) {
        toast("Dependency discovery started", "success");
      } else {
        toast("Dependency discovery queued", "success");
      }
      await loadDependencyGraph(id);
      if (state.activeTab === "dependency") renderDependencyVisualization();
    } catch (err) {
      console.error(err);
      toast(err?.message || "Failed to queue dependency discovery", "error");
      await loadDependencyGraph(id).catch(() => {});
    }
  });

  el.depZoomInBtn?.addEventListener("click", () => depZoomBy(1.2));
  el.depZoomOutBtn?.addEventListener("click", () => depZoomBy(0.85));
  el.depZoomResetBtn?.addEventListener("click", depResetZoom);

  // Exports (capability visualisations)
  el.exportGraphPdfBtn?.addEventListener("click", async () => {
    const proj = safeFilename(
      state.project?.machine_name ||
        state.project?.display_name ||
        `project_${state.projectId || ""}`,
    );
    const ver = safeFilename(
      state.versions?.find((x) => x.id === state.currentVersionId)?.version ||
        String(state.currentVersionId || ""),
    );
    await exportContainer(el.graph, {
      filenameBase: `${proj}_${ver}_capabilities`,
      format: "pdf",
    });
  });
  el.exportGraphJpegBtn?.addEventListener("click", async () => {
    const proj = safeFilename(
      state.project?.machine_name ||
        state.project?.display_name ||
        `project_${state.projectId || ""}`,
    );
    const ver = safeFilename(
      state.versions?.find((x) => x.id === state.currentVersionId)?.version ||
        String(state.currentVersionId || ""),
    );
    await exportContainer(el.graph, {
      filenameBase: `${proj}_${ver}_capabilities`,
      format: "jpeg",
    });
  });

  // Exports (manifest)
  el.exportManifestJsonBtn?.addEventListener("click", () =>
    exportProjectManifest("json"),
  );
  el.exportManifestXlsxBtn?.addEventListener("click", () =>
    exportProjectManifest("xlsx"),
  );
  el.exportManifestMdBtn?.addEventListener("click", () =>
    exportProjectManifest("markdown"),
  );
  el.saveProjectManifestBtn?.addEventListener("click", saveProjectManifest);

  // Exports (dependency map)
  el.exportDepPdfBtn?.addEventListener("click", async () => {
    const proj = safeFilename(
      state.project?.machine_name ||
        state.project?.display_name ||
        `project_${state.projectId || ""}`,
    );
    const ver = safeFilename(
      state.versions?.find((x) => x.id === state.depGraphVersionId)?.version ||
        String(state.depGraphVersionId || ""),
    );
    await exportContainer(el.depGraph, {
      filenameBase: `${proj}_${ver}_dependencies`,
      format: "pdf",
    });
  });
  el.exportDepJpegBtn?.addEventListener("click", async () => {
    const proj = safeFilename(
      state.project?.machine_name ||
        state.project?.display_name ||
        `project_${state.projectId || ""}`,
    );
    const ver = safeFilename(
      state.versions?.find((x) => x.id === state.depGraphVersionId)?.version ||
        String(state.depGraphVersionId || ""),
    );
    await exportContainer(el.depGraph, {
      filenameBase: `${proj}_${ver}_dependencies`,
      format: "jpeg",
    });
  });

  el.visualTypeSelect?.addEventListener("change", () => {
    if (state.activeTab === "visualise") {
      renderVisualization();
    }
  });

  el.zoomInBtn?.addEventListener("click", () => zoomBy(1.2));
  el.zoomOutBtn?.addEventListener("click", () => zoomBy(0.85));
  el.zoomResetBtn?.addEventListener("click", resetZoom);

  window.addEventListener("resize", () => {
    if (state.activeTab === "visualise") {
      renderVisualization();
    }
    if (state.activeTab === "dependency") {
      renderDependencyVisualization();
    }
  });
}

async function init() {
  try {
    state.me = await initAuth({ redirectOnFail: true });
    if (!state.me) return;

    // Optional areas: hide manifest controls when the installation has the
    // manifests feature off (the API 404s them too).
    if (window.OSPMAE && !window.OSPMAE.featureOn("manifests")) {
      const manifestExportField = document.getElementById(
        "manifestExportField",
      );
      if (manifestExportField) manifestExportField.style.display = "none";
      document.querySelectorAll('[data-feature="manifests"]').forEach((n) => {
        n.style.display = "none";
      });
    }

    const role = roleOf(state.me);
    if (el.whoami) {
      el.whoami.textContent = state.me?.username
        ? `${state.me.username} (${role})`
        : role;
    }

    // Manifest export is available for architect/product owner/admin roles.
    if (el.manifestExportField) {
      el.manifestExportField.style.display = canExportManifests() ? "" : "none";
    }

    // Framework selection (drives the taxonomy mapping + visualisation colouring).
    await loadFrameworks();
    state.frameworks = getFrameworks();
    state.activeFramework = getActiveFramework();

    bindEvents();
    await loadProject();

    // Allow deep-linking directly to a tab, e.g. /project.html?id=1#dependencies
    // or the older query style /project.html?id=1&tab=dependency.
    setTab(tabFromLocation(), { updateLocation: false });
  } catch (error) {
    console.error(error);
    OSPMAE.toast(error.message || "Failed to load project", "error");
    clearGraph(error.message || "Unable to load project visualisations.");
  }
}

init();
