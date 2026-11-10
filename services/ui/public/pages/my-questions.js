import {
  apiGet,
  esc,
  fmtTs,
  initNavbar,
} from "/vendor/mosp-design-system/app.js";

await initNavbar();

const statusEl = document.getElementById("status");
const countEl = document.getElementById("questionsCount");
const emptyEl = document.getElementById("emptyState");
const wrapEl = document.getElementById("questionsTableWrap");
const bodyEl = document.getElementById("questionsBody");

function showStatus(message, kind = "info") {
  if (!statusEl) return;
  statusEl.className = `alert alert-${kind}`;
  statusEl.textContent = message;
  statusEl.style.display = "";
}

function clearStatus() {
  if (statusEl) statusEl.style.display = "none";
}

function latestPreview(thread) {
  const posts = Array.isArray(thread?.posts) ? thread.posts : [];
  const last = posts.length ? posts[posts.length - 1] : null;
  const body = String(last?.body || "")
    .trim()
    .replace(/\s+/g, " ");
  if (!body) return "—";
  return body.length > 140 ? `${body.slice(0, 139)}…` : body;
}

function statusBadge(status) {
  const value = String(status || "open").toLowerCase();
  if (value === "answered")
    return '<span class="badge text-bg-success">answered</span>';
  return '<span class="badge text-bg-warning">open</span>';
}

function render(items) {
  const rows = (items || [])
    .map(
      (thread) => `
    <tr>
      <td class="small text-secondary">${esc(thread?.updated_at ? fmtTs(thread.updated_at) : "—")}</td>
      <td>${esc(thread?.project_display_name || `Project #${thread?.project_id || ""}`)}</td>
      <td>${statusBadge(thread?.status)}</td>
      <td class="wrap">${esc(latestPreview(thread))}</td>
      <td class="text-end"><a class="btn btn-sm btn-outline-primary" href="/project.html?id=${encodeURIComponent(thread?.project_id || "")}&tab=questions">Open</a></td>
    </tr>
  `,
    )
    .join("");

  if (!items.length) {
    emptyEl.style.display = "";
    wrapEl.style.display = "none";
    bodyEl.innerHTML = "";
    countEl.textContent = "0";
    return;
  }

  emptyEl.style.display = "none";
  wrapEl.style.display = "";
  bodyEl.innerHTML = rows;
  countEl.textContent = String(items.length);
}

async function load() {
  try {
    clearStatus();
    // Authentication first; then the questions feature gate, which replaces
    // the page with the dashboard when the feature is off.
    if (window.OSPMAE) {
      await window.OSPMAE.ensureInitialized();
      if (!window.OSPMAE.gateFeature("questions")) return;
    }
    const data = await apiGet("/v1/me/questions");
    render(Array.isArray(data?.items) ? data.items : []);
  } catch (error) {
    showStatus(error?.message || "Failed to load questions.", "danger");
  }
}

document.getElementById("refreshBtn")?.addEventListener("click", load);
await load();
