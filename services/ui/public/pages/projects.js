const OSPMAE = window.OSPMAE;
const {
  api: apiFetch,
  initAuth,
  ensureInitialized,
  canMaintainProjects,
  csvCell,
  escapeHtml,
  toast,
} = OSPMAE;

const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "negligible",
  "unknown",
];
const SEVERITY_BADGE = {
  critical: "text-bg-danger",
  high: "text-bg-warning",
  medium: "text-bg-info",
  low: "text-bg-secondary",
  negligible: "text-bg-light",
  unknown: "text-bg-light",
};

const el = {
  orgFilter: document.getElementById("orgFilter"),
  exportCsv: document.getElementById("exportCsv"),
  newProjectBtn: document.getElementById("newProjectBtn"),
  summary: document.getElementById("summary"),
  rows: document.getElementById("rows"),
};

let current = null;

function orgName(row) {
  return row.organisation || "—";
}

function scanLabel(row) {
  if (!row.latest) return "No release yet";
  // Values come from dependency_discovery_status, written by
  // app/tasks/dependency_discovery.py: not_run, queued, running, complete
  // and error.
  const s = row.dependencies?.discovery_status || "not_run";
  const map = {
    not_run: "Not scanned yet",
    queued: "Discovery queued",
    running: "Discovering",
    complete: "Discovery complete",
    error: "Discovery failed",
  };
  return map[s] || s;
}

function severityChips(v) {
  const by = (v && v.by_severity) || {};
  const chips = [];
  for (const key of SEVERITY_ORDER) {
    const count = by[key] || 0;
    if (!count) continue;
    chips.push(
      `<span class="badge ${SEVERITY_BADGE[key] || "text-bg-secondary"}">${key} ${count}</span>`,
    );
  }
  return chips.length
    ? chips.join(" ")
    : '<span class="badge text-bg-success">none found</span>';
}

function renderSummary(projects) {
  const total = projects.length;
  // Same vocabulary the rows use: dependency_discovery_status is
  // not_run, queued, running, complete or error. Queued and running work
  // count as scanned neither — they are in flight, and the rows show it.
  const scanned = projects.filter(
    (p) => p.dependencies?.discovery_status === "complete",
  ).length;
  const stale = projects.filter((p) => {
    const status = p.dependencies?.discovery_status || "not_run";
    return p.latest && (status === "not_run" || status === "error");
  }).length;
  const critical = projects.reduce((acc, p) => {
    const by = p.vulnerabilities?.by_severity || {};
    return acc + (by.critical || 0) + (by.high || 0);
  }, 0);
  const cards = [
    ["Projects", total],
    ["Scanned releases", scanned],
    ["Needing a scan", stale],
    ["Critical + high findings (latest)", critical],
  ];
  el.summary.innerHTML = cards
    .map(
      ([label, value]) =>
        `<div class="col-6 col-lg-3"><div class="card py-2"><div class="px-3"><div class="small text-secondary">${label}</div><div class="h4 mb-0">${value}</div></div></div></div>`,
    )
    .join("");
}

function renderRows(projects) {
  if (!projects.length) {
    el.rows.innerHTML =
      '<tr><td colspan="7" class="text-secondary">No projects in this view yet. Use New project to add one.</td></tr>';
    return;
  }
  el.rows.innerHTML = projects
    .map((row) => {
      // A tracked branch stands in for releases: its version is the branch.
      // The icon alone tells the two apart: a branch, or a release tag.
      const [icon, kind] = row.tracked_branch
        ? ["bi-git", "Tracked branch"]
        : ["bi-tag", "Release"];
      const latest = row.latest
        ? `<span title="${kind}"><i class="bi ${icon} text-secondary" aria-hidden="true"></i><span class="visually-hidden">${kind}: </span> ${escapeHtml(row.latest.version)}</span>`
        : '<span class="text-secondary">no release</span>';
      // The column is a single number: how many direct dependencies the
      // latest release recorded. The status vocabulary is not_run, queued,
      // running, complete and error (dependency_discovery.py) — anything
      // else falls through to the least-assuming label.
      const discovery = row.dependencies;
      const status = String(discovery?.discovery_status || "not_run");
      let deps;
      if (status === "complete") {
        deps = String(discovery.count ?? 0);
      } else if (status === "error") {
        deps = '<span class="badge text-bg-warning">discovery failed</span>';
      } else if (status === "queued" || status === "running") {
        deps = '<span class="text-secondary small">discovery running…</span>';
      } else {
        deps = '<span class="text-secondary small">not scanned yet</span>';
      }
      const link = row.latest
        ? `href="/project.html?id=${Number(row.id)}&version_id=${Number(row.latest.id)}"`
        : "";
      return `<tr>
        <td><a class="text-decoration-none" ${link}>${escapeHtml(row.name)}</a></td>
        <td>${escapeHtml(orgName(row))}</td>
        <td>${latest}</td>
        <td>${escapeHtml(scanLabel(row))}</td>
        <td class="text-end">${deps}</td>
        <td>${severityChips(row.vulnerabilities)}</td>
        <td class="text-nowrap"><a class="btn btn-sm btn-outline-primary" href="/project.html?id=${Number(row.id)}">Open</a></td>
      </tr>`;
    })
    .join("");
}

function csv() {
  const projects = current || [];
  const lines = [
    "project,organisation,machine_name,latest_version,scan_state,dependencies,unfixed_total",
  ];
  for (const row of projects) {
    const unfixed = row.vulnerabilities
      ? SEVERITY_ORDER.filter((k) => k !== "unknown").reduce(
          (acc, k) => acc + ((row.vulnerabilities.by_severity || {})[k] || 0),
          0,
        )
      : 0;
    lines.push(
      [
        row.name,
        row.organisation || "",
        row.machine_name,
        row.latest?.version || "",
        scanLabel(row),
        row.dependencies?.discovery_status === "complete"
          ? row.dependencies.count
          : "",
        unfixed,
      ]
        .map(csvCell)
        .join(","),
    );
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "ospmae-dependency-dashboard.csv";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function refresh() {
  const org = String(el.orgFilter.value || "");
  const url =
    "/v1/dashboard" +
    (org ? `?organisation_id=${encodeURIComponent(org)}` : "");
  try {
    const body = await apiFetch(url);
    current = body.projects || [];
    renderSummary(current);
    renderRows(current);
  } catch (err) {
    toast(err?.message || "Dashboard failed to load", "error");
  }
}

(async () => {
  await initAuth();
  await ensureInitialized();
  // The API decides who may create projects; the button only spares other
  // roles a form they cannot submit.
  el.newProjectBtn.hidden = !canMaintainProjects();
  try {
    const orgs = await apiFetch("/v1/organisations");
    for (const o of orgs) {
      const option = document.createElement("option");
      option.value = o.id;
      option.textContent = `${o.name} (${o.project_count})`;
      el.orgFilter.append(option);
    }
  } catch {}
  el.orgFilter.addEventListener("change", refresh);
  el.exportCsv.addEventListener("click", csv);
  await refresh();
})();
