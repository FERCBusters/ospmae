// Dependency browser: a searchable index of everything dependency discovery
// has recorded, with UUID deep links into the detail view (?id= handles the
// existing per-version page; no id means the browser).

const OSPMAE = window.OSPMAE;
const { api: apiFetch, initAuth, ensureInitialized, toast } = OSPMAE;

const escapeHtml = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );

function buildBrowser() {
  const section = document.createElement("main");
  section.id = "dep-browser-main";
  // The id matters: the removal logic below excludes this element through
  // :not(#dep-browser-main), so an unlabelled section makes the browser
  // exclude itself and every control lookup return null.
  section.className = "container py-4";
  section.innerHTML = `
    <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-3">
      <div>
        <h1 class="h3 mb-1">Dependencies</h1>
        <div class="text-secondary small">
          Everything dependency discovery has recorded, with usage counts and unfixed findings.
        </div>
      </div>
      <div class="d-flex gap-2 align-items-center flex-wrap">
        <input id="depSearch" class="form-control form-control-sm" placeholder="Search packages…" style="min-width:220px" />
        <select id="depEcosystem" class="form-select form-select-sm" style="min-width:140px">
          <option value="">All ecosystems</option>
        </select>
        <div class="form-check">
          <input type="checkbox" class="form-check-input" id="depVulnerable" />
          <label class="form-check-label small" for="depVulnerable">With vulnerabilities</label>
        </div>
      </div>
    </div>
    <div class="card"><div class="table-responsive"><table class="table table-sm align-middle mb-0">
      <thead class="table-light"><tr>
        <th>Package</th><th>Ecosystem</th><th class="text-end">Versions</th>
        <th class="text-end">Used by</th><th>Unfixed findings</th><th></th>
      </tr></thead>
      <tbody id="depRows"><tr><td colspan="6" class="text-secondary">Loading…</td></tr></tbody>
    </table></div></div>
  `;
  document.body.prepend(section);

  // The detail container stays hidden unless a dependency is deep-linked.
  const main = document.querySelector("main.container:not(#dep-browser-main)");
  if (main && !new URLSearchParams(window.location.search).get("id")) {
    main.remove();
  } else if (main) {
    section.remove();
    return null;
  }

  return {
    search: document.getElementById("depSearch"),
    ecosystem: document.getElementById("depEcosystem"),
    vulnerable: document.getElementById("depVulnerable"),
    rows: document.getElementById("depRows"),
  };
}

async function load(rows) {
  rows.innerHTML =
    '<tr><td colspan="6" class="text-secondary">Loading…</td></tr>';
  try {
    const params = new URLSearchParams();
    const search = document.getElementById("depSearch").value.trim();
    const ecosystem = document.getElementById("depEcosystem").value;
    if (search) params.set("q", search);
    if (ecosystem) params.set("ecosystem", ecosystem);
    if (document.getElementById("depVulnerable").checked)
      params.set("vulnerable", "true");
    params.set("limit", "200");
    const body = await apiFetch("/v1/dependencies?" + params.toString());
    if (!body.dependencies.length) {
      rows.innerHTML =
        '<tr><td colspan="6" class="text-secondary">Nothing matched. Dependency discovery populates this list as scans run.</td></tr>';
      return;
    }
    rows.innerHTML = body.dependencies
      .map(
        (d) => `<tr>
        <td><a class="text-decoration-none" href="/dependencies.html?id=${encodeURIComponent(d.public_id)}">${escapeHtml(d.name)}</a></td>
        <td>${escapeHtml(d.ecosystem)}</td>
        <td class="text-end">${d.version_count}</td>
        <td class="text-end">${d.used_by_count}</td>
        <td>${d.vulnerability_count ? `<span class="badge text-bg-warning">${d.vulnerability_count}</span>` : '<span class="badge text-bg-success">clean</span>'}</td>
        <td><a class="btn btn-sm btn-outline-primary" href="/dependencies.html?id=${encodeURIComponent(d.public_id)}">Open</a></td>
      </tr>`,
      )
      .join("");
  } catch (err) {
    rows.innerHTML =
      '<tr><td colspan="6" class="text-secondary">Failed to load.</td></tr>';
    toast(err?.message || "Dependency index failed", "error");
  }
}

(async () => {
  await initAuth();
  await ensureInitialized();
  const controls = buildBrowser();
  if (!controls) return;

  // Wire from the elements buildBrowser() created rather than re-querying
  // the document; a missed prepend must fail closed (no browser wiring and
  // no listeners) instead of throwing half-initialised.
  if (!controls.search || !controls.ecosystem || !controls.vulnerable) {
    return;
  }
  let timer = null;
  controls.search.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => load(controls.rows), 300);
  });
  controls.ecosystem.addEventListener("change", () => load(controls.rows));
  controls.vulnerable.addEventListener("change", () => load(controls.rows));
  await load(controls.rows);
})();
