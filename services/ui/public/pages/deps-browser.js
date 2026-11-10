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
    <div class="d-flex flex-wrap gap-2 align-items-center justify-content-between mt-2">
      <div id="depPagerInfo" class="small text-secondary"></div>
      <div class="d-flex gap-2">
        <button id="depPrevBtn" class="btn btn-sm btn-outline-primary" type="button">Prev</button>
        <button id="depNextBtn" class="btn btn-sm btn-outline-primary" type="button">Next</button>
      </div>
    </div>
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
    pagerInfo: document.getElementById("depPagerInfo"),
    prevBtn: document.getElementById("depPrevBtn"),
    nextBtn: document.getElementById("depNextBtn"),
  };
}

const browserPage = { limit: 50, offset: 0, total: 0 };

function updatePager(controls) {
  const info = `${browserPage.total} package(s) matching; showing ${browserPage.total ? browserPage.offset + 1 : 0}–${Math.min(browserPage.offset + browserPage.limit, browserPage.total)}`;
  if (controls.pagerInfo) controls.pagerInfo.textContent = info;
  if (controls.prevBtn) controls.prevBtn.disabled = browserPage.offset <= 0;
  if (controls.nextBtn) {
    controls.nextBtn.disabled =
      browserPage.offset + browserPage.limit >= browserPage.total;
  }
}

async function changePage(controls, direction) {
  const next = browserPage.offset + direction * browserPage.limit;
  if (next < 0 || next >= browserPage.total) return;
  browserPage.offset = next;
  await load(controls);
}

async function load(controls) {
  controls.rows.innerHTML =
    '<tr><td colspan="6" class="text-secondary">Loading…</td></tr>';
  try {
    const params = new URLSearchParams();
    const search = controls.search.value.trim();
    const ecosystem = controls.ecosystem.value;
    if (search) params.set("q", search);
    if (ecosystem) params.set("ecosystem", ecosystem);
    if (controls.vulnerable.checked) params.set("vulnerable", "true");
    params.set("limit", String(browserPage.limit));
    params.set("offset", String(browserPage.offset));
    const body = await apiFetch("/v1/dependencies?" + params.toString());
    // The ecosystem filter offers whatever the server says exists; fill it
    // once on the first page so a user's selection survives pagination.
    if (
      Array.isArray(body.ecosystems) &&
      controls.ecosystem.options.length <= 1
    ) {
      for (const eco of body.ecosystems) {
        const option = document.createElement("option");
        option.value = eco;
        option.textContent = eco;
        controls.ecosystem.append(option);
      }
    }
    browserPage.total = Number(body.total ?? body.dependencies.length);
    if (!body.dependencies.length) {
      controls.rows.innerHTML =
        '<tr><td colspan="6" class="text-secondary">Nothing matched. Dependency discovery populates this list as scans run.</td></tr>';
      updatePager(controls);
      return;
    }
    controls.rows.innerHTML = body.dependencies
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
    controls.rows.innerHTML =
      '<tr><td colspan="6" class="text-secondary">Failed to load.</td></tr>';
    updatePager(controls);
    toast(err?.message || "Dependency index failed", "error");
  }
  updatePager(controls);
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
    browserPage.offset = 0;
    timer = setTimeout(() => load(controls), 300);
  });
  const resetAndLoad = () => {
    browserPage.offset = 0;
    load(controls);
  };
  controls.ecosystem.addEventListener("change", resetAndLoad);
  controls.vulnerable.addEventListener("change", resetAndLoad);
  controls.prevBtn?.addEventListener("click", () => changePage(controls, -1));
  controls.nextBtn?.addEventListener("click", () => changePage(controls, 1));
  await load(controls);
  updatePager(controls);
})();
