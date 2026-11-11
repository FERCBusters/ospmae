/* global d3 */

(() => {
  const apiFetch =
    window.OSPMAE?.api || window.OSPMAE?.apiRequest || window.apiRequest;
  const initAuth = window.OSPMAE?.initAuth;
  const toast = window.OSPMAE?.toast;

  const el = {
    refreshBtn: document.getElementById("refreshBtn"),
    notFound: document.getElementById("notFound"),

    depTitle: document.getElementById("depTitle"),
    depSubtitle: document.getElementById("depSubtitle"),
    depBadges: document.getElementById("depBadges"),
    depName: document.getElementById("depName"),
    depMeta: document.getElementById("depMeta"),

    vulnSummary: document.getElementById("vulnSummary"),
    vulnBody: document.getElementById("vulnBody"),
    vulnCount: document.getElementById("vulnCount"),

    usedByBody: document.getElementById("usedByBody"),
    usedByCount: document.getElementById("usedByCount"),
    usageGraph: document.getElementById("depUsageGraph"),

    packageVersionsCard: document.getElementById("packageVersionsCard"),
    packageProjectsBadge: document.getElementById("packageProjectsBadge"),
    packageVersionsBody: document.getElementById("packageVersionsBody"),
    packageVersionsMore: document.getElementById("packageVersionsMore"),

    namespaceCard: document.getElementById("namespaceCard"),
    namespaceBadge: document.getElementById("namespaceBadge"),
    namespaceHelp: document.getElementById("namespaceHelp"),
    namespaceList: document.getElementById("namespaceList"),
  };

  const state = {
    id: null,
    data: null,
  };

  function roleOf(me) {
    return String(me?.effective_role || me?.role || "viewer").toLowerCase();
  }

  function esc(s) {
    const fn = window.OSPMAE?.escapeHtml;
    if (fn) return fn(String(s ?? ""));
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function badge(text, className) {
    const span = document.createElement("span");
    span.className = `badge ${className || "text-bg-secondary"}`;
    span.textContent = text;
    return span;
  }

  function sevBadge(sev) {
    const s = String(sev || "UNKNOWN").toUpperCase();
    if (s === "CRITICAL") return badge(s, "text-bg-danger");
    if (s === "HIGH") return badge(s, "text-bg-danger");
    if (s === "MEDIUM") return badge(s, "text-bg-warning");
    if (s === "LOW") return badge(s, "text-bg-info");
    return badge(s, "text-bg-secondary");
  }

  function fmtBool(v) {
    return v
      ? '<i class="bi bi-check-lg text-success"></i>'
      : '<span class="text-secondary">—</span>';
  }

  function dims() {
    const rect = el.usageGraph?.getBoundingClientRect?.();
    const width = Math.max(520, Math.floor(rect?.width || 1100));
    const height = Math.max(420, Math.floor(rect?.height || 520));
    return { width, height };
  }

  // Every recorded version of the package with its own project count, so
  // the list's package-level figure reconciles with this version's backlinks.
  function renderPackageVersions(pkg) {
    const versions = Array.isArray(pkg?.versions) ? pkg.versions : [];
    if (!el.packageVersionsCard) return;
    el.packageVersionsCard.hidden = versions.length === 0;
    el.packageProjectsBadge.textContent = `${Number(pkg?.project_count || 0)} projects, any version`;
    el.packageVersionsMore.hidden = !pkg?.versions_truncated;
    el.packageVersionsBody.replaceChildren(
      ...versions.map((v) => {
        const tr = document.createElement("tr");
        const name = document.createElement("td");
        if (v.current) {
          name.textContent = String(v.version || "(unversioned)");
          const here = document.createElement("span");
          here.className = "badge text-bg-primary ms-2";
          here.textContent = "this page";
          name.appendChild(here);
        } else {
          const link = document.createElement("a");
          link.href = `/dependencies.html?id=${encodeURIComponent(String(v.public_id || ""))}`;
          link.textContent = String(v.version || "(unversioned)");
          name.appendChild(link);
        }
        const count = document.createElement("td");
        count.className = "text-end";
        count.textContent = String(Number(v.project_count || 0));
        tr.append(name, count);
        return tr;
      }),
    );
  }

  function renderUsageGraph(projects, depLabel) {
    if (!el.usageGraph || !window.d3) return;
    const { width, height } = dims();

    el.usageGraph.innerHTML = "";

    const svg = d3
      .select(el.usageGraph)
      .append("svg")
      .attr("viewBox", [0, 0, width, height])
      .attr("width", "100%")
      .attr("height", height);

    const nodes = [];
    const links = [];

    const depNode = { id: "dep", type: "dependency", label: depLabel };
    nodes.push(depNode);

    const maxProjects = 60;
    const shown = Array.isArray(projects) ? projects.slice(0, maxProjects) : [];
    shown.forEach((p) => {
      const ver = String(p.project_version || "").trim();
      const pLabel = ver ? `${p.project_name} ${ver}` : p.project_name;
      const n = {
        id: `p:${p.project_id}:${p.project_version_id}`,
        type: "project",
        label: pLabel,
        project_id: p.project_id,
      };
      nodes.push(n);
      links.push({
        source: depNode.id,
        target: n.id,
        indirect: !!p.is_indirect,
      });
    });

    const sim = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink(links)
          .id((d) => d.id)
          .distance(120)
          .strength(0.65),
      )
      .force("charge", d3.forceManyBody().strength(-420))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force(
        "collide",
        d3
          .forceCollide()
          .radius((d) => (d.type === "dependency" ? 46 : 26))
          .iterations(2),
      );

    const link = svg
      .append("g")
      .attr("stroke", "var(--bs-secondary-color)")
      .attr("stroke-opacity", 0.35)
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke-dasharray", (d) => (d.indirect ? "3,4" : null));

    const node = svg
      .append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .style("cursor", (d) => (d.type === "project" ? "pointer" : "default"))
      .on("click", (event, d) => {
        if (event?.defaultPrevented) return;
        if (d.type === "project" && d.project_id) {
          window.location.href = `/project.html?id=${encodeURIComponent(String(d.project_id))}`;
        }
      })
      .call(
        d3
          .drag()
          .on("start", (event, d) => {
            if (!event.active) sim.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) sim.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          }),
      );

    node
      .append("circle")
      .attr("r", (d) => (d.type === "dependency" ? 22 : 10))
      .attr("fill", (d) =>
        d.type === "dependency" ? "var(--bs-primary)" : "var(--bs-body-color)",
      )
      .attr("opacity", (d) => (d.type === "dependency" ? 0.9 : 0.7));

    node
      .append("text")
      .attr("x", 14)
      .attr("dy", "0.32em")
      .style("font-size", (d) => (d.type === "dependency" ? "12px" : "11px"))
      .style("font-weight", (d) => (d.type === "dependency" ? 650 : 500))
      .text((d) => d.label);

    sim.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    if (projects.length > maxProjects) {
      const note = document.createElement("div");
      note.className = "text-secondary small mt-2";
      note.textContent = `Showing ${maxProjects} of ${projects.length} project links.`;
      el.usageGraph.appendChild(note);
    }
  }

  function render() {
    const data = state.data;
    if (!data?.dependency_version) return;

    const dv = data.dependency_version;
    const eco = String(dv.ecosystem || "").toLowerCase();
    const name = dv.name || dv.normalized_name || "";
    const label = dv.version ? `${name}@${dv.version}` : name;

    if (el.depTitle) el.depTitle.textContent = label || "Dependency";
    if (el.depSubtitle)
      el.depSubtitle.textContent = `${eco || "ecosystem"} • dependency version #${dv.dependency_version_id}`;

    if (el.depName) el.depName.textContent = label;

    if (el.depMeta) {
      const parts = [];
      if (dv.normalized_name && dv.normalized_name !== dv.name)
        parts.push(`normalized: ${dv.normalized_name}`);
      if (dv.created_at)
        parts.push(
          `first seen: ${window.OSPMAE.formatTimestamp(dv.created_at)}`,
        );
      el.depMeta.textContent = parts.join(" • ");
    }

    if (el.depBadges) {
      el.depBadges.innerHTML = "";
      el.depBadges.appendChild(badge(eco || "unknown", "text-bg-secondary"));
      el.depBadges.appendChild(
        badge(`id ${dv.dependency_version_id}`, "text-bg-light"),
      );
    }

    // Vulnerability summary
    const sevCounts = data.severity_counts || {};
    const vulnTotal = Array.isArray(data.vulnerabilities)
      ? data.vulnerabilities.length
      : 0;
    if (el.vulnCount) el.vulnCount.textContent = String(vulnTotal);

    if (el.vulnSummary) {
      el.vulnSummary.innerHTML = "";
      if (!vulnTotal) {
        el.vulnSummary.innerHTML =
          '<span class="text-secondary">No known vulnerabilities recorded.</span>';
      } else {
        const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
        const wrap = document.createElement("div");
        wrap.className = "d-flex flex-wrap gap-2 align-items-center";
        order.forEach((k) => {
          const n = Number(sevCounts[k] || 0);
          if (!n) return;
          const b = sevBadge(k);
          b.textContent = `${k} ${n}`;
          wrap.appendChild(b);
        });
        const totalB = badge(`Total ${vulnTotal}`, "text-bg-secondary");
        wrap.appendChild(totalB);
        el.vulnSummary.appendChild(wrap);
      }
    }

    // Used by table: one row per project release; the badge counts projects.
    const projects = Array.isArray(data.projects) ? data.projects : [];
    if (el.usedByCount)
      el.usedByCount.textContent = String(
        new Set(projects.map((p) => p.project_id)).size,
      );
    if (el.usedByBody) {
      el.usedByBody.innerHTML = projects.length
        ? ""
        : '<tr><td colspan="5" class="text-secondary">No projects linked to this dependency version yet.</td></tr>';
      projects.forEach((p) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><a href="/project.html?id=${encodeURIComponent(String(p.project_id))}">${esc(p.project_name)}</a></td>
          <td class="text-nowrap">${esc(p.project_version || "")}</td>
          <td class="text-center">${fmtBool(p.is_latest)}</td>
          <td class="text-center">${fmtBool(p.is_draft)}</td>
          <td class="text-center">${fmtBool(p.is_indirect)}</td>
        `;
        el.usedByBody.appendChild(tr);
      });
    }

    renderUsageGraph(projects, label);
    renderPackageVersions(data.package);

    // Vulnerabilities table
    const vulns = Array.isArray(data.vulnerabilities)
      ? data.vulnerabilities
      : [];
    if (el.vulnBody) {
      el.vulnBody.innerHTML = vulns.length
        ? ""
        : '<tr><td colspan="5" class="text-secondary">No vulnerabilities recorded for this dependency version.</td></tr>';
      vulns.forEach((v) => {
        const refs = Array.isArray(v.references) ? v.references : [];
        const title = v.title || "";
        const id = v.vulnerability_id || "";
        const fixed = v.fixed_version || "";
        const sev = String(v.severity || "UNKNOWN").toUpperCase();
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${sevBadge(sev).outerHTML}</td>
          <td class="text-nowrap">${esc(id)}</td>
          <td>${esc(title)}${
            refs.length
              ? `<div class="small text-secondary mt-1">${refs
                  .slice(0, 3)
                  .map((r) => `<span class=\"me-2\">${esc(r)}</span>`)
                  .join("")}</div>`
              : ""
          }</td>
          <td class="text-nowrap">${esc(fixed)}</td>
          <td class="text-nowrap">${esc(v.scanner || "")}</td>
        `;
        el.vulnBody.appendChild(tr);
      });
    }

    // Namespace
    const ns = data.namespace;
    if (ns && el.namespaceCard && el.namespaceList) {
      el.namespaceCard.style.display = "";
      if (el.namespaceBadge)
        el.namespaceBadge.textContent = `${ns.scope || ""}`;
      if (el.namespaceHelp) {
        el.namespaceHelp.textContent = `Other ${String(ns.ecosystem || "").toLowerCase()} packages under ${ns.scope}.`;
      }

      el.namespaceList.innerHTML = "";
      const pkgs = Array.isArray(ns.packages) ? ns.packages : [];
      pkgs.forEach((p) => {
        const col = document.createElement("div");
        col.className = "col-12 col-md-6 col-lg-4";
        col.innerHTML = `<div class="border rounded-3 p-2 d-flex align-items-center justify-content-between gap-2">
          <div class="text-truncate" title="${esc(p.name)}">${esc(p.name)}</div>
          <span class="badge text-bg-light">pkg</span>
        </div>`;
        el.namespaceList.appendChild(col);
      });

      if (ns.truncated) {
        const note = document.createElement("div");
        note.className = "text-secondary small mt-2";
        note.textContent = "List truncated.";
        el.namespaceList.parentElement.appendChild(note);
      }
    } else if (el.namespaceCard) {
      el.namespaceCard.style.display = "none";
    }
  }

  async function load() {
    if (!apiFetch) throw new Error("App is not initialised");
    if (!state.id) throw new Error("Missing dependency id");

    el.notFound.style.display = "none";
    el.depSubtitle.textContent = "Loading…";

    const data = await apiFetch(
      `/v1/dependencies/${encodeURIComponent(String(state.id))}`,
    );
    state.data = data;
    render();
  }

  async function init() {
    const params = new URLSearchParams(window.location.search || "");
    // The id is either a legacy numeric dependency-version id or the UUID
    // public id the dependency browser deep-links; the API resolves both.
    const id = (params.get("id") || "").trim();
    state.id = id && /^[a-z0-9-]{1,64}$/i.test(id) ? id : null;

    // Admin-only page (dependency metadata is global).
    try {
      const me = initAuth ? await initAuth({ redirectOnFail: true }) : null;
      if (window.OSPMAE && !window.OSPMAE.gateFeature("dependency_scans"))
        return null;
      if (!me) return;
      if (roleOf(me) !== "admin") {
        el.notFound.style.display = "";
        el.notFound.textContent = "This page is only available to admins.";
        el.depSubtitle.textContent = "Not authorised.";
        return;
      }
    } catch (e) {
      // initAuth already handled redirects
      return;
    }

    el.refreshBtn?.addEventListener("click", () => {
      load().catch((e) =>
        toast?.(e?.message || "Failed to load dependency", "error"),
      );
    });

    if (!state.id) {
      // No id means the dependency browser owns this page; it rewrites the
      // whole main after authentication, so the detail view stays quiet
      // instead of flashing "Dependency not found." as a leftover.
      el.depSubtitle.textContent = "Opening the dependency browser…";
      return;
    }

    load().catch((e) => {
      console.error(e);
      el.notFound.style.display = "";
      toast?.(e?.message || "Failed to load dependency", "error");
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      init();
    });
  } else {
    init();
  }
})();
