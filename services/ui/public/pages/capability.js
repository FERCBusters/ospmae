/* global d3 */

(() => {
  const apiFetch = window.OSPMAE?.api || window.OSPMAE?.apiRequest || window.apiRequest;
  const toast = window.OSPMAE?.toast;

  const el = {
    refreshBtn: document.getElementById('refreshBtn'),
    notFound: document.getElementById('notFound'),

    capTitle: document.getElementById('capTitle'),
    capSubtitle: document.getElementById('capSubtitle'),
    capBadges: document.getElementById('capBadges'),
    capName: document.getElementById('capName'),
    capMeta: document.getElementById('capMeta'),
    capUsage: document.getElementById('capUsage'),

    usedByBody: document.getElementById('usedByBody'),
    usedByCount: document.getElementById('usedByCount'),
    usageGraph: document.getElementById('capUsageGraph'),
  };

  const state = {
    id: null,
    data: null,
  };

  function esc(s) {
    const fn = window.OSPMAE?.escapeHtml;
    if (fn) return fn(String(s ?? ''));
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function badge(text, className) {
    const span = document.createElement('span');
    span.className = `badge ${className || 'text-bg-secondary'}`;
    span.textContent = text;
    return span;
  }

  function fmtBool(v) {
    return v ? '<i class="bi bi-check-lg text-success"></i>' : '<span class="text-secondary">—</span>';
  }

  function dims() {
    const rect = el.usageGraph?.getBoundingClientRect?.();
    const width = Math.max(520, Math.floor(rect?.width || 1100));
    const height = Math.max(420, Math.floor(rect?.height || 520));
    return { width, height };
  }

  function renderUsageGraph(projects, capLabel) {
    if (!el.usageGraph || !window.d3) return;
    const { width, height } = dims();
    el.usageGraph.innerHTML = '';

    const svg = d3.select(el.usageGraph)
      .append('svg')
      .attr('viewBox', [0, 0, width, height])
      .attr('width', '100%')
      .attr('height', height);

    const nodes = [];
    const links = [];
    const capNode = { id: 'cap', type: 'capability', label: capLabel };
    nodes.push(capNode);

    const maxProjects = 70;
    const shown = Array.isArray(projects) ? projects.slice(0, maxProjects) : [];
    shown.forEach((p) => {
      const ver = String(p.project_version || '').trim();
      const pLabel = ver ? `${p.project_name} ${ver}` : p.project_name;
      const n = {
        id: `p:${p.project_id}:${p.project_version_id}`,
        type: 'project',
        label: pLabel,
        project_id: p.project_id,
      };
      nodes.push(n);
      links.push({ source: capNode.id, target: n.id });
    });

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id).distance(120).strength(0.65))
      .force('charge', d3.forceManyBody().strength(-420))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide().radius((d) => (d.type === 'capability' ? 46 : 26)).iterations(2));

    const link = svg.append('g')
      .attr('stroke', 'var(--bs-secondary-color)')
      .attr('stroke-opacity', 0.35)
      .selectAll('line')
      .data(links)
      .join('line');

    const node = svg.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .style('cursor', (d) => (d.type === 'project' ? 'pointer' : 'default'))
      .on('click', (event, d) => {
        if (event?.defaultPrevented) return;
        if (d.type === 'project' && d.project_id) {
          window.location.href = `/project.html?id=${encodeURIComponent(String(d.project_id))}`;
        }
      })
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) sim.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) sim.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        }));

    node.append('circle')
      .attr('r', (d) => (d.type === 'capability' ? 22 : 10))
      .attr('fill', (d) => (d.type === 'capability' ? 'var(--bs-primary)' : 'var(--bs-body-color)'))
      .attr('opacity', (d) => (d.type === 'capability' ? 0.9 : 0.7));

    node.append('text')
      .attr('x', 14)
      .attr('dy', '0.32em')
      .style('font-size', (d) => (d.type === 'capability' ? '12px' : '11px'))
      .style('font-weight', (d) => (d.type === 'capability' ? 650 : 500))
      .text((d) => d.label);

    sim.on('tick', () => {
      link
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y);

      node.attr('transform', (d) => `translate(${d.x},${d.y})`);
    });

    if (projects.length > maxProjects) {
      const note = document.createElement('div');
      note.className = 'text-secondary small mt-2';
      note.textContent = `Showing ${maxProjects} of ${projects.length} project links.`;
      el.usageGraph.appendChild(note);
    }
  }

  function render() {
    const data = state.data;
    if (!data?.capability) return;

    const c = data.capability;
    const label = c.path || c.display_name || `Capability #${c.framework_node_id}`;
    const fw = c.framework_display_name || c.framework_machine_name || '';

    if (el.capTitle) el.capTitle.textContent = label;
    if (el.capSubtitle) el.capSubtitle.textContent = `${fw || 'framework'} • capability #${c.framework_node_id}`;

    if (el.capName) el.capName.textContent = label;

    if (el.capMeta) {
      const parts = [];
      if (c.key) parts.push(`key: ${c.key}`);
      if (c.level != null) parts.push(`level: ${c.level}`);
      if (c.description) parts.push(c.description);
      el.capMeta.textContent = parts.join(' • ');
    }

    if (el.capBadges) {
      el.capBadges.innerHTML = '';
      if (fw) el.capBadges.appendChild(badge(fw, 'text-bg-secondary'));
      el.capBadges.appendChild(badge(`id ${c.framework_node_id}`, 'text-bg-light'));
    }

    const projects = Array.isArray(data.projects) ? data.projects : [];
    if (el.capUsage) el.capUsage.textContent = `${projects.length} projects`;
    if (el.usedByCount) el.usedByCount.textContent = String(projects.length);

    if (el.usedByBody) {
      el.usedByBody.innerHTML = projects.length
        ? ''
        : '<tr><td colspan="4" class="text-secondary">No projects mapped to this capability yet.</td></tr>';
      projects.forEach((p) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><a href="/project.html?id=${encodeURIComponent(String(p.project_id))}">${esc(p.project_name)}</a></td>
          <td class="text-nowrap">${esc(p.project_version || '')}</td>
          <td class="text-center">${fmtBool(p.is_latest)}</td>
          <td class="text-center">${fmtBool(p.is_draft)}</td>
        `;
        el.usedByBody.appendChild(tr);
      });
    }

    renderUsageGraph(projects, label);
  }

  async function load() {
    if (!state.id) throw new Error('Missing capability id');
    const data = await apiFetch(`/v1/capabilities/${encodeURIComponent(String(state.id))}`);
    state.data = data;
    if (el.notFound) el.notFound.style.display = 'none';
    render();
  }

  function parseId() {
    const url = new URL(window.location.href);
    const id = url.searchParams.get('id');
    state.id = id ? Number(id) : null;
  }

  async function init() {
    parseId();
    el.refreshBtn?.addEventListener('click', () => load().catch((e) => toast?.(e?.message || 'Failed to load', 'error')));

    if (!state.id || Number.isNaN(state.id)) {
      if (el.notFound) el.notFound.style.display = 'block';
      if (el.capSubtitle) el.capSubtitle.textContent = 'Missing capability id.';
      return;
    }

    try {
      await load();
    } catch (err) {
      console.error(err);
      if (String(err?.detail || err?.message || '').toLowerCase().includes('not found')) {
        if (el.notFound) el.notFound.style.display = 'block';
        if (el.capSubtitle) el.capSubtitle.textContent = 'Capability not found.';
        return;
      }
      toast?.(err?.message || 'Failed to load capability', 'error');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
