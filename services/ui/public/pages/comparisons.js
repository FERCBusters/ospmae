/* global d3 */

(() => {
  const apiFetch = window.OSPMAE?.api || window.OSPMAE?.apiRequest || window.apiRequest;
  const initAuth = window.OSPMAE?.initAuth;
  const toast = window.OSPMAE?.toast;

  const el = {
    refreshBtn: document.getElementById('refreshBtn'),
    exportGraphPdfBtn: document.getElementById('exportGraphPdfBtn'),
    exportGraphJpegBtn: document.getElementById('exportGraphJpegBtn'),
    applyBtn: document.getElementById('applyBtn'),
    lens: document.getElementById('lens'),
    latestOnly: document.getElementById('latestOnly'),
    limitProjects: document.getElementById('limitProjects'),
    limitDeps: document.getElementById('limitDeps'),
    minUsage: document.getElementById('minUsage'),
    graph: document.getElementById('bipartiteGraph'),
    meta: document.getElementById('vizMeta'),

    chartTitle: document.getElementById('chartTitle'),
    limitItemsLabel: document.getElementById('limitItemsLabel'),

    tooltip: document.getElementById('vizTooltip'),
    tooltipTitle: document.getElementById('vizTooltipTitle'),
    tooltipBody: document.getElementById('vizTooltipBody'),
  };

  const state = {
    data: null,
    svg: null,
    viewport: null,
    zoom: null,
  };

  function roleOf(me) {
    return String(me?.effective_role || me?.role || 'viewer').toLowerCase();
  }


  // -----------------------------------------------------------------------------
  // Export helpers (SVG -> JPEG / PDF)
  // -----------------------------------------------------------------------------

  function findSvgIn(containerEl) {
    if (!containerEl) return null;
    return containerEl.querySelector('svg');
  }

  function safeFilename(value) {
    const v = String(value || 'export');
    const out = v.replace(/[^a-z0-9\-_.]+/gi, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '');
    return out || 'export';
  }

  function isTransparentColor(value) {
    const v = String(value || '').trim().toLowerCase();
    return v === 'transparent' || v === 'rgba(0, 0, 0, 0)' || v === 'rgba(0,0,0,0)';
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
    return '#ffffff';
  }

  function cloneSvgForExport(svgEl, { padding = 24, backgroundColor = '#ffffff' } = {}) {
    const clone = svgEl.cloneNode(true);

    // Ensure namespaces exist for standalone SVG serialization (helps text render correctly
    // when converting to an Image via a data: URL).
    try {
      if (!clone.getAttribute('xmlns')) clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
      if (!clone.getAttribute('xmlns:xlink')) clone.setAttribute('xmlns:xlink', 'http://www.w3.org/1999/xlink');
    } catch (_) {
      // ignore
    }

    // Prefer exporting the un-zoomed content (full graph). Remove zoom transform on the first <g>.
    const g = clone.querySelector('g');
    if (g) g.removeAttribute('transform');

    // Compute bbox on the ORIGINAL element (temporarily removing zoom transform).
    let bbox = null;
    try {
      const origG = svgEl.querySelector('g');
      if (origG) {
        const prev = origG.getAttribute('transform');
        origG.removeAttribute('transform');
        bbox = origG.getBBox();
        if (prev) origG.setAttribute('transform', prev);
        else origG.removeAttribute('transform');
      } else {
        bbox = svgEl.getBBox();
      }
    } catch (_) {
      // ignore
    }

    if (!bbox || !(bbox.width > 0 && bbox.height > 0)) {
      const vb = (svgEl.getAttribute('viewBox') || '').trim().split(/\s+/).map(Number);
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

    clone.setAttribute('viewBox', `${x} ${y} ${w} ${h}`);
    clone.setAttribute('width', String(w));
    clone.setAttribute('height', String(h));

    // Inline computed styles for common SVG elements to avoid missing CSS in exports.
    try {
      const selector = 'text,path,circle,rect,line,polyline,polygon';
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
        ].join(';');
        c.setAttribute('style', s);
      }
    } catch (_) {
      // ignore
    }

    // Add export background (helps JPEG/PDF and preserves the on-screen background).
    const ns = 'http://www.w3.org/2000/svg';
    const bg = document.createElementNS(ns, 'rect');
    bg.setAttribute('x', String(x));
    bg.setAttribute('y', String(y));
    bg.setAttribute('width', String(w));
    bg.setAttribute('height', String(h));
    bg.setAttribute('fill', backgroundColor || '#ffffff');
    clone.insertBefore(bg, clone.firstChild);

    try {
      clone.style.backgroundColor = backgroundColor || '#ffffff';
    } catch (_) {
      // ignore
    }

    // Make labels readable in exports (PDF/JPEG)
    applyExportTextOutline(clone);

    return { clone, box: { x, y, width: w, height: h } };
  }

  function parseCssColorToRgb(value) {
    const v = String(value || '').trim();
    if (!v) return null;
    // rgb/rgba
    let m = v.match(/^rgba?\((\d+)[,\s]+(\d+)[,\s]+(\d+)/i);
    if (m) return { r: Number(m[1]), g: Number(m[2]), b: Number(m[3]) };
    // hex
    m = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
    if (m) {
      const hex = m[1];
      if (hex.length === 3) {
        return {
          r: parseInt(hex[0] + hex[0], 16),
          g: parseInt(hex[1] + hex[1], 16),
          b: parseInt(hex[2] + hex[2], 16),
        };
      }
      return {
        r: parseInt(hex.slice(0, 2), 16),
        g: parseInt(hex.slice(2, 4), 16),
        b: parseInt(hex.slice(4, 6), 16),
      };
    }
    return null;
  }

  function relativeLuminance({ r, g, b }) {
    const srgb = [r, g, b].map((n) => {
      const c = (Number(n) || 0) / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * srgb[0] + 0.7152 * srgb[1] + 0.0722 * srgb[2];
  }

  function styleGet(style, prop) {
    const reProp = new RegExp(`${prop}\\s*:\\s*([^;]+)`, 'i');
    const m = String(style || '').match(reProp);
    return m ? String(m[1]).trim() : '';
  }

  function applyExportTextOutline(cloneSvg) {
    try {
      const texts = cloneSvg.querySelectorAll('text');
      texts.forEach((t) => {
        const style = t.getAttribute('style') || '';
        const fill = styleGet(style, 'fill') || t.getAttribute('fill') || '';
        const rgb = parseCssColorToRgb(fill);
        if (!rgb) return;
        const lum = relativeLuminance(rgb);
        const fontSizeStr = styleGet(style, 'font-size') || '12px';
        const fs = Number.parseFloat(fontSizeStr) || 12;
        const sw = Math.max(1, Math.min(3, fs * 0.14));
        const strokeRgb = lum > 0.60 ? 'rgb(0,0,0)' : 'rgb(255,255,255)';
        const strokeOpacity = lum > 0.60 ? 0.55 : 0.40;
        const extra = [
          'paint-order:stroke fill',
          'stroke-linejoin:round',
          'stroke-linecap:round',
          `stroke:${strokeRgb}`,
          `stroke-opacity:${strokeOpacity}`,
          `stroke-width:${sw}px`,
        ].join(';');
        t.setAttribute('style', `${style};${extra}`);
      });
    } catch (_) {
      // ignore
    }
  }

  async function svgToCanvas(svgEl, { maxDim = 4096, scale = 2, backgroundColor = '#ffffff' } = {}) {
    const { clone, box } = cloneSvgForExport(svgEl, { padding: 24, backgroundColor });
    const serializer = new XMLSerializer();
    const svgText = serializer.serializeToString(clone);
    const svgUrl = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svgText)}`;

    const img = new Image();
    img.decoding = 'async';

    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = reject;
      img.src = svgUrl;
    });

    const targetScale = Math.max(0.2, Math.min(scale, maxDim / box.width, maxDim / box.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.floor(box.width * targetScale));
    canvas.height = Math.max(1, Math.floor(box.height * targetScale));
    const ctx = canvas.getContext('2d');
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.fillStyle = backgroundColor || '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    return canvas;
  }

  function downloadDataUrl(dataUrl, filename) {
    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  async function exportSvgAsJpeg(svgEl, filenameBase, backgroundColor) {
    const canvas = await svgToCanvas(svgEl, { backgroundColor });
    const url = canvas.toDataURL('image/jpeg', 0.92);
    downloadDataUrl(url, `${filenameBase}.jpg`);
  }

  async function exportSvgAsPdf(svgEl, filenameBase, backgroundColor) {
    const jsPDF = window.jspdf?.jsPDF;
    if (!jsPDF) {
      toast?.('PDF export library (jsPDF) is not available', 'error');
      return;
    }
    const canvas = await svgToCanvas(svgEl, { backgroundColor });
    const imgData = canvas.toDataURL('image/jpeg', 0.92);

    const orientation = canvas.width >= canvas.height ? 'landscape' : 'portrait';
    const doc = new jsPDF({ orientation, unit: 'mm', format: 'a4' });
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
    doc.addImage(imgData, 'JPEG', x, y, drawW, drawH, undefined, 'FAST');
    doc.save(`${filenameBase}.pdf`);
  }

  async function exportContainer(containerEl, { filenameBase, format }) {
    const svgEl = findSvgIn(containerEl);
    if (!svgEl) {
      toast?.('Nothing to export yet (no graph rendered)', 'error');
      return;
    }
    const bg = effectiveBackgroundColor(containerEl);
    if (format === 'pdf') {
      await exportSvgAsPdf(svgEl, filenameBase, bg);
    } else {
      await exportSvgAsJpeg(svgEl, filenameBase, bg);
    }
  }

  function dims() {
    const rect = el.graph?.getBoundingClientRect?.();
    const width = Math.max(420, Math.floor(rect?.width || 1100));
    const height = Math.max(520, Math.floor(rect?.height || 620));
    return { width, height };
  }

  function showTooltip(title, body, x, y) {
    if (!el.tooltip) return;
    el.tooltipTitle.textContent = title || '';
    el.tooltipBody.textContent = body || '';
    el.tooltip.style.display = 'block';

    const pad = 14;
    const rect = el.tooltip.getBoundingClientRect();
    const left = Math.min(window.innerWidth - rect.width - pad, Math.max(pad, x + 12));
    const top = Math.min(window.innerHeight - rect.height - pad, Math.max(pad, y + 12));
    el.tooltip.style.left = `${left}px`;
    el.tooltip.style.top = `${top}px`;
  }

  function hideTooltip() {
    if (!el.tooltip) return;
    el.tooltip.style.display = 'none';
  }

  function clear(message) {
    if (!el.graph) return;
    el.graph.innerHTML = `<div class="p-3 text-secondary">${(window.OSPMAE?.escapeHtml || ((x) => x))(message || 'No data')}</div>`;
  }

  function currentLens() {
    const v = String(el.lens?.value || 'dependencies').toLowerCase().trim();
    if (v === 'capabilities') return 'capabilities';
    if (v === 'licenses') return 'licenses';
    return 'dependencies';
  }

function applyInitialLensFromUrl() {
  if (!el.lens) return;
  try {
    const params = new URLSearchParams(window.location.search || '');
    const requested = String(params.get('lens') || '').toLowerCase().trim();
    if (requested === 'dependencies' || requested === 'capabilities' || requested === 'licenses') {
      el.lens.value = requested;
      return;
    }
  } catch (_) {
    // ignore
  }
  // Default: show common capabilities first.
  el.lens.value = 'capabilities';
}


  function updateLensUi() {
    const lens = currentLens();
    if (el.limitItemsLabel) {
      el.limitItemsLabel.textContent = lens === 'dependencies'
        ? 'Max dependencies'
        : (lens === 'capabilities' ? 'Max capabilities' : 'Max licenses');
    }
    if (el.chartTitle) {
      el.chartTitle.textContent = lens === 'dependencies'
        ? 'Common dependencies'
        : (lens === 'capabilities' ? 'Common capabilities' : 'Common licenses');
    }
  }

  function buildQuery() {
    const params = new URLSearchParams();
    params.set('lens', currentLens());
    params.set('latest_only', el.latestOnly?.checked ? 'true' : 'false');
    params.set('limit_projects', String(Number(el.limitProjects?.value || 30) || 30));
    params.set('limit_items', String(Number(el.limitDeps?.value || 80) || 80));
    params.set('min_usage', String(Number(el.minUsage?.value || 2) || 2));
    return params;
  }

  async function load() {
    if (!apiFetch) {
      clear('App is not initialised');
      return;
    }

    clear('Loading…');
    updateLensUi();
    const params = buildQuery();
    const res = await apiFetch(`/v1/visualisations/bipartite?${params.toString()}`);
    state.data = res;

    const nodeCount = Array.isArray(res?.nodes) ? res.nodes.length : 0;
    const linkCount = Array.isArray(res?.links) ? res.links.length : 0;
    if (el.meta) {
      const lens = currentLens();
      el.meta.textContent = `${nodeCount} nodes • ${linkCount} links • ${lens}`;
    }

    render();
  }

  function render() {
    const data = state.data;
    const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
    const links = Array.isArray(data?.links) ? data.links : [];

    if (!nodes.length || !links.length) {
      clear('No graph data yet. Add projects and run discovery/mapping so cross-project insights can be generated.');
      return;
    }

    const left = nodes.filter((n) => n.type === 'project_version');
    const right = nodes.filter((n) => n.type !== 'project_version');

    const lens = currentLens();
    const rightTitle = lens === 'dependencies' ? 'Dependency'
      : (lens === 'capabilities' ? 'Capability' : 'License');

    const { width } = dims();

    const rowH = 18;
    const height = Math.max(dims().height, Math.max(left.length, right.length) * rowH + 140);

    const margin = { top: 32, right: 24, bottom: 32, left: 24 };

    // Put project labels on the *left* of the project node so link bundles don't run through the label.
    // Estimate label width (px) from character count; this avoids expensive SVG text measurement.
    const maxLeftLabelLen = d3.max(left, (d) => String(d.label || '').length) || 10;
    const estLeftLabelPx = Math.min(520, Math.max(140, Math.round(maxLeftLabelLen * 7.2)));

    let leftX = margin.left + estLeftLabelPx + 18;
    const rightX = width - margin.right - 18;
    if (rightX - leftX < 260) {
      leftX = Math.max(margin.left + 18, rightX - 260);
    }

    el.graph.innerHTML = '';

    const svg = d3.select(el.graph)
      .append('svg')
      .attr('viewBox', [0, 0, width, height])
      .attr('width', '100%')
      .attr('height', height);

    const viewport = svg.append('g');

    const zoom = d3.zoom()
      .scaleExtent([0.2, 8])
      .on('zoom', (event) => viewport.attr('transform', event.transform));

    svg.call(zoom);

    state.svg = svg;
    state.viewport = viewport;
    state.zoom = zoom;

    const yLeft = d3.scalePoint()
      .domain(left.map((d) => d.id))
      .range([margin.top, height - margin.bottom])
      .padding(0.65);

    const yRight = d3.scalePoint()
      .domain(right.map((d) => d.id))
      .range([margin.top, height - margin.bottom])
      .padding(0.65);

    const nodeById = new Map(nodes.map((n) => [n.id, n]));
    const linkData = links
      .map((l) => ({
        source: nodeById.get(l.source),
        target: nodeById.get(l.target),
        weight: Number(l.weight || 1),
      }))
      .filter((l) => l.source && l.target);

    const linkPath = d3.linkHorizontal()
      .x((d) => d.x)
      .y((d) => d.y);

    const linkSel = viewport.append('g')
      .attr('fill', 'none')
      .attr('stroke', 'var(--bs-secondary-color)')
      .attr('stroke-opacity', 0.15)
      .attr('stroke-width', 1.1)
      .selectAll('path')
      .data(linkData)
      .join('path')
      .attr('d', (d) => linkPath({
        source: { x: leftX + 10, y: yLeft(d.source.id) },
        target: { x: rightX - 10, y: yRight(d.target.id) },
      }));

    linkSel
      .on('mouseenter', (event, d) => {
        showTooltip('Connection', `${d.source.label} → ${d.target.label}`, event.clientX, event.clientY);
        highlight(d.source.id, d.target.id);
      })
      .on('mousemove', (event, d) => {
        showTooltip('Connection', `${d.source.label} → ${d.target.label}`, event.clientX, event.clientY);
      })
      .on('mouseleave', () => {
        hideTooltip();
        resetHighlight();
      });

    // Left nodes (projects)
    const leftNodes = viewport.append('g')
      .selectAll('g')
      .data(left)
      .join('g')
      .attr('transform', (d) => `translate(${leftX},${yLeft(d.id)})`)
      .style('cursor', 'pointer');

    leftNodes.append('circle')
      .attr('r', 4)
      .attr('fill', 'var(--bs-primary)')
      .attr('opacity', 0.85);

    leftNodes.append('text')
      .attr('x', -10)
      .attr('dy', '0.32em')
      .attr('text-anchor', 'end')
      .style('font-size', '12px')
      .style('font-weight', 600)
      .text((d) => d.label);

    // Right nodes (items)
    const maxUsage = Math.max(1, ...right.map((d) => Number(d.usage_count || 0)));
    const rScale = d3.scaleSqrt().domain([1, maxUsage]).range([3.2, 7.5]);

    const rightNodes = viewport.append('g')
      .selectAll('g')
      .data(right)
      .join('g')
      .attr('transform', (d) => `translate(${rightX},${yRight(d.id)})`)
      .style('cursor', (d) => (lens === 'dependencies' && d?.dependency_version_id ? 'pointer' : 'default'));

    rightNodes.append('circle')
      .attr('r', (d) => rScale(Math.max(1, Number(d.usage_count || 1))))
      .attr('fill', 'var(--bs-body-color)')
      .attr('opacity', 0.75);

    rightNodes.append('text')
      .attr('x', -10)
      .attr('dy', '0.32em')
      .attr('text-anchor', 'end')
      .style('font-size', '12px')
      .style('font-weight', 450)
      .text((d) => d.label);

    rightNodes.append('text')
      .attr('x', -10)
      .attr('y', 14)
      .attr('text-anchor', 'end')
      .style('font-size', '10px')
      .attr('fill', 'var(--bs-secondary-color)')
      .text((d) => {
        const u = Number(d.usage_count || 0);
        const extra = (lens === 'dependencies' && d.ecosystem) ? ` • ${d.ecosystem}`
          : (lens === 'capabilities' && d.framework) ? ` • ${d.framework}`
            : '';
        return `${u} projects${extra}`;
      });

    const leftIndex = new Map();
    linkData.forEach((l) => {
      if (!leftIndex.has(l.source.id)) leftIndex.set(l.source.id, new Set());
      leftIndex.get(l.source.id).add(l.target.id);
    });

    const rightIndex = new Map();
    linkData.forEach((l) => {
      if (!rightIndex.has(l.target.id)) rightIndex.set(l.target.id, new Set());
      rightIndex.get(l.target.id).add(l.source.id);
    });

    function resetHighlight() {
      linkSel.attr('stroke-opacity', 0.15).attr('stroke-width', 1.1);
      leftNodes.selectAll('circle').attr('opacity', 0.85);
      rightNodes.selectAll('circle').attr('opacity', 0.75);
      leftNodes.selectAll('text').attr('opacity', 1);
      rightNodes.selectAll('text').attr('opacity', 1);
    }

    function highlight(leftId, rightId) {
      linkSel
        .attr('stroke-opacity', (d) => ((d.source.id === leftId && d.target.id === rightId) ? 0.85 : 0.06))
        .attr('stroke-width', (d) => ((d.source.id === leftId && d.target.id === rightId) ? 2.4 : 1.0));

      leftNodes.selectAll('circle').attr('opacity', (d) => (d.id === leftId ? 1 : 0.2));
      rightNodes.selectAll('circle').attr('opacity', (d) => (d.id === rightId ? 1 : 0.2));
      leftNodes.selectAll('text').attr('opacity', (d) => (d.id === leftId ? 1 : 0.35));
      rightNodes.selectAll('text').attr('opacity', (d) => (d.id === rightId ? 1 : 0.35));
    }

    function highlightProject(pid) {
      const connected = leftIndex.get(pid) || new Set();
      linkSel
        .attr('stroke-opacity', (d) => (d.source.id === pid ? 0.55 : 0.05))
        .attr('stroke-width', (d) => (d.source.id === pid ? 1.8 : 1.0));

      leftNodes.selectAll('circle').attr('opacity', (d) => (d.id === pid ? 1 : 0.22));
      leftNodes.selectAll('text').attr('opacity', (d) => (d.id === pid ? 1 : 0.35));
      rightNodes.selectAll('circle').attr('opacity', (d) => (connected.has(d.id) ? 1 : 0.2));
      rightNodes.selectAll('text').attr('opacity', (d) => (connected.has(d.id) ? 1 : 0.35));
    }

    function highlightItem(did) {
      const connected = rightIndex.get(did) || new Set();
      linkSel
        .attr('stroke-opacity', (d) => (d.target.id === did ? 0.55 : 0.05))
        .attr('stroke-width', (d) => (d.target.id === did ? 1.8 : 1.0));

      rightNodes.selectAll('circle').attr('opacity', (d) => (d.id === did ? 1 : 0.22));
      rightNodes.selectAll('text').attr('opacity', (d) => (d.id === did ? 1 : 0.35));
      leftNodes.selectAll('circle').attr('opacity', (d) => (connected.has(d.id) ? 1 : 0.2));
      leftNodes.selectAll('text').attr('opacity', (d) => (connected.has(d.id) ? 1 : 0.35));
    }

    leftNodes
      .on('mouseenter', (event, d) => {
        showTooltip('Project', d.label, event.clientX, event.clientY);
        highlightProject(d.id);
      })
      .on('mousemove', (event, d) => showTooltip('Project', d.label, event.clientX, event.clientY))
      .on('mouseleave', () => { hideTooltip(); resetHighlight(); })
      .on('click', (event, d) => {
        if (event?.defaultPrevented) return;
        if (d?.project_id) {
          window.location.href = `/project.html?id=${encodeURIComponent(String(d.project_id))}`;
        }
      });

    rightNodes
      .on('mouseenter', (event, d) => {
        const u = Number(d.usage_count || 0);
        const extra = (lens === 'dependencies' && d.ecosystem) ? ` • ${d.ecosystem}`
          : (lens === 'capabilities' && d.framework) ? ` • ${d.framework}`
            : '';
        const body = `${d.label}\n${u} projects${extra}`;
        showTooltip(rightTitle, body, event.clientX, event.clientY);
        highlightItem(d.id);
      })
      .on('mousemove', (event, d) => {
        const u = Number(d.usage_count || 0);
        const extra = (lens === 'dependencies' && d.ecosystem) ? ` • ${d.ecosystem}`
          : (lens === 'capabilities' && d.framework) ? ` • ${d.framework}`
            : '';
        const body = `${d.label}\n${u} projects${extra}`;
        showTooltip(rightTitle, body, event.clientX, event.clientY);
      })
      .on('mouseleave', () => { hideTooltip(); resetHighlight(); })
      .on('click', (event, d) => {
        if (event?.defaultPrevented) return;
        if (lens === 'dependencies' && d?.dependency_version_id) {
          window.location.href = `/dependencies.html?id=${encodeURIComponent(String(d.dependency_version_id))}`;
        }
        if (lens === 'capabilities' && d?.framework_node_id) {
          window.location.href = `/capability.html?id=${encodeURIComponent(String(d.framework_node_id))}`;
        }
      });

    // Initial fit
    const box = viewport.node()?.getBBox?.();
    if (box && box.width > 0 && box.height > 0) {
      const pad = 30;
      const scale = Math.min(6, Math.max(0.2, Math.min(
        (width - pad * 2) / box.width,
        (height - pad * 2) / box.height
      )));
      const tx = (width - box.width * scale) / 2 - box.x * scale;
      const ty = (height - box.height * scale) / 2 - box.y * scale;
      svg.call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    }
  }

  function wire() {
    el.exportGraphPdfBtn?.addEventListener('click', () => {
      const base = safeFilename(`visualisations_${currentLens()}_${new Date().toISOString().slice(0, 10)}`);
      exportContainer(el.graph, { filenameBase: base, format: 'pdf' }).catch((e) => toast?.(e?.message || 'Export failed', 'error'));
    });
    el.exportGraphJpegBtn?.addEventListener('click', () => {
      const base = safeFilename(`visualisations_${currentLens()}_${new Date().toISOString().slice(0, 10)}`);
      exportContainer(el.graph, { filenameBase: base, format: 'jpeg' }).catch((e) => toast?.(e?.message || 'Export failed', 'error'));
    });

    el.refreshBtn?.addEventListener('click', () => load().catch((e) => toast?.(e?.message || 'Failed to load', 'error')));
    el.applyBtn?.addEventListener('click', () => load().catch((e) => toast?.(e?.message || 'Failed to load', 'error')));

    el.lens?.addEventListener('change', () => {
      updateLensUi();
      load().catch((e) => toast?.(e?.message || 'Failed to load', 'error'));
    });

    window.addEventListener('resize', () => {
      if (state.data) render();
    });
  }

  async function init() {
    // Ensure user is authenticated; dependencies lens is admin-only.
    let me = null;
    try {
      me = initAuth ? await initAuth({ redirectOnFail: true }) : null;
    } catch (_) {
      return;
    }
    if (!me) return;

    const r = roleOf(me);
    if (el.lens && r !== 'admin') {
      // hide dependencies lens (backend restricts it).
      const opt = el.lens.querySelector('option[value="dependencies"]');
      if (opt) opt.remove();
      if (String(el.lens.value || '') === 'dependencies') {
        el.lens.value = 'capabilities';
      }
    }

    wire();
    applyInitialLensFromUrl();
    if (el.lens && r !== 'admin') {
      if (String(el.lens.value || '') === 'dependencies') el.lens.value = 'capabilities';
    }
    updateLensUi();
    try {
      await load();
    } catch (err) {
      console.error(err);
      toast?.(err?.message || 'Failed to load bipartite graph', 'error');
      clear(err?.message || 'Failed to load graph');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
