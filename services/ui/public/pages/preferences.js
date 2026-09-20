(() => {
  const OSPMAE = window.OSPMAE;
  const {
    initAuth,
    loadFrameworks,
    getFrameworks,
    getActiveFramework,
    setActiveFrameworkByMachineName,
    loadFrameworkNodes,
    getUserPreferences,
    saveUserPreferences,
    nodeColor,
    getNodeColorOverrides,
    DEFAULT_NODE_COLORS,
    ALLOWED_START_PAGES,
    canMaintainProjects,
    canExportManifests,
  } = OSPMAE;

  const state = {
    me: null,
    frameworks: [],
    activeFramework: null,
    paletteNodes: [],
    overrides: {},
    prefs: {},
  };

  const el = {
    whoami: document.getElementById('whoami'),
    frameworkSelect: document.getElementById('frameworkSelect'),
    defaultStartPage: document.getElementById('defaultStartPage'),
    colorRows: document.getElementById('colorRows'),
    saveColorsBtn: document.getElementById('saveColorsBtn'),
    resetColorsBtn: document.getElementById('resetColorsBtn'),
  };

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function roleOf(me) {
    return me?.effective_role || me?.role || 'viewer';
  }

  function canMaintainFrameworks(me) {
    const role = roleOf(me);
    return role === 'admin' || role === 'framework_admin';
  }

  function buildStartPageOptions(me) {
    const role = roleOf(me);
    const opts = [];
    for (const page of (ALLOWED_START_PAGES || [])) {
      if (page.permission === 'public') {
        opts.push(page);
        continue;
      }
      if (page.permission === 'manifests') {
        if (canExportManifests()) opts.push(page);
        continue;
      }
      if (page.permission === 'project_admin') {
        if (canMaintainProjects()) opts.push(page);
        continue;
      }
      if (page.permission === 'framework_admin') {
        if (canMaintainFrameworks(me)) opts.push(page);
        continue;
      }
      if (page.permission === 'admin') {
        if (role === 'admin') opts.push(page);
      }
    }
    return opts;
  }

  function renderStartPageSelect() {
    if (!el.defaultStartPage) return;
    const options = buildStartPageOptions(state.me);
    el.defaultStartPage.innerHTML = options
      .map((p) => `<option value="${escapeHtml(p.value)}">${escapeHtml(p.label)}</option>`)
      .join('');

    const current = state.prefs?.default_start_page || '';
    if (current && options.some((o) => o.value === current)) {
      el.defaultStartPage.value = current;
    } else {
      el.defaultStartPage.value = options[0]?.value || '/index.html';
    }
  }

  function renderFrameworkSelect() {
    if (!el.frameworkSelect) return;
    el.frameworkSelect.innerHTML = state.frameworks
      .map((f) => `<option value="${escapeHtml(f.machine_name)}">${escapeHtml(f.display_name || f.machine_name)}</option>`)
      .join('');
    if (state.activeFramework?.machine_name) {
      el.frameworkSelect.value = state.activeFramework.machine_name;
    }
  }

  function computePaletteNodes(flat) {
    const items = (flat || []).map((n) => ({
      id: Number(n.id),
      key: n.key,
      display_name: n.display_name,
      parent_id: n.parent_id,
      level: n.level,
      description: n.description,
    }));

    // Generic: only expose the top-level nodes (level 1) for per-framework palette overrides.
    // This keeps colour preferences independent of any specific framework taxonomy.
    return items
      .filter((n) => n.level === 1)
      .sort((a, b) => (a.display_name || '').localeCompare(b.display_name || ''));
  }

  function fullKeyFor(node) {
    const fw = state.activeFramework;
    const prefix = fw?.machine_name ? `${fw.machine_name}:` : '';
    return `${prefix}${node.key}`;
  }

  function renderColorRows() {
    if (!el.colorRows) return;

    if (!state.activeFramework) {
      el.colorRows.innerHTML = '<div class="muted">No frameworks available.</div>';
      return;
    }

    if (!state.paletteNodes.length) {
      el.colorRows.innerHTML = '<div class="muted">No categories found for this framework.</div>';
      return;
    }

    const overrides = state.overrides || {};

    el.colorRows.innerHTML = state.paletteNodes
      .map((node) => {
        const fullKey = fullKeyFor(node);
        const effective = nodeColor(fullKey);
        const explicit = overrides[fullKey];
        const defaultColor = DEFAULT_NODE_COLORS?.[fullKey] || effective;

        return `
          <div class="pref-row" data-full-key="${escapeHtml(fullKey)}">
            <div class="pref-row-main">
              <div class="pref-row-title">${escapeHtml(node.display_name || node.key)}</div>
              <div class="small muted">Key: <code>${escapeHtml(fullKey)}</code></div>
            </div>
            <div class="pref-row-actions">
              <input type="color" value="${escapeHtml((explicit || effective) || '#64748b')}" data-color-input="1" aria-label="Colour for ${escapeHtml(node.display_name || node.key)}" />
              <button type="button" class="button" data-action="reset" title="Reset this colour">Reset</button>
              <span class="small muted" title="Default: ${escapeHtml(defaultColor)}">${explicit ? 'custom' : 'default'}</span>
            </div>
          </div>
        `;
      })
      .join('');

    el.colorRows.querySelectorAll('input[data-color-input]').forEach((input) => {
      input.addEventListener('input', () => {
        const row = input.closest('.pref-row');
        const fullKey = row?.dataset?.fullKey;
        if (!fullKey) return;
        state.overrides[fullKey] = input.value;
      });
    });

    el.colorRows.querySelectorAll('button[data-action="reset"]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const row = btn.closest('.pref-row');
        const fullKey = row?.dataset?.fullKey;
        if (!fullKey) return;
        delete state.overrides[fullKey];
        renderColorRows();
      });
    });
  }

  async function refreshPaletteForFramework() {
    const fw = state.activeFramework;
    if (!fw?.id) {
      state.paletteNodes = [];
      renderColorRows();
      return;
    }

    const { flat } = await loadFrameworkNodes(fw.id);
    state.paletteNodes = computePaletteNodes(flat);
    renderColorRows();
  }

  async function savePreferences() {
    const payload = {
      ...state.prefs,
      default_start_page: el.defaultStartPage?.value || state.prefs?.default_start_page || '/index.html',
      node_colors: state.overrides,
    };
    const saved = await saveUserPreferences(payload);
    state.prefs = saved;
    OSPMAE.toast('Preferences saved.');
  }

  async function resetColors() {
    if (!confirm('Reset all custom colours?')) return;
    state.overrides = {};
    renderColorRows();
    await savePreferences();
  }

  function wireEvents() {
    el.frameworkSelect?.addEventListener('change', async () => {
      const machine = el.frameworkSelect.value;
      state.activeFramework = setActiveFrameworkByMachineName(machine);
      await refreshPaletteForFramework();
    });

    el.saveColorsBtn?.addEventListener('click', () => {
      savePreferences().catch((err) => OSPMAE.toast(err.message || 'Failed to save preferences', 'error'));
    });

    el.resetColorsBtn?.addEventListener('click', () => {
      resetColors().catch((err) => OSPMAE.toast(err.message || 'Failed to reset colours', 'error'));
    });
  }

  async function init() {
    state.me = await initAuth({ redirectOnFail: true });
    if (!state.me) return;

    if (el.whoami) {
      const role = roleOf(state.me);
      el.whoami.textContent = state.me?.username ? `${state.me.username} (${role})` : role;
    }

    state.prefs = getUserPreferences() || {};
    state.overrides = { ...(getNodeColorOverrides() || {}) };

    await loadFrameworks();
    state.frameworks = getFrameworks();
    state.activeFramework = getActiveFramework();

    renderFrameworkSelect();
    renderStartPageSelect();
    wireEvents();

    await refreshPaletteForFramework();
  }

  document.addEventListener('DOMContentLoaded', () => {
    init().catch((err) => {
      console.error(err);
      OSPMAE.toast(err.message || 'Failed to load preferences', 'error');
    });
  });
})();
