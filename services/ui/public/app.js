(() => {
  const state = {
    me: null,
    csrfToken: null,
    userPreferences: {
      node_colors: {},
      default_start_page: '/index.html',
    },
    userPreferencesLoaded: false,
    userPreferencesPromise: null,
    authInitPromise: null,
    frameworks: [],
    frameworksLoaded: false,
    frameworksPromise: null,
    activeFramework: null,
    frameworkNodesById: new Map(),
    frameworkTreesById: new Map(),
    questionBellInit: false,
    questionBellTimer: null,
    shortcuts: [],
    shortcutsLoaded: false,
    shortcutsPromise: null,
    shortcutsInit: false,
  };

  function getCookie(name) {
    const encoded = `${name}=`;
    const parts = document.cookie ? document.cookie.split(';') : [];
    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed.startsWith(encoded)) {
        return decodeURIComponent(trimmed.slice(encoded.length));
      }
    }
    return null;
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  async function parseError(response) {
    let message = `HTTP ${response.status}`;
    try {
      const data = await response.clone().json();
      if (typeof data?.detail === 'string') {
        message = data.detail;
      } else if (Array.isArray(data?.detail)) {
        message = data.detail.map((d) => d?.msg || JSON.stringify(d)).join('; ');
      } else if (data?.message) {
        message = String(data.message);
      }
    } catch (_) {
      try {
        const text = await response.clone().text();
        if (text) message = text;
      } catch (__) {
        // ignore
      }
    }

    const err = new Error(message);
    err.status = response.status;
    throw err;
  }

  async function apiRequest(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = {
      ...(options.headers || {}),
    };

    if (!headers.Accept) {
      headers.Accept = 'application/json';
    }

    const hasBody = options.body !== undefined && options.body !== null;
    if (hasBody && !(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    // Prefer the current cookie token over any cached value. This prevents
    // intermittent CSRF failures when the cookie value changes (e.g. multiple
    // tabs, re-login flows, etc.).
    const cookieCsrf = getCookie('ospmae_csrf');
    const csrfToken = cookieCsrf || state.csrfToken;
    if (csrfToken) state.csrfToken = csrfToken;
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }

    const response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: hasBody && headers['Content-Type'] === 'application/json' ? JSON.stringify(options.body) : options.body,
    });

    if (!response.ok && !options.allowErrorStatuses?.includes(response.status)) {
      await parseError(response);
    }

    const responseType = options.responseType || 'json';
    if (responseType === 'raw') return response;
    if (responseType === 'blob') return response.blob();
    if (responseType === 'text') return response.text();

    const text = await response.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch (_) {
      return text;
    }
  }

  function ensureToastContainer() {
    let container = document.getElementById('toastContainer');
    if (container) return container;

    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    container.style.zIndex = '1080';
    document.body.appendChild(container);
    return container;
  }

  function toast(message, level = 'info', opts = {}) {
    const txt = String(message ?? '').trim();
    if (!txt) return;

    const kind = (() => {
      const raw = String(level || 'info').toLowerCase();
      if (raw === 'success') return 'success';
      if (raw === 'warn' || raw === 'warning') return 'warning';
      if (raw === 'error' || raw === 'danger') return 'danger';
      if (raw === 'info') return 'info';
      return 'secondary';
    })();

    const container = ensureToastContainer();

    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${kind} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');

    const delay = Number.isFinite(opts?.delay)
      ? opts.delay
      : kind === 'danger'
        ? 5200
        : kind === 'warning'
          ? 4200
          : 2800;

    toastEl.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">${escapeHtml(txt)}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    `;

    container.appendChild(toastEl);

    try {
      const inst = bootstrap.Toast.getOrCreateInstance(toastEl, { delay, autohide: true });
      toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove(), { once: true });
      inst.show();
    } catch (err) {
      // Fallback if bootstrap isn't available for some reason.
      toastEl.classList.add('show');
      toastEl.style.display = 'block';
      window.setTimeout(() => toastEl.remove(), delay);
      console.warn('Bootstrap toast unavailable:', err);
    }
  }

  function updateWhoAmI() {
    const el = document.getElementById('whoami');
    if (!el) return;
    if (!state.me) {
      el.textContent = '';
      return;
    }
    const role = state.me.effective_role || state.me.role || 'viewer';
    el.textContent = `${state.me.username} (${role})`;
  }

  function getPreferredHomeHref() {
    if (!state.me) return '/index.html';
    return normalizeStartPage(state.userPreferences?.default_start_page);
  }

  function applyBrandHomeLink() {
    const brand = document.querySelector('.topbar .brand');
    if (!brand) return;

    let titleEl = brand.querySelector('[data-brand-title]');
    if (!titleEl) {
      titleEl = brand.firstElementChild;
    }
    if (!titleEl) return;

    const href = getPreferredHomeHref() || '/index.html';

    if (titleEl.tagName && titleEl.tagName.toLowerCase() === 'a') {
      titleEl.href = href;
      titleEl.classList.add('brand-home-link');
      if (!titleEl.getAttribute('aria-label')) {
        titleEl.setAttribute('aria-label', 'Go to home page');
      }
      return;
    }

    const link = document.createElement('a');
    link.href = href;
    link.className = 'brand-home-link';
    link.setAttribute('aria-label', 'Go to home page');
    link.textContent = titleEl.textContent || '';
    titleEl.replaceWith(link);
  }
  function applyNavPermissions() {
    const currentRole = role();
    const canMaintain = currentRole === 'admin' || currentRole === 'maintainer';
    const canManifests = currentRole === 'admin' || currentRole === 'architect' || currentRole === 'product_owner';
    const canFrameworks = currentRole === 'admin' || currentRole === 'framework_admin';
    const adminOnly = currentRole === 'admin';
    const canAnswer = currentRole === 'admin' || currentRole === 'maintainer' || currentRole === 'contributor';

    document.querySelectorAll('a[href="/project-manage.html"]').forEach((el) => {
      el.style.display = canMaintain ? '' : 'none';
    });

    document.querySelectorAll('a[href="/saved-manifests.html"]').forEach((el) => {
      el.style.display = canManifests ? '' : 'none';
    });

    document.querySelectorAll('a[href="/admin.html"]').forEach((el) => {
      el.style.display = adminOnly ? '' : 'none';
    });

    document.querySelectorAll('a[href="/framework-manage.html"]').forEach((el) => {
      el.style.display = canFrameworks ? '' : 'none';
    });

    const bell = document.getElementById('navQuestionsBell');
    if (bell) bell.style.display = canAnswer ? '' : 'none';
  }

  
  // ---------------------------------------------------------------------------
  // Shortcuts (saved views)
  // ---------------------------------------------------------------------------

  async function loadShortcuts(opts = {}) {
    const force = opts.force === true;
    if (!force && state.shortcutsPromise) return state.shortcutsPromise;

    state.shortcutsPromise = (async () => {
      try {
        const rows = await apiRequest('/v1/me/shortcuts', { allowErrorStatuses: [401] });
        if (!Array.isArray(rows)) {
          state.shortcuts = [];
          state.shortcutsLoaded = true;
          return state.shortcuts;
        }
        state.shortcuts = rows
          .map((r) => ({
            id: Number(r.id),
            name: String(r.name || '').trim(),
            url: String(r.url || '').trim(),
          }))
          .filter((r) => r.name && r.url);
        state.shortcutsLoaded = true;
        return state.shortcuts;
      } catch (_) {
        state.shortcuts = [];
        state.shortcutsLoaded = true;
        return state.shortcuts;
      } finally {
        state.shortcutsPromise = null;
      }
    })();

    return state.shortcutsPromise;
  }

  function _currentRelativeUrl() {
    const { pathname, search, hash } = window.location;
    return `${pathname || '/'}${search || ''}${hash || ''}`;
  }

  async function saveCurrentViewAsShortcut() {
    if (!state.me) return;
    const defaultName = document.title?.replace(/\s+\|\s+.*$/, '').trim() || 'Saved view';
    const name = prompt('Shortcut name', defaultName);
    if (!name) return;

    const url = _currentRelativeUrl();

    try {
      await apiRequest('/v1/me/shortcuts', {
        method: 'POST',
        body: { name, url },
      });
      toast('Shortcut saved.');
      await loadShortcuts({ force: true });
      renderShortcutsNav();
    } catch (err) {
      toast(err?.message || 'Failed to save shortcut', 'error');
    }
  }

  function initShortcutsNav() {
    if (state.shortcutsInit) return;
    const nav = document.querySelector('.topbar .nav');
    if (!nav) return;

    let select = document.getElementById('navShortcutsSelect');
    if (!select) {
      select = document.createElement('select');
      select.id = 'navShortcutsSelect';
      select.className = 'nav-shortcuts';
      select.style.display = 'none';
      select.innerHTML = '<option value="">Shortcuts…</option>';
      nav.insertBefore(select, nav.querySelector('a[href="/preferences.html"]') || nav.lastElementChild);
    }

    let saveBtn = document.getElementById('navShortcutsSaveBtn');
    if (!saveBtn) {
      saveBtn = document.createElement('button');
      saveBtn.id = 'navShortcutsSaveBtn';
      saveBtn.type = 'button';
      saveBtn.className = 'secondary nav-shortcuts-save';
      saveBtn.textContent = 'Save view';
      saveBtn.style.display = 'none';
      nav.insertBefore(saveBtn, nav.querySelector('a[href="/preferences.html"]') || nav.lastElementChild);
    }

    select.addEventListener('change', () => {
      const v = select.value || '';
      if (!v) return;
      window.location.href = v;
    });

    saveBtn.addEventListener('click', () => {
      saveCurrentViewAsShortcut();
    });

    state.shortcutsInit = true;
  }

  function renderShortcutsNav() {
    const select = document.getElementById('navShortcutsSelect');
    const saveBtn = document.getElementById('navShortcutsSaveBtn');
    if (!select || !saveBtn) return;

    if (!state.me) {
      select.style.display = 'none';
      saveBtn.style.display = 'none';
      return;
    }

    // Always show save button when authenticated.
    saveBtn.style.display = '';

    const items = Array.isArray(state.shortcuts) ? state.shortcuts : [];
    if (!items.length) {
      select.style.display = 'none';
      select.innerHTML = '<option value="">Shortcuts…</option>';
      return;
    }

    select.style.display = '';
    const current = _currentRelativeUrl();

    const opts = ['<option value="">Shortcuts…</option>'].concat(
      items.map((s) => {
        const selected = s.url === current ? ' selected' : '';
        return `<option value="${escapeHtml(s.url)}"${selected}>${escapeHtml(s.name)}</option>`;
      }),
    );

    select.innerHTML = opts.join('');
  }
function canAnswerQuestions() {
    const r = role();
    return r === 'admin' || r === 'maintainer' || r === 'contributor';
  }

  function _setQuestionBellCount(n) {
    const bell = document.getElementById('navQuestionsBell');
    const badge = document.getElementById('navQuestionsCount');
    if (!bell || !badge) return;

    const v = Number(n || 0);
    if (v > 0) {
      badge.style.display = '';
      badge.textContent = String(v);
      bell.classList.add('has-unread');
    } else {
      badge.style.display = 'none';
      badge.textContent = '';
      bell.classList.remove('has-unread');
    }
  }

  async function refreshQuestionBell() {
    if (!state.me) return;
    if (!canAnswerQuestions()) {
      _setQuestionBellCount(0);
      return;
    }

    try {
      const sum = await apiRequest('/v1/questions/unanswered/summary', { allowErrorStatuses: [403, 404] });
      const n = sum?.open_count ?? 0;
      _setQuestionBellCount(n);
    } catch (_) {
      // ignore
    }
  }

  function initQuestionBell() {
    const bell = document.getElementById('navQuestionsBell');
    const badge = document.getElementById('navQuestionsCount');
    if (!bell || !badge) return;

    if (!state.me || !canAnswerQuestions()) {
      bell.style.display = 'none';
      _setQuestionBellCount(0);
      return;
    }

    bell.style.display = '';

    // Only bind listeners once per page load.
    if (!state.questionBellInit) {
      state.questionBellInit = true;

      window.addEventListener('ospmae-notification', (ev) => {
        const msg = ev?.detail;
        if (!msg) return;
        if (msg.kind === 'project_question_created' || msg.kind === 'project_question_replied') {
          refreshQuestionBell();
        }
      });

      if (state.questionBellTimer) {
        clearInterval(state.questionBellTimer);
      }
      state.questionBellTimer = setInterval(() => refreshQuestionBell(), 30000);
    }

    refreshQuestionBell();
  }

  function wsBaseUrl() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}`;
  }

  function stopNotifications() {
    if (state.ws) {
      try { state.ws.close(); } catch (_) {}
    }
    state.ws = null;
  }

  function startNotifications() {
    if (!state.me || isPendingUser()) return;
    if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const url = `${wsBaseUrl()}/ws/notifications`;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (_) {
      return;
    }
    state.ws = ws;

    ws.addEventListener('message', (ev) => {
      let msg = null;
      try { msg = JSON.parse(ev.data); } catch (_) { return; }
      if (!msg) return;

      window.dispatchEvent(new CustomEvent('ospmae-notification', { detail: msg }));

      // Default toast for question activity.
      if (msg.kind === 'project_question_created') {
        toast(`New question on ${msg.project_display_name || 'a project'}`, 'info');
      } else if (msg.kind === 'project_question_replied') {
        toast(`New reply on ${msg.project_display_name || 'a project'}`, 'info');
      }
    });

    ws.addEventListener('close', () => {
      state.ws = null;
      // Best-effort reconnect while logged in.
      if (state.me) {
        setTimeout(() => startNotifications(), 2000);
      }
    });

    ws.addEventListener('error', () => {
      // socket errors are surfaced via close; no-op here
    });
  }


  function role() {
    return (state.me?.effective_role || state.me?.role || 'viewer').toLowerCase();
  }

  function isPendingUser() {
    return role() === 'pending';
  }

  // Default palette keyed by '<framework_machine_name>:<node_key>'
  // (Only UWRA is pre-seeded here; other frameworks fall back to a deterministic hash colour.)
  const DEFAULT_NODE_COLORS = {
    // Channel Tier umbrella + major capability groups
    'uwra:channel_tier': '#5b8def',
    'uwra:admin_ui': '#4f83ff',
    'uwra:transactional_ui': '#6366f1',
    'uwra:sdk_and_api': '#22c55e',
    'uwra:agents': '#06b6d4',
    'uwra:wallet_services': '#f59e0b',
    'uwra:secure_storage': '#8b5cf6',
    'uwra:network_services': '#14b8a6',
    'uwra:p2p_services': '#ef4444',

    // Platform/Infrastructure tier groups
    'uwra:security_services': '#7c3aed',
    'uwra:devops_services': '#0ea5a4',
    'uwra:external_integration_services': '#f59e0b',
    'uwra:platform_infrastructure_services': '#64748b',

    // Root fallback
    'uwra:technology_capabilities': '#475569',
  };

  // Start page choices shown in Preferences.
  // `permission` is used client-side only to filter options by role.
  const ALLOWED_START_PAGES = [
    { value: '/index.html', label: 'Find projects', permission: 'public' },
    { value: '/saved-manifests.html', label: 'Saved manifests', permission: 'manifests' },
    { value: '/project-manage.html', label: 'Manage projects', permission: 'project_admin' },
    { value: '/framework-manage.html', label: 'Framework administration', permission: 'framework_admin' },
    { value: '/account.html', label: 'Account', permission: 'public' },
    { value: '/pending.html', label: 'Pending approval', permission: 'pending' },
    { value: '/admin.html', label: 'Admin', permission: 'admin' },
  ];

  const DEFAULT_START_PAGE = '/index.html';

  function normalizeHexColor(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    const v = raw.startsWith('#') ? raw : `#${raw}`;
    return /^#[0-9a-fA-F]{6}$/.test(v) ? v.toLowerCase() : null;
  }

  function normalizeStartPage(value) {
    const raw = String(value || '').trim();
    if (!raw) return DEFAULT_START_PAGE;
    const v = raw.startsWith('/') ? raw : `/${raw}`;
    if (v === '/pending.html') return isPendingUser() ? v : DEFAULT_START_PAGE;
    const allowed = (ALLOWED_START_PAGES || [])
      .filter((p) => p?.permission !== 'pending')
      .some((p) => p?.value === v);
    return allowed ? v : DEFAULT_START_PAGE;
  }

  function normalizeNodeColorMap(raw) {
    if (!raw || typeof raw !== 'object') return {};
    const out = {};
    Object.entries(raw).forEach(([key, color]) => {
      const k = String(key || '').trim();
      const c = normalizeHexColor(color);
      if (!k || !c) return;
      out[k] = c;
    });
    return out;
  }

  function normalizeUserPreferences(raw) {
    // Backwards-compatible: capability_colors from older UI is mapped to uwra:<key>
    const legacy = raw?.capability_colors && typeof raw.capability_colors === 'object'
      ? Object.fromEntries(Object.entries(raw.capability_colors).map(([k, v]) => [`uwra:${k}`, v]))
      : {};

    return {
      node_colors: {
        ...normalizeNodeColorMap(legacy),
        ...normalizeNodeColorMap(raw?.node_colors),
      },
      default_start_page: normalizeStartPage(raw?.default_start_page),
      sticky_enabled: typeof raw?.sticky_enabled === 'boolean' ? raw.sticky_enabled : false,
      auto_apply_enabled: typeof raw?.auto_apply_enabled === 'boolean' ? raw.auto_apply_enabled : true,
    };
  }

  function applyStickyPreference(stickyEnabled) {
    const enabled = stickyEnabled !== false;
    document.body.classList.toggle('keen-sticky-disabled', !enabled);
  }

  function applyUiBehaviourPreferences(prefs) {
    applyStickyPreference(prefs?.sticky_enabled);

    // Broadcast (page-local) events so long-lived pages can react.
    document.dispatchEvent(
      new CustomEvent('mosp:auto-apply-changed', { detail: { enabled: prefs?.auto_apply_enabled !== false } }),
    );
    document.dispatchEvent(
      new CustomEvent('mosp:sticky-changed', { detail: { enabled: prefs?.sticky_enabled !== false } }),
    );
  }

  async function loadUserPreferences(options = {}) {
    const force = options.force === true;

    if (!state.me || isPendingUser()) {
      state.userPreferences = normalizeUserPreferences(
        isPendingUser() ? { default_start_page: '/pending.html' } : null,
      );
      applyUiBehaviourPreferences(state.userPreferences);
      state.userPreferencesLoaded = false;
      state.userPreferencesPromise = null;
      return state.userPreferences;
    }

    if (!force && state.userPreferencesLoaded) {
      return state.userPreferences;
    }

    if (!force && state.userPreferencesPromise) {
      return state.userPreferencesPromise;
    }

    state.userPreferencesPromise = (async () => {
      try {
        const pref = await apiRequest('/v1/me/preferences', { allowErrorStatuses: [404] });
        state.userPreferences = normalizeUserPreferences(pref || null);
      } catch (_) {
        state.userPreferences = normalizeUserPreferences(null);
      } finally {
        applyUiBehaviourPreferences(state.userPreferences);
        state.userPreferencesLoaded = true;
      }
      return state.userPreferences;
    })();

    try {
      return await state.userPreferencesPromise;
    } finally {
      state.userPreferencesPromise = null;
    }
  }

  async function saveUserPreferences(update) {
    if (!state.me) throw new Error('Not authenticated');

    const payload = {};
    if (update && Object.prototype.hasOwnProperty.call(update, 'node_colors')) {
      payload.node_colors = normalizeNodeColorMap(update.node_colors);
    }
    if (update && Object.prototype.hasOwnProperty.call(update, 'default_start_page')) {
      payload.default_start_page = normalizeStartPage(update.default_start_page);
    }
    if (update && Object.prototype.hasOwnProperty.call(update, 'sticky_enabled')) {
      payload.sticky_enabled = Boolean(update.sticky_enabled);
    }
    if (update && Object.prototype.hasOwnProperty.call(update, 'auto_apply_enabled')) {
      payload.auto_apply_enabled = Boolean(update.auto_apply_enabled);
    }

    const saved = await apiRequest('/v1/me/preferences', {
      method: 'PUT',
      body: payload,
    });

    state.userPreferences = normalizeUserPreferences(saved || payload || null);
    state.userPreferencesLoaded = true;
    applyUiBehaviourPreferences(state.userPreferences);
    applyBrandHomeLink();

    initShortcutsNav();
    return state.userPreferences;
  }

  function getUserPreferences() {
    return {
      node_colors: { ...(state.userPreferences?.node_colors || {}) },
      default_start_page: normalizeStartPage(state.userPreferences?.default_start_page),
      sticky_enabled: state.userPreferences?.sticky_enabled !== false,
      auto_apply_enabled: state.userPreferences?.auto_apply_enabled !== false,
    };
  }

  function _hashString(value) {
    const str = String(value || '');
    let h = 2166136261;
    for (let i = 0; i < str.length; i += 1) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  function _hslToHex(h, s, l) {
    const sat = s / 100;
    const lit = l / 100;
    const c = (1 - Math.abs(2 * lit - 1)) * sat;
    const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
    const m = lit - c / 2;

    let r = 0;
    let g = 0;
    let b = 0;
    if (h >= 0 && h < 60) {
      r = c;
      g = x;
    } else if (h >= 60 && h < 120) {
      r = x;
      g = c;
    } else if (h >= 120 && h < 180) {
      g = c;
      b = x;
    } else if (h >= 180 && h < 240) {
      g = x;
      b = c;
    } else if (h >= 240 && h < 300) {
      r = x;
      b = c;
    } else {
      r = c;
      b = x;
    }

    const toHex = (v) => {
      const n = Math.round((v + m) * 255);
      return n.toString(16).padStart(2, '0');
    };

    return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
  }

  function _defaultColorForKey(fullKey) {
    if (DEFAULT_NODE_COLORS[fullKey]) return DEFAULT_NODE_COLORS[fullKey];
    const h = _hashString(fullKey) % 360;
    return _hslToHex(h, 62, 52);
  }

  function getNodeColorOverrides() {
    return { ...(state.userPreferences?.node_colors || {}) };
  }

  function getNodeColors() {
    return {
      ...DEFAULT_NODE_COLORS,
      ...getNodeColorOverrides(),
    };
  }

  function setNodeColor(fullKey, color) {
    if (!fullKey) return false;
    const normalized = normalizeHexColor(color);
    if (!normalized) return false;
    const current = { ...(state.userPreferences?.node_colors || {}) };
    current[fullKey] = normalized;
    state.userPreferences = {
      ...state.userPreferences,
      node_colors: current,
    };
    return true;
  }

  function clearNodeColor(fullKey) {
    const current = { ...(state.userPreferences?.node_colors || {}) };
    delete current[fullKey];
    state.userPreferences = {
      ...state.userPreferences,
      node_colors: current,
    };
  }

  function resetNodeColors() {
    state.userPreferences = {
      ...state.userPreferences,
      node_colors: {},
    };
  }

  function nodeColor(fullKey) {
    const overrides = getNodeColorOverrides();
    if (overrides[fullKey]) return overrides[fullKey];
    return _defaultColorForKey(fullKey);
  }

  // Legacy aliases (for older pages; safe to remove later).
  function getCapabilityColorOverrides() {
    const out = {};
    const nodeOverrides = getNodeColorOverrides();
    Object.entries(nodeOverrides).forEach(([k, v]) => {
      if (String(k).startsWith('uwra:')) out[k.slice(5)] = v;
    });
    return out;
  }

  function getCapabilityColors() {
    const out = {};
    Object.entries(DEFAULT_NODE_COLORS).forEach(([k, v]) => {
      if (String(k).startsWith('uwra:')) out[k.slice(5)] = v;
    });
    return {
      ...out,
      ...getCapabilityColorOverrides(),
    };
  }

  function capabilityColor(rootKey) {
    return nodeColor(`uwra:${rootKey || 'technology_capabilities'}`);
  }

  function _legacyFrameworkStorageKey() {
    return 'ospmae_active_framework_machine';
  }

  function _mospFrameworkStorageKey() {
    try {
      return window.mospUiConfig?.storage?.frameworkKey || null;
    } catch {
      return null;
    }
  }

  function _frameworkQueryParam() {
    try {
      return window.mospUiConfig?.framework?.queryParam || 'framework';
    } catch {
      return 'framework';
    }
  }

  function _getStoredFrameworkMachine() {
    try {
      const mospKey = _mospFrameworkStorageKey();
      const storedMosp = mospKey ? String(window.localStorage.getItem(mospKey) || '').trim() : '';
      if (storedMosp) return storedMosp;
      return String(window.localStorage.getItem(_legacyFrameworkStorageKey()) || '').trim() || null;
    } catch {
      return null;
    }
  }

  function _getFrameworkMachineFromUrl() {
    try {
      const params = new URLSearchParams(window.location.search || '');
      const raw = String(params.get(_frameworkQueryParam()) || '').trim();
      return raw || null;
    } catch {
      return null;
    }
  }

  function _setStoredFrameworkMachine(machine) {
    const val = String(machine || '').trim();
    try {
      window.localStorage.setItem(_legacyFrameworkStorageKey(), val);
    } catch {
      // ignore
    }
    try {
      const mospKey = _mospFrameworkStorageKey();
      if (mospKey) window.localStorage.setItem(mospKey, val);
    } catch {
      // ignore
    }
  }


  function getFrameworks() {
    return Array.isArray(state.frameworks) ? [...state.frameworks] : [];
  }

  function getActiveFramework() {
    return state.activeFramework ? { ...state.activeFramework } : null;
  }

  function setActiveFrameworkByMachineName(machineName) {
    const machine = String(machineName || '').trim();
    if (!machine) return null;
    const fw = (state.frameworks || []).find((f) => f.machine_name === machine) || null;
    if (!fw) return null;
    state.activeFramework = fw;
    _setStoredFrameworkMachine(fw.machine_name);
    return fw;
  }

  async function loadFrameworks(options = {}) {
    const force = options.force === true;

    if (!state.me) {
      state.frameworks = [];
      state.frameworksLoaded = false;
      state.frameworksPromise = null;
      state.activeFramework = null;
      return [];
    }

    if (!force && state.frameworksLoaded) return getFrameworks();
    if (!force && state.frameworksPromise) return state.frameworksPromise;

    state.frameworksPromise = (async () => {
      const data = await apiRequest('/v1/frameworks');
      state.frameworks = Array.isArray(data?.items) ? data.items : [];
      state.frameworksLoaded = true;

      const requested = _getFrameworkMachineFromUrl();
      const stored = _getStoredFrameworkMachine();
      const preferUwra = state.frameworks.find((f) => f.machine_name === 'uwra');

      const selected = (requested && state.frameworks.find((f) => f.machine_name === requested))
        || (stored && state.frameworks.find((f) => f.machine_name === stored))
        || preferUwra
        || state.frameworks[0]
        || null;

      state.activeFramework = selected || null;
      if (selected) _setStoredFrameworkMachine(selected.machine_name);
      return getFrameworks();
    })();

    try {
      return await state.frameworksPromise;
    } finally {
      state.frameworksPromise = null;
    }
  }

  async function loadActiveFramework(options = {}) {
    await loadFrameworks(options);
    return getActiveFramework();
  }

  async function loadFrameworkNodes(frameworkId, options = {}) {
    const fwId = Number(frameworkId);
    if (!fwId || Number.isNaN(fwId)) throw new Error('frameworkId is required');

    const force = options.force === true;
    if (force) {
      state.frameworkTreesById.delete(fwId);
      state.frameworkNodesById.delete(fwId);
    }

    if (state.frameworkTreesById.has(fwId) && state.frameworkNodesById.has(fwId)) {
      return {
        tree: state.frameworkTreesById.get(fwId),
        flat: state.frameworkNodesById.get(fwId),
      };
    }

    const data = await apiRequest(`/v1/frameworks/${fwId}/nodes`);
    const tree = Array.isArray(data?.tree) ? data.tree : [];
    const flat = Array.isArray(data?.items) ? data.items : [];
    state.frameworkTreesById.set(fwId, tree);
    state.frameworkNodesById.set(fwId, flat);
    return { tree, flat };
  }

  function getDefaultStartPage() {
    return normalizeStartPage(state.userPreferences?.default_start_page);
  }

  function maybeRedirectToPreferredStart() {
    if (!state.me) return false;
    if (isPendingUser()) {
      if (location.pathname !== '/pending.html') {
        window.location.replace('/pending.html');
        return true;
      }
      return false;
    }
    if (location.pathname === '/pending.html') {
      window.location.replace('/index.html');
      return true;
    }
    if (location.pathname !== '/') return false;
    const preferred = getDefaultStartPage();
    if (preferred && preferred !== '/index.html') {
      window.location.replace(preferred);
      return true;
    }
    return false;
  }

  async function initAuth(opts = {}) {
    const redirectOnFail = opts.redirectOnFail !== false;
    const force = opts.force === true;

    if (!force && state.authInitPromise) {
      return state.authInitPromise;
    }

    state.authInitPromise = (async () => {
      try {
        const me = await apiRequest('/v1/me', { allowErrorStatuses: [401] });
        if (!me || me.detail) {
          state.me = null;
          state.csrfToken = null;
          state.userPreferences = normalizeUserPreferences(null);
          state.userPreferencesLoaded = false;
          state.userPreferencesPromise = null;
          if (redirectOnFail) {
            window.location.href = '/login.html';
          }
          return null;
        }

        state.me = me;
        state.csrfToken = me.csrf_token || getCookie('ospmae_csrf');

        if (isPendingUser()) {
          state.userPreferences = normalizeUserPreferences({ default_start_page: '/pending.html' });
          updateWhoAmI();
          applyNavPermissions();
          applyBrandHomeLink();
          const redirected = maybeRedirectToPreferredStart();
          return redirected ? null : me;
        }

        await loadUserPreferences();
        updateWhoAmI();
        applyNavPermissions();
        applyBrandHomeLink();

    initShortcutsNav();
        startNotifications();
        initQuestionBell();
        initShortcutsNav();
        await loadShortcuts({ force: true });
        renderShortcutsNav();

        const redirected = maybeRedirectToPreferredStart();
        if (redirected) {
          return null;
        }

        return me;
      } catch (err) {
        state.me = null;
        state.csrfToken = null;
        state.userPreferences = normalizeUserPreferences(null);
        state.userPreferencesLoaded = false;
        state.userPreferencesPromise = null;
        if (redirectOnFail) {
          window.location.href = '/login.html';
        }
        return null;
      } finally {
        state.authInitPromise = null;
      }
    })();

    return state.authInitPromise;
  }

  async function logout() {
    // Prefer a full-page navigation so the browser reliably applies cookie
    // clears + any redirect to an IdP end-session endpoint.
    stopNotifications();
    state.me = null;
    state.csrfToken = null;
    state.userPreferences = normalizeUserPreferences(null);
    state.userPreferencesLoaded = false;
    state.userPreferencesPromise = null;
    state.frameworks = [];
    state.frameworksLoaded = false;
    state.frameworksPromise = null;
    state.activeFramework = null;
    state.frameworkNodesById = new Map();
    state.frameworkTreesById = new Map();
    state.shortcuts = [];
    state.shortcutsLoaded = false;
    state.shortcutsPromise = null;
    renderShortcutsNav();
    window.location.href = '/v1/auth/logout';
  }

  async function ensureInitialized() {
    if (!state.me) {
      await initAuth({ redirectOnFail: true });
    }
    return state.me;
  }

  function isAdmin() {
    return role() === 'admin';
  }

  function canMaintainProjects() {
    const r = role();
    return r === 'admin' || r === 'maintainer';
  }

  function canExportManifests() {
    const r = role();
    return r === 'admin' || r === 'architect' || r === 'product_owner';
  }

  function downloadResponseAsFile(response, fallbackName = 'download.bin') {
    const disposition = response.headers.get('content-disposition') || '';
    let filename = fallbackName;
    const match = disposition.match(/filename="?([^";]+)"?/i);
    if (match && match[1]) filename = match[1];

    return response.blob().then((blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });
  }

  function _changelogValueHtml(value) {
    if (value === null || value === undefined || value === '') return '<span class="text-muted">—</span>';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (typeof value === 'number') return escapeHtml(value);
    if (Array.isArray(value) || typeof value === 'object') {
      const text = JSON.stringify(value, null, 2);
      return `<pre class="small bg-light border rounded p-2 mb-0 changelog-json">${escapeHtml(text)}</pre>`;
    }
    return escapeHtml(value);
  }

  function entityChangelogHtml(items = [], { empty = 'No changelog entries yet.' } = {}) {
    if (!Array.isArray(items) || !items.length) {
      return `<div class="small text-muted">${escapeHtml(empty)}</div>`;
    }
    return items.map((item) => {
      const changes = Array.isArray(item.changes) ? item.changes : [];
      const changeTable = changes.length
        ? `<div class="table-responsive mt-2"><table class="table table-sm align-middle mb-0 changelog-diff-table"><thead><tr><th style="width:180px;">Field</th><th>Before</th><th>After</th></tr></thead><tbody>${changes.map((c) => `<tr><td class="fw-semibold">${escapeHtml(c?.label || c?.field || '')}</td><td>${_changelogValueHtml(c?.before)}</td><td>${_changelogValueHtml(c?.after)}</td></tr>`).join('')}</tbody></table></div>`
        : '';
      const actor = item.changed_by_username || 'system';
      const when = item.changed_at ? new Date(item.changed_at).toLocaleString() : '—';
      const title = item.entity_title || item.entity_ref || `${item.entity_type || 'entity'} #${item.entity_id || ''}`;
      return `
        <div class="card mb-2">
          <div class="card-body p-3">
            <div class="d-flex justify-content-between gap-3 flex-wrap">
              <div>
                <div class="fw-semibold">${escapeHtml(item.summary || item.action || 'Change')}</div>
                <div class="small text-muted">${escapeHtml(title)} · ${escapeHtml(item.entity_type || '')} · ${escapeHtml(actor)}</div>
              </div>
              <div class="small text-muted text-end">${escapeHtml(when)}</div>
            </div>
            ${changeTable}
          </div>
        </div>
      `;
    }).join('');
  }

  async function loadEntityChangelog(container, url, { empty = 'No changelog entries yet.', loading = 'Loading changelog…' } = {}) {
    if (!container) return null;
    container.innerHTML = `<div class="small text-muted">${escapeHtml(loading)}</div>`;
    const data = await apiRequest(url);
    const items = Array.isArray(data?.items) ? data.items : [];
    container.innerHTML = entityChangelogHtml(items, { empty });
    return data;
  }

  document.addEventListener('DOMContentLoaded', () => {
    applyBrandHomeLink();

    initShortcutsNav();

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        logout();
      });
    }
  });

  window.escapeHtml = escapeHtml;
  window.parseError = parseError;
  window.apiRequest = apiRequest;

  window.OSPMAE = {
    state,
    api: apiRequest,
    initAuth,
    ensureInitialized,
    logout,
    startNotifications,
    stopNotifications,
    toast,
    escapeHtml,
    isAdmin,
    canMaintainProjects,
    canExportManifests,
    canAnswerQuestions,
    refreshQuestionBell,
    downloadResponseAsFile,
    entityChangelogHtml,
    loadEntityChangelog,
    role,
    isPendingUser,
    DEFAULT_NODE_COLORS,
    ALLOWED_START_PAGES,
    DEFAULT_START_PAGE,
    loadFrameworks,
    getFrameworks,
    getActiveFramework,
    setActiveFrameworkByMachineName,
    loadActiveFramework,
    loadFrameworkNodes,
    getCapabilityColors,
    getCapabilityColorOverrides,
    capabilityColor,
    getNodeColors,
    getNodeColorOverrides,
    setNodeColor,
    clearNodeColor,
    resetNodeColors,
    nodeColor,
    normalizeHexColor,
    normalizeStartPage,
    loadUserPreferences,
    saveUserPreferences,
    getUserPreferences,
    getStickyEnabled: () => state.userPreferences?.sticky_enabled !== false,
    getAutoApplyEnabled: () => state.userPreferences?.auto_apply_enabled !== false,
    getDefaultStartPage,
    applyBrandHomeLink,
    loadShortcuts,
    renderShortcutsNav,
    saveCurrentViewAsShortcut,
  };
})();
