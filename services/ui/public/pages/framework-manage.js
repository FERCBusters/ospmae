(() => {
  const OSPMAE = window.OSPMAE;
  const {
    api: apiFetch,
    initAuth,
    loadFrameworks,
    getFrameworks,
    loadFrameworkNodes,
    toast,
  } = OSPMAE;

  const state = {
    me: null,
    frameworks: [],
    selectedFramework: null,
    nodesFlat: [],
    nodeTree: [],
    nodeById: new Map(),
    nodePathById: new Map(),
    selectedNodeId: null,
    editingMode: 'edit', // 'new' or 'edit'

    // Taxonomy tree UX (shared MOSP pills renderer)
    expandedNodeIds: new Set(),
    treeOpenMode: 'all', // 'all' | 'none' | null
  };

  const el = {
    whoami: document.getElementById('whoami'),

    refreshFrameworksBtn: document.getElementById('refreshFrameworksBtn'),
    frameworkList: document.getElementById('frameworkList'),

    fwCreateMachine: document.getElementById('fwCreateMachine'),
    fwCreateDisplay: document.getElementById('fwCreateDisplay'),
    fwCreateDescription: document.getElementById('fwCreateDescription'),
    fwCreateBtn: document.getElementById('fwCreateBtn'),
    fwCreateMsg: document.getElementById('fwCreateMsg'),

    selectedFrameworkEmpty: document.getElementById('selectedFrameworkEmpty'),
    selectedFrameworkPanel: document.getElementById('selectedFrameworkPanel'),
    fwTitle: document.getElementById('fwTitle'),
    fwMeta: document.getElementById('fwMeta'),
    fwReloadNodesBtn: document.getElementById('fwReloadNodesBtn'),
    fwSaveBtn: document.getElementById('fwSaveBtn'),
    fwDeleteBtn: document.getElementById('fwDeleteBtn'),
    fwMachine: document.getElementById('fwMachine'),
    fwDisplay: document.getElementById('fwDisplay'),
    fwDescription: document.getElementById('fwDescription'),
    fwSaveMsg: document.getElementById('fwSaveMsg'),

    nodeSearch: document.getElementById('nodeSearch'),
    nodeTree: document.getElementById('nodeTree'),
    nodeExpandAllBtn: document.getElementById('nodeExpandAllBtn'),
    nodeCollapseAllBtn: document.getElementById('nodeCollapseAllBtn'),
    nodeNewBtn: document.getElementById('nodeNewBtn'),
    nodeSaveBtn: document.getElementById('nodeSaveBtn'),
    nodeDeleteBtn: document.getElementById('nodeDeleteBtn'),

    nodeKey: document.getElementById('nodeKey'),
    nodeDisplay: document.getElementById('nodeDisplay'),
    nodeDescription: document.getElementById('nodeDescription'),
    nodeParent: document.getElementById('nodeParent'),
    nodeSort: document.getElementById('nodeSort'),
    nodePath: document.getElementById('nodePath'),
    nodeMsg: document.getElementById('nodeMsg'),
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
    return (me?.effective_role || me?.role || 'viewer').toLowerCase();
  }

  function canMaintainFrameworks(me) {
    const r = roleOf(me);
    return r === 'admin' || r === 'framework_admin';
  }

  function canDeleteFramework(me, fw) {
    const r = roleOf(me);
    if (r === 'admin') return true;
    const ownerId = fw?.created_by_user_id;
    return ownerId && Number(ownerId) === Number(me?.id);
  }

  function deleteFrameworkReason(me, fw) {
    if (!fw) return '';
    if (canDeleteFramework(me, fw)) return '';
    return 'Only the framework owner or an admin can delete this framework.';
  }


  function setMsg(container, message, level = 'info') {
    if (!container) return;
    container.textContent = message || '';
    const cls = ['small'];
    if (level === 'error') cls.push('msg-error');
    if (level === 'success') cls.push('msg-success');
    container.className = cls.join(' ');
  }

  function renderFrameworkList() {
    if (!el.frameworkList) return;
    if (!state.frameworks.length) {
      el.frameworkList.innerHTML = '<div class="small muted">No frameworks found.</div>';
      return;
    }

    const currentId = state.selectedFramework?.id;

    el.frameworkList.innerHTML = `
      <table class="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Machine</th>
            <th>Owner</th>
          </tr>
        </thead>
        <tbody>
          ${state.frameworks
            .map((f) => {
              const selected = Number(f.id) === Number(currentId);
              const owner = Number(f.created_by_user_id) === Number(state.me?.id) ? 'you' : `user:${f.created_by_user_id}`;
              return `
                <tr data-framework-id="${f.id}" style="cursor:pointer; ${selected ? 'background:#f4effb;' : ''}">
                  <td><strong>${escapeHtml(f.display_name || f.machine_name)}</strong><div class="small muted">${escapeHtml(f.description || '')}</div></td>
                  <td><span class="badge text-bg-light border font-monospace">${escapeHtml(f.machine_name)}</span></td>
                  <td class="small muted">${escapeHtml(owner)}</td>
                </tr>
              `;
            })
            .join('')}
        </tbody>
      </table>
    `;
  }

  function showFrameworkPanel(framework) {
    state.selectedFramework = framework;
    state.selectedNodeId = null;
    state.editingMode = 'edit';

    if (!framework) {
      if (el.selectedFrameworkPanel) el.selectedFrameworkPanel.style.display = 'none';
      if (el.selectedFrameworkEmpty) el.selectedFrameworkEmpty.style.display = '';
      if (el.fwDeleteBtn) el.fwDeleteBtn.style.display = 'none';
      renderFrameworkList();
      return;
    }

    if (el.selectedFrameworkEmpty) el.selectedFrameworkEmpty.style.display = 'none';
    if (el.selectedFrameworkPanel) el.selectedFrameworkPanel.style.display = '';

    if (el.fwTitle) el.fwTitle.textContent = framework.display_name || framework.machine_name;
    if (el.fwMeta) el.fwMeta.textContent = `id ${framework.id} • machine ${framework.machine_name}`;
    if (el.fwMachine) el.fwMachine.value = framework.machine_name || '';
    if (el.fwDisplay) el.fwDisplay.value = framework.display_name || '';
    if (el.fwDescription) el.fwDescription.value = framework.description || '';

    if (el.fwDeleteBtn) {
      const reason = deleteFrameworkReason(state.me, framework);
      el.fwDeleteBtn.style.display = '';
      el.fwDeleteBtn.disabled = Boolean(reason);
      el.fwDeleteBtn.title = reason;
    }

    setMsg(el.fwSaveMsg, '', 'info');
    setMsg(el.nodeMsg, '', 'info');
    if (el.nodeSearch) el.nodeSearch.value = '';
    clearNodeEditor();

    renderFrameworkList();
  }

  function rememberNodes(flat, tree) {
    state.nodesFlat = flat || [];
    state.nodeTree = tree || [];
    state.nodeById = new Map();
    state.nodePathById = new Map();

    for (const n of state.nodesFlat) {
      state.nodeById.set(Number(n.id), {
        id: Number(n.id),
        key: n.key,
        display_name: n.display_name,
        description: n.description,
        parent_id: n.parent_id,
        level: n.level,
        sort_order: n.sort_order,
      });
      state.nodePathById.set(Number(n.id), n.path || n.display_name || n.key);
    }
  }

  function descendantsOf(nodeId) {
    const out = new Set();
    const queue = [Number(nodeId)];
    while (queue.length) {
      const current = queue.shift();
      for (const n of state.nodesFlat) {
        if (Number(n.parent_id) === Number(current)) {
          if (!out.has(Number(n.id))) {
            out.add(Number(n.id));
            queue.push(Number(n.id));
          }
        }
      }
    }
    return out;
  }

  function renderParentSelect() {
    if (!el.nodeParent) return;
    const noneOpt = `<option value="">(no parent)</option>`;
    const currentId = state.editingMode === 'edit' ? Number(state.selectedNodeId) : null;
    const banned = currentId ? descendantsOf(currentId) : new Set();
    if (currentId) banned.add(currentId);

    const options = state.nodesFlat
      .filter((n) => !banned.has(Number(n.id)))
      .sort((a, b) => (a.path || '').localeCompare(b.path || ''))
      .map((n) => `<option value="${n.id}">${escapeHtml(n.path || n.display_name || n.key)}</option>`)
      .join('');

    el.nodeParent.innerHTML = noneOpt + options;
  }

  function clearNodeEditor() {
    state.selectedNodeId = null;
    state.editingMode = 'new';
    if (el.nodeKey) el.nodeKey.value = '';
    if (el.nodeDisplay) el.nodeDisplay.value = '';
    if (el.nodeDescription) el.nodeDescription.value = '';
    if (el.nodeSort) el.nodeSort.value = '0';
    renderParentSelect();
    if (el.nodeParent) el.nodeParent.value = '';
    if (el.nodePath) el.nodePath.textContent = '';
    if (el.nodeDeleteBtn) el.nodeDeleteBtn.disabled = true;
  }

  function loadNodeIntoEditor(nodeId) {
    const node = state.nodeById.get(Number(nodeId));
    if (!node) return;
    state.selectedNodeId = Number(nodeId);
    state.editingMode = 'edit';

    if (el.nodeKey) el.nodeKey.value = node.key || '';
    if (el.nodeDisplay) el.nodeDisplay.value = node.display_name || '';
    if (el.nodeDescription) el.nodeDescription.value = node.description || '';
    if (el.nodeSort) el.nodeSort.value = String(node.sort_order ?? 0);
    renderParentSelect();
    if (el.nodeParent) el.nodeParent.value = node.parent_id ? String(node.parent_id) : '';
    if (el.nodePath) el.nodePath.textContent = state.nodePathById.get(Number(nodeId)) || '';
    if (el.nodeDeleteBtn) el.nodeDeleteBtn.disabled = false;
  }

  function shouldShowNode(node, termLower) {
    if (!termLower) return true;
    const path = state.nodePathById.get(Number(node.id)) || '';
    const direct = [node.display_name, node.key, path]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
      .includes(termLower);
    if (direct) return true;
    return (node.children || []).some((c) => shouldShowNode(c, termLower));
  }

  function ancestryFor(nodeId) {
    const chain = [];
    let current = state.nodeById.get(Number(nodeId));
    let safety = 0;
    while (current && safety < 50) {
      chain.push(current);
      if (!current.parent_id) break;
      current = state.nodeById.get(Number(current.parent_id));
      safety += 1;
    }
    return chain.reverse();
  }

  function groupKeyForNodeId(nodeId) {
    const chain = ancestryFor(nodeId);
    if (!chain.length) return 'technology_capabilities';
    // Prefer the first child under the root (UWRA uses "Technology Capabilities" as the root).
    return chain[1]?.key || chain[0]?.key || 'technology_capabilities';
  }

  function colorForNodeId(nodeId) {
    const fw = state.selectedFramework;
    const groupKey = groupKeyForNodeId(nodeId);
    const prefix = fw?.machine_name ? `${fw.machine_name}:` : '';
    return OSPMAE.nodeColor(`${prefix}${groupKey}`);
  }

  function renderNodeTree() {
    if (!el.nodeTree) return;

    const mospUi = window.mospUi;
    if (!mospUi?.renderTaxonomyPillsBrowser) {
      el.nodeTree.innerHTML = '<div class="small">Unable to load taxonomy UI.</div>';
      return;
    }

    const tree = state.nodeTree || [];
    const term = (el.nodeSearch?.value || '').trim();

    const collectExpandable = (nodes, acc) => {
      for (const n of nodes || []) {
        if (Array.isArray(n.children) && n.children.length) {
          acc.add(Number(n.id));
          collectExpandable(n.children, acc);
        }
      }
    };

    let expanded = state.expandedNodeIds;
    if (state.treeOpenMode === 'all') {
      expanded = new Set();
      collectExpandable(tree, expanded);
    } else if (state.treeOpenMode === 'none') {
      expanded = new Set();
    }

    // Keep the canonical expanded set in sync so toggles behave sensibly after
    // pressing "Expand all" / "Collapse all".
    state.expandedNodeIds = expanded;

    mospUi.renderTaxonomyPillsBrowser({
      container: el.nodeTree,
      tree,
      selectionMode: 'single',
      selectedId: state.selectedNodeId,
      expandedIds: expanded,
      searchTerm: term,
      pathsById: state.nodePathById,
      showSelectedPills: false,
      colorForNode: (node) => colorForNodeId(node?.id),
      onSelect: (id) => {
        loadNodeIntoEditor(id);
        setMsg(el.nodeMsg, '', 'info');
        renderNodeTree();
      },
      onToggleExpand: (id) => {
        state.treeOpenMode = null;
        if (state.expandedNodeIds.has(id)) state.expandedNodeIds.delete(id);
        else state.expandedNodeIds.add(id);
        renderNodeTree();
      },
    });
  }

  async function refreshFrameworks(force = false) {
    await loadFrameworks({ force });
    state.frameworks = getFrameworks();
    renderFrameworkList();
  }

  async function selectFrameworkById(id) {
    const fw = state.frameworks.find((f) => Number(f.id) === Number(id));
    if (!fw) return;
    showFrameworkPanel(fw);
    await refreshNodes();
  }

  async function refreshNodes() {
    const fw = state.selectedFramework;
    if (!fw) return;
    const data = await loadFrameworkNodes(Number(fw.id), { force: true });
    rememberNodes(data?.flat || [], data?.tree || []);

    // Default to expanded taxonomy so existing subcategories are immediately visible.
    state.treeOpenMode = 'all';
    state.expandedNodeIds = new Set();

    renderParentSelect();
    renderNodeTree();
    clearNodeEditor();
  }

  async function createFramework() {
    setMsg(el.fwCreateMsg, '', 'info');
    const machine = (el.fwCreateMachine?.value || '').trim();
    const display = (el.fwCreateDisplay?.value || '').trim();
    const description = (el.fwCreateDescription?.value || '').trim();

    if (!machine || !display) {
      setMsg(el.fwCreateMsg, 'Machine name and display name are required.', 'error');
      return;
    }

    try {
      const created = await apiFetch('/v1/frameworks', {
        method: 'POST',
        body: {
          machine_name: machine,
          display_name: display,
          description: description || null,
        },
      });
      setMsg(el.fwCreateMsg, 'Framework created.', 'success');
      if (el.fwCreateMachine) el.fwCreateMachine.value = '';
      if (el.fwCreateDisplay) el.fwCreateDisplay.value = '';
      if (el.fwCreateDescription) el.fwCreateDescription.value = '';
      await refreshFrameworks(true);
      await selectFrameworkById(created?.id);
    } catch (err) {
      setMsg(el.fwCreateMsg, err.message || 'Failed to create framework', 'error');
    }
  }

  async function saveFramework() {
    const fw = state.selectedFramework;
    if (!fw) return;
    setMsg(el.fwSaveMsg, '', 'info');
    const payload = {
      machine_name: (el.fwMachine?.value || '').trim(),
      display_name: (el.fwDisplay?.value || '').trim(),
      description: (el.fwDescription?.value || '').trim() || null,
    };

    if (!payload.machine_name || !payload.display_name) {
      setMsg(el.fwSaveMsg, 'Machine name and display name are required.', 'error');
      return;
    }

    try {
      const updated = await apiFetch(`/v1/frameworks/${fw.id}`, {
        method: 'PUT',
        body: payload,
      });
      setMsg(el.fwSaveMsg, 'Saved.', 'success');
      await refreshFrameworks(true);
      showFrameworkPanel(updated);
    } catch (err) {
      setMsg(el.fwSaveMsg, err.message || 'Failed to save framework', 'error');
    }
  }

  async function deleteFramework() {
    const fw = state.selectedFramework;
    if (!fw) return;

    const reason = deleteFrameworkReason(state.me, fw);
    if (reason) {
      toast(reason, 'error');
      return;
    }

    const ok = window.confirm(`Delete framework "${fw.display_name || fw.machine_name}"?\n\nThis will remove its taxonomy nodes and may remove any project mappings that reference those nodes.`);
    if (!ok) return;

    try {
      await apiFetch(`/v1/frameworks/${fw.id}`, { method: 'DELETE' });
    } catch (err) {
      // If the framework is referenced, offer a force-delete.
      if (err?.status === 409) {
        const okForce = window.confirm(`${err.message}\n\nDelete anyway? This will remove nodes and any mappings that reference them.`);
        if (!okForce) return;
        await apiFetch(`/v1/frameworks/${fw.id}?force=true`, { method: 'DELETE' });
      } else {
        throw err;
      }
    }

    toast('Framework deleted', 'success');
    await refreshFrameworks(true);
    showFrameworkPanel(null);
  }

  function readNodeEditor() {
    const key = (el.nodeKey?.value || '').trim();
    const display = (el.nodeDisplay?.value || '').trim();
    const description = (el.nodeDescription?.value || '').trim();
    const parentStr = (el.nodeParent?.value || '').trim();
    const sortStr = (el.nodeSort?.value || '').trim();

    return {
      key,
      display_name: display,
      description: description || null,
      parent_id: parentStr ? Number(parentStr) : null,
      sort_order: sortStr ? Number(sortStr) : 0,
    };
  }

  async function saveNode() {
    const fw = state.selectedFramework;
    if (!fw) return;
    setMsg(el.nodeMsg, '', 'info');
    const payload = readNodeEditor();

    if (!payload.key || !payload.display_name) {
      setMsg(el.nodeMsg, 'Node key and display name are required.', 'error');
      return;
    }

    if (Number.isNaN(payload.sort_order)) {
      setMsg(el.nodeMsg, 'Sort order must be a number.', 'error');
      return;
    }

    try {
      if (state.editingMode === 'edit' && state.selectedNodeId) {
        await apiFetch(`/v1/framework-nodes/${state.selectedNodeId}`, {
          method: 'PUT',
          body: payload,
        });
        setMsg(el.nodeMsg, 'Node updated.', 'success');
      } else {
        await apiFetch(`/v1/frameworks/${fw.id}/nodes`, {
          method: 'POST',
          body: payload,
        });
        setMsg(el.nodeMsg, 'Node created.', 'success');
      }

      await refreshNodes();
    } catch (err) {
      setMsg(el.nodeMsg, err.message || 'Failed to save node', 'error');
    }
  }

  async function deleteNode() {
    if (!state.selectedNodeId) return;
    const ok = window.confirm('Delete this node? This cannot be undone.');
    if (!ok) return;

    try {
      await apiFetch(`/v1/framework-nodes/${state.selectedNodeId}`, {
        method: 'DELETE',
      });
      toast('Node deleted', 'info');
      await refreshNodes();
    } catch (err) {
      setMsg(el.nodeMsg, err.message || 'Failed to delete node', 'error');
    }
  }

  function wireEvents() {
    if (el.refreshFrameworksBtn) {
      el.refreshFrameworksBtn.addEventListener('click', () => refreshFrameworks(true).catch((e) => toast(e.message, 'error')));
    }

    if (el.frameworkList) {
      el.frameworkList.addEventListener('click', (ev) => {
        const tr = ev.target.closest('[data-framework-id]');
        if (!tr) return;
        const id = tr.getAttribute('data-framework-id');
        if (!id) return;
        selectFrameworkById(id).catch((e) => toast(e.message, 'error'));
      });
    }

    if (el.fwCreateBtn) {
      el.fwCreateBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        createFramework();
      });
    }

    if (el.fwSaveBtn) {
      el.fwSaveBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        saveFramework();
      });
    }

    if (el.fwDeleteBtn) {
      el.fwDeleteBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        deleteFramework().catch((e) => toast(e.message || 'Failed to delete framework', 'error'));
      });
    }

    if (el.fwReloadNodesBtn) {
      el.fwReloadNodesBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        refreshNodes().catch((e) => toast(e.message, 'error'));
      });
    }

    if (el.nodeSearch) {
      el.nodeSearch.addEventListener('input', () => renderNodeTree());
    }

    if (el.nodeExpandAllBtn) {
      el.nodeExpandAllBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        state.treeOpenMode = 'all';
        renderNodeTree();
      });
    }

    if (el.nodeCollapseAllBtn) {
      el.nodeCollapseAllBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        state.treeOpenMode = 'none';
        renderNodeTree();
      });
    }

    if (el.nodeNewBtn) {
      el.nodeNewBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        clearNodeEditor();
        setMsg(el.nodeMsg, 'Creating a new node.', 'info');
      });
    }

    if (el.nodeSaveBtn) {
      el.nodeSaveBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        saveNode();
      });
    }

    if (el.nodeDeleteBtn) {
      el.nodeDeleteBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        deleteNode();
      });
    }
  }

  async function init() {
    state.me = await initAuth({ redirectOnFail: true });
    if (!state.me) return;

    if (el.whoami) {
      const r = roleOf(state.me);
      el.whoami.textContent = state.me?.username ? `${state.me.username} (${r})` : r;
    }

    if (!canMaintainFrameworks(state.me)) {
      toast('You do not have access to framework administration.', 'error');
      window.location.href = '/index.html';
      return;
    }

    wireEvents();
    await refreshFrameworks(false);

    // Auto-select the active framework if set, otherwise first.
    const active = OSPMAE.getActiveFramework?.();
    if (active?.id) {
      await selectFrameworkById(active.id);
    } else if (state.frameworks[0]) {
      await selectFrameworkById(state.frameworks[0].id);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    init().catch((err) => {
      console.error(err);
      toast(err.message || 'Failed to load framework administration', 'error');
    });
  });
})();
