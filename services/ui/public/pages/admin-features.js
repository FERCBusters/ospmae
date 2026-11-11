// Installation feature switches on the Administration page. Ported from
// KEEN's pages/admin-features.js; keep the two aligned.
(() => {
  "use strict";

  function mountFeatures() {
    const root = document.getElementById("feature-settings");
    const status = document.getElementById("feature-status");
    const tab = document.getElementById("tab-features");
    const reload = document.getElementById("features-reload");
    const versionLabel = document.getElementById("feature-version");
    if (!root || !status || !tab) return;

    let config = null;
    let busy = false;
    let pending = null;

    function show(message, kind) {
      status.hidden = false;
      status.className = `small alert alert-${kind} py-2 mt-2 mb-2`;
      status.textContent = message;
    }

    function render() {
      root.setAttribute("aria-busy", String(busy));
      if (reload) reload.disabled = busy;
      root.replaceChildren();
      for (const item of config.items) {
        const row = document.createElement("div");
        row.className = `form-check form-switch py-2 ${item.parent ? "ms-4" : "border-top mt-3"}`;
        const input = document.createElement("input");
        input.type = "checkbox";
        input.className = "form-check-input";
        input.id = `feature-${item.key}`;
        input.setAttribute("role", "switch");
        const deploymentOff = config.deployment?.[item.key] === false;
        input.checked = deploymentOff
          ? false
          : pending?.key === item.key
            ? pending.checked
            : config.configured[item.key];
        const parentOff = item.parent && !config.enabled[item.parent];
        input.disabled = busy || !!parentOff || deploymentOff;
        const label = document.createElement("label");
        label.htmlFor = input.id;
        label.className = "form-check-label";
        label.textContent = item.label;
        row.append(input, label);
        const note = deploymentOff
          ? `Turned off for this deployment (OSPMAE_FEATURE_${item.key.toUpperCase()}=false).`
          : parentOff
            ? "Unavailable while its parent feature is off. Your setting is preserved."
            : "";
        if (note) {
          const help = document.createElement("div");
          help.className = "form-text";
          help.id = `${input.id}-help`;
          help.textContent = note;
          input.setAttribute("aria-describedby", help.id);
          row.append(help);
        }
        input.addEventListener("change", () => save(item, input.checked));
        root.append(row);
      }
      if (versionLabel) {
        versionLabel.textContent = `Configuration revision ${config.version}`;
      }
    }

    async function save(item, checked) {
      busy = true;
      pending = { key: item.key, checked };
      show(`Saving ${item.label}`, "info");
      render();
      try {
        config = await OSPMAE.api("/v1/admin/features", {
          method: "PUT",
          body: { version: config.version, changes: { [item.key]: checked } },
        });
        OSPMAE.setFeatures?.(config.enabled);
        // The next page this tab opens draws its navbar from the new state.
        window.mospUi?.clearCachedMe?.();
        show(
          `${item.label} ${checked ? "enabled" : "disabled"}. Settings saved. Reload the page to refresh navigation.`,
          "success",
        );
      } catch (error) {
        show(
          `Could not save: ${error?.message || error}. Reload settings before trying again.`,
          "danger",
        );
        try {
          config = await OSPMAE.api("/v1/admin/features");
        } catch (_) {
          // Keep the last confirmed values.
        }
      } finally {
        busy = false;
        pending = null;
        render();
        document.getElementById(`feature-${item.key}`)?.focus();
      }
    }

    async function load() {
      if (busy) return;
      busy = true;
      root.setAttribute("aria-busy", "true");
      if (reload) reload.disabled = true;
      if (config) render();
      show("Loading feature settings", "info");
      try {
        config = await OSPMAE.api("/v1/admin/features");
        status.hidden = true;
      } catch (error) {
        show(
          `Could not load features: ${error?.message || error}. Use Reload settings to retry.`,
          "danger",
        );
      } finally {
        busy = false;
        root.setAttribute("aria-busy", "false");
        if (reload) reload.disabled = false;
        if (config) render();
      }
    }

    tab.addEventListener("shown.bs.tab", load);
    reload?.addEventListener("click", load);
    const isActive = () =>
      tab.classList.contains("active") ||
      window.location.hash.toLowerCase() === "#features";
    // Restoring a document from the back/forward cache emits no tab event.
    window.addEventListener("pageshow", (event) => {
      if (event.persisted && isActive()) load();
    });
    if (isActive()) load();
  }

  async function start() {
    await OSPMAE.ensureInitialized();
    if (!OSPMAE.isAdmin()) return;
    mountFeatures();
  }

  if (typeof window !== "undefined" && window.OSPMAE) {
    start().catch((error) => console.error(error));
  }
})();
