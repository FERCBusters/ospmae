// Manifests page chrome: the vertical tabs that hold the Manifest Builder
// (pages/manifest-builder.js) and Saved Manifests (pages/saved-manifests.js).
// Tabs follow the URL hash (#builder, #saved), and a ?id= deep link (sent in
// manifest-shared e-mails) opens the saved tab with that manifest.

(() => {
  const OSPMAE = window.OSPMAE;
  const { ensureInitialized, gateFeature, canExportManifests } = OSPMAE;

  function showTab(hash) {
    if (!hash) return;
    const btn = document.querySelector(
      `#manifestTabs button[data-hash="${CSS.escape(hash)}"]`,
    );
    if (!btn || btn.closest("[hidden]") || !window.bootstrap?.Tab) return;
    try {
      window.bootstrap.Tab.getOrCreateInstance(btn).show();
    } catch {}
  }

  function wireHashNavigation() {
    document
      .querySelectorAll('#manifestTabs button[data-bs-toggle="tab"]')
      .forEach((btn) => {
        btn.addEventListener("shown.bs.tab", (e) => {
          const target = e?.target?.getAttribute?.("data-hash");
          if (!target) return;
          try {
            const url = new URL(window.location.href);
            // A manifest id only belongs to the saved tab.
            if (target !== "saved") url.searchParams.delete("id");
            url.hash = target;
            history.replaceState(
              null,
              "",
              url.pathname + url.search + url.hash,
            );
          } catch {}
        });
      });
    window.addEventListener("hashchange", () => {
      showTab(String(window.location.hash || "").replace("#", ""));
    });
  }

  async function init() {
    await ensureInitialized();
    if (!gateFeature("manifests")) return;

    const savedItem = document.getElementById("savedTabItem");
    if (savedItem) savedItem.hidden = !canExportManifests();

    wireHashNavigation();
    const params = new URLSearchParams(window.location.search);
    const hash = String(window.location.hash || "")
      .replace("#", "")
      .trim()
      .toLowerCase();
    showTab(params.get("id") ? "saved" : hash);
  }

  document.addEventListener("DOMContentLoaded", () => {
    init().catch((err) => console.error(err));
  });
})();
