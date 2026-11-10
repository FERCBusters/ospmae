import {
  initNavbar,
  renderTaxonomyPillsBrowser,
  safeExternalHref,
  applyTheme,
  THEMES,
} from "/vendor/mosp-design-system/app.js";

// Mount the unified navbar for legacy (non-module) pages.
// Pages should include:
//  - <div id="navbar"></div>
//  - <script src="/mosp-ui-config.js"></script>
//  - <script src="/vendor/bootstrap/bootstrap.bundle.min.js"></script>
//  - <script type="module" src="/mosp-shell.js"></script>

// Expose reusable UI helpers to non-module page scripts.
window.mospUi = window.mospUi || {};
window.mospUi.renderTaxonomyPillsBrowser = renderTaxonomyPillsBrowser;
window.mospUi.safeExternalHref = safeExternalHref;
window.mospUi.applyTheme = applyTheme;
window.mospUi.THEMES = THEMES;

initNavbar().catch((err) => {
  console.error("MOSP navbar init failed", err);
});
