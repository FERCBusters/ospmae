// Flags HTML insertion that bypasses escapeHtml(); run it with
// `bash lint-ui.sh` from the repository root, which file patterns are
// relative to. Ported from KEEN's check. Sites that predate it are listed in
// eslint-suppressions.json, which new code leaves alone: write new markup
// with escapeHtml() around every value, or build nodes with textContent.
import noUnsanitized from "eslint-plugin-no-unsanitized";

// Functions whose result is safe to insert as HTML.
const escape = {
  methods: ["escapeHtml", "OSPMAE.escapeHtml", "esc"],
};

const rules = {
  "no-unsanitized/method": ["error", { escape }],
  "no-unsanitized/property": ["error", { escape }],
};

export default [
  {
    linterOptions: { reportUnusedDisableDirectives: "error" },
  },
  {
    // First-party page scripts are classic scripts; the shell is a module.
    files: ["services/ui/public/**/*.js"],
    ignores: [
      "services/ui/public/vendor/**",
      "services/ui/public/mosp-shell.js",
    ],
    languageOptions: { ecmaVersion: "latest", sourceType: "script" },
    plugins: { "no-unsanitized": noUnsanitized },
    rules,
  },
  {
    files: ["services/ui/public/mosp-shell.js"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module" },
    plugins: { "no-unsanitized": noUnsanitized },
    rules,
  },
];
