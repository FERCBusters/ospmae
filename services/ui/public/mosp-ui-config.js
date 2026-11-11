// MOSP UI configuration for OSPMAE.
// This must load BEFORE any page calls initNavbar().

(function () {
  function mapMe(me) {
    // OSPMAE returns: { username, role, effective_role, ... }
    const role =
      String(me?.effective_role || me?.role || "").toLowerCase() || "viewer";
    const isPending = role === "pending";
    const canViewCatalogue = !isPending;
    const isAdmin = role === "admin";
    const isFrameworkAdmin = isAdmin || role === "framework_admin";
    const canManageProjects = isAdmin || role === "maintainer";
    const canExportManifests =
      isAdmin || role === "architect" || role === "product_owner";
    const canAnswerQuestions =
      isAdmin || role === "maintainer" || role === "contributor";
    const canAskQuestions =
      canAnswerQuestions ||
      role === "engineer" ||
      role === "product_owner" ||
      role === "architect";

    // Installation features from /v1/me decide which links the navbar
    // renders; an unknown or missing switch counts as on.
    const features = me?.features || {};
    const featureOn = (key) => features[key] !== false;

    return {
      ...me,
      feature_frameworks: featureOn("frameworks"),
      feature_manifests: featureOn("manifests"),
      feature_dependency_scans: featureOn("dependency_scans"),
      feature_comparisons: featureOn("comparisons"),
      user: String(me?.user || me?.username || "").trim(),
      role,
      is_pending: isPending,
      can_view_catalogue: canViewCatalogue,
      is_admin: isAdmin,
      is_framework_admin: isFrameworkAdmin,
      can_manage_projects: canManageProjects,
      can_export_manifests: canExportManifests,
      can_ask_questions: canAskQuestions,
      can_answer_questions: canAnswerQuestions,
    };
  }

  window.mospUiConfig = {
    appId: "ospmae",
    appName: "OSPMAE",
    brandIcon: "/favicon.svg",
    brandHref: "/index.html",

    // OSPMAE uses /v1/* (not /api/v1/*)
    auth: {
      meEndpoint: "/v1/me",
      loginUrl: "/login.html",
      logoutEndpoint: "/v1/auth/logout",
      logoutRedirect: "/login.html",
      accountHref: "/account.html",
    },

    csrf: { cookieName: "ospmae_csrf" },

    // Keep the navbar unified across apps; Account is provided by the shared UI.
    // Each key is the data-page of the page it highlights in the navbar.
    links: [
      {
        key: "projects",
        label: "Projects",
        href: "/index.html",
        requireAny: ["can_view_catalogue"],
      },
      {
        key: "manifests",
        label: "Manifests",
        href: "/manifests.html",
        requireAny: ["can_view_catalogue"],
        requireAll: ["feature_manifests"],
      },
      {
        key: "dependencies",
        label: "Dependencies",
        href: "/dependencies.html",
        requireAny: ["can_view_catalogue"],
        requireAll: ["feature_dependency_scans"],
      },
      {
        key: "comparisons",
        label: "Project Comparisons",
        href: "/comparisons.html",
        requireAny: ["can_view_catalogue"],
        requireAll: ["feature_comparisons"],
      },
      {
        key: "frameworks",
        label: "Frameworks",
        href: "/framework-manage.html",
        requireAny: ["is_framework_admin", "is_admin"],
        requireAll: ["feature_frameworks"],
      },
      {
        key: "admin",
        label: "Admin",
        href: "/admin.html",
        requireAny: ["is_admin"],
      },
    ],

    framework: {
      enabled: true,
      label: "Framework",
      queryParam: "framework",
      endpoint: "/v1/frameworks",
      selectMinWidthPx: 240,
    },

    // OSPMAE doesn't have global navbar search.
    search: { enabled: false },

    shortcuts: {
      enabled: true,
      endpoint: "/v1/me/shortcuts",
      label: "Shortcuts",
    },

    // The shared MOSP shell defaults are KEEN-flavoured and include KEEN's
    // "Start audit" action. OSPMAE does not have an audits module, so opt out
    // of navbar extra actions while keeping the shared navbar shell itself.
    nav: {
      extraHtml: "",
    },

    bell: {
      enabled: true,
      href: "/questions.html",
      title: "Questions",
      summaryEndpoint: "/v1/questions/unanswered/summary",
      countKey: "open_count",
    },

    // Use the design system's default keys so the pre-paint theme-boot reads
    // the same value on pages that load without this config (login, reset).
    storage: {
      themeKey: "keen_theme",
      frameworkKey: "keen_framework",
    },

    uiPreferences: {
      endpoint: "/v1/me/preferences",
      method: "PUT",
      stickyField: "sticky_enabled",
    },

    mapMe,
  };
})();
