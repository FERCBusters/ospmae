// The project page as its tests drive it: see app-page.mjs for what the
// fixture supplies. This adds the page's API answers.
import { loadPage } from "./load-page.mjs";
import {
  D3,
  FEATURES,
  FRAMEWORK,
  account,
  installBrowser,
  installLayout,
} from "./app-page.mjs";

export { D3, FEATURES, FRAMEWORK, account };

export const VERSIONS = [
  {
    id: 12,
    version: "2.0.0",
    is_latest: true,
    is_draft: false,
    status: "stable",
    release_date: "2026-03-04T00:00:00",
    link_to_source_code: "https://github.com/example/repo",
    notes: "Second release",
    capability_paths: ["Wallet > Storage > Keys", "Issuer"],
    dependency_discovery_status: "complete",
  },
  {
    id: 11,
    version: "1.0.0",
    is_latest: false,
    is_draft: false,
    status: "obsolete",
    release_date: "2025-01-02T00:00:00",
    link_to_source_code: null,
    notes: null,
    capability_paths: [],
    dependency_discovery_status: "not_run",
  },
];

export const PROJECT = {
  id: 5,
  machine_name: "wallet-kit",
  display_name: "Wallet Kit",
  organisation: "Acme",
  project_type: "library",
  license: "Apache-2.0",
  programming_languages: ["Rust", "Go"],
  link_to_app: "https://wallet.example/",
  capability: "wallet",
  supported_profiles: ["OpenID4VCI"],
  supported_formats: ["SD-JWT"],
  supported_issuance_protocols: [],
  supported_presentation_protocols: [],
  supported_key_managements: [],
  supported_signing_algorithms: ["ES256"],
  created_by_user_id: 7,
  owner_group_ids: [],
  is_subscribed: false,
  can_view_drafts: true,
  latest_version: VERSIONS[0],
  versions: VERSIONS,
  capability_paths: ["Wallet > Storage > Keys", "Issuer"],
};

// The capability graph the API serves for a version: its selected nodes with
// the ancestors that lead to them.
export function capabilityGraph(version = VERSIONS[0]) {
  const tree = [
    {
      id: 31,
      key: "issuer",
      display_name: "Issuer",
      level: 0,
      selected: true,
      children: [],
    },
    {
      id: 30,
      key: "wallet",
      display_name: "Wallet",
      level: 0,
      selected: false,
      children: [
        {
          id: 32,
          key: "storage",
          display_name: "Storage",
          level: 1,
          selected: false,
          children: [
            {
              id: 33,
              key: "keys",
              display_name: "Keys",
              level: 2,
              selected: true,
              children: [],
            },
            {
              id: 34,
              key: "backup",
              display_name: "Backup & recovery of credentials",
              level: 2,
              selected: true,
              children: [],
            },
          ],
        },
      ],
    },
  ];
  const nodes = [
    {
      id: "project:5",
      label: "Wallet Kit",
      group: "project",
      level: 0,
      selected: true,
    },
    {
      id: `version:${version.id}`,
      label: version.version,
      group: "version",
      level: 1,
      selected: true,
    },
  ];
  const links = [
    { source: "project:5", target: `version:${version.id}`, value: 1 },
  ];
  const walk = (parent, items) => {
    for (const item of items) {
      const id = `node:${item.id}`;
      nodes.push({
        id,
        label: item.display_name,
        group: "framework_node",
        level: item.level + 2,
        selected: item.selected,
      });
      links.push({ source: parent, target: id, value: 1 });
      walk(id, item.children);
    }
  };
  walk(`version:${version.id}`, tree);
  return {
    framework: FRAMEWORK,
    project: { id: 5, display_name: "Wallet Kit" },
    version,
    nodes,
    links,
    capability_tree: tree,
  };
}

const leaf = (ecosystem, namespace, pkg, version, id, extra = {}) => ({
  name: `${pkg.split("/").pop()}@${version}`,
  value: 1,
  ecosystem,
  namespace,
  package: pkg,
  version,
  dependency_version_id: id,
  is_indirect: false,
  vulnerability_count: 0,
  ...extra,
});

// A version's dependency graph as the API serves it after a finished scan.
export function dependencyGraph(overrides = {}) {
  const leaves = [
    leaf("npm", "@inquirer", "@inquirer/confirm", "5.1.21", 101, {
      vulnerability_count: 2,
    }),
    leaf("npm", "(unscoped)", "lodash", "4.17.21", 102, { is_indirect: true }),
    leaf("python", "(root)", "requests", "2.31.0", 103, {
      vulnerability_count: 1,
    }),
    leaf("python", "(root)", "idna", "3.6", 104, { is_indirect: true }),
  ];
  const group = (items, key) => {
    const out = new Map();
    for (const item of items) {
      if (!out.has(item[key])) out.set(item[key], []);
      out.get(item[key]).push(item);
    }
    return out;
  };
  const tree = {
    name: "Wallet Kit",
    children: [
      {
        name: "2.0.0",
        children: [...group(leaves, "ecosystem")].map(([eco, items]) => ({
          name: eco,
          children: [...group(items, "namespace")].map(([ns, members]) => ({
            name: ns,
            children: members,
          })),
        })),
      },
    ],
  };
  return {
    project: {
      id: 5,
      name: "Wallet Kit",
      display_name: "Wallet Kit",
      machine_name: "wallet-kit",
    },
    version: {
      id: 12,
      version: "2.0.0",
      is_latest: true,
      link_to_source_code: "https://github.com/example/repo",
      dependency_discovery_status: "complete",
      dependency_discovery_started_at: "2026-03-05T10:00:00",
      dependency_discovery_finished_at: "2026-03-05T10:02:00",
      dependency_discovery_error: null,
      dependency_last_commit: "c0ffee1234567890",
      dependency_count: 4,
      vulnerability_count: 3,
    },
    dependency_tree: tree,
    dependencies: leaves.map((l) => ({
      ecosystem: l.ecosystem,
      namespace: l.namespace,
      name: l.package,
      version: l.version,
      label: `${l.package}@${l.version}`,
      dependency_version_id: l.dependency_version_id,
      is_indirect: l.is_indirect,
      vulnerability_count: l.vulnerability_count,
    })),
    vulnerabilities: [
      {
        ecosystem: "npm",
        namespace: "@inquirer",
        package: "@inquirer/confirm",
        version: "5.1.21",
        dependency_label: "@inquirer/confirm@5.1.21",
        dependency_version_id: 101,
        scanner: "grype",
        vulnerability_id: "CVE-2026-0001",
        severity: "CRITICAL",
        title: "Prompt <injection>",
        fixed_version: "5.2.0",
        references: [
          "https://advisories.example/CVE-2026-0001",
          "javascript:alert(1)",
        ],
      },
      {
        ecosystem: "npm",
        namespace: "@inquirer",
        package: "@inquirer/confirm",
        version: "5.1.21",
        dependency_label: "@inquirer/confirm@5.1.21",
        dependency_version_id: 101,
        scanner: "grype",
        vulnerability_id: "GHSA-aaaa",
        severity: "LOW",
        title: null,
        fixed_version: null,
        references: [],
      },
      {
        ecosystem: "python",
        namespace: "(root)",
        package: "requests",
        version: "2.31.0",
        dependency_label: "requests@2.31.0",
        dependency_version_id: 103,
        scanner: "grype",
        vulnerability_id: "CVE-2026-0002",
        severity: null,
        title: "Unknown severity",
        fixed_version: "2.32.0",
        references: [],
      },
    ],
    summary: {
      dependency_count: 4,
      vulnerability_count: 3,
      ecosystems: { npm: 2, python: 2 },
      namespaces: {},
    },
    ...overrides,
  };
}

export async function projectPage(t, options = {}) {
  const record = {
    images: [],
    canvases: [],
    pdfs: [],
    blobs: [],
    downloads: [],
  };
  const me = options.me || account();
  const answers = {
    project: PROJECT,
    graph: capabilityGraph(),
    dependencies: dependencyGraph(),
    questions: { items: [], can_answer: false },
    changelog: { items: [], total: 0 },
    subscription: {
      subscribed: false,
      notify_new_versions: false,
      notify_questions: false,
    },
    ...(options.answers || {}),
  };
  const give = (value, ...args) =>
    typeof value === "function" ? value(...args) : value;
  const page = await loadPage("project.html", "pages/project.js", {
    url: `https://ospmae.example/project.html${options.query ?? "?id=5"}${options.hash || ""}`,
    withApp: true,
    libraries: options.d3 === false ? [] : [D3],
    setup(window) {
      installLayout(window, options.size);
      installBrowser(window, record, options);
      window.confirm = () => options.confirm !== false;
      options.setup?.(window);
    },
    api: async (method, path, body) => {
      const custom = await options.api?.(method, path, body, answers);
      if (custom) return custom;
      if (path === "/v1/me") return [200, me];
      if (path === "/v1/system/features") return [200, me.features];
      if (path === "/v1/frameworks") return [200, { items: [FRAMEWORK] }];
      if (path === "/v1/projects/5" && method === "GET")
        return [200, give(answers.project)];
      if (path === "/v1/projects/5/graph") return [200, give(answers.graph)];
      if (path === "/v1/projects/5/dependency-graph")
        return [200, give(answers.dependencies)];
      if (path === "/v1/projects/5/questions" && method === "GET")
        return [200, give(answers.questions)];
      if (path === "/v1/projects/5/changelog")
        return [200, give(answers.changelog)];
      if (path === "/v1/projects/5/subscription" && method === "GET")
        return [200, give(answers.subscription)];
      return [200, {}];
    },
  });
  t.after(page.close);
  const settle = async (turns = 30) => {
    for (let i = 0; i < turns; i += 1) await page.settle();
  };
  await settle();
  const doc = page.document;
  return {
    ...page,
    doc,
    record,
    wait: settle,
    // Toasts shown so far, as [level, text].
    toasts: () =>
      [...doc.querySelectorAll(".toast")].map((toast) => [
        [...toast.classList].find((c) => c.startsWith("text-bg-")).slice(8),
        toast.querySelector(".toast-body").textContent,
      ]),
    $: (id) => doc.getElementById(id),
    asked: () => page.requests.map(([method, path]) => `${method} ${path}`),
    async choose(id, value) {
      const select = doc.getElementById(id);
      select.value = value;
      select.dispatchEvent(new page.window.Event("change"));
      await settle();
    },
    async click(id) {
      doc.getElementById(id).click();
      await settle();
    },
    texts: (selector) =>
      [...doc.querySelectorAll(selector)].map((n) => n.textContent.trim()),
  };
}
