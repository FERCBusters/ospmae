// A first-party page as its tests drive it: the real markup, app.js and the
// page's own scripts against an API fixture. Only what jsdom has no engine
// for is supplied (SVG text measurement, element sizes, canvas, image
// decoding) or recorded (downloads, the Bootstrap widgets, the PDF library).
import { loadPage } from "./load-page.mjs";

export const D3 = new URL("../node_modules/d3/dist/d3.min.js", import.meta.url);

export const FEATURES = {
  frameworks: true,
  manifests: true,
  comparisons: true,
  questions: true,
  dependency_scans: true,
  release_feed: true,
};

export const FRAMEWORK = {
  id: 3,
  machine_name: "tax",
  display_name: "Taxonomy",
};

export function account(role = "admin", extra = {}) {
  return {
    id: 7,
    username: "ada",
    role,
    effective_role: role,
    csrf_token: "token",
    preferences: {},
    permissions: [],
    group_ids: [],
    features: FEATURES,
    ...extra,
  };
}

// What jsdom cannot compute: sizes and text measurement. Text is measured at
// a fixed advance per character, so label fitting follows label length.
export function installLayout(window, { width = 1200, height = 700 } = {}) {
  const proto = window.SVGElement.prototype;
  const measure = (node) => (node.textContent || "").length * 7;
  proto.getComputedTextLength = function () {
    return measure(this);
  };
  proto.getBBox = function () {
    return { x: 0, y: 0, width: Math.max(measure(this), 10), height: 14 };
  };
  proto.getBoundingClientRect = function () {
    return {
      x: 0,
      y: 0,
      left: 0,
      top: 0,
      width,
      height,
      right: width,
      bottom: height,
    };
  };
  for (const [name, value] of [
    ["clientWidth", width],
    ["clientHeight", height],
  ]) {
    Object.defineProperty(window.HTMLElement.prototype, name, {
      configurable: true,
      get() {
        return value;
      },
    });
  }
}

// Browser facilities jsdom leaves out, each recording what the page asked of
// it: the Bootstrap modal, image decoding, canvas, the PDF library and file
// downloads.
export function installBrowser(window, record, options) {
  window.bootstrap = {
    Modal: class {
      constructor(element) {
        this.element = element;
      }
      show() {
        this.element.classList.add("show");
      }
      hide() {
        this.element.classList.remove("show");
      }
    },
  };
  // The design system's taxonomy browser (a vendored module the shell
  // exposes as window.mospUi). The stand-in keeps what the page asked it to
  // show and draws one button per node the page left expanded, so a test
  // can pick and fold nodes the way the real widget reports them.
  window.mospUi = {
    renderTaxonomyPillsBrowser(view) {
      record.taxonomy = view;
      const draw = (nodes, depth) =>
        (nodes || [])
          .map((node) => {
            const open = view.expandedIds?.has(Number(node.id));
            const kids = (node.children || []).length;
            const picked =
              view.selectionMode === "single"
                ? Number(view.selectedId) === Number(node.id)
                : view.selectedIds?.has?.(Number(node.id));
            return (
              `<div data-depth="${depth}">` +
              (kids
                ? `<button type="button" data-fold="${node.id}">${open ? "-" : "+"}</button>`
                : "") +
              `<button type="button" data-pick="${node.id}" class="${picked ? "selected" : ""}" style="--cap-color:${view.colorForNode?.(node) || ""}"></button>` +
              (open ? draw(node.children, depth + 1) : "") +
              "</div>"
            );
          })
          .join("");
      view.container.innerHTML = draw(view.tree, 0);
      for (const button of view.container.querySelectorAll("[data-pick]")) {
        const node = button.dataset.pick;
        button.textContent = view.pathsById?.get?.(Number(node)) || node;
        button.addEventListener("click", () =>
          (view.onSelect || view.onToggleSelect)?.(Number(node)),
        );
      }
      for (const button of view.container.querySelectorAll("[data-fold]"))
        button.addEventListener("click", () =>
          view.onToggleExpand?.(Number(button.dataset.fold)),
        );
    },
    safeExternalHref: (value) =>
      /^https?:\/\//i.test(String(value || "")) ? String(value) : "",
    clearCachedMe() {
      record.navbarRefreshes = (record.navbarRefreshes || 0) + 1;
    },
  };
  // jsdom has no CSS.escape; the pages use it for identifiers in selectors.
  window.CSS = {
    escape: (value) =>
      String(value).replace(/[^a-zA-Z0-9_\u00a0-\uffff-]/g, (ch) => `\\${ch}`),
  };
  window.bootstrap.Tab = {
    getOrCreateInstance: (button) => ({
      show() {
        record.tabs.push(button.getAttribute("data-hash") || button.id);
        button.dispatchEvent(
          new window.Event("shown.bs.tab", { bubbles: true }),
        );
      },
    }),
  };
  window.Image = class {
    set src(value) {
      record.images.push(value);
      setTimeout(
        () =>
          options.imageFails
            ? this.onerror(new Error("decode"))
            : this.onload(),
        0,
      );
    }
  };
  window.HTMLCanvasElement.prototype.getContext = function () {
    const canvas = this;
    return {
      fillRect() {},
      drawImage() {
        record.canvases.push({
          width: canvas.width,
          height: canvas.height,
          fill: this.fillStyle,
        });
      },
    };
  };
  window.HTMLCanvasElement.prototype.toDataURL = (type) =>
    `data:${type};base64,AAAA`;
  if (options.pdf !== false) {
    window.jspdf = {
      jsPDF: class {
        constructor(setup) {
          this.setup = setup;
          this.internal = {
            pageSize: { getWidth: () => 297, getHeight: () => 210 },
          };
          if (setup.orientation === "portrait")
            this.internal.pageSize = {
              getWidth: () => 210,
              getHeight: () => 297,
            };
        }
        addImage(data, format, x, y, width, height) {
          this.image = { format, x, y, width, height };
        }
        save(name) {
          record.pdfs.push({
            name,
            orientation: this.setup.orientation,
            image: this.image,
          });
        }
      },
    };
  }
  window.URL.createObjectURL = (blob) => {
    record.blobs.push(blob);
    return `blob:https://ospmae.example/${record.blobs.length}`;
  };
  window.URL.revokeObjectURL = () => {};
  // A download is an anchor with a file name, clicked by the page.
  window.HTMLAnchorElement.prototype.click = function () {
    if (this.hasAttribute("download"))
      record.downloads.push({
        name: this.getAttribute("download"),
        href: this.getAttribute("href"),
      });
  };
}

// Options:
//   me        the signed-in account (default an administrator)
//   query, hash   the address after the page name
//   api       (method, path, body, query) => [status, body] for the page's
//             requests;
//             return nothing to fall through to the defaults
//   d3        false leaves the chart library out
//   setup     runs on the window before any script
export async function appPage(t, htmlName, scripts, options = {}) {
  const record = {
    images: [],
    canvases: [],
    pdfs: [],
    blobs: [],
    downloads: [],
    modals: [],
    tabs: [],
  };
  const me = options.me === undefined ? account() : options.me;
  const page = await loadPage(htmlName, scripts, {
    url: `https://ospmae.example/${htmlName}${options.query || ""}${options.hash || ""}`,
    withApp: true,
    libraries: options.d3 === false ? [] : [D3],
    setup(window) {
      installLayout(window, options.size);
      installBrowser(window, record, options);
      window.confirm = (message) => {
        record.confirms = [...(record.confirms || []), message];
        return options.confirm !== false;
      };
      options.setup?.(window);
    },
    api: async (method, path, body, query) => {
      const custom = await options.api?.(method, path, body, query);
      if (custom) return custom;
      if (path === "/v1/me")
        return me ? [200, me] : [401, { detail: "Not authenticated" }];
      if (path === "/v1/system/features")
        return [200, (me || account()).features];
      if (path === "/v1/frameworks") return [200, { items: [FRAMEWORK] }];
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
    $: (id) => doc.getElementById(id),
    // jsdom cannot leave the page: a move to another address is reported
    // as an error instead, and counted here.
    navigations: () =>
      page.errors.filter((error) =>
        /navigation/i.test(String(error?.message || error)),
      ).length,
    asked: () => page.requests.map(([method, path]) => `${method} ${path}`),
    sent: (method, path) =>
      page.requests
        .filter(([m, p]) => m === method && p.split("?")[0] === path)
        .map(([, , body]) => body),
    // Toasts shown so far, as [level, text].
    toasts: () =>
      [...doc.querySelectorAll(".toast")].map((toast) => [
        [...toast.classList].find((c) => c.startsWith("text-bg-")).slice(8),
        toast.querySelector(".toast-body").textContent,
      ]),
    async choose(id, value) {
      const select = typeof id === "string" ? doc.getElementById(id) : id;
      select.value = value;
      select.dispatchEvent(new page.window.Event("change", { bubbles: true }));
      await settle();
    },
    async type(id, value, event = "input") {
      const field = typeof id === "string" ? doc.getElementById(id) : id;
      field.value = value;
      field.dispatchEvent(new page.window.Event(event, { bubbles: true }));
      await settle();
    },
    async click(id) {
      (typeof id === "string" ? doc.getElementById(id) : id).click();
      await settle();
    },
    texts: (selector) =>
      [...doc.querySelectorAll(selector)].map((n) =>
        n.textContent.replace(/\s+/g, " ").trim(),
      ),
  };
}
