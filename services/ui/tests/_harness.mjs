// Imports the real app.js so V8 coverage maps to the first-party file; the
// shims are installed as globals before the import, like a browser would.
const shim = {
  createElement(tag = "div") {
    const node = {
      tagName: String(tag).toUpperCase(),
      children: [],
      style: {},
      dataset: {},
      classList: {
        add() {},
        remove() {},
        toggle() {},
        contains() {
          return false;
        },
      },
      innerHTML: "",
      textContent: "",
      value: "",
      addEventListener() {},
      appendChild() {},
      querySelector() {
        return null;
      },
      querySelectorAll() {
        return [];
      },
    };
    return node;
  },
};

shim.window = {
  location: {
    pathname: "/index.html",
    search: "",
    origin: "https://ospmae.test",
    href: "",
    hash: "",
    replace() {},
  },
  document: null,
  addEventListener() {},
  setTimeout: () => 0,
  clearTimeout: () => {},
  matchMedia: () => ({ matches: false }),
};
shim.document = {
  title: "",
  readyState: "complete",
  cookie: "",
  addEventListener() {},
  querySelector() {
    return null;
  },
  querySelectorAll() {
    return [];
  },
  getElementById() {
    return null;
  },
  createElement: shim.createElement,
  createElementNS: shim.createElement,
  body: shim.createElement("body"),
  documentElement: shim.createElement("html"),
};
shim.window.document = shim.document;
shim.window.downloadResponseAsFile = undefined;
shim.window.OSPMAE = undefined;

const originalWindow = globalThis.window;
const originalDocument = globalThis.document;

// The shims stay installed for the whole test process: the exported helpers
// resolve bare `document`/`window` at call time.
export async function loadApp() {
  globalThis.window = shim.window;
  globalThis.document = shim.document;
  await import("../public/app.js");
  assertOK();
  return shim.window.OSPMAE;
}

function assertOK() {
  if (!shim.window.OSPMAE) {
    throw new Error("app.js did not install window.OSPMAE");
  }
}
