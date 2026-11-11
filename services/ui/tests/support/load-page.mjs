// Load a real OSPMAE page (its HTML and a classic page script) into jsdom.
// Ported from KEEN's support/load-ui.mjs for OSPMAE's classic scripts: only
// window.OSPMAE (app.js, the network boundary) is substituted, and the page
// script runs unchanged under its own file URL so coverage maps to it.
import { JSDOM, VirtualConsole } from "jsdom";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const publicRoot = new URL("../../public/", import.meta.url);

export async function loadPage(
  htmlPath,
  scriptPath,
  { url, ospmae = {}, setup, withApp = false, api, libraries = [] } = {},
) {
  const html = await readFile(new URL(htmlPath, publicRoot), "utf8");
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (error) => errors.push(error));
  const dom = new JSDOM(html, {
    url: url || `https://ospmae.example/${htmlPath}`,
    runScripts: "outside-only",
    virtualConsole,
  });
  const { window } = dom;
  const requests = [];
  const context = dom.getInternalVMContext();
  async function run(path) {
    const fileUrl = new URL(path, publicRoot);
    const source = await readFile(fileUrl, "utf8");
    new vm.Script(source, { filename: fileUrl.href }).runInContext(context);
  }
  // Third-party libraries a page loads from /vendor (d3, say), run from the
  // test dependencies before any first-party script.
  for (const library of libraries) {
    new vm.Script(await readFile(library, "utf8"), {
      filename: library.href,
    }).runInContext(context);
  }
  if (withApp) {
    // The real app.js, with only the network replaced: `api(method, path,
    // body)` answers each request as [status, body].
    window.fetch = async (input, init = {}) => {
      const target = new URL(String(input), window.location.href);
      const method = String(init.method || "GET").toUpperCase();
      const body = init.body ? JSON.parse(init.body) : undefined;
      requests.push([method, target.pathname + target.search, body]);
      const [status, payload] = (await api(method, target.pathname, body)) || [
        200,
        {},
      ];
      // A string answer is a download body; anything else is JSON.
      const raw = typeof payload === "string";
      const text =
        payload === undefined ? "" : raw ? payload : JSON.stringify(payload);
      const response = {
        ok: status >= 200 && status < 300,
        status,
        headers: {
          get: (name) =>
            String(name).toLowerCase() === "content-type"
              ? raw
                ? "application/octet-stream"
                : "application/json"
              : null,
        },
        text: async () => text,
        json: async () => JSON.parse(text),
        blob: async () => new window.Blob([text]),
        clone: () => response,
      };
      return response;
    };
    await run("app.js");
  } else {
    window.OSPMAE = {
      ensureInitialized: async () => {},
      isAdmin: () => true,
      featureOn: () => true,
      ...ospmae,
    };
  }
  setup?.(window);
  // A page may load several first-party scripts. A browser runs deferred
  // scripts one after another with no network answer arriving in between, so
  // the sources are read first and then run back to back.
  const pageScripts = [];
  for (const path of [scriptPath].flat()) {
    const fileUrl = new URL(path, publicRoot);
    pageScripts.push([fileUrl, await readFile(fileUrl, "utf8")]);
  }
  for (const [fileUrl, source] of pageScripts)
    new vm.Script(source, { filename: fileUrl.href }).runInContext(context);
  if (withApp)
    window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
  return {
    requests,
    window,
    document: window.document,
    errors,
    settle: () => new Promise((resolve) => setTimeout(resolve, 0)),
    close: () => window.close(),
  };
}
