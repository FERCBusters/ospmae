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
  { url, ospmae = {}, setup, withApp = false, api } = {},
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
      const text = payload === undefined ? "" : JSON.stringify(payload);
      const response = {
        ok: status >= 200 && status < 300,
        status,
        headers: { get: () => "application/json" },
        text: async () => text,
        json: async () => JSON.parse(text),
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
  await run(scriptPath);
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
