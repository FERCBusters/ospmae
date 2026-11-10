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
  { url, ospmae = {}, setup } = {},
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
  window.OSPMAE = {
    ensureInitialized: async () => {},
    isAdmin: () => true,
    featureOn: () => true,
    ...ospmae,
  };
  setup?.(window);
  const scriptUrl = new URL(scriptPath, publicRoot);
  const source = await readFile(scriptUrl, "utf8");
  new vm.Script(source, { filename: scriptUrl.href }).runInContext(
    dom.getInternalVMContext(),
  );
  return {
    window,
    document: window.document,
    errors,
    settle: () => new Promise((resolve) => setTimeout(resolve, 0)),
    close: () => window.close(),
  };
}
