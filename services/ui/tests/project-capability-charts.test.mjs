// The capability charts' interactions on the project page: zooming the
// sunburst, the treemap's labels for narrow groups, and the chart drawn
// from a version's capability paths when the graph has no tree.
import test from "node:test";
import assert from "node:assert/strict";
import {
  PROJECT,
  VERSIONS,
  capabilityGraph,
  projectPage,
} from "./support/project-page.mjs";

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const press = (page, node) =>
  node.dispatchEvent(new page.window.MouseEvent("click", { bubbles: true }));

test("clicking a sunburst segment zooms into it, and the centre zooms back out", async (t) => {
  const page = await projectPage(t);
  await page.choose("visualTypeSelect", "sunburst");
  const arcs = () =>
    Object.fromEntries(
      [...page.doc.querySelectorAll("#graph svg path")].map((path) => [
        path
          .querySelector("title")
          .textContent.split("\n")[0]
          .split(" > ")
          .pop(),
        path.getAttribute("pointer-events"),
      ]),
    );
  const before = arcs();
  assert.equal(before.Issuer, "auto");

  const wallet = [...page.doc.querySelectorAll("#graph svg path")].find(
    (path) =>
      path.querySelector("title").textContent.split("\n")[0].endsWith("Wallet"),
  );
  press(page, wallet);
  await pause(900);
  // Wallet's branch fills the chart; its sibling leaves the view.
  assert.equal(arcs().Issuer, "none");
  assert.equal(arcs().Keys, "auto");

  // The centre steps out one level at a time.
  press(page, page.doc.querySelector("#graph svg circle"));
  await pause(900);
  assert.equal(arcs().Issuer, "auto");
  press(page, page.doc.querySelector("#graph svg circle"));
  await pause(900);
  assert.deepEqual(arcs(), before);
  assert.deepEqual(page.errors, []);
});

test("a graph without a tree is drawn from the version's capability paths", async (t) => {
  const page = await projectPage(t, {
    answers: { graph: { ...capabilityGraph(), capability_tree: [] } },
  });
  const drawn = new Set(
    page.texts("#graph svg title").map((title) => title.split("\n")[0]),
  );
  for (const name of ["Wallet", "Storage", "Keys", "Issuer"])
    assert.ok(
      [...drawn].some((title) => title.endsWith(name)),
      `${name} in ${[...drawn].join(" | ")}`,
    );
  assert.deepEqual(page.errors, []);
});

test("a version that maps nothing draws nothing from another version's paths", async (t) => {
  const bare = { ...VERSIONS[0], capability_paths: [] };
  const page = await projectPage(t, {
    answers: {
      project: {
        ...PROJECT,
        versions: [bare, ...VERSIONS.slice(1)],
        latest_version: bare,
      },
      graph: { ...capabilityGraph(), capability_tree: [] },
    },
  });
  // Only the version's own tile is left.
  assert.equal(
    page.$("visualSummary").textContent,
    "1 tiles • focus: Wallet Kit",
  );
  assert.doesNotMatch(page.$("graph").textContent, /Wallet > |Issuer|Keys/);
});

// One large group beside a small one leaves the small one a narrow, tall
// strip of the chart.
function lopsidedGraph() {
  let id = 100;
  const group = (name, size) => ({
    id: (id += 1),
    key: name.toLowerCase(),
    display_name: name,
    level: 0,
    selected: false,
    children: Array.from({ length: size }, (_, i) => ({
      id: (id += 1),
      key: `${name}_${i}`.toLowerCase(),
      display_name: `${name} part ${i + 1}`,
      level: 1,
      selected: true,
      children: [],
    })),
  });
  return {
    ...capabilityGraph(),
    capability_tree: [group("Broad", 40), group("Slim", 1)],
  };
}

test("a narrow group in the treemap carries its name on a vertical strip", async (t) => {
  const page = await projectPage(t, { answers: { graph: lopsidedGraph() } });
  const strip = (name) =>
    [...page.doc.querySelectorAll("#graph svg g.container-label")].find(
      (label) => label.querySelector("tspan").textContent.startsWith(name),
    );
  const slim = strip("Slim");
  const broad = strip("Broad");
  // The tiles ease into place; wait for the chart to settle.
  for (
    let i = 0;
    i < 60 && !slim.querySelector("text").getAttribute("transform");
    i += 1
  )
    await pause(100);
  await pause(700);
  assert.match(
    slim.querySelector("text").getAttribute("transform"),
    /^translate\([\d.]+, ?[\d.]+\) rotate\(-90\)$/,
  );
  assert.equal(broad.querySelector("text").getAttribute("transform"), null);
  // The turned strip is as tall as its group and shows the name alone.
  const [, count] = slim.querySelectorAll("tspan");
  assert.equal(count.textContent, "");
  assert.equal(
    broad.querySelectorAll("tspan")[1].textContent,
    "40 capabilities",
  );
  const size = (label, side) =>
    Number(label.querySelector("rect").getAttribute(side));
  assert.ok(size(slim, "height") > 4 * size(slim, "width"));
  assert.ok(size(broad, "width") > 4 * size(broad, "height"));
  assert.deepEqual(page.errors, []);
});
