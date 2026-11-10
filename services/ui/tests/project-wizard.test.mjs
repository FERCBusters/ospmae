import test from "node:test";
import assert from "node:assert/strict";

// The project editor wizard against a minimal DOM: Save belongs to the final
// step only, and Next refuses to leave a step whose fields fail the
// browser's own constraint checks.

function field(valid = true) {
  return {
    valid,
    reported: 0,
    closest() {
      return null;
    },
    checkValidity() {
      return this.valid;
    },
    reportValidity() {
      this.reported += 1;
      return this.valid;
    },
  };
}

function element(id, fields = []) {
  return {
    id,
    hidden: false,
    removed: false,
    textContent: "",
    listeners: {},
    addEventListener(type, fn) {
      (this.listeners[type] ||= []).push(fn);
    },
    click() {
      for (const fn of this.listeners.click || []) fn();
    },
    querySelectorAll() {
      return fields;
    },
    remove() {
      this.removed = true;
    },
  };
}

async function loadWizard({ frameworks = true, tag }) {
  const step1Fields = [field(false)];
  const els = {
    projectWizardStep1: element("projectWizardStep1", step1Fields),
    projectWizardStep2: element("projectWizardStep2", [field(true)]),
    projectWizardStep3: element("projectWizardStep3", []),
    wizardIndicator: element("wizardIndicator"),
    wizardPrev: element("wizardPrev"),
    wizardNext: element("wizardNext"),
    saveProjectBtn: element("saveProjectBtn"),
  };
  els.saveProjectBtn.hidden = true;
  globalThis.document = {
    body: {
      contains(node) {
        return !node.removed;
      },
    },
    getElementById(id) {
      return els[id] || null;
    },
    createElement() {
      return {};
    },
  };
  globalThis.window = {
    OSPMAE: {
      api: async () => [],
      ensureInitialized: async () => ({ username: "u" }),
      featureOn: (name) => (name === "frameworks" ? frameworks : true),
    },
  };
  await import(`../public/pages/project-wizard.js?${tag}`);
  // Let onStart's awaits settle.
  for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));
  return { els, step1Fields };
}

test("Save appears on the final step only, and Next checks each step", async () => {
  const { els, step1Fields } = await loadWizard({ tag: "three-steps" });
  assert.equal(els.wizardIndicator.textContent, "Step 1: Identity");
  assert.equal(els.saveProjectBtn.hidden, true);
  assert.equal(els.wizardPrev.hidden, true);
  assert.equal(els.wizardNext.hidden, false);

  // An incomplete step stays put and the browser reports why.
  els.wizardNext.click();
  assert.equal(els.wizardIndicator.textContent, "Step 1: Identity");
  assert.equal(step1Fields[0].reported, 1);

  step1Fields[0].valid = true;
  els.wizardNext.click();
  assert.equal(els.wizardIndicator.textContent, "Step 2: Links & releases");
  assert.equal(els.wizardNext.textContent, "Final step ➜");
  assert.equal(els.saveProjectBtn.hidden, true);

  els.wizardNext.click();
  assert.equal(els.wizardIndicator.textContent, "Step 3: Framework options");
  assert.equal(els.saveProjectBtn.hidden, false);
  assert.equal(els.wizardNext.hidden, true);

  els.wizardPrev.click();
  assert.equal(els.saveProjectBtn.hidden, true);
  assert.equal(els.wizardNext.hidden, false);
});

test("without frameworks the second step is the final one", async () => {
  const { els, step1Fields } = await loadWizard({
    frameworks: false,
    tag: "two-steps",
  });
  assert.equal(els.projectWizardStep3.removed, true);
  step1Fields[0].valid = true;
  assert.equal(els.wizardNext.textContent, "Final step ➜");
  els.wizardNext.click();
  assert.equal(els.wizardIndicator.textContent, "Step 2: Links & releases");
  assert.equal(els.saveProjectBtn.hidden, false);
  assert.equal(els.wizardNext.hidden, true);
});
