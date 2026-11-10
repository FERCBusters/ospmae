// Project editor wizard: confirms inputs one step at a time while keeping
// every existing editor element in the DOM, so the project-manage page
// logic reads and saves exactly as before. The framework-options step is
// presented only when the frameworks feature is on; otherwise it is
// removed and blank values save, so no capability fields leak into
// non-framework deployments.

const OSPMAE = window.OSPMAE;
const { api: apiFetch, ensureInitialized, featureOn } = OSPMAE;

const STEPS = ["Identity", "Links & releases", "Framework options"];

function sections() {
  return [1, 2, 3]
    .map((n) => document.getElementById(`projectWizardStep${n}`))
    .filter((s) => s && document.body.contains(s));
}

function go(index) {
  const steps = sections();
  const current = Math.max(0, Math.min(index, steps.length - 1));
  steps.forEach((section, i) => {
    section.hidden = i !== current;
  });
  const indicator = document.getElementById("wizardIndicator");
  if (indicator)
    indicator.textContent = `Step ${current + 1}: ${STEPS[current]}`;
  const prev = document.getElementById("wizardPrev");
  const next = document.getElementById("wizardNext");
  if (prev) prev.hidden = current === 0;
  if (next) {
    next.textContent = current >= steps.length - 2 ? "Final step ➜" : "Next ➜";
    next.hidden = current === steps.length - 1;
  }
}

function wire() {
  const next = document.getElementById("wizardNext");
  const prev = document.getElementById("wizardPrev");
  let current = 0;
  next?.addEventListener("click", () => {
    current = Math.min(current + 1, sections().length - 1);
    go(current);
  });
  prev?.addEventListener("click", () => {
    current = Math.max(current - 1, 0);
    go(current);
  });
}

function prepareSteps() {
  const steps = sections();
  if (steps.length < 3) return go(0);
  if (!featureOn("frameworks")) {
    // No framework step without the feature: blank capability values save.
    steps[2].remove();
  }
  go(0);
}

async function onStart() {
  const editor = document.getElementById("projectEditorCard");
  const datalist = document.getElementById("organisationOptions");
  try {
    const orgs = await apiFetch("/v1/organisations");
    if (datalist && Array.isArray(orgs)) {
      for (const org of orgs) {
        const option = document.createElement("option");
        option.value = org.name;
        datalist.append(option);
      }
    }
  } catch {}

  wire();
  if (editor && editor.style.display !== "none") {
    prepareSteps();
  } else if (editor) {
    const observer = new MutationObserver(() => {
      if (editor.style.display !== "none" && document.body.contains(editor)) {
        observer.disconnect();
        prepareSteps();
      }
    });
    observer.observe(editor, { attributes: true, attributeFilter: ["style"] });
  }
}

onStart();
