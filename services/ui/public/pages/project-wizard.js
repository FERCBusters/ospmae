// Project editor wizard: confirms inputs one step at a time while keeping
// every editor element in the DOM, so pages/project-edit.js reads and saves
// the whole form at once. Saving belongs to the final step only: a Save
// beside Next would read as a second way forward. Next checks the step it
// leaves, so the final step is reached with the earlier steps complete. The
// framework-options step is presented only when the frameworks feature is
// on; otherwise it is removed and blank values save, so no capability fields
// leak into non-framework deployments.

const OSPMAE = window.OSPMAE;
const { api: apiFetch, ensureInitialized, featureOn } = OSPMAE;

const STEPS = ["Identity", "Links & releases", "Framework options"];

let current = 0;

function sections() {
  return [1, 2, 3]
    .map((n) => document.getElementById(`projectWizardStep${n}`))
    .filter((s) => s && document.body.contains(s));
}

function go(index) {
  const steps = sections();
  current = Math.max(0, Math.min(index, steps.length - 1));
  const last = current === steps.length - 1;
  steps.forEach((section, i) => {
    section.hidden = i !== current;
  });
  const indicator = document.getElementById("wizardIndicator");
  if (indicator)
    indicator.textContent = `Step ${current + 1}: ${STEPS[current]}`;
  const prev = document.getElementById("wizardPrev");
  const next = document.getElementById("wizardNext");
  const save = document.getElementById("saveProjectBtn");
  if (prev) prev.hidden = current === 0;
  if (next) {
    next.textContent = current === steps.length - 2 ? "Final step ➜" : "Next ➜";
    next.hidden = last;
  }
  if (save) save.hidden = !last;
}

// The browser's own constraint checks (required, min/max, maxlength) on
// the fields this step shows; hidden groups are not part of the step.
function stepIsComplete(section) {
  for (const field of section.querySelectorAll("input, select, textarea")) {
    if (field.closest("[hidden]")) continue;
    if (!field.checkValidity()) {
      field.reportValidity();
      return false;
    }
  }
  return true;
}

function wire() {
  const next = document.getElementById("wizardNext");
  const prev = document.getElementById("wizardPrev");
  next?.addEventListener("click", () => {
    const steps = sections();
    if (steps[current] && !stepIsComplete(steps[current])) return;
    go(current + 1);
  });
  prev?.addEventListener("click", () => go(current - 1));
}

function prepareSteps() {
  const steps = sections();
  if (steps.length >= 3 && !featureOn("frameworks")) {
    // No framework step without the feature: blank capability values save.
    steps[2].remove();
  }
  go(0);
}

async function onStart() {
  // Feature switches arrive with the signed-in user.
  await ensureInitialized();
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
  prepareSteps();
}

onStart();
