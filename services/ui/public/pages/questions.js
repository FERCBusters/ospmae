const {
  api: apiFetch,
  initAuth,
  canAnswerQuestions,
  refreshQuestionBell,
  escapeHtml,
} = window.OSPMAE;

const el = {
  whoami: document.getElementById("whoami"),
  list: document.getElementById("questionsList"),
  count: document.getElementById("questionsCount"),
  notPermitted: document.getElementById("notPermitted"),
  refreshBtn: document.getElementById("refreshBtn"),
};

function formatDateTime(iso) {
  return window.OSPMAE.formatTimestamp(iso);
}

function render(items) {
  const rows = (items || [])
    .map((it) => {
      const projectName = escapeHtml(
        it.project_display_name || `Project #${it.project_id}`,
      );
      const askedBy = escapeHtml(it.asked_by?.username || "unknown");
      const askedAt = formatDateTime(it.asked_at);
      const updatedAt = formatDateTime(it.updated_at);
      const preview = escapeHtml(it.question_preview || "");
      const href = `/project.html?id=${encodeURIComponent(it.project_id)}&tab=questions`;

      return `
      <tr>
        <td>${updatedAt}</td>
        <td><a href="${href}">${projectName}</a></td>
        <td>${askedBy}</td>
        <td title="Asked: ${askedAt}">${preview}</td>
        <td style="white-space:nowrap;"><a class="btn btn-secondary" href="${href}">Open</a></td>
      </tr>
    `;
    })
    .join("");

  if (!items || items.length === 0) {
    el.list.innerHTML = '<div class="small">No unanswered questions 🎉</div>';
    return;
  }

  el.list.innerHTML = `
    <table class="table" style="width:100%;">
      <thead>
        <tr>
          <th>Updated</th>
          <th>Project</th>
          <th>Asked by</th>
          <th>Question</th>
          <th data-nosort="1">Action</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;
}

async function load() {
  if (!canAnswerQuestions()) {
    el.notPermitted.style.display = "";
    el.notPermitted.textContent =
      "Not permitted to view the unanswered questions inbox.";
    el.list.innerHTML = "";
    el.count.textContent = "";
    return;
  }

  try {
    const data = await apiFetch("/v1/questions/unanswered", {
      allowErrorStatuses: [403],
    });
    if (data?.detail) {
      el.notPermitted.style.display = "";
      el.notPermitted.textContent = String(data.detail);
      el.list.innerHTML = "";
      el.count.textContent = "";
      return;
    }

    const items = data?.items || [];
    const n = Number(data?.open_count ?? items.length ?? 0);
    el.notPermitted.style.display = "none";
    el.count.textContent = n ? `${n} open` : "";
    render(items);
    refreshQuestionBell();
  } catch (e) {
    el.notPermitted.style.display = "";
    el.notPermitted.textContent = e?.message
      ? `Error: ${e.message}`
      : "Error loading questions.";
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const me = await initAuth({ redirectOnFail: true });
  if (window.OSPMAE && !window.OSPMAE.gateFeature("questions")) return null;
  if (el.whoami && me) {
    const r = me.effective_role || me.role || "viewer";
    el.whoami.textContent = `${me.username} (${r})`;
  }

  if (el.refreshBtn) {
    el.refreshBtn.addEventListener("click", (ev) => {
      ev.preventDefault();
      load();
    });
  }

  window.addEventListener("ospmae-notification", (ev) => {
    const msg = ev?.detail;
    if (!msg) return;
    if (
      msg.kind === "project_question_created" ||
      msg.kind === "project_question_replied"
    ) {
      load();
    }
  });

  await load();
});
