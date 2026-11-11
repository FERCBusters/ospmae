// The project page's actions: questions, subscriptions, manifests and chart
// exports, against an API fixture.
import test from "node:test";
import assert from "node:assert/strict";
import { account, projectPage } from "./support/project-page.mjs";

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const THREADS = {
  can_answer: false,
  items: [
    {
      id: 9,
      status: "answered",
      updated_at: "2026-03-05T10:00:00",
      created_by: { id: 7, username: "ada" },
      posts: [
        {
          id: 1,
          body: "Is it <b>audited</b>?",
          created_at: "2026-03-04T09:00:00",
          created_by: { id: 7, username: "ada" },
        },
        {
          id: 2,
          body: "Yes.\nYearly.",
          created_at: "2026-03-05T10:00:00",
          created_by: null,
        },
      ],
    },
    {
      id: 8,
      status: null,
      updated_at: null,
      created_by: { id: 99, username: "bob" },
      posts: [],
    },
  ],
};

async function questionsTab(t, options = {}) {
  const page = await projectPage(t, { hash: "#questions", ...options });
  await page.wait();
  return page;
}

function submit(page, form) {
  form.dispatchEvent(new page.window.Event("submit", { cancelable: true }));
  return page.wait();
}

test("an engineer reads threads, asks, and replies to their own", async (t) => {
  const posted = [];
  const page = await questionsTab(t, {
    me: account("engineer"),
    answers: { questions: THREADS },
    api: (method, path, body) => {
      if (method === "POST") {
        posted.push([path, body]);
        return [200, {}];
      }
      return null;
    },
  });
  assert.equal(page.$("questionsMeta").textContent, "You can ask questions.");
  assert.equal(page.$("questionsInfo").textContent, "");
  assert.equal(page.$("askQuestionBox").style.display, "");
  const cards = [...page.doc.querySelectorAll("#questionsList .card")];
  assert.equal(cards.length, 2);
  assert.match(cards[0].textContent, /Thread #9\s*• Answered/);
  assert.match(cards[1].textContent, /Thread #8\s*• Open/);
  const when = new Date("2026-03-05T10:00:00Z").toLocaleString();
  assert.ok(cards[0].textContent.includes(`Updated ${when}`));
  assert.ok(cards[0].textContent.includes(`unknown • ${when}`));
  // A post is text: markup in it is not rendered.
  assert.equal(cards[0].querySelector("b"), null);
  assert.ok(cards[0].textContent.includes("Is it <b>audited</b>?"));
  // The asker may follow up on their own thread, not on someone else's.
  assert.equal(cards[0].querySelectorAll("form").length, 1);
  assert.equal(cards[1].querySelectorAll("form").length, 0);

  const reply = cards[0].querySelector("form");
  await submit(page, reply);
  assert.deepEqual(posted, []); // an empty reply is not sent
  reply.querySelector("textarea").value = "  Thanks  ";
  await submit(page, reply);
  assert.deepEqual(posted, [["/v1/questions/9/reply", { body: "Thanks" }]]);

  page.$("askQuestionBody").value = "   ";
  await submit(page, page.$("askQuestionForm"));
  assert.equal(posted.length, 1);
  page.$("askQuestionBody").value = "How are keys rotated?";
  await submit(page, page.$("askQuestionForm"));
  assert.deepEqual(posted[1], [
    "/v1/projects/5/questions",
    { body: "How are keys rotated?" },
  ]);
  assert.equal(page.$("askQuestionBody").value, "");
  assert.deepEqual(page.toasts(), [
    ["success", "Reply sent"],
    ["success", "Question submitted"],
  ]);
  // Each post reloads the threads.
  assert.equal(
    page.asked().filter((r) => r === "GET /v1/projects/5/questions").length,
    3,
  );
});

test("an answerer may reply everywhere but not ask", async (t) => {
  const page = await questionsTab(t, {
    me: account("maintainer"),
    answers: { questions: { ...THREADS, can_answer: true } },
  });
  assert.equal(
    page.$("questionsMeta").textContent,
    "You can answer questions.",
  );
  assert.equal(page.$("askQuestionBox").style.display, "none");
  assert.equal(page.doc.querySelectorAll("#questionsList form").length, 2);

  const admin = await questionsTab(t, {
    answers: { questions: { items: [], can_answer: false } },
  });
  assert.equal(
    admin.$("questionsMeta").textContent,
    "You can ask questions. You can answer questions.",
  );
  assert.equal(admin.$("questionsInfo").textContent, "No questions yet.");
});

test("failures to load or post questions are reported", async (t) => {
  const failing = await questionsTab(t, {
    api: (method, path) =>
      path === "/v1/projects/5/questions" && method === "GET"
        ? [500, { detail: "Questions are unavailable" }]
        : null,
  });
  assert.equal(
    failing.$("questionsInfo").textContent,
    "Questions are unavailable",
  );

  const refused = await questionsTab(t, {
    answers: { questions: THREADS },
    api: (method) =>
      method === "POST" ? [403, { detail: "Not permitted" }] : null,
  });
  refused.$("askQuestionBody").value = "Why?";
  await submit(refused, refused.$("askQuestionForm"));
  const reply = refused.doc.querySelector("#questionsList form");
  reply.querySelector("textarea").value = "Because";
  await submit(refused, reply);
  assert.deepEqual(refused.toasts(), [
    ["danger", "Not permitted"],
    ["danger", "Not permitted"],
  ]);
});

test("a live notice refreshes open questions and marks hidden ones stale", async (t) => {
  const page = await questionsTab(t, { answers: { questions: THREADS } });
  const loads = () =>
    page.asked().filter((r) => r === "GET /v1/projects/5/questions").length;
  const notify = (detail) => {
    page.window.dispatchEvent(
      new page.window.CustomEvent("ospmae-notification", { detail }),
    );
    return page.wait();
  };
  assert.equal(loads(), 1);
  await notify({ kind: "project_question_replied", project_id: 5 });
  assert.equal(loads(), 2);
  // Notices for other projects, of other kinds, or empty change nothing.
  await notify({ kind: "project_question_created", project_id: 6 });
  await notify({ kind: "something_else", project_id: 5 });
  await notify(null);
  assert.equal(loads(), 2);

  // Away from the tab nothing is fetched, until the tab is opened again.
  await page.click("tabMetadataBtn");
  await notify({ kind: "project_question_created", project_id: "5" });
  assert.equal(loads(), 2);
  await page.click("tabQuestionsBtn");
  assert.equal(loads(), 3);
  await page.click("tabMetadataBtn");
  await page.click("tabQuestionsBtn");
  assert.equal(loads(), 3);
});

test("subscribing opens the choices and saves them", async (t) => {
  const sent = [];
  const page = await projectPage(t, {
    api: (method, path, body) => {
      if (path === "/v1/projects/5/subscription" && method === "POST") {
        sent.push(body);
        return [
          200,
          { subscribed: body.notify_new_versions || body.notify_questions },
        ];
      }
      return null;
    },
  });
  const button = page.$("subscribeBtn");
  assert.equal(button.textContent.trim(), "Subscribe");
  assert.ok(button.classList.contains("btn-outline-primary"));

  await page.click("subscribeBtn");
  const modal = page.$("subscriptionModal");
  assert.ok(modal.classList.contains("show"));
  // A new subscription starts with new versions on and questions off.
  assert.equal(page.$("subNotifyNewVersions").checked, true);
  assert.equal(page.$("subNotifyQuestions").checked, false);
  assert.equal(page.$("subscriptionUnsubscribeBtn").style.display, "none");
  assert.equal(button.hasAttribute("disabled"), false);

  page.$("subNotifyQuestions").checked = true;
  await page.click("subscriptionSaveBtn");
  assert.deepEqual(sent, [
    { notify_new_versions: true, notify_questions: true },
  ]);
  assert.equal(modal.classList.contains("show"), false);
  assert.equal(button.textContent.trim(), "Subscribed");
  assert.ok(button.classList.contains("btn-outline-secondary"));

  // Clearing every choice unsubscribes.
  page.$("subNotifyNewVersions").checked = false;
  page.$("subNotifyQuestions").checked = false;
  await page.click("subscriptionSaveBtn");
  assert.equal(button.textContent.trim(), "Subscribe");
  assert.deepEqual(page.toasts(), [
    ["success", "Subscription saved"],
    ["success", "Unsubscribed"],
  ]);
});

test("an existing subscription shows its choices and can be removed", async (t) => {
  const page = await projectPage(t, {
    answers: {
      project: {
        ...(await import("./support/project-page.mjs")).PROJECT,
        is_subscribed: true,
      },
      subscription: {
        subscribed: true,
        notify_new_versions: false,
        notify_questions: true,
      },
    },
  });
  assert.equal(page.$("subscribeBtn").textContent.trim(), "Subscribed");
  await page.click("subscribeBtn");
  assert.equal(page.$("subNotifyNewVersions").checked, false);
  assert.equal(page.$("subNotifyQuestions").checked, true);
  assert.equal(page.$("subscriptionUnsubscribeBtn").style.display, "");
  await page.click("subscriptionUnsubscribeBtn");
  assert.ok(page.asked().includes("DELETE /v1/projects/5/subscription"));
  assert.equal(page.$("subscribeBtn").textContent.trim(), "Subscribe");
  assert.equal(page.$("subscriptionModal").classList.contains("show"), false);
  assert.deepEqual(page.toasts(), [["success", "Unsubscribed"]]);
});

test("subscription failures explain themselves, with a tip about e-mail", async (t) => {
  const page = await projectPage(t, {
    api: (method, path) => {
      if (path !== "/v1/projects/5/subscription") return null;
      if (method === "POST")
        return [
          400,
          { detail: "You must have an email address available to subscribe." },
        ];
      if (method === "DELETE") return [500, { detail: "Try again" }];
      return null;
    },
  });
  await page.click("subscribeBtn");
  await page.click("subscriptionSaveBtn");
  await page.click("subscriptionUnsubscribeBtn");
  assert.deepEqual(page.toasts(), [
    ["danger", "You must have an email address available to subscribe."],
    ["info", "Tip: set your email address in Account → Profile."],
    ["danger", "Try again"],
  ]);
  assert.equal(page.$("subscribeBtn").textContent.trim(), "Subscribe");
  for (const id of ["subscriptionSaveBtn", "subscriptionUnsubscribeBtn"])
    assert.equal(page.$(id).hasAttribute("disabled"), false);

  const blocked = await projectPage(t, {
    api: (method, path) =>
      path === "/v1/projects/5/subscription"
        ? [500, { detail: "Subscriptions are down" }]
        : null,
  });
  await blocked.click("subscribeBtn");
  assert.deepEqual(blocked.toasts(), [["danger", "Subscriptions are down"]]);
  assert.equal(
    blocked.$("subscriptionModal").classList.contains("show"),
    false,
  );
});

test("without the modal markup the button toggles the subscription directly", async (t) => {
  const page = await projectPage(t, {
    setup: (window) =>
      window.document.getElementById("subscriptionModal").remove(),
  });
  await page.click("subscribeBtn");
  assert.equal(page.$("subscribeBtn").textContent.trim(), "Subscribed");
  await page.click("subscribeBtn");
  assert.equal(page.$("subscribeBtn").textContent.trim(), "Subscribe");
  assert.deepEqual(
    page.asked().filter((r) => r.includes("subscription")),
    ["POST /v1/projects/5/subscription", "DELETE /v1/projects/5/subscription"],
  );
  assert.deepEqual(page.toasts(), [
    ["success", "Subscribed"],
    ["success", "Unsubscribed"],
  ]);

  const refused = await projectPage(t, {
    setup: (window) =>
      window.document.getElementById("subscriptionModal").remove(),
    api: (method, path) =>
      path === "/v1/projects/5/subscription"
        ? [400, { detail: "No email on file" }]
        : null,
  });
  await refused.click("subscribeBtn");
  assert.deepEqual(refused.toasts(), [
    ["danger", "No email on file"],
    ["info", "Tip: set your email address in Account → Profile."],
  ]);
});

test("manifests export for the chosen version in each format", async (t) => {
  const page = await projectPage(t, {
    api: (method, path) =>
      path === "/v1/projects/5/manifest/export" ? [200, "file-body"] : null,
  });
  assert.equal(page.$("manifestExportField").style.display, "");
  assert.equal(
    page.$("projectManifestName").value,
    "wallet-kit_2.0.0_manifest",
  );
  for (const id of [
    "exportManifestJsonBtn",
    "exportManifestXlsxBtn",
    "exportManifestMdBtn",
  ])
    await page.click(id);
  const exports = page.asked().filter((r) => r.includes("/manifest/export"));
  assert.deepEqual(
    exports.map((r) =>
      Object.fromEntries(new URLSearchParams(r.split("?")[1])),
    ),
    ["json", "xlsx", "markdown"].map((format) => ({
      format,
      name: "wallet-kit_2.0.0_manifest",
      framework_id: "3",
      version_id: "12",
    })),
  );
  assert.deepEqual(
    page.record.downloads.map((d) => d.name),
    [
      "wallet-kit_2.0.0_manifest.json",
      "wallet-kit_2.0.0_manifest.xlsx",
      "wallet-kit_2.0.0_manifest.md",
    ],
  );
  assert.equal(page.record.blobs.length, 3);
});

test("a manifest is saved under the given or suggested name", async (t) => {
  const saved = [];
  const page = await projectPage(t, {
    api: (method, path, body) => {
      if (path === "/v1/projects/5/manifest/save") {
        saved.push(body);
        return saved.length === 3
          ? [403, { detail: "Not allowed" }]
          : [200, { name: body.name }];
      }
      if (path === "/v1/projects/5/manifest/export")
        return [500, { detail: "Export failed" }];
      return null;
    },
  });
  page.$("projectManifestName").value = " Board pack ";
  page.$("projectManifestDescription").value = " for review ";
  await page.click("saveProjectManifestBtn");
  assert.deepEqual(saved[0], {
    name: "Board pack",
    description: "for review",
    framework_id: 3,
    node_ids: [],
    project_ids: [5],
    q: null,
    owner_group_id: null,
  });
  assert.ok(
    page
      .asked()
      .includes(
        "POST /v1/projects/5/manifest/save?framework_id=3&version_id=12",
      ),
  );
  // A name the reader typed survives a change of version; a blank one is suggested.
  await page.choose("versionSelect", "11");
  assert.equal(page.$("projectManifestName").value, " Board pack ");
  page.$("projectManifestName").value = "";
  page.$("projectManifestDescription").value = "";
  await page.click("saveProjectManifestBtn");
  assert.equal(saved[1].name, "wallet-kit_1.0.0_manifest");
  assert.equal(saved[1].description, null);
  await page.click("saveProjectManifestBtn");
  await page.click("exportManifestJsonBtn");
  assert.deepEqual(page.toasts(), [
    ["success", "Saved manifest “Board pack”"],
    ["success", "Saved manifest “wallet-kit_1.0.0_manifest”"],
    ["danger", "Not allowed"],
    ["danger", "Export failed"],
  ]);
  assert.equal(page.record.downloads.length, 0);
});

test("manifest controls are hidden from roles that cannot export", async (t) => {
  const page = await projectPage(t, { me: account("viewer") });
  assert.equal(page.$("manifestExportField").style.display, "none");
});

test("a chart exports as an image or a PDF named after project and version", async (t) => {
  const page = await projectPage(t);
  await page.click("exportGraphJpegBtn");
  await pause(20);
  assert.deepEqual(page.record.downloads, [
    {
      name: "wallet-kit_2.0.0_capabilities.jpg",
      href: "data:image/jpeg;base64,AAAA",
    },
  ]);
  // The chart is serialised as it stands, with its labels.
  const svg = decodeURIComponent(page.record.images[0].split(",")[1]);
  assert.ok(svg.startsWith("<svg"));
  assert.ok(svg.includes("Issuer"));
  const canvas = page.record.canvases[0];
  assert.ok(canvas.width > 0 && canvas.height > 0);

  await page.click("exportGraphPdfBtn");
  await pause(20);
  const [pdf] = page.record.pdfs;
  assert.equal(pdf.name, "wallet-kit_2.0.0_capabilities.pdf");
  assert.equal(
    pdf.orientation,
    canvas.width >= canvas.height ? "landscape" : "portrait",
  );
  // The image is centred inside the page margins.
  assert.equal(pdf.image.format, "JPEG");
  assert.ok(pdf.image.x >= 8 && pdf.image.y >= 8);
  assert.ok(
    pdf.image.width <= 297 - 16 + 1e-9 && pdf.image.height <= 210 - 16 + 1e-9,
  );

  await page.click("tabDependencyBtn");
  await page.click("exportDepJpegBtn");
  await pause(20);
  await page.click("exportDepPdfBtn");
  await pause(20);
  assert.equal(
    page.record.downloads[1].name,
    "wallet-kit_2.0.0_dependencies.jpg",
  );
  assert.equal(page.record.pdfs[1].name, "wallet-kit_2.0.0_dependencies.pdf");
  assert.ok(
    decodeURIComponent(page.record.images[2].split(",")[1]).includes(
      "requests@2.31.0",
    ),
  );
});

test("exports say so when there is nothing drawn or no PDF library", async (t) => {
  const page = await projectPage(t, { pdf: false, d3: false });
  await page.click("exportGraphJpegBtn");
  assert.deepEqual(page.toasts(), [
    ["danger", "Nothing to export yet (no graph rendered)"],
  ]);

  const noPdf = await projectPage(t, { pdf: false });
  await noPdf.click("exportGraphPdfBtn");
  await pause(20);
  assert.deepEqual(noPdf.toasts(), [
    ["danger", "PDF export library (jsPDF) is not available"],
  ]);
  assert.equal(noPdf.record.pdfs.length, 0);
});
