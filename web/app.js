// Ringtail web page: wiring for the browser half of ADR 0003.
//
// The loop and rendering live in ringtail-client.js and ringtail-ui.js, shared with the
// extension. The user's key lives only in the `key` input (page memory) and is sent only
// to api.anthropic.com. The Ringtail backend builds prompts and runs every check.

import {
  MODEL_RE, ServerError, StopRun, createClient, keyProblem, runLoop,
} from "./ringtail-client.js";
import {
  createProgress, download, renderResult, setupTabs, usageText,
} from "./ringtail-ui.js";

const $ = (id) => document.getElementById(id);
const el = {
  key: $("key"), model: $("model"), forget: $("forget"), keyProblem: $("key-problem"),
  access: $("access"), accessRow: $("access-row"), accessNote: $("access-note"),
  input: $("input"), run: $("run"), stop: $("stop"), chars: $("chars"),
  progressPanel: $("progress-panel"), log: $("log"), usage: $("usage"),
  resultPanel: $("result-panel"),
};
const out = {
  summary: $("summary"), rule: $("out-rule"), card: $("out-card"),
  tp: $("out-tp"), fp: $("out-fp"), siem: $("out-siem"),
};

let maxAttempts = 3;
let controller = null;
let result = null;
const usage = { input: 0, output: 0, calls: 0 };
const progress = createProgress(el.log);
const selectTab = setupTabs($("result-panel"));

const client = createClient({
  baseUrl: "",
  getAccessCode: () => el.access.value,
  onUsage: ({ input, output }) => {
    usage.calls += 1;
    usage.input += input;
    usage.output += output;
    el.usage.textContent = usageText(usage);
  },
});

function showKeyProblem(msg) {
  el.keyProblem.textContent = msg || "";
  el.keyProblem.hidden = !msg;
}

function showAccessField(on) {
  el.accessRow.hidden = !on;
  el.accessNote.hidden = !on;
}

function setRunning(on) {
  el.run.disabled = on;
  el.stop.hidden = !on;
  el.input.readOnly = on;
  el.key.readOnly = on;
  el.access.readOnly = on;
  el.model.readOnly = on;
}

async function start() {
  const key = el.key.value;
  const problem = keyProblem(key);
  showKeyProblem(problem);
  if (problem) { el.key.focus(); return; }
  const model = el.model.value.trim();
  if (!MODEL_RE.test(model)) { showKeyProblem("Model name looks wrong (e.g. claude-opus-5-5)."); el.model.focus(); return; }
  const text = el.input.value;
  if (!text.trim()) { el.input.focus(); return; }

  progress.clear();
  // Counts are per run, not per tab.
  usage.input = 0; usage.output = 0; usage.calls = 0;
  el.usage.textContent = "";
  el.resultPanel.hidden = true;
  el.progressPanel.hidden = false;
  result = null;
  controller = new AbortController();
  setRunning(true);
  try {
    result = await runLoop({ text, key, model, maxAttempts, client, signal: controller.signal, log: progress });
    progress.line("Done. Review the rule below before using it.", "ok");
    renderResult(out, result);
    selectTab("tab-rule");
    el.resultPanel.hidden = false;
    el.resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    if (e instanceof StopRun) {
      progress.line("Stopped.", "bad");
    } else {
      progress.failBusy();
      progress.line(e.message || "Something went wrong.", "bad");
      if (e instanceof ServerError && e.status === 401) {
        showAccessField(true);
        el.access.focus();
      }
    }
  } finally {
    controller = null;
    setRunning(false);
  }
}

el.run.addEventListener("click", start);
el.stop.addEventListener("click", () => controller && controller.abort());
el.forget.addEventListener("click", () => { el.key.value = ""; showKeyProblem(null); el.key.focus(); });
el.key.addEventListener("input", () => showKeyProblem(null));
el.input.addEventListener("input", () => {
  const n = el.input.value.length;
  el.chars.textContent = n > 50000 ? `${n.toLocaleString()} / 60,000 characters` : "";
});
el.input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && !el.run.disabled) start();
});
for (const chip of document.querySelectorAll("[data-example]")) {
  chip.addEventListener("click", () => { el.input.value = chip.dataset.example; el.input.focus(); });
}
for (const btn of document.querySelectorAll("[data-download]")) {
  btn.addEventListener("click", () => download(document, result, btn.dataset.download));
}

// Versions from the server, so the page never drifts from the pinned ATT&CK data.
client.health()
  .then((info) => {
    if (typeof info.attack_version === "string") $("attack-version").textContent = `v${info.attack_version}`;
    if (Number.isInteger(info.max_attempts)) maxAttempts = info.max_attempts;
    if (info.access_code_required === true) showAccessField(true);
    if (typeof info.default_model === "string" && MODEL_RE.test(info.default_model)) el.model.value = info.default_model;
  })
  .catch(() => {});
