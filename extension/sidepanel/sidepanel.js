// Ringtail side panel: the same loop as the web page, inside the extension (ADR 0005).
//
// Storage rules (threat model T7):
// - SECRETS (API key, access code, pending selection) live only in chrome.storage.session:
//   in memory, wiped when the browser quits, never on disk, not readable by websites.
// - PREFS (server URL, model name) are not secret and may persist in chrome.storage.local.
// The key is sent only to api.anthropic.com; the access code only to the Ringtail server.

import {
  MODEL_RE, ServerError, StopRun, createClient, keyProblem, runLoop,
} from "../lib/ringtail-client.js";
import {
  createProgress, download, renderResult, setupTabs, usageText,
} from "../lib/ringtail-ui.js";

const DEFAULT_BACKEND = "https://web-production-34d65045.up.railway.app";
const SECRETS = chrome.storage.session;
const PREFS = chrome.storage.local;

const $ = (id) => document.getElementById(id);
const el = {
  key: $("key"), model: $("model"), forget: $("forget"), keyProblem: $("key-problem"),
  access: $("access"), accessRow: $("access-row"),
  input: $("input"), selectionNote: $("selection-note"), run: $("run"), stop: $("stop"),
  progressPanel: $("progress-panel"), log: $("log"), usage: $("usage"),
  resultPanel: $("result-panel"),
  backend: $("backend"), saveBackend: $("save-backend"), resetBackend: $("reset-backend"),
  backendStatus: $("backend-status"),
};
const out = {
  summary: $("summary"), rule: $("out-rule"), card: $("out-card"),
  tp: $("out-tp"), fp: $("out-fp"), siem: $("out-siem"),
};

let backendUrl = DEFAULT_BACKEND;
let maxAttempts = 3;
let controller = null;
let result = null;
const usage = { input: 0, output: 0, calls: 0 };
const progress = createProgress(el.log);
const selectTab = setupTabs($("result-panel"));

function makeClient() {
  return createClient({
    baseUrl: backendUrl,
    getAccessCode: () => el.access.value,
    onUsage: ({ input, output }) => {
      usage.calls += 1;
      usage.input += input;
      usage.output += output;
      el.usage.textContent = usageText(usage);
    },
  });
}
let client = makeClient();

function showKeyProblem(msg) {
  el.keyProblem.textContent = msg || "";
  el.keyProblem.hidden = !msg;
}

function setRunning(on) {
  el.run.disabled = on;
  el.stop.hidden = !on;
  for (const f of [el.input, el.key, el.access, el.model]) f.readOnly = on;
}

// --- selection hand-off from the context menu ------------------------------------------

function takeSelection(sel) {
  if (!sel || typeof sel.text !== "string" || !sel.text.trim()) return;
  el.input.value = sel.text;
  el.selectionNote.hidden = false;
  SECRETS.remove("pendingSelection");
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.pendingSelection && changes.pendingSelection.newValue && !controller) {
    takeSelection(changes.pendingSelection.newValue);
  }
});

// --- server settings -------------------------------------------------------------------

function normalizeServer(raw) {
  let u;
  try { u = new URL(String(raw).trim()); } catch { return null; }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) return null;
  return u.origin;
}

async function loadServerInfo() {
  try {
    const info = await client.health();
    if (Number.isInteger(info.max_attempts)) maxAttempts = info.max_attempts;
    el.accessRow.hidden = info.access_code_required !== true && !el.access.value;
    if (typeof info.default_model === "string" && MODEL_RE.test(info.default_model) && !el.model.dataset.userSet) {
      el.model.value = info.default_model;
    }
    el.backendStatus.textContent = `Connected: ${backendUrl} (ATT&CK v${info.attack_version}).`;
  } catch {
    el.backendStatus.textContent = `Can't reach ${backendUrl}. Check the address, or use the default.`;
  }
}

async function useServer(origin) {
  backendUrl = origin;
  el.backend.value = origin;
  client = makeClient();
  await PREFS.set({ backendUrl: origin === DEFAULT_BACKEND ? null : origin });
  await loadServerInfo();
}

el.saveBackend.addEventListener("click", async () => {
  const origin = normalizeServer(el.backend.value);
  if (!origin) {
    el.backendStatus.textContent = "Use an https:// address (or http://localhost for a local server).";
    return;
  }
  if (origin !== DEFAULT_BACKEND) {
    // Ask for exactly this one origin, now, from the click. Never broad access at install.
    const granted = await chrome.permissions.request({ origins: [origin + "/*"] });
    if (!granted) {
      el.backendStatus.textContent = "Permission not granted, so the server wasn't changed.";
      return;
    }
  }
  await useServer(origin);
});

el.resetBackend.addEventListener("click", () => useServer(DEFAULT_BACKEND));

// --- run ---------------------------------------------------------------------------------

async function start() {
  const key = el.key.value;
  const problem = keyProblem(key);
  showKeyProblem(problem);
  if (problem) { el.key.focus(); return; }
  const model = el.model.value.trim();
  if (!MODEL_RE.test(model)) { showKeyProblem("Model name looks wrong (e.g. claude-opus-5-5)."); el.model.focus(); return; }
  const text = el.input.value;
  if (!text.trim()) { el.input.focus(); return; }

  await SECRETS.set({ apiKey: key, accessCode: el.access.value.trim() });
  el.selectionNote.hidden = true;
  progress.clear();
  usage.input = 0; usage.output = 0; usage.calls = 0;
  el.usage.textContent = "";
  el.resultPanel.hidden = true;
  el.progressPanel.hidden = false;
  result = null;
  controller = new AbortController();
  setRunning(true);
  try {
    result = await runLoop({ text, key, model, maxAttempts, client, signal: controller.signal, log: progress });
    progress.line("Done. Review the rule before using it.", "ok");
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
        el.accessRow.hidden = false;
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
el.forget.addEventListener("click", async () => {
  el.key.value = "";
  el.access.value = "";
  await SECRETS.remove(["apiKey", "accessCode"]);
  showKeyProblem(null);
  el.key.focus();
});
el.key.addEventListener("input", () => showKeyProblem(null));
el.model.addEventListener("change", () => {
  el.model.dataset.userSet = "1";
  PREFS.set({ model: el.model.value.trim() });
});
for (const btn of document.querySelectorAll("[data-download]")) {
  btn.addEventListener("click", () => download(document, result, btn.dataset.download));
}

// --- startup -------------------------------------------------------------------------

(async () => {
  const [secrets, prefs] = await Promise.all([
    SECRETS.get(["apiKey", "accessCode", "pendingSelection"]),
    PREFS.get(["backendUrl", "model"]),
  ]);
  if (typeof secrets.apiKey === "string") el.key.value = secrets.apiKey;
  if (typeof secrets.accessCode === "string" && secrets.accessCode) {
    el.access.value = secrets.accessCode;
    el.accessRow.hidden = false;
  }
  if (typeof prefs.model === "string" && MODEL_RE.test(prefs.model)) {
    el.model.value = prefs.model;
    el.model.dataset.userSet = "1";
  }
  backendUrl = (typeof prefs.backendUrl === "string" && normalizeServer(prefs.backendUrl)) || DEFAULT_BACKEND;
  el.backend.value = backendUrl;
  client = makeClient();
  takeSelection(secrets.pendingSelection);
  await loadServerInfo();
})();
