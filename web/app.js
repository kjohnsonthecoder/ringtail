// Ringtail web page: the browser half of ADR 0003.
//
// The user's key lives only in the `key` input (page memory). It is sent only to
// api.anthropic.com. The Ringtail backend builds prompts and runs every check; it never
// sees the key. All model output is inserted with textContent, never as HTML.

const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2026-10-21";
const FALLBACK_BETA = "server-side-fallback-2026-07-01";
const MAX_TOKENS = 16000;
const MODEL_RE = /^[a-z0-9][a-z0-9.\-]{2,63}$/;

const $ = (id) => document.getElementById(id);
const el = {
  key: $("key"), model: $("model"), forget: $("forget"), keyProblem: $("key-problem"),
  access: $("access"), accessRow: $("access-row"), accessNote: $("access-note"),
  input: $("input"), run: $("run"), stop: $("stop"), chars: $("chars"),
  progressPanel: $("progress-panel"), log: $("log"), usage: $("usage"),
  resultPanel: $("result-panel"), summary: $("summary"),
  outRule: $("out-rule"), outCard: $("out-card"), outTp: $("out-tp"), outFp: $("out-fp"),
  outSiem: $("out-siem"),
};

let maxAttempts = 3;
let controller = null;
let result = null;
const usage = { input: 0, output: 0, calls: 0 };

class StopRun extends Error {}

// ---------------------------------------------------------------------------
// Key hygiene, mirroring config.key_problem() in the CLI. Never echoes the key.

function keyProblem(key) {
  if (!key) return "Enter your Anthropic API key.";
  if (key !== key.trim()) return "The key has leading or trailing whitespace (often a pasted newline).";
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i);
    if (c < 0x21 || c > 0x7e) {
      return `The key has an invalid character at position ${i + 1} of ${key.length} (a space, smart quote, or "…" from copy-paste).`;
    }
  }
  if (/^["']|["']$/.test(key)) return "The key includes quote characters. Paste it without quotes.";
  if (!key.startsWith("sk-ant-")) return "That doesn't look like an Anthropic API key (they start with sk-ant-).";
  return null;
}

function showKeyProblem(msg) {
  el.keyProblem.textContent = msg || "";
  el.keyProblem.hidden = !msg;
}

// ---------------------------------------------------------------------------
// Progress log (text only)

function logLine(text, kind = "step", details = []) {
  const li = document.createElement("li");
  li.className = kind;
  li.textContent = text;
  if (details.length) {
    const ul = document.createElement("ul");
    for (const d of details) {
      const item = document.createElement("li");
      item.textContent = d;
      ul.appendChild(item);
    }
    li.appendChild(ul);
  }
  el.log.appendChild(li);
  return li;
}

function settle(li, kind, text) {
  li.className = kind;
  if (text) li.firstChild.textContent = text;
}

// Shorten long text at a word boundary, with an ellipsis, instead of mid-word.
function clip(text, max) {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const space = cut.lastIndexOf(" ");
  return (space > max * 0.6 ? cut.slice(0, space) : cut).replace(/[\s,;:.]+$/, "") + "…";
}

function showUsage() {
  el.usage.textContent = usage.calls
    ? `Claude calls: ${usage.calls} · tokens: ${usage.input.toLocaleString()} in / ${usage.output.toLocaleString()} out (billed to your key)`
    : "";
}

// ---------------------------------------------------------------------------
// Backend (no key, ever)

function accessHeaders() {
  const h = { "content-type": "application/json" };
  const code = el.access.value.trim();
  if (code) h["x-ringtail-access-code"] = code;
  return h;
}

function showAccessField(on) {
  el.accessRow.hidden = !on;
  el.accessNote.hidden = !on;
}

async function backend(path, body) {
  let resp;
  try {
    resp = await fetch(path, {
      method: "POST",
      // The access code (if this server needs one) goes only here, to the Ringtail server.
      // The Anthropic key never does.
      headers: accessHeaders(),
      body: JSON.stringify(body),
      signal: controller.signal,
      credentials: "omit",
    });
  } catch (e) {
    if (e.name === "AbortError") throw new StopRun();
    throw new Error("Could not reach the Ringtail server.");
  }
  let data = null;
  try { data = await resp.json(); } catch { /* handled below */ }
  if (!resp.ok) {
    const msg = data && typeof data.error === "string" ? data.error : `HTTP ${resp.status}`;
    if (resp.status === 429) {
      throw new Error(`Ringtail server: ${msg} (try again in ${resp.headers.get("retry-after") || "a few"} seconds).`);
    }
    if (resp.status === 401) {
      showAccessField(true);
      el.access.focus();
    }
    throw new Error(`Ringtail server: ${msg}`);
  }
  if (!data || typeof data !== "object") throw new Error("Ringtail server sent an unreadable reply.");
  return data;
}

// ---------------------------------------------------------------------------
// Claude, straight from the browser with the user's key

class ModelError extends Error {}   // the reply was unusable: worth another attempt
class FatalError extends Error {}   // key/model problem: stop the run

async function claude(prompt, key, model) {
  let resp;
  try {
    resp = await fetch(ANTHROPIC_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": ANTHROPIC_VERSION,
        "anthropic-beta": FALLBACK_BETA,
        // Required for calls from a browser. The key here is typed by its owner and kept
        // in page memory; it is not embedded in shipped code. See ADR 0003.
        "anthropic-dangerous-direct-browser-access": "true",
      },
      body: JSON.stringify({
        model,
        max_tokens: MAX_TOKENS,
        system: prompt.system,
        messages: [{ role: "user", content: prompt.user }],
        output_config: { effort: "high", format: { type: "json_schema", schema: prompt.schema } },
        fallbacks: "default",
      }),
      signal: controller.signal,
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
  } catch (e) {
    if (e.name === "AbortError") throw new StopRun();
    throw new FatalError("Could not reach api.anthropic.com. Check your connection, or whether a proxy or extension is blocking it.");
  }

  let data = null;
  try { data = await resp.json(); } catch { /* handled below */ }
  if (!resp.ok) {
    const apiMsg = data && data.error && typeof data.error.message === "string" ? data.error.message : "";
    const s = resp.status;
    if (s === 401) throw new FatalError("Anthropic rejected the API key (401). Check that it's correct and active.");
    if (s === 403 || s === 404) throw new FatalError(`Model "${model}" isn't available to this key (${s}). ${apiMsg}`);
    if (s === 400) throw new FatalError(`Anthropic rejected the request (400): ${apiMsg}`);
    if (s === 429) throw new FatalError("Your key hit Anthropic's rate limit (429). Wait a minute and try again.");
    if (s === 529 || s >= 500) throw new ModelError(`Anthropic API error ${s}${apiMsg ? ": " + apiMsg : ""}`);
    throw new FatalError(`Anthropic API error ${s}${apiMsg ? ": " + apiMsg : ""}`);
  }
  if (!data || typeof data !== "object") throw new ModelError("Anthropic sent an unreadable reply.");

  if (data.usage) {
    usage.calls += 1;
    usage.input += Number(data.usage.input_tokens) || 0;
    usage.output += Number(data.usage.output_tokens) || 0;
    showUsage();
  }
  if (data.stop_reason === "refusal") throw new ModelError("the model declined this request");
  if (data.stop_reason === "max_tokens") throw new ModelError(`the reply hit max_tokens (${MAX_TOKENS}) and was cut off`);

  const block = Array.isArray(data.content) ? data.content.find((b) => b && b.type === "text") : null;
  if (!block || typeof block.text !== "string") throw new ModelError("the reply had no text block");
  let parsed;
  try { parsed = JSON.parse(block.text); } catch { throw new ModelError("the reply was not valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new ModelError("the reply was JSON but not an object");
  return parsed;
}

// ---------------------------------------------------------------------------
// The loop: extract -> (draft -> check) x up to maxAttempts

async function runLoop(text, key, model) {
  let li = logLine("Building the extraction prompt (input sanitized and wrapped as data)…", "busy");
  const extractPrompt = await backend("/api/prompt", { stage: "extract", input: text });
  settle(li, "busy", "Claude: extracting the behavior, log source, and candidate techniques…");
  const extraction = await claude(extractPrompt, key, model);
  settle(li, "ok", `Behavior: ${clip(String(extraction.behavior_summary || ""), 600)}`);

  let previous = null;
  for (let n = 1; n <= maxAttempts; n++) {
    li = logLine(`Attempt ${n}/${maxAttempts}: Claude is drafting the rule, samples, and card notes…`, "busy");
    const req = { stage: "draft", extraction, attempt: n };
    if (previous && n > 1) req.previous = previous;
    const draftPrompt = await backend("/api/prompt", req);

    let draft;
    try {
      draft = await claude(draftPrompt, key, model);
    } catch (e) {
      if (!(e instanceof ModelError)) throw e;
      settle(li, "bad", `Attempt ${n}/${maxAttempts}: reply unusable (${e.message}).`);
      continue;
    }

    settle(li, "busy", `Attempt ${n}/${maxAttempts}: Ringtail is validating and replaying the samples…`);
    const checked = await backend("/api/check", { draft });
    if (checked.passed) {
      settle(li, "ok", `Attempt ${n}/${maxAttempts}: all checks passed.`);
      return checked.result;
    }
    const errors = Array.isArray(checked.errors) ? checked.errors.map(String) : [];
    li.remove();
    logLine(`Attempt ${n}/${maxAttempts}: ${errors.length} problem(s). ${n < maxAttempts ? "Sending the exact errors back to Claude." : ""}`, "bad", errors);
    previous = draft;
  }
  throw new Error(`No passing draft after ${maxAttempts} attempts. Try a more specific description.`);
}

// ---------------------------------------------------------------------------
// Results

function pretty(events) {
  return JSON.stringify(events, null, 2);
}

function showResult(r) {
  result = r;
  const t = r.tests || {};
  const tp = t.true_positive || {}, fp = t.false_positive || {};
  el.summary.textContent =
    `${r.slug}: fired on ${tp.passed}/${tp.total} attack samples and stayed quiet on ` +
    `${fp.passed}/${fp.total} benign samples, including a near miss. Validated against pinned ATT&CK.`;
  el.outRule.textContent = r.rule_yaml;
  el.outCard.textContent = r.card_markdown;
  el.outTp.textContent = pretty(r.true_positives);
  el.outFp.textContent = pretty(r.false_positives);
  showQueries(Array.isArray(r.queries) ? r.queries : []);
  selectTab("tab-rule");
  el.resultPanel.hidden = false;
  el.resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

// One block per SIEM target: a label, the schema the field names assume, the query (or
// why it isn't available), and a copy button. All text goes in with textContent.
function showQueries(queries) {
  el.outSiem.replaceChildren();
  if (!queries.length) {
    const p = document.createElement("p");
    p.className = "note";
    p.textContent = "No SIEM queries were returned.";
    el.outSiem.appendChild(p);
    return;
  }
  for (const q of queries) {
    const box = document.createElement("div");
    box.className = "query";
    const head = document.createElement("div");
    head.className = "query-head";
    const label = document.createElement("strong");
    label.textContent = String(q.label || q.target || "Query");
    head.appendChild(label);
    if (q.query) {
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "secondary small";
      copy.textContent = "Copy";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(String(q.query));
          copy.textContent = "Copied";
        } catch {
          copy.textContent = "Select and copy";
        }
        setTimeout(() => { copy.textContent = "Copy"; }, 1500);
      });
      head.appendChild(copy);
    }
    box.appendChild(head);
    const meta = document.createElement("p");
    meta.className = "note";
    meta.textContent = q.query ? String(q.schema || "") : `Not available: ${String(q.error || "unknown reason")}`;
    box.appendChild(meta);
    if (q.query) {
      const pre = document.createElement("pre");
      pre.textContent = String(q.query);
      box.appendChild(pre);
    }
    el.outSiem.appendChild(box);
  }
}

function download(kind) {
  if (!result) return;
  const s = result.slug;
  const files = {
    rule: [`${s}.yml`, result.rule_yaml, "application/yaml"],
    tp: ["true_positive.json", pretty(result.true_positives) + "\n", "application/json"],
    fp: ["false_positive.json", pretty(result.false_positives) + "\n", "application/json"],
    notes: [`${s}.card.yml`, result.card_notes_yaml, "application/yaml"],
    card: [`${s}.md`, result.card_markdown, "text/markdown"],
  };
  const [name, text, type] = files[kind];
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---------------------------------------------------------------------------
// Tabs (WAI-ARIA tab pattern)

const tabs = Array.from(document.querySelectorAll('[role="tab"]'));

function selectTab(id) {
  for (const tab of tabs) {
    const on = tab.id === id;
    tab.setAttribute("aria-selected", String(on));
    tab.tabIndex = on ? 0 : -1;
    $(tab.getAttribute("aria-controls")).hidden = !on;
  }
}

for (const tab of tabs) {
  tab.addEventListener("click", () => selectTab(tab.id));
  tab.addEventListener("keydown", (e) => {
    const i = tabs.indexOf(tab);
    let next = null;
    if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
    if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
    if (e.key === "Home") next = tabs[0];
    if (e.key === "End") next = tabs[tabs.length - 1];
    if (next) { e.preventDefault(); selectTab(next.id); next.focus(); }
  });
}

// ---------------------------------------------------------------------------
// Wiring

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

  el.log.replaceChildren();
  // Counts are per run, not per tab.
  usage.input = 0; usage.output = 0; usage.calls = 0;
  showUsage();
  el.resultPanel.hidden = true;
  el.progressPanel.hidden = false;
  result = null;
  controller = new AbortController();
  setRunning(true);
  try {
    const r = await runLoop(text, key, model);
    logLine("Done. Review the rule below before using it.", "ok");
    showResult(r);
  } catch (e) {
    if (e instanceof StopRun) {
      logLine("Stopped.", "bad");
    } else {
      for (const li of el.log.querySelectorAll("li.busy")) settle(li, "bad");
      logLine(e.message || "Something went wrong.", "bad");
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
  btn.addEventListener("click", () => download(btn.dataset.download));
}

// Versions from the server, so the page never drifts from the pinned ATT&CK data.
fetch("/api/health", { credentials: "omit" })
  .then((r) => (r.ok ? r.json() : null))
  .then((info) => {
    if (!info) return;
    if (typeof info.attack_version === "string") $("attack-version").textContent = `v${info.attack_version}`;
    if (Number.isInteger(info.max_attempts)) maxAttempts = info.max_attempts;
    if (info.access_code_required === true) showAccessField(true);
    if (typeof info.default_model === "string" && MODEL_RE.test(info.default_model)) el.model.value = info.default_model;
  })
  .catch(() => {});
