// Unit tests for web/ringtail-client.js with Node's built-in runner: `node --test tests/js`.
// No npm packages, no network, no key: fetch is a scripted fake.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ACCESS_HEADER, ANTHROPIC_URL, FatalError, ModelError, ServerError, StopRun,
  clip, createClient, keyProblem, runLoop,
} from "../../web/ringtail-client.js";

const KEY = "sk-ant-api03-FAKEFAKEFAKE";
const EXTRACTION = { behavior_summary: "certutil downloads a file", log_source: {}, key_fields: [], candidate_techniques: [], notes: "" };
const DRAFT = { slug: "x", rule_yaml: "title: x" };
const RESULT = { slug: "win_x", rule_yaml: "title: x" };

function json(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[k.toLowerCase()] ?? null },
    json: async () => body,
  };
}

function claudeReply(obj, extra = {}) {
  return json(200, { stop_reason: "end_turn", usage: { input_tokens: 10, output_tokens: 5 }, content: [{ type: "text", text: JSON.stringify(obj) }], ...extra });
}

/** A fake fetch: routes by URL, records every call (url, headers, body). */
function fakeFetch({ claude = [], check = [], prompt } = {}) {
  const calls = [];
  const fn = async (url, opts = {}) => {
    calls.push({ url, headers: opts.headers || {}, body: opts.body ? JSON.parse(opts.body) : null });
    if (url === ANTHROPIC_URL) {
      const next = claude.shift();
      if (next instanceof Error) throw next;
      return next;
    }
    if (url.endsWith("/api/prompt")) return prompt ? prompt(calls.at(-1).body) : json(200, { system: "s", user: "u", schema: {} });
    if (url.endsWith("/api/check")) return check.shift();
    if (url.endsWith("/api/health")) return json(200, { status: "ok" });
    throw new Error("unexpected url " + url);
  };
  return { fn, calls };
}

function fakeLog() {
  const lines = [];
  let n = 0;
  return {
    lines,
    start: (t) => { lines.push(["start", t]); return ++n; },
    update: (h, t) => lines.push(["update", t]),
    ok: (h, t) => lines.push(["ok", t]),
    bad: (h, t) => lines.push(["bad", t]),
    remove: () => lines.push(["remove"]),
    problem: (t, d) => lines.push(["problem", t, d]),
  };
}

// --- key hygiene and clip ---------------------------------------------------------

test("keyProblem catches the usual copy-paste mistakes without echoing the key", () => {
  assert.equal(keyProblem(KEY), null);
  for (const [k, needle] of [
    ["", "Enter"], [KEY + "\n", "whitespace"], ["sk-ant-fake key", "position 12"],
    [`'${KEY}'`, "quote"], ["sk-ant-…", "position 8"], ["AKIAEXAMPLE", "sk-ant-"],
  ]) {
    const p = keyProblem(k);
    assert.ok(p && p.includes(needle), `${JSON.stringify(k)} -> ${p}`);
    assert.ok(!p.includes("FAKE"));
  }
});

test("clip cuts at a word boundary with an ellipsis", () => {
  assert.equal(clip("short", 10), "short");
  const c = clip("alpha beta gamma delta epsilon", 20);
  assert.ok(c.endsWith("…") && !c.includes("epsil"), c);
});

// --- where secrets go ---------------------------------------------------------------

test("the key goes only to Anthropic; the access code only to the Ringtail backend", async () => {
  const f = fakeFetch({ claude: [claudeReply(EXTRACTION), claudeReply(DRAFT)], check: [json(200, { passed: true, result: RESULT })] });
  const client = createClient({ baseUrl: "https://ringtail.example/", getAccessCode: () => " otter-1 ", fetch: f.fn });
  const r = await runLoop({ text: "t", key: KEY, model: "claude-opus-5-5", client, log: fakeLog() });
  assert.deepEqual(r, RESULT);
  for (const c of f.calls) {
    const toAnthropic = c.url === ANTHROPIC_URL;
    assert.equal("x-api-key" in c.headers, toAnthropic, c.url);
    assert.equal(ACCESS_HEADER in c.headers, !toAnthropic, c.url);
    assert.ok(!JSON.stringify(c.body).includes("FAKEFAKE"), "key leaked into a body: " + c.url);
    if (toAnthropic) assert.equal(c.headers["anthropic-dangerous-direct-browser-access"], "true");
    else {
      assert.ok(c.url.startsWith("https://ringtail.example/api/"), c.url);  // trailing slash trimmed
      assert.equal(c.headers[ACCESS_HEADER], "otter-1");                    // trimmed
    }
  }
});

test("no access code header when none is set", async () => {
  const f = fakeFetch();
  await createClient({ fetch: f.fn }).backend("/api/prompt", {});
  assert.ok(!(ACCESS_HEADER in f.calls[0].headers));
});

// --- the retry loop ------------------------------------------------------------------

test("a failed check sends the failed draft back as `previous`, then passes", async () => {
  const f = fakeFetch({
    claude: [claudeReply(EXTRACTION), claudeReply(DRAFT), claudeReply({ ...DRAFT, slug: "y" })],
    check: [json(200, { passed: false, errors: ["test: tp[0] did not match"] }), json(200, { passed: true, result: RESULT })],
  });
  const log = fakeLog();
  const r = await runLoop({ text: "t", key: KEY, model: "m-1", client: createClient({ fetch: f.fn }), log });
  assert.deepEqual(r, RESULT);
  const drafts = f.calls.filter((c) => c.url.endsWith("/api/prompt") && c.body.stage === "draft");
  assert.equal(drafts.length, 2);
  assert.equal(drafts[0].body.attempt, 1);
  assert.ok(!("previous" in drafts[0].body));
  assert.deepEqual(drafts[1].body, { stage: "draft", extraction: EXTRACTION, attempt: 2, previous: DRAFT });
  assert.deepEqual(log.lines.find((l) => l[0] === "problem")[2], ["test: tp[0] did not match"]);
});

test("an unusable model reply skips to the next attempt without a `previous`", async () => {
  const f = fakeFetch({
    claude: [claudeReply(EXTRACTION), json(200, { stop_reason: "end_turn", content: [{ type: "text", text: "not json" }] }), claudeReply(DRAFT)],
    check: [json(200, { passed: true, result: RESULT })],
  });
  const log = fakeLog();
  await runLoop({ text: "t", key: KEY, model: "m-1", client: createClient({ fetch: f.fn }), log });
  assert.ok(log.lines.some((l) => l[0] === "bad" && l[1].includes("not valid JSON")));
  const second = f.calls.filter((c) => c.url.endsWith("/api/prompt") && c.body.stage === "draft")[1].body;
  assert.equal(second.attempt, 2);
  assert.ok(!("previous" in second));
});

test("gives up after maxAttempts", async () => {
  const fail = () => json(200, { passed: false, errors: ["nope"] });
  const f = fakeFetch({ claude: [claudeReply(EXTRACTION), claudeReply(DRAFT), claudeReply(DRAFT)], check: [fail(), fail()] });
  await assert.rejects(
    runLoop({ text: "t", key: KEY, model: "m-1", maxAttempts: 2, client: createClient({ fetch: f.fn }), log: fakeLog() }),
    /No passing draft after 2 attempts/,
  );
});

// --- error mapping ------------------------------------------------------------------

test("Anthropic errors: 401 and 429 are fatal, 529 and refusals are retryable", async () => {
  const cases = [
    [json(401, { error: { message: "invalid x-api-key" } }), FatalError, /rejected the API key/],
    [json(429, {}), FatalError, /rate limit/],
    [json(529, { error: { message: "overloaded" } }), ModelError, /529: overloaded/],
    [claudeReply({}, { stop_reason: "refusal" }), ModelError, /declined/],
    [claudeReply({}, { stop_reason: "max_tokens" }), ModelError, /max_tokens/],
    [claudeReply([1, 2]), ModelError, /not an object/],
  ];
  for (const [resp, cls, re] of cases) {
    const f = fakeFetch({ claude: [resp] });
    await assert.rejects(createClient({ fetch: f.fn }).claude({ system: "", user: "", schema: {} }, KEY, "m"), (e) => e instanceof cls && re.test(e.message));
  }
});

test("Ringtail server errors carry the status; 429 includes Retry-After", async () => {
  const f = fakeFetch({ prompt: () => json(401, { error: "This Ringtail server needs an access code." }) });
  await assert.rejects(createClient({ fetch: f.fn }).backend("/api/prompt", {}), (e) => e instanceof ServerError && e.status === 401 && /access code/.test(e.message));
  const g = fakeFetch({ prompt: () => json(429, { error: "too many requests" }, { "retry-after": "42" }) });
  await assert.rejects(createClient({ fetch: g.fn }).backend("/api/prompt", {}), (e) => e.status === 429 && /42 seconds/.test(e.message));
});

test("an aborted request becomes StopRun", async () => {
  const abort = Object.assign(new Error("aborted"), { name: "AbortError" });
  const f = fakeFetch({ claude: [abort] });
  await assert.rejects(createClient({ fetch: f.fn }).claude({}, KEY, "m"), StopRun);
  const g = { fn: async () => { throw abort; } };
  await assert.rejects(createClient({ fetch: g.fn }).backend("/api/check", {}), StopRun);
});

test("usage is reported per Claude reply", async () => {
  const seen = [];
  const f = fakeFetch({ claude: [claudeReply(EXTRACTION)] });
  await createClient({ fetch: f.fn, onUsage: (u) => seen.push(u) }).claude({}, KEY, "m");
  assert.deepEqual(seen, [{ input: 10, output: 5 }]);
});
