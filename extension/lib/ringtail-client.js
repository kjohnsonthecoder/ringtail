// Ringtail client: the browser half of the loop, shared by the web page and the extension.
//
// No DOM here, so it runs (and is unit-tested) in Node too. ADR 0003 and ADR 0005:
// - the user's key goes only to api.anthropic.com, in the x-api-key header;
// - the Ringtail backend builds prompts and runs every check, and never gets the key;
// - the optional access code goes only to the Ringtail backend, never to Anthropic.
//
// The extension ships a byte-for-byte copy in extension/lib/ (MV3 forbids remote code);
// tests/test_extension.py fails if the copies drift.

export const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
export const ANTHROPIC_VERSION = "2026-10-21";
export const FALLBACK_BETA = "server-side-fallback-2026-07-01";
export const MAX_TOKENS = 16000;
export const MODEL_RE = /^[a-z0-9][a-z0-9.\-]{2,63}$/;
export const ACCESS_HEADER = "x-ringtail-access-code";

export class StopRun extends Error {}
export class ModelError extends Error {}   // the reply was unusable: worth another attempt
export class FatalError extends Error {}   // key/model problem: stop the run
export class ServerError extends Error {   // the Ringtail backend refused the request
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// Key hygiene, mirroring config.key_problem() in the CLI. Never echoes the key.
export function keyProblem(key) {
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

// Shorten long text at a word boundary, with an ellipsis, instead of mid-word.
export function clip(text, max) {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const space = cut.lastIndexOf(" ");
  return (space > max * 0.6 ? cut.slice(0, space) : cut).replace(/[\s,;:.]+$/, "") + "…";
}

function isAbort(e) {
  return e && e.name === "AbortError";
}

/**
 * baseUrl: "" for the page's own server, or e.g. "https://ringtail.example" for the extension.
 * getAccessCode: returns the access code to send to the Ringtail backend, or "".
 * onUsage: called with {input, output} token counts after each Claude reply.
 * fetch: injectable for tests.
 */
export function createClient({ baseUrl = "", getAccessCode = () => "", onUsage = () => {}, fetch: fetchImpl } = {}) {
  const doFetch = fetchImpl || ((...args) => globalThis.fetch(...args));
  const base = String(baseUrl).replace(/\/+$/, "");

  async function backend(path, body, signal) {
    const headers = { "content-type": "application/json" };
    const code = String(getAccessCode() || "").trim();
    if (code) headers[ACCESS_HEADER] = code;
    let resp;
    try {
      resp = await doFetch(base + path, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal,
        credentials: "omit",
      });
    } catch (e) {
      if (isAbort(e)) throw new StopRun();
      throw new ServerError("Could not reach the Ringtail server.", 0);
    }
    let data = null;
    try { data = await resp.json(); } catch { /* handled below */ }
    if (!resp.ok) {
      const msg = data && typeof data.error === "string" ? data.error : `HTTP ${resp.status}`;
      if (resp.status === 429) {
        const wait = (resp.headers && resp.headers.get && resp.headers.get("retry-after")) || "a few";
        throw new ServerError(`Ringtail server: ${msg} (try again in ${wait} seconds).`, 429);
      }
      throw new ServerError(`Ringtail server: ${msg}`, resp.status);
    }
    if (!data || typeof data !== "object") throw new ServerError("Ringtail server sent an unreadable reply.", resp.status);
    return data;
  }

  async function health(signal) {
    const resp = await doFetch(base + "/api/health", { credentials: "omit", signal });
    if (!resp.ok) throw new ServerError(`Ringtail server health check failed (HTTP ${resp.status}).`, resp.status);
    return resp.json();
  }

  async function claude(prompt, key, model, signal) {
    let resp;
    try {
      resp = await doFetch(ANTHROPIC_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": key,
          "anthropic-version": ANTHROPIC_VERSION,
          "anthropic-beta": FALLBACK_BETA,
          // Required for calls from a browser. The key here is typed by its owner and kept
          // in memory; it is not embedded in shipped code. See ADR 0003.
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
        signal,
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch (e) {
      if (isAbort(e)) throw new StopRun();
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
      onUsage({ input: Number(data.usage.input_tokens) || 0, output: Number(data.usage.output_tokens) || 0 });
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

  return { backend, health, claude };
}

/**
 * extract -> (draft -> check) x up to maxAttempts. Returns the passing result from
 * /api/check. `log` reports progress: start(text) -> handle, update(handle, text),
 * ok(handle, text), bad(handle, text), remove(handle), problem(text, details).
 */
export async function runLoop({ text, key, model, maxAttempts = 3, client, signal, log }) {
  let h = log.start("Building the extraction prompt (input sanitized and wrapped as data)…");
  const extractPrompt = await client.backend("/api/prompt", { stage: "extract", input: text }, signal);
  log.update(h, "Claude: extracting the behavior, log source, and candidate techniques…");
  const extraction = await client.claude(extractPrompt, key, model, signal);
  log.ok(h, `Behavior: ${clip(String(extraction.behavior_summary || ""), 600)}`);

  let previous = null;
  for (let n = 1; n <= maxAttempts; n++) {
    h = log.start(`Attempt ${n}/${maxAttempts}: Claude is drafting the rule, samples, and card notes…`);
    const req = { stage: "draft", extraction, attempt: n };
    if (previous && n > 1) req.previous = previous;
    const draftPrompt = await client.backend("/api/prompt", req, signal);

    let draft;
    try {
      draft = await client.claude(draftPrompt, key, model, signal);
    } catch (e) {
      if (!(e instanceof ModelError)) throw e;
      log.bad(h, `Attempt ${n}/${maxAttempts}: reply unusable (${e.message}).`);
      continue;
    }

    log.update(h, `Attempt ${n}/${maxAttempts}: Ringtail is validating and replaying the samples…`);
    const checked = await client.backend("/api/check", { draft }, signal);
    if (checked.passed) {
      log.ok(h, `Attempt ${n}/${maxAttempts}: all checks passed.`);
      return checked.result;
    }
    const errors = Array.isArray(checked.errors) ? checked.errors.map(String) : [];
    log.remove(h);
    log.problem(`Attempt ${n}/${maxAttempts}: ${errors.length} problem(s). ${n < maxAttempts ? "Sending the exact errors back to Claude." : ""}`, errors);
    previous = draft;
  }
  throw new Error(`No passing draft after ${maxAttempts} attempts. Try a more specific description.`);
}
