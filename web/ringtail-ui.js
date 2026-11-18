// Ringtail UI: rendering shared by the web page and the extension side panel.
//
// Every piece of model or server output is inserted with textContent, never as HTML
// (threat model T2, T6, T7). The extension ships a byte-for-byte copy in extension/lib/.

export function pretty(value) {
  return JSON.stringify(value, null, 2);
}

/** A progress log on an <ol>, implementing the `log` interface runLoop expects. */
export function createProgress(listEl) {
  function line(text, kind = "step", details = []) {
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
    listEl.appendChild(li);
    return li;
  }
  function settle(li, kind, text) {
    li.className = kind;
    if (text) li.firstChild.textContent = text;
  }
  return {
    clear: () => listEl.replaceChildren(),
    line,
    start: (text) => line(text, "busy"),
    update: (li, text) => settle(li, "busy", text),
    ok: (li, text) => settle(li, "ok", text),
    bad: (li, text) => settle(li, "bad", text),
    remove: (li) => li.remove(),
    problem: (text, details) => line(text, "bad", details),
    // After an error: mark any step still spinning as failed.
    failBusy: () => { for (const li of listEl.querySelectorAll("li.busy")) settle(li, "bad"); },
  };
}

export function usageText(u) {
  return u.calls
    ? `Claude calls: ${u.calls} · tokens: ${u.input.toLocaleString()} in / ${u.output.toLocaleString()} out (billed to your key)`
    : "";
}

/** WAI-ARIA tabs inside `root`. Returns selectTab(id). */
export function setupTabs(root) {
  const tabs = Array.from(root.querySelectorAll('[role="tab"]'));
  function selectTab(id) {
    for (const tab of tabs) {
      const on = tab.id === id;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      root.ownerDocument.getElementById(tab.getAttribute("aria-controls")).hidden = !on;
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
  return selectTab;
}

// One block per SIEM target: label, the schema the field names assume, the query (or why
// it isn't available), and a copy button.
export function showQueries(container, queries) {
  const doc = container.ownerDocument;
  container.replaceChildren();
  if (!queries.length) {
    const p = doc.createElement("p");
    p.className = "note";
    p.textContent = "No SIEM queries were returned.";
    container.appendChild(p);
    return;
  }
  for (const q of queries) {
    const box = doc.createElement("div");
    box.className = "query";
    const head = doc.createElement("div");
    head.className = "query-head";
    const label = doc.createElement("strong");
    label.textContent = String(q.label || q.target || "Query");
    head.appendChild(label);
    if (q.query) {
      const copy = doc.createElement("button");
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
    const meta = doc.createElement("p");
    meta.className = "note";
    meta.textContent = q.query ? String(q.schema || "") : `Not available: ${String(q.error || "unknown reason")}`;
    box.appendChild(meta);
    if (q.query) {
      const pre = doc.createElement("pre");
      pre.textContent = String(q.query);
      box.appendChild(pre);
    }
    container.appendChild(box);
  }
}

/** Fill the result outputs. `out` holds: summary, rule, card, tp, fp, siem elements. */
export function renderResult(out, r) {
  const t = r.tests || {};
  const tp = t.true_positive || {}, fp = t.false_positive || {};
  out.summary.textContent =
    `${r.slug}: fired on ${tp.passed}/${tp.total} attack samples and stayed quiet on ` +
    `${fp.passed}/${fp.total} benign samples, including a near miss. Validated against pinned ATT&CK.`;
  out.rule.textContent = r.rule_yaml;
  out.card.textContent = r.card_markdown;
  out.tp.textContent = pretty(r.true_positives);
  out.fp.textContent = pretty(r.false_positives);
  showQueries(out.siem, Array.isArray(r.queries) ? r.queries : []);
}

const FILES = {
  rule: (r) => [`${r.slug}.yml`, r.rule_yaml, "application/yaml"],
  tp: (r) => ["true_positive.json", pretty(r.true_positives) + "\n", "application/json"],
  fp: (r) => ["false_positive.json", pretty(r.false_positives) + "\n", "application/json"],
  notes: (r) => [`${r.slug}.card.yml`, r.card_notes_yaml, "application/yaml"],
  card: (r) => [`${r.slug}.md`, r.card_markdown, "text/markdown"],
};

export function download(doc, result, kind) {
  if (!result || !FILES[kind]) return;
  const [name, text, type] = FILES[kind](result);
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = doc.createElement("a");
  a.href = url;
  a.download = name;
  doc.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
