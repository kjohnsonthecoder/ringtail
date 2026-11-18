# Ringtail — project brief for Claude Code

**Ringtail: plain English in, rules that must fire out.**

Ringtail turns a plain-English behavior description or a pasted threat report into a
Sigma detection rule, maps it to MITRE ATT&CK, and **proves** the rule works by replaying
sample logs: it must fire on the attack and must not fire on benign activity.

Owner: Kevin Johnson (GitHub: `kjohnsonthecoder`). Public, free, open source (MIT).
This is a portfolio project for SOC / detection engineering / IR roles, not a product.
Origin nod: the built-in rule set is called the **Frontline Pack** (Kevin's company,
Frontline Consultant, is where this started).

Live: <https://web-production-34d65045.up.railway.app> · Latest release: v0.2.0.

---

## Core principles (do not violate)

1. **AI output is untrusted. Code decides.** The LLM drafts and maps; deterministic code
   validates syntax, verifies ATT&CK IDs, and runs tests. A rule is never "done" because
   the model said so — only because the checks pass.
2. **BYOK — bring your own key.** Ringtail never ships, stores, or proxies a shared API
   key. The CLI reads `ANTHROPIC_API_KEY` from the user's environment. The web page (and
   the v0.3 browser extension) call Claude directly from the user's browser; the backend
   never sees a key. Never log keys, never write them to disk, never commit them.
3. **Threat reports are hostile input.** Pasted/scraped text may contain prompt injection.
   Strip to plain text, wrap it clearly as data in the prompt, require structured JSON
   output, and validate every field before use. Document this in `docs/threat-model.md`.
4. **Self-hostable.** Everything needed to run Ringtail lives in this repo.

---

## Status

| Version | Scope | State |
|---|---|---|
| v0.1 | `core/` library, `ringtail` CLI, first Frontline Pack rules, CI, README | Done |
| v0.2 | BYOK web page, stateless FastAPI backend, Railway deploy | Done, released as v0.2.0 |
| v0.2.0 extras | Frontline Pack grown to 8 rules; Splunk SPL + Microsoft KQL conversion | Done |
| v0.3 | Browser extension "Highlight to Detect" | **Next** (plan below) |
| Later | Replay public datasets (OTRF, EVTX-ATTACK-SAMPLES); RSigma as a second CI engine | Not started |

Design decisions live in `docs/decisions/` (ADRs 0001–0004). Read the relevant ADR before
changing that area; write a new ADR for any new architectural choice.

---

## Pipeline

```
input text ─► [AI] extract behavior (TTPs, log source, key fields)
           ─► [AI] draft Sigma YAML + ATT&CK tags + TP/FP samples + card notes
           ─► [code] validate: pySigma parse/lint + ATT&CK IDs exist & not revoked/deprecated
           ─► [code] test: replay true-positive and false-positive sample events + guardrails
           ─► pass  → rule + tests + detection card (+ Splunk/KQL queries)
              fail  → send the exact error back to the AI, retry (max 3), then stop and report
```

Where the loop runs: in the CLI (`ringtail run`) the whole loop is local. On the web page
the loop runs in the browser (it holds the key) and the backend builds prompts and runs
every check (ADR 0003). The extension will work the same way as the web page.

---

## Repo layout

```
ringtail/
├── CLAUDE.md · README.md · CHANGELOG.md · LICENSE (MIT)
├── pyproject.toml               # extras: [web] fastapi+uvicorn, [dev] pytest+httpx
├── Dockerfile · railway.json    # Railway deploy of backend + web
├── .env.example                 # ANTHROPIC_API_KEY=, RINGTAIL_MODEL=
├── core/ringtail/
│   ├── cli.py                   # Typer: draft, run, validate, test, card, convert
│   ├── config.py                # default model, max attempts, key hygiene (never echoes keys)
│   ├── llm.py                   # Anthropic SDK calls, structured JSON output
│   ├── prompts/                 # prompt templates (versioned, plain files)
│   ├── sanitize.py              # hostile input → plain text, wrapped as data
│   ├── pipeline.py              # the run loop, draft checks, guardrails
│   ├── service.py               # build_prompt / check as JSON calls (used by the backend)
│   ├── validate.py              # pySigma + ATT&CK checks
│   ├── attack.py                # pinned ATT&CK index lookups
│   ├── matcher.py · testrunner.py   # the test engine (ADR 0001)
│   ├── card.py                  # detection card markdown
│   └── convert.py               # Splunk SPL + our own KQL backend (ADR 0004)
├── backend/app.py               # FastAPI: /api/prompt, /api/check, /api/health; no key ever
├── web/                         # static BYOK page; ringtail-client.js + ringtail-ui.js are shared with the extension
├── extension/                   # v0.3 MV3 extension: manifest, background.js, sidepanel/, lib/ (synced copies), icons/
├── scripts/                     # sync_extension.py (web → extension/lib), make_icons.py
├── data/attack/                 # pinned ATT&CK v20.1 index (+ version note, SHA-256)
├── rules/frontline-pack/{windows,cloudtrail}/<rule>.yml
├── tests/rules/<rule-id>/{true_positive,false_positive}.json
├── cards/<rule-id>.yml (human notes) · cards/<rule-id>.md (generated)
├── docs/threat-model.md · docs/decisions/ · docs/images/
├── tests/                       # pytest for the library and backend
└── .github/workflows/test.yml
```

---

## Stack

- Python 3.11–3.13 (pySigma doesn't support 3.15 yet), `pyproject.toml`, Typer, pytest.
- `pySigma` 2.x for parsing/validation; our own matcher as the test engine (ADR 0001).
- `pysigma-backend-splunk` 3.0.x for SPL; KQL via our own `KustoBackend` (ADR 0004).
  The backend is pinned to a minor version because cards embed its output.
- Anthropic Python SDK in the CLI; direct `fetch` from the browser on the web page.
  Default model lives in one place: `core/ringtail/config.py` (`RINGTAIL_MODEL` overrides).
- FastAPI + uvicorn for the backend; plain HTML/CSS/JS for the page (no framework, no
  third-party scripts, strict CSP).
- ATT&CK: MITRE `enterprise-attack` pinned to **v20.1** as a committed index (ADR 0002).
  Reject unknown, revoked, or deprecated technique IDs.
- Hosting: Railway, deployed from `main` on every push.

---

## CLI

```
ringtail draft "<behavior text>" | --file report.txt   # AI draft only, prints YAML
ringtail run "<text>" | --file report.txt               # full loop; writes to drafts/
ringtail validate <rules>                               # pySigma + ATT&CK checks
ringtail test <rules>                                   # replay TP/FP events
ringtail card <rules> [--check]                         # generate cards / check freshness
ringtail convert <rules> [-t splunk|kql]                # SIEM queries
```

Exit codes: 0 = pass, 1 = validation/test failure, 2 = usage/config error
(e.g. missing `ANTHROPIC_API_KEY` — print a clear BYOK message).

---

## Frontline Pack (8 rules)

Encoded PowerShell (T1059.001) · nltest trust discovery (T1482) · RustDesk service install
(T1219.002, T1543.003) · LSASS dump via comsvcs (T1003.001) · wbadmin NTDS backup
(T1003.003) · shadow copy deletion (T1490) · AWS console login without MFA (T1078.004) ·
CloudTrail logging stopped (T1685.002; formerly T1562.008, revoked in ATT&CK v20).

Rules for adding one:
- Technique IDs must pass `ringtail validate` against pinned v20.1.
- Hand-write small, realistic JSON samples (no real customer data, accounts, or keys —
  obvious placeholders like `EXAMPLE`, `111122223333`, TEST-NET IPs). Benign samples should
  be near misses where possible; label any that aren't as "Out of scope" honestly.
- Write `cards/<rule-id>.yml` (goal, summary, triage, including the rule's coverage gaps),
  then `ringtail card rules/`. CI fails on a stale card.
- Use Write/Edit for files with backslashes; shell heredocs mangle them in this environment.

## Detection card (one per rule, `cards/<rule-id>.md`)

Goal · ATT&CK technique(s) · Log source · Detection logic in plain English · SIEM queries ·
Known false positives · Triage steps · Test results (TP/FP pass) · References

---

## GitHub Action

`.github/workflows/test.yml` on push and pull_request: install → `pytest` →
`ringtail validate rules/` → `ringtail test rules/` → `ringtail card rules/ --check` →
`ringtail convert rules/`. No API key in CI: it never calls the LLM.

---

## v0.3 plan: browser extension "Highlight to Detect"

Highlight text in a threat report on any site → right-click "Detect with Ringtail" → a side
panel runs the same loop as the web page → a proven rule with cards and SIEM queries.

Decisions (Kevin, 2026-11-18; record in ADR 0005 before building):
- **Chrome/Edge Manifest V3.** The selected text comes from the context-menu click itself,
  so **no content scripts and no access to page content**. Permissions: `contextMenus`,
  `sidePanel`, `storage`; host access only to `api.anthropic.com` and the live backend.
- **Key storage: `chrome.storage.session`.** Survives closing the panel, wiped when the
  browser quits, never on disk, not readable by websites. Never `storage.local`/`sync`.
- **Backend: the live Railway URL by default, configurable** for self-hosters. A custom URL
  is granted at runtime through `optional_host_permissions` + `chrome.permissions.request`,
  so the install never asks for access to every site.
- **Distribution: GitHub release zip and the Chrome Web Store.** Needs store-ready assets
  (icons, screenshots, listing text), a privacy policy page, and per-permission
  justifications. Kevin creates the developer account (the $5 fee is his to pay) and
  submits; Claude prepares everything else.
- **JS tests: Node's built-in test runner** (`node --test`, no npm packages) in CI.
- Same split as the web page: the side panel holds the key and calls Claude; the backend
  builds prompts and runs checks. The shared loop code moves into one module used by both
  `web/` and `extension/`; MV3 forbids remote code, so the extension ships a copy and CI
  checks it matches.
- Threat model section T7 (extension): permissions, key storage, hostile page selections,
  no remote code, update and store-review path.

Definition of done for v0.3:
- [x] ADR 0005 and threat-model T7 written before code
- [ ] Highlight → right-click → side panel produces a proven rule against the live backend
- [ ] Key never reaches the Ringtail backend; extension requests no page access
- [x] Shared client module used by web and extension; CI checks the copies match
- [x] `node --test` unit tests for the shared loop in CI
- [ ] Privacy policy published; store listing, icons, and screenshots ready
- [ ] Extension zip attached to a GitHub release; README section with a screenshot
- [ ] Submitted to the Chrome Web Store (Kevin submits; review time is Google's)

---

## Working agreements

- Small commits with clear messages. Never commit `.env` or secrets; keep `.env` in `.gitignore`.
- Never push, publish, or create GitHub releases without Kevin's explicit yes.
- Ask before adding a dependency that isn't listed above.
- Kevin is a visual learner: when explaining a design choice, include a small Mermaid diagram.
