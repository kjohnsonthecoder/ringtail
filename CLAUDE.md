# Ringtail — project brief for Claude Code

**Ringtail: plain English in, rules that must fire out.**

Ringtail turns a plain-English behavior description or a pasted threat report into a
Sigma detection rule, maps it to MITRE ATT&CK, and **proves** the rule works by replaying
sample logs: it must fire on the attack and must not fire on benign activity.

Owner: Kevin Johnson (GitHub: `kjohnsonthecoder`). Public, free, open source (MIT).
This is a portfolio project for SOC / detection engineering / IR roles, not a product.
Origin nod: the built-in rule set is called the **Frontline Pack** (Kevin's company,
Frontline Consultant, is where this started).

---

## Core principles (do not violate)

1. **AI output is untrusted. Code decides.** The LLM drafts and maps; deterministic code
   validates syntax, verifies ATT&CK IDs, and runs tests. A rule is never "done" because
   the model said so — only because the checks pass.
2. **BYOK — bring your own key.** Ringtail never ships, stores, or proxies a shared API
   key. The CLI reads `ANTHROPIC_API_KEY` from the user's environment. Later, the web page
   and browser extension will call Claude directly from the user's browser; the backend
   never sees a key. Never log keys, never write them to disk, never commit them.
3. **Threat reports are hostile input.** Pasted/scraped text may contain prompt injection.
   Strip to plain text, wrap it clearly as data in the prompt, require structured JSON
   output, and validate every field before use. Document this in `docs/threat-model.md`.
4. **Self-hostable.** Everything needed to run Ringtail lives in this repo.

---

## Scope for v0.1 (build this now)

In scope:
- `core/` Python library: prompt → draft → validate → test, with a retry loop.
- `ringtail` CLI.
- Two Frontline Pack rules with passing tests.
- GitHub Action that runs all rule tests on every push/PR.
- README with quickstart, the pipeline diagram (Mermaid), and a test-pass badge.

Out of scope until v0.1 works end-to-end (do NOT start these):
- Web page, FastAPI backend, Railway deploy (v0.2)
- Browser extension "Highlight to Detect" (v0.3)
- SIEM conversion beyond what pySigma gives for free

---

## Pipeline

```
input text ─► [AI] extract behavior (TTPs, log source, key fields)
           ─► [AI] draft Sigma YAML + ATT&CK tags
           ─► [code] validate: pySigma parse/lint + ATT&CK IDs exist & not revoked/deprecated
           ─► [code] test: replay true-positive and false-positive sample events
           ─► pass  → write rule + tests + detection card
              fail  → send the exact error back to the AI, retry (max 3), then stop and report
```

---

## Repo layout

```
ringtail/
├── CLAUDE.md
├── README.md
├── LICENSE                      # MIT
├── pyproject.toml
├── .env.example                 # ANTHROPIC_API_KEY=, RINGTAIL_MODEL=
├── core/ringtail/
│   ├── cli.py                   # Typer app: draft, validate, test, run
│   ├── llm.py                   # Anthropic SDK calls, structured JSON output
│   ├── prompts/                 # prompt templates (versioned, plain files)
│   ├── validate.py              # pySigma + ATT&CK checks
│   ├── attack.py                # load pinned ATT&CK STIX bundle, lookup IDs
│   ├── testrunner.py            # replay sample events against a rule
│   └── card.py                  # render detection card markdown
├── data/attack/                 # pinned enterprise-attack STIX JSON (+ version note)
├── rules/frontline-pack/
│   ├── windows/<rule>.yml
│   └── cloudtrail/<rule>.yml
├── tests/rules/<rule-id>/
│   ├── true_positive.json       # must match
│   └── false_positive.json      # must NOT match
├── cards/<rule-id>.md           # detection card per rule
├── docs/
│   ├── threat-model.md
│   └── decisions/               # short ADRs, e.g. 0001-test-engine.md
├── tests/                       # pytest for the core library
└── .github/workflows/test.yml
```

Placeholders for later (create empty dirs with a README line only): `backend/`, `web/`, `extension/`.

---

## Stack

- Python 3.11+, `pyproject.toml`, Typer for the CLI, pytest.
- `pySigma` for parsing/validation (and later backend conversion to KQL/SPL).
- Anthropic Python SDK. Model is configurable via `RINGTAIL_MODEL`; pick a current
  Claude model as the default and keep it in one place.
- ATT&CK: MITRE's `enterprise-attack` STIX bundle, pinned to a specific version in
  `data/attack/`. Reject unknown, revoked, or deprecated technique IDs.

**Test engine — decide first, record an ADR.** Evaluate and pick the simplest option
that runs in GitHub Actions without heavy setup:
- RSigma (Rust toolkit; has corpus backtesting with per-rule expectations and
  JUnit/JSON output, and can explain why a rule did or didn't match)
- Zircolite (Python; Sigma over JSON/EVTX via SQLite)
- A minimal pySigma-based matcher over JSON events (fallback)
Write the choice and reasoning in `docs/decisions/0001-test-engine.md`.

---

## CLI

```
ringtail draft "<behavior text>" | --file report.txt   # AI draft only, prints YAML
ringtail validate <rule.yml>                            # pySigma + ATT&CK checks
ringtail test <rule.yml>                                # replay TP/FP events
ringtail run "<text>" | --file report.txt               # full loop with retries;
                                                        # writes rule, tests, card
```

Exit codes: 0 = pass, 1 = validation/test failure, 2 = usage/config error
(e.g. missing `ANTHROPIC_API_KEY` — print a clear BYOK message).

---

## First two Frontline Pack rules (weekend 1)

1. **Windows process creation — encoded PowerShell** (ATT&CK T1059.001).
   TP: `powershell.exe -enc <base64>`; FP: normal admin PowerShell with no encoding.
2. **AWS CloudTrail — CloudTrail logging stopped or trail deleted** (ATT&CK T1685.002,
   Defense Impairment; formerly T1562.008, revoked in ATT&CK v20).
   TP: `StopLogging` / `DeleteTrail` event; FP: `DescribeTrails` / `GetTrailStatus`.

ATT&CK is pinned to **v20.1** (`data/attack/`). Technique IDs in this brief must pass
`ringtail validate`; if a future ATT&CK upgrade revokes one, the validator names the
replacement. See `docs/decisions/0002-pinned-attack-index.md`.

Hand-write small, realistic JSON sample events for tests (no real customer data, no
real account IDs/keys — use obvious placeholders). Larger public datasets
(OTRF Security-Datasets, EVTX-ATTACK-SAMPLES, Atomic Red Team output) come later.

## Detection card (one per rule, `cards/<rule-id>.md`)

Goal · ATT&CK technique(s) · Log source · Detection logic in plain English ·
Known false positives · Triage steps · Test results (TP/FP pass) · References

---

## GitHub Action

`.github/workflows/test.yml`: on push and pull_request → set up Python → install →
run `pytest` and `ringtail test` over every rule in `rules/`. No API key needed in CI:
CI only validates and tests committed rules; it never calls the LLM.

---

## Definition of done for v0.1

- [ ] `ringtail run "detect encoded powershell"` produces a rule that validates and passes tests
- [ ] Both Frontline Pack rules committed with TP/FP tests and cards
- [ ] GitHub Action green on `main`; badge in README
- [ ] `docs/threat-model.md` covers prompt injection, BYOK, and untrusted AI output
- [ ] ADR for the test engine
- [ ] README quickstart works from a fresh clone with only `ANTHROPIC_API_KEY` set

## Working agreements

- Small commits with clear messages. Never commit `.env` or secrets; keep `.env` in `.gitignore`.
- Never push, publish, or create GitHub releases without Kevin's explicit yes.
- Ask before adding a dependency that isn't listed above.
- Kevin is a visual learner: when explaining a design choice, include a small Mermaid diagram.
