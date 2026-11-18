# Changelog

## v0.4.0 (2026-11-18)

Every rule is now proven twice beyond its own samples: against real recorded attacks, and
by a second, independent Sigma engine. Plus the Frontline Pack drawn on the attack line.

### Real-data backtest (`ringtail backtest`)
- Replays 13 real attack recordings (59,093 events) from OTRF Security-Datasets against
  every rule, pinned by repository commit and a SHA-256 per file.
- The LSASS (comsvcs) and encoded-PowerShell rules fire on the real attacks. Nothing fires
  on recordings of other techniques.
- 5 coverage gaps are documented with reasons (same technique, a method the rule doesn't
  cover, such as LSASS dumped from Task Manager), not hidden. Full results:
  [docs/backtest.md](docs/backtest.md).
- Downloads are treated as untrusted: verified by hash, read in memory, `.json` only, capped.

### Second engine (`ringtail crosscheck`)
- CI runs every rule through [RSigma](https://github.com/timescale/rsigma) v0.27.0 (pinned,
  hash-checked) on the same samples and real recordings, and fails on any disagreement with
  Ringtail's matcher. First run: full agreement.

### The attack line (`ringtail coverage`)
- An SVG of the Frontline Pack on the MITRE ATT&CK v20.1 tactic line, under Lockheed Martin
  Cyber Kill Chain phases, with each rule colored by its evidence. Shown in the README and
  on the live site; CI fails if it's stale.

### Design
- [ADR 0006](docs/decisions/0006-real-data-backtest-and-second-engine.md); threat model T5
  covers the new downloads and the pinned binary.

## v0.3.0 (2026-11-18)

The **Highlight to Detect** browser extension for Chrome and Edge.

### Browser extension
- Highlight attacker behavior on any page, right-click **Detect with Ringtail**, and the side
  panel drafts, validates, and tests a rule, with Splunk and KQL queries and downloads.
- Small permissions by design ([ADR 0005](docs/decisions/0005-browser-extension.md)):
  `contextMenus`, `sidePanel`, `storage`, plus Anthropic and the Ringtail server. No content
  scripts, so it can't read the pages you visit; it only receives the text you highlight.
- Your key and access code live in `chrome.storage.session` only (memory, cleared when the
  browser quits). A self-hosted server is optional and gets permission for exactly its own
  address, requested at that moment.
- Install: load unpacked from the zip attached to this release (or the `extension/` folder in
  the source code). Chrome Web Store listing pending review.

### Shared code and tests
- The browser loop now lives in shared modules used by the web page and the extension
  (`web/ringtail-client.js`, `web/ringtail-ui.js`), with unit tests on Node's built-in runner.
- CI enforces the extension's guardrails: the exact permission set, no page access, secrets
  only in session storage, no remote code, and the extension's copies matching `web/`.

### Also
- KQL conversion now covers Linux process-creation rules (Defender `DeviceProcessEvents`),
  added after the first real extension run produced a Linux rule.
- Privacy policy page: <https://web-production-34d65045.up.railway.app/privacy.html>.
- Threat model section T7 covers the extension.

## v0.2.0 (2026-11-18)

Ringtail is now a web app as well as a CLI, the Frontline Pack has eight rules, and every
rule comes with Splunk and Microsoft KQL queries.

**Try it:** <https://web-production-34d65045.up.railway.app> (bring your own Anthropic API key).

### Web page and backend (BYOK)
- Browser page that runs the full draft, validate, test, and retry loop. Your API key stays
  in the tab and goes only to Anthropic; the Ringtail server never sees it
  ([ADR 0003](docs/decisions/0003-browser-byok-architecture.md)).
- Stateless FastAPI backend that builds prompts and runs the same deterministic checks as
  the CLI and CI. It never calls Claude and refuses any request carrying a key.
- Hardening: strict Content Security Policy, no third-party scripts, model output rendered
  as text only, request size caps, a per-IP rate limit keyed on Railway's `X-Real-IP`, a
  server-wide cap on simultaneous checks, and an optional access code
  (`RINGTAIL_ACCESS_CODE`) to lock the API without a code change.
- Hosted on Railway (Dockerfile, health check, non-root container).

### Frontline Pack: 2 rules to 8
- New: nltest domain trust discovery (T1482), RustDesk service install (T1219.002,
  T1543.003), LSASS dump via comsvcs.dll (T1003.001), wbadmin NTDS backup (T1003.003),
  shadow copy deletion (T1490), AWS console sign-in without MFA (T1078.004).
- Every card now lists the rule's coverage gaps in its triage steps.

### SIEM queries
- `ringtail convert` turns any rule into Splunk SPL and Microsoft Sentinel / Defender XDR
  KQL. Queries also appear in every detection card and in a SIEM queries tab on the page.
- Splunk uses the official pySigma backend; KQL uses a small backend of our own, since no
  Kusto backend release supports pySigma 2.x ([ADR 0004](docs/decisions/0004-siem-conversion.md)).
  Unmapped log sources or fields report "not available" instead of guessing field names.

### Security findings fixed along the way
- Model-written card notes could carry raw HTML into a downloaded card: now escaped
  outside code spans.
- The first live deploy's rate limit could be dodged by forging `X-Forwarded-For`; found
  by testing the live site, fixed by keying on `X-Real-IP`, and verified live.

## v0.1.0

The CLI and the core pipeline (not separately tagged).

- `ringtail draft | run | validate | test | card`: plain English or a threat report in,
  Sigma rule out, validated against pinned MITRE ATT&CK v20.1 and proven by replaying
  true-positive and false-positive samples, with up to 3 AI retries.
- Custom pySigma-based matcher as the test engine ([ADR 0001](docs/decisions/0001-test-engine.md));
  pinned ATT&CK index ([ADR 0002](docs/decisions/0002-pinned-attack-index.md)).
- Prompt-injection defenses, BYOK key handling, and deterministic guardrails on AI drafts
  ([threat model](docs/threat-model.md)).
- First two Frontline Pack rules and GitHub Actions CI.
