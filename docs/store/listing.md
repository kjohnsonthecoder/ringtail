# Chrome Web Store listing: Ringtail "Highlight to Detect"

Everything the Chrome Web Store developer dashboard asks for, ready to paste. Upload the
package built by `python scripts/package_extension.py` (`dist/ringtail-extension-<version>.zip`).

## Store listing tab

**Name** (from the manifest): Ringtail: Highlight to Detect

**Summary** (from the manifest, 132 characters max):
Highlight attacker behavior in a threat report and get a Sigma detection rule proven against sample logs. Bring your own key.

**Category:** Developer Tools

**Language:** English

**Description:**

> Turn a threat report into a detection rule you can trust.
>
> Highlight the part of a report that describes what an attacker did, right-click, and choose
> "Detect with Ringtail". The side panel drafts a Sigma detection rule with Claude, maps it to
> MITRE ATT&CK, and then proves it: the rule must fire on realistic attack samples and stay quiet
> on benign look-alikes, or it goes back to Claude with the exact errors (up to 3 tries).
>
> You get:
> • A Sigma rule validated against a pinned MITRE ATT&CK version (no made-up or retired technique IDs)
> • True-positive and false-positive test samples, with the test results
> • A detection card: goal, logic in plain English, false positives, and triage steps
> • Ready-to-paste Splunk SPL and Microsoft Sentinel / Defender KQL queries
>
> Bring your own key: you use your own Anthropic API key. It's kept in browser session memory only,
> sent only to Anthropic, and never to the Ringtail server.
>
> Small permissions by design: Ringtail can't read the pages you visit. It only receives the text you
> highlight and choose to send, and you can edit it first. No content scripts, no browsing history,
> no analytics.
>
> Open source (MIT), with a public threat model: https://github.com/kjohnsonthecoder/ringtail
>
> Every rule is an AI draft that passed automated checks, not a reviewed rule. Review before you deploy.

**Graphics:**
- Store icon: `extension/icons/icon-128.png`
- Screenshot (1280×800): `docs/store/screenshot-1.png`
- Small promo tile (440×280): `docs/store/promo-small.png`

**Official URL / homepage:** https://github.com/kjohnsonthecoder/ringtail

**Support URL:** https://github.com/kjohnsonthecoder/ringtail/issues

## Privacy practices tab

**Single purpose:**
Turn text a user highlights in a threat report into a Sigma detection rule, and verify the rule
against sample logs before showing it.

**Permission justifications:**

| Permission | Justification to paste |
|---|---|
| `contextMenus` | Adds "Detect with Ringtail" to the right-click menu when text is selected. The click provides the selected text, which is the extension's only input from a web page. |
| `sidePanel` | Shows the Ringtail panel where the user reviews the selected text, runs the rule drafting and checks, and sees the results. |
| `storage` | Keeps the user's own Anthropic API key and optional server access code in session storage (memory only, cleared when the browser quits), and the chosen server address and model name in local storage. |
| Host: `https://api.anthropic.com/*` | Sends the user's request to Anthropic's API with the user's own API key to draft the detection rule. |
| Host: `https://web-production-34d65045.up.railway.app/*` | The Ringtail server, which builds the prompt from the selected text and runs the validation and tests on the drafted rule. It never receives the API key. |
| Optional host: `https://*/*`, `http://localhost/*`, `http://127.0.0.1/*` | Only requested at runtime, for one origin, if the user chooses to point the extension at their own self-hosted Ringtail server in Settings. |

**Remote code:** No, I am not using remote code. (All JavaScript is packaged in the extension;
Manifest V3 default CSP.)

**Data usage** (what to tick):
- **Authentication information:** yes. The user's Anthropic API key, provided by the user, sent only
  to Anthropic to authenticate the user's own requests. Held in session memory.
- **Website content:** yes. Text the user selects and chooses to send, transmitted to the Ringtail
  server and to Anthropic to draft and check a detection rule. Not stored by the Ringtail server.
- Everything else (personally identifiable information, health, financial, personal communications,
  location, web history, user activity): no.

**Certifications** (all three are true):
- I do not sell or transfer user data to third parties, outside of the approved use cases.
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- I do not use or transfer user data to determine creditworthiness or for lending purposes.

**Privacy policy URL:** https://web-production-34d65045.up.railway.app/privacy.html

## Distribution tab

- Visibility: Public
- Regions: All regions

## Before submitting

1. `python scripts/package_extension.py` and upload `dist/ringtail-extension-<version>.zip`.
2. Make sure the live server is up (`/api/health`) and the privacy URL loads; reviewers test both.
3. The developer account, its one-time registration fee, and the submission itself are the
   account owner's to do.
