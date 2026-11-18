<!-- prompt: draft v1 -->
Write one Sigma detection rule, its test samples, and its detection card notes for the
behavior below.

## Behavior (from the extraction step)

{{EXTRACTION}}

## ATT&CK (checked by code against pinned ATT&CK v{{ATTACK_VERSION}})

{{ATTACK_CHECK}}

Valid tactic tags in this ATT&CK version: {{TACTICS}}. Tag the rule with
`attack.<tactic>` and `attack.tNNNN.NNN` (lowercase), using only IDs listed as valid above
or IDs you're sure exist in ATT&CK v{{ATTACK_VERSION}}.

## The rule (`rule_yaml`)

A complete Sigma rule as YAML text with: `title`, `description`, `references` (at least
the ATT&CK technique URL), `tags`, `logsource`, `detection` with a `condition`,
`falsepositives` (realistic ones), and `level`. Code sets `id`, `status`, `author`, and
`date`, so don't bother with them.

The test engine supports this subset of Sigma, and anything else fails the run:
- modifiers: `contains`, `startswith`, `endswith`, `all`, `re` (with `i`/`m`/`s`),
  `windash`, `base64`, `base64offset`, `wide`/`utf16le`, `cased`, `cidr`, `exists`,
  `lt`/`lte`/`gt`/`gte`
- values: strings with `*` and `?` wildcards, numbers, booleans, `null`, lists
- conditions: `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `1 of them`,
  `all of them`, keyword lists
- not supported: `fieldref`, placeholders (`%name%`), correlation rules, aggregations

Prefer precise logic over broad keyword matches. Match string values case-insensitively
(Sigma's default) unless case really matters.

## The samples (`true_positive_events`, `false_positive_events`)

Each entry is one log event, written as a JSON object **encoded as a string**. Use the same
field names the rule uses, and make events look like real logs from that source.

- At least 2 true positives, covering different realistic variants of the behavior. Every
  one must match the rule.
- At least 2 false positives: benign activity a SOC would really see. None may match.
- At least one false positive must be a near miss: it satisfies at least one of the rule's
  field conditions but not the whole rule (for example, the right process with harmless
  arguments, or the right API service with a read-only call). This proves the rule's logic
  is doing the rejecting.
- Add a `"_comment"` field to each event saying what it shows and why it should or
  shouldn't fire. The matcher ignores fields starting with `_`.
- Use only obvious placeholders: account `111122223333`, hosts like
  `WKSTN-EXAMPLE-01.example.local`, users like `EXAMPLE\\jdoe`, IPs from 192.0.2.0/24,
  198.51.100.0/24 or 203.0.113.0/24, domains under `example.invalid`, and keys containing
  `EXAMPLE`. Never real-looking secrets.

## The card (`card`)

- `goal`: 1-3 sentences on what the rule catches and why it matters.
- `summary`: the detection logic in plain English, 1-3 sentences, for a SOC analyst.
- `triage`: 4-7 concrete steps an analyst takes when it fires: what to check first, how
  to tell benign from malicious, and what to do if it's real.

## `slug`

A short file name for the rule: lowercase letters, digits, and underscores, starting with
a letter, in the style `win_proc_encoded_powershell` or `aws_cloudtrail_logging_disabled`.

## `notes`

Anything the reviewer should know, or "".

{{PREVIOUS_ATTEMPT}}
