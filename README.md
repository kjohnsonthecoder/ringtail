# Ringtail

[![test](https://github.com/kjohnsonthecoder/ringtail/actions/workflows/test.yml/badge.svg)](https://github.com/kjohnsonthecoder/ringtail/actions/workflows/test.yml)

**Plain English in, rules that must fire out.**

Ringtail turns a plain-English behavior description or a threat report into a
[Sigma](https://sigmahq.io) detection rule, maps it to MITRE ATT&CK, and **proves** the rule
works by replaying sample logs: it must fire on the attack and stay quiet on benign activity.

> Status: v0.1 in progress. The test engine and both Frontline Pack rules work today.
> `draft`, `validate`, and `run` are next.

## Pipeline

```mermaid
flowchart LR
    A["Input text"] --> B["AI: extract behavior"]
    B --> C["AI: draft Sigma + ATT&CK tags"]
    C --> D["Code: validate<br/>pySigma + ATT&CK IDs"]
    D --> E["Code: replay TP / FP events"]
    E -->|pass| F["Write rule, tests, card"]
    E -->|fail| G["Exact error back to AI<br/>retry, max 3"]
    G --> C
```

AI output is untrusted. Code decides.

## Quickstart

Requires Python 3.11 to 3.13 (pySigma doesn't support 3.15 yet).

```bash
git clone https://github.com/kjohnsonthecoder/ringtail.git
cd ringtail
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ringtail test rules/
pytest
```

## Frontline Pack

| Rule | ATT&CK | Tests |
|---|---|---|
| [PowerShell launched with an encoded command](rules/frontline-pack/windows/win_proc_encoded_powershell.yml) | T1059.001 | 4 TP / 3 FP |
| [AWS CloudTrail logging stopped or trail deleted](rules/frontline-pack/cloudtrail/aws_cloudtrail_logging_disabled.yml) | T1562.008 | 3 TP / 4 FP |

Each rule `rules/**/<rule-id>.yml` is tested by `tests/rules/<rule-id>/true_positive.json`
(every event must match) and `false_positive.json` (no event may match).

## Design decisions

- [ADR 0001: Test engine](docs/decisions/0001-test-engine.md)

## License

MIT
