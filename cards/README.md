# Detection cards

One card per rule: `<rule-id>.md`. Cards are **generated**. Don't edit the `.md` by hand.

| Source | Gives the card |
|---|---|
| `rules/**/<rule-id>.yml` | Title, ATT&CK, log source, exact logic, false positives, references |
| A fresh test run of `tests/rules/<rule-id>/` | Test results (pass/fail per sample) |
| `cards/<rule-id>.yml` | Goal, plain-English summary, triage steps |

```bash
ringtail card rules/           # regenerate every card
ringtail card rules/ --check   # CI: exit 1 if a committed card is stale
```
