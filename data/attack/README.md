# Pinned MITRE ATT&CK data

| | |
|---|---|
| Version | **Enterprise ATT&CK v20.1** (released 2026-11-05) |
| Source | <https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json> |
| Source SHA-256 | `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5` |
| Committed file | `enterprise-attack-20.1.index.json` (~270 KB) |

The full STIX bundle is 55 MB, so it's git-ignored. Ringtail commits a small index built
from it: tactics, techniques (name, tactics, revoked, deprecated, revoked-by), groups,
software, and campaigns. `ringtail validate` reads only the index and never touches the
network. See [ADR 0002](../../docs/decisions/0002-pinned-attack-index.md).

## Verify or rebuild

```bash
curl -L -o data/attack/enterprise-attack-20.1.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json
sha256sum data/attack/enterprise-attack-20.1.json   # must match the hash above
python -m ringtail.attack build data/attack/enterprise-attack-20.1.json
git diff --stat data/attack/                         # no change = index verified
```

## Upgrading ATT&CK

Change `PINNED_VERSION` in `core/ringtail/attack.py`, download the new bundle, rebuild,
update this table, then run `ringtail validate rules/`. Revoked or deprecated techniques
fail with the replacement ID in the error message.
