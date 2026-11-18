"""Pinned MITRE ATT&CK lookups.

The full enterprise-attack STIX bundle is ~55 MB, so the repo commits a small derived index
instead: data/attack/enterprise-attack-<version>.index.json. The index records the source
URL and SHA-256 of the bundle it came from, so anyone can re-download, verify, and rebuild
the identical file:

    python -m ringtail.attack build data/attack/enterprise-attack-20.1.json

Validation never touches the network. The pinned version only changes when someone rebuilds
the index on purpose and commits it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PINNED_VERSION = "20.1"
SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INDEX = _REPO_ROOT / "data" / "attack" / f"enterprise-attack-{PINNED_VERSION}.index.json"

TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)
OTHER_ID_RE = re.compile(r"^[gsc]\d{4}$", re.IGNORECASE)  # groups, software, campaigns

# STIX object type -> index section, for objects identified by an ATT&CK external ID.
_SECTIONS = {
    "attack-pattern": "techniques",
    "intrusion-set": "groups",
    "malware": "software",
    "tool": "software",
    "campaign": "campaigns",
}


class AttackDataError(Exception):
    """The pinned index is missing or unreadable. A config error, not a rule failure."""


# ---------------------------------------------------------------------------
# Building the index from the full STIX bundle


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def build_index(bundle_path: Path, version: str = PINNED_VERSION) -> dict:
    raw = Path(bundle_path).read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    bundle = json.loads(raw)
    objects = bundle["objects"]
    by_stix_id = {o["id"]: o for o in objects}

    revoked_by: dict[str, str] = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            target = by_stix_id.get(o["target_ref"])
            if target is not None and _external_id(target):
                revoked_by[o["source_ref"]] = _external_id(target)

    index: dict = {
        "attack_version": version,
        "source_url": SOURCE_URL.format(version=version),
        "source_sha256": sha256,
        "tactics": {},
        "techniques": {},
        "groups": {},
        "software": {},
        "campaigns": {},
    }

    for o in objects:
        typ = o.get("type")
        if typ == "x-mitre-tactic":
            if o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            index["tactics"][o["x_mitre_shortname"]] = {"id": _external_id(o), "name": o["name"]}
            continue
        section = _SECTIONS.get(typ)
        eid = _external_id(o)
        if section is None or eid is None:
            continue
        entry = {
            "name": o["name"],
            "revoked": bool(o.get("revoked")),
            "deprecated": bool(o.get("x_mitre_deprecated")),
            "revoked_by": revoked_by.get(o["id"]),
        }
        if section == "techniques":
            entry["tactics"] = sorted(
                p["phase_name"]
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            )
        existing = index[section].get(eid)
        # If an ID appears twice, the live object wins over a revoked/deprecated one.
        if existing is None or (existing["revoked"] or existing["deprecated"]) and not (
            entry["revoked"] or entry["deprecated"]
        ):
            index[section][eid] = entry

    for key in ("tactics", "techniques", "groups", "software", "campaigns"):
        index[key] = dict(sorted(index[key].items()))
    return index


def write_index(index: dict, out_path: Path) -> None:
    out_path.write_text(json.dumps(index, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------
# Lookups


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    revoked: bool
    deprecated: bool
    revoked_by: str | None

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"


class AttackIndex:
    def __init__(self, data: dict):
        self.data = data
        self.version: str = data["attack_version"]

    @classmethod
    def load(cls, path: Path | None = None) -> "AttackIndex":
        path = Path(path or os.environ.get("RINGTAIL_ATTACK_INDEX") or DEFAULT_INDEX)
        if not path.is_file():
            raise AttackDataError(
                f"ATT&CK index not found at {path}. Rebuild it with: "
                f"python -m ringtail.attack build <enterprise-attack-{PINNED_VERSION}.json>"
            )
        try:
            return cls(json.loads(path.read_text(encoding="utf-8")))
        except (ValueError, KeyError) as e:
            raise AttackDataError(f"ATT&CK index at {path} is unreadable: {e}") from e

    def technique(self, tid: str) -> Technique | None:
        tid = tid.upper()
        e = self.data["techniques"].get(tid)
        if e is None:
            return None
        return Technique(tid, e["name"], tuple(e["tactics"]), e["revoked"], e["deprecated"], e["revoked_by"])

    def tactic(self, shortname: str) -> dict | None:
        return self.data["tactics"].get(shortname.lower())

    def tactic_names(self) -> list[str]:
        return list(self.data["tactics"])

    def other(self, oid: str) -> tuple[str, dict] | None:
        """Group (G), software (S), or campaign (C) by ID."""
        section = {"G": "groups", "S": "software", "C": "campaigns"}[oid[0].upper()]
        e = self.data[section].get(oid.upper())
        return (section, e) if e else None


@lru_cache(maxsize=1)
def default_index() -> AttackIndex:
    return AttackIndex.load()


# ---------------------------------------------------------------------------
# Tag checks


@dataclass
class TagCheck:
    errors: list[str]
    warnings: list[str]
    techniques: list[Technique]


def check_tags(tags: list[str], index: AttackIndex | None = None) -> TagCheck:
    """Check Sigma `attack.*` tags against the pinned ATT&CK version.

    Errors: unknown, revoked, or deprecated IDs; unknown tactics; no technique at all.
    Warning: a tagged tactic that none of the tagged techniques belong to.
    """
    index = index or default_index()
    errors: list[str] = []
    warnings: list[str] = []
    techniques: list[Technique] = []
    tactics: list[str] = []
    v = f"ATT&CK v{index.version}"

    for tag in tags:
        ns, _, name = tag.partition(".")
        if ns.lower() != "attack" or not name:
            continue
        if TECHNIQUE_RE.match(name):
            t = index.technique(name)
            if t is None:
                errors.append(f"attack.{name}: technique {name.upper()} does not exist in {v}")
            elif t.revoked:
                hint = f"; use {t.revoked_by} instead" if t.revoked_by else ""
                errors.append(f"attack.{name}: {t.id} ({t.name}) is revoked in {v}{hint}")
            elif t.deprecated:
                errors.append(f"attack.{name}: {t.id} ({t.name}) is deprecated in {v}")
            else:
                techniques.append(t)
        elif OTHER_ID_RE.match(name):
            found = index.other(name)
            if found is None:
                errors.append(f"attack.{name}: {name.upper()} does not exist in {v}")
            elif found[1]["revoked"] or found[1]["deprecated"]:
                state = "revoked" if found[1]["revoked"] else "deprecated"
                hint = f"; use {found[1]['revoked_by']} instead" if found[1].get("revoked_by") else ""
                errors.append(f"attack.{name}: {name.upper()} ({found[1]['name']}) is {state} in {v}{hint}")
        elif index.tactic(name):
            tactics.append(name.lower())
        else:
            errors.append(
                f"attack.{name}: not a technique, group, software, campaign, or tactic in {v}. "
                f"Valid tactics: {', '.join(index.tactic_names())}"
            )

    if not techniques and not any("technique" in e for e in errors):
        errors.append(f"no ATT&CK technique tag (attack.tNNNN or attack.tNNNN.NNN); every Ringtail rule maps to one")

    covered = {tac for t in techniques for tac in t.tactics}
    for tac in tactics:
        if techniques and tac not in covered:
            warnings.append(
                f"attack.{tac}: none of the tagged techniques belong to this tactic in {v} "
                f"(they belong to: {', '.join(sorted(covered))})"
            )
    return TagCheck(errors, warnings, techniques)


# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "build":
        print(f"usage: python -m ringtail.attack build <enterprise-attack-{PINNED_VERSION}.json> [version]")
        return 2
    bundle = Path(argv[2])
    index = build_index(bundle)
    out = DEFAULT_INDEX
    write_index(index, out)
    counts = {k: len(index[k]) for k in ("tactics", "techniques", "groups", "software", "campaigns")}
    print(f"wrote {out} (ATT&CK v{index['attack_version']}, sha256 {index['source_sha256'][:12]}..., {counts})")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
