"""Replay real attack recordings against the rules (ADR 0006).

Recordings come from OTRF Security-Datasets, pinned in data/datasets/otrf.yml by commit and
SHA-256. They're untrusted downloads: verified by hash before use, read in memory (never
extracted), limited to .json members, and capped in size.

Each rule only sees events of its own log source. Outcomes per rule and recording:
  detected    the manifest says the rule must fire here, and it did
  regression  the manifest says it must fire here, and it didn't (fails CI)
  gap         the manifest documents why this rule misses this method (reported)
  unexpected  the rule fired where nothing says it should (fails CI; needs review)
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.rule import SigmaRule

from ringtail.matcher import CompiledRule

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "data" / "datasets" / "otrf.yml"
REPORT_JSON = ROOT / "data" / "datasets" / "backtest.json"
REPORT_MD = ROOT / "docs" / "backtest.md"
CACHE = ROOT / ".cache" / "datasets"

MAX_DOWNLOAD = 50 * 1024 * 1024      # per archive
MAX_UNCOMPRESSED = 300 * 1024 * 1024  # per archive, all .json members together
_ID_RE = re.compile(r"^[a-z0-9_]{3,80}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_PATH_RE = re.compile(r"^[a-z_]+/host/[A-Za-z0-9_]+\.zip$")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

SYSMON = "Microsoft-Windows-Sysmon/Operational"


class BacktestError(Exception):
    pass


# ---------------------------------------------------------------------------
# Manifest


def load_manifest(path: Path = MANIFEST) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    src = data.get("source") or {}
    if not str(src.get("base_url", "")).startswith("https://raw.githubusercontent.com/OTRF/"):
        raise BacktestError("manifest source.base_url must be a raw.githubusercontent.com/OTRF URL")
    seen = set()
    for d in data.get("datasets") or []:
        where = f"dataset {d.get('id')!r}"
        if not _ID_RE.match(str(d.get("id", ""))) or d["id"] in seen:
            raise BacktestError(f"{where}: bad or duplicate id")
        seen.add(d["id"])
        if not _SHA_RE.match(str(d.get("sha256", ""))):
            raise BacktestError(f"{where}: sha256 must be 64 lowercase hex characters")
        if not _PATH_RE.match(str(d.get("path", ""))):
            raise BacktestError(f"{where}: path must look like <tactic>/host/<name>.zip")
        if not d.get("techniques") or not all(_TECH_RE.match(t) for t in d["techniques"]):
            raise BacktestError(f"{where}: techniques must be ATT&CK IDs like T1003.001")
        d.setdefault("fires", [])
        d.setdefault("gaps", {})
        d.setdefault("note", "")
    return data


# ---------------------------------------------------------------------------
# Fetching and reading (untrusted input)


def fetch(dataset: dict, base_url: str, cache: Path = CACHE, offline: bool = False) -> bytes:
    """Return the archive bytes, from cache or the pinned URL, verified by SHA-256."""
    want = dataset["sha256"]
    cached = Path(cache) / f"{want}.zip"
    if cached.exists():
        blob = cached.read_bytes()
        if hashlib.sha256(blob).hexdigest() == want:
            return blob
        cached.unlink()
    if offline:
        raise BacktestError(f"{dataset['id']}: not in cache and --offline was given")
    url = f"{base_url}/{dataset['path']}"
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (pinned https URL)
        blob = resp.read(MAX_DOWNLOAD + 1)
    if len(blob) > MAX_DOWNLOAD:
        raise BacktestError(f"{dataset['id']}: download is over {MAX_DOWNLOAD} bytes")
    got = hashlib.sha256(blob).hexdigest()
    if got != want:
        raise BacktestError(f"{dataset['id']}: SHA-256 mismatch (got {got[:12]}..., pinned {want[:12]}...)")
    Path(cache).mkdir(parents=True, exist_ok=True)
    tmp = cached.with_suffix(".part")
    tmp.write_bytes(blob)
    tmp.replace(cached)
    return blob


def read_events(blob: bytes) -> list[dict]:
    """JSON-lines events from the .json members of a zip, in memory, size-capped."""
    events: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        members = [i for i in z.infolist() if i.filename.endswith(".json") and not i.is_dir()]
        if sum(i.file_size for i in members) > MAX_UNCOMPRESSED:
            raise BacktestError("archive expands past the size cap")
        for info in members:
            for line in z.read(info).decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(ev, dict):
                    events.append(ev)
    return events


def applies(logsource, event: dict) -> bool:
    """Does this event belong to the rule's log source? Only what the pack uses is mapped."""
    product, category, service = logsource.product, logsource.category, logsource.service
    if product == "windows" and category == "process_creation":
        return event.get("Channel") == SYSMON and event.get("EventID") in (1, "1")
    if product == "windows" and service == "system":
        return event.get("Channel") == "System"
    if product == "aws" and service == "cloudtrail":
        return "eventSource" in event and "eventName" in event
    return False


# ---------------------------------------------------------------------------
# Running


@dataclass
class Rule:
    stem: str
    path: Path
    title: str
    techniques: list[str]
    sigma: SigmaRule
    compiled: CompiledRule


def load_rules(paths: list[Path]) -> list[Rule]:
    out = []
    for p in sorted(paths):
        text = p.read_text(encoding="utf-8")
        sr = SigmaRule.from_yaml(text)
        techs = sorted({t.name.upper() for t in sr.tags if t.namespace == "attack" and _TECH_RE.match(t.name.upper())})
        out.append(Rule(p.stem, p, sr.title, techs, sr, CompiledRule.from_yaml(text)))
    return out


def events_by_dataset(manifest: dict, cache: Path = CACHE, offline: bool = False) -> dict[str, list[dict]]:
    base = manifest["source"]["base_url"]
    return {d["id"]: read_events(fetch(d, base, cache, offline)) for d in manifest["datasets"]}


def run(rules: list[Rule], manifest: dict, events: dict[str, list[dict]]) -> dict:
    stems = {r.stem for r in rules}
    for d in manifest["datasets"]:
        for s in list(d["fires"]) + list(d["gaps"]):
            if s not in stems:
                raise BacktestError(f"dataset {d['id']}: unknown rule {s!r}")

    datasets_out = []
    rule_out = {r.stem: {"rule": r.stem, "title": r.title, "techniques": r.techniques,
                         "detected": [], "gaps": [], "unexpected": [], "regressions": [],
                         "events_scanned": 0} for r in rules}
    for d in manifest["datasets"]:
        evs = events[d["id"]]
        datasets_out.append({
            "id": d["id"], "techniques": d["techniques"], "note": d["note"],
            "events": len(evs),
            "process_events": sum(1 for e in evs if e.get("Channel") == SYSMON and e.get("EventID") in (1, "1")),
        })
        for r in rules:
            mine = [e for e in evs if applies(r.sigma.logsource, e)]
            hits = sum(1 for e in mine if r.compiled.match(e).matched)
            ro = rule_out[r.stem]
            ro["events_scanned"] += len(mine)
            if r.stem in d["fires"]:
                (ro["detected"] if hits else ro["regressions"]).append(
                    {"dataset": d["id"], "events": hits} if hits else d["id"])
            elif hits:
                ro["unexpected"].append({"dataset": d["id"], "events": hits})
            if r.stem in d["gaps"]:
                ro["gaps"].append({"dataset": d["id"], "reason": d["gaps"][r.stem], "fired": hits > 0})

    for ro in rule_out.values():
        ro["status"] = "real" if ro["detected"] else "samples"
    rules_list = [rule_out[s] for s in sorted(rule_out)]
    return {
        "source": {k: manifest["source"][k] for k in ("name", "repo", "license", "commit")},
        "datasets": datasets_out,
        "rules": rules_list,
        "totals": {
            "datasets": len(datasets_out),
            "events": sum(d["events"] for d in datasets_out),
            "rules_proven_on_real_data": sum(1 for r in rules_list if r["status"] == "real"),
            "gaps_documented": sum(len(r["gaps"]) for r in rules_list),
            "unexpected": sum(len(r["unexpected"]) for r in rules_list),
            "regressions": sum(len(r["regressions"]) for r in rules_list),
        },
    }


def problems(report: dict) -> list[str]:
    out = []
    for r in report["rules"]:
        for d in r["regressions"]:
            out.append(f"{r['rule']}: expected to fire on {d}, but didn't")
        for u in r["unexpected"]:
            out.append(f"{r['rule']}: fired {u['events']}x on {u['dataset']}, which nothing expects (review)")
        for g in r["gaps"]:
            if g["fired"]:
                out.append(f"{r['rule']}: documented gap on {g['dataset']} now fires; update the manifest")
    return out


# ---------------------------------------------------------------------------
# Rendering


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def to_markdown(report: dict) -> str:
    t = report["totals"]
    src = report["source"]
    lines = [
        "<!-- Generated by `ringtail backtest`. Do not edit: change data/datasets/otrf.yml or the rules. -->",
        "# Real-data backtest",
        "",
        f"Every Frontline Pack rule replayed against {t['datasets']} real attack recordings "
        f"({t['events']:,} events) from [{src['name']}]({src['repo']}) ({src['license']}), pinned to commit "
        f"`{src['commit'][:7]}`. Design: [ADR 0006](decisions/0006-real-data-backtest-and-second-engine.md).",
        "",
        f"- **{t['rules_proven_on_real_data']}** rules fired on a real recording of their attack",
        f"- **{t['unexpected']}** unexpected fires on recordings of other techniques",
        f"- **{t['gaps_documented']}** documented coverage gaps (same technique, different method)",
        f"- **{t['regressions']}** regressions",
        "",
        "These are lab recordings with little background noise, so zero unexpected fires is evidence,",
        "not a production false-positive rate.",
        "",
        "## Rules",
        "",
        "| Rule | ATT&CK | Real-data evidence | Documented gaps | Unexpected |",
        "|---|---|---|---|---|",
    ]
    for r in report["rules"]:
        ev = ", ".join(f"`{d['dataset']}`" for d in r["detected"]) or "none public; proven on test samples"
        gaps = ", ".join(f"`{g['dataset']}`" for g in r["gaps"]) or "-"
        unexpected = ", ".join(f"`{u['dataset']}` ({u['events']})" for u in r["unexpected"]) or "0"
        lines.append(f"| {r['title']} | {', '.join(r['techniques'])} | {ev} | {gaps} | {unexpected} |")
    lines += ["", "## Documented gaps", ""]
    any_gap = False
    for r in report["rules"]:
        for g in r["gaps"]:
            any_gap = True
            lines.append(f"- **{r['title']}** misses `{g['dataset']}`: {g['reason']}.")
    if not any_gap:
        lines.append("None.")
    lines += ["", "## Recordings", "", "| Recording | ATT&CK | What happens | Events | Process events |", "|---|---|---|---|---|"]
    for d in report["datasets"]:
        lines.append(f"| `{d['id']}` | {', '.join(d['techniques'])} | {d['note']} | {d['events']:,} | {d['process_events']} |")
    lines.append("")
    return "\n".join(lines)
