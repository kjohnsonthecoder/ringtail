"""Cross-check Ringtail's matcher against RSigma, an independent Sigma engine (ADR 0006).

Both engines get identical input:
  - every rule's own test samples (keys starting with "_" removed), one verdict per sample;
  - the real recorded events from the backtest, filtered to the rule's log source, compared
    as a match count per recording.
Any disagreement means one engine is wrong about Sigma semantics, and fails CI.

RSigma is a separate binary. CI installs a pinned, hash-checked release; locally this is
skipped unless RSigma is on PATH or passed with --rsigma.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ringtail.backtest import Rule, applies
from ringtail.testrunner import FP_FILE, TP_FILE, find_tests_dir


def find_rsigma(explicit: str | None = None) -> list[str] | None:
    if explicit:
        return [explicit] if Path(explicit).exists() or shutil.which(explicit) else None
    found = shutil.which("rsigma")
    return [found] if found else None


def _results(stdout: str) -> int:
    """Count EvaluationResult lines (one per match) in RSigma's NDJSON output."""
    n = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and ("rule_title" in obj or "rule_id" in obj):
            n += 1
    return n


def rsigma_count(cmd: list[str], rule_path: Path, events: list[dict]) -> int:
    """Run RSigma once over a set of events and return how many matched."""
    if not events:
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "events.ndjson"
        f.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events), encoding="utf-8")
        proc = subprocess.run(
            [*cmd, "engine", "eval", "-r", str(rule_path), "-e", f"@{f}"],
            capture_output=True, text=True, encoding="utf-8", timeout=120,
        )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"rsigma failed on {rule_path.name} (exit {proc.returncode}): {proc.stderr.strip()[:300]}")
    return _results(proc.stdout)


def _clean(ev: dict) -> dict:
    return {k: v for k, v in ev.items() if not k.startswith("_")}


@dataclass
class Disagreement:
    rule: str
    where: str
    ringtail: int
    rsigma: int

    def __str__(self) -> str:
        return f"{self.rule} on {self.where}: Ringtail matched {self.ringtail}, RSigma matched {self.rsigma}"


@dataclass
class CrosscheckReport:
    checked_samples: int = 0
    checked_recordings: int = 0
    disagreements: list[Disagreement] = field(default_factory=list)


def run(cmd: list[str], rules: list[Rule], events: dict[str, list[dict]] | None = None) -> CrosscheckReport:
    rep = CrosscheckReport()
    for r in rules:
        tests = find_tests_dir(r.path)
        for kind, fname in (("true_positive", TP_FILE), ("false_positive", FP_FILE)):
            samples = json.loads((tests / fname).read_text(encoding="utf-8"))
            for i, ev in enumerate(samples):
                ev = _clean(ev)
                ours = 1 if r.compiled.match(ev).matched else 0
                theirs = min(rsigma_count(cmd, r.path, [ev]), 1)
                rep.checked_samples += 1
                if ours != theirs:
                    rep.disagreements.append(Disagreement(r.stem, f"{kind}[{i}]", ours, theirs))
        for ds, evs in (events or {}).items():
            mine = [e for e in evs if applies(r.sigma.logsource, e)]
            if not mine:
                continue
            ours = sum(1 for e in mine if r.compiled.match(e).matched)
            theirs = rsigma_count(cmd, r.path, mine)
            rep.checked_recordings += 1
            if ours != theirs:
                rep.disagreements.append(Disagreement(r.stem, f"recording {ds}", ours, theirs))
    return rep
