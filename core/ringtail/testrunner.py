"""Replay true-positive and false-positive sample events against a rule.

Layout (see CLAUDE.md): a rule at ``rules/**/<rule-id>.yml`` is tested by
``tests/rules/<rule-id>/true_positive.json`` (every event must match) and
``false_positive.json`` (no event may match). Each file holds a JSON list of events.

A rule passes only when both files exist, are non-empty, and every case behaves as expected.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from sigma.exceptions import SigmaError

from ringtail.matcher import CompiledRule, UnsupportedSigmaFeature

TP_FILE = "true_positive.json"
FP_FILE = "false_positive.json"


@dataclass
class CaseResult:
    kind: str  # "true_positive" | "false_positive"
    index: int
    expected: bool
    actual: bool
    detections: dict[str, bool]
    comment: str = ""

    @property
    def passed(self) -> bool:
        return self.expected == self.actual

    def explain(self) -> str:
        """One line a human (or the LLM in the retry loop) can act on."""
        want = "match" if self.expected else "NOT match"
        got = "matched" if self.actual else "did not match"
        parts = ", ".join(f"{k}={'true' if v else 'false'}" for k, v in self.detections.items())
        note = f" ({self.comment})" if self.comment else ""
        return f"{self.kind}[{self.index}]{note}: expected to {want}, {got}. Detections: {parts}"


@dataclass
class RuleReport:
    rule_path: Path
    tests_dir: Path
    cases: list[CaseResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.errors and bool(self.cases) and all(c.passed for c in self.cases)

    def counts(self, kind: str) -> tuple[int, int]:
        mine = [c for c in self.cases if c.kind == kind]
        return sum(c.passed for c in mine), len(mine)

    def to_dict(self) -> dict:
        return {
            "rule": str(self.rule_path),
            "tests_dir": str(self.tests_dir),
            "passed": self.passed,
            "errors": self.errors,
            "failures": [c.explain() for c in self.cases if not c.passed],
            "true_positive": dict(zip(("passed", "total"), self.counts("true_positive"))),
            "false_positive": dict(zip(("passed", "total"), self.counts("false_positive"))),
        }


def find_tests_dir(rule_path: Path, tests_root: Path | None = None) -> Path:
    """tests/rules/<rule-id>/, looking upward from the rule for the repo's tests/rules."""
    rule_id = rule_path.stem
    if tests_root is not None:
        return tests_root / rule_id
    for parent in rule_path.resolve().parents:
        candidate = parent / "tests" / "rules"
        if candidate.is_dir():
            return candidate / rule_id
    return Path("tests") / "rules" / rule_id


def _load_events(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
        raise ValueError(f"{path.name} must be a JSON list of event objects")
    return data


def replay(compiled: CompiledRule, kind: str, events: list[dict], report: RuleReport) -> None:
    """Replay in-memory events, appending one CaseResult (or error) per event."""
    expected = kind == "true_positive"
    for i, event in enumerate(events):
        try:
            res = compiled.match(event)
        except UnsupportedSigmaFeature as e:
            report.errors.append(f"{kind}[{i}]: matcher does not support {e}")
            continue
        report.cases.append(
            CaseResult(
                kind=kind,
                index=i,
                expected=expected,
                actual=res.matched,
                detections=res.detections,
                comment=str(event.get("_comment", "")),
            )
        )


def run_rule_tests(rule_path: Path, tests_root: Path | None = None) -> RuleReport:
    rule_path = Path(rule_path)
    tests_dir = find_tests_dir(rule_path, tests_root)
    report = RuleReport(rule_path=rule_path, tests_dir=tests_dir)

    try:
        compiled = CompiledRule.from_yaml(rule_path.read_text(encoding="utf-8"))
    except (SigmaError, UnsupportedSigmaFeature, OSError) as e:
        report.errors.append(f"could not load rule: {e}")
        return report

    for fname, kind, expected in ((TP_FILE, "true_positive", True), (FP_FILE, "false_positive", False)):
        path = tests_dir / fname
        if not path.is_file():
            report.errors.append(f"missing {path.as_posix()}")
            continue
        try:
            events = _load_events(path)
        except (ValueError, json.JSONDecodeError) as e:
            report.errors.append(f"bad {path.as_posix()}: {e}")
            continue
        if not events:
            report.errors.append(f"{path.as_posix()} has no events")
            continue
        replay(compiled, kind, events, report)
    return report


def discover_rules(paths: list[Path]) -> list[Path]:
    """Expand directories into every *.yml / *.yaml rule beneath them."""
    found: list[Path] = []
    for p in paths:
        if p.is_dir():
            found.extend(sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")]))
        else:
            found.append(p)
    return found
