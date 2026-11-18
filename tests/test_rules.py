"""Every committed rule must pass its true-positive and false-positive samples."""

from pathlib import Path

import pytest

from ringtail.testrunner import discover_rules, run_rule_tests

ROOT = Path(__file__).resolve().parents[1]
RULES = discover_rules([ROOT / "rules"])


def test_rules_exist():
    assert RULES, "no rules found under rules/"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_rule_passes_samples(rule_path):
    report = run_rule_tests(rule_path)
    details = "\n".join(report.errors + [c.explain() for c in report.cases if not c.passed])
    assert report.passed, details
