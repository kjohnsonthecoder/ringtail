"""ringtail validate: committed rules are valid, and broken rules fail with a useful reason."""

from pathlib import Path

import pytest

from ringtail.testrunner import discover_rules
from ringtail.validate import validate_rule, validate_text

ROOT = Path(__file__).resolve().parents[1]
RULES = discover_rules([ROOT / "rules"])

GOOD = """\
title: Example
id: 5f0c7a1e-0000-4000-8000-000000000001
status: experimental
description: Example rule for validator tests.
author: test
date: 2026-11-17
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '.exe'
  condition: selection
falsepositives:
  - Unknown
level: low
"""


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_committed_rules_are_valid(rule_path):
    r = validate_rule(rule_path)
    assert r.passed, r.errors


def test_good_rule_passes():
    r = validate_text(GOOD)
    assert r.passed, r.errors
    assert [t.id for t in r.techniques] == ["T1059.001"]


@pytest.mark.parametrize(
    "old, new, needle",
    [
        ("  - attack.t1059.001", "  - attack.t1562.008", "revoked"),
        ("  - attack.t1059.001", "  - attack.t1059.999", "does not exist"),
        ("  - attack.execution", "  - attack.defense-evasion", "Valid tactics"),
        ("  condition: selection", "  condition: selection and other", "parse"),
        ("Image|endswith:", "Image|endswithh:", "parse"),
        ("falsepositives:\n  - Unknown\n", "", "falsepositives"),
        ("level: low\n", "", "level"),
        ("  condition: selection", "  unused:\n    Foo: bar\n  condition: selection", "Dangling"),
    ],
)
def test_broken_rules_fail(old, new, needle):
    assert old in GOOD
    r = validate_text(GOOD.replace(old, new))
    assert not r.passed
    assert any(needle.lower() in e.lower() for e in r.errors), r.errors


def test_invalid_yaml_is_a_parse_error():
    r = validate_text("title: [unclosed\n")
    assert not r.passed and r.errors[0].startswith("parse")
