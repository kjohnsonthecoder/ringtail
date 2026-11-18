"""Detection cards: committed cards must match a fresh render, and notes are validated."""

from pathlib import Path

import pytest

from ringtail.card import CardNotes, CardNotesError, build_card, render_card
from ringtail.testrunner import CaseResult, RuleReport, discover_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = discover_rules([ROOT / "rules"])


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_committed_card_is_fresh(rule_path):
    card_path, text, report = build_card(rule_path, ROOT / "cards")
    assert report.passed
    assert card_path.is_file(), f"missing {card_path.name}: run `ringtail card rules/`"
    committed = card_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert committed == text, f"{card_path.name} is stale: run `ringtail card rules/`"


@pytest.mark.parametrize(
    "body, msg",
    [
        ("summary: s\ntriage: [a]\n", "goal"),
        ("goal: g\ntriage: [a]\n", "summary"),
        ("goal: g\nsummary: s\ntriage: []\n", "triage"),
        ("goal: g\nsummary: s\ntriage: 'one string'\n", "triage"),
    ],
)
def test_notes_are_validated(tmp_path, body, msg):
    p = tmp_path / "x.yml"
    p.write_text(body, encoding="utf-8")
    with pytest.raises(CardNotesError, match=msg):
        CardNotes.load(p)


def test_missing_notes_file(tmp_path):
    with pytest.raises(CardNotesError, match="missing"):
        CardNotes.load(tmp_path / "nope.yml")


def test_failing_rule_renders_as_fail():
    rule = ROOT / "rules/frontline-pack/windows/win_proc_encoded_powershell.yml"
    report = RuleReport(rule_path=rule, tests_dir=Path("tests/rules/x"))
    report.cases.append(CaseResult("true_positive", 0, True, False, {"sel": False}, "a <b> | c"))
    text = render_card(rule, CardNotes("g", "s", ["t"]), report)
    assert "**FAIL**: 0/1 true-positive" in text
    assert "| a &lt;b&gt; \\| c | yes | no | **FAIL** |" in text
