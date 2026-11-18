"""Cross-check plumbing (with a stand-in engine) and the coverage drawing."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from ringtail import backtest as bt
from ringtail import coverage as cv
from ringtail import crosscheck as xc
from ringtail.attack import default_index
from ringtail.testrunner import discover_rules

ROOT = Path(__file__).resolve().parents[1]
RULE_PATHS = discover_rules([ROOT / "rules"])
RULES = bt.load_rules(RULE_PATHS)

# A stand-in for `rsigma engine eval -r RULE -e @FILE` that prints one result per match,
# using Ringtail's matcher (optionally lying about one rule). It exercises the plumbing;
# the real RSigma runs in CI.
FAKE = r'''
import json, sys
sys.path.insert(0, {core!r})
from ringtail.matcher import CompiledRule
args = sys.argv[1:]
rule = args[args.index("-r") + 1]
src = args[args.index("-e") + 1][1:]
text = open(rule, encoding="utf-8").read()
r = CompiledRule.from_yaml(text)
lie = {lie!r} and {lie!r} in rule
for line in open(src, encoding="utf-8"):
    ev = json.loads(line)
    hit = r.match(ev).matched
    if lie:
        hit = not hit
    if hit:
        print(json.dumps({{"rule_title": "x", "rule_id": "y", "matched_fields": []}}))
print("Processed events.", file=sys.stderr)
'''


def fake_cmd(tmp_path, lie=""):
    f = tmp_path / "fake_rsigma.py"
    f.write_text(FAKE.format(core=str(ROOT / "core"), lie=lie), encoding="utf-8")
    return [sys.executable, str(f)]


def test_agreeing_engines_report_no_disagreements(tmp_path):
    events = {"rec": [{"Channel": bt.SYSMON, "EventID": 1, "Image": "C:\\Windows\\System32\\rundll32.exe",
                       "OriginalFileName": "RUNDLL32.EXE", "CommandLine": "rundll32 comsvcs.dll MiniDump 1 x full"}]}
    rep = xc.run(fake_cmd(tmp_path), RULES, events)
    assert rep.disagreements == []
    assert rep.checked_samples >= 2 * len(RULES) * 2
    assert rep.checked_recordings >= 1


def test_a_disagreement_is_reported_per_sample(tmp_path):
    rep = xc.run(fake_cmd(tmp_path, lie="win_proc_nltest"), RULES, None)
    bad = [d for d in rep.disagreements if d.rule == "win_proc_nltest_domain_trust_discovery"]
    assert bad and all(d.rule == "win_proc_nltest_domain_trust_discovery" for d in rep.disagreements)
    assert "true_positive[0]" in str(bad[0]) and "RSigma matched 0" in str(bad[0])


def test_result_counting_ignores_noise():
    out = '{"rule_title": "a"}\n\nnot json\n{"other": 1}\n{"rule_id": "b"}\n'
    assert xc._results(out) == 2


def test_missing_rsigma_is_none():
    assert xc.find_rsigma("definitely-not-a-real-binary-xyz") is None


# --- coverage -----------------------------------------------------------------------


def test_tactic_line_matches_pinned_attack_and_maps_every_tactic_to_a_kill_chain_phase():
    assert {k for k, _, _ in cv.TACTICS} == set(default_index().tactic_names())
    assert all(phase in cv.PHASE_COLORS for _, _, phase in cv.TACTICS)
    assert [p for _, _, p in cv.TACTICS][:4] == ["Reconnaissance", "Weaponization", "Delivery", "Exploitation"]


def test_coverage_svg_is_valid_and_deterministic():
    report = json.loads(bt.REPORT_JSON.read_text(encoding="utf-8"))
    a = cv.render(RULE_PATHS, report, "20.1")
    assert a == cv.render(RULE_PATHS, report, "20.1")
    root = ET.fromstring(a)  # our own generated SVG, not untrusted XML, so stdlib parsing is fine
    assert root.tag.endswith("svg")
    text = " ".join(t.text or "" for t in root.iter() if t.tag.endswith("text"))
    for needle in ("Installation", "Credential Access", "T1003.001", "proven on real attacks", "no rule yet"):
        assert needle in text, needle


def test_committed_coverage_images_are_fresh():
    report = json.loads(bt.REPORT_JSON.read_text(encoding="utf-8"))
    svg = cv.render(RULE_PATHS, report, default_index().version)
    for path in cv.OUTPUTS:
        assert path.read_text(encoding="utf-8").replace("\r\n", "\n") == svg, f"run: ringtail coverage ({path.name})"


def test_rules_appear_under_each_of_their_tactics():
    report = json.loads(bt.REPORT_JSON.read_text(encoding="utf-8"))
    svg = cv.render(RULE_PATHS, report, "20.1")
    assert svg.count("RustDesk") == 2  # persistence and command-and-control
