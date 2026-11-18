"""SIEM conversion (ADR 0004): Splunk via the official backend, KQL via our own backend."""

from pathlib import Path

import pytest

from ringtail.convert import TARGETS, code_fence, convert_rule
from ringtail.testrunner import discover_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = discover_rules([ROOT / "rules"])


def _q(text: str, target: str):
    return convert_rule(text, [target])[0]


@pytest.mark.parametrize("rule", RULES, ids=lambda p: p.stem)
def test_every_frontline_rule_converts_to_every_target(rule):
    for c in convert_rule(rule.read_text(encoding="utf-8")):
        assert c.error is None, f"{rule.stem} -> {c.target}: {c.error}"
        assert c.query and c.schema


def test_kql_maps_tables_fields_and_escapes_backslashes():
    q = _q((ROOT / "rules/frontline-pack/windows/win_proc_lsass_dump_comsvcs.yml").read_text(encoding="utf-8"), "kql").query
    assert q.startswith("DeviceProcessEvents\n| where ")
    assert 'FolderPath endswith "\\\\rundll32.exe"' in q        # KQL string: "\\rundll32.exe"
    assert 'ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE"' in q
    assert 'ProcessCommandLine contains "comsvcs"' in q
    assert "CommandLine " not in q.replace("ProcessCommandLine", "")  # no unmapped Sigma field names


def test_kql_not_is_a_function_call():
    q = _q((ROOT / "rules/frontline-pack/cloudtrail/aws_console_login_without_mfa.yml").read_text(encoding="utf-8"), "kql").query
    assert 'not(UserIdentityType =~ "AssumedRole")' in q
    assert "not UserIdentityType" not in q
    assert "tostring(parse_json(AdditionalEventData).MFAUsed) =~ \"No\"" in q


def test_kql_groups_and_inside_or():
    q = _q((ROOT / "rules/frontline-pack/windows/win_proc_shadow_copy_deletion.yml").read_text(encoding="utf-8"), "kql").query
    where = q.split("| where ", 1)[1]
    assert where.startswith("((FolderPath endswith")
    assert ') or ((FolderPath endswith "\\\\wmic.exe"' in where


def test_kql_numbers_use_double_equals_and_duplicates_are_dropped():
    q = _q((ROOT / "rules/frontline-pack/windows/win_system_rustdesk_service_install.yml").read_text(encoding="utf-8"), "kql").query
    assert "EventID == 7045" in q
    assert q.count('RenderedDescription contains "rustdesk"') == 1


def test_splunk_uses_windows_pipeline_and_cloudtrail_sourcetype():
    rd = _q((ROOT / "rules/frontline-pack/windows/win_system_rustdesk_service_install.yml").read_text(encoding="utf-8"), "splunk").query
    assert rd.startswith('source="WinEventLog:System"') and "EventCode=7045" in rd
    ct = _q((ROOT / "rules/frontline-pack/cloudtrail/aws_cloudtrail_logging_disabled.yml").read_text(encoding="utf-8"), "splunk").query
    assert ct.startswith('sourcetype="aws:cloudtrail" ')


UNMAPPED_SOURCE = """
title: Linux thing
id: 00000000-0000-4000-8000-000000000001
status: test
logsource: {product: linux, category: process_creation}
detection:
  sel: {Image|endswith: /curl}
  condition: sel
level: low
"""

UNMAPPED_FIELD = """
title: Windows thing with an unmapped field
id: 00000000-0000-4000-8000-000000000002
status: test
logsource: {product: windows, category: process_creation}
detection:
  sel: {IntegrityLevel: High}
  condition: sel
level: low
"""


def test_unmapped_log_source_is_reported_not_guessed():
    c = _q(UNMAPPED_SOURCE, "kql")
    assert c.query is None and "no KQL table mapping" in c.error and "linux" in c.error
    assert _q(UNMAPPED_SOURCE, "splunk").query  # Splunk keeps the rule's own field names


def test_unmapped_field_is_reported_not_guessed():
    c = _q(UNMAPPED_FIELD, "kql")
    assert c.query is None and "IntegrityLevel" in c.error


def test_unknown_target_is_an_error():
    with pytest.raises(ValueError, match="unknown target"):
        convert_rule(UNMAPPED_SOURCE, ["elastic"])
    assert set(TARGETS) == {"splunk", "kql"}


def test_code_fence_outgrows_backticks_in_the_query():
    f = code_fence('x contains "```"', "kql")
    assert f.startswith("````kql\n") and f.endswith("\n````")
    assert code_fence("plain").startswith("```\n")
