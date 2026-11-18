"""Unit tests for the matcher: one small rule per Sigma feature we claim to support."""

import pytest

from ringtail.matcher import CompiledRule, UnsupportedSigmaFeature


def rule(detection: str) -> CompiledRule:
    body = "\n".join("  " + line for line in detection.strip().splitlines())
    return CompiledRule.from_yaml(f"title: t\nlogsource:\n  product: test\ndetection:\n{body}\n")


def hits(r: CompiledRule, event: dict) -> bool:
    return r.match(event).matched


def test_plain_equals_is_case_insensitive():
    r = rule("sel:\n  Image: 'C:\\Tools\\A.exe'\ncondition: sel")
    assert hits(r, {"Image": r"c:\tools\a.EXE"})
    assert not hits(r, {"Image": r"c:\tools\a.exe.bak"})


def test_cased_modifier():
    r = rule("sel:\n  Name|cased: Foo\ncondition: sel")
    assert hits(r, {"Name": "Foo"})
    assert not hits(r, {"Name": "foo"})


def test_contains_startswith_endswith():
    r = rule("sel:\n  a|contains: mid\n  b|startswith: pre\n  c|endswith: post\ncondition: sel")
    assert hits(r, {"a": "xxMIDxx", "b": "prefix", "c": "lamppost"})
    assert not hits(r, {"a": "xxMIDxx", "b": "aprefix", "c": "lamppost"})


def test_wildcards_and_escaped_star():
    r = rule("sel:\n  f: 'a?c*z'\n  g: 'lit\\*'\ncondition: sel")
    assert hits(r, {"f": "abcxyz", "g": "lit*"})
    assert not hits(r, {"f": "abcxyz", "g": "litX"})


def test_list_values_are_or_and_all_modifier_is_and():
    r_or = rule("sel:\n  f|contains: [aa, bb]\ncondition: sel")
    r_all = rule("sel:\n  f|contains|all: [aa, bb]\ncondition: sel")
    assert hits(r_or, {"f": "xx bb"})
    assert not hits(r_all, {"f": "xx bb"})
    assert hits(r_all, {"f": "aa bb"})


def test_windash_matches_slash_and_unicode_dash():
    r = rule("sel:\n  CommandLine|contains|windash: ' -enc '\ncondition: sel")
    assert hits(r, {"CommandLine": "powershell /enc AAAA"})
    assert hits(r, {"CommandLine": "powershell \u2013enc AAAA"})
    assert not hits(r, {"CommandLine": "powershell -NoProfile"})


def test_base64offset():
    r = rule("sel:\n  CommandLine|base64offset|contains: 'http://'\ncondition: sel")
    import base64
    payload = base64.b64encode(b"get http://example.invalid").decode()
    assert hits(r, {"CommandLine": f"x {payload}"})
    assert not hits(r, {"CommandLine": "x aGVsbG8="})


def test_regex():
    r = rule("sel:\n  f|re: '^ab\\d+$'\ncondition: sel")
    assert hits(r, {"f": "ab123"})
    assert not hits(r, {"f": "xab123"})


def test_numbers_bools_null_exists():
    r = rule(
        "sel:\n  EventID: 4688\n  ok: true\n  gone: null\n  here|exists: true\ncondition: sel"
    )
    assert hits(r, {"EventID": 4688, "ok": True, "here": 1})
    assert hits(r, {"EventID": "4688", "ok": True, "here": "x"})
    assert not hits(r, {"EventID": 4688, "ok": True, "here": 1, "gone": "x"})
    assert not hits(r, {"EventID": 4688, "ok": True})


def test_compare_and_cidr():
    r = rule("sel:\n  n|gte: 10\n  ip|cidr: 10.0.0.0/8\ncondition: sel")
    assert hits(r, {"n": 10, "ip": "10.1.2.3"})
    assert not hits(r, {"n": 9, "ip": "10.1.2.3"})
    assert not hits(r, {"n": 10, "ip": "192.168.1.1"})


def test_nested_fields_and_event_lists():
    r = rule("sel:\n  userIdentity.type: Root\n  tags: prod\ncondition: sel")
    assert hits(r, {"userIdentity": {"type": "Root"}, "tags": ["dev", "prod"]})
    assert not hits(r, {"userIdentity": {"type": "IAMUser"}, "tags": ["prod"]})


def test_keywords_search_all_values_but_skip_comments():
    r = rule("kw:\n  - mimikatz\ncondition: kw")
    assert hits(r, {"a": {"b": "run Mimikatz now"}})
    assert not hits(r, {"_comment": "mimikatz", "a": "clean"})


def test_condition_logic_and_detection_breakdown():
    r = rule(
        "sel_a:\n  a: 1\nsel_b:\n  b: 2\nfilter:\n  c: 3\n"
        "condition: all of sel_* and not filter"
    )
    res = r.match({"a": 1, "b": 2, "c": 3})
    assert not res.matched
    assert res.detections == {"sel_a": True, "sel_b": True, "filter": True}
    assert r.match({"a": 1, "b": 2}).matched


def test_unsupported_feature_fails_loud():
    r = rule("sel:\n  a|fieldref: b\ncondition: sel")
    with pytest.raises(UnsupportedSigmaFeature):
        r.match({"a": "x", "b": "x"})
