"""Real-data backtest logic (ADR 0006). No network: synthetic archives and events only.
The real recordings are replayed in CI by `ringtail backtest --check`."""

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
import yaml

from ringtail import backtest as bt
from ringtail.testrunner import discover_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = bt.load_rules(discover_rules([ROOT / "rules"]))
SYSMON = bt.SYSMON


def proc(cmd, image="C:\\Windows\\System32\\rundll32.exe", ofn="RUNDLL32.EXE"):
    return {"Channel": SYSMON, "EventID": 1, "Image": image, "OriginalFileName": ofn, "CommandLine": cmd}


LSASS = proc("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\x.dmp full")
BENIGN = proc("rundll32.exe shell32.dll,Control_RunDLL desk.cpl")


def manifest(*datasets):
    return {"source": {"name": "OTRF", "repo": "r", "license": "MIT", "commit": "c" * 40,
                       "base_url": "https://raw.githubusercontent.com/OTRF/x"},
            "datasets": [{"note": "", "fires": [], "gaps": {}, **d} for d in datasets]}


def ds(id_, **kw):
    return {"id": id_, "path": f"credential_access/host/{id_}.zip", "sha256": "0" * 64, "techniques": ["T1003.001"], **kw}


def test_committed_manifest_is_valid_and_pinned():
    m = bt.load_manifest()
    assert len(m["source"]["commit"]) == 40
    assert m["source"]["base_url"].endswith(m["source"]["commit"] + "/datasets/atomic/windows")
    stems = {r.stem for r in RULES}
    for d in m["datasets"]:
        assert set(d["fires"]) <= stems and set(d["gaps"]) <= stems


def test_committed_manifest_techniques_exist_in_pinned_attack():
    from ringtail.attack import default_index
    ix = default_index()
    for d in bt.load_manifest()["datasets"]:
        for t in d["techniques"]:
            tech = ix.technique(t)
            assert tech and not tech.revoked and not tech.deprecated, (d["id"], t)


@pytest.mark.parametrize("bad, needle", [
    ({"sha256": "abc"}, "sha256"),
    ({"path": "../../etc/passwd.zip"}, "path"),
    ({"path": "credential_access/host/x.tar.gz"}, "path"),
    ({"id": "Bad Id!"}, "id"),
    ({"techniques": ["1003"]}, "techniques"),
])
def test_manifest_rejects_unsafe_or_malformed_entries(tmp_path, bad, needle):
    m = manifest({**ds("good_one"), **bad})
    p = tmp_path / "m.yml"
    p.write_text(yaml.safe_dump(m), encoding="utf-8")
    with pytest.raises(bt.BacktestError, match=needle):
        bt.load_manifest(p)


def test_manifest_requires_the_otrf_base_url(tmp_path):
    m = manifest(ds("good_one"))
    m["source"]["base_url"] = "https://evil.example/data"
    p = tmp_path / "m.yml"
    p.write_text(yaml.safe_dump(m), encoding="utf-8")
    with pytest.raises(bt.BacktestError, match="base_url"):
        bt.load_manifest(p)


def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_read_events_only_reads_json_members_and_skips_junk():
    blob = _zip({
        "a.json": json.dumps(LSASS) + "\n\nnot json\n" + json.dumps([1, 2]) + "\n" + json.dumps(BENIGN),
        "../../evil.sh": "rm -rf /",
        "readme.txt": "ignored",
    })
    evs = bt.read_events(blob)
    assert evs == [LSASS, BENIGN]


def test_read_events_enforces_the_size_cap(monkeypatch):
    monkeypatch.setattr(bt, "MAX_UNCOMPRESSED", 10)
    with pytest.raises(bt.BacktestError, match="size cap"):
        bt.read_events(_zip({"a.json": json.dumps(LSASS)}))


def test_fetch_uses_cache_only_when_the_hash_matches(tmp_path):
    blob = _zip({"a.json": json.dumps(LSASS)})
    sha = hashlib.sha256(blob).hexdigest()
    (tmp_path / f"{sha}.zip").write_bytes(blob)
    assert bt.fetch({"id": "x", "sha256": sha, "path": "p"}, "https://unused", tmp_path, offline=True) == blob
    (tmp_path / f"{sha}.zip").write_bytes(b"tampered")
    with pytest.raises(bt.BacktestError, match="offline"):
        bt.fetch({"id": "x", "sha256": sha, "path": "p"}, "https://unused", tmp_path, offline=True)
    assert not (tmp_path / f"{sha}.zip").exists()  # the tampered file was discarded


def test_logsource_filter():
    pc = next(r for r in RULES if r.stem == "win_proc_lsass_dump_comsvcs").sigma.logsource
    assert bt.applies(pc, LSASS)
    assert not bt.applies(pc, {**LSASS, "EventID": 10})
    assert not bt.applies(pc, {**LSASS, "Channel": "Security"})
    ct = next(r for r in RULES if r.stem == "aws_cloudtrail_logging_disabled").sigma.logsource
    assert bt.applies(ct, {"eventSource": "x", "eventName": "y"}) and not bt.applies(ct, LSASS)


def test_outcomes_detected_gap_unexpected_regression():
    m = manifest(
        ds("hit", fires=["win_proc_lsass_dump_comsvcs"]),
        ds("missed_on_purpose", gaps={"win_proc_lsass_dump_comsvcs": "different method"}),
        ds("should_have_fired", fires=["win_proc_lsass_dump_comsvcs"]),
        ds("noise"),
    )
    events = {"hit": [LSASS, BENIGN], "missed_on_purpose": [BENIGN], "should_have_fired": [BENIGN], "noise": [LSASS]}
    rep = bt.run(RULES, m, events)
    r = next(x for x in rep["rules"] if x["rule"] == "win_proc_lsass_dump_comsvcs")
    assert r["status"] == "real"
    assert r["detected"] == [{"dataset": "hit", "events": 1}]
    assert r["gaps"] == [{"dataset": "missed_on_purpose", "reason": "different method", "fired": False}]
    assert r["regressions"] == ["should_have_fired"]
    assert r["unexpected"] == [{"dataset": "noise", "events": 1}]
    probs = bt.problems(rep)
    assert any("expected to fire on should_have_fired" in p for p in probs)
    assert any("fired 1x on noise" in p for p in probs)
    md = bt.to_markdown(rep)
    assert "misses `missed_on_purpose`: different method" in md


def test_unknown_rule_in_manifest_is_an_error():
    with pytest.raises(bt.BacktestError, match="unknown rule"):
        bt.run(RULES, manifest(ds("x", fires=["no_such_rule"])), {"x": []})


def test_committed_report_matches_the_manifest():
    rep = json.loads(bt.REPORT_JSON.read_text(encoding="utf-8"))
    ids = [d["id"] for d in bt.load_manifest()["datasets"]]
    assert [d["id"] for d in rep["datasets"]] == ids
    assert rep["totals"]["unexpected"] == 0 and rep["totals"]["regressions"] == 0
    assert bt.to_markdown(rep) == bt.REPORT_MD.read_text(encoding="utf-8").replace("\r\n", "\n")
