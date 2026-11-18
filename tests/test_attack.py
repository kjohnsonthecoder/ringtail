"""ATT&CK index building and tag checks, using a tiny synthetic STIX bundle."""

import json

import pytest

from ringtail.attack import PINNED_VERSION, AttackIndex, build_index, check_tags, default_index


def ref(eid):
    return [{"source_name": "mitre-attack", "external_id": eid}]


def phases(*names):
    return [{"kill_chain_name": "mitre-attack", "phase_name": n} for n in names]


BUNDLE = {
    "type": "bundle",
    "objects": [
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Execution",
         "x_mitre_shortname": "execution", "external_references": ref("TA0002")},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--2", "name": "Stealth",
         "x_mitre_shortname": "stealth", "external_references": ref("TA0005")},
        {"type": "attack-pattern", "id": "attack-pattern--live", "name": "PowerShell",
         "external_references": ref("T1059.001"), "kill_chain_phases": phases("execution")},
        {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Old Thing", "revoked": True,
         "external_references": ref("T1000.001"), "kill_chain_phases": phases("stealth")},
        {"type": "attack-pattern", "id": "attack-pattern--new", "name": "New Thing",
         "external_references": ref("T2000.001"), "kill_chain_phases": phases("stealth")},
        {"type": "attack-pattern", "id": "attack-pattern--dep", "name": "Retired", "x_mitre_deprecated": True,
         "external_references": ref("T3000"), "kill_chain_phases": phases("stealth")},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--old", "target_ref": "attack-pattern--new"},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Example Group",
         "external_references": ref("G0001")},
        {"type": "malware", "id": "malware--1", "name": "Example Malware", "external_references": ref("S0001")},
    ],
}


@pytest.fixture()
def index(tmp_path):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(BUNDLE), encoding="utf-8")
    return AttackIndex(build_index(p, version="0.0"))


def test_build_index_records_revocations_and_hash(index):
    data = index.data
    assert len(data["source_sha256"]) == 64
    assert data["techniques"]["T1000.001"]["revoked_by"] == "T2000.001"
    assert data["techniques"]["T1059.001"]["tactics"] == ["execution"]
    assert set(data["tactics"]) == {"execution", "stealth"}
    assert "G0001" in data["groups"] and "S0001" in data["software"]


def test_valid_tags_pass(index):
    r = check_tags(["attack.execution", "attack.t1059.001", "attack.g0001", "attack.s0001"], index)
    assert r.errors == [] and r.warnings == []
    assert [t.id for t in r.techniques] == ["T1059.001"]


@pytest.mark.parametrize(
    "tags, needle",
    [
        (["attack.t1000.001"], "revoked in ATT&CK v0.0; use T2000.001 instead"),
        (["attack.t3000"], "deprecated"),
        (["attack.t9999"], "does not exist"),
        (["attack.t1059.001", "attack.defense-evasion"], "Valid tactics: execution, stealth"),
        (["attack.g9999", "attack.t1059.001"], "G9999 does not exist"),
        (["attack.execution"], "no ATT&CK technique tag"),
    ],
)
def test_bad_tags_fail(index, tags, needle):
    r = check_tags(tags, index)
    assert any(needle in e for e in r.errors), r.errors


def test_tactic_mismatch_is_a_warning(index):
    r = check_tags(["attack.stealth", "attack.t1059.001"], index)
    assert r.errors == []
    assert "none of the tagged techniques belong" in r.warnings[0]


def test_committed_index_is_the_pinned_version():
    idx = default_index()
    assert idx.version == PINNED_VERSION
    assert len(idx.data["source_sha256"]) == 64
    t = idx.technique("T1059.001")
    assert t is not None and t.name == "PowerShell" and not t.revoked
