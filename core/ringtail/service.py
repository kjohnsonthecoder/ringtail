"""The two operations the web page needs, as plain functions over JSON-able dicts.

ADR 0003: the browser holds the key and runs the retry loop; the backend builds prompts
and runs the checks. This module is that backend logic without HTTP, so it is unit-tested
directly and shared with any future front end. It never calls a model and never takes a key.

Everything a request carries is untrusted: the input text (a threat report), the
extraction and drafts (model output relayed by a browser we don't control). Each field is
type-checked here before use, and the retry errors are recomputed by code from the
previous draft rather than accepted from the client.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

import yaml

from ringtail import config
from ringtail.attack import AttackIndex, default_index
from ringtail.card import render_card_text
from ringtail.llm import LLMError
from ringtail.pipeline import (
    CARD_NOTES_HEADER,
    DRAFT_SCHEMA,
    EXTRACT_SCHEMA,
    check_draft,
    check_extraction,
    draft_prompt,
    extract_prompt,
    load_prompt,
)
from ringtail.sanitize import InputError, to_plain_text

_KEY_IN_INPUT = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}")


class ServiceError(ValueError):
    """The request is unusable. The message is safe to show the user (it never echoes input)."""


def info(index: AttackIndex | None = None) -> dict:
    index = index or default_index()
    return {
        "status": "ok",
        "attack_version": index.version,
        "default_model": config.DEFAULT_MODEL,
        "max_attempts": config.MAX_ATTEMPTS,
    }


def _prompt(stage: str, user: str, schema: dict, purpose: str) -> dict:
    return {"stage": stage, "purpose": purpose, "system": load_prompt("system"), "user": user, "schema": schema}


def build_prompt(req: Any, index: AttackIndex | None = None, today: dt.date | None = None) -> dict:
    """Return {stage, purpose, system, user, schema} for the browser to send to Claude.

    stage "extract": {"stage": "extract", "input": "<behavior text or report>"}
    stage "draft":   {"stage": "draft", "extraction": {...}, "attempt": 1..N, "previous": {...}?}

    For a retry, send the failed draft as `previous`. Its errors are recomputed here by the
    same checks as /api/check, so the client can't put its own words into the retry prompt.
    """
    if not isinstance(req, dict):
        raise ServiceError("request body must be a JSON object")
    stage = req.get("stage")

    if stage == "extract":
        text = req.get("input")
        if not isinstance(text, str):
            raise ServiceError("'input' must be a string")
        if _KEY_IN_INPUT.search(text):
            raise ServiceError(
                "the input looks like it contains an Anthropic API key. Remove it: your key goes "
                "only in the key field, which is never sent to this server."
            )
        try:
            clean = to_plain_text(text)
        except InputError as e:
            raise ServiceError(str(e)) from None
        return _prompt("extract", extract_prompt(clean), EXTRACT_SCHEMA, "extract")

    if stage == "draft":
        index = index or default_index()
        try:
            extraction = check_extraction(req.get("extraction") if isinstance(req.get("extraction"), dict) else {})
        except LLMError as e:
            raise ServiceError(str(e)) from None
        attempt = req.get("attempt", 1)
        if not isinstance(attempt, int) or isinstance(attempt, bool) or not 1 <= attempt <= config.MAX_ATTEMPTS:
            raise ServiceError(f"'attempt' must be an integer from 1 to {config.MAX_ATTEMPTS}")
        previous = req.get("previous")
        errors: list[str] = []
        if previous is not None:
            # A retry. Without `previous` (the last reply was unusable) it's a fresh draft.
            if attempt == 1:
                raise ServiceError("'previous' is only allowed when attempt > 1")
            if not isinstance(previous, dict):
                raise ServiceError("'previous' must be the failed draft object")
            _, errors = check_draft(previous, index, today or dt.date.today())
            if not errors:
                raise ServiceError("'previous' passes every check; there is nothing to retry")
        user = draft_prompt(extraction, index, previous, errors, attempt, config.MAX_ATTEMPTS)
        return _prompt("draft", user, DRAFT_SCHEMA, f"draft attempt {attempt}")

    raise ServiceError("'stage' must be 'extract' or 'draft'")


def check(req: Any, index: AttackIndex | None = None, today: dt.date | None = None) -> dict:
    """Run every deterministic check on a draft: {"draft": {...}}.

    Returns {"passed": false, "errors": [...]} or {"passed": true, "errors": [], "result": {...}}
    where result holds the normalized rule, samples, card notes, and the rendered card.
    """
    if not isinstance(req, dict) or not isinstance(req.get("draft"), dict):
        raise ServiceError("request body must be {\"draft\": {...}}")
    index = index or default_index()
    candidate, errors = check_draft(req["draft"], index, today or dt.date.today())
    if candidate is None:
        return {"passed": False, "errors": errors}

    report = candidate.test_report
    report.tests_dir = Path(candidate.slug)  # the card names tests/rules/<slug>/, matching the download
    card_md = render_card_text(candidate.rule_text, candidate.slug, candidate.card, report)
    tp_ok, tp_n = report.counts("true_positive")
    fp_ok, fp_n = report.counts("false_positive")
    return {
        "passed": True,
        "errors": [],
        "result": {
            "slug": candidate.slug,
            "rule_yaml": candidate.rule_text,
            "true_positives": candidate.true_positives,
            "false_positives": candidate.false_positives,
            "card_notes": candidate.card.to_dict(),
            "card_notes_yaml": CARD_NOTES_HEADER + yaml.safe_dump(
                candidate.card.to_dict(), sort_keys=False, allow_unicode=True, width=100),
            "card_markdown": card_md,
            "tests": {
                "true_positive": {"passed": tp_ok, "total": tp_n},
                "false_positive": {"passed": fp_ok, "total": fp_n},
            },
            "notes": candidate.notes,
        },
    }
