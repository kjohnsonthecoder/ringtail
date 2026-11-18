"""The `ringtail run` loop: extract -> draft -> validate -> test -> write, retry up to 3x.

Every model reply is untrusted (docs/threat-model.md). The model proposes; this module
decides, using only deterministic checks:

- schema and type checks on every field;
- code-owned metadata (id, date, author, status) and a safe file name;
- `ringtail validate` (pySigma parse + lint + pinned ATT&CK);
- TP/FP replay through the matcher;
- sample guardrails: minimum counts, no duplicates, a near-miss false positive,
  placeholder-only data.

Failures go back to the model as an exact list of problems. Passing drafts are written to
drafts/ (by default) for a human to review. Nothing goes straight into rules/.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import uuid
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Callable

import yaml

from ringtail import config
from ringtail.attack import AttackIndex, default_index
from ringtail.card import CardNotes, CardNotesError, build_card
from ringtail.llm import LLM, LLMError
from ringtail.matcher import CompiledRule, UnsupportedSigmaFeature
from ringtail.sanitize import to_plain_text, wrap_as_data
from ringtail.testrunner import FP_FILE, TP_FILE, RuleReport, replay
from ringtail.validate import validate_text

AUTHOR = "Ringtail draft (AI-generated; review before use)"
SLUG_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
MIN_SAMPLES = 2
MIN_TRIAGE = 3

_STR = {"type": "string"}
_STR_LIST = {"type": "array", "items": _STR}

EXTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "behavior_summary": _STR,
        "log_source": {
            "type": "object",
            "properties": {"product": _STR, "category": _STR, "service": _STR},
            "required": ["product", "category", "service"],
            "additionalProperties": False,
        },
        "key_fields": _STR_LIST,
        "candidate_techniques": _STR_LIST,
        "notes": _STR,
    },
    "required": ["behavior_summary", "log_source", "key_fields", "candidate_techniques", "notes"],
    "additionalProperties": False,
}

DRAFT_SCHEMA = {
    "type": "object",
    "properties": {
        "slug": _STR,
        "rule_yaml": _STR,
        "true_positive_events": _STR_LIST,
        "false_positive_events": _STR_LIST,
        "card": {
            "type": "object",
            "properties": {"goal": _STR, "summary": _STR, "triage": _STR_LIST},
            "required": ["goal", "summary", "triage"],
            "additionalProperties": False,
        },
        "notes": _STR,
    },
    "required": ["slug", "rule_yaml", "true_positive_events", "false_positive_events", "card", "notes"],
    "additionalProperties": False,
}

# Real-looking secrets that must never appear in committed samples.
_SECRET_PATTERNS = [
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}"), "Anthropic API key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
]

_RULE_KEY_ORDER = [
    "title", "id", "status", "description", "references", "author", "date", "modified",
    "tags", "logsource", "detection", "fields", "falsepositives", "level",
]


def load_prompt(name: str) -> str:
    return resources.files("ringtail.prompts").joinpath(f"{name}.md").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Results


@dataclass
class Attempt:
    number: int
    errors: list[str]
    slug: str | None = None


@dataclass
class Candidate:
    slug: str
    rule_text: str
    true_positives: list[dict]
    false_positives: list[dict]
    card: CardNotes
    test_report: RuleReport
    notes: str = ""


@dataclass
class RunResult:
    passed: bool
    attempts: list[Attempt] = field(default_factory=list)
    extraction: dict | None = None
    written: list[Path] = field(default_factory=list)
    candidate: Candidate | None = None
    error: str | None = None  # a stop that isn't a check failure (LLM error, file exists)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "error": self.error,
            "attempts": [{"number": a.number, "slug": a.slug, "errors": a.errors} for a in self.attempts],
            "written": [p.as_posix() for p in self.written],
            "extraction": self.extraction,
        }


# ---------------------------------------------------------------------------
# Building prompts


def _attack_check_text(candidates: list[str], index: AttackIndex) -> str:
    if not candidates:
        return "- (the extraction step suggested no techniques)"
    lines = []
    for raw in candidates[:10]:
        tid = raw.strip().upper()
        t = index.technique(tid)
        if t is None:
            lines.append(f"- {tid}: does NOT exist in ATT&CK v{index.version}. Don't use it.")
        elif t.revoked:
            rep = index.technique(t.revoked_by) if t.revoked_by else None
            if rep is not None:
                lines.append(
                    f"- {tid}: REVOKED in v{index.version}. Use {rep.id} ({rep.name}; "
                    f"tactics: {', '.join(rep.tactics)}) instead."
                )
            else:
                lines.append(f"- {tid}: REVOKED in v{index.version}. Don't use it.")
        elif t.deprecated:
            lines.append(f"- {tid}: DEPRECATED in v{index.version}. Don't use it.")
        else:
            lines.append(f"- {tid}: valid. {t.name} (tactics: {', '.join(t.tactics)})")
    return "\n".join(lines)


def extract_prompt(clean_text: str) -> str:
    wrapped, _ = wrap_as_data(clean_text, "behavior_or_report")
    return load_prompt("extract").replace("{{INPUT}}", wrapped)


def draft_prompt(extraction: dict, index: AttackIndex, previous: dict | None = None,
                 errors: list[str] | None = None, attempt: int = 1,
                 max_attempts: int = config.MAX_ATTEMPTS) -> str:
    # The extraction is model output derived from untrusted input, so it is wrapped as data too.
    ext_json = json.dumps(extraction, indent=2, ensure_ascii=False)
    ext_wrapped, _ = wrap_as_data(ext_json, "extraction_json")
    prompt = (
        load_prompt("draft")
        .replace("{{ATTACK_VERSION}}", index.version)
        .replace("{{ATTACK_CHECK}}", _attack_check_text(extraction.get("candidate_techniques", []), index))
        .replace("{{TACTICS}}", ", ".join(index.tactic_names()))
        .replace("{{EXTRACTION}}", ext_wrapped)
    )
    retry = ""
    if previous is not None and errors:
        retry = (
            load_prompt("retry")
            .replace("{{ATTEMPT}}", str(attempt))
            .replace("{{MAX_ATTEMPTS}}", str(max_attempts))
            .replace("{{ERRORS}}", "\n".join(f"- {e}" for e in errors))
            .replace("{{PREVIOUS_JSON}}", json.dumps(previous, indent=2, ensure_ascii=False))
        )
    return prompt.replace("{{PREVIOUS_ATTEMPT}}", retry)


# ---------------------------------------------------------------------------
# Checks on model output


def check_extraction(data: dict) -> dict:
    """Light shape check. The extraction is only an input to the draft, never written."""
    for key in ("behavior_summary", "notes"):
        if not isinstance(data.get(key), str):
            raise LLMError(f"extraction: '{key}' must be a string")
    if not data["behavior_summary"].strip():
        raise LLMError("extraction: the model found no detectable behavior in the input")
    for key in ("key_fields", "candidate_techniques"):
        v = data.get(key)
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise LLMError(f"extraction: '{key}' must be a list of strings")
    if not isinstance(data.get("log_source"), dict):
        raise LLMError("extraction: 'log_source' must be an object")
    return data


def safe_slug(proposed: Any, title: str | None) -> str:
    if isinstance(proposed, str) and SLUG_RE.match(proposed):
        return proposed
    base = re.sub(r"[^a-z0-9]+", "_", (title or "ringtail_rule").lower()).strip("_")
    if not base or not base[0].isalpha():
        base = f"rule_{base}"
    return base[:64].rstrip("_") or "ringtail_rule"


def normalize_rule(rule_yaml: Any, today: dt.date) -> tuple[str, dict]:
    """Parse the model's YAML, overwrite code-owned metadata, and re-emit it in a stable
    key order. Raises ValueError with a message meant for the model."""
    if not isinstance(rule_yaml, str) or not rule_yaml.strip():
        raise ValueError("rule_yaml is empty")
    try:
        data = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        raise ValueError(f"rule_yaml is not valid YAML: {e}") from None
    if not isinstance(data, dict):
        raise ValueError("rule_yaml must be a YAML mapping (a single Sigma rule)")
    data["id"] = str(uuid.uuid4())
    data["status"] = "experimental"
    data["author"] = AUTHOR
    data["date"] = today
    data.pop("modified", None)
    ordered = {k: data[k] for k in _RULE_KEY_ORDER if k in data}
    ordered.update({k: v for k, v in data.items() if k not in ordered})
    text = yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, default_flow_style=False, width=100)
    return text, ordered


def _parse_events(raw: Any, kind: str, errors: list[str]) -> list[dict]:
    if not isinstance(raw, list):
        errors.append(f"{kind}_events must be a list")
        return []
    events = []
    for i, item in enumerate(raw):
        try:
            ev = json.loads(item) if isinstance(item, str) else item
        except json.JSONDecodeError as e:
            errors.append(f"{kind}[{i}] is not valid JSON ({e.msg})")
            continue
        if not isinstance(ev, dict) or not ev:
            errors.append(f"{kind}[{i}] must be a non-empty JSON object")
            continue
        events.append(ev)
    if len(events) < MIN_SAMPLES:
        errors.append(f"need at least {MIN_SAMPLES} valid {kind} samples, got {len(events)}")
    return events


def _secret_hits(texts: list[str]) -> list[str]:
    found = []
    for t in texts:
        for rx, label in _SECRET_PATTERNS:
            for m in rx.finditer(t):
                if "EXAMPLE" not in m.group(0).upper():
                    found.append(f"{label} '{m.group(0)[:12]}...'")
    return sorted(set(found))


def check_draft(draft: dict, index: AttackIndex, today: dt.date) -> tuple[Candidate | None, list[str]]:
    """Run every deterministic check. Returns (candidate, []) on success, else (None, errors)."""
    errors: list[str] = []

    tps = _parse_events(draft.get("true_positive_events"), "true_positive", errors)
    fps = _parse_events(draft.get("false_positive_events"), "false_positive", errors)

    seen: dict[str, str] = {}
    for kind, evs in (("true_positive", tps), ("false_positive", fps)):
        for i, ev in enumerate(evs):
            key = json.dumps({k: v for k, v in ev.items() if not k.startswith("_")}, sort_keys=True)
            if key in seen:
                errors.append(f"{kind}[{i}] is identical to {seen[key]} (ignoring _comment)")
            else:
                seen[key] = f"{kind}[{i}]"

    try:
        card = CardNotes.from_dict(draft.get("card"), where="card", min_triage=MIN_TRIAGE)
    except CardNotesError as e:
        errors.append(str(e))
        card = None

    try:
        rule_text, rule_data = normalize_rule(draft.get("rule_yaml"), today)
    except ValueError as e:
        errors.append(str(e))
        return None, errors

    secrets = _secret_hits([rule_text] + [json.dumps(e) for e in tps + fps])
    if secrets:
        errors.append(
            "samples or rule contain real-looking secrets; use placeholders containing EXAMPLE: "
            + ", ".join(secrets)
        )

    v = validate_text(rule_text, index=index)
    errors += [f"validate: {e}" for e in v.errors]
    if any(e.startswith("parse") for e in v.errors):
        return None, errors

    try:
        compiled = CompiledRule.from_yaml(rule_text)
    except UnsupportedSigmaFeature as e:
        errors.append(f"test engine does not support {e}; use only the supported Sigma subset")
        return None, errors
    except Exception as e:  # pySigma errors not caught by validate
        errors.append(f"test engine could not load the rule: {e}")
        return None, errors

    report = RuleReport(rule_path=Path("<draft>"), tests_dir=Path("<draft>"))
    replay(compiled, "true_positive", tps, report)
    replay(compiled, "false_positive", fps, report)
    errors += [f"test: {e}" for e in report.errors]
    errors += [f"test: {c.explain()}" for c in report.cases if not c.passed]

    if fps and not report.errors:
        try:
            near = [ev for ev in fps if compiled.leaf_hits(ev) > 0 and not compiled.match(ev).matched]
        except UnsupportedSigmaFeature:
            near = []
        if not near:
            errors.append(
                "guardrail: no false-positive sample is a near miss. At least one benign "
                "sample must satisfy some of the rule's field conditions without matching the "
                "whole rule, to prove the rule's logic is doing the rejecting"
            )

    if errors or card is None:
        return None, errors
    slug = safe_slug(draft.get("slug"), rule_data.get("title"))
    notes = draft.get("notes") if isinstance(draft.get("notes"), str) else ""
    return Candidate(slug, rule_text, tps, fps, card, report, notes), []


# ---------------------------------------------------------------------------
# Writing


class DraftExistsError(Exception):
    pass


def draft_paths(out_dir: Path, slug: str) -> dict[str, Path]:
    return {
        "rule": out_dir / "rules" / f"{slug}.yml",
        "tp": out_dir / "tests" / "rules" / slug / TP_FILE,
        "fp": out_dir / "tests" / "rules" / slug / FP_FILE,
        "notes": out_dir / "cards" / f"{slug}.yml",
        "card": out_dir / "cards" / f"{slug}.md",
    }


def write_candidate(c: Candidate, out_dir: Path, force: bool = False) -> list[Path]:
    out_dir = Path(out_dir)
    paths = draft_paths(out_dir, c.slug)
    if not force and paths["rule"].exists():
        raise DraftExistsError(f"{paths['rule'].as_posix()} already exists (use --force to overwrite)")
    for p in paths.values():
        resolved = p.resolve()
        if out_dir.resolve() not in resolved.parents:  # belt and braces: slug is already safe
            raise DraftExistsError(f"refusing to write outside {out_dir}: {p}")
        p.parent.mkdir(parents=True, exist_ok=True)

    def dump(path: Path, text: str) -> None:
        path.write_text(text, encoding="utf-8", newline="\n")

    dump(paths["rule"], c.rule_text)
    dump(paths["tp"], json.dumps(c.true_positives, indent=2, ensure_ascii=False) + "\n")
    dump(paths["fp"], json.dumps(c.false_positives, indent=2, ensure_ascii=False) + "\n")
    header = "# AI-drafted card notes. Review and edit, then regenerate the card with: ringtail card <rule>\n"
    dump(paths["notes"], header + yaml.safe_dump(c.card.to_dict(), sort_keys=False, allow_unicode=True, width=100))
    card_path, card_text, _ = build_card(paths["rule"], out_dir / "cards")
    dump(card_path, card_text)
    return list(paths.values())


# ---------------------------------------------------------------------------
# The loop


def extract(text: str, llm: LLM) -> dict:
    clean = to_plain_text(text)
    data = llm.complete_json(load_prompt("system"), extract_prompt(clean), EXTRACT_SCHEMA, purpose="extract")
    return check_extraction(data)


def draft_once(text: str, llm: LLM, index: AttackIndex | None = None,
               today: dt.date | None = None) -> tuple[dict, dict, str | None]:
    """Extract + one draft, no retries. Returns (extraction, raw draft, normalized YAML or None)."""
    index = index or default_index()
    extraction = extract(text, llm)
    draft = llm.complete_json(load_prompt("system"), draft_prompt(extraction, index), DRAFT_SCHEMA, purpose="draft")
    try:
        rule_text, _ = normalize_rule(draft.get("rule_yaml"), today or dt.date.today())
    except ValueError:
        rule_text = None
    return extraction, draft, rule_text


def run(text: str, llm: LLM, out_dir: Path = Path("drafts"), *, max_attempts: int = config.MAX_ATTEMPTS,
        force: bool = False, index: AttackIndex | None = None, today: dt.date | None = None,
        log: Callable[[str], None] = lambda _m: None) -> RunResult:
    index = index or default_index()
    today = today or dt.date.today()
    result = RunResult(passed=False)

    log("extracting behavior...")
    try:
        result.extraction = extract(text, llm)
    except LLMError as e:
        result.error = str(e)
        return result
    log(f"behavior: {result.extraction['behavior_summary']}")

    previous: dict | None = None
    errors: list[str] = []
    for n in range(1, max_attempts + 1):
        log(f"attempt {n}/{max_attempts}: drafting...")
        try:
            draft = llm.complete_json(
                load_prompt("system"),
                draft_prompt(result.extraction, index, previous, errors, n, max_attempts),
                DRAFT_SCHEMA,
                purpose=f"draft attempt {n}",
            )
        except LLMError as e:
            result.attempts.append(Attempt(n, [f"llm: {e}"]))
            errors = [f"your previous reply could not be used: {e}"]
            continue
        candidate, errors = check_draft(draft, index, today)
        result.attempts.append(Attempt(n, errors, candidate.slug if candidate else None))
        if candidate is None:
            log(f"attempt {n}: {len(errors)} problem(s)")
            for e in errors:
                log(f"  - {e}")
            previous = draft
            continue
        log(f"attempt {n}: all checks passed")
        try:
            result.written = write_candidate(candidate, out_dir, force)
        except DraftExistsError as e:
            result.error = str(e)
            result.candidate = candidate
            return result
        result.passed = True
        result.candidate = candidate
        return result

    result.error = f"no passing draft after {max_attempts} attempts"
    return result
