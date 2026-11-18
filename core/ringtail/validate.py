"""Validate a Sigma rule: does it parse, does it lint clean, and do its ATT&CK tags hold up?

Three layers, all deterministic:

1. pySigma parse: invalid YAML, unknown modifiers, broken conditions, bad field types.
2. pySigma lint: its built-in validators (dangling detections, duplicate tags, wildcard
   misuse, ...). Its own ATT&CK tag validator is turned off because it downloads the
   latest ATT&CK at runtime. We check ATT&CK against the pinned index instead.
3. Ringtail rules: required metadata plus attack.py's pinned ATT&CK checks.

Errors fail validation. Warnings are reported but don't fail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssueSeverity
from sigma.validators.core import validators as PYSIGMA_VALIDATORS

from ringtail.attack import AttackIndex, Technique, check_tags, default_index

# Validators that reach the network (unpinned ATT&CK / D3FEND data). We do ATT&CK ourselves.
_NETWORK_VALIDATORS = {"attacktag", "d3_fendtag"}
_ERROR_SEVERITIES = {SigmaValidationIssueSeverity.HIGH, SigmaValidationIssueSeverity.MEDIUM}


@dataclass
class ValidationReport:
    rule_path: Path | None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    techniques: list[Technique] = field(default_factory=list)
    attack_version: str | None = None

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "rule": str(self.rule_path) if self.rule_path else None,
            "passed": self.passed,
            "errors": self.errors,
            "warnings": self.warnings,
            "attack_version": self.attack_version,
            "techniques": [{"id": t.id, "name": t.name} for t in self.techniques],
        }


def _lint(text: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    selected = [v for k, v in PYSIGMA_VALIDATORS.items() if k not in _NETWORK_VALIDATORS]
    issues = SigmaValidator(selected).validate_rules(SigmaCollection.from_yaml(text))
    for issue in issues:
        msg = f"lint ({type(issue).__name__}): {issue.description}"
        (errors if issue.severity in _ERROR_SEVERITIES else warnings).append(msg)
    return errors, warnings


def _metadata(rule: SigmaRule) -> list[str]:
    errors = []
    if rule.id is None:
        errors.append("missing 'id' (a UUID)")
    for attr in ("title", "description"):
        if not getattr(rule, attr):
            errors.append(f"missing '{attr}'")
    if rule.level is None:
        errors.append("missing 'level'")
    if not rule.falsepositives:
        errors.append("missing 'falsepositives' (write 'Unknown' if there truly are none)")
    return errors


def validate_text(text: str, rule_path: Path | None = None, index: AttackIndex | None = None) -> ValidationReport:
    report = ValidationReport(rule_path=rule_path)
    try:
        rule = SigmaRule.from_yaml(text)
        # Some problems (e.g. bad conditions) only surface once the condition is parsed.
        for cond in rule.detection.parsed_condition:
            cond.parsed
    except SigmaError as e:
        report.errors.append(f"parse: {e}")
        return report
    except Exception as e:  # malformed YAML can raise outside SigmaError
        report.errors.append(f"parse: {type(e).__name__}: {e}")
        return report

    errs, warns = _lint(text)
    report.errors += errs
    report.warnings += warns
    report.errors += _metadata(rule)

    index = index or default_index()
    report.attack_version = index.version
    tags = check_tags([str(t) for t in rule.tags], index)
    report.errors += tags.errors
    report.warnings += tags.warnings
    report.techniques = tags.techniques
    return report


def validate_rule(rule_path: Path, index: AttackIndex | None = None) -> ValidationReport:
    rule_path = Path(rule_path)
    try:
        text = rule_path.read_text(encoding="utf-8")
    except OSError as e:
        return ValidationReport(rule_path=rule_path, errors=[f"could not read rule: {e}"])
    return validate_text(text, rule_path, index)
