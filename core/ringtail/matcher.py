"""Minimal Sigma evaluator for JSON events, built on pySigma's parsed condition tree.

pySigma does the hard parts: it parses the condition (``all of selection_*``, ``not filter``),
applies modifiers (``contains``, ``endswith``, ``windash``, ``base64offset``, ``re``, ``all``,
...), and resolves everything into a tree of ConditionAND / ConditionOR / ConditionNOT whose
leaves hold typed values. This module only evaluates those leaves against an event.

Rule: never silently pass. Anything we don't implement raises UnsupportedSigmaFeature, and the
test runner reports it as an error. See docs/decisions/0001-test-engine.md.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterator

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
    SigmaCondition,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

_MISSING = object()


class UnsupportedSigmaFeature(Exception):
    """The rule uses something this matcher doesn't evaluate. Treated as a test error."""


@dataclass
class MatchResult:
    matched: bool
    # Which named detections (selection_*, filter, ...) were true for this event.
    detections: dict[str, bool] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Event access


def _lookup(event: dict, name: str) -> Any:
    """Exact key first, then a dotted path into nested objects (e.g. userIdentity.arn)."""
    if name in event:
        return event[name]
    node: Any = event
    for part in name.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return _MISSING
    return node


def _flatten(value: Any) -> Iterator[Any]:
    """Yield scalar values. An event list matches if any element matches."""
    if isinstance(value, list):
        for v in value:
            yield from _flatten(v)
    else:
        yield value


def _all_scalars(event: Any) -> Iterator[Any]:
    """Every scalar in the event, used for keyword (field-less) matching."""
    if isinstance(event, dict):
        for k, v in event.items():
            if not str(k).startswith("_"):  # skip fixture annotations like _comment
                yield from _all_scalars(v)
    elif isinstance(event, list):
        for v in event:
            yield from _all_scalars(v)
    else:
        yield event


# ---------------------------------------------------------------------------
# Leaf value matching


@lru_cache(maxsize=4096)
def _string_regex(parts: tuple, cased: bool) -> re.Pattern:
    out = []
    for p in parts:
        if isinstance(p, str):
            out.append(re.escape(p))
        elif p is SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif p is SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        else:  # placeholders (%name%) need a processing pipeline we don't apply
            raise UnsupportedSigmaFeature(f"placeholder in string value: {p!r}")
    flags = re.DOTALL if cased else re.DOTALL | re.IGNORECASE
    return re.compile("".join(out), flags)


@lru_cache(maxsize=1024)
def _compiled_regex(pattern: str, flags: int) -> re.Pattern:
    return re.compile(pattern, flags)


def _as_keyword(sv: Any) -> Any:
    """Keywords (no field) are full-text search: match anywhere in a value, like SIEM backends do."""
    if isinstance(sv, SigmaExpansion):
        return SigmaExpansion([_as_keyword(v) for v in sv.values])
    if isinstance(sv, SigmaString):
        parts = list(sv.s)
        if not parts or parts[0] is not SpecialChars.WILDCARD_MULTI:
            parts.insert(0, SpecialChars.WILDCARD_MULTI)
        if parts[-1] is not SpecialChars.WILDCARD_MULTI:
            parts.append(SpecialChars.WILDCARD_MULTI)
        out = sv.__class__("")
        out.s = tuple(parts)
        return out
    return sv


def _as_text(v: Any) -> str | None:
    if v is None or isinstance(v, (dict, list)):
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _as_number(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _match_scalar(sv: Any, ev: Any) -> bool:
    """Does one Sigma value match one scalar event value?"""
    if isinstance(sv, SigmaExpansion):
        return any(_match_scalar(x, ev) for x in sv.values)
    if isinstance(sv, SigmaString):  # includes SigmaCasedString
        text = _as_text(ev)
        if text is None:
            return False
        rx = _string_regex(tuple(sv.s), isinstance(sv, SigmaCasedString))
        return rx.fullmatch(text) is not None
    if isinstance(sv, SigmaRegularExpression):
        text = _as_text(ev)
        if text is None:
            return False
        flags = 0
        for f in sv.flags:
            flags |= sv.sigma_to_python_flags[f]
        # Sigma regexes are unanchored: search, not fullmatch.
        return _compiled_regex(str(sv.regexp), flags).search(text) is not None
    if isinstance(sv, SigmaBool):
        return _as_text(ev) == ("true" if sv.boolean else "false")
    if isinstance(sv, SigmaNumber):
        n = _as_number(ev)
        return n is not None and n == float(sv.number)
    if isinstance(sv, SigmaCompareExpression):
        n = _as_number(ev)
        if n is None:
            return False
        target = float(sv.number.number)
        op = sv.op.name
        return {"LT": n < target, "LTE": n <= target, "GT": n > target, "GTE": n >= target}[op]
    if isinstance(sv, SigmaCIDRExpression):
        try:
            ip = ipaddress.ip_address(str(ev))
        except ValueError:
            return False
        return ip in ipaddress.ip_network(str(sv.network), strict=False)
    raise UnsupportedSigmaFeature(f"value type {type(sv).__name__}")


def _match_field(event: dict, fname: str, sv: Any) -> bool:
    raw = _lookup(event, fname)
    if isinstance(sv, SigmaExists):
        present = raw is not _MISSING and raw is not None
        return present == sv.exists
    if isinstance(sv, SigmaNull):
        return raw is _MISSING or raw is None
    if raw is _MISSING:
        return False
    return any(_match_scalar(sv, ev) for ev in _flatten(raw))


# ---------------------------------------------------------------------------
# Condition tree


def _eval(node: Any, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_field(event, node.field, node.value)
    if isinstance(node, ConditionValueExpression):  # keyword: any value anywhere
        kw = _as_keyword(node.value)
        return any(_match_scalar(kw, v) for v in _all_scalars(event))
    raise UnsupportedSigmaFeature(f"condition node {type(node).__name__}")


class CompiledRule:
    """A Sigma rule parsed once and ready to evaluate against many events."""

    def __init__(self, rule: SigmaRule):
        self.rule = rule
        if not rule.detection.parsed_condition:
            raise UnsupportedSigmaFeature("rule has no condition")
        self._conditions = [c.parsed for c in rule.detection.parsed_condition]
        # One tree per named detection, so failures can say which selection didn't hold.
        self._named = {
            name: SigmaCondition(name, rule.detection).parsed
            for name in rule.detection.detections
        }

    @classmethod
    def from_yaml(cls, text: str) -> "CompiledRule":
        return cls(SigmaRule.from_yaml(text))

    def match(self, event: dict) -> MatchResult:
        # Multiple conditions in one rule are OR'd (Sigma spec).
        matched = any(_eval(c, event) for c in self._conditions)
        detections = {name: _eval(tree, event) for name, tree in self._named.items()}
        return MatchResult(matched=matched, detections=detections)
