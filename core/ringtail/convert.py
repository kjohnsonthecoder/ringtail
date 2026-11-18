"""Convert a Sigma rule into ready-to-paste SIEM queries: Splunk SPL and Microsoft KQL.

ADR 0004. Splunk uses the official pySigma Splunk backend. KQL uses a small backend of our
own (`KustoBackend` below) because no pySigma KQL backend release works with pySigma 2.x.

A query is only as good as its field mapping, so the KQL side maps tables and fields
explicitly per log source. A rule with a log source or field we haven't mapped gets a clear
"not available" with the reason, never a query with guessed field names.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import ClassVar

from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import SigmaCompareExpression

TARGETS = {
    "splunk": "Splunk (SPL)",
    "kql": "Microsoft Sentinel / Defender XDR (KQL)",
}


@dataclass
class Conversion:
    target: str
    label: str
    query: str | None = None
    schema: str = ""  # which table / log format the field names assume
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# KQL backend


class KustoBackend(TextQueryBackend):
    """Kusto Query Language (Microsoft Sentinel, Defender XDR). Produces only the `where`
    expression; `convert_rule` adds the table. String operators in KQL (=~, in~, contains,
    startswith, endswith) are case-insensitive, matching Sigma's default."""

    name: ClassVar[str] = "Ringtail KQL"
    formats: ClassVar[dict[str, str]] = {"default": "KQL where-expression"}
    requires_pipeline: ClassVar[bool] = False

    precedence: ClassVar[tuple] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = "({expr})"
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = " =~ "

    # Field names are already KQL columns or expressions from our mapping: emit them as-is.
    field_quote: ClassVar[str | None] = None

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    add_escaped: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    bool_values: ClassVar[dict] = {True: "true", False: "false"}

    startswith_expression: ClassVar[str] = "{field} startswith {value}"
    not_startswith_expression: ClassVar[str] = "{field} !startswith {value}"
    endswith_expression: ClassVar[str] = "{field} endswith {value}"
    not_endswith_expression: ClassVar[str] = "{field} !endswith {value}"
    contains_expression: ClassVar[str] = "{field} contains {value}"
    not_contains_expression: ClassVar[str] = "{field} !contains {value}"

    re_expression: ClassVar[str] = '{field} matches regex "{regex}"'
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[tuple] = ('"',)

    cidr_expression: ClassVar[str] = 'ipv4_is_in_range({field}, "{value}")'
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[dict] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = "isempty({field})"
    field_exists_expression: ClassVar[str] = "isnotempty({field})"
    field_not_exists_expression: ClassVar[str] = "isempty({field})"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "in~"
    list_separator: ClassVar[str] = ", "

    unbound_value_str_expression: ClassVar[str] = "* contains {value}"
    unbound_value_num_expression: ClassVar[str] = "* contains {value}"

    # Group every compound expression, so a reader never has to know that KQL binds `and`
    # before `or` to see what the query means.
    parenthesize: bool = True

    def convert_condition_field_eq_val_num(self, cond: ConditionFieldEqualsValueExpression,
                                           state: ConversionState) -> str:
        # =~ is a string operator in KQL; numbers need ==.
        return f"{self.escape_and_quote_field(cond.field)} == {cond.value}"

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState):
        # Two Sigma fields can map to one KQL column (ServiceName and ImagePath both live in
        # RenderedDescription), which would repeat a branch. Drop exact duplicates.
        seen, args = set(), []
        for a in cond.args:
            key = (a.field, type(a.value).__name__, str(a.value)) \
                if isinstance(a, ConditionFieldEqualsValueExpression) else id(a)
            if key not in seen:
                seen.add(key)
                args.append(a)
        if len(args) == 1:
            return self.convert_condition(args[0], state)
        cond.args = args
        return super().convert_condition_or(cond, state)

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState):
        # In KQL, not is a function: not(expr). "not X =~ y" is a syntax error.
        out = super().convert_condition_not(cond, state)
        prefix = self.not_token + self.token_separator
        if isinstance(out, str) and out.startswith(prefix):
            inner = out[len(prefix):]
            if inner.startswith("(") and inner.endswith(")"):
                inner = inner[1:-1]
            return f"not({inner})"
        return out


# Table and field mappings per log source. Values are KQL columns or expressions.
# Nested CloudTrail fields live in JSON string columns in Sentinel's AWSCloudTrail table.
_KQL_SOURCES: dict[tuple[str | None, str | None, str | None], tuple[str, str, dict[str, str]]] = {
    ("windows", "process_creation", None): (
        "DeviceProcessEvents",
        "Defender XDR DeviceProcessEvents (also in Sentinel with the Defender XDR connector)",
        {
            "Image": "FolderPath",
            "OriginalFileName": "ProcessVersionInfoOriginalFileName",
            "CommandLine": "ProcessCommandLine",
            "ParentImage": "InitiatingProcessFolderPath",
            "ParentCommandLine": "InitiatingProcessCommandLine",
            "User": "AccountName",
            "Computer": "DeviceName",
        },
    ),
    # Defender for Endpoint on Linux writes to the same table with the same columns.
    # (No OriginalFileName: Linux binaries have no PE version info.)
    ("linux", "process_creation", None): (
        "DeviceProcessEvents",
        "Defender for Endpoint on Linux, DeviceProcessEvents (also in Sentinel with the Defender XDR connector)",
        {
            "Image": "FolderPath",
            "CommandLine": "ProcessCommandLine",
            "ParentImage": "InitiatingProcessFolderPath",
            "ParentCommandLine": "InitiatingProcessCommandLine",
            "User": "AccountName",
            "Computer": "DeviceName",
        },
    ),
    ("windows", None, "system"): (
        "Event",
        "Sentinel Event table (Windows System log collected by the Azure Monitor Agent)",
        {
            "Provider_Name": "Source",
            "EventID": "EventID",
            "Computer": "Computer",
            # Service fields of event 7045 are inside the rendered message in this table, so
            # these work for contains/startswith-style matches on the message text.
            "ServiceName": "RenderedDescription",
            "ImagePath": "RenderedDescription",
        },
    ),
    ("aws", None, "cloudtrail"): (
        "AWSCloudTrail",
        "Sentinel AWSCloudTrail table (AWS S3 connector)",
        {
            "eventSource": "EventSource",
            "eventName": "EventName",
            "awsRegion": "AWSRegion",
            "sourceIPAddress": "SourceIpAddress",
            "userAgent": "UserAgent",
            "errorCode": "ErrorCode",
            "errorMessage": "ErrorMessage",
            "recipientAccountId": "RecipientAccountId",
            "userIdentity.type": "UserIdentityType",
            "userIdentity.arn": "UserIdentityArn",
            "userIdentity.userName": "UserIdentityUserName",
            "userIdentity.accountId": "UserIdentityAccountId",
            "additionalEventData.MFAUsed": "tostring(parse_json(AdditionalEventData).MFAUsed)",
            "responseElements.ConsoleLogin": "tostring(parse_json(ResponseElements).ConsoleLogin)",
        },
    ),
}


def _rule_fields(rule: SigmaRule) -> set[str]:
    fields: set[str] = set()

    def walk(item) -> None:
        if isinstance(item, SigmaDetection):
            for sub in item.detection_items:
                walk(sub)
        elif isinstance(item, SigmaDetectionItem) and item.field:
            fields.add(item.field)

    for det in rule.detection.detections.values():
        walk(det)
    return fields


def _kql_source(rule: SigmaRule):
    ls = rule.logsource
    return _KQL_SOURCES.get((ls.product, ls.category, ls.service))


def _to_kql(rule: SigmaRule, text: str) -> Conversion:
    c = Conversion("kql", TARGETS["kql"])
    src = _kql_source(rule)
    ls = rule.logsource
    if src is None:
        c.error = (f"no KQL table mapping yet for log source product={ls.product}, "
                   f"category={ls.category}, service={ls.service}")
        return c
    table, schema, fields = src
    unmapped = sorted(_rule_fields(rule) - fields.keys())
    if unmapped:
        c.error = f"no KQL column mapping yet for field(s): {', '.join(unmapped)} (table {table})"
        return c
    # Rename fields in the rule text's parsed form by converting with a mapping pipeline.
    from sigma.processing.pipeline import ProcessingItem
    from sigma.processing.transformations import FieldMappingTransformation

    pipeline = ProcessingPipeline(name="ringtail-kql",
                                  items=[ProcessingItem(transformation=FieldMappingTransformation(fields))])
    try:
        where = KustoBackend(pipeline).convert(SigmaCollection.from_yaml(text))
    except Exception as e:  # pySigma raises a family of errors; report, don't crash
        c.error = f"KQL conversion failed: {e}"
        return c
    c.query = f"{table}\n| where {' or '.join(f'({w})' for w in where) if len(where) > 1 else where[0]}"
    c.schema = schema
    return c


# ---------------------------------------------------------------------------
# Splunk


def _to_splunk(rule: SigmaRule, text: str) -> Conversion:
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline

    c = Conversion("splunk", TARGETS["splunk"])
    ls = rule.logsource
    prefix = ""
    if ls.product == "windows":
        pipeline = splunk_windows_pipeline()
        c.schema = ("Windows event and Sysmon field names (Splunk Add-on for Microsoft Windows / Sysmon)"
                    if ls.category == "process_creation" else "Windows event log field names")
    elif ls.product == "linux" and ls.category == "process_creation":
        pipeline = ProcessingPipeline()
        c.schema = "Sysmon for Linux process field names (Image, CommandLine, ParentImage)"
    elif ls.product == "aws" and ls.service == "cloudtrail":
        pipeline = ProcessingPipeline()
        prefix = 'sourcetype="aws:cloudtrail" '
        c.schema = "CloudTrail JSON field names (Splunk Add-on for AWS)"
    else:
        pipeline = ProcessingPipeline()
        c.schema = "Sigma field names as written in the rule"
    try:
        queries = SplunkBackend(pipeline).convert(SigmaCollection.from_yaml(text))
    except Exception as e:
        c.error = f"Splunk conversion failed: {e}"
        return c
    c.query = prefix + "\n".join(queries)
    return c


# ---------------------------------------------------------------------------


def convert_rule(text: str, targets: list[str] | None = None) -> list[Conversion]:
    """Convert one rule (YAML text) to each target. Never raises for a conversion problem:
    the problem is reported in Conversion.error."""
    rule = SigmaRule.from_yaml(text)
    out = []
    for t in targets or list(TARGETS):
        if t == "splunk":
            out.append(_to_splunk(rule, text))
        elif t == "kql":
            out.append(_to_kql(rule, text))
        else:
            raise ValueError(f"unknown target '{t}'; choose from: {', '.join(TARGETS)}")
    return out


def code_fence(text: str, lang: str = "") -> str:
    """A Markdown code block whose fence is longer than any backtick run in the text, so a
    query (possibly built from AI-drafted rule values) can't break out of it."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"
