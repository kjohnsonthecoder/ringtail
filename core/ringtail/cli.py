"""ringtail CLI. Exit codes: 0 = pass, 1 = validation/test failure, 2 = usage/config error."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer

from ringtail.attack import AttackDataError, default_index
from ringtail.card import CardNotesError, build_card
from ringtail.testrunner import discover_rules, run_rule_tests
from ringtail.validate import validate_rule

app = typer.Typer(
    help="Ringtail: plain English in, rules that must fire out.",
    no_args_is_help=True,
    add_completion=False,
)

EXIT_PASS, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _read_input(text: Optional[str], file: Optional[Path]) -> str:
    if (text is None) == (file is None):
        typer.echo('Give exactly one input: "<behavior text>" or --file <report.txt>.', err=True)
        raise typer.Exit(EXIT_USAGE)
    if file is not None:
        try:
            return file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            typer.echo(f"Could not read {file}: {e}", err=True)
            raise typer.Exit(EXIT_USAGE)
    return text or ""


def _make_llm():
    """Build the real client, turning missing credentials into exit 2 with the BYOK message."""
    from ringtail.llm import AnthropicLLM, LLMConfigError

    try:
        return AnthropicLLM()
    except LLMConfigError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(EXIT_USAGE)


@app.command()
def test(
    paths: List[Path] = typer.Argument(..., help="Rule files, or directories to search for *.yml rules."),
    tests_root: Optional[Path] = typer.Option(
        None, "--tests-root", help="Directory holding <rule-id>/ test folders. Default: nearest tests/rules."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable results."),
) -> None:
    """Replay true-positive / false-positive sample events against each rule."""
    missing = [p for p in paths if not p.exists()]
    if missing:
        typer.echo(f"No such file or directory: {', '.join(map(str, missing))}", err=True)
        raise typer.Exit(EXIT_USAGE)
    rules = discover_rules(paths)
    if not rules:
        typer.echo("No rules found.", err=True)
        raise typer.Exit(EXIT_USAGE)

    reports = [run_rule_tests(r, tests_root) for r in rules]

    if as_json:
        typer.echo(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        for r in reports:
            tp_ok, tp_n = r.counts("true_positive")
            fp_ok, fp_n = r.counts("false_positive")
            status = "PASS" if r.passed else "FAIL"
            typer.echo(f"{status}  {r.rule_path.as_posix()}  TP {tp_ok}/{tp_n}  FP {fp_ok}/{fp_n}")
            for e in r.errors:
                typer.echo(f"      error: {e}")
            for c in r.cases:
                if not c.passed:
                    typer.echo(f"      {c.explain()}")
        n_pass = sum(r.passed for r in reports)
        typer.echo(f"\n{n_pass}/{len(reports)} rules passed.")

    raise typer.Exit(EXIT_PASS if all(r.passed for r in reports) else EXIT_FAIL)


@app.command()
def card(
    paths: List[Path] = typer.Argument(..., help="Rule files, or directories to search for *.yml rules."),
    check: bool = typer.Option(False, "--check", help="Don't write. Exit 1 if any committed card is stale."),
) -> None:
    """Generate cards/<rule-id>.md from the rule, its test results, and cards/<rule-id>.yml."""
    missing = [p for p in paths if not p.exists()]
    if missing:
        typer.echo(f"No such file or directory: {', '.join(map(str, missing))}", err=True)
        raise typer.Exit(EXIT_USAGE)
    rules = discover_rules(paths)
    if not rules:
        typer.echo("No rules found.", err=True)
        raise typer.Exit(EXIT_USAGE)

    ok = True
    for rule_path in rules:
        try:
            card_path, text, report = build_card(rule_path)
        except CardNotesError as e:
            typer.echo(f"FAIL  {rule_path.as_posix()}: {e}")
            ok = False
            continue
        if not report.passed:
            ok = False
        current = card_path.read_text(encoding="utf-8") if card_path.is_file() else None
        if check:
            fresh = current is not None and current.replace("\r\n", "\n") == text
            typer.echo(f"{'OK   ' if fresh else 'STALE'}  {card_path.as_posix()}")
            ok = ok and fresh
        else:
            card_path.write_text(text, encoding="utf-8", newline="\n")
            status = "wrote" if report.passed else "wrote (rule tests FAIL)"
            typer.echo(f"{status}  {card_path.as_posix()}")
    if check and not ok:
        typer.echo("\nRegenerate with: ringtail card rules/", err=True)
    raise typer.Exit(EXIT_PASS if ok else EXIT_FAIL)


@app.command()
def validate(
    paths: List[Path] = typer.Argument(..., help="Rule files, or directories to search for *.yml rules."),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable results."),
) -> None:
    """pySigma parse + lint, required metadata, and ATT&CK IDs against the pinned version."""
    rules = _resolve_rules(paths)
    try:
        index = default_index()
    except AttackDataError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(EXIT_USAGE)

    reports = [validate_rule(r, index) for r in rules]
    if as_json:
        typer.echo(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        for r in reports:
            techs = ", ".join(f"{t.id} {t.name}" for t in r.techniques) or "no valid technique"
            typer.echo(f"{'PASS' if r.passed else 'FAIL'}  {r.rule_path.as_posix()}  [{techs}]")
            for e in r.errors:
                typer.echo(f"      error: {e}")
            for w in r.warnings:
                typer.echo(f"      warning: {w}")
        typer.echo(f"\n{sum(r.passed for r in reports)}/{len(reports)} rules valid (ATT&CK v{index.version}).")
    raise typer.Exit(EXIT_PASS if all(r.passed for r in reports) else EXIT_FAIL)


@app.command()
def convert(
    paths: List[Path] = typer.Argument(..., help="Rule files, or directories to search for *.yml rules."),
    target: str = typer.Option("all", "--target", "-t", help="splunk, kql, or all."),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable results."),
) -> None:
    """Convert rules to SIEM queries: Splunk SPL and Microsoft Sentinel / Defender KQL."""
    from ringtail.convert import TARGETS, convert_rule

    if target != "all" and target not in TARGETS:
        typer.echo(f"Unknown target '{target}'. Choose from: all, {', '.join(TARGETS)}", err=True)
        raise typer.Exit(EXIT_USAGE)
    targets = list(TARGETS) if target == "all" else [target]
    rules = _resolve_rules(paths)

    results = []
    for r in rules:
        convs = convert_rule(r.read_text(encoding="utf-8"), targets)
        results.append({"rule": r.as_posix(), "queries": [c.to_dict() for c in convs]})
    ok = all(q["query"] for res in results for q in res["queries"])

    if as_json:
        typer.echo(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for res in results:
            typer.echo(f"=== {res['rule']}")
            for q in res["queries"]:
                if q["query"]:
                    typer.echo(f"--- {q['label']} [{q['schema']}]\n{q['query']}\n")
                else:
                    typer.echo(f"--- {q['label']}: not available ({q['error']})\n")
    raise typer.Exit(EXIT_PASS if ok else EXIT_FAIL)


def _stale(path: Path, text: str) -> bool:
    return not path.exists() or path.read_text(encoding="utf-8").replace("\r\n", "\n") != text


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


@app.command()
def backtest(
    rules_dir: Path = typer.Option(Path("rules"), "--rules", help="Rules to replay."),
    check: bool = typer.Option(False, "--check", help="Don't write. Exit 1 if the committed report is stale."),
    offline: bool = typer.Option(False, "--offline", help="Use only cached recordings; never download."),
) -> None:
    """Replay real attack recordings (OTRF, pinned) against every rule (ADR 0006)."""
    from ringtail import backtest as bt

    try:
        manifest = bt.load_manifest()
        rules = bt.load_rules(_resolve_rules([rules_dir]))
        report = bt.run(rules, manifest, bt.events_by_dataset(manifest, offline=offline))
    except bt.BacktestError as e:
        typer.echo(f"backtest: {e}", err=True)
        raise typer.Exit(EXIT_USAGE)

    t = report["totals"]
    typer.echo(f"{t['datasets']} recordings, {t['events']:,} events. "
               f"{t['rules_proven_on_real_data']} rules fired on real attacks, {t['gaps_documented']} documented gaps, "
               f"{t['unexpected']} unexpected, {t['regressions']} regressions.")
    for r in report["rules"]:
        ev = ", ".join(d["dataset"] for d in r["detected"]) or "samples only"
        typer.echo(f"  {r['rule']}: {ev}" + (f"  ({len(r['gaps'])} gaps)" if r["gaps"] else ""))

    ok = True
    for p in bt.problems(report):
        typer.echo(f"FAIL  {p}")
        ok = False
    outputs = {bt.REPORT_JSON: bt.to_json(report), bt.REPORT_MD: bt.to_markdown(report)}
    for path, text in outputs.items():
        if check:
            if _stale(path, text):
                typer.echo(f"STALE {path.relative_to(bt.ROOT).as_posix()} (run: ringtail backtest)")
                ok = False
        else:
            _write(path, text)
            typer.echo(f"wrote {path.relative_to(bt.ROOT).as_posix()}")
    raise typer.Exit(EXIT_PASS if ok else EXIT_FAIL)


@app.command()
def crosscheck(
    rules_dir: Path = typer.Option(Path("rules"), "--rules", help="Rules to check."),
    rsigma: Optional[str] = typer.Option(None, "--rsigma", help="Path to the rsigma binary (default: on PATH)."),
    require: bool = typer.Option(False, "--require", help="Fail if RSigma isn't available (CI)."),
    real_data: bool = typer.Option(True, "--real-data/--samples-only", help="Also compare on the cached real recordings."),
) -> None:
    """Compare Ringtail's matcher with RSigma, an independent Sigma engine (ADR 0006)."""
    from ringtail import backtest as bt
    from ringtail import crosscheck as xc

    cmd = xc.find_rsigma(rsigma)
    if cmd is None:
        typer.echo("RSigma not found; cross-check skipped (CI runs it with a pinned release).",
                   err=require)
        raise typer.Exit(EXIT_USAGE if require else EXIT_PASS)
    rules = bt.load_rules(_resolve_rules([rules_dir]))
    events = None
    if real_data:
        try:
            events = bt.events_by_dataset(bt.load_manifest(), offline=True)
        except bt.BacktestError as e:
            typer.echo(f"crosscheck: {e} (run `ringtail backtest` first, or pass --samples-only)", err=True)
            raise typer.Exit(EXIT_USAGE)
    rep = xc.run(cmd, rules, events)
    typer.echo(f"Compared {rep.checked_samples} samples and {rep.checked_recordings} rule/recording pairs "
               f"with RSigma: {len(rep.disagreements)} disagreements.")
    for d in rep.disagreements:
        typer.echo(f"DISAGREE  {d}")
    raise typer.Exit(EXIT_FAIL if rep.disagreements else EXIT_PASS)


@app.command()
def coverage(
    rules_dir: Path = typer.Option(Path("rules"), "--rules", help="Rules to plot."),
    check: bool = typer.Option(False, "--check", help="Don't write. Exit 1 if a committed image is stale."),
) -> None:
    """Draw the rules on the ATT&CK tactic line under Kill Chain phases (SVG)."""
    from ringtail import backtest as bt
    from ringtail import coverage as cv

    svg = cv.render(_resolve_rules([rules_dir]), cv.load_report(bt.REPORT_JSON), default_index().version)
    ok = True
    for path in cv.OUTPUTS:
        rel = path.relative_to(cv.ROOT).as_posix()
        if check:
            if _stale(path, svg):
                typer.echo(f"STALE {rel} (run: ringtail coverage)")
                ok = False
            else:
                typer.echo(f"OK    {rel}")
        else:
            _write(path, svg)
            typer.echo(f"wrote {rel}")
    raise typer.Exit(EXIT_PASS if ok else EXIT_FAIL)


def _resolve_rules(paths: List[Path]) -> List[Path]:
    missing = [p for p in paths if not p.exists()]
    if missing:
        typer.echo(f"No such file or directory: {', '.join(map(str, missing))}", err=True)
        raise typer.Exit(EXIT_USAGE)
    rules = discover_rules(paths)
    if not rules:
        typer.echo("No rules found.", err=True)
        raise typer.Exit(EXIT_USAGE)
    return rules


@app.command()
def draft(
    text: Optional[str] = typer.Argument(None, help="Plain-English behavior description."),
    file: Optional[Path] = typer.Option(None, "--file", help="Read a threat report from a text or HTML file."),
) -> None:
    """AI draft only: print the Sigma YAML. No validation or tests (use `run` for that)."""
    from ringtail.llm import LLMConfigError, LLMError
    from ringtail.pipeline import draft_once
    from ringtail.sanitize import InputError

    raw = _read_input(text, file)
    llm = _make_llm()
    try:
        _extraction, result, rule_text = draft_once(raw, llm)
    except InputError as e:
        typer.echo(f"Input problem: {e}", err=True)
        raise typer.Exit(EXIT_USAGE)
    except LLMConfigError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(EXIT_USAGE)
    except LLMError as e:
        typer.echo(f"Model call failed: {e}", err=True)
        raise typer.Exit(EXIT_FAIL)
    if rule_text is None:
        typer.echo("The model's rule_yaml could not be parsed. Raw output follows.", err=True)
        typer.echo(str(result.get("rule_yaml", "")))
        raise typer.Exit(EXIT_FAIL)
    typer.echo("# UNVERIFIED AI draft. Run `ringtail run` to validate and test it.", err=True)
    typer.echo(rule_text, nl=False)
    raise typer.Exit(EXIT_PASS)


@app.command()
def run(
    text: Optional[str] = typer.Argument(None, help="Plain-English behavior description."),
    file: Optional[Path] = typer.Option(None, "--file", help="Read a threat report from a text or HTML file."),
    out: Path = typer.Option(Path("drafts"), "--out", help="Where to write the rule, samples, and card."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing draft with the same name."),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable results."),
) -> None:
    """Full loop: draft, validate, test, retry up to 3 times, then write rule + tests + card."""
    from ringtail.llm import LLMConfigError
    from ringtail.pipeline import run as run_pipeline
    from ringtail.sanitize import InputError

    raw = _read_input(text, file)
    llm = _make_llm()
    log = (lambda m: None) if as_json else (lambda m: typer.echo(m, err=True))
    try:
        result = run_pipeline(raw, llm, out, force=force, log=log)
    except InputError as e:
        typer.echo(f"Input problem: {e}", err=True)
        raise typer.Exit(EXIT_USAGE)
    except LLMConfigError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(EXIT_USAGE)
    except AttackDataError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(EXIT_USAGE)

    usage = getattr(llm, "usage", [])
    if as_json:
        payload = result.to_dict()
        payload["usage"] = usage
        typer.echo(json.dumps(payload, indent=2))
    elif result.passed:
        c = result.candidate
        tp_ok, tp_n = c.test_report.counts("true_positive")
        fp_ok, fp_n = c.test_report.counts("false_positive")
        typer.echo(f"\nPASS after {len(result.attempts)} attempt(s): TP {tp_ok}/{tp_n}, FP {fp_ok}/{fp_n}")
        for p in result.written:
            typer.echo(f"  wrote {p.as_posix()}")
        if c.notes:
            typer.echo(f"\nModel notes for the reviewer: {c.notes}")
        typer.echo(
            "\nThis is an AI draft. Review the rule, samples, and card; then move it into "
            "rules/frontline-pack/ deliberately."
        )
    else:
        typer.echo(f"\nFAIL: {result.error}")
        for a in result.attempts:
            typer.echo(f"  attempt {a.number}:")
            for e in a.errors:
                typer.echo(f"    - {e}")
    if usage and not as_json:
        tin = sum(u["input"] for u in usage)
        tout = sum(u["output"] for u in usage)
        typer.echo(f"\nTokens: {tin:,} in / {tout:,} out across {len(usage)} call(s).", err=True)

    if result.error and result.error.endswith("(use --force to overwrite)"):
        raise typer.Exit(EXIT_USAGE)
    raise typer.Exit(EXIT_PASS if result.passed else EXIT_FAIL)


if __name__ == "__main__":
    app()
