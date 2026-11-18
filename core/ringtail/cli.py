"""ringtail CLI. Exit codes: 0 = pass, 1 = validation/test failure, 2 = usage/config error."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer

from ringtail.card import CardNotesError, build_card
from ringtail.testrunner import discover_rules, run_rule_tests

app = typer.Typer(
    help="Ringtail: plain English in, rules that must fire out.",
    no_args_is_help=True,
    add_completion=False,
)

EXIT_PASS, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _not_yet(name: str) -> None:
    typer.echo(f"ringtail {name}: not implemented yet (v0.1 in progress).", err=True)
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
def validate(rule: Path) -> None:
    """pySigma + ATT&CK checks (coming next)."""
    _not_yet("validate")


@app.command()
def draft(text: Optional[str] = typer.Argument(None), file: Optional[Path] = typer.Option(None, "--file")) -> None:
    """AI draft only, prints YAML (coming next)."""
    _not_yet("draft")


@app.command()
def run(text: Optional[str] = typer.Argument(None), file: Optional[Path] = typer.Option(None, "--file")) -> None:
    """Full draft, validate, test loop with retries (coming next)."""
    _not_yet("run")


if __name__ == "__main__":
    app()
