"""Draw the Frontline Pack on the ATT&CK tactic line, under Kill Chain phases (ADR 0006).

`ringtail coverage` writes docs/images/attack-coverage.svg (README) and
web/attack-coverage.svg (web page) from the rules and the real-data backtest report.
Output is deterministic, so CI can fail when it's stale.

ATT&CK tactics are attacker goals, not strictly ordered steps; the Lockheed Martin Cyber
Kill Chain is seven ordered phases. Each tactic is shown under its closest Kill Chain phase.
They don't line up perfectly (Command and Control sits between "actions on objectives"
tactics in ATT&CK's order), and the drawing shows that instead of hiding it.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from xml.sax.saxutils import escape

from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parents[2]
OUTPUTS = [ROOT / "docs" / "images" / "attack-coverage.svg", ROOT / "web" / "attack-coverage.svg"]

# ATT&CK Enterprise v20 tactic order (v20 split Defense Evasion into Stealth and
# Defense Impairment), each with its closest Kill Chain phase.
TACTICS = [
    ("reconnaissance", "Reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development", "Weaponization"),
    ("initial-access", "Initial Access", "Delivery"),
    ("execution", "Execution", "Exploitation"),
    ("persistence", "Persistence", "Installation"),
    ("privilege-escalation", "Privilege Escalation", "Installation"),
    ("stealth", "Stealth", "Installation"),
    ("defense-impairment", "Defense Impairment", "Installation"),
    ("credential-access", "Credential Access", "Actions on Objectives"),
    ("discovery", "Discovery", "Actions on Objectives"),
    ("lateral-movement", "Lateral Movement", "Actions on Objectives"),
    ("collection", "Collection", "Actions on Objectives"),
    ("command-and-control", "Command and Control", "Command & Control"),
    ("exfiltration", "Exfiltration", "Actions on Objectives"),
    ("impact", "Impact", "Actions on Objectives"),
]
PHASE_COLORS = {
    "Reconnaissance": "#2b3a55", "Weaponization": "#33405e", "Delivery": "#3b4767",
    "Exploitation": "#43506f", "Installation": "#4b5878", "Command & Control": "#556184",
    "Actions on Objectives": "#5e6a8d",
}

BG, PANEL, BORDER = "#0f1216", "#171b21", "#2c333c"
TEXT, MUTED = "#e6e9ee", "#9aa4b1"
AMBER, GREEN, BLUE = "#f0a030", "#56d364", "#4c8dff"
FONT = "Segoe UI, system-ui, -apple-system, Helvetica, Arial, sans-serif"

COL_W = 104
MARGIN = 30
WIDTH = MARGIN * 2 + COL_W * len(TACTICS)
CHIP_H = 74
CHIP_GAP = 8


def _t(x, y, s, size=11, fill=TEXT, weight="normal", anchor="middle", extra=""):
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" font-weight="{weight}" '
            f'text-anchor="{anchor}"{extra}>{escape(s)}</text>')


def _rules(rule_paths: list[Path]) -> list[dict]:
    out = []
    for p in sorted(rule_paths):
        r = SigmaRule.from_yaml(p.read_text(encoding="utf-8"))
        tactics = [t.name for t in r.tags if t.namespace == "attack" and not t.name.lower().startswith("t")]
        techs = sorted(t.name.upper() for t in r.tags if t.namespace == "attack" and t.name.lower().startswith("t"))
        out.append({"stem": p.stem, "title": r.title, "tactics": tactics, "techniques": techs})
    return out


def render(rule_paths: list[Path], report: dict, attack_version: str) -> str:
    rules = _rules(rule_paths)
    by_stem = {r["rule"]: r for r in report.get("rules", [])}
    cols: dict[str, list[dict]] = {k: [] for k, _, _ in TACTICS}
    for r in rules:
        for t in r["tactics"]:
            if t in cols:
                cols[t].append(r)
    covered = sum(1 for v in cols.values() if v)
    tot = report.get("totals", {})
    deepest = max((len(v) for v in cols.values()), default=0)

    y_band, y_line, y_chips = 104, 176, 236
    chips_bottom = y_chips + max(deepest, 1) * (CHIP_H + CHIP_GAP)
    height = chips_bottom + 96

    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" viewBox="0 0 {WIDTH} {height}" '
         f'font-family="{FONT}" role="img" aria-labelledby="t d">',
         '<title id="t">Frontline Pack on the MITRE ATT&amp;CK tactic line</title>',
         f'<desc id="d">{len(rules)} detection rules plotted on ATT&amp;CK v{escape(attack_version)} tactics under '
         f'Lockheed Martin Cyber Kill Chain phases; {tot.get("rules_proven_on_real_data", 0)} proven on real '
         f'recorded attacks.</desc>',
         f'<rect width="{WIDTH}" height="{height}" rx="14" fill="{BG}"/>']

    # Header
    s.append(_t(MARGIN, 46, "Frontline Pack on the attack line", 24, TEXT, "700", "start"))
    s.append(_t(MARGIN, 70, f"MITRE ATT&CK v{attack_version} tactics, grouped under Lockheed Martin Cyber Kill Chain phases",
                13, MUTED, "normal", "start"))
    stats = (f"{len(rules)} rules · {covered} of {len(TACTICS)} tactics · "
             f"{tot.get('rules_proven_on_real_data', 0)} proven on real attacks · "
             f"{tot.get('events', 0):,} real events replayed · {tot.get('unexpected', 0)} unexpected fires")
    s.append(_t(WIDTH - MARGIN, 46, stats, 13, AMBER, "600", "end"))

    # Kill Chain bands: one per contiguous run of the same phase
    i = 0
    while i < len(TACTICS):
        phase = TACTICS[i][2]
        j = i
        while j + 1 < len(TACTICS) and TACTICS[j + 1][2] == phase:
            j += 1
        x0, x1 = MARGIN + i * COL_W + 2, MARGIN + (j + 1) * COL_W - 2
        s.append(f'<rect x="{x0}" y="{y_band}" width="{x1 - x0}" height="34" rx="6" fill="{PHASE_COLORS[phase]}"/>')
        if (x1 - x0) > 8 * len(phase):
            s.append(_t((x0 + x1) / 2, y_band + 22, phase, 12, TEXT, "600"))
        elif (x1 - x0) > 6.4 * len(phase):  # fits on one line at a smaller size
            s.append(_t((x0 + x1) / 2, y_band + 21, phase, 10, TEXT, "600"))
        else:  # too narrow for one line: two smaller lines, never splitting a word
            for n, part in enumerate(textwrap.wrap(phase, 11, break_long_words=False)[:2]):
                s.append(_t((x0 + x1) / 2, y_band + 15 + n * 12, part, 10, TEXT, "600"))
        i = j + 1
    s.append(_t(MARGIN, y_band - 8, "LOCKHEED MARTIN KILL CHAIN", 10, MUTED, "600", "start", ' letter-spacing="1"'))

    # The ATT&CK line
    cx = lambda k: MARGIN + k * COL_W + COL_W / 2  # noqa: E731
    s.append(f'<line x1="{cx(0)}" y1="{y_line}" x2="{cx(len(TACTICS) - 1)}" y2="{y_line}" stroke="{BORDER}" stroke-width="3"/>')
    s.append(_t(MARGIN, y_line - 22, "MITRE ATT&CK TACTICS", 10, MUTED, "600", "start", ' letter-spacing="1"'))
    for k, (key, name, _) in enumerate(TACTICS):
        hit = bool(cols[key])
        s.append(f'<circle cx="{cx(k)}" cy="{y_line}" r="9" fill="{AMBER if hit else BG}" stroke="{AMBER if hit else MUTED}" stroke-width="2"/>')
        for n, part in enumerate(textwrap.wrap(name, 14, break_long_words=False)[:2]):
            s.append(_t(cx(k), y_line + 26 + n * 13, part, 11, TEXT if hit else MUTED, "600" if hit else "normal"))

    # Rule chips under each tactic
    for k, (key, _, _) in enumerate(TACTICS):
        x = MARGIN + k * COL_W + 5
        if not cols[key]:
            s.append(_t(cx(k), y_chips + 22, "no rule yet", 10, "#5b6470", extra=' font-style="italic"'))
            continue
        for n, r in enumerate(cols[key]):
            y = y_chips + n * (CHIP_H + CHIP_GAP)
            ev = by_stem.get(r["stem"], {})
            real = ev.get("status") == "real"
            color = GREEN if real else BLUE
            s.append(f'<line x1="{cx(k)}" y1="{y_line + 9}" x2="{cx(k)}" y2="{y}" stroke="{BORDER}" stroke-width="1" '
                     f'stroke-dasharray="2 3"/>' if n == 0 else "")
            s.append(f'<rect x="{x}" y="{y}" width="{COL_W - 10}" height="{CHIP_H}" rx="7" fill="{PANEL}" stroke="{color}" stroke-width="1.5"/>')
            s.append(f'<rect x="{x}" y="{y}" width="5" height="{CHIP_H}" rx="2" fill="{color}"/>')
            techs = r["techniques"][0] + (f" +{len(r['techniques']) - 1}" if len(r["techniques"]) > 1 else "")
            s.append(_t(x + 11, y + 16, techs, 10.5, color, "700", "start"))
            for m, part in enumerate(textwrap.wrap(r["title"], 15, max_lines=3, placeholder="…")):
                s.append(_t(x + 11, y + 31 + m * 12, part, 10, TEXT, "normal", "start"))
            gaps = len(ev.get("gaps", []))
            if gaps:
                s.append(f'<circle cx="{x + COL_W - 20}" cy="{y + 12}" r="7" fill="{AMBER}"/>')
                s.append(_t(x + COL_W - 20, y + 15.5, str(gaps), 9, BG, "700"))

    # Legend and footer
    ly = chips_bottom + 22
    items = [(GREEN, "rect", "Fired on a real recorded attack (OTRF dataset)"),
             (BLUE, "rect", "Proven on test samples (no public recording yet)"),
             (AMBER, "circle", "Documented gaps: same technique, a method this rule doesn't cover")]
    lx = MARGIN
    for color, shape, label in items:
        if shape == "rect":
            s.append(f'<rect x="{lx}" y="{ly - 10}" width="14" height="14" rx="3" fill="{PANEL}" stroke="{color}" stroke-width="2"/>')
        else:
            s.append(f'<circle cx="{lx + 7}" cy="{ly - 3}" r="7" fill="{color}"/>')
        s.append(_t(lx + 22, ly + 1, label, 12, TEXT, "normal", "start"))
        lx += 22 + 7 * len(label) + 28
    s.append(_t(MARGIN, ly + 30,
                "Mapping is approximate: ATT&CK tactics aren't strict steps, so Command and Control falls between "
                "'actions on objectives' tactics. Generated by `ringtail coverage` from rules/ and docs/backtest.md.",
                11, MUTED, "normal", "start"))
    s.append("</svg>")
    return "\n".join(x for x in s if x) + "\n"


def load_report(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {}
