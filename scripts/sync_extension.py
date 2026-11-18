"""Copy the shared web modules into the extension (MV3 forbids loading remote code).

    python scripts/sync_extension.py          # copy web/ -> extension/lib/
    python scripts/sync_extension.py --check  # exit 1 if any copy is stale (CI uses pytest)

web/ is the source of truth. Edit there, then run this.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED = ["ringtail-client.js", "ringtail-ui.js", "style.css"]
SRC = ROOT / "web"
DST = ROOT / "extension" / "lib"


def normalized(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def stale() -> list[str]:
    return [n for n in SHARED if not (DST / n).exists() or normalized(SRC / n) != normalized(DST / n)]


def main(argv: list[str]) -> int:
    if "--check" in argv:
        bad = stale()
        for n in bad:
            print(f"STALE  extension/lib/{n}  (run: python scripts/sync_extension.py)")
        return 1 if bad else 0
    DST.mkdir(parents=True, exist_ok=True)
    for n in SHARED:
        (DST / n).write_bytes(normalized(SRC / n))
        print(f"copied web/{n} -> extension/lib/{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
