"""Render the Chrome Web Store graphics from docs/store/src/*.html with headless Chrome.

    python scripts/make_store_images.py [--chrome PATH]

Writes docs/store/screenshot-1.png (1280x800) and docs/store/promo-small.png (440x280).
Needs a local Chrome or Edge; no Python packages.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "store" / "src"
OUT = ROOT / "docs" / "store"
JOBS = [("screenshot-1", 1280, 800), ("promo-small", 440, 280)]
CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome", "chromium", "chromium-browser",
]


def find_chrome(explicit: str | None) -> str:
    for c in ([explicit] if explicit else []) + CANDIDATES:
        if c and (Path(c).exists() or shutil.which(c)):
            return c
    sys.exit("Chrome or Edge not found; pass --chrome PATH")


def size(png: Path) -> tuple[int, int]:
    return struct.unpack(">II", png.read_bytes()[16:24])


def main(argv: list[str]) -> int:
    chrome = find_chrome(argv[argv.index("--chrome") + 1] if "--chrome" in argv else None)
    with tempfile.TemporaryDirectory() as profile:
        for name, w, h in JOBS:
            out = OUT / f"{name}.png"
            subprocess.run([
                chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                f"--user-data-dir={profile}", "--allow-file-access-from-files",
                f"--window-size={w},{h}", f"--screenshot={out}", (SRC / f"{name}.html").as_uri(),
            ], check=True, capture_output=True, timeout=60)
            got = size(out)
            print(f"wrote {out.relative_to(ROOT).as_posix()} {got[0]}x{got[1]}")
            if got != (w, h):
                print(f"  expected {w}x{h}", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
