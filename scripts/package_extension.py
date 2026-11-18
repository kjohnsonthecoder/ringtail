"""Build the extension zip for the Chrome Web Store and GitHub releases.

    python scripts/package_extension.py

Writes dist/ringtail-extension-<version>.zip with manifest.json at the zip root. Refuses to
build if extension/lib/ is out of sync with web/ or the manifest version doesn't match
pyproject.toml, so a released zip always matches the tested code.
"""

from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "extension"
DIST = ROOT / "dist"
INCLUDE_SUFFIXES = {".json", ".js", ".html", ".css", ".png"}

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sync_extension  # noqa: E402


def project_version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else ""


def main() -> int:
    manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    if version != project_version():
        print(f"manifest version {version} != pyproject version {project_version()}", file=sys.stderr)
        return 1
    stale = sync_extension.stale()
    if stale:
        print(f"extension/lib is stale: {', '.join(stale)} (run scripts/sync_extension.py)", file=sys.stderr)
        return 1

    files = sorted(p for p in EXT.rglob("*") if p.is_file() and p.suffix in INCLUDE_SUFFIXES)
    DIST.mkdir(exist_ok=True)
    out = DIST / f"ringtail-extension-{version}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            rel = p.relative_to(EXT).as_posix()
            data = p.read_bytes()
            if p.suffix != ".png":
                data = data.replace(b"\r\n", b"\n")  # same bytes on Windows and Linux
            info = zipfile.ZipInfo(rel, date_time=(2026, 1, 1, 0, 0, 0))  # reproducible
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    print(f"wrote {out.relative_to(ROOT).as_posix()} ({len(files)} files, {out.stat().st_size:,} bytes)")
    for p in files:
        print(f"  {p.relative_to(EXT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
