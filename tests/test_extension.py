"""Guardrails for the browser extension (ADR 0005, threat model T7).

These fail CI if the extension's permissions grow, if a page could reach it, if a secret
could land in persistent storage, or if its copies of the shared modules drift from web/.
"""

import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "extension"
MANIFEST = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
LIVE = "https://web-production-34d65045.up.railway.app"

sys.path.insert(0, str(ROOT / "scripts"))
import sync_extension  # noqa: E402


def _js_files():
    return [p for p in EXT.rglob("*.js") if "lib" not in p.parts]


def test_manifest_v3_with_exactly_the_documented_permissions():
    m = MANIFEST
    assert m["manifest_version"] == 3
    assert sorted(m["permissions"]) == ["contextMenus", "sidePanel", "storage"]
    assert m["host_permissions"] == ["https://api.anthropic.com/*", f"{LIVE}/*"]
    assert m["optional_host_permissions"] == ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"]


def test_no_way_for_pages_to_reach_the_extension():
    for key in ("content_scripts", "web_accessible_resources", "externally_connectable"):
        assert key not in MANIFEST, key
    assert "<all_urls>" not in json.dumps(MANIFEST)
    for broad in ("tabs", "activeTab", "scripting", "webRequest", "cookies", "history"):
        assert broad not in MANIFEST["permissions"]
    # A custom CSP could loosen MV3's default; there isn't one.
    assert "content_security_policy" not in MANIFEST


def test_no_remote_code():
    for html in EXT.rglob("*.html"):
        text = html.read_text(encoding="utf-8")
        for src in re.findall(r'<(?:script|link)[^>]+(?:src|href)="([^"]+)"', text):
            assert not re.match(r"(https?:)?//", src), f"{html.name} loads remote {src}"
        assert "<script>" not in text, f"inline script in {html.name}"
    for js in _js_files():
        text = js.read_text(encoding="utf-8")
        assert "eval(" not in text and "new Function" not in text, js.name
        for spec in re.findall(r'from\s+"([^"]+)"', text):
            assert spec.startswith("."), f"{js.name} imports non-local {spec}"


def test_secrets_only_in_session_storage():
    for js in _js_files():
        text = js.read_text(encoding="utf-8")
        assert "storage.sync" not in text, js.name
        assert "localStorage" not in text and "indexedDB" not in text, js.name
    panel = (EXT / "sidepanel" / "sidepanel.js").read_text(encoding="utf-8")
    assert "const SECRETS = chrome.storage.session;" in panel
    assert "const PREFS = chrome.storage.local;" in panel
    for line in panel.splitlines():
        if "PREFS." in line:
            assert not re.search(r"apiKey|accessCode|pendingSelection|key\b", line.replace("PREFS.", "")), line


def test_background_never_reads_the_page():
    bg = (EXT / "background.js").read_text(encoding="utf-8")
    assert "selectionText" in bg
    assert "pageUrl" not in bg and "executeScript" not in bg


def test_shared_modules_match_web():
    assert sync_extension.stale() == [], "run: python scripts/sync_extension.py"


def test_icons_exist_at_declared_sizes():
    for size, rel in MANIFEST["icons"].items():
        data = (EXT / rel).read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        w, h = struct.unpack(">II", data[16:24])
        assert (w, h) == (int(size), int(size)), rel


def test_description_fits_the_store_limit():
    assert len(MANIFEST["description"]) <= 132
    assert re.fullmatch(r"\d+\.\d+\.\d+", MANIFEST["version"])
