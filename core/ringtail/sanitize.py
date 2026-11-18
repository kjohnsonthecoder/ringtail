"""Turn hostile input text into plain text that's safe to wrap as data in a prompt.

See docs/threat-model.md (T1). This is defense in depth, not the main control: the main
controls are the nonce-delimited data wrapper, schema-enforced JSON output, and the
deterministic checks after the model.
"""

from __future__ import annotations

import html
import re
import secrets
import unicodedata

MAX_INPUT_CHARS = 60_000  # ~15k tokens; a long threat report fits, a dumped web page doesn't


class InputError(ValueError):
    """Input is empty or too large. A usage error, not something to silently fix."""


_DROP_BLOCKS = re.compile(r"<(script|style|noscript|template)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_COMMENTS = re.compile(r"<!--.*?-->", re.DOTALL)
_TAGS = re.compile(r"<[a-zA-Z/!][^>]{0,2000}>")
# Delimiter-like strings the input might use to fake the end of the data block.
_FAKE_DELIMS = re.compile(r"</?\s*untrusted_input[^>]*>", re.IGNORECASE)


def _allowed_char(ch: str) -> bool:
    if ch in "\n\t":
        return True
    cat = unicodedata.category(ch)
    # Cc: control chars. Cf: format chars (zero-width spaces, bidi overrides, tag chars).
    return cat not in ("Cc", "Cf", "Co", "Cs")


def to_plain_text(text: str) -> str:
    """Strip HTML and invisible characters, normalize whitespace. Raises InputError."""
    if text is None or not text.strip():
        raise InputError("input text is empty")
    t = unicodedata.normalize("NFKC", text)
    t = _FAKE_DELIMS.sub("[removed delimiter]", t)  # before tag stripping, so it stays visible
    if "<" in t and ">" in t:
        t = _DROP_BLOCKS.sub(" ", t)
        t = _COMMENTS.sub(" ", t)
        t = _TAGS.sub(" ", t)
        t = html.unescape(t)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = "".join(ch for ch in t if _allowed_char(ch))
    t = _FAKE_DELIMS.sub("[removed delimiter]", t)
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t).strip()
    if not t:
        raise InputError("input has no readable text after cleaning")
    if len(t) > MAX_INPUT_CHARS:
        raise InputError(
            f"input is {len(t):,} characters after cleaning; the limit is {MAX_INPUT_CHARS:,}. "
            "Trim it to the relevant part of the report (Ringtail won't cut it silently)."
        )
    return t


def wrap_as_data(text: str, label: str = "input") -> tuple[str, str]:
    """Wrap cleaned text in a delimiter with a random nonce. Returns (wrapped, nonce)."""
    nonce = secrets.token_hex(8)
    wrapped = f'<untrusted_input id="{nonce}" kind="{label}">\n{text}\n</untrusted_input id="{nonce}">'
    return wrapped, nonce
