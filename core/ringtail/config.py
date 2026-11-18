"""Single home for runtime configuration. Reads only from the environment (BYOK)."""

import os

# The one place the default model lives. Override with RINGTAIL_MODEL.
DEFAULT_MODEL = "claude-opus-5-5"

# Hard cap on draft -> validate -> test attempts in `ringtail run` (CLAUDE.md: max 3).
MAX_ATTEMPTS = 3


def model() -> str:
    return os.environ.get("RINGTAIL_MODEL") or DEFAULT_MODEL


def has_credentials() -> bool:
    """BYOK: the key comes only from the user's environment. We never read it ourselves."""
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def key_problem() -> str | None:
    """Describe a malformed ANTHROPIC_API_KEY without ever echoing it.

    A key with whitespace or a non-ASCII character (a smart quote or an ellipsis from
    copy-paste) is not a valid HTTP header value, so the request fails before it is sent
    and the SDK reports it as a connection error. Catch that here with a clear message.
    """
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    if key != key.strip():
        return "ANTHROPIC_API_KEY has leading or trailing whitespace (often a pasted newline)."
    for i, ch in enumerate(key):
        if not ("\x21" <= ch <= "\x7e"):
            return (
                f"ANTHROPIC_API_KEY has an invalid character at position {i + 1} of {len(key)} "
                "(a space, smart quote, or '…' from copy-paste). Set it again, typing the quotes yourself."
            )
    if key[0] in "\"'" or key[-1] in "\"'":
        return "ANTHROPIC_API_KEY includes quote characters. Set it without the surrounding quotes in the value."
    return None


BYOK_MESSAGE = (
    "Ringtail is BYOK (bring your own key): set ANTHROPIC_API_KEY in your environment.\n"
    "  PowerShell:  $env:ANTHROPIC_API_KEY = '<your key>'\n"
    "  bash/zsh:    export ANTHROPIC_API_KEY=<your key>\n"
    "Ringtail never stores, logs, or proxies the key. Only `draft` and `run` need it;\n"
    "`validate`, `test`, and `card` work without it."
)
