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


BYOK_MESSAGE = (
    "Ringtail is BYOK (bring your own key): set ANTHROPIC_API_KEY in your environment.\n"
    "  PowerShell:  $env:ANTHROPIC_API_KEY = '<your key>'\n"
    "  bash/zsh:    export ANTHROPIC_API_KEY=<your key>\n"
    "Ringtail never stores, logs, or proxies the key. Only `draft` and `run` need it;\n"
    "`validate`, `test`, and `card` work without it."
)
