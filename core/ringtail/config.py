"""Single home for runtime configuration. Reads only from the environment (BYOK)."""

import os

# The one place the default model lives. Override with RINGTAIL_MODEL.
DEFAULT_MODEL = "claude-sonnet-5-5"


def model() -> str:
    return os.environ.get("RINGTAIL_MODEL") or DEFAULT_MODEL
