"""BYOK key hygiene and error messages that never echo the key."""

import pytest

from ringtail import config
from ringtail.llm import AnthropicLLM, LLMConfigError, cause_chain

FAKE = "sk-ant-api03-FAKEFAKEFAKE"


@pytest.mark.parametrize(
    "key, needle",
    [
        (FAKE + "\n", "whitespace"),
        (" " + FAKE, "whitespace"),
        ("sk-ant-...your key…", "invalid character at position 15 of 19"),
        ("sk-ant-...yourkey…", "invalid character at position 18 of 18"),
        ("sk-ant-fake key", "invalid character at position 12"),
        (f"'{FAKE}'", "quote"),
    ],
)
def test_malformed_keys_are_caught_without_echoing_them(monkeypatch, key, needle):
    monkeypatch.setenv("ANTHROPIC_API_KEY", key)
    problem = config.key_problem()
    assert problem and needle in problem
    assert "FAKE" not in problem
    with pytest.raises(LLMConfigError) as e:
        AnthropicLLM()
    assert "FAKE" not in str(e.value)


def test_well_formed_key_passes(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE)
    assert config.key_problem() is None


def test_cause_chain_lists_types_only():
    class LocalProtocolError(Exception):
        pass

    class APIConnectionError(Exception):
        pass

    try:
        try:
            raise LocalProtocolError(f"Illegal header value b'{FAKE}\\n'")
        except LocalProtocolError as inner:
            raise APIConnectionError("Connection error.") from inner
    except APIConnectionError as outer:
        text = cause_chain(outer)
    assert text.startswith("APIConnectionError <- LocalProtocolError")
    assert "malformed API key" in text
    assert "FAKE" not in text
