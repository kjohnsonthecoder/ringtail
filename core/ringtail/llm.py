"""Anthropic SDK calls with schema-enforced JSON output.

BYOK: the SDK reads ANTHROPIC_API_KEY from the environment. Ringtail never takes the key as
an argument, never logs it, and never writes it anywhere (docs/threat-model.md, T3).

Everything that calls the model goes through the small `LLM` protocol, so tests and CI use
a fake and never need a key.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from ringtail import config


class LLMError(Exception):
    """The model call failed or returned something unusable. May be retried by the caller."""


class LLMConfigError(Exception):
    """Credentials or model configuration problem. Exit code 2, never retried."""


class LLM(Protocol):
    def complete_json(self, system: str, user: str, schema: dict, *, purpose: str) -> dict:
        """Return the model's reply parsed as a JSON object matching `schema`."""
        ...


class AnthropicLLM:
    """Real client. Structured outputs guarantee syntactically valid JSON matching the
    schema; Ringtail still validates every field afterwards, because valid JSON can still
    say the wrong thing."""

    def __init__(self, model: str | None = None, effort: str = "high", max_tokens: int = 16000):
        import anthropic  # imported here so validate/test/card work without the SDK configured

        if not config.has_credentials():
            raise LLMConfigError(config.BYOK_MESSAGE)
        problem = config.key_problem()
        if problem:
            raise LLMConfigError(problem)
        self._anthropic = anthropic
        self.client = anthropic.Anthropic(max_retries=3)
        self.model = model or config.model()
        self.effort = effort
        self.max_tokens = max_tokens
        self.usage: list[dict] = []

    def complete_json(self, system: str, user: str, schema: dict, *, purpose: str) -> dict:
        a = self._anthropic
        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={
                    "effort": self.effort,
                    "format": {"type": "json_schema", "schema": schema},
                },
                # If a safety classifier declines, the API retries on a fallback model.
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except a.AuthenticationError as e:
            raise LLMConfigError(f"Anthropic rejected the API key ({e.status_code}). {config.BYOK_MESSAGE}") from None
        except (a.PermissionDeniedError, a.NotFoundError) as e:
            raise LLMConfigError(f"model '{self.model}' is not available to this key ({e.status_code}).") from None
        except a.BadRequestError as e:
            raise LLMError(f"{purpose}: request rejected ({e.status_code}): {e.message}") from None
        except a.RateLimitError:
            raise LLMError(f"{purpose}: rate limited after retries; try again shortly") from None
        except a.APIStatusError as e:
            raise LLMError(f"{purpose}: API error {e.status_code}") from None
        except a.APIConnectionError as e:
            raise LLMError(f"{purpose}: could not reach the Anthropic API ({cause_chain(e)})") from None

        u = response.usage
        self.usage.append({"purpose": purpose, "input": u.input_tokens, "output": u.output_tokens})

        if response.stop_reason == "refusal":
            cat = getattr(response.stop_details, "category", None) if response.stop_details else None
            raise LLMError(f"{purpose}: the model declined (category: {cat})")
        if response.stop_reason == "max_tokens":
            raise LLMError(f"{purpose}: reply hit max_tokens ({self.max_tokens}) and was cut off")

        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise LLMError(f"{purpose}: reply had no text block")
        return parse_json_object(text, purpose)


def cause_chain(exc: BaseException, limit: int = 5) -> str:
    """Exception type names only, e.g. 'APIConnectionError <- ConnectError <- SSLError'.

    Never include messages: some HTTP-layer errors quote header values, which would print
    the API key (docs/threat-model.md, T3)."""
    names, cur, seen = [], exc, set()
    while cur is not None and id(cur) not in seen and len(names) < limit:
        seen.add(id(cur))
        names.append(type(cur).__name__)
        cur = cur.__cause__ or cur.__context__
    hint = ""
    joined = " ".join(names)
    if "SSL" in joined or "Certificate" in joined:
        hint = "; a proxy or antivirus may be intercepting HTTPS"
    elif "Timeout" in joined:
        hint = "; the network is slow or blocking api.anthropic.com"
    elif "Protocol" in joined or "Encode" in joined:
        hint = "; often a malformed API key value"
    return " <- ".join(names) + hint


def parse_json_object(text: str, purpose: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise LLMError(f"{purpose}: reply was not valid JSON ({e.msg})") from None
    if not isinstance(data, dict):
        raise LLMError(f"{purpose}: reply was JSON but not an object")
    return data
