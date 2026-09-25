"""The shipped local stack must be able to generate a template at all.

Found during the D6 step 5 acceptance run. `.env.example` pinned
KP_WORKER_AI_MODEL_ID to the llama.cpp identity while KP_WORKER_AI_BASE_URL was
empty, which falls back to the bundled mock-ai. mock-ai self-reports
`mock-ai/0.2.0`, so every generation job failed the model pin and dead-lettered.

It failed the right way - closed, audited, retried, then dead-lettered - but the
consequence was that a default local stack could never produce a template. That
went unnoticed because the separation-of-duties bar stopped anyone reaching
generation in the first place, so the queue stayed empty and the mismatch never
had a chance to show itself.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ENV_EXAMPLE = (_ROOT / ".env.example").read_text(encoding="utf-8")
_MOCK_AI = (_ROOT / "infrastructure" / "mock-services" / "mock_ai.py").read_text(encoding="utf-8")


def _env_value(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}=(.*)$", _ENV_EXAMPLE, re.MULTILINE)
    assert match is not None, f"{name} is missing from .env.example"
    return match.group(1).strip()


def _mock_ai_model_id() -> str:
    match = re.search(r'"model_id":\s*"([^"]+)"', _MOCK_AI)
    assert match is not None, "mock_ai.py no longer advertises a model_id"
    return match.group(1)


def test_shipped_model_pin_matches_the_backend_the_shipped_config_uses() -> None:
    base_url = _env_value("KP_WORKER_AI_BASE_URL")
    pinned = _env_value("KP_WORKER_AI_MODEL_ID")

    if base_url:
        # Pointed at a real gateway: the pin is that deployment's business, and
        # this test has nothing to say about which model it serves.
        return

    assert pinned == _mock_ai_model_id(), (
        "KP_WORKER_AI_BASE_URL is empty, so generation falls back to the bundled "
        f"mock-ai, which self-reports {_mock_ai_model_id()!r} - but the shipped pin is "
        f"{pinned!r}. Every generation job on a default local stack will fail the "
        "model pin and dead-letter, so no template can ever be produced."
    )
