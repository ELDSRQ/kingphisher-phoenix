"""Configuration for the internal AI generation gateway.

The gateway is the supported AI-010 inference path: it turns the platform's
``/propose`` contract into a schema-constrained call to a pinned local
``llama.cpp`` server, and returns the exact configured model identity rather
than trusting the model's self-report (see docs/ai010-worker-parity.md #3).
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    """Environment-driven settings for the AI gateway."""

    model_config = SettingsConfigDict(env_prefix="KP_AI_GATEWAY_", extra="ignore", env_ignore_empty=True)

    #: OpenAI-compatible base URL of the pinned llama.cpp server, e.g.
    #: http://127.0.0.1:18081/v1. Never a public secretless promise: the gateway
    #: is what the worker treats as its provider.
    llama_base_url: str = "http://127.0.0.1:18081/v1"

    #: The exact model identity the AI-010 bake-off selected. This value is
    #: returned as ``model_id`` on every proposal so the worker's pinned-model
    #: guard matches. It is NOT read from the model, which invents identities.
    model_id: str = "llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M"

    #: Per-request timeout to the llama.cpp server, in seconds.
    request_timeout_seconds: float = 120.0

    #: Sampling temperature. Zero for reproducible, review-stable drafts.
    temperature: float = 0.0
