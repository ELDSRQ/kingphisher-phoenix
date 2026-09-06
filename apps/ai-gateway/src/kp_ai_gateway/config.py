"""Configuration for the internal AI generation gateway.

The gateway is the supported AI-010 inference path: it turns the platform's
``/propose`` contract into a schema-constrained call to a pinned local
``llama.cpp`` server, and returns the exact configured model identity rather
than trusting the model's self-report (see docs/ai010-worker-parity.md #3).
"""

from __future__ import annotations

from typing import Self

from pydantic import model_validator
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

    #: Shared secret a caller must present as ``Authorization: Bearer <key>`` on
    #: ``/propose`` and ``/setup-assist``. The generation worker already sends
    #: this value as its ``ai_bearer_token`` (jobs.py:2088), so the same secret
    #: is configured on both sides. When ``None`` (the default) authentication
    #: is disabled to preserve local dev, and the gateway logs once that it is
    #: running unauthenticated. Compared in constant time.
    api_key: str | None = None

    #: Fail-closed switch for managed deployments. When ``True`` the gateway
    #: REQUIRES ``api_key`` to be set and rejects any request that does not
    #: present the matching bearer — a missing ``api_key`` in this posture is a
    #: misconfiguration, not an invitation to serve unauthenticated (that is the
    #: silent-open hole this flag exists to close). When ``False`` (the default)
    #: the local llama.cpp stack keeps working with no secret configured: dev is
    #: satisfiable by a local shared secret or by nothing at all, never by an
    #: Azure-only dependency. Managed sets ``KP_AI_GATEWAY_REQUIRE_AUTH=true``
    #: alongside ``KP_AI_GATEWAY_API_KEY``.
    require_auth: bool = False

    @model_validator(mode="after")
    def _auth_config_is_coherent(self) -> Self:
        """Fail closed at construction when auth is required but no key is set.

        In a managed deployment this raises before the app can serve, so a pod
        that forgot to inject the secret never comes up accepting unauthenticated
        ``/propose`` calls. The default posture (``require_auth`` False) is
        untouched, so the local stack still boots with no secret.
        """

        if self.require_auth and not self.api_key:
            raise ValueError(
                "KP_AI_GATEWAY_REQUIRE_AUTH is set but KP_AI_GATEWAY_API_KEY is empty; "
                "authentication is required and cannot be satisfied. Set the shared bearer "
                "secret or disable REQUIRE_AUTH for local development."
            )
        return self
