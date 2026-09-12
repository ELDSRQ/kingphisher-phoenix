"""Configuration for the internal AI generation gateway.

The gateway is the supported AI-010 inference path: it turns the platform's
``/propose`` contract into a schema-constrained call to a pinned local
``llama.cpp`` server, and returns the exact configured model identity rather
than trusting the model's self-report (see docs/ai010-worker-parity.md #3).
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: How the gateway authenticates OUTBOUND to its model backend. This is
#: deliberately a separate axis from ``api_key``/``require_auth`` below, which
#: authenticate INBOUND callers of ``/propose`` (AI-016). The two must never be
#: conflated: the inbound secret proves the caller is the platform's worker,
#: while this proves the gateway is allowed to call the model backend.
#:
#: * ``none`` — the local/self-hosted ``llama.cpp`` server, which needs no
#:   credential. This is the default, so the existing local stack is unchanged.
#: * ``entra`` — an Azure AI Foundry Serverless (pay-per-token) endpoint
#:   (AI-015 "Path D"), reached with an Entra bearer minted from the gateway's
#:   User-Assigned Managed Identity. No API key is supported or stored: managed
#:   identity is the only managed posture, so no key can be leaked or rotated.
UpstreamAuthMode = Literal["none", "entra"]

#: Default Entra audience for Azure AI Foundry / Azure AI Services endpoints.
#: Foundry Serverless accepts a Cognitive Services audience token.
_DEFAULT_UPSTREAM_SCOPE = "https://cognitiveservices.azure.com/.default"

#: Accepted values for ``reasoning_effort`` (OpenAI / Azure reasoning models).
#: ``none`` is accepted by some models (e.g. gpt-5.6-luna) to disable reasoning;
#: others reject ``reasoning_effort`` entirely (e.g. gpt-5.6-terra) and must
#: leave it unset. Which values a given model accepts is the operator's concern;
#: this set only guards the token itself.
_REASONING_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high"})


class GatewaySettings(BaseSettings):
    """Environment-driven settings for the AI gateway."""

    model_config = SettingsConfigDict(env_prefix="KP_AI_GATEWAY_", extra="ignore", env_ignore_empty=True)

    #: OpenAI-compatible base URL of the UPSTREAM model backend. The name is
    #: historical and kept for the existing env wiring: locally it is the pinned
    #: llama.cpp server (http://127.0.0.1:18081/v1) and in managed deployments
    #: it is the Azure AI Foundry Serverless endpoint
    #: (https://<resource>.services.ai.azure.com/models). Only this value and
    #: the outbound auth mode change between the two — the gateway's contract
    #: and governance layer are identical (see docs/DECISIONS.md D-0001).
    #: Never a public secretless promise: the gateway is what the worker treats
    #: as its provider.
    llama_base_url: str = "http://127.0.0.1:18081/v1"

    #: The exact model identity the AI-010 bake-off selected. This value is
    #: returned as ``model_id`` on every proposal so the worker's pinned-model
    #: guard matches. It is NOT read from the model, which invents identities.
    model_id: str = "llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M"

    #: Per-request timeout to the llama.cpp server, in seconds.
    request_timeout_seconds: float = 120.0

    #: Sampling temperature. Zero for reproducible, review-stable drafts on
    #: backends that accept it (local llama.cpp, gpt-oss-120b). Some current GA
    #: models (e.g. gpt-5.6-terra) reject any non-default temperature and must
    #: have the field omitted entirely — see ``send_temperature``.
    temperature: float = 0.0

    #: Whether to send ``temperature`` at all. ``True`` (the default) preserves
    #: the reproducible-draft behaviour. Set ``False`` for a model that only
    #: accepts its default temperature (it returns 400 "does not support 0.0" /
    #: "Only the default (1) value is supported" otherwise); the field is then
    #: omitted and the model's default applies. A human reviews every draft, so
    #: the loss of temperature=0 reproducibility is acceptable.
    send_temperature: bool = True

    #: Upper bound on generated (completion) tokens. ``None`` (the default) sends
    #: no cap, preserving the historical behaviour. Bounding this is the primary
    #: reliability lever for the managed path: an unbounded reasoning model can
    #: run for tens of seconds and blow the worker's request timeout (the Foundry
    #: ``gpt-oss-120b`` dead-lettering was this). The wire key differs by backend
    #: (see ``_completion_token_param`` in ``main.py``): Azure reasoning models
    #: require ``max_completion_tokens`` and reject ``max_tokens``; the local
    #: llama.cpp server speaks ``max_tokens``. A single value covers both.
    max_completion_tokens: int | None = None

    #: Reasoning effort for reasoning-capable models (``minimal``/``low``/
    #: ``medium``/``high``). ``None`` (the default) sends no field, so non-reasoning
    #: backends (e.g. the local Qwen2.5 llama.cpp server, which is not a reasoning
    #: model) and older OpenAI-compatible servers are unaffected. On the managed
    #: path ``low`` collapsed ``gpt-oss-120b`` latency from tens of seconds to
    #: ~1.7s while keeping valid schema-constrained output.
    reasoning_effort: str | None = None

    #: P1 extraction stage. When set, enables ``POST /extract`` (normalize threat
    #: evidence into a ``CampaignRecord``) using THIS model id, returned as the
    #: record's pinned ``model_id``. ``None`` (the default) disables ``/extract``
    #: with a 503, so a single-model or on-prem deployment is unaffected. The
    #: extract call reuses ``send_temperature`` and ``max_completion_tokens``;
    #: only reasoning effort is separate (generation and extraction models differ
    #: — e.g. gpt-5.6-terra rejects reasoning_effort, gpt-5.6-luna takes ``none``).
    extract_model_id: str | None = None

    #: Reasoning effort for the ``/extract`` model (see ``reasoning_effort``).
    #: ``None`` sends no field; for gpt-5.6-luna extraction, ``none`` is correct.
    extract_reasoning_effort: str | None = None

    #: P3 web-search discovery. When set (together with ``responses_base_url``),
    #: enables ``POST /discover`` — a Responses-API ``web_search`` call that
    #: returns cited, allow-listed campaign leads. ``None`` (default) disables it
    #: with 503, so any deployment without live web egress (all on-prem) is
    #: unaffected. This is the ONLY path that reaches the public web.
    discover_model_id: str | None = None

    #: Base URL of the Azure AI Foundry Responses API (``.../openai/v1``, the
    #: ``services.ai.azure.com`` host), used ONLY by ``/discover``. Distinct from
    #: ``llama_base_url`` (chat/completions). Empty disables ``/discover``.
    responses_base_url: str | None = None

    #: Reasoning effort for the discovery model (``none`` for gpt-5.6-luna).
    discover_reasoning_effort: str | None = None

    #: Output-token budget for a ``/discover`` call. Web search + reasoning spend
    #: budget before the final JSON, so this is generous by default.
    discover_max_output_tokens: int = 6000

    #: Comma-separated override of the approved citation domains a lead must cite
    #: (a lead with no allow-listed citation is dropped: no source, no campaign).
    #: Empty uses the contract default (reputable threat-intel vendors/CERTs).
    discover_citation_domains: str = ""

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

    #: Outbound auth mode for the upstream model backend (see
    #: ``UpstreamAuthMode``). ``none`` (the default) keeps the local llama.cpp
    #: path byte-for-byte unchanged: no ``Authorization`` header is sent.
    #: ``entra`` is the managed/Foundry posture and requires
    #: ``upstream_managed_identity_client_id``.
    upstream_auth_mode: UpstreamAuthMode = "none"

    #: Client id of the User-Assigned Managed Identity the gateway uses to mint
    #: an Entra bearer for the upstream (AI-015 Path D). Required when
    #: ``upstream_auth_mode == "entra"``; a managed deployment that forgets it
    #: fails closed at construction rather than silently calling unauthenticated
    #: (which Foundry would reject, and which would otherwise look like a
    #: backend outage).
    upstream_managed_identity_client_id: str | None = None

    #: Entra token scope (audience) requested for the upstream. The default is
    #: the Azure AI Foundry / Cognitive Services audience; the value is
    #: overridable so a different OpenAI-compatible Entra-protected backend can
    #: be targeted without a code change.
    upstream_token_scope: str = _DEFAULT_UPSTREAM_SCOPE

    @model_validator(mode="after")
    def _upstream_auth_config_is_coherent(self) -> Self:
        """Fail closed when an authenticated upstream is selected but not configured.

        Mirrors the inbound ``require_auth`` rule: a half-configured managed
        posture must be a boot-time error, not a request-time surprise.
        ``none`` (the default) is untouched, so the local stack still boots with
        no identity configured.
        """

        if self.upstream_auth_mode == "entra" and not self.upstream_managed_identity_client_id:
            raise ValueError(
                "KP_AI_GATEWAY_UPSTREAM_AUTH_MODE=entra requires "
                "KP_AI_GATEWAY_UPSTREAM_MANAGED_IDENTITY_CLIENT_ID; set it to the client id of the "
                "gateway's user-assigned managed identity, or select upstream_auth_mode=none for local "
                "development."
            )
        if not self.upstream_token_scope.strip():
            raise ValueError("KP_AI_GATEWAY_UPSTREAM_TOKEN_SCOPE must not be empty")
        return self

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

    @model_validator(mode="after")
    def _generation_bounds_are_coherent(self) -> Self:
        """Validate the optional reliability bounds fail-closed at construction.

        Both default to ``None`` (unbounded / unset), so a deployment that sets
        neither is byte-for-byte unchanged. When set, a bad value is a boot-time
        error rather than a request-time surprise that silently degrades.
        """

        if self.max_completion_tokens is not None and self.max_completion_tokens < 1:
            raise ValueError("KP_AI_GATEWAY_MAX_COMPLETION_TOKENS must be a positive integer when set")
        if self.reasoning_effort is not None and self.reasoning_effort not in _REASONING_EFFORTS:
            raise ValueError(
                f"KP_AI_GATEWAY_REASONING_EFFORT must be one of {', '.join(sorted(_REASONING_EFFORTS))} when set"
            )
        if self.extract_reasoning_effort is not None and self.extract_reasoning_effort not in _REASONING_EFFORTS:
            allowed = ", ".join(sorted(_REASONING_EFFORTS))
            raise ValueError(f"KP_AI_GATEWAY_EXTRACT_REASONING_EFFORT must be one of {allowed} when set")
        if self.discover_reasoning_effort is not None and self.discover_reasoning_effort not in _REASONING_EFFORTS:
            allowed = ", ".join(sorted(_REASONING_EFFORTS))
            raise ValueError(f"KP_AI_GATEWAY_DISCOVER_REASONING_EFFORT must be one of {allowed} when set")
        if self.discover_max_output_tokens < 1:
            raise ValueError("KP_AI_GATEWAY_DISCOVER_MAX_OUTPUT_TOKENS must be a positive integer")
        return self
