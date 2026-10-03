"""Registry of generation-model providers the operator can bring their own key to.

Each preset is an OpenAI-compatible chat/completions endpoint, so the existing
AI gateway can proxy to it unchanged (it keeps enforcing the realistic-lure
prompt and the strict JSON schema). The operator supplies an API key and may
override the base URL and model per provider; ``local`` is the on-prem model and
needs no key or egress.

IMPORTANT: selecting any non-``local`` provider sends the threat evidence and the
generated lure OUT to that third party. That is a deliberate, operator-made
egress decision — never a default.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Outbound auth styles the gateway understands for a provider's upstream call.
AUTH_NONE = "none"
AUTH_BEARER = "bearer"  # Authorization: Bearer <key>  (OpenAI/Gemini/OpenRouter/OpenCode/Anthropic-compat)


@dataclass(frozen=True)
class ProviderPreset:
    key: str
    label: str
    default_base_url: str
    default_model: str
    auth_style: str
    needs_key: bool
    sends_data_offsite: bool
    notes: str


#: The local on-prem model routed through the gateway's own configured backend.
LOCAL = "local"

PROVIDERS: dict[str, ProviderPreset] = {
    LOCAL: ProviderPreset(
        key=LOCAL,
        label="Local model (on-prem)",
        default_base_url="",
        default_model="",
        auth_style=AUTH_NONE,
        needs_key=False,
        sends_data_offsite=False,
        notes="The on-prem model served through the gateway. No key, no egress; the default.",
    ),
    "openai": ProviderPreset(
        key="openai",
        label="OpenAI",
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-4o",
        auth_style=AUTH_BEARER,
        needs_key=True,
        sends_data_offsite=True,
        notes="Sends generation content to OpenAI. Frontier models may refuse to write phishing lures.",
    ),
    "gemini": ProviderPreset(
        key="gemini",
        label="Google Gemini",
        default_base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        default_model="gemini-2.5-pro",
        auth_style=AUTH_BEARER,
        needs_key=True,
        sends_data_offsite=True,
        notes="Gemini via its OpenAI-compatible endpoint. May refuse phishing-content generation.",
    ),
    "anthropic": ProviderPreset(
        key="anthropic",
        label="Anthropic (Claude)",
        default_base_url="https://api.anthropic.com/v1",
        default_model="claude-sonnet-4-5",
        auth_style=AUTH_BEARER,
        needs_key=True,
        sends_data_offsite=True,
        notes="Claude via its OpenAI-compatible endpoint. May refuse phishing-content generation.",
    ),
    "openrouter": ProviderPreset(
        key="openrouter",
        label="OpenRouter",
        default_base_url="https://openrouter.ai/api/v1",
        default_model="",
        auth_style=AUTH_BEARER,
        needs_key=True,
        sends_data_offsite=True,
        notes="One key, many models (set the model id, e.g. anthropic/claude-sonnet-4.5 or openai/gpt-4o).",
    ),
    "opencode": ProviderPreset(
        key="opencode",
        label="OpenCode Zen",
        default_base_url="https://opencode.ai/zen/v1",
        default_model="",
        auth_style=AUTH_BEARER,
        needs_key=True,
        sends_data_offsite=True,
        notes="One key, many models via OpenCode's gateway (set the model id). Override the base URL if needed.",
    ),
}


def is_known_provider(provider: str) -> bool:
    return provider in PROVIDERS


def preset(provider: str) -> ProviderPreset:
    try:
        return PROVIDERS[provider]
    except KeyError:
        raise KeyError(f"unknown provider: {provider}") from None


def resolve_base_url(provider: str, override: str | None) -> str:
    base = (override or "").strip() or preset(provider).default_base_url
    return base.rstrip("/")


def resolve_model(provider: str, override: str | None) -> str:
    return (override or "").strip() or preset(provider).default_model
