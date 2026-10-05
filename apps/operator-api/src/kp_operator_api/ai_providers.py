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

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

#: Outbound auth styles the gateway understands for a provider's upstream call.
AUTH_NONE = "none"
AUTH_BEARER = "bearer"  # Authorization: Bearer <key>  (OpenAI/Gemini/OpenRouter/OpenCode/Anthropic-compat)

#: Egress classification of a selected provider's effective base URL (R-02). The
#: audit record and UI must reflect whether generation content actually leaves
#: the local network, not a static per-preset guess — a ``custom`` base URL can
#: point anywhere.
EGRESS_ON_NETWORK = "on_network"
EGRESS_OFFSITE = "offsite"
EGRESS_UNKNOWN = "unknown"

#: Host name suffixes treated as on-network without DNS resolution.
_ON_NETWORK_HOST_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home.arpa")


def classify_egress(base_url: str | None) -> str:
    """Classify whether content sent to ``base_url`` leaves the local network.

    Decided from the URL host alone (no DNS, to stay deterministic): loopback /
    RFC1918 / link-local IPs and loopback-style names are ``on_network``; a
    malformed/empty URL is ``unknown``; any other (public, or a hostname we
    cannot prove is internal) is ``offsite``. Defaulting an unprovable host to
    ``offsite`` is the honest, fail-safe choice: the system never falsely claims
    "no data leaves your network".
    """

    if not base_url:
        return EGRESS_UNKNOWN
    try:
        host = (urlparse(base_url).hostname or "").strip().lower()
    except ValueError:
        return EGRESS_UNKNOWN
    if not host:
        return EGRESS_UNKNOWN
    if host == "localhost" or host.endswith(_ON_NETWORK_HOST_SUFFIXES):
        return EGRESS_ON_NETWORK
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return EGRESS_OFFSITE  # a non-loopback hostname we cannot prove is internal
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return EGRESS_ON_NETWORK
    return EGRESS_OFFSITE


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
    "custom": ProviderPreset(
        key="custom",
        label="Custom / self-hosted (OpenAI-compatible)",
        default_base_url="",
        default_model="",
        auth_style=AUTH_BEARER,
        needs_key=False,
        sends_data_offsite=False,
        notes=(
            "Point at any OpenAI-compatible endpoint you host, e.g. a local abliterated/uncensored model "
            "served by Ollama (http://127.0.0.1:11434/v1) or vLLM. Set the base URL and model id; an API "
            "key is optional (used only if your server requires one). Whether data stays on your network "
            "depends on the base URL — the console classifies it and records the actual egress."
        ),
    ),
}


def provider_egress(provider: str, base_url: str | None) -> str:
    """Egress class for a selected provider; ``local`` is always on-network.

    ``local`` runs through the gateway's own configured backend and has no
    operator-set base URL, so it is on-network by construction. Every other
    provider is classified from its effective base URL (see ``classify_egress``).
    """

    if provider == LOCAL:
        return EGRESS_ON_NETWORK
    return classify_egress(base_url)


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
