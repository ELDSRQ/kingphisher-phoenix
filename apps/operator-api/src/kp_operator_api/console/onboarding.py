"""Guided setup wizard: field help, AI setup assistance, and connection tests.

Moved verbatim out of ``kp_operator_api.console`` during the ARC-002 Item 2
split. It renders the wizard from the shared step schema in
``kp_operator_api.console.config``, persists a reviewed patch through the one
atomic env-file writer in ``kp_operator_api.console.env_store``, and runs the
pinned-egress connection probes from ``kp_operator_api.connection_probes``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_telemetry.errors import ConflictError, PermissionDeniedError
from pydantic import BaseModel, Field

from kp_operator_api.auth import require_capability
from kp_operator_api.connection_probes import (
    _allow_development_loopback,
    _auth_headers,
    _connection_test_result,
    _credentials_for_destination,
    _microsoft365_probe_url,
    _probe_http,
    _probe_smtp,
    _probe_webhook,
    _resolve_setup_assist_endpoint,
    _selected_destination,
    _validated_acs_endpoint,
)
from kp_operator_api.console.azure_deployment_routes import _AZURE_DEPLOYMENT_STEPS
from kp_operator_api.console.config import (
    _ONBOARDING_STEPS,
    ConfigPatch,
    _onboarding_step_configured,
    _validate_config_candidate,
)
from kp_operator_api.console.env_store import (
    _ALLOWED_KEYS,
    _SECRET_KEYS,
    MANAGED_CONFIG_MESSAGE,
    _atomic_update_env,
    _AtomicEnvUpdateError,
    _env_path,
    _env_values,
    _reject_if_managed,
)

router = APIRouter(prefix="/api/v1/console", tags=["console"])


class OnboardingPatch(ConfigPatch):
    completed: bool | None = None


class ConnectionTest(BaseModel):
    component: str
    values: dict[str, str] = Field(default_factory=dict)


class SetupAssistRequest(BaseModel):
    component: str = Field(min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")
    question: str = Field(min_length=1, max_length=1000)
    values: dict[str, str] = Field(default_factory=dict)


class SetupAssistResponse(BaseModel):
    answer: str
    suggestions: dict[str, str]
    source: str
    warnings: list[str]


_FIELD_HELP: dict[str, tuple[str, str]] = {
    "OPERATOR_API_OIDC_MODE": (
        "Choose 'dev' only for local testing. Choose 'oidc' to let employees sign in through your identity provider.",
        "oidc",
    ),
    "OPERATOR_API_OIDC_ISSUER": (
        "The trusted sign-in authority. Copy the issuer exactly from your provider's OpenID Connect metadata; "
        "it is usually a tenant-specific HTTPS URL.",
        "https://login.microsoftonline.com/your-tenant-id/v2.0",
    ),
    "OPERATOR_API_OIDC_AUDIENCE": (
        "The identifier written into access tokens to show they were issued for this API. It must match the "
        "audience configured for the API in your identity provider.",
        "api://phishing-awareness-platform",
    ),
    "OPERATOR_API_OIDC_CLIENT_ID": (
        "The public identifier assigned to the browser console application by your identity provider. "
        "It is not a secret.",
        "00000000-0000-0000-0000-000000000000",
    ),
    "OPERATOR_API_OIDC_CLIENT_SECRET": (
        "A private credential for a confidential OIDC client. Leave blank for a public PKCE client and never "
        "paste it into support messages.",
        "Leave blank to keep the existing secret",
    ),
    "OPERATOR_API_OIDC_REDIRECT_URI": (
        "The exact URL the identity provider returns users to after sign-in. Register this same value with "
        "the provider.",
        "https://awareness.example/api/v1/console/oidc/callback",
    ),
    "KP_WORKER_GRAPH_BASE_URL": (
        "The root URL of a Microsoft Graph-compatible employee directory. The platform reads its /users "
        "collection in bounded pages.",
        "https://graph.microsoft.com/v1.0",
    ),
    "KP_WORKER_GRAPH_MAX_USERS": (
        "A safety ceiling on employees imported in one synchronization. Start near your expected workforce "
        "size and raise deliberately.",
        "5000",
    ),
    "KP_WORKER_SMTP_ADDRESS": (
        "The mail relay hostname followed by its port. Port 587 normally uses STARTTLS; port 465 normally uses "
        "implicit TLS.",
        "smtp.example.com:587",
    ),
    "KP_WORKER_SMTP_STARTTLS": (
        "Upgrades a normal SMTP connection to encrypted TLS. Usually true on port 587 and false when implicit "
        "TLS is enabled.",
        "true",
    ),
    "KP_WORKER_SMTP_SSL": (
        "Starts SMTP inside TLS immediately, normally on port 465. Do not enable this and STARTTLS together.",
        "false",
    ),
    "KP_WORKER_AI_API_KEY": (
        "A private credential used to authenticate to your AI gateway. It is masked, never returned, and must "
        "not be included in assistant questions.",
        "Leave blank to keep the existing key",
    ),
    "KP_WORKER_ALERT_WEBHOOK_DOMAINS": (
        "A comma-separated allowlist of hosts that may receive signed operational alerts. This prevents alerts "
        "from being sent to arbitrary destinations.",
        "hooks.example.com,events.example.net",
    ),
    "KP_WORKER_ALERT_WEBHOOK_URL": (
        "An HTTPS endpoint used only for the connection test. Webhooks are signed so the receiver can verify "
        "their origin.",
        "https://hooks.example.com/awareness-health",
    ),
}


_FIELD_LOCATIONS: dict[str, str] = {
    "OPERATOR_API_OIDC_MODE": "Use 'dev' only on this computer. For production, choose 'oidc'.",
    "OPERATOR_API_OIDC_ISSUER": (
        "Identity provider → application or tenant settings → OpenID Connect metadata → issuer."
    ),
    "OPERATOR_API_OIDC_AUDIENCE": "Identity provider → API registration → application ID URI or audience.",
    "OPERATOR_API_OIDC_CLIENT_ID": (
        "Identity provider → app registrations → your console application → client/application ID."
    ),
    "OPERATOR_API_OIDC_CLIENT_SECRET": (
        "Identity provider → console application → credentials or client secrets. Create a dedicated secret "
        "only if the provider requires a confidential client."
    ),
    "OPERATOR_API_OIDC_REDIRECT_URI": (
        "Copy the suggested console callback URL here, then register the identical value under the provider "
        "application's redirect URIs."
    ),
    "KP_WORKER_GRAPH_BASE_URL": (
        "Microsoft Graph normally uses https://graph.microsoft.com/v1.0. For a gateway, copy its documented "
        "API base URL."
    ),
    "KP_WORKER_GRAPH_BEARER_TOKEN": (
        "Identity provider → directory application → token/credential flow. Request only the read-only user "
        "permission needed by your directory policy."
    ),
    "KP_WORKER_GRAPH_API_KEY": (
        "Your API gateway → application credentials or subscriptions. Leave blank when the gateway does not "
        "require a key."
    ),
    "KP_WORKER_GRAPH_MAX_USERS": (
        "Use your HR or directory count, rounded up modestly; this is a safety ceiling, not a license limit."
    ),
    "KP_WORKER_SMTP_ADDRESS": (
        "Mail provider administration → SMTP relay or authenticated SMTP settings → server name and port."
    ),
    "KP_WORKER_SMTP_USERNAME": (
        "Mail provider → SMTP service account. This is often a mailbox address or generated account name."
    ),
    "KP_WORKER_SMTP_PASSWORD": (
        "Mail provider → SMTP service account → app password or credential. Never use a personal password."
    ),
    "KP_WORKER_SMTP_STARTTLS": "Mail provider's encryption instructions. Port 587 usually uses STARTTLS.",
    "KP_WORKER_SMTP_SSL": "Mail provider's encryption instructions. Enable for implicit TLS, usually on port 465.",
    "KP_WORKER_SMTP_SENDER": (
        "Mail provider → approved senders. Use the exact mailbox or address authorized for the relay account."
    ),
    "KP_WORKER_REPORTED_MAILBOX_URL": (
        "Reported-mail provider → API or integration settings → base URL, without a message identifier."
    ),
    "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "Reported-mail provider → API credentials → bearer/access token.",
    "KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME": "Reported-mail provider → API basic-auth credentials → username.",
    "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD": "Reported-mail provider → API basic-auth credentials → password.",
    "KP_WORKER_AI_BASE_URL": (
        "AI gateway administration → API endpoints. Enter the base before /propose or /setup-assist."
    ),
    "KP_WORKER_AI_BEARER_TOKEN": "AI gateway → service accounts or API credentials → bearer token.",
    "KP_WORKER_AI_API_KEY": "AI gateway → API keys. Create a dedicated restricted key for this platform.",
    "OPERATOR_API_TRAINING_BASE_URL": (
        "Training provider → course publication or share settings → learner landing-page URL."
    ),
    "OPERATOR_API_TRAINING_DOMAINS": (
        "Take the hostname from every approved training URL; enter hostnames only, separated by commas."
    ),
    "KP_WORKER_TRAINING_BASE_URL": "Filled automatically from the training URL when this step is saved.",
    "KP_WORKER_TRAINING_DOMAINS": "Filled automatically from the allowed training domains when this step is saved.",
    "KP_WORKER_ALERT_WEBHOOK_DOMAINS": (
        "Alert receiver URL → copy only its hostname. Add multiple approved hosts as a comma-separated list."
    ),
    "KP_WORKER_ALERT_WEBHOOK_URL": (
        "Alerting or automation provider → incoming webhook → HTTPS endpoint used for testing."
    ),
}


_FIELD_CHOICES: dict[str, tuple[dict[str, str], ...]] = {
    "OPERATOR_API_OIDC_MODE": (
        {"value": "dev", "label": "Local development login"},
        {"value": "oidc", "label": "Organization identity provider (OIDC)"},
    ),
    "KP_WORKER_SMTP_STARTTLS": (
        {"value": "", "label": "Automatic (recommended)"},
        {"value": "true", "label": "Require STARTTLS"},
        {"value": "false", "label": "Do not use STARTTLS"},
    ),
    "KP_WORKER_SMTP_SSL": (
        {"value": "false", "label": "No implicit TLS"},
        {"value": "true", "label": "Use implicit TLS"},
    ),
    "KP_WORKER_EMAIL_PROVIDER": (
        {"value": "smtp", "label": "SMTP relay"},
        {"value": "azure_communication_services", "label": "Azure Communication Services Email"},
    ),
    "KP_WORKER_REPORTED_MAILBOX_PROVIDER": (
        {"value": "mailpit", "label": "Local Mailpit (development)"},
        {"value": "microsoft365", "label": "Microsoft 365 reported mailbox"},
    ),
}


_FIELD_PROVIDER_RULES: dict[str, dict[str, tuple[str, ...]]] = {
    "KP_WORKER_SMTP_ADDRESS": {"providers": ("smtp",), "required_for": ("smtp",)},
    "KP_WORKER_SMTP_USERNAME": {"providers": ("smtp",)},
    "KP_WORKER_SMTP_PASSWORD": {"providers": ("smtp",)},
    "KP_WORKER_SMTP_STARTTLS": {"providers": ("smtp",)},
    "KP_WORKER_SMTP_SSL": {"providers": ("smtp",)},
    "KP_WORKER_SMTP_SENDER": {
        "providers": ("smtp", "azure_communication_services"),
        "required_for": ("smtp", "azure_communication_services"),
    },
    "KP_WORKER_ACS_EMAIL_ENDPOINT": {
        "providers": ("azure_communication_services",),
        "required_for": ("azure_communication_services",),
    },
    "KP_WORKER_ACS_CLIENT_ID": {"providers": ("azure_communication_services",)},
    "KP_WORKER_ACS_EMAIL_CONNECTION_STRING": {"providers": ("azure_communication_services",)},
    "KP_WORKER_ACS_SENDING_DOMAIN": {
        "providers": ("azure_communication_services",),
        "required_for": ("azure_communication_services",),
    },
    "KP_WORKER_ACS_SENDER_LOCAL_PART": {
        "providers": ("azure_communication_services",),
        "required_for": ("azure_communication_services",),
    },
    "KP_WORKER_ACS_SENDER_DISPLAY_NAME": {
        "providers": ("azure_communication_services",),
        "required_for": ("azure_communication_services",),
    },
    "KP_WORKER_REPORTED_MAILBOX_URL": {
        "providers": ("mailpit", "microsoft365"),
        "required_for": ("mailpit", "microsoft365"),
    },
    "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID": {
        "providers": ("microsoft365",),
        "required_for": ("microsoft365",),
    },
    "KP_WORKER_REPORTED_MAILBOX_ID": {
        "providers": ("microsoft365",),
        "required_for": ("microsoft365",),
    },
    "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID": {
        "providers": ("microsoft365",),
        "required_for": ("microsoft365",),
    },
    "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": {"providers": ("microsoft365",)},
}


_GLOSSARY: tuple[dict[str, str], ...] = (
    {
        "term": "OIDC",
        "meaning": "OpenID Connect: a standard that lets this console use your organization's existing "
        "sign-in service.",
    },
    {"term": "Issuer", "meaning": "The identity provider URL that signs and identifies trusted login tokens."},
    {
        "term": "Audience",
        "meaning": "The API identifier a token is intended for; it prevents a token for another service being "
        "reused here.",
    },
    {"term": "Client ID", "meaning": "A non-secret identifier assigned to an application by an identity provider."},
    {
        "term": "Microsoft Graph",
        "meaning": "Microsoft's API for directory data such as users. This platform uses a bounded, read-only "
        "users interface.",
    },
    {"term": "SMTP", "meaning": "The standard protocol used to hand campaign email to your approved mail relay."},
    {
        "term": "STARTTLS",
        "meaning": "A command that upgrades an SMTP connection to encrypted TLS, commonly on port 587.",
    },
    {
        "term": "API key",
        "meaning": "A private credential sent to a service. Treat it like a password and rotate it if exposed.",
    },
    {"term": "Webhook", "meaning": "An HTTPS endpoint that receives automatic event notifications from this platform."},
    {
        "term": "Azure subscription ID",
        "meaning": "The non-secret identifier for the Azure subscription that will own the deployment resources.",
    },
    {
        "term": "Tenant ID",
        "meaning": "The non-secret identifier for your Microsoft Entra directory; find it on the Entra overview page.",
    },
    {
        "term": "Terraform state",
        "meaning": "Terraform's record of deployed resources. Store it in the dedicated, access-controlled "
        "Azure Storage backend prepared before deployment.",
    },
    {
        "term": "Workload identity",
        "meaning": "A short-lived, federated identity used by deployment automation instead of a stored Azure "
        "client secret.",
    },
)


_TOPICS: tuple[dict[str, str], ...] = (
    {
        "id": "identity",
        "title": "Sign-in and roles",
        "summary": "Register the console and API with your identity provider, then map separate operator and "
        "approval roles.",
    },
    {
        "id": "email",
        "title": "Email delivery",
        "summary": "Use a dedicated SMTP relay account, require TLS, and authorize the configured sender address.",
    },
    {
        "id": "secrets",
        "title": "Handling credentials",
        "summary": "Enter credentials only in masked fields. Blank secret fields preserve their existing values.",
    },
    {
        "id": "testing",
        "title": "Connection tests",
        "summary": "Test each connection before completing setup. Tests use entered values transiently and do "
        "not save them.",
    },
    {
        "id": "azure-deployment",
        "title": "Azure deployment preparation",
        "summary": "Use Azure deployment to collect and validate non-secret subscription, Entra, DNS, integration, "
        "and Terraform backend values. Export them for the protected GitHub workflow; the wizard never requests "
        "Azure credentials, saves values on the server, or starts a deployment.",
    },
)


def _onboarding_state(path: Path) -> dict[str, Any]:
    values = _env_values(path)
    effective_values = dict(values)
    for preferred, fallback in {
        "KP_WORKER_GRAPH_BASE_URL": "MOCK_GRAPH_URL",
        "KP_WORKER_AI_BASE_URL": "MOCK_AI_URL",
        "KP_WORKER_REPORTED_MAILBOX_URL": "KP_WORKER_MAILPIT_API_URL",
        "KP_WORKER_SMTP_ADDRESS": "KP_WORKER_MAILPIT_SMTP",
    }.items():
        if not effective_values.get(preferred):
            effective_values[preferred] = effective_values.get(fallback, "")
    steps = []
    for definition in _ONBOARDING_STEPS:
        configured = _onboarding_step_configured(definition, values)
        fields = [
            {
                "key": key,
                "label": label,
                "type": input_type,
                "required": required,
                "secret": secret,
                "placeholder": _FIELD_HELP.get(key, ("", placeholder))[1],
                "help": _FIELD_HELP.get(
                    key,
                    ("Stored in the local environment; restart services after changing this value.", placeholder),
                )[0],
                "example": _FIELD_HELP.get(key, ("", placeholder))[1],
                "where_to_find": _FIELD_LOCATIONS.get(
                    key, "See the provider's administration or integration documentation."
                ),
                "choices": list(_FIELD_CHOICES.get(key, ())),
                "providers": list(_FIELD_PROVIDER_RULES.get(key, {}).get("providers", ())),
                "required_for": list(_FIELD_PROVIDER_RULES.get(key, {}).get("required_for", ())),
                "value": "" if secret else effective_values.get(key, ""),
            }
            for key, label, input_type, required, secret, placeholder in definition["fields"]
        ]
        steps.append(
            {
                "id": definition["id"],
                "component": definition["id"],
                "provider_key": definition.get("provider_key"),
                "title": definition["title"],
                "description": definition["description"],
                "optional": definition["optional"],
                "estimated_minutes": definition["estimated_minutes"],
                "prerequisites": list(definition["prerequisites"]),
                "configured": configured,
                "ready": configured,
                "fields": fields,
            }
        )
    complete = values.get("OPERATOR_API_ONBOARDING_COMPLETED", "").lower() == "true"
    return {
        "complete": complete,
        "completed": complete,
        "steps": steps,
    }


@router.get("/onboarding", response_model=dict[str, Any])
def get_onboarding(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """Return wizard metadata, non-secret values, and readiness flags."""
    return _onboarding_state(_env_path(request))


@router.get("/help", response_model=dict[str, Any])
def get_console_help(
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    """Return curated setup help without exposing environment configuration."""
    return {
        "glossary": list(_GLOSSARY),
        "topics": list(_TOPICS),
        "safety_note": "Never paste passwords, tokens, API keys, or client secrets into the setup assistant.",
    }


_AZURE_ASSIST_PROTECTED_KEYS = frozenset(
    {
        "environment",
        "deployment_stage",
        "network_mode",
        "subscription_id",
        "entra_tenant_id",
        "entra_client_id",
        "azure_deployment_client_id",
        "tf_state_resource_group",
        "tf_state_storage_account",
        "tf_state_container",
        "runner_label",
        "acs_resource_mode",
        "acs_existing_communication_service_id",
        "acs_existing_email_endpoint",
        "acs_existing_email_domain_id",
        "acs_dns_zone_id",
    }
)


_AZURE_EMAIL_PROTECTED_AI_OUTPUT = re.compile(
    r"(?:foundation_bootstrap|foundation_finalize|\bworkloads\b|\bverified\b|verification[_ ]status|"
    r"readiness[_ ]checked|subscription[_ ]id|tenant[_ ]id|resource[_ ]id|dns[_ ]zone[_ ]id|\bauthority\b)",
    re.IGNORECASE,
)


def _component_nonsecret_keys(component: str) -> frozenset[str]:
    for definition in _ONBOARDING_STEPS:
        if definition["id"] == component:
            return frozenset(field[0] for field in definition["fields"] if not field[4])
    for definition in _AZURE_DEPLOYMENT_STEPS:
        if definition["id"] == component:
            return frozenset(field[0] for field in definition["fields"]) - _AZURE_ASSIST_PROTECTED_KEYS
    return frozenset()


_CREDENTIAL_KEY = re.compile(r"(?:password|secret|token|api[_-]?key|credential|authorization)", re.IGNORECASE)
_CREDENTIAL_VALUE = re.compile(
    r"(?:bearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:password|secret|token|api[_-]?key)\s*[:=]\s*\S+|"
    r"sk-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
    re.IGNORECASE,
)
_MAX_SETUP_ASSIST_RESPONSE_BYTES = 32 * 1024
_MAX_SETUP_ASSIST_SUGGESTIONS = 32
_MAX_SETUP_ASSIST_WARNINGS = 5
_MAX_SETUP_ASSIST_WARNING_LENGTH = 500


def _assist_secret_values(values: dict[str, str], environment: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value
                for key, value in {**environment, **values}.items()
                if value and (_CREDENTIAL_KEY.search(key) or key in _SECRET_KEYS) and len(value) >= 4
            },
            key=len,
            reverse=True,
        )
    )


def _redact_assist_text(value: str, secret_values: tuple[str, ...]) -> str:
    result = _CREDENTIAL_VALUE.sub("[credential removed]", value)
    for secret in secret_values:
        result = result.replace(secret, "[credential removed]")
    return result


def _safe_assist_question(question: str, values: dict[str, str], environment: dict[str, str]) -> str:
    return _redact_assist_text(question.strip(), _assist_secret_values(values, environment))


def _curated_assistance(component: str) -> str:
    guidance = {
        "identity": (
            "Start with your identity provider's application registration page. Register the exact redirect URI, "
            "identify the issuer and API audience, and use separate people for campaign creation and approval."
        ),
        "graph": (
            "Use a read-only directory application with permission to list users. Set a conservative import "
            "limit, test the /users connection, and review the first synchronization before scheduling it."
        ),
        "smtp": (
            "Ask your mail administrator for the relay host, port, service account, TLS mode, and approved "
            "sender. Port 587 normally uses STARTTLS; port 465 normally uses implicit TLS."
        ),
        "mailbox": (
            "Provide the reporting API base URL and the least-privileged credential able to read reported "
            "messages. Test access before enabling polling."
        ),
        "ai": (
            "Connect a compatible /propose gateway. AI output remains advisory and is still checked by "
            "deterministic safety rules before use."
        ),
        "azure_foundation": (
            "Open Azure portal → Subscriptions to copy the subscription ID, then confirm the approved Azure "
            "region with your cloud governance team. Start with staging and use a short lowercase prefix."
        ),
        "azure_identity_dns": (
            "Find the tenant ID under Microsoft Entra ID → Overview and the client ID under App registrations. "
            "Ask the DNS administrator for separate operator and tracking hostnames; never paste a client secret."
        ),
        "azure_email": (
            "Use a dedicated customer-managed simulation domain and a recognizable sender. Start with conservative "
            "daily, per-minute, and batch limits. The protected workflow—not AI or an operator checkbox—reads live "
            "Domain, SPF, DKIM, DKIM2, association, and sender state from Azure before advancing."
        ),
        "azure_integrations": (
            "Choose the ACS data geography required by policy. An AI value must be an approved Azure-hosted "
            "gateway exposing /propose and /setup-assist, not a raw model endpoint. Use hostnames only for alerts."
        ),
        "azure_automation": (
            "Use a dedicated private Storage container for Terraform state and a self-hosted GitHub runner with "
            "the azure-vnet label. Configure deployment identity through OIDC; do not create a CI client secret."
        ),
        "training": (
            "Choose the exact HTTPS training destination and allowlist only domains your organization controls "
            "or has approved."
        ),
        "webhook": (
            "The allowed webhook domain is the hostname of an approved HTTPS application that receives signed "
            "operational alerts. It is not an email destination and does not require an MTA or mail relay. "
            "Test reachability and configure the receiver to verify the platform's HMAC signature."
        ),
    }
    return guidance.get(component, "Choose a setup component and use its field help and connection test before saving.")


async def _bounded_setup_assist_json(response: httpx.Response) -> Any:
    content_lengths = response.headers.get_list("content-length")
    if len(content_lengths) > 1:
        raise ValueError("invalid setup assistant response length")
    if content_lengths:
        declared = content_lengths[0]
        if len(declared) > 10 or re.fullmatch(r"[0-9]+", declared) is None:
            raise ValueError("invalid setup assistant response length")
        if int(declared) > _MAX_SETUP_ASSIST_RESPONSE_BYTES:
            raise ValueError("setup assistant response is too large")

    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > _MAX_SETUP_ASSIST_RESPONSE_BYTES:
            raise ValueError("setup assistant response is too large")
        body.extend(chunk)
    try:
        text = bytes(body).decode("utf-8")
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid setup assistant JSON") from None


def _validated_ai_assistance(
    payload: Any,
    allowed_keys: frozenset[str],
    *,
    secret_values: tuple[str, ...] = (),
) -> tuple[str, dict[str, str], list[str]]:
    if (
        not isinstance(payload, dict)
        or set(payload) - {"answer", "suggestions", "warnings"}
        or not isinstance(payload.get("answer"), str)
    ):
        raise ValueError("invalid setup assistant response")
    raw_answer = payload["answer"].strip()
    if not raw_answer or len(raw_answer) > 4000:
        raise ValueError("invalid setup assistant answer")
    answer = _redact_assist_text(raw_answer, secret_values)
    raw_suggestions = payload.get("suggestions", {})
    if not isinstance(raw_suggestions, dict) or len(raw_suggestions) > _MAX_SETUP_ASSIST_SUGGESTIONS:
        raise ValueError("invalid setup assistant suggestions")
    suggestions: dict[str, str] = {}
    warnings: list[str] = []
    for key, value in raw_suggestions.items():
        if key not in allowed_keys or _CREDENTIAL_KEY.search(str(key)):
            warning = "The AI returned a suggestion outside this setup step; it was ignored."
            if warning not in warnings:
                warnings.append(warning)
            continue
        if not isinstance(value, str) or len(value) > 2048 or _redact_assist_text(value, secret_values) != value:
            if len(warnings) < _MAX_SETUP_ASSIST_WARNINGS:
                warnings.append(f"An unsafe suggestion for {key} was ignored.")
            continue
        suggestions[key] = value
    raw_warnings = payload.get("warnings", [])
    if (
        not isinstance(raw_warnings, list)
        or len(raw_warnings) > _MAX_SETUP_ASSIST_WARNINGS
        or any(not isinstance(item, str) or len(item) > _MAX_SETUP_ASSIST_WARNING_LENGTH for item in raw_warnings)
    ):
        raise ValueError("invalid setup assistant warnings")
    for item in raw_warnings:
        redacted = _redact_assist_text(item, secret_values)
        if redacted not in warnings and len(warnings) < _MAX_SETUP_ASSIST_WARNINGS:
            warnings.append(redacted)
    return answer, suggestions, warnings[:_MAX_SETUP_ASSIST_WARNINGS]


@router.post("/onboarding/assist", response_model=SetupAssistResponse)
async def assist_onboarding(
    body: SetupAssistRequest,
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> SetupAssistResponse:
    """Provide advisory setup guidance without persisting or auditing prompt content."""
    _reject_if_managed(request, MANAGED_CONFIG_MESSAGE)
    component = body.component.lower()
    allowed_keys = _component_nonsecret_keys(component)
    if not allowed_keys:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unsupported component")
    azure_assist_keys = {field[0] for step in _AZURE_DEPLOYMENT_STEPS for field in step["fields"]}
    forbidden = set(body.values) - (_ALLOWED_KEYS | azure_assist_keys)
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")
    environment = _env_values(_env_path(request))
    safe_values = {
        key: value
        for key, value in body.values.items()
        if key in allowed_keys
        and not _CREDENTIAL_KEY.search(key)
        and len(value) <= 2048
        and not _CREDENTIAL_VALUE.search(value)
        and not (urlparse(value).username or urlparse(value).password)
    }
    safe_question = _safe_assist_question(body.question, body.values, environment)
    destination_key, base_url = _selected_destination(environment, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL")
    warnings = ["AI suggestions are advisory. Review them and run the connection test before saving."]
    if base_url:
        try:
            endpoint = await asyncio.to_thread(
                _resolve_setup_assist_endpoint,
                base_url,
                settings=request.app.state.settings,
                destination_key=destination_key,
            )
            headers = {**_auth_headers(environment, "KP_WORKER_AI"), "Host": endpoint.host_header}
            async with (
                httpx.AsyncClient(
                    timeout=5.0,
                    follow_redirects=False,
                    trust_env=False,
                    http2=False,
                ) as client,
                client.stream(
                    "POST",
                    endpoint.request_url,
                    headers=headers,
                    json={"component": component, "question": safe_question, "values": safe_values},
                    extensions=endpoint.extensions,
                ) as response,
            ):
                if response.is_redirect:
                    raise ValueError("setup assistant redirected")
                response.raise_for_status()
                payload = await _bounded_setup_assist_json(response)
            answer, suggestions, provider_warnings = _validated_ai_assistance(
                payload,
                allowed_keys,
                secret_values=_assist_secret_values(body.values, environment),
            )
            if component == "azure_email" and any(
                _AZURE_EMAIL_PROTECTED_AI_OUTPUT.search(value)
                for value in (answer, *provider_warnings, *suggestions.values())
            ):
                raise ValueError("AI attempted to influence protected Azure deployment state")
            return SetupAssistResponse(
                answer=answer,
                suggestions=suggestions,
                source="configured-ai",
                warnings=warnings + provider_warnings,
            )
        except (httpx.HTTPError, OSError, ValueError):
            warnings.append(
                "The configured AI service was unavailable or returned an invalid response; local guidance is "
                "shown instead."
            )
    else:
        warnings.append("No AI setup service is configured; local guidance is shown instead.")
    return SetupAssistResponse(
        answer=_curated_assistance(component), suggestions={}, source="curated", warnings=warnings
    )


def _persist_onboarding(body: OnboardingPatch, request: Request, principal: Principal) -> list[str]:
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")
    desired = dict(body.values)
    # Training configuration is consumed by both the operator safety gate and
    # workers. Mirror it here so the wizard cannot leave the two processes on
    # inconsistent allowlists or destinations.
    mirrors = {
        "OPERATOR_API_TRAINING_BASE_URL": "KP_WORKER_TRAINING_BASE_URL",
        "OPERATOR_API_TRAINING_DOMAINS": "KP_WORKER_TRAINING_DOMAINS",
    }
    for source, target in mirrors.items():
        if source in desired and target not in desired:
            desired[target] = desired[source]
    if body.completed is not None:
        desired["OPERATOR_API_ONBOARDING_COMPLETED"] = str(body.completed).lower()

    def validate(proposed: dict[str, str]) -> None:
        _validate_config_candidate(proposed, require_complete=body.completed is True)

    try:
        changed = _atomic_update_env(_env_path(request), desired, validate_candidate=validate)
    except _AtomicEnvUpdateError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from None
    request.app.state.audit_store.record(
        actor=principal.principal_id,
        action="console.onboarding.update",
        object_type="system",
        object_id=".env",
        detail={"changed": changed},
    )
    return changed


@router.put("/onboarding", response_model=dict[str, Any])
def put_onboarding(
    body: OnboardingPatch,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    _reject_if_managed(request, MANAGED_CONFIG_MESSAGE)
    changed = _persist_onboarding(body, request, principal)
    return {"ok": True, "changed": changed, **_onboarding_state(_env_path(request))}


@router.post("/onboarding/test", response_model=dict[str, Any])
def test_onboarding_connection(
    body: ConnectionTest,
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    if request.app.state.settings.config_is_managed:
        raise ConflictError(
            "connection tests based on a local env file are disabled for managed deployments. "
            "Use the Azure deployment workflow's validation results; this endpoint cannot safely read "
            "Key Vault-backed values."
        )
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")
    saved = _env_values(_env_path(request))
    values = {**saved, **body.values}
    settings = request.app.state.settings
    component = body.component.lower()
    scope = "connection"
    if component in {"identity", "oidc"}:
        scope = "oidc_discovery"
        destination_key = "OPERATOR_API_OIDC_ISSUER"
        base = values.get(destination_key, "")
        endpoint = base.rstrip("/") + "/.well-known/openid-configuration"
        ok, kind = _probe_http(
            endpoint,
            allow_loopback=_allow_development_loopback(settings, destination_key, base),
        )
    elif component == "graph":
        scope = "directory_read"
        destination_key, base = _selected_destination(values, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL")
        _saved_key, saved_base = _selected_destination(saved, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL")
        credentials = _credentials_for_destination(body.values, values, destination_changed=base != saved_base)
        ok, kind = _probe_http(
            base.rstrip("/") + "/users",
            headers=_auth_headers(credentials, "KP_WORKER_GRAPH"),
            allow_loopback=_allow_development_loopback(settings, destination_key, base),
        )
    elif component == "ai":
        scope = "ai_endpoint_reachability"
        destination_key, base = _selected_destination(values, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL")
        _saved_key, saved_base = _selected_destination(saved, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL")
        credentials = _credentials_for_destination(body.values, values, destination_changed=base != saved_base)
        ok, kind = _probe_http(
            base.rstrip("/") + "/propose",
            headers=_auth_headers(credentials, "KP_WORKER_AI"),
            reachable_only=True,
            allow_loopback=_allow_development_loopback(settings, destination_key, base),
        )
    elif component == "mailbox":
        provider = values.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "mailpit").strip() or "mailpit"
        if provider not in {"mailpit", "microsoft365"}:
            return _connection_test_result(
                component,
                ok=False,
                error_kind="config",
                verification_scope="reported_mailbox",
                message="Choose Mailpit or Microsoft 365 before testing the reported mailbox.",
            )
        destination_key, base = _selected_destination(
            values, "KP_WORKER_REPORTED_MAILBOX_URL", "KP_WORKER_MAILPIT_API_URL"
        )
        _saved_key, saved_base = _selected_destination(
            saved, "KP_WORKER_REPORTED_MAILBOX_URL", "KP_WORKER_MAILPIT_API_URL"
        )
        saved_provider = saved.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "mailpit").strip() or "mailpit"
        credentials = _credentials_for_destination(
            body.values,
            values,
            destination_changed=base != saved_base or provider != saved_provider,
        )
        if provider == "mailpit":
            scope = "mailpit_mailbox_read"
            headers = _auth_headers(credentials, "KP_WORKER_REPORTED_MAILBOX")
            basic_username = credentials.get("KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME", "")
            basic_password = credentials.get("KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD", "")
            if basic_username and basic_password:
                token = base64.b64encode(f"{basic_username}:{basic_password}".encode()).decode()
                headers["Authorization"] = f"Basic {token}"
            ok, kind = _probe_http(
                base.rstrip("/") + "/api/v1/messages",
                headers=headers,
                allow_loopback=_allow_development_loopback(settings, destination_key, base),
            )
        else:
            try:
                endpoint = _microsoft365_probe_url(
                    base,
                    values.get("KP_WORKER_REPORTED_MAILBOX_ID", ""),
                    values.get("KP_WORKER_REPORTED_MAILBOX_FOLDER_ID", ""),
                )
            except ValueError:
                return _connection_test_result(
                    component,
                    ok=False,
                    error_kind="config",
                    verification_scope="microsoft365_mailbox_read",
                )
            headers = _auth_headers(credentials, "KP_WORKER_REPORTED_MAILBOX")
            if headers.get("Authorization"):
                scope = "microsoft365_mailbox_read"
                ok, kind = _probe_http(endpoint, headers=headers, require_2xx=True)
            else:
                scope = "microsoft365_endpoint_reachability"
                ok, kind = _probe_http(
                    endpoint,
                    reachable_only=True,
                    accept_auth_challenge=True,
                )
                if ok:
                    return _connection_test_result(
                        component,
                        ok=False,
                        error_kind=None,
                        verification_scope=scope,
                        reachable_unverified=True,
                        message=(
                            "Microsoft Graph is reachable. The dedicated managed identity, Exchange Application "
                            "RBAC, and mailbox read remain unverified; run the bounded reported-mailbox poll after "
                            "deployment."
                        ),
                    )
    elif component == "training":
        scope = "training_page"
        destination_key = "OPERATOR_API_TRAINING_BASE_URL"
        base = values.get(destination_key, "")
        ok, kind = _probe_http(
            base,
            allow_loopback=_allow_development_loopback(settings, destination_key, base),
        )
    elif component == "smtp":
        provider = values.get("KP_WORKER_EMAIL_PROVIDER", "smtp").strip() or "smtp"
        if provider == "azure_communication_services":
            scope = "acs_endpoint_reachability"
            endpoint = values.get("KP_WORKER_ACS_EMAIL_ENDPOINT", "")
            try:
                endpoint = _validated_acs_endpoint(endpoint)
            except ValueError:
                return _connection_test_result(
                    component,
                    ok=False,
                    error_kind="config",
                    verification_scope=scope,
                )
            ok, kind = _probe_http(
                endpoint,
                reachable_only=True,
                accept_auth_challenge=True,
            )
            if ok:
                return _connection_test_result(
                    component,
                    ok=False,
                    error_kind=None,
                    verification_scope=scope,
                    reachable_unverified=True,
                    message=(
                        "The ACS endpoint is reachable. No message or credential was sent; managed-identity access, "
                        "custom-domain readiness, delivery, and inbox placement remain unverified."
                    ),
                )
        elif provider == "smtp":
            scope = "smtp_session"
            destination_key, address = _selected_destination(values, "KP_WORKER_SMTP_ADDRESS", "KP_WORKER_MAILPIT_SMTP")
            _saved_key, saved_address = _selected_destination(saved, "KP_WORKER_SMTP_ADDRESS", "KP_WORKER_MAILPIT_SMTP")
            credentials = _credentials_for_destination(
                body.values, values, destination_changed=address != saved_address
            )
            ok, kind = _probe_smtp(
                address,
                values.get("KP_WORKER_SMTP_STARTTLS", "false").lower() == "true",
                use_ssl=values.get("KP_WORKER_SMTP_SSL", "false").lower() == "true",
                username=credentials.get("KP_WORKER_SMTP_USERNAME") or None,
                password=credentials.get("KP_WORKER_SMTP_PASSWORD") or None,
                allow_loopback=_allow_development_loopback(settings, destination_key, address, smtp=True),
            )
        else:
            return _connection_test_result(
                component,
                ok=False,
                error_kind="config",
                verification_scope="email_provider",
                message="Choose SMTP or Azure Communication Services before testing email delivery.",
            )
    elif component == "webhook":
        scope = "webhook_tls"
        ok, kind = _probe_webhook(values.get("KP_WORKER_ALERT_WEBHOOK_URL", ""))
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unsupported component")
    return _connection_test_result(
        component,
        ok=ok,
        error_kind=kind,
        verification_scope=scope,
    )
