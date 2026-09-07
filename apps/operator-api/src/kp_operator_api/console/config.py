"""Console configuration surface: request models, step schema, and validation.

Moved verbatim out of ``kp_operator_api.console`` during the ARC-002 Item 2
split. This module holds the declarative description of every console-managed
configuration key (``_ONBOARDING_STEPS``) together with the cross-field
candidate validation that guards every write, plus the two ``/config`` routes.
The onboarding wizard imports these definitions; nothing here imports the
wizard, which keeps the console package's imports acyclic and the validator
defined exactly once.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_telemetry.errors import PermissionDeniedError
from pydantic import BaseModel, Field

from kp_operator_api.auth import require_capability
from kp_operator_api.connection_probes import (
    _microsoft365_probe_url,
    _parse_smtp_address,
    _safe_url,
    _validated_acs_endpoint,
)
from kp_operator_api.console.console_auth import _validated_oidc_redirect_uri
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


class ConfigPatch(BaseModel):
    values: dict[str, str] = Field(default_factory=dict)

    # Keys the console may mutate. Anything not listed is rejected so a
    # compromised console token cannot rewrite arbitrary files.


class ConfigResponse(BaseModel):
    values: dict[str, str]
    masked: dict[str, bool]
    config_store: str = "env_file"
    mutable: bool = True


_ONBOARDING_STEPS: tuple[dict[str, Any], ...] = (
    {
        "id": "identity",
        "title": "Identity provider",
        "description": (
            "Use local development login or connect an OpenID Connect provider with separate operator roles."
        ),
        "optional": False,
        "estimated_minutes": 8,
        "prerequisites": (
            "Identity-provider administrator access",
            "Permission to register a browser application and API",
            "The public HTTPS address operators will use for this console",
        ),
        "configured_any": (("OPERATOR_API_OIDC_MODE",),),
        "fields": (
            ("OPERATOR_API_OIDC_MODE", "Authentication mode", "text", True, False, "dev or oidc"),
            ("OPERATOR_API_OIDC_ISSUER", "OIDC issuer URL", "url", False, False, "https://id.example/tenant"),
            ("OPERATOR_API_OIDC_AUDIENCE", "API audience", "text", False, False, "kp-operator-api"),
            ("OPERATOR_API_OIDC_CLIENT_ID", "Console client ID", "text", False, False, "kp-operator-console"),
            (
                "OPERATOR_API_OIDC_CLIENT_SECRET",
                "Client secret",
                "password",
                False,
                True,
                "optional for public clients",
            ),
            (
                "OPERATOR_API_OIDC_REDIRECT_URI",
                "Redirect URI",
                "url",
                False,
                False,
                "https://console.example/api/v1/console/oidc/callback",
            ),
        ),
    },
    {
        "id": "graph",
        "title": "Employee directory",
        "description": ("Use a dedicated managed identity to synchronize only selected Microsoft Entra groups."),
        "optional": True,
        "estimated_minutes": 5,
        "prerequisites": (
            "A dedicated directory managed identity",
            "Tenant-admin consent for GroupMember.Read.All and User.ReadBasic.All",
            "One or more selected Entra group object IDs",
            "An expected upper bound for employee records",
        ),
        "configured_any": (("KP_WORKER_GRAPH_BASE_URL",), ("MOCK_GRAPH_URL",)),
        "fields": (
            ("KP_WORKER_GRAPH_BASE_URL", "Graph base URL", "url", True, False, "https://graph.microsoft.com/v1.0"),
            ("KP_WORKER_MICROSOFT_TENANT_ID", "Microsoft tenant ID", "text", True, False, "tenant UUID"),
            ("KP_WORKER_GRAPH_CLIENT_ID", "Directory identity client ID", "text", True, False, "identity UUID"),
            ("KP_WORKER_GRAPH_GROUP_IDS", "Selected group object IDs", "text", True, False, "UUIDs, comma-separated"),
            ("KP_WORKER_GRAPH_MAX_USERS", "Maximum users", "number", False, False, "1000"),
        ),
    },
    {
        "id": "smtp",
        "provider_key": "KP_WORKER_EMAIL_PROVIDER",
        "title": "Email delivery",
        "description": (
            "Choose SMTP or ACS. Managed ACS requires a verified customer domain and current readiness evidence."
        ),
        "optional": False,
        "estimated_minutes": 5,
        "prerequisites": (
            "An approved SMTP relay or service account",
            "The sender mailbox authorized by that relay",
            "The relay's TLS requirement and port",
        ),
        "configured_any": (("KP_WORKER_SMTP_ADDRESS",), ("KP_WORKER_MAILPIT_SMTP",), ("KP_WORKER_ACS_EMAIL_ENDPOINT",)),
        "fields": (
            ("KP_WORKER_EMAIL_PROVIDER", "Email provider", "text", True, False, "Choose a provider"),
            ("KP_WORKER_SMTP_ADDRESS", "SMTP host and port", "text", True, False, "smtp.example.com:587"),
            ("KP_WORKER_SMTP_USERNAME", "SMTP username", "text", False, False, "service account"),
            ("KP_WORKER_SMTP_PASSWORD", "SMTP password", "password", False, True, "leave blank to keep existing"),
            ("KP_WORKER_SMTP_STARTTLS", "Use STARTTLS", "text", False, False, "true or false"),
            ("KP_WORKER_SMTP_SSL", "Use implicit TLS", "text", False, False, "true or false"),
            ("KP_WORKER_SMTP_SENDER", "Sender mailbox", "email", False, False, "awareness@example.com"),
            (
                "KP_WORKER_ACS_EMAIL_ENDPOINT",
                "ACS endpoint",
                "url",
                False,
                False,
                "https://name.communication.azure.com",
            ),
            (
                "KP_WORKER_ACS_CLIENT_ID",
                "ACS sending identity client ID",
                "text",
                False,
                False,
                "identity UUID",
            ),
            (
                "KP_WORKER_ACS_EMAIL_CONNECTION_STRING",
                "ACS connection string",
                "password",
                False,
                True,
                "local use only",
            ),
            ("KP_WORKER_ACS_SENDING_DOMAIN", "ACS customer domain", "text", False, False, "mail.example.com"),
            ("KP_WORKER_ACS_SENDER_LOCAL_PART", "ACS sender local part", "text", False, False, "awareness"),
            (
                "KP_WORKER_ACS_SENDER_DISPLAY_NAME",
                "ACS sender display name",
                "text",
                False,
                False,
                "Security Awareness",
            ),
        ),
    },
    {
        "id": "mailbox",
        "provider_key": "KP_WORKER_REPORTED_MAILBOX_PROVIDER",
        "title": "Reported-message mailbox",
        "description": "Poll one Microsoft 365 report mailbox using a separate mailbox-scoped managed identity.",
        "optional": True,
        "estimated_minutes": 4,
        "prerequisites": (
            "A dedicated report mailbox",
            "A dedicated mailbox managed identity",
            "Exchange Online Application RBAC scoped to only that mailbox",
        ),
        "configured_any": (("KP_WORKER_REPORTED_MAILBOX_URL",), ("KP_WORKER_MAILPIT_API_URL",)),
        "fields": (
            ("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "Mailbox provider", "text", True, False, "Choose a provider"),
            (
                "KP_WORKER_REPORTED_MAILBOX_URL",
                "Mailbox API base URL",
                "url",
                True,
                False,
                "https://graph.microsoft.com/v1.0",
            ),
            (
                "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID",
                "Mailbox identity client ID",
                "text",
                True,
                False,
                "identity UUID",
            ),
            ("KP_WORKER_REPORTED_MAILBOX_ID", "Report mailbox", "email", True, False, "phish-reports@example.com"),
            ("KP_WORKER_REPORTED_MAILBOX_FOLDER_ID", "Mailbox folder", "text", False, False, "inbox"),
            (
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN",
                "Development bearer token",
                "password",
                False,
                True,
                "optional local test credential",
            ),
        ),
    },
    {
        "id": "ai",
        "title": "Content-generation service",
        "description": (
            "Connect a compatible /propose service. Deterministic safety validation remains mandatory after generation."
        ),
        "optional": True,
        "estimated_minutes": 4,
        "prerequisites": (
            "A compatible service exposing /propose and /setup-assist",
            "A dedicated, least-privilege credential if authentication is required",
        ),
        "configured_any": (("KP_WORKER_AI_BASE_URL",), ("MOCK_AI_URL",)),
        "fields": (
            ("KP_WORKER_AI_BASE_URL", "AI service base URL", "url", True, False, "https://ai-gateway.example"),
            ("KP_WORKER_AI_BEARER_TOKEN", "Bearer token", "password", False, True, "optional"),
            ("KP_WORKER_AI_API_KEY", "API key", "password", False, True, "optional"),
        ),
    },
    {
        "id": "training",
        "title": "Training experience",
        "description": "Set the recipient training destination and the exact domains allowed in campaign content.",
        "optional": False,
        "estimated_minutes": 3,
        "prerequisites": (
            "The exact training landing-page URL",
            "Every domain that may host approved training content",
        ),
        "configured_any": (("OPERATOR_API_TRAINING_BASE_URL", "OPERATOR_API_TRAINING_DOMAINS"),),
        "fields": (
            (
                "OPERATOR_API_TRAINING_BASE_URL",
                "Training URL",
                "url",
                True,
                False,
                "https://training.example/awareness",
            ),
            ("OPERATOR_API_TRAINING_DOMAINS", "Allowed training domains", "text", True, False, "training.example"),
        ),
    },
    {
        "id": "webhook",
        "title": "Operational alerts",
        "description": "Allowlist HTTPS webhook hosts and test a destination without sending campaign data.",
        "optional": True,
        "estimated_minutes": 4,
        "prerequisites": (
            "An HTTPS receiver for operational alerts",
            "The receiver hostname approved for the outbound allowlist",
        ),
        "configured_any": (("KP_WORKER_ALERT_WEBHOOK_DOMAINS",),),
        "fields": (
            ("KP_WORKER_ALERT_WEBHOOK_DOMAINS", "Allowed webhook domains", "text", True, False, "hooks.example.com"),
            (
                "KP_WORKER_ALERT_WEBHOOK_URL",
                "Test webhook or ntfy topic URL",
                "url",
                False,
                False,
                "https://hooks.example.com/health",
            ),
        ),
    },
)


def _has_values(values: dict[str, str], *keys: str) -> bool:
    return all(bool(values.get(key, "").strip()) for key in keys)


def _onboarding_step_configured(definition: dict[str, Any], values: dict[str, str]) -> bool:
    step_id = definition["id"]
    if step_id == "smtp":
        provider = values.get("KP_WORKER_EMAIL_PROVIDER", "").strip()
        if provider == "smtp":
            return bool(
                (values.get("KP_WORKER_SMTP_ADDRESS") or values.get("KP_WORKER_MAILPIT_SMTP", "")).strip()
                and values.get("KP_WORKER_SMTP_SENDER", "").strip()
            )
        if provider == "azure_communication_services":
            return _has_values(
                values,
                "KP_WORKER_ACS_EMAIL_ENDPOINT",
                "KP_WORKER_ACS_SENDING_DOMAIN",
                "KP_WORKER_ACS_SENDER_LOCAL_PART",
                "KP_WORKER_ACS_SENDER_DISPLAY_NAME",
                "KP_WORKER_SMTP_SENDER",
            ) and bool(
                values.get("KP_WORKER_ACS_CLIENT_ID", "").strip()
                or values.get("KP_WORKER_ACS_EMAIL_CONNECTION_STRING", "").strip()
            )
        return False
    if step_id == "mailbox":
        provider = values.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "").strip()
        base = (values.get("KP_WORKER_REPORTED_MAILBOX_URL") or values.get("KP_WORKER_MAILPIT_API_URL", "")).strip()
        if provider == "mailpit":
            return bool(base)
        if provider == "microsoft365":
            return bool(base) and _has_values(
                values,
                "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID",
                "KP_WORKER_REPORTED_MAILBOX_ID",
                "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID",
            )
        return False
    return any(
        all(bool(values.get(key, "").strip()) for key in key_group) for key_group in definition["configured_any"]
    )


def _validate_config_candidate(proposed: dict[str, str], *, require_complete: bool = False) -> None:
    """Validate cross-field invariants against the complete post-update view."""
    if proposed.get("OPERATOR_API_OIDC_MODE", "dev") not in {"dev", "oidc"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="authentication mode must be dev or oidc",
        )
    redirect_uri = proposed.get("OPERATOR_API_OIDC_REDIRECT_URI", "")
    if redirect_uri:
        try:
            _validated_oidc_redirect_uri(redirect_uri)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    "OIDC redirect URI must use HTTPS and the exact console callback path; only the documented "
                    "http://localhost:8000 development callback is permitted"
                ),
            ) from None
    boolean_keys = ("KP_WORKER_SMTP_STARTTLS", "KP_WORKER_SMTP_SSL")
    if any(proposed.get(key, "").lower() not in {"", "true", "false"} for key in boolean_keys):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="TLS settings must be true or false",
        )
    if (
        proposed.get("KP_WORKER_SMTP_STARTTLS", "").lower() == "true"
        and proposed.get("KP_WORKER_SMTP_SSL", "").lower() == "true"
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="SMTP SSL and STARTTLS are exclusive",
        )
    email_provider = proposed.get("KP_WORKER_EMAIL_PROVIDER", "").strip()
    if email_provider and email_provider not in {"smtp", "azure_communication_services"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="email provider must be smtp or azure_communication_services",
        )
    if email_provider == "smtp":
        smtp_address = (proposed.get("KP_WORKER_SMTP_ADDRESS") or proposed.get("KP_WORKER_MAILPIT_SMTP", "")).strip()
        try:
            _parse_smtp_address(smtp_address)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="SMTP provider requires a valid relay host and port",
            ) from None
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", proposed.get("KP_WORKER_SMTP_SENDER", "").strip()):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="SMTP provider requires a valid sender mailbox",
            )
        if bool(proposed.get("KP_WORKER_SMTP_USERNAME", "").strip()) != bool(
            proposed.get("KP_WORKER_SMTP_PASSWORD", "").strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="SMTP username and password must be configured together",
            )
    elif email_provider == "azure_communication_services":
        endpoint = proposed.get("KP_WORKER_ACS_EMAIL_ENDPOINT", "")
        try:
            _validated_acs_endpoint(endpoint)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS provider requires an exact HTTPS *.communication.azure.com endpoint on port 443",
            ) from None
        if not (
            proposed.get("KP_WORKER_ACS_CLIENT_ID", "").strip()
            or proposed.get("KP_WORKER_ACS_EMAIL_CONNECTION_STRING", "").strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS provider requires a managed identity client ID or local connection string",
            )
        domain = proposed.get("KP_WORKER_ACS_SENDING_DOMAIN", "").strip().lower().rstrip(".")
        local_part = proposed.get("KP_WORKER_ACS_SENDER_LOCAL_PART", "").strip().lower()
        sender = proposed.get("KP_WORKER_SMTP_SENDER", "").strip().lower()
        display_name = proposed.get("KP_WORKER_ACS_SENDER_DISPLAY_NAME", "").strip()
        if (
            re.fullmatch(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain) is None
            or domain == "azurecomm.net"
            or domain.endswith(".azurecomm.net")
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS provider requires a customer-managed public sending domain",
            )
        if re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local_part) is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS provider sender local part is malformed",
            )
        if sender != f"{local_part}@{domain}":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS sender mailbox must match its local part and sending domain",
            )
        if not display_name or len(display_name) > 64 or any(ord(character) < 32 for character in display_name):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS sender display name must be 1-64 printable characters",
            )
    mailbox_provider = proposed.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "").strip()
    if mailbox_provider and mailbox_provider not in {"mailpit", "microsoft365"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="reported mailbox provider must be mailpit or microsoft365",
        )
    if mailbox_provider:
        mailbox_base = (
            proposed.get("KP_WORKER_REPORTED_MAILBOX_URL") or proposed.get("KP_WORKER_MAILPIT_API_URL", "")
        ).strip()
        try:
            _safe_url(mailbox_base, https_only=mailbox_provider == "microsoft365")
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="reported mailbox provider requires a valid base URL",
            ) from None
        if mailbox_provider == "microsoft365":
            try:
                _microsoft365_probe_url(
                    mailbox_base,
                    proposed.get("KP_WORKER_REPORTED_MAILBOX_ID", ""),
                    proposed.get("KP_WORKER_REPORTED_MAILBOX_FOLDER_ID", ""),
                )
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Microsoft 365 provider requires a valid mailbox and folder",
                ) from None
            client_id = proposed.get("KP_WORKER_REPORTED_MAILBOX_CLIENT_ID", "").strip()
            if (
                re.fullmatch(
                    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                    client_id,
                )
                is None
            ):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Microsoft 365 provider requires the mailbox managed identity client ID",
                )
    if require_complete:
        missing = [
            definition["title"]
            for definition in _ONBOARDING_STEPS
            if not definition["optional"] and not _onboarding_step_configured(definition, proposed)
        ]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"required setup steps are incomplete: {', '.join(missing)}",
            )


@router.get("/config", response_model=ConfigResponse)
def get_config(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> ConfigResponse:
    settings = request.app.state.settings
    # An env file inside a managed container is neither the source of truth nor
    # durable. Do not present its incidental contents as current Azure
    # configuration. The UI can use ``mutable`` to render this view read-only.
    values = {} if settings.config_is_managed else _env_values(_env_path(request))
    masked: dict[str, bool] = {}
    display: dict[str, str] = {}
    for key in _ALLOWED_KEYS:
        raw = values.get(key, "")
        # Secrets are never returned — not even masked — so the GUI cannot
        # round-trip a masked placeholder back into .env (CRIT-01).
        display[key] = "" if key in _SECRET_KEYS else raw
        masked[key] = key in _SECRET_KEYS
    return ConfigResponse(
        values=display,
        masked=masked,
        config_store=settings.config_store,
        mutable=not settings.config_is_managed,
    )


@router.put("/config", response_model=dict[str, Any])
def put_config(
    body: ConfigPatch,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    _reject_if_managed(request, MANAGED_CONFIG_MESSAGE)
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")

    try:
        changed = _atomic_update_env(
            _env_path(request),
            body.values,
            validate_candidate=_validate_config_candidate,
        )
    except _AtomicEnvUpdateError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from None

    audit = request.app.state.audit_store
    audit.record(
        actor=principal.principal_id,
        action="console.config.update",
        object_type="system",
        object_id=".env",
        detail={"changed": changed},
    )
    return {"ok": True, "changed": changed}
