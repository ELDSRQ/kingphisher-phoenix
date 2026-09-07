"""Azure deployment wizard: schema, validation, and orchestration routes.

Moved verbatim out of ``kp_operator_api.console`` during the ARC-002 Item 2
split; this is the surface ARC-002 Item 1 quarantines behind
``deploy_connector_enabled``. Every route here keeps its
``_require_deploy_connector_enabled`` dependency, which carries no
``Capability`` so the route-authorization inventory still reads ``manage:roles``
for all eight endpoints.
"""

from __future__ import annotations

import re
from typing import Any, cast
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_telemetry.errors import ConflictError, PermissionDeniedError
from pydantic import BaseModel, Field

from kp_operator_api.auth import require_capability
from kp_operator_api.connection_probes import (
    _explicit_loopback_host,
    _validated_acs_endpoint,
)
from kp_operator_api.deployment_orchestration import (
    DeploymentConflict,
    DeploymentOrchestrator,
    DeploymentUnavailable,
    public_deployment_error,
)

router = APIRouter(prefix="/api/v1/console", tags=["console"])


def _require_deploy_connector_enabled(request: Request) -> None:
    """Gate the in-operator-API Azure deploy connector on ``deploy_connector_enabled``.

    ARC-002 Item 1 Phase 1. When the flag is on (the default) this is a no-op and
    the Azure deployment routes behave byte-identically to before the flag
    existed. When an operator opts a local-only install out by turning it off,
    the whole Azure-deploy route surface responds 404 as if it were not mounted,
    so a two-operator local install never sees it. The routes stay registered
    (the OpenAPI/route inventory is unchanged) so flipping the flag back on fully
    restores the connector with no redeploy of the surface itself.
    """
    if not request.app.state.settings.deploy_connector_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="the Azure deployment connector is disabled on this deployment",
        )


class AzureDeploymentValidationRequest(BaseModel):
    values: dict[str, str] = Field(default_factory=dict)


class AzureDeploymentConfirmationRequest(BaseModel):
    confirm: bool
    review_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rationale: str = Field(min_length=10, max_length=500)


class AzureDeploymentAdvanceRequest(BaseModel):
    confirm: bool
    review_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def _azure_release_readiness() -> dict[str, Any]:
    """Return immutable implementation truth, never operator attestation."""
    return {
        "evidence_level": "local_contract_only",
        "production_plan_allowed": False,
        "staging_plan_allowed": True,
        "summary": (
            "Application controls are locally testable, but production edge and recovery readiness has not "
            "been proven in Azure."
        ),
        "gates": [
            {
                "id": "operator_hsts_application",
                "label": "Operator HSTS application contract",
                "status": "implemented_unproven_at_edge",
                "detail": "Every operator response emits HSTS; browser-to-edge delivery has not been observed live.",
            },
            {
                "id": "operator_custom_domain",
                "label": "Operator custom-domain binding",
                "status": "external_unverified",
                "detail": "The selected hostname is configuration only; no live Azure binding is inspected here.",
            },
            {
                "id": "tracking_custom_domain",
                "label": "Tracking custom-domain binding",
                "status": "external_unverified",
                "detail": "The selected hostname is configuration only; no live Azure binding is inspected here.",
            },
            {
                "id": "managed_certificates",
                "label": "Custom-domain certificates",
                "status": "external_unverified",
                "detail": "Certificate issuance, hostname coverage, expiry, and renewal are not inspected here.",
            },
            {
                "id": "default_host_restriction",
                "label": "Default Container Apps host restriction",
                "status": "not_implemented",
                "detail": "Direct default-host access is not restricted by the current infrastructure.",
            },
            {
                "id": "waf_edge",
                "label": "WAF and edge policy",
                "status": "not_implemented",
                "detail": "No Azure edge or WAF policy is implemented by the current deployment.",
            },
            {
                "id": "live_hsts_observation",
                "label": "Live custom-host HSTS observation",
                "status": "external_unverified",
                "detail": "The local header contract is not proof of the response seen through the production edge.",
            },
            {
                "id": "backup_restore",
                "label": "Backup and restore qualification",
                "status": "external_unverified",
                "detail": "No disposable-Azure restore exercise is recorded by this GUI.",
            },
            {
                "id": "rollback",
                "label": "Reviewed rollback workflow",
                "status": "unsupported",
                "detail": "No allowlisted GUI rollback workflow or previously qualified revision target exists.",
            },
        ],
    }


_DEPLOYMENT_RATIONALE_SECRET = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|"
    r"(?:password|secret|token|api[_-]?key|authorization|accountkey)\s*[:=]\s*\S+|"
    r"bearer\s+[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)


_AZURE_DEPLOYMENT_STEPS: tuple[dict[str, Any], ...] = (
    {
        "id": "azure_foundation",
        "title": "Azure account and environment",
        "description": "Choose the Azure subscription, region, environment, and short resource-name prefix.",
        "estimated_minutes": 5,
        "prerequisites": (
            "Azure subscription Owner or an approved deployment identity",
            "A region approved for organizational data residency",
            "A separate staging environment before production",
        ),
        "fields": (
            (
                "subscription_id",
                "Azure subscription ID",
                "text",
                True,
                "00000000-0000-0000-0000-000000000000",
                "Azure portal → Subscriptions → select the target subscription → Subscription ID.",
            ),
            (
                "environment",
                "Environment",
                "select",
                True,
                "staging",
                "Choose staging for the first deployment. Production enables HA and stronger retention controls.",
            ),
            (
                "deployment_stage",
                "Deployment stage",
                "select",
                True,
                "foundation_bootstrap",
                "Run the three stages in order. The server advances only after exact protected-workflow evidence.",
            ),
            (
                "location",
                "Azure region",
                "text",
                True,
                "eastus2",
                "Azure portal → a permitted resource group → Location, or ask the cloud governance team.",
            ),
            (
                "name_prefix",
                "Resource prefix",
                "text",
                True,
                "kp",
                "Choose 2–11 lowercase letters, numbers, or hyphens used to recognize these resources.",
            ),
        ),
    },
    {
        "id": "azure_identity_dns",
        "title": "Identity and public addresses",
        "description": "Connect the deployment to Microsoft Entra and choose the two public HTTPS hostnames.",
        "estimated_minutes": 10,
        "prerequisites": (
            "Microsoft Entra permission to register an application",
            "Two DNS names in a domain the organization controls",
            "Approval for an operator console hostname and a separate tracking hostname",
        ),
        "fields": (
            (
                "entra_tenant_id",
                "Microsoft Entra tenant ID",
                "text",
                True,
                "00000000-0000-0000-0000-000000000000",
                "Azure portal → Microsoft Entra ID → Overview → Tenant ID.",
            ),
            (
                "entra_client_id",
                "Entra application client ID",
                "text",
                True,
                "00000000-0000-0000-0000-000000000000",
                "Microsoft Entra ID → App registrations → the console application → Application (client) ID.",
            ),
            (
                "operator_fqdn",
                "Operator console hostname",
                "text",
                True,
                "awareness.example.com",
                "DNS provider → the organization's approved zone. Create a dedicated hostname for administrators.",
            ),
            (
                "tracking_fqdn",
                "Tracking hostname",
                "text",
                True,
                "awareness-track.example.com",
                "DNS provider → the same approved zone. Keep this separate from the operator console hostname.",
            ),
        ),
    },
    {
        "id": "azure_email",
        "title": "ACS customer sending domain",
        "description": (
            "Provision dedicated ACS email resources or reference reviewed existing resources, then verify a "
            "customer-managed domain."
        ),
        "estimated_minutes": 15,
        "prerequisites": (
            "A dedicated customer-managed simulation domain",
            "Access to its public DNS zone or a DNS administrator",
            "Current ACS quota and ramp limits approved for the campaign",
        ),
        "fields": (
            (
                "acs_resource_mode",
                "ACS resource mode",
                "select",
                True,
                "provision",
                "Choose provision unless an approved Communication Service and email domain already exist.",
            ),
            (
                "acs_existing_communication_service_id",
                "Existing Communication Service resource ID",
                "text",
                False,
                "",
                "Azure portal → Communication Service → JSON view → Resource ID. This is not a secret.",
            ),
            (
                "acs_existing_email_endpoint",
                "Existing Communication Service endpoint",
                "text",
                False,
                "",
                "Use the non-secret HTTPS endpoint ending in .communication.azure.com; "
                "never paste a connection string.",
            ),
            (
                "acs_existing_email_domain_id",
                "Existing email-domain resource ID",
                "text",
                False,
                "",
                "Azure portal → Email Communication Service → custom domain → JSON view → Resource ID.",
            ),
            (
                "acs_sending_domain",
                "Customer sending domain",
                "text",
                True,
                "mail.example.com",
                "Use a dedicated public domain controlled by the organization; Azure-managed test domains are blocked.",
            ),
            (
                "acs_sender_local_part",
                "Sender local part",
                "text",
                True,
                "awareness",
                "Choose the mailbox text before @; Terraform provisions it in provision mode.",
            ),
            (
                "acs_sender_display_name",
                "Sender display name",
                "text",
                True,
                "Security Awareness",
                "Use a recognizable 1–64 character name without control characters.",
            ),
            (
                "acs_dns_zone_id",
                "Azure DNS zone resource ID",
                "text",
                False,
                "",
                "Optional: supply only a same-subscription public Azure DNS zone containing the sending domain.",
            ),
            (
                "acs_daily_message_limit",
                "Daily message limit",
                "number",
                True,
                "1000",
                "Use the reviewed limit shown for the ACS resource/support-approved quota.",
            ),
            (
                "acs_messages_per_minute",
                "Messages per minute",
                "number",
                True,
                "20",
                "Choose a value no greater than the reviewed ACS rate limit.",
            ),
            (
                "acs_ramp_batch_size",
                "Initial ramp batch",
                "number",
                True,
                "10",
                "Start below the per-minute limit and increase only after deliverability review.",
            ),
            (
                "acs_ramp_interval_seconds",
                "Ramp interval seconds",
                "number",
                True,
                "60",
                "Use 1–3600 seconds between planned ramp batches.",
            ),
        ),
    },
    {
        "id": "azure_integrations",
        "title": "Azure services and integrations",
        "description": "Choose email data residency, the required private AI gateway, and optional alert endpoints.",
        "estimated_minutes": 5,
        "prerequisites": (
            "Organizational data-residency policy",
            "An approved Azure-hosted AI gateway implementing the platform generation contract",
            "An authenticated Azure-hosted webhook or ntfy service if alerts are required",
        ),
        "fields": (
            (
                "communication_data_location",
                "Email data location",
                "select",
                True,
                "United States",
                "Choose the geography approved for Azure Communication Services email data.",
            ),
            (
                "ai_endpoint",
                "AI gateway endpoint",
                "url",
                True,
                "https://ai-gateway.example.com",
                "Azure-hosted gateway → Overview → endpoint. Managed deployments require it to expose "
                "/propose and /setup-assist so the first approved pattern can produce a template.",
            ),
            (
                "enable_directory_sync",
                "Enable selected-group directory sync",
                "select",
                True,
                "false",
                "Enable only after a tenant administrator reviews and grants the directory permission matrix.",
            ),
            (
                "directory_group_ids",
                "Selected Entra group object IDs",
                "text",
                False,
                "UUIDs, comma-separated",
                "Microsoft Entra admin center → Groups → each approved group → Object ID.",
            ),
            (
                "enable_reported_mailbox",
                "Enable Microsoft 365 report mailbox",
                "select",
                True,
                "false",
                "Enable only after Exchange Application RBAC is scoped and tested for the report mailbox.",
            ),
            (
                "reported_mailbox_address",
                "Report mailbox address",
                "email",
                False,
                "phish-reports@example.com",
                "Exchange admin center → Recipients → the dedicated mailbox receiving reported simulations.",
            ),
            (
                "reported_mailbox_folder",
                "Report mailbox folder",
                "text",
                False,
                "inbox",
                "Use inbox or the immutable Microsoft Graph folder ID selected for reported messages.",
            ),
            (
                "alert_webhook_domains",
                "Allowed alert hostnames",
                "text",
                False,
                "ntfy.example.com",
                "Copy hostname only from each approved Azure-hosted HTTPS webhook; separate multiple hosts "
                "with commas.",
            ),
            (
                "allowed_recipient_domains",
                "Allowed recipient domains",
                "text",
                True,
                "example.com",
                "Enter only organization-owned mail domains authorized by the Rules of Engagement; "
                "separate multiple domains with commas.",
            ),
        ),
    },
    {
        "id": "azure_automation",
        "title": "Deployment automation",
        "description": "Choose the reviewed network path, Terraform-state location, and protected deployment runner.",
        "estimated_minutes": 8,
        "prerequisites": (
            "Azure Storage account with blob versioning and RBAC",
            "A private azure-vnet runner for all three guided deployment stages",
            "GitHub staging and production environments with required production reviewers",
        ),
        "fields": (
            (
                "network_mode",
                "Azure network mode",
                "select",
                True,
                "private",
                "The guided three-stage deployment uses the private azure-vnet runner from bootstrap through "
                "workloads.",
            ),
            (
                "azure_deployment_client_id",
                "Azure deployment identity client ID",
                "text",
                True,
                "00000000-0000-0000-0000-000000000000",
                "Microsoft Entra ID → App registrations → the GitHub OIDC deployment application → "
                "Application (client) ID. This is not the operator-console application ID.",
            ),
            (
                "tf_state_resource_group",
                "Terraform-state resource group",
                "text",
                True,
                "rg-kp-terraform-state",
                "Azure portal → Resource groups → the dedicated infrastructure-state resource group.",
            ),
            (
                "tf_state_storage_account",
                "Terraform-state storage account",
                "text",
                True,
                "kptfstateprod",
                "Azure portal → Storage accounts → the private account holding the tfstate container.",
            ),
            (
                "tf_state_container",
                "Terraform-state container",
                "text",
                True,
                "tfstate",
                "Storage account → Data storage → Containers → the private state container.",
            ),
            (
                "runner_label",
                "Private runner label",
                "text",
                False,
                "azure-vnet",
                "GitHub repository → Settings → Actions → Runners → labels. The workflow expects azure-vnet.",
            ),
            (
                "ciphertext_active_key_id",
                "Active ciphertext key ID",
                "text",
                True,
                "primary",
                "Choose the non-secret 1–32 character identifier shared by the operator and every worker. "
                "It is fixed after foundation deployment; active-key rotation is not yet supported.",
            ),
            (
                "ciphertext_prior_key_ids",
                "Prior decrypt-only key IDs",
                "text",
                False,
                "2026q2,2026q1",
                "For legacy recovery, list up to four retired key IDs in the external Key Vault keyring value. "
                "This does not rotate the active key. Do not enter key material here.",
            ),
            (
                "ciphertext_prior_keys_secret_id",
                "Prior-key Key Vault reference",
                "text",
                False,
                "/subscriptions/.../vaults/.../secrets/ciphertext-prior-keys",
                "After foundation, create the legacy decrypt-only keyring directly in this deployment's Key "
                "Vault and paste its versionless Azure resource ID. Never paste its value.",
            ),
        ),
    },
)


# DEP-010: fields a normal operator does not see on the first pass. These are
# Azure resource IDs, GitHub/Terraform internals, key-vault references, exact
# quota numbers, or identity hooks that the wizard only needs when the default
# path is not used. The GUI collapses them under an explicit Advanced disclosure
# so the common path shows strong defaults rather than infrastructure noise.
_AZURE_ADVANCED_KEYS = frozenset(
    {
        # Existing-resource references (only needed when not provisioning).
        "acs_resource_mode",
        "acs_existing_communication_service_id",
        "acs_existing_email_endpoint",
        "acs_existing_email_domain_id",
        "acs_dns_zone_id",
        # Exact quota/ramp tuning; the reviewed defaults already apply.
        "acs_daily_message_limit",
        "acs_messages_per_minute",
        "acs_ramp_batch_size",
        "acs_ramp_interval_seconds",
        # GitHub Actions / Terraform / repository internals.
        "runner_label",
        "tf_state_resource_group",
        "tf_state_storage_account",
        "tf_state_container",
        "network_mode",
        "azure_deployment_client_id",
        # Key-vault and prior-key references (rotation/recovery only).
        "ciphertext_active_key_id",
        "ciphertext_prior_key_ids",
        "ciphertext_prior_keys_secret_id",
        # Optional identity selectors disclosed only when their feature is on.
        "directory_group_ids",
        "reported_mailbox_address",
        "reported_mailbox_folder",
        "alert_webhook_domains",
    }
)


# DEP-010 strong defaults: values a first-time operator rarely needs to change.
# They seed the form so "normal inputs" shrink to the genuinely organization-
# specific choices. Keys here are the field keys from _AZURE_DEPLOYMENT_STEPS.
_AZURE_SUGGESTED_DEFAULTS: dict[str, str] = {
    "deployment_stage": "foundation_bootstrap",
    "network_mode": "private",
    "acs_resource_mode": "provision",
    "acs_sending_domain": "mail.example.com",
    "acs_sender_local_part": "awareness",
    "acs_sender_display_name": "Security Awareness",
    "acs_daily_message_limit": "1000",
    "acs_messages_per_minute": "20",
    "acs_ramp_batch_size": "10",
    "acs_ramp_interval_seconds": "60",
    "communication_data_location": "United States",
    "enable_directory_sync": "false",
    "enable_reported_mailbox": "false",
    "reported_mailbox_folder": "inbox",
    "name_prefix": "kp",
    "location": "eastus2",
    "environment": "staging",
}


def _azure_deployment_schema() -> dict[str, Any]:
    select_choices = {
        "environment": [
            {"value": "staging", "label": "Staging (recommended first)"},
            {"value": "production", "label": "Production"},
        ],
        "deployment_stage": [
            {"value": "foundation_bootstrap", "label": "1. Bootstrap ACS and publish DNS guidance"},
            {"value": "foundation_finalize", "label": "2. Verify DNS and finalize the sender"},
            {"value": "workloads", "label": "3. Deploy workloads after final evidence"},
        ],
        "network_mode": [
            {"value": "private", "label": "Private network (guided deployment)"},
        ],
        "communication_data_location": [
            {"value": value, "label": value}
            for value in ("United States", "Canada", "Europe", "UK", "Australia", "Asia Pacific")
        ],
        "enable_directory_sync": [
            {"value": "false", "label": "Disabled"},
            {"value": "true", "label": "Enabled"},
        ],
        "enable_reported_mailbox": [
            {"value": "false", "label": "Disabled"},
            {"value": "true", "label": "Enabled"},
        ],
        "acs_resource_mode": [
            {"value": "provision", "label": "Provision dedicated resources"},
            {"value": "existing", "label": "Use reviewed existing resources"},
        ],
    }
    return {
        "steps": [
            {
                **{key: value for key, value in step.items() if key != "fields"},
                "fields": [
                    {
                        "key": key,
                        "label": label,
                        "type": input_type,
                        "required": required,
                        "secret": False,
                        "server_controlled": key == "deployment_stage",
                        "placeholder": placeholder,
                        "where_to_find": location,
                        # DEP-010: advanced internals collapse behind a disclosure;
                        # suggested_default seeds the common path from strong defaults.
                        "advanced": key in _AZURE_ADVANCED_KEYS,
                        "suggested_default": _AZURE_SUGGESTED_DEFAULTS.get(key),
                        "choices": select_choices.get(key, []),
                    }
                    for key, label, input_type, required, placeholder, location in step["fields"]
                ],
            }
            for step in _AZURE_DEPLOYMENT_STEPS
        ],
        "safety_note": "This wizard never asks for Azure passwords, client secrets, access keys, or Terraform state.",
        "workflow": ".github/workflows/azure-deploy.yml",
        "microsoft_graph": {
            "endpoint": "https://graph.microsoft.com/v1.0",
            "identity_separation": "Directory and report-mailbox roles use different user-assigned identities.",
            "permission_matrix": [
                {
                    "role": "directory",
                    "permissions": ["GroupMember.Read.All", "User.ReadBasic.All"],
                    "scope": "Queries are limited to selected group object IDs.",
                    "admin_required": True,
                },
                {
                    "role": "mailbox",
                    "permissions": ["Application Mail.Read"],
                    "scope": "Exchange Online Application RBAC must target only the report mailbox.",
                    "admin_required": True,
                },
            ],
            "manual_steps_required": True,
            "readiness_claim": "configuration_only",
        },
        "acs_email": {
            "managed_domain_fallback": False,
            "dns_automation": "only_when_same_subscription_azure_dns_zone_id_is_supplied",
            "readiness_claim": "configuration_only",
            "provider_acceptance_is_delivery": False,
            "delivery_events_implemented": True,
        },
        "release_readiness": _azure_release_readiness(),
        "orchestration": DeploymentOrchestrator.public_configuration(),
    }


@router.get("/azure-deployment", response_model=dict[str, Any])
def get_azure_deployment(
    _connector: None = Depends(_require_deploy_connector_enabled),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    return _azure_deployment_schema()


@router.post("/azure-deployment/validate", response_model=dict[str, Any])
def validate_azure_deployment(
    body: AzureDeploymentValidationRequest,
    _connector: None = Depends(_require_deploy_connector_enabled),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    allowed = {field[0] for step in _AZURE_DEPLOYMENT_STEPS for field in step["fields"]}
    unknown = set(body.values) - allowed
    if unknown:
        raise PermissionDeniedError("rejected unrecognized Azure deployment keys")
    values = {key: value.strip() for key, value in body.values.items()}
    errors: dict[str, str] = {}
    for key, value in values.items():
        if _DEPLOYMENT_RATIONALE_SECRET.search(value):
            errors[key] = "Do not enter credentials, access keys, connection strings, or tokens."
    uuid_keys = ("subscription_id", "entra_tenant_id", "entra_client_id", "azure_deployment_client_id")
    uuid_pattern = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    for key in uuid_keys:
        if not uuid_pattern.fullmatch(values.get(key, "")):
            errors[key] = "Enter the complete UUID shown in Azure or Microsoft Entra."
    if values.get("environment") not in {"staging", "production"}:
        errors["environment"] = "Choose staging or production."
    deployment_stage = values.get("deployment_stage", "")
    if deployment_stage not in {"foundation_bootstrap", "foundation_finalize", "workloads"}:
        errors["deployment_stage"] = "Choose one of the three deployment stages."
    network_mode = values.get("network_mode", "")
    if network_mode not in {"private", "starter"}:
        errors["network_mode"] = "Choose private or the staging-foundation starter path."
    elif network_mode == "starter" and (
        values.get("environment") != "staging"
        or deployment_stage not in {"foundation_bootstrap", "foundation_finalize"}
    ):
        errors["network_mode"] = "Starter mode is allowed only for staging foundation stages."
    elif deployment_stage == "workloads" and network_mode != "private":
        errors["network_mode"] = "Workloads require private mode and the azure-vnet runner."
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,10}", values.get("name_prefix", "")):
        errors["name_prefix"] = "Use 2–11 lowercase letters, numbers, or hyphens."
    if not re.fullmatch(r"[a-z0-9]+", values.get("location", "")):
        errors["location"] = "Enter the Azure region code, such as eastus2."
    hostname_pattern = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
    for key in ("operator_fqdn", "tracking_fqdn"):
        if not hostname_pattern.fullmatch(values.get(key, "").lower()):
            errors[key] = "Enter a hostname only, without https:// or a path."
    if values.get("operator_fqdn", "").lower() == values.get("tracking_fqdn", "").lower():
        errors["tracking_fqdn"] = "Use a hostname separate from the operator console."
    acs_mode = values.get("acs_resource_mode", "")
    if acs_mode not in {"provision", "existing"}:
        errors["acs_resource_mode"] = "Choose provision or existing."
    acs_domain = values.get("acs_sending_domain", "").lower().rstrip(".")
    # Microsoft-owned zones (azurecomm.net, onmicrosoft.com) cannot have their
    # DNS edited by the tenant, so ACS custom-domain verification can never
    # complete against them. Require a customer-managed public DNS domain.
    microsoft_managed_zones = ("azurecomm.net", "onmicrosoft.com")
    if (
        not hostname_pattern.fullmatch(acs_domain)
        or acs_domain in microsoft_managed_zones
        or any(acs_domain.endswith("." + zone) for zone in microsoft_managed_zones)
    ):
        errors["acs_sending_domain"] = (
            "Use a customer-managed public DNS domain whose DNS you can edit, not an "
            "Azure/Microsoft-managed domain (azurecomm.net, onmicrosoft.com)."
        )
    local_part = values.get("acs_sender_local_part", "").lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._+-]{0,63}", local_part):
        errors["acs_sender_local_part"] = "Use 1–64 lowercase mailbox characters before @."
    display_name = values.get("acs_sender_display_name", "")
    if not 1 <= len(display_name) <= 64 or any(ord(character) < 32 for character in display_name):
        errors["acs_sender_display_name"] = "Use 1–64 printable characters."
    if acs_mode == "existing":
        if not re.fullmatch(
            r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Communication/"
            r"CommunicationServices/[^/]+",
            values.get("acs_existing_communication_service_id", ""),
            flags=re.IGNORECASE,
        ):
            errors["acs_existing_communication_service_id"] = (
                "Enter the complete Communication Service Azure resource ID."
            )
        try:
            _validated_acs_endpoint(values.get("acs_existing_email_endpoint", ""))
        except ValueError:
            errors["acs_existing_email_endpoint"] = (
                "Enter the non-secret HTTPS Communication Service endpoint, not a connection string."
            )
        if not re.fullmatch(
            r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Communication/"
            r"emailServices/[^/]+/domains/[^/]+",
            values.get("acs_existing_email_domain_id", ""),
            flags=re.IGNORECASE,
        ):
            errors["acs_existing_email_domain_id"] = "Enter the complete customer email-domain Azure resource ID."
    dns_zone_id = values.get("acs_dns_zone_id", "")
    if dns_zone_id:
        match = re.fullmatch(
            r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.Network/dnszones/([^/]+)",
            dns_zone_id,
            flags=re.IGNORECASE,
        )
        if not match or match.group(1).lower() != values.get("subscription_id", "").lower():
            errors["acs_dns_zone_id"] = "Use a complete same-subscription public Azure DNS zone resource ID."
        elif acs_domain != match.group(2).lower() and not acs_domain.endswith(f".{match.group(2).lower()}"):
            errors["acs_dns_zone_id"] = "The Azure DNS zone must contain the customer sending domain."
    pacing: dict[str, int] = {}
    for key, minimum, maximum in (
        ("acs_daily_message_limit", 1, 1_000_000),
        ("acs_messages_per_minute", 1, 10_000),
        ("acs_ramp_batch_size", 1, 2_000),
        ("acs_ramp_interval_seconds", 1, 3_600),
    ):
        try:
            pacing[key] = int(values.get(key, ""))
        except ValueError:
            errors[key] = "Enter a whole number."
            continue
        if not minimum <= pacing[key] <= maximum:
            errors[key] = f"Enter a value from {minimum} to {maximum}."
    if pacing.get("acs_messages_per_minute", 1) > pacing.get("acs_daily_message_limit", 1):
        errors["acs_messages_per_minute"] = "The per-minute limit cannot exceed the daily limit."
    if pacing.get("acs_ramp_batch_size", 1) > pacing.get("acs_messages_per_minute", 1):
        errors["acs_ramp_batch_size"] = "The initial batch cannot exceed the per-minute limit."
    endpoint = values.get("ai_endpoint", "")
    if not endpoint:
        errors["ai_endpoint"] = (
            "Enter the approved HTTPS AI gateway that exposes /propose and /setup-assist; "
            "managed deployments cannot create their first template without it."
        )
    else:
        parsed = urlparse(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or _explicit_loopback_host(parsed.hostname)
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            errors["ai_endpoint"] = (
                "Use a non-local HTTPS base URL without credentials, query parameters, or fragments."
            )
    for key in ("enable_directory_sync", "enable_reported_mailbox"):
        if values.get(key) not in {"true", "false"}:
            errors[key] = "Choose enabled or disabled."
    group_ids = [item.strip() for item in values.get("directory_group_ids", "").split(",") if item.strip()]
    if values.get("enable_directory_sync") == "true":
        if not group_ids:
            errors["directory_group_ids"] = "Select at least one Entra group object ID."
        elif any(not uuid_pattern.fullmatch(group_id) for group_id in group_ids):
            errors["directory_group_ids"] = "Enter comma-separated Entra group object UUIDs."
    mailbox = values.get("reported_mailbox_address", "")
    if values.get("enable_reported_mailbox") == "true" and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", mailbox):
        errors["reported_mailbox_address"] = "Enter the dedicated Microsoft 365 report mailbox address."
    if values.get("enable_reported_mailbox") == "true" and not values.get("reported_mailbox_folder", ""):
        errors["reported_mailbox_folder"] = "Enter inbox or a Microsoft Graph mail folder ID."
    domains = [item.strip().lower() for item in values.get("alert_webhook_domains", "").split(",") if item.strip()]
    if any(not hostname_pattern.fullmatch(domain) for domain in domains):
        errors["alert_webhook_domains"] = "Enter hostnames only, separated by commas."
    recipient_domains = [
        item.strip().lower() for item in values.get("allowed_recipient_domains", "").split(",") if item.strip()
    ]
    if not recipient_domains or any(not hostname_pattern.fullmatch(domain) for domain in recipient_domains):
        errors["allowed_recipient_domains"] = "Enter at least one authorized mail domain, separated by commas."
    if not re.fullmatch(r"[A-Za-z0-9_.()\-]{1,90}", values.get("tf_state_resource_group", "")):
        errors["tf_state_resource_group"] = "Enter the 1–90 character Azure resource-group name."
    if not re.fullmatch(r"[a-z0-9]{3,24}", values.get("tf_state_storage_account", "")):
        errors["tf_state_storage_account"] = "Use the 3–24 character lowercase Azure Storage account name."
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", values.get("tf_state_container", "")):
        errors["tf_state_container"] = "Enter the lowercase blob container name."
    ciphertext_key_id_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
    active_ciphertext_key_id = values.get("ciphertext_active_key_id", "")
    if ciphertext_key_id_pattern.fullmatch(active_ciphertext_key_id) is None:
        errors["ciphertext_active_key_id"] = "Use 1–32 ASCII letters, digits, underscores, or hyphens."
    prior_ciphertext_key_ids = (
        [item.strip() for item in values.get("ciphertext_prior_key_ids", "").split(",")]
        if values.get("ciphertext_prior_key_ids", "").strip()
        else []
    )
    if (
        len(prior_ciphertext_key_ids) > 4
        or len(set(prior_ciphertext_key_ids)) != len(prior_ciphertext_key_ids)
        or any(ciphertext_key_id_pattern.fullmatch(key_id) is None for key_id in prior_ciphertext_key_ids)
        or active_ciphertext_key_id in prior_ciphertext_key_ids
    ):
        errors["ciphertext_prior_key_ids"] = "List at most four unique valid key IDs, excluding the active key ID."
    prior_ciphertext_secret_id = values.get("ciphertext_prior_keys_secret_id", "")
    secret_id_match = re.fullmatch(
        r"/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.KeyVault/"
        r"vaults/([A-Za-z0-9-]{3,24})/secrets/([A-Za-z0-9-]{1,127})",
        prior_ciphertext_secret_id,
        flags=re.IGNORECASE,
    )
    if bool(prior_ciphertext_key_ids) != bool(prior_ciphertext_secret_id):
        rotation_reference_error = "Prior key IDs and their versionless Key Vault reference must be supplied together."
        errors["ciphertext_prior_keys_secret_id"] = rotation_reference_error
    elif prior_ciphertext_secret_id and (
        secret_id_match is None or secret_id_match.group(1).lower() != values.get("subscription_id", "").lower()
    ):
        rotation_reference_error = (
            "Use a versionless secret resource ID from the selected subscription; never paste a secret value."
        )
        errors["ciphertext_prior_keys_secret_id"] = rotation_reference_error
    if deployment_stage != "workloads" and (prior_ciphertext_key_ids or prior_ciphertext_secret_id):
        rotation_reference_error = (
            "Prior-key recovery is allowed only in the workloads phase after the deployment Key Vault exists."
        )
        errors["ciphertext_prior_keys_secret_id"] = rotation_reference_error
    if values.get("communication_data_location") not in {
        "United States",
        "Canada",
        "Europe",
        "UK",
        "Australia",
        "Asia Pacific",
    }:
        errors["communication_data_location"] = "Choose one of the supported data locations."
    required = {field[0] for step in _AZURE_DEPLOYMENT_STEPS for field in step["fields"] if field[3]}
    for key in required:
        if not values.get(key):
            errors.setdefault(key, "This value is required.")
    warnings = []
    if network_mode == "private" and values.get("runner_label") != "azure-vnet":
        errors["runner_label"] = "Private mode requires the exact protected runner label azure-vnet."
    elif network_mode == "starter":
        warnings.append("Starter mode uses a hosted runner and must transition to private before workloads.")
    enabled_roles = [
        role
        for role, enabled in (
            ("directory", values.get("enable_directory_sync") == "true"),
            ("mailbox", values.get("enable_reported_mailbox") == "true"),
        )
        if enabled
    ]
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "provider_readiness": {
            "enabled_roles": enabled_roles,
            "configuration_valid": not any(
                key in errors
                for key in (
                    "enable_directory_sync",
                    "directory_group_ids",
                    "enable_reported_mailbox",
                    "reported_mailbox_address",
                    "reported_mailbox_folder",
                )
            ),
            "admin_consent_verified": False,
            "live_connectivity_verified": False,
        },
        "acs_email_readiness": {
            "configuration_valid": not any(
                key in errors for key in ({field[0] for field in _AZURE_DEPLOYMENT_STEPS[2]["fields"]})
            ),
            "resource_mode": acs_mode,
            "deployment_stage": deployment_stage,
            "sender_address": f"{local_part}@{acs_domain}" if local_part and acs_domain else "",
            "dns_status": "azure_dns_automation_planned"
            if dns_zone_id and "acs_dns_zone_id" not in errors
            else "manual_dns_required",
            "evidence_source": "protected_workflow_artifact_only",
            "advance_blocked_until_verified_artifact": deployment_stage != "workloads",
            "live_verification_performed": False,
            "provider_acceptance_is_confirmed_delivery": False,
            "delivery_events_implemented": True,
            "pacing": pacing,
        },
        "release_readiness": _azure_release_readiness(),
    }


def _deployment_orchestrator(request: Request) -> DeploymentOrchestrator:
    existing = getattr(request.app.state, "deployment_orchestrator", None)
    if existing is not None:
        return cast(DeploymentOrchestrator, existing)
    try:
        orchestrator = DeploymentOrchestrator.from_environment(request.app.state.settings.redis_url)
    except DeploymentUnavailable as exc:
        raise ConflictError(public_deployment_error(exc)) from None
    request.app.state.deployment_orchestrator = orchestrator
    return orchestrator


@router.post("/azure-deployment/orchestration/plan", response_model=dict[str, Any])
def plan_azure_deployment(
    body: AzureDeploymentValidationRequest,
    request: Request,
    _connector: None = Depends(_require_deploy_connector_enabled),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    validation = validate_azure_deployment(body, _principal=principal)
    if not validation["ok"]:
        return validation
    values = {key: value.strip() for key, value in body.values.items()}
    if values.get("environment") == "production":
        raise ConflictError(
            "production deployment planning is blocked until custom-domain, certificate, edge restriction, "
            "live HSTS, backup/restore, and rollback gates are verifiable; use staging for bootstrap"
        )
    if values.get("deployment_stage") != "foundation_bootstrap":
        raise ConflictError(
            "a new GUI deployment must begin with foundation bootstrap; use the verified stage advance action"
        )
    if values.get("network_mode") != "private":
        raise ConflictError(
            "the GUI stage sequence requires the private azure-vnet runner from bootstrap through workloads"
        )
    try:
        plan = _deployment_orchestrator(request).create_plan(values, actor=principal.principal_id)
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None
    request.app.state.audit_store.record(
        actor=principal.principal_id,
        action="deployment.plan.review",
        object_type="azure_deployment",
        object_id=str(plan["plan_id"]),
        detail={
            "review_digest": plan["review_digest"],
            "environment": plan["review"]["environment"],
            "deployment_stage": plan["review"]["deployment_stage"],
            "workflow": plan["workflow"],
            "commit_sha": plan["source_revision"]["commit_sha"],
            "workflow_content_sha256": plan["source_revision"]["workflow_content_sha256"],
        },
    )
    return plan


@router.get("/azure-deployment/orchestration/latest", response_model=dict[str, Any])
def get_latest_azure_deployment_plan(
    request: Request,
    environment: str = "staging",
    _connector: None = Depends(_require_deploy_connector_enabled),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    try:
        plan = _deployment_orchestrator(request).get_latest_plan(environment, actor=principal.principal_id)
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None
    return {"environment": environment, "plan": plan}


@router.get("/azure-deployment/orchestration/plans/{plan_id}", response_model=dict[str, Any])
def get_azure_deployment_plan(
    plan_id: str,
    request: Request,
    _connector: None = Depends(_require_deploy_connector_enabled),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    try:
        return _deployment_orchestrator(request).get_plan(plan_id, actor=principal.principal_id)
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None


def _submit_azure_deployment_plan(
    plan_id: str,
    body: AzureDeploymentConfirmationRequest,
    request: Request,
    principal: Principal,
    *,
    retry: bool,
) -> dict[str, Any]:
    if not body.confirm:
        raise PermissionDeniedError("deployment dispatch requires explicit reviewed confirmation")
    if _DEPLOYMENT_RATIONALE_SECRET.search(body.rationale):
        raise PermissionDeniedError("authorization reasons must not contain credentials or tokens")

    def audit(detail: dict[str, Any]) -> None:
        request.app.state.audit_store.record(
            actor=principal.principal_id,
            action="deployment.retry.request" if retry else "deployment.apply.request",
            object_type="azure_deployment",
            object_id=plan_id,
            detail=detail,
        )

    try:
        return _deployment_orchestrator(request).apply(
            plan_id,
            body.review_digest,
            actor=principal.principal_id,
            rationale=body.rationale.strip(),
            retry=retry,
            audit=audit,
        )
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None


@router.post("/azure-deployment/orchestration/plans/{plan_id}/apply", response_model=dict[str, Any])
def apply_azure_deployment_plan(
    plan_id: str,
    body: AzureDeploymentConfirmationRequest,
    request: Request,
    _connector: None = Depends(_require_deploy_connector_enabled),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    return _submit_azure_deployment_plan(plan_id, body, request, principal, retry=False)


@router.post("/azure-deployment/orchestration/plans/{plan_id}/retry", response_model=dict[str, Any])
def retry_azure_deployment_plan(
    plan_id: str,
    body: AzureDeploymentConfirmationRequest,
    request: Request,
    _connector: None = Depends(_require_deploy_connector_enabled),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    return _submit_azure_deployment_plan(plan_id, body, request, principal, retry=True)


@router.post("/azure-deployment/orchestration/plans/{plan_id}/advance", response_model=dict[str, Any])
def advance_azure_deployment_plan(
    plan_id: str,
    body: AzureDeploymentAdvanceRequest,
    request: Request,
    _connector: None = Depends(_require_deploy_connector_enabled),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    if not body.confirm:
        raise PermissionDeniedError("deployment stage advance requires explicit reviewed confirmation")
    try:
        plan = _deployment_orchestrator(request).advance_plan(
            plan_id,
            body.review_digest,
            actor=principal.principal_id,
        )
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None
    request.app.state.audit_store.record(
        actor=principal.principal_id,
        action="deployment.stage.advance",
        object_type="azure_deployment",
        object_id=str(plan["plan_id"]),
        detail={
            "review_digest": plan["review_digest"],
            "deployment_stage": plan["review"]["deployment_stage"],
            "predecessor": plan["stage_predecessor"],
        },
    )
    return plan
