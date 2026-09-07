"""Operator API router aggregate: campaign lifecycle, sources, recipients,
approvals, patterns, templates, audit.

The route implementations live in :mod:`kp_operator_api.routes`, one module per
resource (ARC-002 Item 2). This module is the facade that assembles them into
the single ``/api/v1`` router ``main.py`` includes, in exactly the registration
order the routes had when they all lived here, and re-exports the names the
operator-api tests import.

Every mutating endpoint records a hash-chained audit event and enforces
RBAC. Deterministic checks (safety validation, approval requirements,
self-approval checks on legacy review routes, manifest hashing) happen in-process, so they cannot
be bypassed by the client.
"""

from __future__ import annotations

from fastapi import APIRouter
from kp_domain_models.policy import ApprovalPolicy

from kp_operator_api.content_library import register_routes as register_content_library_routes
from kp_operator_api.recipient_import_planning import (
    RecipientImportApplyRequest,
    RecipientImportPreviewRequest,
    RecipientsImport,
)
from kp_operator_api.routes.alerts import (
    AlertSubscribe,
    list_alert_subscriptions,
    subscribe_alerts,
)
from kp_operator_api.routes.alerts import (
    router as alerts_router,
)
from kp_operator_api.routes.audience_groups import (
    router as audience_groups_router,
)
from kp_operator_api.routes.audit import (
    router as audit_router,
)
from kp_operator_api.routes.campaigns import (
    _MAX_COVERING_ROE_CANDIDATES,
    _PROOF_SEND_ACTOR_LIMIT,
    _PROOF_SEND_GLOBAL_LIMIT,
    ApprovalSubmit,
    CampaignAudienceUpdate,
    CampaignCreate,
    CampaignTrainingBindingUpdate,
    ProofSendRequest,
    _campaign_action_flags,
    _campaign_report,
    _covering_roes,
    _require_campaign_approval_capability,
    _training_binding_view,
    approve_campaign,
    campaign_evidence_bundle,
    campaign_recipient_results,
    campaigns_needing_my_decision,
    list_campaigns,
    proof_send_campaign,
    queue_training_reminders,
    update_campaign_audience,
    update_campaign_training_resource,
)
from kp_operator_api.routes.campaigns import (
    router as campaigns_router,
)
from kp_operator_api.routes.dead_letters import (
    DeadLetterReplay,
    inspect_dead_letter,
    list_dead_letters,
    replay_dead_letter,
)
from kp_operator_api.routes.dead_letters import (
    router as dead_letters_router,
)
from kp_operator_api.routes.patterns import (
    TemplateDecision,
    _require_active_pattern_source,
    approve_pattern,
    decide_template,
    list_pending_templates,
)
from kp_operator_api.routes.patterns import (
    router as patterns_router,
)
from kp_operator_api.routes.privacy import (
    _PRIVACY_EXPORT_RECORD_LIMIT,
    PrivacyFulfillment,
    PrivacyRequestCreate,
    _bounded_privacy_export_rows,
)
from kp_operator_api.routes.privacy import (
    router as privacy_router,
)
from kp_operator_api.routes.recipients import (
    DirectoryApply,
    ExclusionCreate,
    ExclusionRevoke,
    apply_recipients_csv,
    apply_recipients_from_directory,
    discard_directory_preview,
    import_recipients_csv,
    list_recipients,
    microsoft365_integration_status,
    poll_reported_mailbox,
    preview_recipients_csv,
    preview_recipients_from_directory,
)
from kp_operator_api.routes.recipients import (
    router as recipients_router,
)
from kp_operator_api.routes.sources import (
    SourceCreate,
    list_sources,
)
from kp_operator_api.routes.sources import (
    router as sources_router,
)
from kp_operator_api.sending_domains_roe import (
    # re-exported so tests keep working; the test-only names below are declared
    # in ``__all__`` so ruff F401 accepts them
    _domain_verification_key,
    _roe_signing_key,
    list_roes,
    list_sending_domains,
)
from kp_operator_api.sending_domains_roe import (
    router as sending_router,
)

__all__ = [
    "_MAX_COVERING_ROE_CANDIDATES",
    "_PRIVACY_EXPORT_RECORD_LIMIT",
    "_PROOF_SEND_ACTOR_LIMIT",
    "_PROOF_SEND_GLOBAL_LIMIT",
    "AlertSubscribe",
    "ApprovalPolicy",
    "ApprovalSubmit",
    "CampaignAudienceUpdate",
    "CampaignCreate",
    "CampaignTrainingBindingUpdate",
    "DeadLetterReplay",
    "DirectoryApply",
    "ExclusionCreate",
    "ExclusionRevoke",
    "PrivacyFulfillment",
    "PrivacyRequestCreate",
    "ProofSendRequest",
    "RecipientImportApplyRequest",
    "RecipientImportPreviewRequest",
    "RecipientsImport",
    "SourceCreate",
    "TemplateDecision",
    "_bounded_privacy_export_rows",
    "_campaign_action_flags",
    "_campaign_report",
    "_covering_roes",
    "_domain_verification_key",
    "_require_active_pattern_source",
    "_require_campaign_approval_capability",
    "_roe_signing_key",
    "_training_binding_view",
    "apply_recipients_csv",
    "apply_recipients_from_directory",
    "approve_campaign",
    "approve_pattern",
    "campaign_evidence_bundle",
    "campaign_recipient_results",
    "campaigns_needing_my_decision",
    "decide_template",
    "discard_directory_preview",
    "import_recipients_csv",
    "inspect_dead_letter",
    "list_alert_subscriptions",
    "list_campaigns",
    "list_dead_letters",
    "list_pending_templates",
    "list_recipients",
    "list_roes",
    "list_sending_domains",
    "list_sources",
    "microsoft365_integration_status",
    "poll_reported_mailbox",
    "preview_recipients_csv",
    "preview_recipients_from_directory",
    "proof_send_campaign",
    "queue_training_reminders",
    "replay_dead_letter",
    "router",
    "subscribe_alerts",
    "update_campaign_audience",
    "update_campaign_training_resource",
]

router = APIRouter(prefix="/api/v1")

# FastAPI >=0.141 wraps ``include_router`` in a lazy ``_IncludedRouter`` instead
# of flattening, which hides the routes from one-level ``router.routes`` walkers
# (the operator-api route-inventory contracts). Every resource router carries the
# same ``/api/v1`` prefix, so copying their route objects into the facade router
# preserves both the exact registration order and the fully-qualified paths.
for _resource_router in (
    audience_groups_router,
    campaigns_router,
    sources_router,
    recipients_router,
    alerts_router,
):
    for _resource_route in _resource_router.routes:
        router.routes.append(_resource_route)

register_content_library_routes(router)

for _resource_router in (
    patterns_router,
    dead_letters_router,
    audit_router,
    privacy_router,
    sending_router,
):
    for _resource_route in _resource_router.routes:
        router.routes.append(_resource_route)
