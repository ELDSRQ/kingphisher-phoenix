"""Shared deployment-orchestration contracts.

Module-level constants, exceptions, public error guidance, and the two
frozen value types (WorkflowPreflight, WorkflowConfiguration) used by both
the GitHub workflow gateway and the deployment orchestrator.

Trust boundary: same-process, deterministic configuration data. No I/O;
every secret-bearing value is validated by regex before use. The public
error guidance deliberately returns only reviewed operator-facing strings,
never raw exception text.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

WORKFLOW_FILE = "azure-deploy.yml"
WORKFLOW_PATH = ".github/workflows/azure-deploy.yml"
PLAN_TTL_SECONDS = 24 * 60 * 60
ACTIVE_TTL_SECONDS = PLAN_TTL_SECONDS
OPERATION_TTL_SECONDS = 5 * 60
RUNS_PER_PAGE = 100
MAX_RUN_PAGES = 3
MAX_BASELINE_RUNS = RUNS_PER_PAGE * MAX_RUN_PAGES
MAX_ACTIVITY = 160
MAX_STEPS_PER_JOB = 96
MAX_DEPLOYMENT_ATTEMPTS = 8
CHECKPOINT_RESERVE_PER_ATTEMPT = 8
CORRELATION_PREFIX = "kp"
MAX_WORKFLOW_BYTES = 256 * 1024
MAX_GITHUB_METADATA_BYTES = 1024 * 1024
MAX_GITHUB_STATUS_BYTES = 256 * 1024
MAX_GITHUB_ACTIVITY_BYTES = 512 * 1024
MAX_DEPLOYMENT_CONFIG_BYTES = 32 * 1024
MAX_PLAN_BYTES = 128 * 1024
MAX_CHECKPOINTS = 64
MAX_ACS_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ACS_EVIDENCE_BYTES = 16 * 1024
MAX_ACS_EVIDENCE_AGE_SECONDS = 24 * 60 * 60
# Updated only when the fixed workflow and connector contract are reviewed
# together. A repository ref that resolves to any other content is not ready.
EXPECTED_WORKFLOW_SHA256 = "32c9d13a8dee21dc0d9fe5308e6a3180b7391d7275aa91d033281bc8ddafc873"
REQUIRED_WORKFLOW_INPUTS = frozenset(
    {
        "environment",
        "network_mode",
        "deployment_phase",
        "deployment_config",
        "deployment_request_id",
        "reviewed_commit_sha",
    }
)
DEPLOYMENT_CONFIG_KEYS = (
    "subscription_id",
    "location",
    "name_prefix",
    "operator_fqdn",
    "tracking_fqdn",
    "entra_tenant_id",
    "entra_client_id",
    "acs_resource_mode",
    "acs_existing_communication_service_id",
    "acs_existing_email_endpoint",
    "acs_existing_email_domain_id",
    "acs_sending_domain",
    "acs_sender_local_part",
    "acs_sender_display_name",
    "acs_dns_zone_id",
    "acs_daily_message_limit",
    "acs_messages_per_minute",
    "acs_ramp_batch_size",
    "acs_ramp_interval_seconds",
    "communication_data_location",
    "ai_endpoint",
    "enable_directory_sync",
    "directory_group_ids",
    "enable_reported_mailbox",
    "reported_mailbox_address",
    "reported_mailbox_folder",
    "alert_webhook_domains",
    "allowed_recipient_domains",
    "ciphertext_active_key_id",
    "ciphertext_prior_key_ids",
    "ciphertext_prior_keys_secret_id",
)
# These values are workflow-internal defensive defaults. They can never be
# supplied by a browser, AI assistant, export, or caller-controlled allowlist.
# Only authenticated Azure control-plane readback may replace them.
INTERNAL_ACS_CONFIG_DEFAULTS = {
    "acs_domain_verification_status": "pending_live_readback",
    "acs_spf_verification_status": "pending_live_readback",
    "acs_dkim_verification_status": "pending_live_readback",
    "acs_dkim2_verification_status": "pending_live_readback",
    "acs_sender_username_status": "pending_live_readback",
    "acs_domain_association_status": "pending_live_readback",
    "acs_readiness_checked_at": "",
}
DEPLOYMENT_STAGES = ("foundation_bootstrap", "foundation_finalize", "workloads")
_NEXT_DEPLOYMENT_STAGE = {
    "foundation_bootstrap": "foundation_finalize",
    "foundation_finalize": "workloads",
}
ACS_EVIDENCE_ARTIFACT_SCHEMA = "kp.acs-stage-result.v1"
ACS_EVIDENCE_ARTIFACT_PATH = "acs-stage-result.json"
ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS = frozenset(
    {
        "acs-live-readiness.json",
        "acs-verification-initiation.json",
        "acs-finalize-readback.json",
        "acs-stage-result.json",
        "checkpoints.ndjson",
    }
)
_ACS_STAGE_RESULT_BY_STAGE = {
    "foundation_bootstrap": frozenset(
        {
            "foundation_bootstrap_pending_dns",
            "foundation_bootstrap_already_verified_no_mutation",
            "foundation_bootstrap_existing_resource_no_mutation",
        }
    ),
    "foundation_finalize": frozenset({"foundation_finalized"}),
    "workloads": frozenset({"workloads_deployed"}),
}
_ACS_STATUS_VALUES = frozenset(
    {
        "not_observed",
        "not_linked",
        "notstarted",
        "verificationrequested",
        "verificationinprogress",
        "verificationfailed",
        "verified",
    }
)
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_REF = re.compile(r"[A-Za-z0-9._/-]{1,255}\Z")
_PLAN_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_GITHUB_TOKEN = re.compile(r"[A-Za-z0-9_-]{20,512}\Z")
_CIPHERTEXT_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
_VERSIONLESS_KEY_VAULT_SECRET_ID = re.compile(
    r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/"
    r"vaults/[A-Za-z0-9-]{3,24}/secrets/[A-Za-z0-9-]{1,127}\Z",
    re.IGNORECASE,
)
_TERMINAL_FAILURES = frozenset({"failure", "cancelled", "timed_out", "action_required", "stale"})
_TERMINAL_RESULTS = _TERMINAL_FAILURES | {"success", "neutral", "skipped"}
_RUN_STATUSES = frozenset({"queued", "in_progress", "completed", "waiting", "requested", "pending"})
_ACTIVITY_STATUSES = _RUN_STATUSES | {"unknown"}
_JSON_CONTENT_TYPE = re.compile(r"application/(?:json|[A-Za-z0-9!#$&^_.+-]+\+json)\Z", re.IGNORECASE)
_SENSITIVE_ACTIVITY = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|"
    r"(?:password|secret|token|api[_-]?key|authorization|accountkey)\s*[:=])",
    re.IGNORECASE,
)
_SENSITIVE_DEPLOYMENT_VALUE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|"
    r"(?:password|secret|token|api[_-]?key|authorization|accountkey)\s*[:=]\s*\S+|"
    r"bearer\s+[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)

# Deployment recovery is deliberately preservation-first.  These values are
# returned as reviewed, machine-readable policy; they are not shell commands
# and the connector has no cleanup primitive.
PRESERVATION_REQUIRED_ASSETS = (
    "working_tree",
    "python_environment",
    "terraform_provider_cache",
    "container_images",
    "compose_containers",
    "build_cache",
    "named_volumes",
    "databases",
    "runtime_state",
    "qualification_evidence",
)
PROHIBITED_AUTOMATIC_ACTIONS = (
    "delete_files",
    "prune_build_cache",
    "remove_images",
    "remove_containers",
    "remove_volumes",
    "drop_databases",
    "compose_down",
    "reset_working_tree",
)
RECOVERY_EVIDENCE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "disk": (
        "free_bytes_before_build",
        "required_bytes_estimate",
        "capacity_decision",
    ),
    "runtime": (
        "container_runtime_available",
        "container_runtime_writable",
        "runtime_version",
    ),
    "images": (
        "required_image_references",
        "required_image_digests",
        "missing_images_rebuild_plan",
    ),
    "platform": (
        "runner_operating_system",
        "runner_architecture",
        "target_platform",
    ),
    "volumes": (
        "required_named_volumes",
        "volume_presence",
        "preservation_decision",
    ),
    "databases": (
        "required_databases",
        "schema_revision",
        "backup_or_recovery_evidence",
        "preservation_decision",
    ),
}
QUALIFICATION_JOB = "Qualify source and release gates"
GUARD_JOB = "Guard reviewed deployment inputs"
DEPLOY_JOB = "Deploy reviewed Azure phase"
_COMMON_RECOVERY_STEPS = (
    (QUALIFICATION_JOB, "Record runner disk headroom before qualification"),
    (QUALIFICATION_JOB, "Required hermetic no-skip suite"),
    (QUALIFICATION_JOB, "Validate Terraform without a backend"),
    (QUALIFICATION_JOB, "Upload qualification recovery evidence"),
    (GUARD_JOB, "Validate opaque deployment request correlation"),
    (GUARD_JOB, "Refuse source drift after GUI review"),
    (GUARD_JOB, "Record selected mode"),
    (DEPLOY_JOB, "Initialize append-only deployment checkpoint"),
    (DEPLOY_JOB, "Validate and materialize reviewed deployment values"),
    (DEPLOY_JOB, "Checkpoint reviewed configuration"),
    (DEPLOY_JOB, "Authenticate to Azure"),
    (DEPLOY_JOB, "Checkpoint Azure authentication"),
    (DEPLOY_JOB, "Initialize Terraform"),
    (DEPLOY_JOB, "Checkpoint Terraform state identity"),
    (DEPLOY_JOB, "Validate ciphertext key-rotation lifecycle metadata"),
    (DEPLOY_JOB, "Read ACS readiness from the authenticated Azure control plane"),
    (DEPLOY_JOB, "Checkpoint live ACS control-plane observation"),
    (DEPLOY_JOB, "Summarize"),
    (DEPLOY_JOB, "Checkpoint conclusive ACS stage result"),
    (DEPLOY_JOB, "Record completed cloud operations"),
    (DEPLOY_JOB, "Upload append-only deployment recovery evidence"),
)
_FOUNDATION_BOOTSTRAP_RECOVERY_STEPS = (
    (DEPLOY_JOB, "Plan ACS foundation bootstrap"),
    (DEPLOY_JOB, "Enforce ACS foundation bootstrap plan allowlist"),
    (DEPLOY_JOB, "Checkpoint allowlisted foundation bootstrap plan"),
    (DEPLOY_JOB, "Apply ACS foundation bootstrap"),
    (DEPLOY_JOB, "Checkpoint ACS foundation bootstrap apply"),
    (DEPLOY_JOB, "Publish non-secret integration bootstrap plan"),
    (DEPLOY_JOB, "Checkpoint integration bootstrap plan"),
    (DEPLOY_JOB, "Initiate pending ACS customer-domain verification"),
    (DEPLOY_JOB, "Checkpoint ACS verification initiation"),
)
_FOUNDATION_FINALIZE_RECOVERY_STEPS = (
    (DEPLOY_JOB, "Plan ACS foundation finalize"),
    (DEPLOY_JOB, "Enforce ACS foundation finalize plan allowlist"),
    (DEPLOY_JOB, "Checkpoint allowlisted foundation finalize plan"),
    (DEPLOY_JOB, "Apply ACS foundation finalize"),
    (DEPLOY_JOB, "Checkpoint ACS foundation finalize apply"),
    (DEPLOY_JOB, "Prove finalized ACS association and sender from Azure"),
    (DEPLOY_JOB, "Checkpoint finalized ACS readback"),
)
_WORKLOAD_RECOVERY_STEPS = (
    (QUALIFICATION_JOB, "Required PostgreSQL integration gate"),
    (QUALIFICATION_JOB, "Required Redis integration gate"),
    (QUALIFICATION_JOB, "Required fresh-migration gate"),
    (QUALIFICATION_JOB, "Build and start every release image"),
    (QUALIFICATION_JOB, "Scan the built release images"),
    (DEPLOY_JOB, "Build immutable images in the registry"),
    (DEPLOY_JOB, "Verify registry attestations before deployment"),
    (DEPLOY_JOB, "Checkpoint verified immutable images"),
    (DEPLOY_JOB, "Plan workloads"),
    (DEPLOY_JOB, "Refuse destructive workload changes"),
    (DEPLOY_JOB, "Checkpoint non-destructive workload plan"),
    (DEPLOY_JOB, "Apply workloads"),
    (DEPLOY_JOB, "Checkpoint workload apply"),
    (DEPLOY_JOB, "Migrate and qualify"),
    (DEPLOY_JOB, "Checkpoint migration and health qualification"),
    (DEPLOY_JOB, "Plan ACS receipt subscription activation"),
    (DEPLOY_JOB, "Refuse unrelated changes in receipt activation plan"),
    (DEPLOY_JOB, "Checkpoint non-destructive receipt plan"),
    (DEPLOY_JOB, "Activate ACS receipt subscription after readiness"),
    (DEPLOY_JOB, "Verify ACS Event Grid subscription"),
    (DEPLOY_JOB, "Checkpoint verified receipt activation"),
    (DEPLOY_JOB, "Remove ephemeral registry credentials"),
)
_CHECKPOINT_EVIDENCE_FIELDS = {
    "plan_reviewed": frozenset({"review_digest", "source_revision_digest"}),
    "dispatch_intent_saved": frozenset({"baseline_run_count", "retry"}),
    "dispatch_blocked": frozenset({"reason"}),
    "audit_evidence_committed": frozenset(),
    "review_invalidated": frozenset({"reason"}),
    "source_revalidated": frozenset({"source_revision_digest"}),
    "dispatch_rejected": frozenset({"retry_safe"}),
    "dispatch_indeterminate": frozenset({"retry_safe"}),
    "dispatch_interrupted": frozenset({"retry_safe"}),
    "dispatch_accepted": frozenset({"retry_safe"}),
    "reconciliation_blocked": frozenset({"reason"}),
    "run_linked": frozenset({"run_id"}),
    "workflow_failed": frozenset({"run_id", "conclusion", "retry_safe"}),
    "workflow_evidence_unverified": frozenset({"run_id", "reason"}),
    "workflow_succeeded": frozenset({"run_id"}),
    "workflow_status_observed": frozenset({"run_id", "status"}),
}
_CHECKPOINT_REASONS = frozenset(
    {
        "audit_evidence_unavailable",
        "preflight_unavailable",
        "source_revision_drift",
        "exclusivity_lost",
        "identity_changed",
        "ambiguous_runs",
        "correlation_changed",
        "required_activity_unverified",
    }
)

_NEXT_ACTIONS = {
    "reviewed": "Review the preservation and preflight evidence requirements, then approve this plan.",
    "dispatching": "Refresh this plan to reconcile the existing request; do not retry or clean up resources.",
    "dispatch_accepted": "Refresh this plan while GitHub links the existing run; do not dispatch again.",
    "dispatch_indeterminate": (
        "Inspect GitHub Actions for the displayed correlation ID, then refresh; do not retry or clean up resources."
    ),
    "queued": "Wait for protected-environment approval, then refresh this plan.",
    "running": "Allow the existing protected workflow to finish, then refresh this plan.",
    "dispatch_failed": "Reconcile the confirmed pre-dispatch result; retry is available only for a rejected dispatch.",
    "run_failed": (
        "Review the linked GitHub run and reconcile Azure and Terraform state; do not dispatch this plan again."
    ),
    "evidence_unverified": (
        "The run reported success but required pinned workflow steps were not verified; inspect the run and reconcile "
        "Azure and Terraform state."
    ),
    "review_required": "Create and review a new plan; preserve this plan and its evidence for audit.",
    "workflow_succeeded": (
        "Verify the live Azure resources and required recovery evidence before declaring deployment complete."
    ),
}


class DeploymentUnavailable(RuntimeError):
    """The reviewed workflow connector is not configured or reachable."""


class DeploymentConflict(RuntimeError):
    """The requested transition could duplicate or overlap a deployment."""


class DispatchRejected(RuntimeError):
    """GitHub conclusively rejected the dispatch before it was accepted."""


class DispatchIndeterminate(RuntimeError):
    """The dispatch may have reached GitHub; retrying could duplicate it."""


PUBLIC_DEPLOYMENT_UNAVAILABLE = (
    "GUI deployment is unavailable; review the protected GitHub Actions connector configuration and retry"
)
PUBLIC_DEPLOYMENT_CONFLICT = (
    "the deployment request cannot be completed in its current state; refresh and review the plan"
)
PUBLIC_DEPLOYMENT_STATUS_UNAVAILABLE = (
    "Deployment status details are unavailable; inspect the protected GitHub Actions workflow"
)

# These are the only exception messages allowed to cross the GUI boundary.
# Each value is fixed by this module; provider responses and arbitrary exception
# strings are deliberately excluded.
_PUBLIC_UNAVAILABLE_MESSAGES = frozenset(
    {
        "GUI deployment dispatch is disabled; configure the protected GitHub Actions connector",
        "the server-side GitHub repository is missing or invalid",
        "the server-side GitHub workflow ref is missing or invalid",
        "the server-side GitHub workflow credential is missing or invalid",
        "the server-side GitHub API origin is invalid",
        "the fixed workflow environment is invalid",
        "GitHub configured deployment ref metadata is malformed",
        "GitHub deployment workflow path does not match the fixed connector",
        "the fixed GitHub deployment workflow is disabled",
        "GitHub deployment workflow metadata is malformed",
        "GitHub deployment workflow content metadata is malformed",
        "GitHub deployment workflow content is malformed",
        "GitHub deployment workflow content size is inconsistent",
        "the configured ref does not contain the reviewed deployment workflow",
        "the fixed deployment workflow input contract is incomplete",
        "GitHub protected environment metadata is malformed",
        "GitHub protected environment reviewer metadata is malformed",
        "GitHub protected environment wait timer metadata is malformed",
        "GitHub protected environment branch policy metadata is malformed",
        "GitHub workflow status is unavailable",
        "GitHub workflow status is malformed",
        "GitHub workflow run status is unavailable",
        "GitHub workflow run status is malformed",
        "GitHub workflow activity is unavailable",
        "GitHub returned an invalid workflow run",
        "deployment plan storage is unavailable",
        "deployment plan storage is malformed",
        *{
            message
            for purpose in (
                "configured deployment ref",
                "deployment workflow",
                "deployment workflow content",
                "protected staging environment",
                "protected production environment",
                "protected staging environment variables",
                "protected production environment variables",
            )
            for message in (
                f"GitHub {purpose} is unavailable",
                f"the GitHub connector cannot inspect {purpose}; verify read permissions",
                f"GitHub {purpose} is missing or is not visible to the connector",
                f"GitHub {purpose} metadata exceeds the connector limit",
                f"GitHub {purpose} metadata is malformed",
            )
        },
        *{
            message
            for environment in ("staging", "production")
            for message in (
                f"the GitHub {environment} environment allows administrator approval bypass",
                f"the GitHub {environment} environment has no required reviewer protection",
                f"the GitHub {environment} environment allows reviewer self-approval",
                f"the GitHub {environment} environment has no deployment branch protection",
            )
        },
    }
)

_PUBLIC_CONFLICT_MESSAGES = frozenset(
    {
        "the reviewed deployment digest does not match",
        "retry is allowed only after GitHub rejected a dispatch before creating a run",
        "this reviewed plan has already been submitted",
        "The stored plan lacks reviewed source evidence; create and review a new plan",
        "this deployment attempt was already submitted",
        "this deployment plan is currently being updated; refresh and retry",
        "GitHub workflow, ref, or protected environment drifted; create and review a new plan",
        "invalid deployment plan identifier",
        "deployment plan is missing or expired",
        "deployment plans may be used only by the administrator who reviewed them",
        "deployment values must not contain credentials or tokens",
        "deployment configuration exceeds the fixed workflow limit",
        "ciphertext recovery metadata is invalid",
        "deployment network mode is invalid for the reviewed environment and phase",
        "reviewed Terraform state identity does not match the protected environment",
        "deployment plan has reached its safe attempt or checkpoint limit; create and review a new plan",
        *{f"another {environment} deployment is active" for environment in ("staging", "production")},
    }
)

_PUBLIC_PLAN_ERRORS = frozenset(
    {
        "Audit evidence could not be committed; no workflow was dispatched",
        "GitHub preflight became unavailable; no workflow was dispatched",
        "GitHub workflow, ref, or protected environment drifted; create and review a new plan",
        "GitHub conclusively rejected the workflow dispatch; correct access and retry",
        "Dispatch outcome is unknown; inspect GitHub Actions and do not retry this plan",
        "Multiple new workflow runs exist; inspect GitHub Actions before any retry",
        "The linked workflow correlation changed; inspect GitHub Actions",
        "The linked workflow identity changed; inspect GitHub Actions",
        "Deployment exclusivity was lost; inspect GitHub Actions before continuing",
        "The protected workflow ended unsuccessfully; review its GitHub evidence before retrying",
        "The protected workflow ended unsuccessfully; reconcile its evidence and Azure state without retrying",
        "The workflow reported success but required pinned job or step evidence is unavailable or incomplete",
        "The prior operation stopped before workflow dispatch; reconcile its checkpoints without redispatching",
        "The stored plan lacks reviewed source evidence; create and review a new plan",
    }
)


def public_deployment_error(exc: DeploymentUnavailable | DeploymentConflict) -> str:
    """Return only reviewed operator guidance for a deployment exception."""

    message = str(exc)
    if type(exc) is DeploymentUnavailable and message in _PUBLIC_UNAVAILABLE_MESSAGES:
        return message
    if type(exc) is DeploymentConflict and message in _PUBLIC_CONFLICT_MESSAGES:
        return message
    if isinstance(exc, DeploymentConflict):
        return PUBLIC_DEPLOYMENT_CONFLICT
    return PUBLIC_DEPLOYMENT_UNAVAILABLE


@dataclass(frozen=True, slots=True)
class WorkflowPreflight:
    """Security-relevant GitHub metadata bound into a reviewed plan."""

    commit_sha: str
    workflow_id: int
    workflow_blob_sha: str
    workflow_content_sha256: str
    environment_metadata_sha256: str
    environment: str
    required_reviewer_count: int
    admin_bypass_allowed: bool
    deployment_branch_policy_present: bool
    tf_state_resource_group: str
    tf_state_storage_account: str
    tf_state_container: str

    def review_payload(self) -> dict[str, Any]:
        return {
            "commit_sha": self.commit_sha,
            "workflow_id": self.workflow_id,
            "workflow_blob_sha": self.workflow_blob_sha,
            "workflow_content_sha256": self.workflow_content_sha256,
            "workflow_state": "active",
            "workflow_path": WORKFLOW_PATH,
            "input_contract": "exact_pinned_workflow_content",
            "environment": self.environment,
            "environment_metadata_sha256": self.environment_metadata_sha256,
            "required_reviewer_count": self.required_reviewer_count,
            "admin_bypass_allowed": self.admin_bypass_allowed,
            "deployment_branch_policy_present": self.deployment_branch_policy_present,
            "terraform_state_identity": {
                "resource_group": self.tf_state_resource_group,
                "storage_account": self.tf_state_storage_account,
                "container": self.tf_state_container,
            },
        }


@dataclass(frozen=True)
class WorkflowConfiguration:
    repository: str
    ref: str
    token: str

    @classmethod
    def from_environment(cls) -> WorkflowConfiguration:
        mode = os.getenv("OPERATOR_API_DEPLOYMENT_ORCHESTRATION_MODE", "disabled").strip().lower()
        if mode != "github_actions":
            raise DeploymentUnavailable(
                "GUI deployment dispatch is disabled; configure the protected GitHub Actions connector"
            )
        repository = os.getenv("OPERATOR_API_DEPLOYMENT_GITHUB_REPOSITORY", "").strip()
        ref = os.getenv("OPERATOR_API_DEPLOYMENT_GITHUB_REF", "main").strip()
        token = os.getenv("OPERATOR_API_DEPLOYMENT_GITHUB_TOKEN", "")
        repository_parts = repository.split("/")
        if _REPOSITORY.fullmatch(repository) is None or any(part in {".", ".."} for part in repository_parts):
            raise DeploymentUnavailable("the server-side GitHub repository is missing or invalid")
        if (
            _REF.fullmatch(ref) is None
            or ref.startswith("/")
            or ref.endswith(("/", ".", ".lock"))
            or ".." in ref
            or "//" in ref
            or any(part.startswith(".") for part in ref.split("/"))
        ):
            raise DeploymentUnavailable("the server-side GitHub workflow ref is missing or invalid")
        if _GITHUB_TOKEN.fullmatch(token) is None:
            raise DeploymentUnavailable("the server-side GitHub workflow credential is missing or invalid")
        return cls(repository=repository, ref=ref, token=token)
