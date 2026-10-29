"""Pure phish-cloning and forward-a-phish curation logic.

Extracted from ``kp_operator_api`` (R-03) so the worker deployable no longer
depends on the control-plane app package: both the operator API and the workers
import this package. Cloning a real phish into a neutralized DRAFT template
(``clone_real_message``) and auto-curating a forwarded phish
(``curate_forwarded_message``) live here; neither touches the operator API.
"""

from kp_curation.clone_service import ClonedTemplate, CloneError, clone_real_message
from kp_curation.curation_service import (
    CURATED_MODEL_ID,
    CurationResult,
    curate_forwarded_message,
    curation_hash,
)
from kp_curation.threat_bundle import (
    BundleArtifact,
    BundleError,
    VerifiedBundle,
    canonical_payload,
    sign_bundle,
    verify_bundle,
)
from kp_curation.threat_library import (
    FAILURE_THRESHOLD,
    PARSER_VERSION,
    IngestResult,
    SafeArtifact,
    SourcePolicyHealth,
    artifact_hash,
    build_safe_artifact,
    ingest_threat_artifact,
    policy_admits_ingestion,
    source_policy_health,
)

__all__ = [
    "CURATED_MODEL_ID",
    "FAILURE_THRESHOLD",
    "PARSER_VERSION",
    "BundleArtifact",
    "BundleError",
    "ClonedTemplate",
    "CloneError",
    "CurationResult",
    "IngestResult",
    "SafeArtifact",
    "SourcePolicyHealth",
    "VerifiedBundle",
    "artifact_hash",
    "build_safe_artifact",
    "canonical_payload",
    "clone_real_message",
    "curate_forwarded_message",
    "curation_hash",
    "ingest_threat_artifact",
    "policy_admits_ingestion",
    "sign_bundle",
    "source_policy_health",
    "verify_bundle",
]
