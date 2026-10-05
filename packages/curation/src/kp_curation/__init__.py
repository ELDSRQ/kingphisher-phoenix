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

__all__ = [
    "CURATED_MODEL_ID",
    "ClonedTemplate",
    "CloneError",
    "CurationResult",
    "clone_real_message",
    "curate_forwarded_message",
    "curation_hash",
]
