"""Single source of truth for recipient personal-data stores (KP-AUD-003).

Every table that holds — or directly links — a data subject's personal data is
registered here so the three personal-data lifecycle operations stay in step:

* the DSR **access export** (``routes/privacy.export_privacy_request``),
* the DSR **erasure** / recipient delete (``privacy.erase_recipient_data``), and
* the time-based **retention** purge (``retention_jobs.process_retention``).

Before KP-AUD-003 the reply-receipt table and the awareness ledger silently
escaped this lifecycle: erasure and retention never touched reply receipts, and
the access export disclosed neither reply/reported receipts nor the awareness
ledger. The registry makes each store's coverage explicit and testable; the
hermetic coverage test (``test_personal_data_registry``) fails if a store that
must be exported is missing from the export payload.

This is deliberately a catalog plus one shared model tuple, not a generic
deletion framework: retention and erasure keep their own table-specific
queries. The one place the query shape is genuinely identical — the two
assignment-linked mail-receipt tables — is shared through
``ASSIGNMENT_LINKED_RECEIPT_MODELS`` so reply and reported receipts cannot drift
apart again.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from kp_database.base import Base
from kp_database.models import (
    AwarenessLedgerEntry,
    Recipient,
    RecipientAssignment,
    RecipientExclusion,
    ReplyMailReceipt,
    ReportedMailReceipt,
    TrackingEvent,
    TrackingToken,
    TrainingAssignment,
)


@dataclass(frozen=True)
class PersonalDataStore:
    """One table in the recipient personal-data lifecycle.

    ``name`` is the stable identifier and, for an exported store, the exact key
    the DSR access-export payload uses for that store's section. The three
    boolean flags record which lifecycle operations are responsible for the
    store; ``note`` documents any deliberate asymmetry (an intentionally
    retained or non-disclosed store).
    """

    name: str
    model: type[Base]
    in_export: bool
    in_erasure: bool
    in_retention: bool
    note: str = ""


PERSONAL_DATA_STORES: Final[tuple[PersonalDataStore, ...]] = (
    PersonalDataStore(
        name="records",
        model=Recipient,
        in_export=True,
        in_erasure=True,
        in_retention=False,
        note=(
            "Erasure anonymizes the recipient to a tombstone (deleted_at plus a random mailbox "
            "digest) rather than deleting the row, so historic aggregate/audit references stay "
            "structurally valid."
        ),
    ),
    PersonalDataStore(
        name="assignments",
        model=RecipientAssignment,
        in_export=True,
        in_erasure=True,
        in_retention=True,
    ),
    PersonalDataStore(
        name="tracking_tokens",
        model=TrackingToken,
        in_export=False,
        in_erasure=True,
        in_retention=True,
        note=(
            "A tracking token carries a delivery HMAC secret and is an internal linkage, not "
            "subject-facing content, so it is erased and retention-purged but never disclosed in "
            "an access export. It is collected during export only to resolve the subject's events."
        ),
    ),
    PersonalDataStore(
        name="events",
        model=TrackingEvent,
        in_export=True,
        in_erasure=True,
        in_retention=True,
    ),
    PersonalDataStore(
        name="training_assignments",
        model=TrainingAssignment,
        in_export=True,
        in_erasure=True,
        in_retention=False,
        note=(
            "Training assignments are erased with the subject but are not part of the time-based "
            "retention batch; they follow the raw assignment lifecycle."
        ),
    ),
    PersonalDataStore(
        name="exclusions",
        model=RecipientExclusion,
        in_export=True,
        in_erasure=True,
        in_retention=False,
    ),
    PersonalDataStore(
        name="reported_receipts",
        model=ReportedMailReceipt,
        in_export=True,
        in_erasure=True,
        in_retention=True,
    ),
    PersonalDataStore(
        name="reply_receipts",
        model=ReplyMailReceipt,
        in_export=True,
        in_erasure=True,
        in_retention=True,
    ),
    PersonalDataStore(
        name="awareness_ledger",
        model=AwarenessLedgerEntry,
        in_export=True,
        in_erasure=False,
        in_retention=True,
        note=(
            "The awareness ledger is PII-free and pseudonymous (keyed HMAC, no recipient or "
            "assignment foreign key). It is intentionally RETAINED through erasure as anonymous "
            "aggregate evidence and expires only on its own five-year horizon in the retention "
            "job. The access export discloses the subject's own pseudonymous entries, resolved "
            "via the governed pseudonym key, never recipient attributes."
        ),
    ),
)

#: The two assignment-linked mail-receipt tables share an identical delete-by-
#: assignment and purge-by-``received_at`` shape. Erasure and retention iterate
#: this tuple so reply and reported receipts cannot diverge again (KP-AUD-003).
ASSIGNMENT_LINKED_RECEIPT_MODELS: Final = (ReportedMailReceipt, ReplyMailReceipt)


def exported_store_names() -> frozenset[str]:
    """Names of the stores that must appear in the DSR access export."""

    return frozenset(store.name for store in PERSONAL_DATA_STORES if store.in_export)
