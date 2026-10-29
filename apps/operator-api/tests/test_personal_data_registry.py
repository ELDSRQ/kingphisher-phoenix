"""Hermetic coverage of the personal-data store registry (KP-AUD-003).

Runs without a database: it asserts that every personal-data store that must be
disclosed in a DSR access export is actually wired into the export payload, and
that the registry itself is internally consistent. This is the regression guard
for the bug where reply receipts and the awareness ledger silently escaped the
personal-data lifecycle.
"""

from __future__ import annotations

from kp_database.models import ReplyMailReceipt, ReportedMailReceipt
from kp_database.personal_data import (
    ASSIGNMENT_LINKED_RECEIPT_MODELS,
    PERSONAL_DATA_STORES,
    exported_store_names,
)
from kp_operator_api.routes.privacy import _PrivacyExportData, build_privacy_export_payload


def test_every_exported_store_appears_in_export_payload() -> None:
    # An empty export still carries one section per exported store, so a store
    # registered for export cannot be forgotten in the payload assembly.
    payload = build_privacy_export_payload(
        privacy_request_id="00000000-0000-0000-0000-000000000000",
        request_type="access_export",
        data=_PrivacyExportData(),
    )
    missing = exported_store_names() - payload.keys()
    assert not missing, f"exported stores absent from the export payload: {sorted(missing)}"

    # The stores introduced by KP-AUD-003 must be present by name.
    for required in ("reply_receipts", "reported_receipts", "awareness_ledger"):
        assert required in exported_store_names()
        assert required in payload


def test_registry_is_internally_consistent() -> None:
    names = [store.name for store in PERSONAL_DATA_STORES]
    assert len(names) == len(set(names)), "personal-data store names must be unique"

    for store in PERSONAL_DATA_STORES:
        # No dead entry: a registered store participates in at least one op.
        assert store.in_export or store.in_erasure or store.in_retention, store.name
        # Any non-exported store must document why it is withheld from export.
        if not store.in_export:
            assert store.note, f"non-exported store {store.name} must justify its omission"


def test_assignment_linked_receipts_are_fully_covered() -> None:
    # Reply and reported receipts share the lifecycle and must be exported,
    # erased, and retention-purged identically (the KP-AUD-003 asymmetry).
    receipt_models = {ReportedMailReceipt, ReplyMailReceipt}
    assert set(ASSIGNMENT_LINKED_RECEIPT_MODELS) == receipt_models

    receipt_stores = [store for store in PERSONAL_DATA_STORES if store.model in receipt_models]
    assert {store.model for store in receipt_stores} == receipt_models
    for store in receipt_stores:
        assert store.in_export and store.in_erasure and store.in_retention, store.name
