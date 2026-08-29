"""Recipient CSV import planning: preview/apply plan construction for the
operator API.

Holds the import plan models and pure planning helpers
(RecipientImportColumnMapping .. _recipient_import_preview_payload) that the
recipient import routes in kp_operator_api.routers consume. The routes own
auditing, authorization, and the two-phase preview->apply handshake; this
module owns only how a CSV upload becomes an auditable, replayable plan.

Trust boundary: same-process helper code. No network I/O; the only shared
state is the advisory-lock key and the in-process SQLite serialization lock
used by _serialize_recipient_import_write. Fail-closed: any CSV parse error
becomes a ValidationError_ before a plan can be built, and the plan digest
is keyed so the apply route can detect preview/apply drift.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any, Literal

from kp_database.models import Recipient
from kp_domain_models import models as dm
from kp_telemetry.errors import ValidationError_
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.recipient_import import (
    MAX_RECIPIENT_CSV_BYTES,
    MAX_RECIPIENT_CSV_COLUMNS,
    ParsedRecipient,
    ParsedRecipientCsv,
    RecipientCsvError,
    RecipientHeaderMode,
    parse_recipient_csv,
    recipient_import_digest,
    validate_csv_text,
)
from kp_operator_api.send_policy import resolve_recipient_policy

_RECIPIENT_IMPORT_ADVISORY_LOCK_KEY = 0x4B505243494D5054  # "KPRCIMPT"
_RECIPIENT_IMPORT_LOCAL_LOCK = threading.Lock()


class RecipientImportColumnMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mailbox: int | None = Field(default=None, ge=0, lt=MAX_RECIPIENT_CSV_COLUMNS)
    display_name: int | None = Field(default=None, ge=0, lt=MAX_RECIPIENT_CSV_COLUMNS)
    department: int | None = Field(default=None, ge=0, lt=MAX_RECIPIENT_CSV_COLUMNS)


class RecipientImportPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    csv_text: str = Field(min_length=1, max_length=MAX_RECIPIENT_CSV_BYTES)
    department: str = Field(default="", max_length=255)
    header_mode: RecipientHeaderMode = "auto"
    mapping: RecipientImportColumnMapping = Field(default_factory=RecipientImportColumnMapping)
    merge_existing: Literal["skip", "update"] = "skip"
    deactivate_missing: StrictBool = False

    @field_validator("csv_text")
    @classmethod
    def bound_csv_bytes(cls, value: str) -> str:
        try:
            return validate_csv_text(value)
        except RecipientCsvError as exc:
            raise ValueError(str(exc)) from None

    @field_validator("department")
    @classmethod
    def normalize_default_department(cls, value: str) -> str:
        return value.strip()


class RecipientImportApplyRequest(RecipientImportPreviewRequest):
    preview_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    deactivate_missing_confirm: StrictBool = False


class RecipientsImport(BaseModel):
    """Compatibility request for bounded, create-only legacy imports."""

    model_config = ConfigDict(extra="forbid")

    csv_text: str = Field(min_length=1, max_length=MAX_RECIPIENT_CSV_BYTES)
    department: str = Field(default="", max_length=255)

    @field_validator("csv_text")
    @classmethod
    def bound_csv_bytes(cls, value: str) -> str:
        try:
            return validate_csv_text(value)
        except RecipientCsvError as exc:
            raise ValueError(str(exc)) from None

    @field_validator("department")
    @classmethod
    def normalize_default_department(cls, value: str) -> str:
        return value.strip()


@dataclass(frozen=True)
class _RecipientImportPlan:
    parsed: ParsedRecipientCsv
    create_rows: tuple[ParsedRecipient, ...]
    update_rows: tuple[tuple[Recipient, ParsedRecipient], ...]
    deactivate_rows: tuple[Recipient, ...]
    counts: dict[str, int]
    digest: str
    can_apply: bool


def _recipient_is_directory_owned(recipient: Recipient) -> bool:
    return bool(
        recipient.directory_owned
        or recipient.directory_source
        or recipient.directory_object_id_hash
        or recipient.last_snapshot_source == "microsoft365"
    )


def _recipient_import_mapping(body: RecipientImportPreviewRequest) -> dict[str, int | None]:
    return body.mapping.model_dump(exclude_unset=True)


@contextmanager
def _serialize_recipient_import_write(session: Session) -> Iterator[None]:
    """Serialize all CSV recipient writes before their authoritative re-plan."""

    if session.get_bind().dialect.name == "postgresql":
        session.execute(
            text("SELECT pg_advisory_xact_lock(:recipient_import_lock_key)"),
            {"recipient_import_lock_key": _RECIPIENT_IMPORT_ADVISORY_LOCK_KEY},
        )
        yield
        return
    # SQLite has no transaction advisory locks. Its supported development and
    # unit-test path is serialized within this API process instead of issuing
    # PostgreSQL-only SQL.
    with _RECIPIENT_IMPORT_LOCAL_LOCK:
        yield


def _recipient_import_retryable_db_conflict(exc: DBAPIError) -> bool:
    sqlstate = getattr(exc.orig, "sqlstate", None) or getattr(exc.orig, "pgcode", None)
    if isinstance(exc, IntegrityError):
        # SQLite does not expose a PostgreSQL SQLSTATE. Its IntegrityError is
        # still the stable uniqueness-race boundary for the development path.
        return sqlstate is None or sqlstate == "23505"
    return sqlstate in {"40001", "40P01"}


def _rollback_recipient_import_conflict(session: Session) -> None:
    with suppress(DBAPIError):
        session.rollback()
    # The dependency closes a failed session if rollback itself fails. Do not
    # reflect driver text or destabilize an already-recognized race response.


def _recipient_import_current_fingerprint(recipient: Recipient) -> str:
    current = "\0".join(
        (
            recipient.employee_key or "",
            recipient.mailbox or "",
            recipient.display_name or "",
            recipient.department or "",
            recipient.status.value,
            recipient.last_snapshot_source or "",
            recipient.directory_source or "",
            recipient.directory_object_id_hash or "",
            str(bool(recipient.directory_owned)),
        )
    )
    return hashlib.sha256(current.encode("utf-8")).hexdigest()


def _recipient_import_plan(
    body: RecipientImportPreviewRequest,
    session: Session,
    settings: OperatorApiSettings,
    *,
    lock_rows: bool,
) -> _RecipientImportPlan:
    salt = settings.require_recipient_hash_salt()
    allowlist, unrestricted = resolve_recipient_policy(settings)
    try:
        parsed = parse_recipient_csv(
            body.csv_text,
            requested_mapping=_recipient_import_mapping(body),
            default_department=body.department,
            salt=salt,
            allowlist=allowlist,
            unrestricted=unrestricted,
            header_mode=body.header_mode,
        )
    except RecipientCsvError as exc:
        raise ValidationError_(str(exc)) from None

    mailbox_hashes = [recipient.mailbox_hash for recipient in parsed.recipients]
    existing_rows: list[Recipient] = []
    if mailbox_hashes:
        existing_query = select(Recipient).where(
            Recipient.mailbox_sha256.in_(mailbox_hashes),
            Recipient.deleted_at.is_(None),
        )
        if lock_rows:
            existing_query = existing_query.with_for_update()
        existing_rows = list(session.scalars(existing_query))
    existing_by_hash = {recipient.mailbox_sha256: recipient for recipient in existing_rows}
    create_rows: list[ParsedRecipient] = []
    update_rows: list[tuple[Recipient, ParsedRecipient]] = []
    existing_count = 0
    operation_bindings: list[dict[str, Any]] = []
    for parsed_recipient in parsed.recipients:
        existing = existing_by_hash.get(parsed_recipient.mailbox_hash)
        if existing is None:
            create_rows.append(parsed_recipient)
            operation_bindings.append(
                {
                    "row": parsed_recipient.row,
                    "mailbox_hash": parsed_recipient.mailbox_hash,
                    "operation": "create",
                }
            )
            continue
        if body.merge_existing == "update" and not _recipient_is_directory_owned(existing):
            update_rows.append((existing, parsed_recipient))
            operation = "update"
        else:
            existing_count += 1
            operation = "existing_directory" if _recipient_is_directory_owned(existing) else "existing_skip"
        operation_bindings.append(
            {
                "row": parsed_recipient.row,
                "mailbox_hash": parsed_recipient.mailbox_hash,
                "operation": operation,
                "recipient_id": str(existing.recipient_id),
                "current_fingerprint": _recipient_import_current_fingerprint(existing),
            }
        )

    deactivate_rows: list[Recipient] = []
    deactivation_safe = not body.deactivate_missing or not (parsed.blocked or parsed.invalid or parsed.duplicate)
    if body.deactivate_missing and deactivation_safe:
        deactivation_query = select(Recipient).where(
            Recipient.last_snapshot_source == "csv",
            Recipient.directory_owned.is_(False),
            Recipient.directory_source.is_(None),
            Recipient.directory_object_id_hash.is_(None),
            Recipient.deleted_at.is_(None),
            Recipient.status == dm.RecipientStatus.ACTIVE,
        )
        if mailbox_hashes:
            deactivation_query = deactivation_query.where(Recipient.mailbox_sha256.not_in(mailbox_hashes))
        if lock_rows:
            deactivation_query = deactivation_query.with_for_update()
        deactivate_rows = list(session.scalars(deactivation_query))

    counts = {
        "created": len(create_rows),
        "updateable": len(update_rows),
        "existing": existing_count,
        "blocked": parsed.blocked,
        "invalid": parsed.invalid,
        "duplicate": parsed.duplicate,
        "deactivateable": len(deactivate_rows),
    }
    digest_payload = {
        "version": 1,
        "content_hash": parsed.content_hash,
        "input_rows": parsed.input_rows,
        "header_mode": body.header_mode,
        "header_detected": parsed.header_detected,
        "mapping": parsed.mapping,
        "default_department": body.department,
        "merge_existing": body.merge_existing,
        "deactivate_missing": body.deactivate_missing,
        "recipient_policy": {
            "unrestricted": unrestricted,
            "allowlist": sorted(allowlist),
        },
        "counts": counts,
        "operations": operation_bindings,
        "deactivations": [
            {
                "recipient_id": str(recipient.recipient_id),
                "mailbox_hash": recipient.mailbox_sha256,
                "current_fingerprint": _recipient_import_current_fingerprint(recipient),
            }
            for recipient in deactivate_rows
        ],
        "deactivation_safe": deactivation_safe,
    }
    return _RecipientImportPlan(
        parsed=parsed,
        create_rows=tuple(create_rows),
        update_rows=tuple(update_rows),
        deactivate_rows=tuple(deactivate_rows),
        counts=counts,
        digest=recipient_import_digest(settings.require_secret_key(), digest_payload),
        can_apply=deactivation_safe,
    )


def _recipient_import_options(body: RecipientImportPreviewRequest, plan: _RecipientImportPlan) -> dict[str, Any]:
    return {
        "mapping": plan.parsed.mapping,
        "merge_existing": body.merge_existing,
        "deactivate_missing": body.deactivate_missing,
        "header_mode": body.header_mode,
        "header_detected": plan.parsed.header_detected,
    }


def _recipient_import_issues(plan: _RecipientImportPlan) -> list[dict[str, Any]]:
    return [{"row": issue.row, "code": issue.code} for issue in plan.parsed.errors]


def _recipient_import_audit_detail(
    body: RecipientImportPreviewRequest,
    plan: _RecipientImportPlan,
) -> dict[str, Any]:
    return {
        "counts": plan.counts,
        "options": _recipient_import_options(body, plan),
        "preview_digest": plan.digest,
        "input_rows": plan.parsed.input_rows,
    }


def _apply_recipient_import_plan(plan: _RecipientImportPlan, session: Session) -> None:
    for parsed_recipient in plan.create_rows:
        session.add(
            Recipient(
                recipient_id=uuid.uuid4(),
                employee_key=parsed_recipient.mailbox,
                mailbox=parsed_recipient.mailbox,
                mailbox_sha256=parsed_recipient.mailbox_hash,
                display_name=parsed_recipient.display_name,
                department=parsed_recipient.department,
                is_test_account=False,
                status=dm.RecipientStatus.ACTIVE,
                last_snapshot_source="csv",
                directory_owned=False,
            )
        )
    for recipient, parsed_recipient in plan.update_rows:
        recipient.display_name = parsed_recipient.display_name
        recipient.department = parsed_recipient.department
        if recipient.last_snapshot_source == "csv" and recipient.status is dm.RecipientStatus.DEPARTED:
            recipient.status = dm.RecipientStatus.ACTIVE
        recipient.last_snapshot_source = "csv"
    for recipient in plan.deactivate_rows:
        recipient.status = dm.RecipientStatus.DEPARTED


def _recipient_import_preview_payload(
    body: RecipientImportPreviewRequest,
    plan: _RecipientImportPlan,
) -> dict[str, Any]:
    return {
        "preview_digest": plan.digest,
        "input_rows": plan.parsed.input_rows,
        "header_mode": body.header_mode,
        "header_detected": plan.parsed.header_detected,
        "columns": list(plan.parsed.columns),
        "mapping": plan.parsed.mapping,
        "merge_existing": body.merge_existing,
        "deactivate_missing": body.deactivate_missing,
        "counts": plan.counts,
        "errors": _recipient_import_issues(plan),
        "errors_truncated": (
            plan.parsed.blocked + plan.parsed.invalid + plan.parsed.duplicate > len(plan.parsed.errors)
        ),
        "can_apply": plan.can_apply,
        "deactivation_requires_clean_preview": body.deactivate_missing and not plan.can_apply,
    }
