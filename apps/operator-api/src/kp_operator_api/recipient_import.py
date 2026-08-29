"""Bounded, non-mutating parsing for reviewed recipient CSV imports."""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
from dataclasses import dataclass
from typing import Any, Literal

from kp_database.privacy import hash_mailbox
from kp_domain_models.policy import is_recipient_allowed, mailbox_domain

MAX_RECIPIENT_CSV_BYTES = 512 * 1024
MAX_RECIPIENT_CSV_ROWS = 5_000
MAX_RECIPIENT_CSV_COLUMNS = 50
MAX_RECIPIENT_CSV_CELL_CHARS = 1_024
MAX_RECIPIENT_IMPORT_ERRORS = 20
MAX_RECIPIENT_HEADER_LABEL_CHARS = 128

RecipientHeaderMode = Literal["auto", "first_row", "none"]

_HEADER_ALIASES = {
    "mailbox": frozenset(
        {
            "email",
            "emailaddress",
            "mail",
            "mailbox",
            "userprincipalname",
            "upn",
        }
    ),
    "display_name": frozenset({"displayname", "fullname", "name"}),
    "department": frozenset({"department", "dept", "division", "team"}),
}
_HEADER_LABELS = {
    "mailbox": "Mailbox",
    "display_name": "Name",
    "department": "Department",
}


class RecipientCsvError(ValueError):
    """Safe validation failure that never contains CSV cell contents."""


@dataclass(frozen=True)
class RecipientImportIssue:
    row: int
    code: str


@dataclass(frozen=True)
class ParsedRecipient:
    row: int
    mailbox: str
    mailbox_hash: str
    display_name: str | None
    department: str | None


@dataclass(frozen=True)
class ParsedRecipientCsv:
    input_rows: int
    header_detected: bool
    columns: tuple[dict[str, Any], ...]
    mapping: dict[str, int | None]
    recipients: tuple[ParsedRecipient, ...]
    blocked: int
    invalid: int
    duplicate: int
    errors: tuple[RecipientImportIssue, ...]
    content_hash: str


def validate_csv_text(csv_text: str) -> str:
    """Validate the transport bound and return the unchanged text."""

    if not csv_text:
        raise RecipientCsvError("CSV text is required")
    if len(csv_text.encode("utf-8")) > MAX_RECIPIENT_CSV_BYTES:
        raise RecipientCsvError(f"CSV text must be at most {MAX_RECIPIENT_CSV_BYTES} UTF-8 bytes")
    return csv_text


def _normalized_header(value: str) -> str:
    return "".join(character for character in value.strip().lower() if character.isalnum())


def _detected_header_mapping(row: list[str]) -> dict[str, int]:
    detected: dict[str, int] = {}
    for index, value in enumerate(row):
        normalized = _normalized_header(value)
        for field, aliases in _HEADER_ALIASES.items():
            if field not in detected and normalized in aliases:
                detected[field] = index
    return detected


def _resolved_mapping(
    *,
    requested: dict[str, int | None],
    detected: dict[str, int],
    header_detected: bool,
    column_count: int,
) -> dict[str, int | None]:
    defaults: dict[str, int | None]
    if header_detected and "mailbox" in detected:
        defaults = {
            "mailbox": detected["mailbox"],
            "display_name": detected.get("display_name"),
            "department": detected.get("department"),
        }
    else:
        defaults = {
            "mailbox": 0,
            "display_name": 1 if column_count > 1 else None,
            "department": 2 if column_count > 2 else None,
        }
    resolved = {field: requested.get(field, defaults[field]) for field in defaults}
    mailbox_index = resolved["mailbox"]
    if mailbox_index is None:
        raise RecipientCsvError("mailbox column mapping is required")
    selected = [index for index in resolved.values() if index is not None]
    if len(selected) != len(set(selected)):
        raise RecipientCsvError("CSV column mappings must use distinct columns")
    if any(index < 0 or index >= column_count for index in selected):
        raise RecipientCsvError("CSV column mapping is outside the available columns")
    return resolved


def _safe_header_label(value: str, index: int) -> str:
    printable = "".join(character if character.isprintable() else " " for character in value)
    normalized = " ".join(printable.split())
    if not normalized:
        return f"Column {index + 1}"
    if len(normalized) > MAX_RECIPIENT_HEADER_LABEL_CHARS:
        normalized = f"{normalized[: MAX_RECIPIENT_HEADER_LABEL_CHARS - 1]}…"
    return f"Column {index + 1} — {normalized}"


def _column_payload(
    first_row: list[str],
    *,
    header_detected: bool,
    header_mode: RecipientHeaderMode,
    column_count: int,
) -> tuple[dict[str, Any], ...]:
    labels_by_index: dict[int, str] = {}
    if header_mode == "first_row":
        labels_by_index.update(
            (index, _safe_header_label(first_row[index] if index < len(first_row) else "", index))
            for index in range(column_count)
        )
    elif header_detected:
        for field, index in _detected_header_mapping(first_row).items():
            labels_by_index[index] = _HEADER_LABELS[field]
    return tuple(
        {
            "index": index,
            "label": labels_by_index.get(index, f"Column {index + 1}"),
        }
        for index in range(column_count)
    )


def parse_recipient_csv(
    csv_text: str,
    *,
    requested_mapping: dict[str, int | None],
    default_department: str | None,
    salt: bytes,
    allowlist: frozenset[str],
    unrestricted: bool,
    header_mode: RecipientHeaderMode = "auto",
) -> ParsedRecipientCsv:
    """Parse a bounded CSV into a PII-minimized preview plan."""

    validate_csv_text(csv_text)
    try:
        rows = list(csv.reader(io.StringIO(csv_text), strict=True))
    except csv.Error as exc:
        raise RecipientCsvError("CSV syntax is invalid") from exc
    if len(rows) > MAX_RECIPIENT_CSV_ROWS:
        raise RecipientCsvError(f"CSV must contain at most {MAX_RECIPIENT_CSV_ROWS} rows including its header")
    if any(len(row) > MAX_RECIPIENT_CSV_COLUMNS for row in rows):
        raise RecipientCsvError(f"CSV rows must contain at most {MAX_RECIPIENT_CSV_COLUMNS} columns")
    if any(len(cell) > MAX_RECIPIENT_CSV_CELL_CHARS for row in rows for cell in row):
        raise RecipientCsvError(f"CSV cells must contain at most {MAX_RECIPIENT_CSV_CELL_CHARS} characters")

    populated = [(index, row) for index, row in enumerate(rows, start=1) if any(cell.strip() for cell in row)]
    if not populated:
        raise RecipientCsvError("CSV contains no recipient rows")
    first_row_number, first_row = populated[0]
    detected = _detected_header_mapping(first_row)
    header_detected = header_mode == "first_row" or (header_mode == "auto" and "mailbox" in detected)
    column_count = max(len(row) for _, row in populated)
    mapping = _resolved_mapping(
        requested=requested_mapping,
        detected=detected,
        header_detected=header_detected,
        column_count=column_count,
    )
    data_rows = populated[1:] if header_detected else populated
    issues: list[RecipientImportIssue] = []
    recipients: list[ParsedRecipient] = []
    blocked = invalid = duplicate = 0
    seen_hashes: set[str] = set()
    normalized_default_department = (default_department or "").strip() or None

    def issue(row: int, code: str) -> None:
        if len(issues) < MAX_RECIPIENT_IMPORT_ERRORS:
            issues.append(RecipientImportIssue(row=row, code=code))

    def mapped_value(row: list[str], index: int | None) -> str:
        return row[index].strip() if index is not None and index < len(row) else ""

    for row_number, row in data_rows:
        mailbox_index = mapping["mailbox"]
        if mailbox_index is None or mailbox_index >= len(row):
            invalid += 1
            issue(row_number, "missing_mailbox")
            continue
        mailbox = row[mailbox_index].strip().lower()
        if mailbox_domain(mailbox) is None:
            invalid += 1
            issue(row_number, "invalid_mailbox")
            continue
        if not unrestricted and not is_recipient_allowed(mailbox, allowlist):
            blocked += 1
            issue(row_number, "domain_not_allowed")
            continue

        display_index = mapping["display_name"]
        department_index = mapping["department"]
        display_name = mapped_value(row, display_index)
        department = mapped_value(row, department_index)
        if len(display_name) > 255:
            invalid += 1
            issue(row_number, "name_too_long")
            continue
        if len(department) > 255 or (normalized_default_department and len(normalized_default_department) > 255):
            invalid += 1
            issue(row_number, "department_too_long")
            continue
        mailbox_hash = hash_mailbox(mailbox, salt)
        if mailbox_hash in seen_hashes:
            duplicate += 1
            issue(row_number, "duplicate_mailbox")
            continue
        seen_hashes.add(mailbox_hash)
        recipients.append(
            ParsedRecipient(
                row=row_number,
                mailbox=mailbox,
                mailbox_hash=mailbox_hash,
                display_name=display_name or None,
                department=department or normalized_default_department,
            )
        )

    if not recipients and blocked == 0 and invalid == 0 and duplicate == 0:
        raise RecipientCsvError(f"CSV contains no recipient rows after the header on row {first_row_number}")
    return ParsedRecipientCsv(
        input_rows=len(data_rows),
        header_detected=header_detected,
        columns=_column_payload(
            first_row,
            header_detected=header_detected,
            header_mode=header_mode,
            column_count=column_count,
        ),
        mapping=mapping,
        recipients=tuple(recipients),
        blocked=blocked,
        invalid=invalid,
        duplicate=duplicate,
        errors=tuple(issues),
        content_hash=hashlib.sha256(csv_text.encode("utf-8")).hexdigest(),
    )


def recipient_import_digest(secret_key: bytes, payload: dict[str, Any]) -> str:
    """Bind a preview without exposing its PII-bearing canonical plan."""

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hmac.new(secret_key, b"kp-recipient-import-v1\0" + canonical, hashlib.sha256).hexdigest()
