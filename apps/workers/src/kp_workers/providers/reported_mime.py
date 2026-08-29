"""Strict, non-rendering extraction of correlation evidence from reported mail."""

from __future__ import annotations

import base64
import binascii
import quopri
import re
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from typing import Any, Literal

_CORRELATION_HEADER = "X-KP-Report-Correlation"
_OPAQUE_CANDIDATE = re.compile(r"[A-Za-z0-9._~-]{16,256}\Z")
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,78}\Z")
_MAX_CORRELATION_HEADER_VALUE_CHARS = 1024
_VALID_TRANSFER_ENCODINGS = frozenset({"7bit", "8bit", "binary", "base64", "quoted-printable"})
_INVALID_QUOTED_PRINTABLE = re.compile(rb"=(?![0-9A-Fa-f]{2}|\r?\n)")
_COMPRESSED_MEDIA_TYPES = frozenset(
    {
        "application/gzip",
        "application/vnd.rar",
        "application/x-7z-compressed",
        "application/x-gzip",
        "application/x-rar-compressed",
        "application/zip",
    }
)


class ReportedMimeError(ValueError):
    """A bounded, content-redacted MIME parsing failure."""


@dataclass(frozen=True)
class CorrelationEvidence:
    """Untrusted candidate data; this is not proof that a report is valid."""

    candidate: str
    header_name: str
    source: Literal["wrapper", "attached_original", "nested_message"]
    depth: int
    part_path: tuple[int, ...]
    message_id: str | None


@dataclass(frozen=True)
class ReportedMimeResult:
    evidence: tuple[CorrelationEvidence, ...]
    disposition: Literal["none", "single", "ambiguous"]
    candidate: str | None
    parts_seen: int
    attachments_seen: int
    decoded_bytes: int
    invalid_candidate_count: int
    compressed_parts_skipped: int


class ReportedMimeParser:
    """Extract opaque correlation candidates without rendering any content."""

    def __init__(
        self,
        *,
        correlation_header: str = _CORRELATION_HEADER,
        max_total_bytes: int = 5 * 1024 * 1024,
        max_decoded_bytes: int = 8 * 1024 * 1024,
        max_depth: int = 4,
        max_parts: int = 64,
        max_attachments: int = 16,
        max_correlation_headers: int = 32,
    ) -> None:
        if _HEADER_NAME.fullmatch(correlation_header) is None:
            raise ValueError("correlation header is malformed")
        if max_total_bytes < 1 or max_decoded_bytes < 1:
            raise ValueError("MIME byte limits must be positive")
        if max_depth < 0 or max_parts < 1 or max_attachments < 0 or max_correlation_headers < 1:
            raise ValueError("MIME structure limits are invalid")
        self._correlation_header = correlation_header
        self._max_total_bytes = max_total_bytes
        self._max_decoded_bytes = max_decoded_bytes
        self._max_depth = max_depth
        self._max_parts = max_parts
        self._max_attachments = max_attachments
        self._max_correlation_headers = max_correlation_headers

    @property
    def max_total_bytes(self) -> int:
        return self._max_total_bytes

    def parse(self, raw_message: bytes) -> ReportedMimeResult:
        if not raw_message or len(raw_message) > self._max_total_bytes:
            raise ReportedMimeError("reported MIME exceeds the configured total byte limit")
        try:
            root = BytesParser(policy=policy.default).parsebytes(raw_message)
        except (MemoryError, RecursionError, ValueError):
            raise ReportedMimeError("reported MIME is malformed") from None
        if root.defects:
            raise ReportedMimeError("reported MIME is malformed")

        evidence: list[CorrelationEvidence] = []
        invalid_candidates = 0
        parts_seen = 0
        attachments_seen = 0
        decoded_bytes = 0
        compressed_parts = 0
        correlation_headers_seen = 0
        # message, depth, path, inside an attached original
        pending: list[tuple[Message, int, tuple[int, ...], bool]] = [(root, 0, (), False)]

        while pending:
            message, depth, path, attached = pending.pop()
            if depth > self._max_depth:
                raise ReportedMimeError("reported MIME exceeds the configured nesting depth")
            parts_seen += 1
            if parts_seen > self._max_parts:
                raise ReportedMimeError("reported MIME exceeds the configured part limit")
            if message.defects:
                raise ReportedMimeError("reported MIME is malformed")
            self._validate_transfer_encoding(message)

            is_embedded = message.get_content_type().lower() == "message/rfc822"
            filename = message.get_filename() or ""
            is_eml_file = filename.lower().endswith(".eml")
            is_attachment = message.get_content_disposition() == "attachment" or is_embedded or is_eml_file
            next_attached = attached or is_attachment
            if is_attachment:
                attachments_seen += 1
                if attachments_seen > self._max_attachments:
                    raise ReportedMimeError("reported MIME exceeds the configured attachment limit")

            found, invalid, header_count = self._evidence(
                message,
                depth=depth,
                path=path,
                attached=attached,
                remaining_headers=self._max_correlation_headers - correlation_headers_seen,
            )
            evidence.extend(found)
            invalid_candidates += invalid
            correlation_headers_seen += header_count

            if message.is_multipart():
                payload = message.get_payload()
                if not isinstance(payload, list):
                    raise ReportedMimeError("reported MIME multipart payload is malformed")
                nested_raw = self._encoded_embedded_payload(message, payload) if is_embedded else None
                if nested_raw is not None:
                    decoded_bytes = self._add_decoded(decoded_bytes, len(nested_raw))
                    nested = self._parse_nested(nested_raw)
                    pending.append((nested, depth + 1, (*path, 0), True))
                    continue
                for index in range(len(payload) - 1, -1, -1):
                    child = payload[index]
                    if not isinstance(child, Message):
                        raise ReportedMimeError("reported MIME multipart payload is malformed")
                    pending.append((child, depth + 1, (*path, index), next_attached))
                continue

            decoded = self._decoded_payload(message)
            decoded_bytes = self._add_decoded(decoded_bytes, len(decoded))
            media_type = message.get_content_type().lower()
            if media_type in _COMPRESSED_MEDIA_TYPES:
                compressed_parts += 1
                continue
            if is_eml_file:
                nested = self._parse_nested(decoded)
                pending.append((nested, depth + 1, (*path, 0), True))

        distinct = tuple(dict.fromkeys(item.candidate for item in evidence))
        disposition: Literal["none", "single", "ambiguous"]
        if not distinct:
            disposition = "none"
        elif len(distinct) == 1:
            disposition = "single"
        else:
            disposition = "ambiguous"
        return ReportedMimeResult(
            evidence=tuple(evidence),
            disposition=disposition,
            candidate=distinct[0] if disposition == "single" else None,
            parts_seen=parts_seen,
            attachments_seen=attachments_seen,
            decoded_bytes=decoded_bytes,
            invalid_candidate_count=invalid_candidates,
            compressed_parts_skipped=compressed_parts,
        )

    def _evidence(
        self,
        message: Message,
        *,
        depth: int,
        path: tuple[int, ...],
        attached: bool,
        remaining_headers: int,
    ) -> tuple[list[CorrelationEvidence], int, int]:
        output: list[CorrelationEvidence] = []
        invalid = 0
        raw_values = message.get_all(self._correlation_header, [])
        if len(raw_values) > remaining_headers:
            raise ReportedMimeError("reported MIME exceeds the configured correlation header limit")
        for raw_value in raw_values:
            rendered = str(raw_value)
            if len(rendered) > _MAX_CORRELATION_HEADER_VALUE_CHARS:
                invalid += 1
                continue
            candidate = re.sub(r"\s+", "", rendered)
            if _OPAQUE_CANDIDATE.fullmatch(candidate) is None:
                invalid += 1
                continue
            if depth == 0:
                source: Literal["wrapper", "attached_original", "nested_message"] = "wrapper"
            elif attached:
                source = "attached_original"
            else:
                source = "nested_message"
            message_id = self._safe_message_id(message.get("Message-ID"))
            output.append(
                CorrelationEvidence(
                    candidate=candidate,
                    header_name=self._correlation_header,
                    source=source,
                    depth=depth,
                    part_path=path,
                    message_id=message_id,
                )
            )
        return output, invalid, len(raw_values)

    @staticmethod
    def _safe_message_id(raw_value: object) -> str | None:
        if raw_value is None:
            return None
        value = str(raw_value).strip()
        if not value or len(value) > 998 or any(ord(character) < 32 or ord(character) == 127 for character in value):
            return None
        return value

    def _add_decoded(self, current: int, added: int) -> int:
        total = current + added
        if total > self._max_decoded_bytes:
            raise ReportedMimeError("reported MIME exceeds the configured decoded byte limit")
        return total

    @staticmethod
    def _decoded_payload(message: Message) -> bytes:
        try:
            decoded = message.get_payload(decode=True)
        except (binascii.Error, UnicodeError, ValueError):
            raise ReportedMimeError("reported MIME transfer encoding is malformed") from None
        if decoded is None:
            payload = message.get_payload()
            if payload in (None, ""):
                return b""
            if not isinstance(payload, str):
                raise ReportedMimeError("reported MIME payload is malformed")
            return payload.encode("utf-8", errors="strict")
        if not isinstance(decoded, bytes):
            raise ReportedMimeError("reported MIME payload is malformed")
        return decoded

    @staticmethod
    def _validate_transfer_encoding(message: Message) -> None:
        raw_values = message.get_all("Content-Transfer-Encoding", [])
        if len(raw_values) > 1:
            raise ReportedMimeError("reported MIME transfer encoding is malformed")
        if not raw_values:
            return
        encoding = str(raw_values[0]).strip().lower()
        if encoding not in _VALID_TRANSFER_ENCODINGS:
            raise ReportedMimeError("reported MIME transfer encoding is malformed")
        if (
            message.is_multipart()
            and encoding not in {"7bit", "8bit", "binary"}
            and message.get_content_type().lower() != "message/rfc822"
        ):
            # message/rfc822 is represented as multipart by the email parser;
            # its encoded payload is handled and validated separately below.
            raise ReportedMimeError("reported MIME transfer encoding is malformed")
        if message.is_multipart():
            return
        payload = message.get_payload()
        if not isinstance(payload, str) or encoding not in {"base64", "quoted-printable"}:
            return
        try:
            encoded = payload.encode("ascii", errors="strict")
            if encoding == "base64":
                base64.b64decode(re.sub(rb"\s+", b"", encoded), validate=True)
            elif _INVALID_QUOTED_PRINTABLE.search(encoded):
                raise ValueError
        except (UnicodeError, binascii.Error, ValueError):
            raise ReportedMimeError("reported MIME transfer encoding is malformed") from None

    @staticmethod
    def _encoded_embedded_payload(message: Message, payload: list[Any]) -> bytes | None:
        encoding = str(message.get("Content-Transfer-Encoding", "")).strip().lower()
        if encoding not in {"base64", "quoted-printable"} or len(payload) != 1:
            return None
        encoded = payload[0].get_payload()
        if not isinstance(encoded, str):
            raise ReportedMimeError("reported MIME embedded message is malformed")
        try:
            encoded_bytes = encoded.encode("ascii", errors="strict")
            if encoding == "base64":
                return base64.b64decode(re.sub(rb"\s+", b"", encoded_bytes), validate=True)
            if _INVALID_QUOTED_PRINTABLE.search(encoded_bytes):
                raise ValueError
            return quopri.decodestring(encoded_bytes)
        except (UnicodeError, binascii.Error, ValueError):
            raise ReportedMimeError("reported MIME transfer encoding is malformed") from None

    @staticmethod
    def _parse_nested(raw_message: bytes) -> Message:
        if not raw_message:
            raise ReportedMimeError("reported MIME attached message is malformed")
        try:
            nested = BytesParser(policy=policy.default).parsebytes(raw_message)
        except (MemoryError, RecursionError, ValueError):
            raise ReportedMimeError("reported MIME attached message is malformed") from None
        if nested.defects or not nested.items():
            raise ReportedMimeError("reported MIME attached message is malformed")
        return nested
