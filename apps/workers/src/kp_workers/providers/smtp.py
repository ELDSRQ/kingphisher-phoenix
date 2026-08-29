"""Authenticated SMTP transport shared by campaign and reminder delivery."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
import secrets
import smtplib
import ssl
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import getaddresses
from types import TracebackType
from typing import Protocol, Self
from urllib.parse import urlparse

REPORT_CORRELATION_HEADER = "X-KP-Report-Correlation"
SOURCE_MESSAGE_ID_HEADER = "X-KP-Source-Message-ID"
DEFAULT_MAX_PROVIDER_MESSAGE_BYTES = 10 * 1024 * 1024
_REPORT_VERIFIER_RE = re.compile(r"rpt1_[A-Za-z0-9_-]{43}\Z")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ACS_ENDPOINT_HOST_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.communication\.azure\.com\Z",
    re.IGNORECASE,
)
_CORRELATION_NAMESPACE = uuid.UUID("92f0c2d5-559d-4dda-a834-3837418cb35d")


def new_report_verifier() -> str:
    """Mint verifier material exclusively for reported-message correlation.

    The prefix prevents a tracking/training bearer from being accepted by the
    provider seam accidentally. The caller must persist and reuse the returned
    value for retries; providers never derive it from recipient information.
    """

    return f"rpt1_{secrets.token_urlsafe(32)}"


def _message_id_domain(value: str) -> str:
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("message ID domain must be a valid DNS name") from exc
    if not domain or len(domain) > 253 or any(not _DNS_LABEL_RE.fullmatch(label) for label in domain.split(".")):
        raise ValueError("message ID domain must be a valid DNS name")
    return domain


@dataclass(frozen=True, slots=True, init=False)
class DeliveryCorrelation:
    """Validated, retry-stable metadata for one delivery attempt.

    ``report_verifier`` is deliberately excluded from repr so diagnostics do
    not disclose the verifier carried in the report-correlation header.
    """

    message_id: str = field(init=False)
    operation_id: str = field(init=False)
    report_verifier: str = field(init=False, repr=False)

    def __init__(
        self,
        *,
        delivery_attempt_id: uuid.UUID | str,
        report_verifier: str,
        message_id_domain: str,
    ) -> None:
        if not _REPORT_VERIFIER_RE.fullmatch(report_verifier):
            raise ValueError("report verifier must be purpose-scoped rpt1 verifier material")
        try:
            attempt_id = uuid.UUID(str(delivery_attempt_id))
        except ValueError as exc:
            raise ValueError("delivery attempt ID must be a UUID") from exc
        domain = _message_id_domain(message_id_domain)
        digest = hashlib.sha256(
            b"kp-report-correlation-v1\0" + attempt_id.bytes + b"\0" + report_verifier.encode("ascii")
        ).hexdigest()
        object.__setattr__(self, "message_id", f"<kp-rpt-{attempt_id.hex}.{digest[:16]}@{domain}>")
        object.__setattr__(
            self,
            "operation_id",
            str(uuid.uuid5(_CORRELATION_NAMESPACE, f"{attempt_id.hex}:{digest}")),
        )
        object.__setattr__(self, "report_verifier", report_verifier)

    @classmethod
    def create(
        cls,
        *,
        delivery_attempt_id: uuid.UUID | str,
        report_verifier: str,
        message_id_domain: str,
    ) -> DeliveryCorrelation:
        return cls(
            delivery_attempt_id=delivery_attempt_id,
            report_verifier=report_verifier,
            message_id_domain=message_id_domain,
        )


@dataclass(frozen=True, slots=True)
class DeliveryReceipt:
    """Provider acceptance metadata; it never contains report verifier material."""

    message_id: str | None
    provider_id: str | None
    provider_status: str | None = None


class DeliveryIndeterminateError(RuntimeError):
    """The connection failed after submission may have reached the provider."""

    def __init__(self, *, message_id: str | None) -> None:
        super().__init__("delivery result is indeterminate; do not retry automatically")
        self.message_id = message_id


def _single_header(message: EmailMessage, name: str) -> str | None:
    values = message.get_all(name, [])
    if len(values) > 1:
        raise ValueError(f"email must contain at most one {name} header")
    return str(values[0]) if values else None


def _prepare_correlation(message: EmailMessage, correlation: DeliveryCorrelation | None) -> str | None:
    existing_report = _single_header(message, REPORT_CORRELATION_HEADER)
    existing_message_id = _single_header(message, "Message-ID")
    if correlation is None:
        if existing_report is not None:
            raise ValueError("report-correlation header requires DeliveryCorrelation metadata")
        return existing_message_id

    expected_headers = (
        ("Message-ID", existing_message_id, correlation.message_id),
        (REPORT_CORRELATION_HEADER, existing_report, correlation.report_verifier),
    )
    for name, existing, expected in expected_headers:
        if existing is None:
            message[name] = expected
        elif existing != expected:
            raise ValueError(f"email contains conflicting {name} header")
    return correlation.message_id


def _validate_size(payload_size: int, maximum: int) -> None:
    if payload_size > maximum:
        raise ValueError("email exceeds provider message size limit")


class EmailSender(Protocol):
    """A transport that can send one message, optionally over a held session.

    Entering the sender lets a batch reuse one connection; outside a `with`
    block every send is self-contained, which keeps single-message callers
    (reminders, test sends) unchanged.
    """

    def send(self, message: EmailMessage, *, correlation: DeliveryCorrelation | None = None) -> DeliveryReceipt: ...

    def __enter__(self) -> Self: ...

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None: ...


class SmtpSender:
    def __init__(
        self,
        address: str,
        *,
        username: str | None = None,
        password: str | None = None,
        starttls: bool = False,
        use_ssl: bool = False,
        timeout: float = 10.0,
        max_message_bytes: int = DEFAULT_MAX_PROVIDER_MESSAGE_BYTES,
    ) -> None:
        host, separator, port_text = address.rpartition(":")
        if not separator or not host:
            raise ValueError("SMTP address must use host:port format")
        self._host = host.strip("[]")
        self._port = int(port_text)
        self._username = username
        self._password = password
        self._starttls = starttls
        self._use_ssl = use_ssl
        self._timeout = timeout
        if max_message_bytes <= 0:
            raise ValueError("maximum message size must be positive")
        self._max_message_bytes = max_message_bytes
        #: Connection held for the duration of a `with` block, so a delivery
        #: batch pays one connect+login instead of one per recipient (ARCH-1).
        self._session: smtplib.SMTP | None = None
        self._batching = False

    def _connect(self) -> smtplib.SMTP:
        context = ssl.create_default_context()
        smtp: smtplib.SMTP
        if self._use_ssl:
            smtp = smtplib.SMTP_SSL(self._host, self._port, timeout=self._timeout, context=context)
        else:
            smtp = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
        if self._starttls:
            smtp.starttls(context=context)
        if self._username is not None:
            smtp.login(self._username, self._password or "")
        return smtp

    def __enter__(self) -> Self:
        self._batching = True
        self._session = self._connect()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self._batching = False
        self._close_session()

    def _close_session(self) -> None:
        session, self._session = self._session, None
        if session is None:
            return
        # The batch is finished; a failed QUIT is not worth surfacing, and the
        # socket is dropped either way.
        with contextlib.suppress(Exception):
            try:
                session.quit()
            finally:
                session.close()

    def send(self, message: EmailMessage, *, correlation: DeliveryCorrelation | None = None) -> DeliveryReceipt:
        message_id = _prepare_correlation(message, correlation)
        _validate_size(len(message.as_bytes(policy=SMTP_POLICY)), self._max_message_bytes)
        session = self._session
        if session is None:
            if self._batching:
                self._session = self._connect()
                session = self._session
            else:
                smtp = self._connect()
                try:
                    smtp.send_message(message)
                except (smtplib.SMTPServerDisconnected, OSError) as exc:
                    with contextlib.suppress(Exception):
                        smtp.close()
                    raise DeliveryIndeterminateError(message_id=message_id) from exc
                finally:
                    with contextlib.suppress(Exception):
                        smtp.quit()
                return DeliveryReceipt(message_id=message_id, provider_id=None)
        try:
            session.send_message(message)
        except (smtplib.SMTPServerDisconnected, OSError) as exc:
            # A disconnect can happen after the relay accepted DATA. Retrying
            # the same message would be a blind duplicate. Drop the connection
            # and surface the indeterminate result; the next assignment in a
            # batch may establish a fresh connection of its own.
            self._close_session()
            raise DeliveryIndeterminateError(message_id=message_id) from exc
        return DeliveryReceipt(message_id=message_id, provider_id=None)


class AzureCommunicationEmailSender:
    """Azure Communication Services transport using managed identity by default."""

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        with contextlib.suppress(Exception):
            self._client.close()
        if self._credential is not None:
            with contextlib.suppress(Exception):
                self._credential.close()

    def __init__(
        self,
        endpoint: str,
        *,
        connection_string: str | None = None,
        managed_identity_client_id: str | None = None,
        max_message_bytes: int = DEFAULT_MAX_PROVIDER_MESSAGE_BYTES,
    ) -> None:
        if max_message_bytes <= 0:
            raise ValueError("maximum message size must be positive")
        if not connection_string:
            error = "ACS email endpoint must use an approved HTTPS *.communication.azure.com endpoint on port 443"
            try:
                parsed = urlparse(endpoint)
                port = parsed.port
            except ValueError:
                raise ValueError(error) from None
            hostname = parsed.hostname or ""
            if (
                parsed.scheme != "https"
                or parsed.username is not None
                or parsed.password is not None
                or port not in {None, 443}
                or parsed.path not in {"", "/"}
                or parsed.params
                or parsed.query
                or parsed.fragment
                or _ACS_ENDPOINT_HOST_RE.fullmatch(hostname) is None
            ):
                raise ValueError(error)

        from azure.communication.email import EmailClient

        self._max_message_bytes = max_message_bytes
        self._credential = None
        if connection_string:
            self._client = EmailClient.from_connection_string(connection_string)
        else:
            if not managed_identity_client_id:
                raise ValueError("ACS managed identity client ID is required")
            from azure.identity import ManagedIdentityCredential

            self._credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
            self._client = EmailClient(endpoint, self._credential)

    def send(self, message: EmailMessage, *, correlation: DeliveryCorrelation | None = None) -> DeliveryReceipt:
        message_id = _prepare_correlation(message, correlation)
        sender = str(message.get("From", ""))
        recipients = [address for _, address in getaddresses(message.get_all("To", []))]
        if not sender or not recipients:
            raise ValueError("email requires From and To addresses")
        plain = ""
        html = ""
        attachments: list[dict[str, str]] = []
        for part in message.walk():
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                decoded = part.get_payload(decode=True)
                attachment_content = decoded if isinstance(decoded, bytes) else b""
                attachments.append(
                    {
                        "name": part.get_filename() or "attachment",
                        "contentType": part.get_content_type(),
                        "contentInBase64": base64.b64encode(attachment_content).decode("ascii"),
                    }
                )
            elif part.get_content_type() == "text/plain":
                plain = part.get_content()
            elif part.get_content_type() == "text/html":
                html = part.get_content()
        payload: dict[str, object] = {
            "senderAddress": sender,
            "recipients": {"to": [{"address": address} for address in recipients]},
            "content": {"subject": str(message.get("Subject", "")), "plainText": plain, "html": html},
        }
        if attachments:
            payload["attachments"] = attachments
        if correlation is not None:
            # ACS documents custom headers as a string mapping. Preserve the
            # report verifier and a copy of our deterministic RFC Message-ID;
            # do not attempt to override ACS's own reserved Message-ID header.
            payload["headers"] = {
                REPORT_CORRELATION_HEADER: correlation.report_verifier,
                SOURCE_MESSAGE_ID_HEADER: correlation.message_id,
            }
        payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        _validate_size(len(payload_bytes), self._max_message_bytes)

        if correlation is None:
            result = self._client.begin_send(payload).result()
        else:
            result = self._client.begin_send(payload, operation_id=correlation.operation_id).result()
        if not isinstance(result, Mapping):
            raise RuntimeError("ACS response did not include a provider operation ID")
        provider_id = result.get("id")
        if not isinstance(provider_id, str) or not provider_id or "\r" in provider_id or "\n" in provider_id:
            raise RuntimeError("ACS response did not include a valid provider operation ID")
        status_value = result.get("status")
        status = str(status_value) if status_value is not None else None
        return DeliveryReceipt(message_id=message_id, provider_id=provider_id, provider_status=status)


def make_email_sender(
    *,
    provider: str,
    smtp_address: str,
    smtp_username: str | None,
    smtp_password: str | None,
    smtp_starttls: bool,
    smtp_ssl: bool,
    acs_endpoint: str | None,
    acs_connection_string: str | None,
    acs_client_id: str | None,
    timeout: float,
) -> EmailSender:
    if provider == "azure_communication_services":
        if not acs_endpoint:
            raise ValueError("ACS email endpoint is required")
        return AzureCommunicationEmailSender(
            acs_endpoint,
            connection_string=acs_connection_string,
            managed_identity_client_id=acs_client_id,
        )
    return SmtpSender(
        smtp_address,
        username=smtp_username,
        password=smtp_password,
        starttls=smtp_starttls,
        use_ssl=smtp_ssl,
        timeout=timeout,
    )
