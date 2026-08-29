from __future__ import annotations

import smtplib
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import SMTP as SMTP_POLICY
from email.policy import default
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest
from kp_workers.providers.smtp import (
    REPORT_CORRELATION_HEADER,
    SOURCE_MESSAGE_ID_HEADER,
    AzureCommunicationEmailSender,
    DeliveryCorrelation,
    DeliveryIndeterminateError,
    SmtpSender,
    new_report_verifier,
)

REPORT_VERIFIER = "rpt1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DELIVERY_ATTEMPT_ID = UUID("b805ac5c-91b8-4714-b103-1c671a0de127")
ACS_CLIENT_ID = "66666666-6666-4666-8666-666666666666"


def _correlation() -> DeliveryCorrelation:
    return DeliveryCorrelation.create(
        delivery_attempt_id=DELIVERY_ATTEMPT_ID,
        report_verifier=REPORT_VERIFIER,
        message_id_domain="mail.example.com",
    )


def _message() -> EmailMessage:
    message = EmailMessage()
    message["From"] = "DoNotReply@example.azurecomm.net"
    message["To"] = "learner@example.com"
    message["Subject"] = "Awareness"
    message.set_content("Plain guidance")
    return message


def test_smtp_sender_uses_starttls_then_auth_without_exposing_password() -> None:
    smtp = MagicMock()
    # Mirror real smtplib: SMTP.__enter__ returns self, so the connected object
    # and the context-manager target are the same instance.
    smtp.__enter__.return_value = smtp
    message = EmailMessage()
    with patch("kp_workers.providers.smtp.smtplib.SMTP", return_value=smtp) as constructor:
        SmtpSender(
            "smtp.example.com:587",
            username="service",
            password="secret",
            starttls=True,
            timeout=7.0,
        ).send(message)
    constructor.assert_called_once_with("smtp.example.com", 587, timeout=7.0)
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("service", "secret")
    smtp.send_message.assert_called_once_with(message)
    # The channel must be encrypted before credentials cross it.
    called = [call[0] for call in smtp.method_calls]
    assert called.index("starttls") < called.index("login")


def test_acs_sender_uses_managed_identity_and_preserves_content() -> None:
    client = MagicMock()
    poller = MagicMock()
    poller.result.return_value = {"id": "acs-operation-1", "status": "Succeeded"}
    client.begin_send.return_value = poller
    message = _message()
    message.add_alternative("<p>Plain guidance</p>", subtype="html")
    with (
        patch("azure.identity.ManagedIdentityCredential") as credential,
        patch("azure.communication.email.EmailClient", return_value=client) as constructor,
    ):
        receipt = AzureCommunicationEmailSender(
            "https://example.communication.azure.com",
            managed_identity_client_id=ACS_CLIENT_ID,
        ).send(message)

    credential.assert_called_once_with(client_id=ACS_CLIENT_ID)
    constructor.assert_called_once_with("https://example.communication.azure.com", credential.return_value)
    payload = client.begin_send.call_args.args[0]
    assert payload["senderAddress"] == "DoNotReply@example.azurecomm.net"
    assert payload["recipients"] == {"to": [{"address": "learner@example.com"}]}
    assert payload["content"]["subject"] == "Awareness"
    assert "Plain guidance" in payload["content"]["plainText"]
    poller.result.assert_called_once_with()
    assert receipt.provider_id == "acs-operation-1"
    assert receipt.provider_status == "Succeeded"


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://attacker.example",
        "https://mailer.communication.azure.com.attacker.example",
        "https://communication.azure.com",
        "https://nested.mailer.communication.azure.com",
        "https://mailer.communication.azure.com:444",
        "https://mailer.communication.azure.com/private",
        "https://mailer.communication.azure.com./",
        "https://operator:secret@mailer.communication.azure.com",
        "https://mailer.communication.azure.com?redirect=attacker.example",
    ],
)
def test_acs_managed_identity_rejects_unapproved_endpoint_before_credentials(endpoint: str) -> None:
    with (
        patch("azure.identity.ManagedIdentityCredential") as credential,
        patch("azure.communication.email.EmailClient") as client,
        pytest.raises(ValueError, match=r"approved HTTPS \*\.communication\.azure\.com"),
    ):
        AzureCommunicationEmailSender(endpoint, managed_identity_client_id=ACS_CLIENT_ID)

    credential.assert_not_called()
    client.assert_not_called()


def test_acs_explicit_connection_string_preserves_local_development_mock_path() -> None:
    client = MagicMock()
    connection_string = "endpoint=http://localhost:8080;accesskey=development-only"
    with (
        patch("azure.identity.ManagedIdentityCredential") as credential,
        patch("azure.communication.email.EmailClient") as email_client,
    ):
        email_client.from_connection_string.return_value = client
        sender = AzureCommunicationEmailSender(
            "http://localhost:8080",
            connection_string=connection_string,
        )

    email_client.from_connection_string.assert_called_once_with(connection_string)
    credential.assert_not_called()
    assert sender._client is client


def test_delivery_correlation_is_purpose_scoped_retry_stable_and_repr_safe() -> None:
    first = _correlation()
    duplicate = _correlation()

    assert first == duplicate
    assert first.message_id == ("<kp-rpt-b805ac5c91b84714b1031c671a0de127.9cae31a3be62bf68@mail.example.com>")
    assert str(UUID(first.operation_id)) == first.operation_id
    assert REPORT_VERIFIER not in repr(first)
    assert new_report_verifier().startswith("rpt1_")


@pytest.mark.parametrize(
    ("verifier", "domain"),
    [
        ("training-bearer", "mail.example.com"),
        (f"{REPORT_VERIFIER}\r\nBcc: attacker@example.com", "mail.example.com"),
        (REPORT_VERIFIER, "mail.example.com\r\nX-Evil: true"),
    ],
)
def test_delivery_correlation_rejects_wrong_purpose_and_header_injection(verifier: str, domain: str) -> None:
    with pytest.raises(ValueError):
        DeliveryCorrelation.create(
            delivery_attempt_id=DELIVERY_ATTEMPT_ID,
            report_verifier=verifier,
            message_id_domain=domain,
        )


def test_smtp_round_trips_deterministic_message_and_report_headers() -> None:
    smtp = MagicMock()
    message = _message()
    correlation = _correlation()
    with patch("kp_workers.providers.smtp.smtplib.SMTP", return_value=smtp):
        receipt = SmtpSender("smtp.example.com:25").send(message, correlation=correlation)

    sent = smtp.send_message.call_args.args[0]
    parsed = BytesParser(policy=default).parsebytes(sent.as_bytes(policy=SMTP_POLICY))
    assert parsed["Message-ID"] == correlation.message_id
    assert parsed[REPORT_CORRELATION_HEADER] == REPORT_VERIFIER
    assert receipt.message_id == correlation.message_id
    assert receipt.provider_id is None


def test_smtp_duplicate_messages_reuse_identical_correlation_headers() -> None:
    smtp = MagicMock()
    correlation = _correlation()
    first = _message()
    retry = _message()
    with patch("kp_workers.providers.smtp.smtplib.SMTP", return_value=smtp):
        sender = SmtpSender("smtp.example.com:25")
        sender.send(first, correlation=correlation)
        sender.send(retry, correlation=correlation)

    assert first["Message-ID"] == retry["Message-ID"] == correlation.message_id
    assert first[REPORT_CORRELATION_HEADER] == retry[REPORT_CORRELATION_HEADER] == REPORT_VERIFIER


def test_correlation_header_cannot_bypass_validated_contract_or_conflict() -> None:
    manual = _message()
    manual[REPORT_CORRELATION_HEADER] = REPORT_VERIFIER
    sender = SmtpSender("smtp.example.com:25")
    with pytest.raises(ValueError, match="requires DeliveryCorrelation"):
        sender.send(manual)

    conflicting = _message()
    conflicting["Message-ID"] = "<different@mail.example.com>"
    with pytest.raises(ValueError, match="conflicting Message-ID"):
        sender.send(conflicting, correlation=_correlation())


def test_smtp_disconnect_is_not_blindly_retried() -> None:
    first = MagicMock()
    second = MagicMock()
    first.send_message.side_effect = smtplib.SMTPServerDisconnected("result unknown")
    message = _message()
    correlation = _correlation()
    with patch("kp_workers.providers.smtp.smtplib.SMTP", side_effect=[first, second]):
        sender = SmtpSender("smtp.example.com:25")
        sender.__enter__()
        with pytest.raises(DeliveryIndeterminateError, match="do not retry") as caught:
            sender.send(message, correlation=correlation)
        # A later, different assignment may reconnect, but the failed call did
        # not resend this message on the new connection.
        sender.send(_message(), correlation=correlation)
        sender.__exit__(None, None, None)

    first.send_message.assert_called_once_with(message)
    second.send_message.assert_called_once()
    assert caught.value.message_id == correlation.message_id
    assert REPORT_VERIFIER not in str(caught.value)


def test_acs_preserves_correlation_and_returns_provider_operation_id() -> None:
    client = MagicMock()
    poller = MagicMock()
    poller.result.return_value = {"id": "acs-provider-id", "status": "Succeeded"}
    client.begin_send.return_value = poller
    correlation = _correlation()
    with (
        patch("azure.identity.ManagedIdentityCredential"),
        patch("azure.communication.email.EmailClient", return_value=client),
    ):
        receipt = AzureCommunicationEmailSender(
            "https://example.communication.azure.com",
            managed_identity_client_id=ACS_CLIENT_ID,
        ).send(_message(), correlation=correlation)

    payload = client.begin_send.call_args.args[0]
    assert payload["headers"] == {
        REPORT_CORRELATION_HEADER: REPORT_VERIFIER,
        SOURCE_MESSAGE_ID_HEADER: correlation.message_id,
    }
    assert client.begin_send.call_args.kwargs == {"operation_id": correlation.operation_id}
    assert receipt.message_id == correlation.message_id
    assert receipt.provider_id == "acs-provider-id"
    assert REPORT_VERIFIER not in repr(receipt)


def test_acs_fails_if_provider_operation_id_is_not_returned() -> None:
    client = MagicMock()
    client.begin_send.return_value.result.return_value = {"status": "Succeeded"}
    with (
        patch("azure.identity.ManagedIdentityCredential"),
        patch("azure.communication.email.EmailClient", return_value=client),
    ):
        sender = AzureCommunicationEmailSender(
            "https://example.communication.azure.com",
            managed_identity_client_id=ACS_CLIENT_ID,
        )
        with pytest.raises(RuntimeError, match="provider operation ID"):
            sender.send(_message(), correlation=_correlation())


@pytest.mark.parametrize("provider", ["smtp", "acs"])
def test_provider_size_limit_rejects_before_network_submission(provider: str) -> None:
    message = _message()
    message.set_content("x" * 512)
    if provider == "smtp":
        with patch("kp_workers.providers.smtp.smtplib.SMTP") as constructor:
            sender = SmtpSender("smtp.example.com:25", max_message_bytes=128)
            with pytest.raises(ValueError, match="size limit"):
                sender.send(message, correlation=_correlation())
        constructor.assert_not_called()
        return

    client = MagicMock()
    with (
        patch("azure.identity.ManagedIdentityCredential"),
        patch("azure.communication.email.EmailClient", return_value=client),
    ):
        sender = AzureCommunicationEmailSender(
            "https://example.communication.azure.com",
            managed_identity_client_id=ACS_CLIENT_ID,
            max_message_bytes=128,
        )
        with pytest.raises(ValueError, match="size limit"):
            sender.send(message, correlation=_correlation())
    client.begin_send.assert_not_called()


def test_acs_sender_never_falls_back_to_a_shared_credential_chain() -> None:
    with (
        patch("azure.identity.ManagedIdentityCredential") as managed,
        patch("azure.identity.DefaultAzureCredential", create=True) as fallback,
        patch("azure.communication.email.EmailClient") as client,
        pytest.raises(ValueError, match="managed identity client ID"),
    ):
        AzureCommunicationEmailSender("https://example.communication.azure.com")

    managed.assert_not_called()
    fallback.assert_not_called()
    client.assert_not_called()


def test_acs_sender_context_closes_client_and_owned_credential() -> None:
    client = MagicMock()
    with (
        patch("azure.identity.ManagedIdentityCredential") as credential,
        patch("azure.communication.email.EmailClient", return_value=client),
        AzureCommunicationEmailSender(
            "https://example.communication.azure.com",
            managed_identity_client_id=ACS_CLIENT_ID,
        ),
    ):
        pass

    client.close.assert_called_once_with()
    credential.return_value.close.assert_called_once_with()
