from __future__ import annotations

from email.message import EmailMessage
from unittest.mock import MagicMock, patch

from kp_workers.providers.smtp import AzureCommunicationEmailSender, SmtpSender


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
    client.begin_send.return_value = poller
    message = EmailMessage()
    message["From"] = "DoNotReply@example.azurecomm.net"
    message["To"] = "learner@example.com"
    message["Subject"] = "Awareness"
    message.set_content("Plain guidance")
    message.add_alternative("<p>Plain guidance</p>", subtype="html")
    with (
        patch("azure.identity.DefaultAzureCredential") as credential,
        patch("azure.communication.email.EmailClient", return_value=client) as constructor,
    ):
        AzureCommunicationEmailSender("https://example.communication.azure.com").send(message)

    constructor.assert_called_once_with("https://example.communication.azure.com", credential.return_value)
    payload = client.begin_send.call_args.args[0]
    assert payload["senderAddress"] == "DoNotReply@example.azurecomm.net"
    assert payload["recipients"] == {"to": [{"address": "learner@example.com"}]}
    assert payload["content"]["subject"] == "Awareness"
    assert "Plain guidance" in payload["content"]["plainText"]
    poller.result.assert_called_once_with()
