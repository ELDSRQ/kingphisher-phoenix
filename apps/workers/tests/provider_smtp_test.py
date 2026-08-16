from __future__ import annotations

from email.message import EmailMessage
from unittest.mock import MagicMock, patch

from kp_workers.providers.smtp import SmtpSender


def test_smtp_sender_uses_starttls_then_auth_without_exposing_password() -> None:
    smtp = MagicMock()
    manager = MagicMock()
    manager.__enter__.return_value = smtp
    message = EmailMessage()
    with patch("kp_workers.providers.smtp.smtplib.SMTP", return_value=manager) as constructor:
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
