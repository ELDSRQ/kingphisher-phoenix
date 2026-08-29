from __future__ import annotations

from email.message import EmailMessage
from unittest.mock import MagicMock, patch

from kp_workers.providers.reminders import ProviderReminderSender, Reminder, SmtpReminderSender


def test_smtp_reminder_sender_builds_plain_message() -> None:
    smtp = MagicMock()
    # Mirror real smtplib: SMTP.__enter__ returns self.
    smtp.__enter__.return_value = smtp
    with patch("kp_workers.providers.smtp.smtplib.SMTP", return_value=smtp) as constructor:
        SmtpReminderSender("mailpit:1025", sender="training@example.com").send(
            Reminder(recipient="learner@example.com", subject="Reminder", text="Complete training")
        )
    constructor.assert_called_once_with("mailpit", 1025, timeout=5.0)
    message = smtp.send_message.call_args.args[0]
    assert isinstance(message, EmailMessage)
    assert message["To"] == "learner@example.com"
    assert message.get_content().strip() == "Complete training"


def test_provider_reminder_sender_closes_its_per_job_transport() -> None:
    transport = MagicMock()
    transport.__enter__.return_value = transport

    ProviderReminderSender(transport, sender="training@example.com").send(
        Reminder(recipient="learner@example.com", subject="Reminder", text="Complete training")
    )

    transport.__enter__.assert_called_once_with()
    transport.__exit__.assert_called_once_with(None, None, None)
    message = transport.send.call_args.args[0]
    assert message["From"] == "training@example.com"
    assert message["To"] == "learner@example.com"
