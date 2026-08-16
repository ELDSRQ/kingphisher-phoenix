from __future__ import annotations

from email.message import EmailMessage
from unittest.mock import MagicMock, patch

from kp_workers.providers.reminders import Reminder, SmtpReminderSender


def test_smtp_reminder_sender_builds_plain_message() -> None:
    smtp = MagicMock()
    manager = MagicMock()
    manager.__enter__.return_value = smtp
    with patch("kp_workers.providers.smtp.smtplib.SMTP", return_value=manager) as constructor:
        SmtpReminderSender("mailpit:1025", sender="training@example.com").send(
            Reminder(recipient="learner@example.com", subject="Reminder", text="Complete training")
        )
    constructor.assert_called_once_with("mailpit", 1025, timeout=5.0)
    message = smtp.send_message.call_args.args[0]
    assert isinstance(message, EmailMessage)
    assert message["To"] == "learner@example.com"
    assert message.get_content().strip() == "Complete training"
