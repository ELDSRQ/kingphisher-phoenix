"""Training-reminder transport contracts and SMTP implementation."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

from kp_workers.providers.smtp import SmtpSender


@dataclass(frozen=True)
class Reminder:
    recipient: str
    subject: str
    text: str


class ReminderSender(Protocol):
    def send(self, reminder: Reminder) -> None: ...


class SmtpReminderSender:
    def __init__(
        self,
        address: str,
        *,
        sender: str,
        timeout: float = 5.0,
        username: str | None = None,
        password: str | None = None,
        starttls: bool = False,
        use_ssl: bool = False,
    ) -> None:
        self._sender = sender
        self._transport = SmtpSender(
            address,
            timeout=timeout,
            username=username,
            password=password,
            starttls=starttls,
            use_ssl=use_ssl,
        )

    def send(self, reminder: Reminder) -> None:
        message = EmailMessage()
        message["Subject"] = reminder.subject
        message["From"] = self._sender
        message["To"] = reminder.recipient
        message.set_content(reminder.text)
        self._transport.send(message)
