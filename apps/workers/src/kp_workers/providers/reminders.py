"""Training-reminder transport contracts and SMTP implementation."""

from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol


@dataclass(frozen=True)
class Reminder:
    recipient: str
    subject: str
    text: str


class ReminderSender(Protocol):
    def send(self, reminder: Reminder) -> None: ...


class SmtpReminderSender:
    def __init__(self, address: str, *, sender: str, timeout: float = 5.0) -> None:
        host, separator, port_text = address.rpartition(":")
        if not separator or not host:
            raise ValueError("SMTP address must use host:port format")
        self._host = host
        self._port = int(port_text)
        self._sender = sender
        self._timeout = timeout

    def send(self, reminder: Reminder) -> None:
        message = EmailMessage()
        message["Subject"] = reminder.subject
        message["From"] = self._sender
        message["To"] = reminder.recipient
        message.set_content(reminder.text)
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            smtp.send_message(message)
