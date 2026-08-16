"""Authenticated SMTP transport shared by campaign and reminder delivery."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage


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

    def send(self, message: EmailMessage) -> None:
        context = ssl.create_default_context()
        smtp_manager: smtplib.SMTP
        if self._use_ssl:
            smtp_manager = smtplib.SMTP_SSL(self._host, self._port, timeout=self._timeout, context=context)
        else:
            smtp_manager = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
        with smtp_manager as smtp:
            if self._starttls:
                smtp.starttls(context=context)
            if self._username is not None:
                smtp.login(self._username, self._password or "")
            smtp.send_message(message)
