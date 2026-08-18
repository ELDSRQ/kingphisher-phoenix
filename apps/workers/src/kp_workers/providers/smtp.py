"""Authenticated SMTP transport shared by campaign and reminder delivery."""

from __future__ import annotations

import base64
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import getaddresses
from typing import Protocol


class EmailSender(Protocol):
    def send(self, message: EmailMessage) -> None: ...


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


class AzureCommunicationEmailSender:
    """Azure Communication Services transport using managed identity by default."""

    def __init__(self, endpoint: str, *, connection_string: str | None = None) -> None:
        from azure.communication.email import EmailClient

        if connection_string:
            self._client = EmailClient.from_connection_string(connection_string)
        else:
            from azure.identity import DefaultAzureCredential

            self._client = EmailClient(endpoint, DefaultAzureCredential())

    def send(self, message: EmailMessage) -> None:
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
        self._client.begin_send(payload).result()


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
    timeout: float,
) -> EmailSender:
    if provider == "azure_communication_services":
        if not acs_endpoint:
            raise ValueError("ACS email endpoint is required")
        return AzureCommunicationEmailSender(acs_endpoint, connection_string=acs_connection_string)
    return SmtpSender(
        smtp_address,
        username=smtp_username,
        password=smtp_password,
        starttls=smtp_starttls,
        use_ssl=smtp_ssl,
        timeout=timeout,
    )
