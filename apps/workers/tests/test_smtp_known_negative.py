"""Actual smtplib DATA protocol without any socket or external provider."""

from __future__ import annotations

import smtplib
from collections import deque
from email.message import EmailMessage

import pytest
from kp_workers.providers.smtp import DeliveryIndeterminateError, SmtpSender


class ScriptedSMTP(smtplib.SMTP):
    """Run real send_message/sendmail/data against bounded scripted replies."""

    def __init__(self, result):
        super().__init__()  # Empty host does not connect.
        self.helo_resp = self.ehlo_resp = b"synthetic ready"
        self.replies = deque([(250, b"sender"), (250, b"recipient"), (354, b"data"), result, (250, b"reset")])
        self.commands = []
        self.bodies = []
        self.closed = False

    def putcmd(self, command, args=""):
        self.commands.append(command.lower())

    def getreply(self):
        result = self.replies.popleft()
        if isinstance(result, Exception):
            raise result
        return result

    def send(self, value):
        self.bodies.append(value)

    def close(self):
        self.closed = True

    def quit(self):
        return 221, b"bye"


def message():
    value = EmailMessage()
    value["From"] = "sender@example.test"
    value["To"] = "recipient@example.test"
    value["Subject"] = "synthetic"
    value.set_content("Synthetic body")
    return value


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("code", [451, 550])
def test_real_data_negative_retains_phase_and_code_instead_of_becoming_unknown(monkeypatch, batch, code):
    protocol = ScriptedSMTP((code, b"synthetic rejection"))
    monkeypatch.setattr(SmtpSender, "_connect", lambda _: protocol)
    sender = SmtpSender("smtp.example.test:25")
    if batch:
        sender.__enter__()
    try:
        with pytest.raises(smtplib.SMTPDataError) as caught:
            sender.send(message())
        assert caught.value.smtp_code == code
        assert protocol.commands[:3] == ["mail", "rcpt", "data"]
        assert len(protocol.bodies) == 1 and protocol.bodies[0].endswith(b"\r\n.\r\n")
    finally:
        if batch:
            sender.__exit__(None, None, None)


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    "failure", [smtplib.SMTPServerDisconnected("unknown result"), TimeoutError("lost final reply")]
)
def test_disconnect_or_timeout_after_data_submission_remains_unknown_without_transport_retry(
    monkeypatch, batch, failure
):
    protocol = ScriptedSMTP(failure)
    monkeypatch.setattr(SmtpSender, "_connect", lambda _: protocol)
    sender = SmtpSender("smtp.example.test:25")
    if batch:
        sender.__enter__()
    try:
        with pytest.raises(DeliveryIndeterminateError):
            sender.send(message())
        assert protocol.commands.count("data") == len(protocol.bodies) == 1
    finally:
        if batch:
            sender.__exit__(None, None, None)


@pytest.mark.parametrize("batch", [False, True])
def test_failed_quit_after_positive_data_response_does_not_erase_acceptance(monkeypatch, batch):
    protocol = ScriptedSMTP((250, b"accepted"))

    def failed_quit():
        raise TimeoutError("lost QUIT reply after acceptance")

    protocol.quit = failed_quit
    monkeypatch.setattr(SmtpSender, "_connect", lambda _: protocol)
    sender = SmtpSender("smtp.example.test:25")
    if batch:
        sender.__enter__()
    result = sender.send(message())
    if batch:
        sender.__exit__(None, None, None)
    assert result.provider_id is None and len(protocol.bodies) == 1


@pytest.mark.parametrize("batch", [False, True])
def test_whole_envelope_recipient_refusal_preserves_typed_negative(monkeypatch, batch):
    protocol = ScriptedSMTP((250, b"unused"))
    protocol.replies = deque([(250, b"sender"), (450, b"no recipients accepted"), (250, b"reset")])
    monkeypatch.setattr(SmtpSender, "_connect", lambda _: protocol)
    sender = SmtpSender("smtp.example.test:25")
    if batch:
        sender.__enter__()
    try:
        with pytest.raises(smtplib.SMTPRecipientsRefused):
            sender.send(message())
        assert protocol.bodies == [] and "data" not in protocol.commands
    finally:
        if batch:
            sender.__exit__(None, None, None)
