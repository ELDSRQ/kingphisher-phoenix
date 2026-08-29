"""Redaction + data-minimization unit tests (WS-9/WS-12)."""

from __future__ import annotations

import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from kp_database.privacy import hash_mailbox, minimize_ip, minimize_user_agent
from kp_telemetry.logging import AccessLogMiddleware, configure_logging, get_logger, redact_processor, redact_value


def test_redacts_43_char_token() -> None:
    token = "A" * 43
    assert redact_value(f"pixel?token={token}&rest") == "pixel?token=[REDACTED]&rest"


def test_redacts_64_hex_token_hash() -> None:
    digest = hashlib.sha256(b"deadbeef").hexdigest()
    assert len(digest) == 64
    assert redact_value(f"object_id={digest}") == "object_id=[REDACTED]"


def test_redacts_email_and_ip() -> None:
    assert redact_value("mailto:alice@example.com from 10.0.0.1") == "mailto:[REDACTED] from [REDACTED]"


def test_redacts_nested_dict_and_list() -> None:
    payload = {"detail": {"recipient": "bob@example.com", "hashes": ["0" * 64]}}
    out = redact_value(payload)
    assert out["detail"]["recipient"] == "[REDACTED]"
    assert out["detail"]["hashes"] == ["[REDACTED]"]


def test_redacts_every_structured_field() -> None:
    digest = "a" * 64
    event = {"path": f"/track/{digest}", "client": "203.0.113.7", "custom": {"email": "a@example.com"}}
    out = redact_processor(None, "info", event)
    assert out == {
        "path": "/track/[REDACTED]",
        "client": "[REDACTED]",
        "custom": {"email": "[REDACTED]"},
    }


def test_redacts_sensitive_keys_even_when_values_do_not_match_pii_patterns() -> None:
    event = {
        "mime_body": "private prose without an address",
        "provider_correlation": "opaque-provider-value",
        "mailbox_id": "shared-inbox-alias",
        "trace_id": "1" * 32,
    }

    out = redact_processor(None, "info", event)

    assert out == {
        "mime_body": "[REDACTED]",
        "provider_correlation": "[REDACTED]",
        "mailbox_id": "[REDACTED]",
        "trace_id": "1" * 32,
    }


def test_serialized_log_redacts_arbitrary_context(capsys: object) -> None:
    configure_logging()
    token_hash = "b" * 64
    get_logger("redaction-test").info("request", path=f"/v1/track/open/{token_hash}", client="198.51.100.20")
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    record = json.loads(output)
    assert token_hash not in output
    assert "198.51.100.20" not in output
    assert record["path"] == "/v1/track/open/[REDACTED]"
    assert record["client"] == "[REDACTED]"


def test_hash_mailbox_is_salted_and_deterministic() -> None:
    salt = b"0123456789abcdef"
    a = hash_mailbox("Alice@Example.com", salt)
    b = hash_mailbox("alice@example.com", salt)
    bare = hashlib.sha256(b"alice@example.com").hexdigest()
    assert a == b
    assert a != bare
    assert hash_mailbox("alice@example.com", b"different-salt") != a


def test_minimize_ip_prefixes() -> None:
    assert minimize_ip("203.0.113.55") == "203.0.113.0"
    assert minimize_ip("2001:db8:abcd:12::1") == "2001:db8:abcd:12::"


def test_minimize_user_agent_truncates() -> None:
    assert minimize_user_agent("x" * 500) == "x" * 128
    assert minimize_user_agent("short") == "short"
    assert minimize_user_agent(None) is None


def test_access_failure_log_never_serializes_exception_or_request_data(capsys: object) -> None:
    class DatabasePasswordLeak(RuntimeError):
        pass

    async def failing_app(scope: object, receive: object, send: object) -> None:
        del scope, receive, send
        raise DatabasePasswordLeak("password=must-not-reach-log")

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"secret request body"}

    async def send(message: object) -> None:
        del message

    configure_logging()
    middleware = AccessLogMiddleware(failing_app)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/programs/attacker-controlled?password=secret",
        "query_string": b"password=secret",
        "headers": [],
        "route": SimpleNamespace(path="/api/v1/programs/{program_id}"),
    }
    with pytest.raises(DatabasePasswordLeak):
        asyncio.run(middleware(scope, receive, send))

    output = capsys.readouterr().out  # type: ignore[attr-defined]
    records = [json.loads(line) for line in output.splitlines()]
    failed = next(record for record in records if record["event"] == "request_failed")
    assert failed["exception_type"] == "DatabasePasswordLeak"
    assert failed["method"] == "POST"
    assert failed["route"] == "/api/v1/programs/{program_id}"
    assert "password=must-not-reach-log" not in output
    assert "attacker-controlled" not in output
    assert "secret request body" not in output
    assert "exception" not in failed
