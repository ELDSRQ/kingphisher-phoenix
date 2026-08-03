"""Structured logging with PII redaction.

Implements §27.1 of the reconstructed spec: JSON logs via structlog with
a redaction processor that masks PII patterns and never logs raw tracking
tokens.
"""

from __future__ import annotations

import json
import re
from collections.abc import MutableMapping
from typing import Any

import structlog

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Opaque tracking tokens: 43-char base64url strings produced by
# secrets.token_urlsafe(32) — never log them.
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{43}\b")
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

REDACTED = "[REDACTED]"


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        value = _EMAIL_RE.sub(REDACTED, value)
        value = _TOKEN_RE.sub(REDACTED, value)
        value = _IP_RE.sub(REDACTED, value)
        return value
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    return value


def redact_processor(logger: Any, method_name: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for key in ("event", "msg", "detail", "payload", "error", "request", "response"):
        if key in event_dict:
            event_dict[key] = redact_value(event_dict[key])
    return event_dict


def key_renamer(logger: Any, method_name: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    # structlog uses "event"; append a human message under "msg" as well.
    if "event" in event_dict and "msg" not in event_dict:
        event_dict["msg"] = event_dict["event"]
    return event_dict


def _json_serializer(data: Any, *_: Any, **__: Any) -> str:
    return json.dumps(data, default=str, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            key_renamer,
            redact_processor,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(serializer=_json_serializer),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "kingphisher") -> Any:
    return structlog.get_logger(name)
