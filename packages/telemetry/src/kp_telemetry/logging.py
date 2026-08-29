"""Structured logging with PII redaction.

Implements §27.1 of the reconstructed spec: JSON logs via structlog with
a redaction processor that masks PII patterns and never logs raw tracking
tokens.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import MutableMapping
from typing import Any

import structlog

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Opaque tracking tokens: 43-char base64url strings produced by
# secrets.token_urlsafe(32) — never log them. Also masks 256-bit hex
# token hashes (64 hex chars) used as the at-rest identifier.
_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9_-]{43}|[0-9a-fA-F]{64})\b")
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_SENSITIVE_KEY_PARTS = frozenset(
    {
        "authorization",
        "correlation",
        "mailbox",
        "mime",
        "password",
        "secret",
        "token",
    }
)

REDACTED = "[REDACTED]"


def _sensitive_key(key: object) -> bool:
    normalized = str(key).casefold().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        value = _EMAIL_RE.sub(REDACTED, value)
        value = _TOKEN_RE.sub(REDACTED, value)
        value = _IP_RE.sub(REDACTED, value)
        return value
    if isinstance(value, dict):
        return {k: REDACTED if _sensitive_key(k) else redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    return value


def redact_processor(logger: Any, method_name: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    # Structured context is extensible, so an allow-list of field names is not
    # a safe redaction boundary.  Process every value, including values bound
    # by middleware and third-party integrations.
    for key, value in event_dict.items():
        event_dict[key] = REDACTED if _sensitive_key(key) else redact_value(value)
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


class AccessLogMiddleware:
    """Structured request logging replacing uvicorn's default access log.

    Uvicorn's built-in access log is disabled (`access_log=False`) and this
    middleware emits one JSON line per request instead, so request data passes
    through the redaction processors (MED-04 / WS-12).
    """

    def __init__(self, app: Any, *, logger_name: str = "kp.access") -> None:
        self.app = app
        self.logger = get_logger(logger_name)

    @staticmethod
    def _route_template(scope: Any) -> str:
        """Return a non-identifying route name, never the request path.

        Starlette attaches the matched route to the scope while dispatching.
        Unmatched paths are deliberately collapsed so attacker-controlled URL
        data cannot become an access-log side channel.
        """
        route = scope.get("route")
        template = getattr(route, "path", None)
        return template if isinstance(template, str) else "<unmatched>"

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status_holder: list[int] = [200]
        trace_id = _request_trace_id(scope)
        span_id = secrets.token_hex(8)
        context = structlog.contextvars.bind_contextvars(trace_id=trace_id)

        async def _send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder[0] = message["status"]
                headers = [header for header in message.get("headers", []) if header[0].lower() != b"traceparent"]
                headers.append((b"traceparent", f"00-{trace_id}-{span_id}-01".encode("ascii")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, _send)
        except Exception as exc:
            method = scope.get("method")
            self.logger.error(
                "request_failed",
                exception_type=type(exc).__name__[:128],
                method=method if method in {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"} else "UNKNOWN",
                route=self._route_template(scope),
            )
            raise
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            self.logger.info(
                "request",
                method=scope.get("method"),
                route=self._route_template(scope),
                status=status_holder[0],
                duration_ms=round(duration_ms, 2),
            )
            structlog.contextvars.unbind_contextvars(*context)


def _request_trace_id(scope: Any) -> str:
    """Accept a valid W3C trace id or create a fresh non-identifying one."""
    for raw_name, raw_value in scope.get("headers", ()):
        if raw_name.lower() != b"traceparent":
            continue
        try:
            candidate = raw_value.decode("ascii").lower()
        except UnicodeDecodeError:
            break
        matched = _TRACEPARENT_RE.fullmatch(candidate)
        if matched is not None and matched.group(1) != "0" * 32 and matched.group(2) != "0" * 16:
            return matched.group(1)
        break
    return secrets.token_hex(16)
