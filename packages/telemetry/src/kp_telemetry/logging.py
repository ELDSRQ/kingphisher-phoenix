"""Structured logging with PII redaction.

Implements §27.1 of the reconstructed spec: JSON logs via structlog with
a redaction processor that masks PII patterns and never logs raw tracking
tokens.
"""

from __future__ import annotations

import json
import re
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
    # Structured context is extensible, so an allow-list of field names is not
    # a safe redaction boundary.  Process every value, including values bound
    # by middleware and third-party integrations.
    for key, value in event_dict.items():
        event_dict[key] = redact_value(value)
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

        async def _send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder[0] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, _send)
        except Exception:
            self.logger.exception("request_failed", method=scope.get("method"), route=self._route_template(scope))
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
