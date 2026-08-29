"""ASGI middleware for the tracking API.

BodyLimitMiddleware mirrors the operator API's body cap (HIGH-09 residual):
a content-length pre-check plus a streaming guard, so chunked uploads without
a content-length are also capped. SecurityHeadersMiddleware stamps privacy
and hardening headers on every response — including error responses and the
click 302 — because tracking URLs embed bearer credentials; without
`Referrer-Policy: no-referrer` the redirect destination would receive the
bearer via the `Referer` header.
"""

from __future__ import annotations

from kp_telemetry.logging import get_logger
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class _BodyTooLarge(Exception):
    pass


class _InvalidContentLength(Exception):
    pass


def _content_length(scope: Scope) -> int | None:
    values = [value for name, value in scope.get("headers", []) if name.lower() == b"content-length"]
    if not values:
        return None
    # Reject duplicates, including identical values. Accepting multiple
    # Content-Length fields creates request-smuggling ambiguity between
    # proxies and the application server.
    if len(values) != 1 or not values[0].isdigit():
        raise _InvalidContentLength
    # Avoid Python's integer-string digit limit becoming an unhandled 500.
    # Any 20+ digit request length is well beyond this service's body cap.
    if len(values[0]) > 19:
        return 10**19
    return int(values[0])


class BodyLimitMiddleware:
    """Enforce the body cap while streaming, including chunked requests."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            length = _content_length(scope)
        except _InvalidContentLength:
            response = JSONResponse(status_code=400, content={"detail": "invalid content length"})
            await response(scope, receive, send)
            return
        if length is not None and length > self.max_bytes:
            response = JSONResponse(status_code=413, content={"detail": "request body too large"})
            await response(scope, receive, send)
            return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            response = JSONResponse(status_code=413, content={"detail": "request body too large"})
            await response(scope, limited_receive, send)


class RequestTargetLimitMiddleware:
    """Reject oversized paths/queries before routing or log enrichment."""

    def __init__(self, app: ASGIApp, *, max_bytes: int = 8192) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        raw_path = scope.get("raw_path")
        if not isinstance(raw_path, bytes):
            raw_path = str(scope.get("path", "")).encode("utf-8", errors="replace")
        query = scope.get("query_string", b"")
        query_bytes = query if isinstance(query, bytes) else b""
        separator_size = 1 if query_bytes else 0
        if len(raw_path) + separator_size + len(query_bytes) > self.max_bytes:
            response = JSONResponse(status_code=414, content={"detail": "request target too large"})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class PublicExceptionBoundaryMiddleware:
    """Translate unexpected failures without reflecting secrets or internals."""

    _SAFE_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.logger = get_logger("kp.tracking.errors")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        response_started = False

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        except Exception as exc:
            route = scope.get("route")
            route_template = getattr(route, "path", None)
            if not isinstance(route_template, str) or not route_template.startswith("/"):
                route_template = "<unmatched>"
            method = scope.get("method")
            self.logger.error(
                "unexpected_request_error",
                exception_type=type(exc).__name__[:128],
                method=method if method in self._SAFE_METHODS else "UNKNOWN",
                route=route_template,
            )
            if response_started:
                raise
            response = JSONResponse(status_code=500, content={"detail": "internal server error"})
            await response(scope, receive, send)


_SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"cache-control", b"no-store"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"referrer-policy", b"no-referrer"),
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"x-robots-tag", b"noindex, nofollow, noarchive"),
)


class SecurityHeadersMiddleware:
    """Set privacy/hardening headers on every HTTP response (no route edits)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                present = {name.lower() for name, _ in headers}
                for name, value in _SECURITY_HEADERS:
                    if name not in present:
                        headers.append((name, value))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
