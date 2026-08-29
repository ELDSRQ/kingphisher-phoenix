"""Response hardening shared by every operator API outcome."""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

HSTS_VALUE = "max-age=31536000"
_HSTS_HEADER = (b"strict-transport-security", HSTS_VALUE.encode("ascii"))


class OperatorSecurityHeadersMiddleware:
    """Stamp HSTS even when an inner middleware returns an early error.

    This is an application-layer contract only.  It does not claim that an
    Azure custom domain, certificate, or edge route has been configured or
    observed live.  ``includeSubDomains`` and ``preload`` are intentionally
    omitted because this application does not own its parent DNS zone.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_hsts(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                if not any(name.lower() == _HSTS_HEADER[0] for name, _ in headers):
                    headers.append(_HSTS_HEADER)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_hsts)
