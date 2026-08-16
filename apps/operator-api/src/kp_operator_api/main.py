"""Operator API application assembly."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from kp_contracts.queue import JobQueue
from kp_database.audit_store import AuditStore
from kp_database.models import CipherText
from kp_database.session import create_db_engine, make_session_factory
from kp_safety_validation.validator import SafetyValidator
from kp_telemetry.errors import (
    AuditFailureError,
    AuthenticationError,
    ConflictError,
    KpError,
    NotFoundError,
    PermissionDeniedError,
    SafetyRejectionError,
    ValidationError_,
)
from kp_telemetry.logging import AccessLogMiddleware, configure_logging
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kp_operator_api.auth import make_idp
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.console import router as console_router
from kp_operator_api.ratelimit import LoginThrottle, RateLimiter
from kp_operator_api.routers import router


class _BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Enforce the body cap while streaming, including chunked requests."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
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


_ERROR_STATUS: dict[type[KpError], int] = {
    AuthenticationError: 401,
    PermissionDeniedError: 403,
    NotFoundError: 404,
    ConflictError: 409,
    SafetyRejectionError: 422,
    ValidationError_: 422,
    AuditFailureError: 500,
}


def create_app(settings: OperatorApiSettings | None = None) -> FastAPI:
    settings = settings or OperatorApiSettings()
    configure_logging(level=settings.log_level)

    engine = create_db_engine(settings.database_url)
    audit_engine = create_db_engine(settings.audit_database_url)
    session_factory = make_session_factory(engine)
    audit_store = AuditStore(audit_engine, settings.require_secret_key())
    CipherText.configure_key(settings.require_cipher_kek())
    idp = make_idp(
        settings.oidc_issuer,
        settings.oidc_audience,
        mode=settings.oidc_mode,
        dev_secret=settings.require_console_jwt_secret().decode(),
    )
    queue = JobQueue(settings.redis_url)
    training_domains = {d.strip() for d in settings.training_domains.split(",") if d.strip()}

    app = FastAPI(title=settings.app_name, version="0.1.0")
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.audit_store = audit_store
    app.state.queue = queue
    app.state.idp = idp
    app.state.user_limiter = RateLimiter(limit=settings.rate_limit_user_per_min, window_seconds=60.0)
    app.state.ip_limiter = RateLimiter(limit=settings.rate_limit_ip_per_min, window_seconds=60.0)
    app.state.login_throttle = LoginThrottle()
    # `info` is a sessionmaker keyword: per-session `.info` carries the validator
    # (previously the kwarg name was mangled and the value never reached sessions).
    session_factory.configure(info={"safety_validator": SafetyValidator(training_domains=training_domains)})

    app.include_router(router)
    app.include_router(console_router)

    _mount_console(app, settings)

    # Structured access logging replaces uvicorn's plain-text access log
    # (MED-04 / WS-12); uvicorn runs with access_log=False in __main__.
    app.add_middleware(AccessLogMiddleware, logger_name="kp.access.operator")
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next: RequestResponseEndpoint) -> Response:
        if _too_large(request, settings.max_body_bytes):
            return JSONResponse(status_code=413, content={"detail": "request body too large"})
        client_ip = request.client.host if request.client else "unknown"
        if not app.state.ip_limiter.allow(client_ip):
            return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/console"):
            response.headers.setdefault("Content-Security-Policy", _CONSOLE_CSP)
        return response

    @app.exception_handler(KpError)
    async def kp_error_handler(request: Request, exc: KpError) -> JSONResponse:
        status_code = _ERROR_STATUS.get(type(exc), 500)
        return JSONResponse(status_code=status_code, content={"code": exc.code, "detail": str(exc)})

    @app.exception_handler(AuthenticationError)
    async def auth_error_handler(request: Request, exc: AuthenticationError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"code": exc.code, "detail": str(exc)})

    @app.exception_handler(PermissionDeniedError)
    async def permission_error_handler(request: Request, exc: PermissionDeniedError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"code": exc.code, "detail": str(exc)})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


_CONSOLE_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'"


def _too_large(request: Request, max_bytes: int) -> bool:
    length = request.headers.get("content-length")
    if length and length.isdigit():
        return int(length) > max_bytes
    return False


def _mount_console(app: FastAPI, settings: OperatorApiSettings) -> None:
    """Mount the browser console SPA at /console if the static directory exists.

    The console is optional at import time (tests and containers run without
    it), so a missing directory degrades to an API-only deployment.
    """
    static_dir = Path(settings.console_static_dir)
    if static_dir.is_dir():
        app.mount("/console", StaticFiles(directory=str(static_dir), html=True), name="console")


app = create_app()
