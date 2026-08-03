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
)
from kp_telemetry.logging import configure_logging

from kp_operator_api.auth import make_idp
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.console import router as console_router
from kp_operator_api.routers import router

_ERROR_STATUS: dict[type[KpError], int] = {
    AuthenticationError: 401,
    PermissionDeniedError: 403,
    NotFoundError: 404,
    ConflictError: 409,
    SafetyRejectionError: 422,
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
    idp = make_idp(settings.oidc_issuer, settings.oidc_audience, settings.require_secret_key().hex())
    queue = JobQueue(settings.redis_url)
    training_domains = {d.strip() for d in settings.training_domains.split(",") if d.strip()}

    app = FastAPI(title=settings.app_name, version="0.1.0")
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.audit_store = audit_store
    app.state.queue = queue
    app.state.idp = idp
    session_factory.configure(**{"info.safety_validator": SafetyValidator(training_domains=training_domains)})

    app.include_router(router)
    app.include_router(console_router)

    _mount_console(app, settings)

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


def _mount_console(app: FastAPI, settings: OperatorApiSettings) -> None:
    """Mount the browser console SPA at /console if the static directory exists.

    The console is optional at import time (tests and containers run without
    it), so a missing directory degrades to an API-only deployment.
    """
    static_dir = Path(settings.console_static_dir)
    if static_dir.is_dir():
        app.mount("/console", StaticFiles(directory=str(static_dir), html=True), name="console")


app = create_app()
