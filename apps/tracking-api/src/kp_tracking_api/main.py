"""Tracking API application assembly."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from kp_database.session import create_db_engine, make_session_factory
from kp_telemetry.errors import ConflictError, KpError, NotFoundError
from kp_telemetry.logging import AccessLogMiddleware, configure_logging
from kp_telemetry.ratelimit import RateLimiter
from sqlalchemy.exc import SQLAlchemyError

from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.middleware import (
    BodyLimitMiddleware,
    PublicExceptionBoundaryMiddleware,
    RequestTargetLimitMiddleware,
    SecurityHeadersMiddleware,
)
from kp_tracking_api.routers import router

_PUBLIC_KP_ERRORS: dict[type[KpError], tuple[int, str, str]] = {
    NotFoundError: (404, "KP-004", "not found"),
    ConflictError: (409, "KP-005", "request conflicts with current state"),
}

_MAX_REQUEST_VALIDATION_ERRORS = 16
_MAX_VALIDATION_LOCATION_PARTS = 8
_VALIDATION_MESSAGES = {
    "missing": "Field is required",
    "string_too_long": "Value exceeds the allowed length",
    "string_too_short": "Value is shorter than the allowed length",
    "too_long": "Collection exceeds the allowed size",
    "too_short": "Collection is smaller than the allowed size",
    "greater_than": "Value is below the allowed range",
    "greater_than_equal": "Value is below the allowed range",
    "less_than": "Value exceeds the allowed range",
    "less_than_equal": "Value exceeds the allowed range",
    "string_pattern_mismatch": "Value has an invalid format",
    "uuid_parsing": "Value must be a valid UUID",
    "datetime_from_date_parsing": "Value must be a valid timestamp",
    "datetime_parsing": "Value must be a valid timestamp",
    "enum": "Value is not an allowed choice",
    "extra_forbidden": "Unexpected field",
    "json_invalid": "Request body must be valid JSON",
    "string_type": "Value is invalid",
    "int_type": "Value is invalid",
    "int_parsing": "Value is invalid",
    "float_type": "Value is invalid",
    "float_parsing": "Value is invalid",
    "bool_type": "Value is invalid",
    "bool_parsing": "Value is invalid",
    "list_type": "Value is invalid",
    "dict_type": "Value is invalid",
    "model_attributes_type": "Value is invalid",
}
_VALIDATION_LOCATION_ROOTS = frozenset({"body", "cookie", "header", "path", "query"})


def _bounded_validation_errors(exc: RequestValidationError) -> tuple[list[dict[str, object]], bool]:
    """Return bounded request metadata without reflecting submitted values.

    Pydantic errors contain the invalid input, validator context, and sometimes
    attacker-controlled mapping keys in their locations. Public responses keep
    only an allowlisted error type, a generic message, and bounded structural
    location metadata.
    """

    errors = exc.errors()
    bounded: list[dict[str, object]] = []
    for error in errors[:_MAX_REQUEST_VALIDATION_ERRORS]:
        raw_type = error.get("type")
        error_type = raw_type if isinstance(raw_type, str) and raw_type in _VALIDATION_MESSAGES else "invalid"
        raw_location = error.get("loc")
        location: list[str | int] = []
        if isinstance(raw_location, tuple | list):
            for index, part in enumerate(raw_location[:_MAX_VALIDATION_LOCATION_PARTS]):
                if index == 0 and isinstance(part, str) and part in _VALIDATION_LOCATION_ROOTS:
                    location.append(part)
                elif isinstance(part, int) and not isinstance(part, bool):
                    location.append(max(-1_000_000, min(part, 1_000_000)))
                else:
                    # Model field names and mapping keys are not needed by a
                    # bearer-only public client and may be attacker chosen.
                    location.append("field")
        bounded.append(
            {
                "type": error_type,
                "loc": location,
                "msg": _VALIDATION_MESSAGES.get(error_type, "Value is invalid"),
            }
        )
    return bounded, len(errors) > _MAX_REQUEST_VALIDATION_ERRORS


def _database_is_ready(engine: object) -> bool:
    """Return whether the primary database can serve a trivial query."""
    try:
        # The concrete value is a SQLAlchemy Engine.  Keeping the helper
        # structural makes dependency-state tests deterministic and avoids
        # exposing backend exceptions through the public readiness response.
        with engine.connect() as connection:  # type: ignore[attr-defined]
            connection.exec_driver_sql("SELECT 1")
    except Exception:
        return False
    return True


def create_app(settings: TrackingApiSettings | None = None) -> FastAPI:
    settings = settings or TrackingApiSettings()
    configure_logging(level=settings.log_level)

    owned_resources = contextlib.ExitStack()
    try:
        engine = create_db_engine(settings.database_url)
        owned_resources.callback(engine.dispose)
        limiter_redis_url = settings.redis_url if settings.rate_limit_backend == "redis" else None
        ip_limiter = RateLimiter(
            limit=settings.rate_limit_ip_per_min,
            window_seconds=60.0,
            max_keys=settings.rate_limit_max_keys,
            redis_url=limiter_redis_url,
            namespace="tracking-ip",
        )
        owned_resources.callback(ip_limiter.close)
        token_limiter = RateLimiter(
            limit=settings.rate_limit_token_per_min,
            window_seconds=60.0,
            max_keys=settings.rate_limit_max_keys,
            redis_url=limiter_redis_url,
            namespace="tracking-token",
        )
        owned_resources.callback(token_limiter.close)
        global_limiter = RateLimiter(
            limit=settings.rate_limit_global_per_min,
            window_seconds=60.0,
            max_keys=1,
            redis_url=limiter_redis_url,
            namespace="tracking-global",
        )
        owned_resources.callback(global_limiter.close)
    except BaseException:
        owned_resources.close()
        raise

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            owned_resources.close()

    # Tracking is a deliberately tiny public bearer surface. Framework
    # documentation and schema endpoints are development conveniences and
    # must not advertise routes or models to unauthenticated recipients.
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.db_engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.ip_limiter = ip_limiter
    app.state.token_limiter = token_limiter
    app.state.global_limiter = global_limiter

    app.include_router(router)

    # HIGH-09 residual: cap request bodies (streaming-safe, 413 on breach).
    # These boundary middleware are registered inside-out. Access logging sees
    # their final statuses, and SecurityHeadersMiddleware remains outermost so
    # it stamps every early rejection and translated error.
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(RequestTargetLimitMiddleware, max_bytes=8192)
    app.add_middleware(PublicExceptionBoundaryMiddleware)
    # Structured access logging replaces uvicorn's plain-text access log
    # (MED-04 / WS-12); uvicorn runs with access_log=False in __main__.
    app.add_middleware(AccessLogMiddleware, logger_name="kp.access.tracking")
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(RequestValidationError)
    async def request_validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        detail, truncated = _bounded_validation_errors(exc)
        return JSONResponse(
            status_code=422,
            content={
                "code": "request_validation_failed",
                "detail": detail,
                "truncated": truncated,
            },
        )

    @app.exception_handler(KpError)
    async def kp_error_handler(_request: Request, exc: KpError) -> JSONResponse:
        status_code, code, detail = _PUBLIC_KP_ERRORS.get(type(exc), (500, "KP-010", "internal server error"))
        return JSONResponse(status_code=status_code, content={"code": code, "detail": detail})

    @app.exception_handler(SQLAlchemyError)
    async def database_error_handler(_request: Request, _exc: SQLAlchemyError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "service temporarily unavailable"})

    @app.get("/livez")
    def livez() -> dict[str, str]:
        """Process liveness only; never call downstream dependencies here."""
        return {"status": "alive"}

    @app.get("/readyz", response_model=None)
    def readyz() -> JSONResponse:
        """Report readiness without leaking database failure details."""
        database_ready = _database_is_ready(app.state.db_engine)
        limiters_ready = all(
            limiter.ready() for limiter in (app.state.ip_limiter, app.state.token_limiter, app.state.global_limiter)
        )
        if not database_ready or not limiters_ready:
            return JSONResponse(status_code=503, content={"status": "not_ready"})
        return JSONResponse(status_code=200, content={"status": "ready"})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Compatibility endpoint retained for existing monitoring clients."""
        return {"status": "ok"}

    return app


app = create_app()
