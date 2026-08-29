"""Operator API application assembly."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
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
from kp_telemetry.logging import AccessLogMiddleware, configure_logging, get_logger
from kp_telemetry.settings import local_dotenv_file
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kp_operator_api.acs_receipts import EventGridTokenVerifier
from kp_operator_api.acs_receipts import router as acs_receipts_router
from kp_operator_api.analytics_routes import router as analytics_router
from kp_operator_api.auth import make_idp
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.console import router as console_router
from kp_operator_api.program_routes import router as program_router
from kp_operator_api.ratelimit import LoginThrottle, RateLimiter
from kp_operator_api.routers import router
from kp_operator_api.security_headers import HSTS_VALUE, OperatorSecurityHeadersMiddleware
from kp_operator_api.threat_routes import router as threat_router
from kp_operator_api.training_library import router as training_library_router


class _BodyTooLarge(Exception):
    pass


class _InvalidContentLength(Exception):
    pass


def _content_length(scope: Scope) -> int | None:
    values = [value for name, value in scope.get("headers", []) if name.lower() == b"content-length"]
    if not values:
        return None
    # Multiple Content-Length fields are ambiguous across proxies even when
    # their values match, so reject them at the application boundary.
    if len(values) != 1 or not values[0].isdigit():
        raise _InvalidContentLength
    # Keep Python's integer-string limit from turning an attacker-controlled
    # header into an unhandled exception. Twenty digits already exceeds every
    # supported request limit.
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


_ERROR_STATUS: dict[type[KpError], int] = {
    AuthenticationError: 401,
    PermissionDeniedError: 403,
    NotFoundError: 404,
    ConflictError: 409,
    SafetyRejectionError: 422,
    ValidationError_: 422,
    AuditFailureError: 503,
}

_DEFAULT_AUDIT_VERIFY_INTERVAL_SECONDS = 6 * 60 * 60
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_MAX_REQUEST_VALIDATION_ERRORS = 16
_MAX_VALIDATION_LOCATION_PARTS = 8


def _bounded_validation_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    """Return useful request errors without reflecting attacker-controlled input.

    FastAPI's default response includes each invalid value and validator
    context. A single oversized or secret-bearing field can therefore be
    amplified into the response. Keep only bounded location/type metadata and
    a message chosen from a small, application-owned vocabulary.
    """

    messages = {
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
    }
    bounded: list[dict[str, Any]] = []
    for error in exc.errors()[:_MAX_REQUEST_VALIDATION_ERRORS]:
        raw_type = error.get("type")
        error_type = raw_type if isinstance(raw_type, str) and raw_type.replace("_", "").isalnum() else "invalid"
        error_type = error_type[:64]
        location: list[str | int] = []
        raw_location = error.get("loc")
        if isinstance(raw_location, tuple | list):
            for part in raw_location[:_MAX_VALIDATION_LOCATION_PARTS]:
                if isinstance(part, int) and not isinstance(part, bool):
                    location.append(max(-1_000_000, min(part, 1_000_000)))
                elif isinstance(part, str) and part:
                    location.append(part[:64] if part.replace("_", "").replace("-", "").isalnum() else "field")
        bounded.append(
            {
                "type": error_type,
                "loc": location,
                "msg": messages.get(error_type, "Value is invalid"),
            }
        )
    return bounded


# Every unsafe API route is protected by default. These narrowly enumerated
# operations must remain reachable for authentication, recovery, harmless
# rendering/validation, or local console control that cannot share the
# database transaction. Adding a new mutation never requires updating the
# gate; adding a new exemption requires an explicit security review.
_AUDIT_GATE_EXEMPT_ROUTES = frozenset(
    {
        ("POST", "/api/v1/audit/verify"),
        ("POST", "/api/v1/console/azure-deployment/validate"),
        ("PUT", "/api/v1/console/config"),
        ("POST", "/api/v1/console/logout"),
        ("PUT", "/api/v1/console/onboarding"),
        ("POST", "/api/v1/console/onboarding/assist"),
        ("POST", "/api/v1/console/onboarding/test"),
        ("POST", "/api/v1/console/restart"),
        ("POST", "/api/v1/console/session"),
        ("POST", "/api/v1/kill-switch"),
        ("POST", "/api/v1/templates/preview"),
    }
)


def _requires_healthy_audit(method: str, path: str) -> bool:
    """Fail closed for every unsafe API operation unless explicitly exempt."""
    normalized_method = method.upper()
    return (
        normalized_method in _UNSAFE_METHODS
        and path.startswith("/api/v1/")
        and (normalized_method, path) not in _AUDIT_GATE_EXEMPT_ROUTES
    )


def _audit_mutation_state_is_healthy(verifier: Any, audit_store: Any) -> bool:
    """Fail closed unless both chain verification and outbox health are known-good."""
    if verifier is None or getattr(verifier, "status", None) != "ok":
        return False
    outbox_health = getattr(audit_store, "outbox_health", None)
    if not callable(outbox_health):
        return False
    try:
        state = outbox_health()
        return all(int(state[name]) == 0 for name in ("overdue_pending", "failed", "dispatching_stale"))
    except (KeyError, TypeError, ValueError, OSError, RuntimeError):
        return False


def _normalized_origin(value: str, *, configured_url: bool = False) -> str | None:
    """Return a canonical HTTP origin, or ``None`` for an invalid value.

    The configured redirect URI is a full URL and may contain its callback
    path. A browser ``Origin`` value may contain only the origin itself. Both
    forms reject credentials and normalize default ports so comparison does
    not depend on reverse-proxy Host or scheme headers.
    """
    if not value or value != value.strip() or any(character.isspace() for character in value):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (not configured_url and (parsed.path not in {"", "/"} or parsed.query))
    ):
        return None
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}{f':{port}' if port is not None and port != default_port else ''}"


def _csrf_rejection(request: Request, trusted_origin: str) -> str | None:
    """Return a rejection reason for an unsafe cookie-authenticated request."""
    if request.method.upper() not in _UNSAFE_METHODS or "kp_oidc_session" not in request.cookies:
        return None

    # get_principal gives a well-formed Bearer header precedence over the
    # session cookie. Preserve non-browser API clients that happen to retain a
    # cookie while ensuring malformed/other auth schemes do not bypass CSRF.
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer ") and authorization.removeprefix("Bearer ").strip():
        return None

    origin_header = request.headers.get("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    if origin_header is None and fetch_site is None:
        return "cookie-authenticated unsafe requests require same-origin browser metadata"
    if origin_header is not None and _normalized_origin(origin_header) != trusted_origin:
        return "request origin does not match the configured operator origin"
    if fetch_site is not None and fetch_site.lower().strip() != "same-origin":
        return "request fetch site is not same-origin"
    return None


class _AuditVerificationSettings(BaseSettings):
    """Env knob for the scheduled audit verification interval.

    Declared here rather than config.py to respect this wave's file ownership
    boundaries; mirrors the main settings' env/.env loading semantics. An
    invalid value fails startup loudly, like every other misconfigured
    setting.
    """

    model_config = SettingsConfigDict(
        env_prefix="OPERATOR_API_",
        env_file=local_dotenv_file(),
        extra="ignore",
        hide_input_in_errors=True,
    )

    audit_verify_interval_seconds: int = Field(default=_DEFAULT_AUDIT_VERIFY_INTERVAL_SECONDS, ge=1)


class _RateLimitSettings(BaseSettings):
    """Select the shared backend explicitly for managed runtime deployments."""

    model_config = SettingsConfigDict(
        env_prefix="OPERATOR_API_",
        env_file=local_dotenv_file(),
        extra="ignore",
        hide_input_in_errors=True,
    )

    rate_limit_backend: Literal["memory", "redis"] = "memory"


def _audit_verify_interval_seconds() -> int:
    return _AuditVerificationSettings().audit_verify_interval_seconds


def _database_is_ready(engine: Any) -> bool:
    """Return whether a database can serve a trivial query.

    Readiness deliberately collapses connection and query failures to a
    boolean.  The HTTP response must not disclose connection details or
    backend error messages.
    """
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
    except Exception:
        return False
    return True


def _queue_is_ready(queue: JobQueue) -> bool:
    """Return whether the queue backend is reachable."""
    try:
        # JobQueue owns the Redis client but has no public health operation.
        # Keeping the probe here avoids changing the queue contract solely for
        # deployment health checks.
        return bool(queue._client.ping())
    except Exception:
        return False


class AuditVerificationScheduler:
    """Continuously verify the audit hash chain (CRIT-06 residual).

    Verification previously ran only on demand (POST /audit/verify, make
    verify-audit), so a tampered chain could sit undetected until someone
    asked. This scheduler runs AuditStore.verify() at startup and then every
    interval. A failing verification (or a verification that raises) is logged
    CRITICAL with a bounded count and mirrored into aggregate state for
    /healthz. The verifier deliberately does not retain the problem strings:
    they can contain actor identifiers, actions, timestamps, and chain hashes.
    Fail-closed philosophy: errors never escape the loop and never take the API
    down; they stay loud and visible instead.
    """

    def __init__(
        self,
        audit_store: AuditStore,
        *,
        interval_seconds: float,
        logger: Any | None = None,
    ) -> None:
        self._audit_store = audit_store
        # Clamp so a misconfigured negative interval cannot spin the loop.
        self._interval_seconds = max(0.0, float(interval_seconds))
        self._logger = logger if logger is not None else get_logger("kp.audit.verify")
        self.status = "pending"  # pending | ok | failing | error
        self.problem_count = 0
        self._blocking_tasks: set[asyncio.Task[Any]] = set()
        self._stopping = False

    def _blocking_done(self, task: asyncio.Task[Any]) -> None:
        self._blocking_tasks.discard(task)
        # Cancellation of the scheduler intentionally leaves the shielded
        # thread task running. Retrieve a later exception so asyncio never
        # reports it as an abandoned task; verify_once handles exceptions on
        # the normal awaited path.
        if not task.cancelled():
            task.exception()

    async def _run_blocking(self, operation: Callable[[], Any]) -> Any:
        if self._stopping:
            raise asyncio.CancelledError
        task = asyncio.create_task(asyncio.to_thread(operation), name="audit-verification-blocking")
        self._blocking_tasks.add(task)
        task.add_done_callback(self._blocking_done)
        # Shield the actual thread future. Cancelling run() stays prompt, but
        # does not discard the handle needed to join it before engine disposal.
        return await asyncio.shield(task)

    async def verify_once(self) -> None:
        """One verification pass; records state and never raises (except cancellation)."""
        try:
            dispatch = getattr(self._audit_store, "dispatch_pending_audit", None)
            if dispatch is not None:
                await self._run_blocking(dispatch)
            problems = await self._run_blocking(self._audit_store.verify)
            if problems:
                # Audit writers can advance the chain between the verifier's
                # event and head reads. Confirm a bad snapshot immediately so
                # a single concurrent append cannot pin readiness in the
                # failing state for the full verification interval. Persistent
                # corruption still fails closed on the consecutive check.
                problems = await self._run_blocking(self._audit_store.verify)
        except Exception as exc:
            # Chain state unknown (e.g. audit store unreachable) — treat as a
            # tamper-relevant fault, not a reason to crash the API loop.
            self.status = "error"
            self.problem_count = 0
            self._logger.critical(
                "audit_chain_verification_error",
                exception_type=type(exc).__name__[:128],
            )
            return
        if problems:
            self.status = "failing"
            self.problem_count = min(len(problems), 10_000)
            self._logger.critical(
                "audit_chain_verification_failed",
                status="failing",
                problem_count=self.problem_count,
            )
        else:
            self.status = "ok"
            self.problem_count = 0
            self._logger.info("audit_chain_verified", detail="audit chain intact")

    async def run(self) -> None:
        while True:
            await self.verify_once()
            await asyncio.sleep(self._interval_seconds)

    async def shutdown(self) -> None:
        """Join owned blocking passes before their database engines close.

        ``Task.cancel()`` cannot stop a function already running in a worker
        thread. Keep cancellation prompt for the scheduler itself, then wait
        only for this scheduler's shielded work. Repeated calls are safe.
        """

        self._stopping = True
        cancelled = False
        while self._blocking_tasks:
            snapshot = tuple(self._blocking_tasks)
            joiner = asyncio.gather(*snapshot, return_exceptions=True)
            while not joiner.done():
                try:
                    await asyncio.shield(joiner)
                except asyncio.CancelledError:
                    # Finish the resource-ordering fence even if shutdown is
                    # cancelled; propagate cancellation once joining is safe.
                    cancelled = True
            # Retrieve gather's result/exception before taking a new snapshot.
            joiner.result()
            # Done callbacks normally remove these first. Discard explicitly
            # as well so shutdown cannot spin if callback scheduling is delayed.
            self._blocking_tasks.difference_update(snapshot)
        if cancelled:
            raise asyncio.CancelledError


def create_app(settings: OperatorApiSettings | None = None) -> FastAPI:
    settings = settings or OperatorApiSettings()
    configure_logging(level=settings.log_level)
    unexpected_error_logger = get_logger("kp.operator.errors")
    trusted_operator_origin = _normalized_origin(settings.oidc_redirect_uri, configured_url=True)
    if trusted_operator_origin is None:
        raise ValueError("OPERATOR_API_OIDC_REDIRECT_URI must contain a valid HTTP(S) operator origin")

    owned_resources = contextlib.ExitStack()
    try:
        engine = create_db_engine(settings.database_url)
        owned_resources.callback(engine.dispose)
        audit_engine = create_db_engine(settings.audit_database_url)
        owned_resources.callback(audit_engine.dispose)
        session_factory = make_session_factory(engine)
        # The signing root is held by the NOLOGIN database owner and migration
        # workload. API replicas stage intent only; they never receive the key.
        legacy_audit_key = settings.require_secret_key() if settings.audit_hmac_key else None
        audit_store = AuditStore(audit_engine, legacy_audit_key)
        if hasattr(audit_store, "bind_intent_engine"):
            audit_store.bind_intent_engine(engine)
        ciphertext_key_id, ciphertext_key, ciphertext_prior_keys = settings.require_cipher_keyring()
        CipherText.configure_keyring(ciphertext_key_id, ciphertext_key, ciphertext_prior_keys)
        idp = make_idp(
            settings.oidc_issuer,
            settings.oidc_audience,
            mode=settings.oidc_mode,
            dev_secret=settings.require_console_jwt_secret().decode(),
        )
        queue = JobQueue(settings.redis_url)
        owned_resources.callback(queue.close)
        event_grid_values = (
            settings.acs_receipt_signing_key,
            settings.event_grid_tenant_id,
            settings.event_grid_audience,
            settings.event_grid_subscription_name,
            settings.event_grid_topic,
        )
        if any(event_grid_values) and not all(event_grid_values):
            raise ValueError("ACS Event Grid receipt ingress configuration is incomplete")
        event_grid_token_verifier = EventGridTokenVerifier(settings) if all(event_grid_values) else None
        training_domains = {d.strip() for d in settings.training_domains.split(",") if d.strip()}
        audit_verifier = AuditVerificationScheduler(
            audit_store,
            interval_seconds=_audit_verify_interval_seconds(),
        )

        rate_limit_backend = _RateLimitSettings().rate_limit_backend
        if rate_limit_backend == "redis" and not settings.redis_url.strip():
            raise ValueError("OPERATOR_API_REDIS_URL is required when rate limiting uses Redis")
        limiter_redis_url = settings.redis_url if rate_limit_backend == "redis" else None
        user_limiter = RateLimiter(
            limit=settings.rate_limit_user_per_min,
            window_seconds=60.0,
            redis_url=limiter_redis_url,
            namespace="operator-user",
        )
        owned_resources.callback(user_limiter.close)
        ip_limiter = RateLimiter(
            limit=settings.rate_limit_ip_per_min,
            window_seconds=60.0,
            redis_url=limiter_redis_url,
            namespace="operator-ip",
        )
        owned_resources.callback(ip_limiter.close)
        login_throttle = LoginThrottle(
            redis_url=limiter_redis_url,
            namespace="operator-login",
        )
        owned_resources.callback(login_throttle.close)
    except BaseException:
        owned_resources.close()
        raise

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # Scheduled audit verification: first pass fires at startup, then every
        # interval. Cancelled on shutdown so exits stay graceful.
        verifier_task = asyncio.create_task(audit_verifier.run(), name="audit-verification")
        try:
            yield
        finally:
            try:
                verifier_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await verifier_task
                await audit_verifier.shutdown()
            finally:
                orchestrator = getattr(app.state, "deployment_orchestrator", None)
                close_orchestrator = getattr(orchestrator, "close_owned_resources", None)
                if getattr(orchestrator, "owns_resources", False) and callable(close_orchestrator):
                    owned_resources.callback(close_orchestrator)
                owned_resources.close()

    # This product is operated through the browser console. Publishing the
    # framework's developer schema and interactive documentation adds an
    # unauthenticated discovery surface without helping normal operation.
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
    app.state.audit_engine = audit_engine
    app.state.session_factory = session_factory
    app.state.audit_store = audit_store
    app.state.audit_verifier = audit_verifier
    # Deliberate test seam: production uses the real chain/outbox state below;
    # focused unit tests may replace this zero-argument checker with a fake.
    app.state.audit_health_check = lambda: _audit_mutation_state_is_healthy(
        app.state.audit_verifier,
        app.state.audit_store,
    )
    app.state.queue = queue
    app.state.event_grid_token_verifier = event_grid_token_verifier
    app.state.idp = idp
    app.state.user_limiter = user_limiter
    app.state.ip_limiter = ip_limiter
    app.state.login_throttle = login_throttle
    app.state.trusted_operator_origin = trusted_operator_origin
    # `info` is a sessionmaker keyword: per-session `.info` carries the validator
    # (previously the kwarg name was mangled and the value never reached sessions).
    session_factory.configure(info={"safety_validator": SafetyValidator(training_domains=training_domains)})

    app.include_router(router)
    app.include_router(analytics_router)
    app.include_router(program_router)
    app.include_router(training_library_router)
    app.include_router(threat_router)
    app.include_router(console_router)
    app.include_router(acs_receipts_router)

    _mount_console(app, settings)

    # Structured access logging replaces uvicorn's plain-text access log
    # (MED-04 / WS-12); uvicorn runs with access_log=False in __main__.
    app.add_middleware(AccessLogMiddleware, logger_name="kp.access.operator")
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            length = _content_length(request.scope)
        except _InvalidContentLength:
            return JSONResponse(status_code=400, content={"detail": "invalid content length"})
        if length is not None and length > settings.max_body_bytes:
            return JSONResponse(status_code=413, content={"detail": "request body too large"})
        csrf_rejection = _csrf_rejection(request, trusted_operator_origin)
        if csrf_rejection is not None:
            return JSONResponse(
                status_code=403,
                content={"code": "csrf_rejected", "detail": csrf_rejection},
            )
        if request.url.path not in {"/livez", "/readyz", "/healthz"}:
            client_ip = request.client.host if request.client else "unknown"
            if not app.state.ip_limiter.allow(client_ip):
                return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
        if _requires_healthy_audit(request.method, request.url.path):
            try:
                audit_healthy = bool(app.state.audit_health_check())
            except Exception:
                audit_healthy = False
            if not audit_healthy:
                return JSONResponse(
                    status_code=503,
                    content={
                        "code": "audit_integrity_unhealthy",
                        "detail": "privileged changes are disabled",
                    },
                )
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/console"):
            response.headers.setdefault("Content-Security-Policy", _CONSOLE_CSP)
        return response

    # Registered after every inner request middleware so HSTS is also present
    # on their early 4xx/5xx responses. This header is not evidence that the
    # selected Azure hostname or its certificate has been configured live.
    app.add_middleware(OperatorSecurityHeadersMiddleware)

    @app.exception_handler(RequestValidationError)
    async def request_validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=422,
            content={
                "code": "request_validation_failed",
                "detail": _bounded_validation_errors(exc),
                "truncated": len(exc.errors()) > _MAX_REQUEST_VALIDATION_ERRORS,
            },
        )

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

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        # Starlette's server-error boundary sits outside user middleware, so
        # its response needs the header explicitly. Keep the response bounded
        # and avoid reflecting exception or request detail.
        route = request.scope.get("route")
        route_template = getattr(route, "path", None)
        if not isinstance(route_template, str) or not route_template.startswith("/"):
            route_template = "unmatched"
        unexpected_error_logger.error(
            "unexpected_request_error",
            exception_type=type(exc).__name__[:128],
            method=request.method if request.method in _UNSAFE_METHODS | {"GET", "HEAD", "OPTIONS"} else "UNKNOWN",
            route_template=route_template,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "internal server error"},
            headers={"Strict-Transport-Security": HSTS_VALUE},
        )

    @app.get("/livez")
    def livez() -> dict[str, str]:
        """Process liveness only; never call downstream dependencies here."""
        return {"status": "alive"}

    @app.get("/readyz", response_model=None)
    def readyz() -> JSONResponse:
        """Fail closed until all dependencies and audit integrity are ready."""
        verifier: AuditVerificationScheduler = app.state.audit_verifier
        primary_database_ready = _database_is_ready(app.state.db_engine)
        audit_database_ready = primary_database_ready and _database_is_ready(app.state.audit_engine)
        dependency_state = {
            "primary_database": primary_database_ready,
            "audit_database": audit_database_ready,
            "queue": _queue_is_ready(app.state.queue),
            "rate_limits": all(
                limiter.ready() for limiter in (app.state.user_limiter, app.state.ip_limiter, app.state.login_throttle)
            ),
            "audit_chain": verifier.status == "ok",
        }
        ready = all(dependency_state.values())
        if not ready:
            return JSONResponse(status_code=503, content={"status": "not_ready"})
        return JSONResponse(status_code=200, content={"status": "ready"})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        # Compatibility endpoint for existing monitors.  New deployment
        # probes use /livez and /readyz so this legacy HTTP 200 contract can be
        # retained while JSON-aware clients continue to see audit degradation.
        # Audit verification details can contain actors, actions, timestamps,
        # and chain hashes. Detail is available through authenticated audit
        # tooling; this compatibility endpoint exposes aggregate state only.
        verifier: AuditVerificationScheduler | None = getattr(app.state, "audit_verifier", None)
        if verifier is not None and verifier.status in ("failing", "error"):
            return {"status": "degraded", "audit_verification": verifier.status}
        return {"status": "ok"}

    return app


_CONSOLE_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'"


def _mount_console(app: FastAPI, settings: OperatorApiSettings) -> None:
    """Mount the browser console SPA at /console if the static directory exists.

    The console is optional at import time (tests and containers run without
    it), so a missing directory degrades to an API-only deployment.
    """
    static_dir = Path(settings.console_static_dir)
    if static_dir.is_dir():
        app.mount("/console", StaticFiles(directory=str(static_dir), html=True), name="console")


app = create_app()
