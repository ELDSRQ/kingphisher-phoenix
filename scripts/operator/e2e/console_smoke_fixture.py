"""Loopback-only fixture for the console CI smoke; never launch the real stack.

Production authentication, configuration writes, status routing and middleware
remain in use. Audit storage and three ancillary Settings reads are synthetic;
background jobs, service probes and outbound connections are disabled here.
Scratch state is retained under the OS temporary directory for inspection.
"""

from __future__ import annotations

import argparse
import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch

FIXTURE_PASSWORD = "ConsoleSmokeSynthetic2026"  # noqa: S105 - synthetic test credential
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def isolated_environment(scratch: Path, port: int) -> None:
    # Set this before importing any application settings, including main.app.
    # No ambient app/provider/cloud settings, credentials or proxy survive.
    inherited = {
        key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "TMPDIR", "LANG", "SYSTEMROOT"}
    }
    os.environ.clear()
    os.environ.update(inherited)
    os.environ.update(
        {
            "KP_DISABLE_DOTENV": "1",
            "KP_PROFILE": "local-dev",
            "OPERATOR_API_ENV_FILE": str(scratch / ".env"),
            "OPERATOR_API_DATABASE_URL": "postgresql+psycopg://fixture:fixture@127.0.0.1:1/console_smoke",
            "OPERATOR_API_AUDIT_DATABASE_URL": "postgresql+psycopg://fixture:fixture@127.0.0.1:1/console_smoke",
            "OPERATOR_API_REDIS_URL": "redis://127.0.0.1:1/15",
            "OPERATOR_API_TRACKING_BASE_URL": "http://127.0.0.1:1",
            "OPERATOR_API_OIDC_ISSUER": "http://127.0.0.1:1/fixture",
            "OPERATOR_API_OIDC_REDIRECT_URI": f"http://127.0.0.1:{port}/api/v1/console/oidc/callback",
            "OPERATOR_API_CONSOLE_STATIC_DIR": str(PROJECT_ROOT / "apps/operator-ui/src/console"),
            "OPERATOR_API_AUDIT_HMAC_KEY": "11" * 32,
            "OPERATOR_API_CIPHERTEXT_KEK": "22" * 32,
            "OPERATOR_API_CONSOLE_JWT_SECRET": "33" * 32,
            "OPERATOR_API_RECIPIENT_HASH_SALT": "44" * 16,
            "OPERATOR_API_RATE_LIMIT_BACKEND": "memory",
            "OPERATOR_API_AGGREGATION_SCHEDULER_ENABLED": "false",
        }
    )
    env_path = scratch / ".env"
    env_path.write_text(
        f"KP_CONSOLE_PASSWORD={FIXTURE_PASSWORD}\n"
        "OPERATOR_API_OIDC_MODE=dev\n"
        "OPERATOR_API_ONBOARDING_COMPLETED=true\n"
        "OPERATOR_API_APP_NAME=console-smoke-original\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)


class FixtureAuditStore:
    """Record the real config handler's audit calls without a database."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, *, actor: str, action: str, object_type: str, object_id: str, detail: Any = None) -> None:
        self.events.append(
            {
                "actor": str(actor),
                "action": action,
                "object_type": object_type,
                "object_id": object_id,
                "detail": detail,
            }
        )


def create_fixture(scratch: Path, port: int, run_id: str) -> Any:
    isolated_environment(scratch, port)

    # Local imports ensure application settings cannot load the repository .env.
    from fastapi import Depends, Request
    from fastapi.responses import JSONResponse
    from kp_authorization.rbac import Capability
    from kp_operator_api.auth import require_capability
    from kp_operator_api.console import runtime_status
    from kp_operator_api.main import app
    from sqlalchemy import event

    audit = FixtureAuditStore()
    app.state.audit_store = audit
    runtime_status._tcp_ok = lambda *_args: False
    runtime_status._http_ok = lambda *_args: False

    def forbid_database_connect(*_args: Any, **_kwargs: Any) -> None:
        # psycopg connects in native code, outside the Python socket guard.
        raise RuntimeError("smoke fixture forbids database connections")

    for engine in (app.state.db_engine, app.state.audit_engine):
        event.listen(engine, "do_connect", forbid_database_connect)

    @asynccontextmanager
    async def fixture_lifespan(_app: Any) -> AsyncIterator[None]:
        # Do not start production audit/aggregation jobs. Close only resources
        # constructed by this fixture's own app, without deleting its evidence.
        try:
            yield
        finally:
            app.state.queue.close()
            for name in ("user_limiter", "ip_limiter", "login_throttle"):
                getattr(app.state, name).close()
            app.state.db_engine.dispose()
            app.state.audit_engine.dispose()

    app.router.lifespan_context = fixture_lifespan
    ancillary = {
        "/api/v1/campaigns/needs-my-decision": (Capability.APPROVE_SECURITY, []),
        "/api/v1/kill-switch": (Capability.USE_KILL_SWITCH, {"engaged": True, "generation": 0}),
        "/api/v1/console/ai-providers": (Capability.MANAGE_ROLES, {"managed": False, "providers": []}),
    }
    # These fixture reads preserve capability checks and never claim live
    # campaign/provider/audit readiness. Their corresponding mutations stay blocked.
    fixture_reads = []

    def reader(value: Any) -> Any:
        def fixture_read() -> Any:
            return value

        return fixture_read

    for path, (capability, payload) in ancillary.items():
        app.add_api_route(
            path, reader(payload), methods=["GET"], dependencies=[Depends(require_capability(capability))]
        )
        fixture_reads.append(app.router.routes.pop())
    # Give these handlers priority over included production routers (which
    # recent FastAPI versions retain as nested router objects).
    app.router.routes[0:0] = fixture_reads

    @app.get("/__smoke__/ready")
    def fixture_ready() -> dict[str, str]:
        return {"fixture": "console-ci-smoke", "run_id": run_id}

    @app.get("/__smoke__/audit", dependencies=[Depends(require_capability(Capability.VIEW_AUDIT))])
    def fixture_audit() -> dict[str, Any]:
        return {"events": audit.events}

    allowed = {
        ("GET", "/__smoke__/ready"),
        ("GET", "/__smoke__/audit"),
        ("GET", "/api/v1/console/auth-mode"),
        ("GET", "/api/v1/console/session"),
        ("POST", "/api/v1/console/session"),
        ("POST", "/api/v1/console/logout"),
        ("GET", "/api/v1/console/onboarding"),
        ("GET", "/api/v1/console/config"),
        ("PUT", "/api/v1/console/config"),
        ("GET", "/api/v1/console/status"),
        *(("GET", path) for path in ancillary),
    }

    @app.middleware("http")
    async def fixture_boundary(request: Request, call_next: Any) -> Any:
        if request.client is None or request.client.host not in {"127.0.0.1", "testclient"}:
            return JSONResponse({"detail": "fixture is loopback-only"}, status_code=403)
        static = request.method in {"GET", "HEAD"} and request.url.path.startswith("/console/")
        if not static and (request.method, request.url.path) not in allowed:
            return JSONResponse({"detail": "route is outside this isolated smoke fixture"}, status_code=503)
        return await call_next(request)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", choices=["127.0.0.1"], default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be an unprivileged loopback port")
    scratch = Path(tempfile.mkdtemp(prefix="kp-console-ci-smoke-"))
    app = create_fixture(scratch, args.port, args.run_id)

    import uvicorn

    # Accept loopback browser requests, but fail closed on every outbound socket
    # connection, even if a future admitted handler attempts service access.
    with (
        patch("socket.socket.connect", side_effect=RuntimeError("smoke fixture forbids outbound connections")),
        patch("socket.socket.connect_ex", side_effect=RuntimeError("smoke fixture forbids outbound connections")),
    ):
        uvicorn.run(app, host=args.host, port=args.port, access_log=False, proxy_headers=False)


if __name__ == "__main__":
    main()
