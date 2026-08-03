"""Tracking API application assembly."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from kp_database.session import create_db_engine, make_session_factory
from kp_telemetry.errors import ConflictError, KpError, NotFoundError
from kp_telemetry.logging import configure_logging

from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.routers import router


def create_app(settings: TrackingApiSettings | None = None) -> FastAPI:
    settings = settings or TrackingApiSettings()
    configure_logging(level=settings.log_level)

    engine = create_db_engine(settings.database_url)
    app = FastAPI(title=settings.app_name, version="0.1.0")
    app.state.settings = settings
    app.state.session_factory = make_session_factory(engine)

    app.include_router(router)

    @app.exception_handler(KpError)
    async def kp_error_handler(request: Request, exc: KpError) -> JSONResponse:
        status_code = {NotFoundError: 404, ConflictError: 409}.get(type(exc), 500)
        return JSONResponse(status_code=status_code, content={"code": exc.code, "detail": str(exc)})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
