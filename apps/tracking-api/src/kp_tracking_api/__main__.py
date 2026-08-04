import uvicorn

from kp_tracking_api.config import TrackingApiSettings


def main() -> None:
    settings = TrackingApiSettings()
    uvicorn.run(
        "kp_tracking_api.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        access_log=False,  # access log emitted via AccessLogMiddleware (MED-04 / WS-12)
    )


if __name__ == "__main__":
    main()
