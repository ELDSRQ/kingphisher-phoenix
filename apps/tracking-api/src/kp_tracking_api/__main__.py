import uvicorn

from kp_tracking_api.config import TrackingApiSettings


def main() -> None:
    settings = TrackingApiSettings()
    uvicorn.run(
        "kp_tracking_api.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        # The application validates the direct peer against its bounded
        # TRACKING_API_TRUSTED_PROXIES networks before reading X-Forwarded-For.
        # Disable uvicorn's independent proxy rewrite so that peer evidence is
        # not changed by an ambient FORWARDED_ALLOW_IPS setting.
        proxy_headers=False,
        access_log=False,  # access log emitted via AccessLogMiddleware (MED-04 / WS-12)
    )


if __name__ == "__main__":
    main()
