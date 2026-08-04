import uvicorn

from kp_operator_api.config import OperatorApiSettings


def main() -> None:
    settings = OperatorApiSettings()
    uvicorn.run(
        "kp_operator_api.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        access_log=False,  # access log emitted via AccessLogMiddleware (MED-04 / WS-12)
    )


if __name__ == "__main__":
    main()
