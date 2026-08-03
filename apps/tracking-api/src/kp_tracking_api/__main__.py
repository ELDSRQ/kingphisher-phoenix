import uvicorn


def main() -> None:
    uvicorn.run("kp_tracking_api.main:app", host="0.0.0.0", port=8001, reload=False)  # noqa: S104


if __name__ == "__main__":
    main()
