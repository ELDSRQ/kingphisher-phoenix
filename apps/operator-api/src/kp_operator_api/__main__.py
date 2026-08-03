import uvicorn


def main() -> None:
    uvicorn.run("kp_operator_api.main:app", host="0.0.0.0", port=8000, reload=False)  # noqa: S104


if __name__ == "__main__":
    main()
