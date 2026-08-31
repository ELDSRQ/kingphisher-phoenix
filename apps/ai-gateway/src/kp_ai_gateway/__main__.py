"""Run the AI gateway with uvicorn."""

from __future__ import annotations

import os


def main() -> None:
    import uvicorn

    uvicorn.run(
        "kp_ai_gateway.main:app",
        host=os.environ.get("KP_AI_GATEWAY_HOST", "127.0.0.1"),
        port=int(os.environ.get("KP_AI_GATEWAY_PORT", "8090")),
    )


if __name__ == "__main__":
    main()
