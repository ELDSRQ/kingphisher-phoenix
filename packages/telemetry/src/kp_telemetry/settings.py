"""Shared configuration-source controls.

Runtime services may use the repository ``.env`` for the local GUI launcher.
Qualification processes set ``KP_DISABLE_DOTENV=1`` so settings cannot silently
re-import live endpoints after their environment has been scrubbed.
"""

from __future__ import annotations

import os


def local_dotenv_file() -> str | None:
    """Return the local dotenv path unless this process explicitly forbids it."""

    return None if os.environ.get("KP_DISABLE_DOTENV") == "1" else ".env"
