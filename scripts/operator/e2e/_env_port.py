"""Read a numeric port from .env for the E2E runner.

Keeps the runner's port assumptions in one place: .env is the single source
the console and the gate both read, so moving the stack off a busy port needs
no script edits.
"""

from __future__ import annotations

import pathlib
import sys


def main() -> None:
    key, default = sys.argv[1], sys.argv[2]
    value = ""
    try:
        for line in pathlib.Path(".env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, raw = line.split("=", 1)
            if name.strip() != key:
                continue
            raw = raw.strip()
            if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
                raw = raw[1:-1]
            value = raw.strip()
    except OSError:
        pass
    print(value if value.isdigit() else default)


if __name__ == "__main__":
    main()
