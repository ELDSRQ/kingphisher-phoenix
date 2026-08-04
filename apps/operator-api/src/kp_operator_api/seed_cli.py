"""`kp-seed` console entry point (WS-13).

Runs the repo-local seed script (scripts/seed.py) from the source tree. Seeding
is a developer operation against the local dev stack, so the entry resolves the
repository root from the installed source path and executes the script exactly
as `make seed` does (`uv run python scripts/seed.py`).
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[4]
    seed_script = repo_root / "scripts" / "seed.py"
    if not seed_script.is_file():
        raise SystemExit(f"seed script not found: {seed_script} (run from a source checkout)")
    sys.path.insert(0, str(repo_root))
    runpy.run_path(str(seed_script), run_name="__main__")


if __name__ == "__main__":
    main()
