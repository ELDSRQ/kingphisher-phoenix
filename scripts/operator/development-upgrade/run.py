#!/usr/bin/env python3
"""Explicit, gated development upgrade; private state stays on the reviewed worker."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from kp_dev_upgrade.coordinator import Upgrade  # noqa: E402 - prohibit incidental source cache writes
from kp_dev_upgrade.core import Blocked  # noqa: E402

PHASE_SECONDS = {"prepare": 1200, "checkpoint": 600, "rehearse": 1200, "cutover": 600, "verify": 300}


def deadline(_signum: int, _frame: object) -> None:
    raise Blocked("phase_deadline_preserve_state_and_inspect")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "checkpoint", "rehearse", "cutover", "verify"))
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument(
        "--execute", action="store_true", help="explicitly authorize this phase; no implicit phase chaining"
    )
    parser.add_argument("--source", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--commit")
    args = parser.parse_args()
    os.umask(0o077)
    if not args.execute:
        print(f"Plan only: {args.phase}; no changes performed. Review README and supply --execute after gates.")
        return 0
    try:
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(PHASE_SECONDS[args.phase])
        upgrade = Upgrade(args.run)
        if args.phase == "prepare":
            if not all((args.source, args.manifest, args.manifest_sha256, args.commit)):
                raise Blocked("prepare_requires_exact_qualified_source_manifest")
            upgrade.prepare(args.source, args.manifest, args.manifest_sha256, args.commit)
        else:
            getattr(upgrade, args.phase)()
    except Exception as exc:
        code = str(exc) if isinstance(exc, Blocked) else type(exc).__name__
        print(f"Upgrade blocked: {code}. Preserve all state; inspect worker-private evidence.")
        return 1
    finally:
        signal.alarm(0)
    print(f"Completed {args.phase}; private evidence and all resources preserved at {args.run}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
