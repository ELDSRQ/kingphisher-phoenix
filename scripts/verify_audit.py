"""Audit-chain verification for the local dev stack.

Recomputes the hash chain across every row in `audit_events` using the same
canonical serialization the app uses, then reports any mismatch or a non-genesis
head. Exits non-zero on failure so CI and `make verify-audit` can gate on it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kp_database.audit_store import AuditStore  # noqa: E402
from kp_database.session import create_db_engine  # noqa: E402


def main() -> int:
    store = AuditStore(
        create_db_engine("postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher")
    )
    problems = store.verify()
    if problems:
        print("audit chain FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("audit chain OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
