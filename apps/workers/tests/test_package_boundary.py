"""R-03 boundary: the worker deployable must not import the operator-api package.

The worker is a separate deployable with a narrower authority. Importing
``kp_operator_api`` pulls the entire control-plane surface into the worker image
and contradicts the documented three-deployables boundary, so shared logic lives
in packages (``kp_curation``, ``kp_domain_models``) that both apps depend on.
This test fails closed if that boundary is ever re-crossed.
"""

from __future__ import annotations

from pathlib import Path

_WORKER_SRC = Path(__file__).resolve().parents[1] / "src" / "kp_workers"


def test_worker_src_never_imports_operator_api() -> None:
    offenders: list[str] = []
    for path in _WORKER_SRC.rglob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if (stripped.startswith(("import ", "from "))) and "kp_operator_api" in stripped:
                offenders.append(f"{path.relative_to(_WORKER_SRC)}: {stripped}")
    assert not offenders, f"apps/workers must not import kp_operator_api (R-03): {offenders}"
