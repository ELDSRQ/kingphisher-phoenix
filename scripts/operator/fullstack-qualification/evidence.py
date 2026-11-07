"""Private, exclusive evidence and immutable qualification limits."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class QualificationFailure(RuntimeError):
    """A stable, non-sensitive qualification failure."""


@dataclass(frozen=True)
class Profile:
    recipients: tuple[int, ...] = (125, 1250)
    soak_seconds: int = 300
    total_seconds: int = 1800
    drain_seconds: int = 600
    readiness_seconds: int = 120
    api_p95_seconds: float = 1.0
    critical_seconds: float = 2.0
    rto_seconds: int = 900
    rpo_missing: int = 0


def loopback_url(value: str, schemes: set[str]) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in schemes or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise QualificationFailure("explicit IPv4 loopback URL required")
    if parsed.fragment or parsed.query:
        raise QualificationFailure("URL options are forbidden")
    if parsed.port in {5432, 6379, 8000, 8001, 8025, 51458, 51459}:
        raise QualificationFailure("preserved service port is forbidden")
    return value


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Evidence:
    def __init__(self, root: Path, run_id: str, profile: Profile):
        if not root.is_absolute() or root.resolve() != root or root.is_symlink():
            raise QualificationFailure("evidence directory must be absolute and canonical")
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.root, self.run_id, self.profile = root, run_id, profile
        self.started = time.monotonic()
        self.json("profile.json", {"run_id": run_id, "scope": "native-source-process-synthetic", **asdict(profile)})

    def remaining(self, maximum: float | None = None) -> float:
        left = self.profile.total_seconds - (time.monotonic() - self.started)
        if left <= 0:
            raise QualificationFailure("absolute qualification deadline exceeded")
        return max(0.01, min(left, maximum) if maximum is not None else left)

    def json(self, name: str, value: Any) -> Path:
        if Path(name).name != name:
            raise QualificationFailure("evidence name must be a single component")
        path = self.root / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, default=str, indent=2)
            stream.write("\n")
        return path

    def event(self, phase: str, **observations: Any) -> None:
        fd = os.open(self.root / "journal.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as stream:
            stream.write(
                json.dumps(
                    {"phase": phase, "elapsed": time.monotonic() - self.started, **observations},
                    sort_keys=True,
                    default=str,
                )
                + "\n"
            )


def percentile(values: list[float], quantile: float = 0.95) -> float:
    if not values:
        raise QualificationFailure("latency has no observations")
    import math

    return sorted(values)[max(0, math.ceil(len(values) * quantile) - 1)]
