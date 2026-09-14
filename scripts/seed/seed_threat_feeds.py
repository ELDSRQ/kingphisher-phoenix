"""Validate the curated threat-feed source manifest for on-prem aggregation (M3).

This script defines/validates the SOURCE manifest (`threat_feeds.yaml`) that the
on-prem background aggregation stage reads to know WHERE current-phishing-campaign
signal comes from. It is deliberately dependency-light and side-effect-free:

  * It makes NO network calls. Fetching feeds is a separate ingestion concern;
    this only checks the shape of the reviewed source list.
  * By default it prints a human summary to stderr and the validated, enabled +
    disabled set as JSON to stdout (or to ``--out FILE``). Running it twice on
    the same manifest yields identical output (idempotent).
  * ``--check`` validates only and exits non-zero on any invalid entry.

Usage (matching the repo idiom, e.g. scripts/seed.py):
    uv run python scripts/seed/seed_threat_feeds.py            # summary + JSON
    uv run python scripts/seed/seed_threat_feeds.py --check    # validate only
    uv run python scripts/seed/seed_threat_feeds.py --out feeds.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - PyYAML is a repo dep
    raise SystemExit(
        "PyYAML is required to load the threat-feed manifest "
        "(it ships with the repo's dependencies; run via `uv run`)."
    ) from exc

DEFAULT_MANIFEST = Path(__file__).resolve().parent / "threat_feeds.yaml"

#: Allowed feed kinds. Ingestion knows how to parse exactly these.
ALLOWED_KINDS = frozenset({"rss", "atom", "html", "json"})

#: Required keys on every feed entry, and the type each must hold.
REQUIRED_FIELDS: dict[str, type | tuple[type, ...]] = {
    "id": str,
    "name": str,
    "url": str,
    "kind": str,
    "publisher": str,
    "categories": list,
    "enabled": bool,
}

#: Optional keys allowed on an entry (anything else is rejected).
OPTIONAL_FIELDS: dict[str, type | tuple[type, ...]] = {
    "note": str,
}


class ManifestError(ValueError):
    """Raised when the manifest does not match the allow-listed shape."""


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _validate_entry(index: int, entry: Any, seen_ids: set[str]) -> list[str]:
    """Return a list of human-readable problems with a single entry."""
    where = f"feeds[{index}]"
    problems: list[str] = []

    if not isinstance(entry, dict):
        return [f"{where}: entry must be a mapping, got {type(entry).__name__}"]

    entry_id = entry.get("id")
    if isinstance(entry_id, str) and entry_id:
        where = f"feeds[{index}] (id={entry_id!r})"

    for field, expected in REQUIRED_FIELDS.items():
        if field not in entry:
            problems.append(f"{where}: missing required field {field!r}")
        elif not isinstance(entry[field], expected) or (
            # bool is a subclass of int; keep the two distinct.
            expected is not bool and isinstance(entry[field], bool)
        ):
            problems.append(
                f"{where}: field {field!r} must be {getattr(expected, '__name__', expected)}"
            )

    unknown = set(entry) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS)
    if unknown:
        problems.append(f"{where}: unknown field(s) {sorted(unknown)}")
    for field, expected in OPTIONAL_FIELDS.items():
        if field in entry and not isinstance(entry[field], expected):
            problems.append(
                f"{where}: optional field {field!r} must be {getattr(expected, '__name__', expected)}"
            )

    if isinstance(entry_id, str) and entry_id:
        if entry_id in seen_ids:
            problems.append(f"{where}: duplicate id {entry_id!r}")
        seen_ids.add(entry_id)
    elif "id" in entry:
        problems.append(f"{where}: id must be a non-empty string")

    url = entry.get("url")
    if isinstance(url, str) and url and not _is_http_url(url):
        problems.append(f"{where}: url must be an http(s) URL, got {url!r}")

    kind = entry.get("kind")
    if isinstance(kind, str) and kind and kind not in ALLOWED_KINDS:
        problems.append(
            f"{where}: kind {kind!r} not in allowed set {sorted(ALLOWED_KINDS)}"
        )

    categories = entry.get("categories")
    if isinstance(categories, list):
        if not categories:
            problems.append(f"{where}: categories must be a non-empty list")
        elif not all(isinstance(c, str) and c for c in categories):
            problems.append(f"{where}: every category must be a non-empty string")

    return problems


def validate_manifest(data: Any) -> list[dict[str, Any]]:
    """Validate a loaded manifest and return the normalized list of entries.

    Raises :class:`ManifestError` with every problem found if invalid.
    """
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a mapping")
    feeds = data.get("feeds")
    if not isinstance(feeds, list) or not feeds:
        raise ManifestError("manifest must contain a non-empty 'feeds' list")

    problems: list[str] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(feeds):
        problems.extend(_validate_entry(index, entry, seen_ids))

    if problems:
        raise ManifestError("invalid threat-feed manifest:\n  - " + "\n  - ".join(problems))
    return feeds


def load_manifest(path: Path) -> Any:
    if not path.exists():
        raise ManifestError(f"manifest not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _summary_lines(feeds: list[dict[str, Any]]) -> list[str]:
    enabled = [f for f in feeds if f.get("enabled")]
    disabled = [f for f in feeds if not f.get("enabled")]
    lines = [
        f"threat-feed manifest OK: {len(feeds)} source(s) — "
        f"{len(enabled)} enabled, {len(disabled)} disabled",
    ]
    for feed in enabled:
        lines.append(f"  [on ] {feed['id']:<24} {feed['kind']:<4} {feed['url']}")
    for feed in disabled:
        lines.append(f"  [off] {feed['id']:<24} {feed['kind']:<4} {feed['url']}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="path to threat_feeds.yaml (default: alongside this script)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate only; non-zero exit on any invalid entry, no JSON output",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write the validated set as JSON to this file (default: stdout)",
    )
    args = parser.parse_args(argv)

    try:
        data = load_manifest(args.manifest)
        feeds = validate_manifest(data)
    except ManifestError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for line in _summary_lines(feeds):
        print(line, file=sys.stderr)

    if args.check:
        return 0

    payload = json.dumps(feeds, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.write_text(payload, encoding="utf-8")
        print(f"wrote {len(feeds)} feed(s) to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
