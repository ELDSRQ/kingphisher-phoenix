"""Deterministic command shim used by offline Azure onboarding tests."""

from __future__ import annotations

import json
import sys

TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

_MUTATING_AZ_COMMANDS = (
    ("group", "create"),
    ("storage", "account", "create"),
    ("storage", "account", "blob-service-properties", "update"),
    ("storage", "container", "create"),
    ("ad", "app", "create"),
    ("ad", "app", "update"),
    ("ad", "sp", "create"),
    ("role", "assignment", "create"),
)


def _has(args: list[str], *values: str) -> bool:
    return all(value in args for value in values)


def _azure(args: list[str]) -> int:
    if any(tuple(args[: len(prefix)]) == prefix for prefix in _MUTATING_AZ_COMMANDS):
        print(f"offline Azure shim blocked mutating command: {' '.join(args)}", file=sys.stderr)
        return 97
    if args[:1] == ["version"]:
        print("2.80.0")
    elif args[:2] == ["account", "show"]:
        if _has(args, "--query", "tenantId"):
            print(TENANT_ID)
        else:
            print(json.dumps({"id": "offline-subscription", "tenantId": TENANT_ID, "state": "Disabled"}))
    elif args[:3] == ["ad", "signed-in-user", "show"]:
        print("offline-user-id")
    elif (args[:3] == ["provider", "show", "--namespace"] or args[:2] == ["provider", "show"]) and _has(
        args, "--query", "registrationState"
    ):
        print("NotRegistered")
    # All discovery commands intentionally return an empty result.  That makes
    # preflight produce a deterministic blocked verdict and makes bootstrap's
    # dry-run plan new resources without touching a tenant.
    return 0


def _github(args: list[str]) -> int:
    if args[:2] == ["variable", "set"]:
        print(f"offline GitHub shim blocked mutating command: {' '.join(args)}", file=sys.stderr)
        return 97
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        return 2
    cli, args = sys.argv[1], sys.argv[2:]
    if cli == "az":
        return _azure(args)
    if cli == "gh":
        return _github(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
