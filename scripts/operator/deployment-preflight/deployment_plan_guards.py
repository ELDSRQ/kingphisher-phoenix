#!/usr/bin/env python3
"""Preserve existing receipt subscriptions and reject destructive deploy plans."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

RECEIPT_ADDRESS = "azurerm_eventgrid_system_topic_event_subscription.acs_delivery[0]"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class UnsafePlan(ValueError):
    pass


def changes(plan: Any) -> list[dict[str, Any]]:
    if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes", []), list):
        raise UnsafePlan("Terraform plan has malformed resource changes")
    result = plan.get("resource_changes", [])
    for change in result:
        if not isinstance(change, dict) or not isinstance(change.get("address"), str):
            raise UnsafePlan("Terraform resource change has no address")
        body = change.get("change")
        actions = body.get("actions") if isinstance(body, dict) else None
        if not isinstance(actions, list) or not actions or not all(isinstance(action, str) for action in actions):
            raise UnsafePlan("Terraform resource actions are malformed")
        if any(action not in {"no-op", "read", "create", "update"} for action in actions):
            raise UnsafePlan("deployment plan refuses deletes, replacements and state removals")
    return result


def validate_workloads(plan: Any) -> None:
    for change in changes(plan):
        if change["address"] == RECEIPT_ADDRESS and "create" in change["change"]["actions"]:
            raise UnsafePlan(
                "first receipt creation must wait for migration and readiness; reconcile receipt state first"
            )


def validate_receipt_activation(plan: Any, *, preserve_existing: bool) -> None:
    found = False
    for change in changes(plan):
        actions = change["change"]["actions"]
        if "create" in actions and change["address"] != RECEIPT_ADDRESS:
            raise UnsafePlan("receipt activation plan contains unrelated resource creation")
        if change["address"] == RECEIPT_ADDRESS:
            found = True
            if not preserve_existing and "create" not in actions:
                raise UnsafePlan("first receipt activation must create its reviewed subscription")
    if not found:
        raise UnsafePlan("receipt activation plan has no reviewed receipt subscription")


def _terraform(arguments: list[str]) -> str:
    executable = shutil.which("terraform")
    if executable is None:
        raise UnsafePlan("Terraform is unavailable")
    result = subprocess.run(  # noqa: S603 - resolved fixed CLI, bounded arguments from this script
        [executable, *arguments], capture_output=True, text=True, timeout=60, check=False
    )
    if result.returncode or len(result.stdout.encode()) > MAX_RESPONSE_BYTES:
        # Terraform state/plan output can contain secrets. Never echo it.
        raise UnsafePlan("Terraform state or plan inspection failed; existing resources must be preserved")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("receipt-state", "workloads", "receipt-activation"))
    parser.add_argument("plan", nargs="?")
    args = parser.parse_args()
    try:
        if args.phase == "receipt-state":
            addresses = _terraform(["state", "list"]).splitlines()
            preserve = RECEIPT_ADDRESS in addresses
            target = Path(os.environ["GITHUB_ENV"])
            with target.open("a", encoding="utf-8") as output:
                output.write(f"KP_PRESERVE_ACS_RECEIPTS={'true' if preserve else 'false'}\n")
            print(
                "Tracked receipt subscription will be preserved"
                if preserve
                else "First receipt creation waits for readiness"
            )
        else:
            if not args.plan:
                raise UnsafePlan("a saved reviewed Terraform plan is required")
            plan = json.loads(_terraform(["show", "-json", args.plan]))
            if args.phase == "workloads":
                validate_workloads(plan)
            else:
                value = os.environ.get("KP_PRESERVE_ACS_RECEIPTS")
                if value not in {"true", "false"}:
                    raise UnsafePlan("receipt preservation state is missing or invalid")
                validate_receipt_activation(plan, preserve_existing=value == "true")
            print("Saved plan passed preservation checks")
    except (UnsafePlan, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error) if isinstance(error, UnsafePlan) else "Deployment plan inspection failed closed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
