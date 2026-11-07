#!/usr/bin/env python3
"""Run one reviewed synthetic recovery phase; default invocation is a local plan.

Requests contain private paths/URLs and belong in owned mode0600 files. Source
capture and target restore are separate host operations; this dispatcher cannot
provision hosts, retrieve cloud credentials or authorize campaign recipients.
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from pathlib import Path
from typing import Any, cast

from common import (
    RecoveryError,
    private_directory,
    private_file,
    private_json,
    read_json,
    remaining,
    require,
    sha256,
    unused,
)

HERE = Path(__file__).resolve().parent
PHASES = ("capture", "encrypt", "restore", "rewrap", "upload", "download")
TOOL_FILES = ("common.py", "run.py", "artifacts.py", "source_capture.py", "target_restore.py")
REQUEST_SCHEMA = "kp.offhost-recovery.phase-request.v1"


def result_object(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "phase_result_not_object")
    return cast(dict[str, Any], value)


def verify_tools(manifest: Any) -> None:
    require(isinstance(manifest, dict) and set(manifest) == set(TOOL_FILES), "tool_membership_mismatch")
    for name in TOOL_FILES:
        expected = manifest[name]
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "tool_digest_invalid")
        path = HERE / name
        require(path.is_file() and not path.is_symlink() and sha256(path) == expected, "tool_digest_mismatch")


def execute(request: dict[str, Any]) -> dict[str, Any]:
    require(request.get("schema") == REQUEST_SCHEMA, "phase_schema_invalid")
    require(request.get("scope") == "synthetic-qualification", "phase_scope_invalid")
    phase = request.get("phase")
    require(phase in PHASES, "phase_unknown")
    remaining(request["deadline"])
    verify_tools(request.get("tool_manifest"))
    if phase in {"capture", "restore"}:
        operation = request["operation"]
        require(
            isinstance(operation, dict)
            and operation.get("scope") == request["scope"]
            and operation.get("deadline", float("inf")) <= request["deadline"],
            "nested_operation_scope_or_deadline",
        )
        module = importlib.import_module("source_capture" if phase == "capture" else "target_restore")
        function = getattr(module, phase)
        return result_object(function(operation))
    module = importlib.import_module("artifacts")
    values = request["operation"]
    deadline = request["deadline"]
    require(isinstance(values, dict), "phase_operation_invalid")
    if phase == "encrypt":
        return result_object(
            module.encrypt_snapshot(
                Path(values["snapshot"]),
                Path(values["output"]),
                values["recipient"],
                age_command=values["age_command"],
                deadline=deadline,
            )
        )
    if phase == "rewrap":
        return result_object(
            module.rewrap(
                Path(values["cipher"]),
                Path(values["identity"]),
                values["recipient"],
                Path(values["output"]),
                values["expected_sha256"],
                age_command=values["age_command"],
                deadline=deadline,
            )
        )
    if phase == "upload":
        return result_object(
            module.upload_cipher(Path(values["path"]), values["url"], values["expected_host"], deadline=deadline)
        )
    return result_object(
        module.download_cipher(
            values["url"],
            values["expected_host"],
            Path(values["output"]),
            values["expected_sha256"],
            deadline=deadline,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("--execute-after-review", action="store_true")
    parser.add_argument("--receipt", type=Path)
    options = parser.parse_args(argv)
    try:
        private_file(options.request)
        request = read_json(options.request)
        require(request.get("schema") == REQUEST_SCHEMA, "phase_schema_invalid")
        require(request.get("scope") == "synthetic-qualification", "phase_scope_invalid")
        require(request.get("phase") in PHASES, "phase_unknown")
        if not options.execute_after_review:
            print(json.dumps({"plan": True, "phase": request["phase"], "scope": request["scope"]}, sort_keys=True))
            return 0
        require(options.receipt is not None, "exclusive_private_receipt_required")
        unused(options.receipt)
        private_directory(options.receipt.parent)
        result = execute(request)
        # Detailed source manifests and local filesystem paths stay private.
        private_json(options.receipt, {"phase": request["phase"], "result": result})
        print(json.dumps({"passed": True, "phase": request["phase"]}, sort_keys=True))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, RecoveryError) else type(error).__name__
        print(json.dumps({"passed": False, "error": code}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
