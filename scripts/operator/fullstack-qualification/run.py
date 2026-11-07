#!/usr/bin/env python3
"""Bounded full-stack synthetic qualification; preserve every run resource."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from campaign import Campaigns
from evidence import Evidence, Profile, QualificationFailure
from recovery import qualify_recovery
from stack import Stack


def source_manifest(root: Path) -> dict[str, str]:
    result = {}
    paths = [root / "pyproject.toml", root / "uv.lock"]
    for group in ("apps", "packages", "scripts"):
        for directory, subdirs, filenames in os.walk(root / group, followlinks=False):
            subdirs[:] = [
                name
                for name in subdirs
                if not name.startswith(".")
                and name not in {"node_modules", "__pycache__", "data"}
                and not (Path(directory) / name).is_symlink()
            ]
            paths.extend(Path(directory) / name for name in filenames)
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.name.startswith(".env"):
            continue
        if path.suffix in {
            ".py",
            ".toml",
            ".lock",
            ".ini",
            ".mako",
            ".json",
            ".js",
            ".mjs",
            ".html",
            ".css",
            ".svg",
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
            ".woff2",
            ".j2",
            ".jinja",
            ".yaml",
            ".yml",
            ".txt",
            ".sql",
            ".sh",
        }:
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result or "uv.lock" not in result:
        raise QualificationFailure("exact source/lock manifest unavailable")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--expected-engine-id", required=True)
    parser.add_argument("--subnet", default="10.254.247.0/28", help="reviewed unused/28 inside10.254.247.0/24")
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument(
        "--smoke-only", action="store_true", help="bounded3-recipient smoke; never qualifies full profile"
    )
    args = parser.parse_args()
    os.umask(0o077)
    evidence = Evidence(args.output, uuid.uuid4().hex, Profile())
    stack = Stack(evidence, args.source, args.expected_hostname, args.expected_engine_id, args.subnet)
    result: dict[str, Any] = {"passed": False, "full_profile": not args.smoke_only, "resources_preserved": True}
    try:
        evidence.json("source-manifest.json", source_manifest(stack.source))
        evidence.json(
            "execution-scope.json",
            {
                "python": sys.executable,
                "version": sys.version,
                "source": str(stack.source),
                "scope": "native-source-processes",
                "final_images_qualified": False,
            },
        )
        stack.preflight()
        services = stack.create_services("source")
        stack.bootstrap(services)
        endpoints = stack.start_applications(services, "source")
        campaigns = Campaigns(stack, services, endpoints)
        campaigns.ready("source")
        campaigns.fixtures()
        first = campaigns.launch(3, "smoke")
        campaigns.drain(first)
        campaigns.exercise_training(first)
        campaigns.finish_queues()
        if not args.smoke_only:
            for size in evidence.profile.recipients:
                campaign = campaigns.launch(size, f"baseline-{size}")
                if size == 1250:
                    campaigns.soak(campaign, "source")
                campaigns.drain(campaign)
                campaigns.exercise_training(campaign)
                campaigns.critical_probe("source")
            campaigns.verify_normal_latency()
            for mode in ("delay", "reject", "disconnect_after_accept"):
                (evidence.root / "smtp-mode").write_text(mode)
                campaign = campaigns.launch(1, f"fault-{mode}")
                delay_entered = campaigns.delay_boundary(campaign, "fault_enter") if mode == "delay" else None
                probe_started = time.time()
                campaigns.critical_probe("source")
                probe_completed = time.time()
                if delay_entered is not None:
                    delay_exited = campaigns.delay_boundary(campaign, "fault_exit")
                    if not delay_entered <= probe_started < probe_completed < delay_exited:
                        raise QualificationFailure("critical probes did not complete during the active5s SMTP stall")
                    evidence.event(
                        "slow_provider_isolation_verified",
                        stall_seconds=delay_exited - delay_entered,
                        critical_probe_seconds=probe_completed - probe_started,
                    )
                campaigns.require_fault_observed(campaign, mode)
                if mode == "reject":
                    (evidence.root / "smtp-mode").write_text("pass")
                campaigns.drain(campaign, uncertain=mode == "disconnect_after_accept")
                campaigns.sink_counts()
                (evidence.root / "smtp-mode").write_text("pass")
            campaigns.finish_queues()
            campaigns = qualify_recovery(stack, services, campaigns)
        accepted = campaigns.verify_sink_accounting()
        evidence.remaining()
        if source_manifest(stack.source) != __import__("json").loads(
            (evidence.root / "source-manifest.json").read_text()
        ):
            raise QualificationFailure("source changed while qualification ran")
        result.update(passed=True, smtp_sink_acceptances=accepted, recipient_delivery_confirmed=False)
    except Exception as exc:
        # Third-party errors/arguments can contain generated credentials. The
        # private logs hold detail; the report exposes only stable authored codes.
        result["failure"] = str(exc) if isinstance(exc, QualificationFailure) else type(exc).__name__
    finally:
        try:
            stack.quiesce()
        except Exception as exc:
            result.update(passed=False, quiescence_failure=type(exc).__name__)
        evidence.json("result.json", result)
        evidence.event("run_finished", **result)
    print(
        f"Qualification {'PASS' if result['passed'] else 'FAIL'}; evidence and all resources preserved: {evidence.root}"
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
