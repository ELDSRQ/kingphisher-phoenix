"""Checkpoint collision/failure effects without contacting any Docker engine."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/operator/wsl2-docker-worker/checkpoint-state-wsl2.sh"


def _environment(tmp_path: Path) -> dict[str, str]:
    binary = tmp_path / "bin"
    binary.mkdir()
    fake = binary / "docker"
    fake.write_text(
        """#!/usr/bin/env python3
import io
import json
import os
import sys
import tarfile
from pathlib import Path

args = sys.argv[1:]
assert args[:2] == ['--host', 'unix:///var/run/docker.sock']
args = args[2:]
with Path(os.environ['CHECKPOINT_COMMANDS']).open('a') as log:
    log.write(json.dumps(args) + '\\n')
if args[0] == 'info':
    print('qualification|linux|x86_64')
elif args[0] == 'inspect':
    if '.State.Running' in args[-1]:
        print('true')
    elif '.Config.Cmd' in args[-1]:
        print('["redis-server"]')
    else:
        print('postgres:qualification' if 'postgres' in args[1] else 'redis:qualification')
elif args[0] == 'exec':
    if 'pg_dumpall' in args:
        print('CREATE ROLE qualification;')
    elif 'pg_dump' in args:
        sys.stdout.write('PGDMP-partial-or-complete')
        if os.environ.get('CHECKPOINT_FAIL_DUMP'):
            sys.exit(2)
    elif 'psql' in args:
        print('3')
    elif args[-1] == 'LASTSAVE':
        print('2' if Path(os.environ['CHECKPOINT_SAVED']).exists() else '1')
    elif args[-1] == 'BGSAVE':
        Path(os.environ['CHECKPOINT_SAVED']).write_text('saved')
        print('Background saving started')
elif args[0] == 'cp':
    assert args[-1] == '-'
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
        item = tarfile.TarInfo('dump.rdb')
        data = b'qualification-rdb'
        item.size = len(data)
        archive.addfile(item, io.BytesIO(data))
elif args[0] == 'run':
    if 'pg_restore' in args:
        sys.stdin.buffer.read()
else:
    raise SystemExit(90)
"""
    )
    fake.chmod(0o755)
    sleep = binary / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)
    environment = dict(os.environ)
    environment.pop("DOCKER_CONTEXT", None)
    environment.pop("DOCKER_HOST", None)
    environment.update(
        PATH=f"{binary}{os.pathsep}{environment['PATH']}",
        CHECKPOINT_COMMANDS=str(tmp_path / "commands.jsonl"),
        CHECKPOINT_SAVED=str(tmp_path / "saved"),
    )
    return environment


def _run(output: Path, environment: dict[str, str], *, verify: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed helper and isolated fake executable
        [
            "/bin/bash",
            str(SCRIPT),
            "--output-dir",
            str(output.parent.resolve() / output.name),
            *(["--verify"] if verify else []),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_existing_checkpoint_collision_preserves_every_byte(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    output = tmp_path / "preserved"
    output.mkdir()
    before = {
        name: f"preserved-{name}".encode() for name in ("postgres.dump", "globals.sql", "redis.rdb", "MANIFEST.txt")
    }
    for name, content in before.items():
        (output / name).write_bytes(content)

    result = _run(output, environment)

    assert result.returncode != 0
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before
    assert not Path(environment["CHECKPOINT_COMMANDS"]).exists()


def test_capture_failure_keeps_partial_evidence_and_refuses_reuse(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    environment["CHECKPOINT_FAIL_DUMP"] = "1"
    output = tmp_path / "failed"

    result = _run(output, environment)

    assert result.returncode != 0
    assert (output / "postgres.dump").read_bytes() == b"PGDMP-partial-or-complete"
    assert (output / "globals.sql").read_text() == "CREATE ROLE qualification;\n"
    assert not (output / "MANIFEST.txt").exists()
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    assert _run(output, environment).returncode != 0
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())


def test_capture_and_verify_bind_manifest_without_overwriting(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    output = tmp_path / "new"

    capture = _run(output, environment)
    assert capture.returncode == 0, capture.stderr
    assert _run(output, environment, verify=True).returncode == 0
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    assert _run(output, environment).returncode != 0
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before
    (output / "redis.rdb").write_bytes(b"changed-archive")
    changed = _run(output, environment, verify=True)
    assert changed.returncode != 0
    assert "manifest integrity" in changed.stderr
    assert (output / "redis.rdb").read_bytes() == b"changed-archive"


@pytest.mark.parametrize("redirect", ("context", "endpoint", "symlink"))
def test_checkpoint_refuses_redirected_targets_before_docker(tmp_path: Path, redirect: str) -> None:
    environment = _environment(tmp_path)
    output = tmp_path / "new"
    if redirect == "context":
        environment["DOCKER_CONTEXT"] = "desktop-linux"
    elif redirect == "endpoint":
        environment["DOCKER_HOST"] = "ssh://retired.example/old.sock"
    else:
        existing = tmp_path / "existing"
        existing.mkdir()
        output.symlink_to(existing, target_is_directory=True)

    result = _run(output, environment)

    assert result.returncode != 0
    assert not Path(environment["CHECKPOINT_COMMANDS"]).exists()
