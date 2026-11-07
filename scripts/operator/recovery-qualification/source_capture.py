"""Explicit A-only capture of the retained, synthetic clean-Linux VM.

Required proofs mapping keys are reboot_after, container_inventory,
preserved_before_b, final_state and source_proof. Each has path and sha256;
paths must select their exact original evidence filenames. expected_containers
is the reboot-after container projection augmented with image_reference from
A-container-inventory.json. No original qualification artifact is modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from common import (
    MAX_CLEAR_BYTES,
    MAX_FILES,
    RUNTIME_COMMIT,
    SERVICES,
    SNAPSHOT_SCHEMA,
    SOURCE_REQUEST_SCHEMA,
    RecoveryError,
    canonical,
    command,
    private_bytes,
    private_directory,
    private_file,
    private_json,
    purpose_fingerprints,
    read_json,
    relative_name,
    remaining,
    require,
    sha256,
    unused,
)

ROOT = Path("/srv/kp-cleanlinux")
PROC = Path("/proc")
CGROUPS = Path("/sys/fs/cgroup")
A_SOCKET = "unix:///var/run/docker.sock"
B_SOCKET = Path("/run/kp-cleanlinux-upgrade-docker/docker.sock")
PROJECT = "phishing-awareness-platform"
SOURCE_VM_PATTERN = re.compile(
    r"/subscriptions/169644fd-c81d-4935-af55-5770f8271022/resourceGroups/"
    r"rg-kp-cleanlinux-20261106-3lkij1-v(?P<version>[4-9]|[1-9][0-9]{1,2})/"
    r"providers/Microsoft.Compute/virtualMachines/vm-kp-cleanlinux-20261106-3lkij1-v(?P=version)",
    re.IGNORECASE,
)
PROOFS = {
    "reboot_after": "reboot-after.json",
    "container_inventory": "A-container-inventory.json",
    "preserved_before_b": "A-preserved-before-B.json",
    "final_state": "reboot-final-state.json",
    "source_proof": "clean-target-source-proof.json",
}
UNITS = tuple(
    "kp-cleanlinux-" + name + ".service"
    for name in ("upgrade-engine", "clean-install", "warm-rerun", "repair", "reboot-relaunch", "baseline", "upgrade")
)


def _environment() -> dict[str, str]:
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/home/kpqual",
        "USER": "kpqual",
        "LOGNAME": "kpqual",
        "DOCKER_HOST": A_SOCKET,
        "KP_DISABLE_DOTENV": "1",
    }


def _run(argv: list[str], deadline: float, evidence: Path, **kwargs: Any) -> bytes:
    return command(
        argv,
        timeout=min(120, remaining(deadline, reserve=2)),
        env=_environment(),
        evidence=evidence,
        **kwargs,
    )


def _docker(argv: list[str], deadline: float, evidence: Path, **kwargs: Any) -> bytes:
    return _run(["/usr/bin/docker", "--host", A_SOCKET, *argv], deadline, evidence, **kwargs)


def _vm_identity(deadline: float) -> str:
    request = urllib.request.Request(
        "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
        headers={"Metadata": "true"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=min(3, remaining(deadline))) as response:
        raw = response.read(65537)
    require(len(raw) <= 65536, "imds_response_bound")
    value = json.loads(raw)
    require(isinstance(value, dict) and isinstance(value.get("resourceId"), str), "imds_identity_missing")
    return str(value["resourceId"])


def _request(request: dict[str, Any]) -> tuple[Path, Path, float]:
    require(request.get("schema") == SOURCE_REQUEST_SCHEMA, "source_request_schema")
    require(request.get("scope") == "synthetic-qualification" and request.get("source_mode") == "A", "source_scope")
    require(bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{7,79}", str(request.get("run_id", "")))), "run_id_invalid")
    deadline = request.get("deadline")
    if not isinstance(deadline, (float, int)) or isinstance(deadline, bool):
        raise RecoveryError("source_deadline_invalid")
    require(0 < deadline - time.time() <= 45 * 60, "source_deadline_invalid")
    source = canonical(Path(request["source_root"]))
    require(source == ROOT / "clean-target", "source_is_not_qualified_a")
    vm_id = request.get("expected_vm_id")
    require(isinstance(vm_id, str) and SOURCE_VM_PATTERN.fullmatch(vm_id) is not None, "source_vm_outside_task")
    require(socket.gethostname() == request.get("expected_hostname"), "source_hostname_mismatch")
    application = request.get("application", {})
    require(
        bool(re.fullmatch("[0-9a-f]{40}", application.get("bundle_commit", "")))
        and application.get("runtime_commit") == RUNTIME_COMMIT
        and bool(re.fullmatch("[0-9]{4}_[a-z0-9_]+", application.get("schema_head", ""))),
        "application_binding_invalid",
    )
    output = unused(Path(request["output"]))
    require(output.parent == ROOT and output.name.startswith("offhost-capture-"), "source_output_namespace")
    require(_vm_identity(float(deadline)).lower() == str(vm_id).lower(), "source_vm_identity_mismatch")
    return source, output, float(deadline)


def verify_source(source: Path, manifest: dict[str, Any], deadline: float) -> None:
    require(isinstance(manifest, dict) and 0 < len(manifest) <= MAX_FILES, "source_manifest_bound")
    for name, expected in manifest.items():
        remaining(deadline)
        relative_name(name)
        path = source / name
        mode = expected.get("mode")
        require(mode in {"100644", "100755", "120000"}, "source_git_mode_invalid")
        if mode == "120000":
            require(path.is_symlink(), "source_git_kind_changed")
            link = os.readlink(path)
            require(not Path(link).is_absolute() and path.resolve().is_relative_to(source), "source_link_escapes")
            payload = link.encode()
        else:
            canonical(path)
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "source_git_kind_changed")
            require(bool(info.st_mode & 0o111) == (mode == "100755"), "source_executable_changed")
            require(info.st_size <= 50 * 1024**2, "source_git_object_bound")
            payload = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload, usedforsecurity=False).hexdigest()
        require(blob == expected.get("blob"), "source_git_bytes_changed")


def _proofs(request: dict[str, Any], source: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    values: dict[str, Any] = {}
    require(set(request.get("proofs", {})) == set(PROOFS), "source_proofs_missing")
    for name, basename in PROOFS.items():
        record = request["proofs"][name]
        path = canonical(Path(record["path"]))
        require(path == ROOT / "evidence" / basename, "source_proof_path_mismatch")
        require(path.is_file() and path.stat().st_size <= 8 * 1024**2, "source_proof_bound")
        require(sha256(path) == record.get("sha256"), "source_proof_digest_mismatch")
        values[name] = json.loads(path.read_bytes())
    reboot, inventory = values["reboot_after"], values["container_inventory"]
    require(isinstance(inventory, list) and len(inventory) == 6, "source_container_inventory_invalid")
    by_id = {row["id"]: row for row in inventory}
    containers = []
    require(len(reboot["containers"]) == len(by_id) == 6, "source_container_count")
    for row in reboot["containers"]:
        item = by_id.get(row["id"], {})
        require(
            all(item.get(key) == row[key] for key in ("id", "image", "name", "service")), "a_proof_identity_conflict"
        )
        containers.append({**row, "image_reference": item["image_reference"]})
    containers.sort(key=lambda row: row["id"])
    require(
        containers == sorted(request["expected_containers"], key=lambda row: row["id"]), "expected_container_mismatch"
    )
    require({row["service"] for row in containers} == set(SERVICES), "a_service_scope_mismatch")
    require(
        all(
            re.fullmatch("[0-9a-f]{64}", row["id"])
            and row["name"] == f"/{PROJECT}-{row['service']}-1"
            and re.fullmatch("sha256:[0-9a-f]{64}", row["image"])
            for row in containers
        ),
        "a_container_descriptor_invalid",
    )
    preserved = values["preserved_before_b"]
    require(
        set(preserved["ids"]) == set(by_id) and preserved.get("containers_stopped_not_removed") is True,
        "a_stop_proof_invalid",
    )
    require(preserved.get("daemon_and_socket_inactive_runtime_masked") is True, "a_preservation_proof_invalid")
    volumes = reboot["volumes"]
    require(volumes == preserved["volumes"], "a_volume_proof_conflict")
    require(
        {row["Name"] for row in volumes} == {PROJECT + "_postgres_data", PROJECT + "_redis_data"},
        "a_volume_scope_mismatch",
    )
    engine = request["expected_engine"]
    require(
        engine == {"id": reboot["engine"]["ID"], "root": "/var/lib/docker", "socket": A_SOCKET}
        and reboot["engine"]["DockerRootDir"] == engine["root"],
        "a_engine_proof_mismatch",
    )
    require(sha256(source / ".env") == reboot["configuration_sha256"], "a_configuration_changed")
    require(
        values["source_proof"].get("source_sha") == request["application"]["bundle_commit"], "a_source_commit_mismatch"
    )
    require(values["source_proof"].get("git_blobs_and_modes") is True, "a_source_proof_incomplete")
    require(
        values["source_proof"].get("objects") == len(request["source_git_manifest"])
        and values["source_proof"].get("manifest_sha256")
        == hashlib.sha256(json.dumps(request["source_git_manifest"], sort_keys=True).encode()).hexdigest(),
        "a_git_manifest_proof_mismatch",
    )
    require(
        values["final_state"].get("preservation_verified") is True
        and values["final_state"].get("database_revision") == request["application"]["schema_head"],
        "a_final_state_incomplete",
    )
    return containers, volumes, values["final_state"]


def _quiescent(source: Path, deadline: float, evidence: Path) -> None:
    require(not os.path.lexists(B_SOCKET), "b_socket_present")
    loaded = _run(["systemctl", "list-units", "--all", "--plain", "--no-legend", *UNITS], deadline, evidence)
    for line in loaded.decode().splitlines():
        if not line.strip():
            continue
        unit = line.split()[0]
        require(unit in UNITS, "unexpected_application_unit")
        raw = _run(
            ["systemctl", "show", unit, "--property=ActiveState", "--property=MainPID", "--property=ControlGroup"],
            deadline,
            evidence,
        )
        properties = dict(item.split("=", 1) for item in raw.decode().splitlines() if "=" in item)
        require(
            properties.get("ActiveState") in {"inactive", "failed"} and properties.get("MainPID") == "0",
            "application_unit_live",
        )
        if group := properties.get("ControlGroup"):
            require(
                group.startswith("/") and ".." not in Path(group).parts and Path(group).name == unit,
                "cgroup_identity_invalid",
            )
            root = CGROUPS / group.lstrip("/")
            for index, member in enumerate(root.rglob("cgroup.procs")):
                require(index < 256 and remaining(deadline) > 0, "cgroup_inspection_bound")
                require(not member.read_text().strip(), "application_cgroup_live")
    for path in (source / "data/run").glob("*.pid"):
        require(not os.path.lexists(path), "application_pid_state_ambiguous")
    for index, process in enumerate(PROC.iterdir()):
        require(index < 8192 and remaining(deadline) > 0, "process_inspection_bound")
        if not process.name.isdecimal():
            continue
        try:
            arguments = (process / "cmdline").read_bytes()
            require(len(arguments) <= 1024 * 1024, "process_command_bound")
            require(
                not any(
                    marker in arguments
                    for marker in (
                        b"kp-cleanlinux-upgrade-docker",
                        b"kp-cleanlinux-upgrade-plugins",
                        b"upgrade-daemon.json",
                    )
                ),
                "b_process_live",
            )
            cwd = (process / "cwd").resolve()
            if cwd.is_relative_to(ROOT):
                require(
                    not any(
                        name in arguments
                        for name in (b"kp_operator_api", b"kp_tracking_api", b"kp_workers", b"scripts/supervisor.py")
                    ),
                    "native_application_process_live",
                )
        except FileNotFoundError:
            continue
        except PermissionError:
            raise RecoveryError("process_identity_unreadable") from None


def _engine(
    containers: list[dict[str, Any]],
    volumes: list[dict[str, Any]],
    expected: dict[str, Any],
    deadline: float,
    evidence: Path,
) -> dict[str, dict[str, Any]]:
    info = json.loads(_docker(["info", "--format", "{{json .}}"], deadline, evidence))
    require(
        info.get("ID") == expected["id"] and info.get("DockerRootDir") == expected["root"], "a_engine_identity_changed"
    )
    require(
        info.get("OSType") == "linux" and info.get("Architecture") in {"amd64", "x86_64"}, "a_engine_platform_changed"
    )
    ids = (
        _docker(
            ["ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + PROJECT],
            deadline,
            evidence,
        )
        .decode()
        .split()
    )
    require(set(ids) == {row["id"] for row in containers} and len(ids) == 6, "a_container_set_changed")
    rows = json.loads(_docker(["inspect", *sorted(ids)], deadline, evidence, record=False))
    actual = {}
    for row in rows:
        expected_row = next((item for item in containers if item["id"] == row["Id"]), None)
        if expected_row is None:
            raise RecoveryError("a_container_unexpected")
        require(
            all(
                row.get(key) == expected_row[column]
                for key, column in (("Image", "image"), ("Name", "name"), ("Created", "created"), ("Mounts", "mounts"))
            )
            and row["Config"]["Image"] == expected_row["image_reference"]
            and row["Config"]["Labels"].get("com.docker.compose.project") == PROJECT
            and row["Config"]["Labels"].get("com.docker.compose.service") == expected_row["service"],
            "a_container_identity_changed",
        )
        actual[expected_row["service"]] = row
    current = json.loads(_docker(["volume", "inspect", *sorted(row["Name"] for row in volumes)], deadline, evidence))
    projected = [{key: row.get(key) for key in ("Name", "CreatedAt", "Mountpoint", "Labels")} for row in current]
    require(
        sorted(projected, key=lambda row: row["Name"]) == sorted(volumes, key=lambda row: row["Name"]),
        "a_volume_identity_changed",
    )
    return actual


def _probe(source: Path, program: str, payload: dict[str, Any], deadline: float, evidence: Path) -> dict[str, Any]:
    raw = _run(
        [str(source / ".venv/bin/python"), "-c", program, str(source)],
        deadline,
        evidence,
        input_data=json.dumps(payload).encode(),
        cwd=source,
        record=False,
    )
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise RecoveryError("application_probe_shape")
    return result


PROBE_PREAMBLE = r"""
import hashlib, json, os, pathlib, sys, time

root = pathlib.Path(sys.argv[1])
request = json.load(sys.stdin)
from dotenv import dotenv_values

config = {k.upper(): v for k, v in dotenv_values(root / ".env", interpolate=False).items() if v is not None}
for key, value in config.items():
    os.environ[key] = value
os.environ["OPERATOR_API_ENV_FILE"] = str(root / ".env")
import kp_database, kp_contracts, kp_operator_api

assert pathlib.Path(kp_database.__file__).resolve().is_relative_to(root / "packages/database/src")
assert pathlib.Path(kp_contracts.__file__).resolve().is_relative_to(root / "packages/contracts/src")
assert pathlib.Path(kp_operator_api.__file__).resolve().is_relative_to(root / "apps/operator-api/src")
"""

DATABASE_PROBE = "\n".join(
    (
        PROBE_PREAMBLE,
        r"""
from kp_database import models
from kp_database.base import Base
from kp_database.audit_store import AuditStore
from kp_database.session import create_db_engine
from kp_operator_api.config import OperatorApiSettings
from sqlalchemy import MetaData, Table, Column, String, select, text, func, inspect
from sqlalchemy.orm import Session

settings = OperatorApiSettings()
models.CipherText.configure_keyring(*settings.require_cipher_keyring())
engine = create_db_engine(settings.database_url)
audit_engine = create_db_engine(settings.audit_database_url)
try:
    if request.get("create_sentinel"):
        spec = request["sentinel"]
        table = Table(
            spec["table"],
            MetaData(),
            Column("sentinel_key", String(80), primary_key=True),
            Column("sentinel_value", String(80), nullable=False),
        )
        table.create(engine, checkfirst=False)
        with engine.begin() as connection:
            connection.execute(table.insert().values(sentinel_key=spec["key"], sentinel_value=spec["value"]))
    with engine.connect() as connection:
        connection.execute(text("SET TRANSACTION READ ONLY"))
        connection.execute(text("SET LOCAL statement_timeout='20s'"))
        counts = {
            name: int(
                connection.scalar(select(func.count()).select_from(Table(name, MetaData(), schema="public"))) or 0
            )
            for name in inspect(connection).get_table_names(schema="public")
        }
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
        signature = connection.scalar(text("SELECT signature FROM audit_chain_head WHERE id=1"))
        sentinel = None
        if request.get("sentinel"):
            spec = request["sentinel"]
            table = Table(
                spec["table"], MetaData(), Column("sentinel_key", String(80)), Column("sentinel_value", String(80))
            )
            found = connection.scalar(select(table.c.sentinel_value).where(table.c.sentinel_key == spec["key"]))
            assert found == spec["value"]
            sentinel = {**spec, "value": found}
    ciphertexts = {}
    with Session(engine) as session:
        session.execute(text("SET TRANSACTION READ ONLY"))
        session.execute(text("SET LOCAL statement_timeout='30s'"))
        for mapper in Base.registry.mappers:
            columns = [column for column in mapper.columns if isinstance(column.type, models.CipherText)]
            if not columns:
                continue
            rows = list(session.scalars(select(mapper.class_).order_by(*mapper.primary_key).limit(10001)))
            assert len(rows) <= 10000
            for column in columns:
                checksum = hashlib.sha256()
                for row in rows:
                    value = [str(getattr(row, key.key)) for key in mapper.primary_key] + [getattr(row, column.key)]
                    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
                    checksum.update(len(encoded).to_bytes(8, "big") + encoded)
                ciphertexts[str(mapper.local_table.name) + "." + column.key] = {
                    "count": len(rows),
                    "sha256": checksum.hexdigest(),
                }
    store = AuditStore(
        audit_engine, settings.require_secret_key() if settings.audit_hmac_key else None, intent_engine=engine
    )
    assert not store.verify()
    head = store.head_snapshot()
    assert head and head.sequence > 0
    if request.get("previous_audit"):
        prior = request["previous_audit"]
        assert store.hashes_by_sequence({prior["sequence"]})[prior["sequence"]] == prior["event_hash"]
    print(
        json.dumps(
            {
                "schema_head": revision,
                "table_counts": counts,
                "audit": {
                    "sequence": head.sequence,
                    "event_hash": head.event_hash,
                    "signature": signature,
                    "audit_verified": True,
                },
                "ciphertexts": ciphertexts,
                "sentinel": sentinel,
            }
        )
    )
finally:
    engine.dispose()
    audit_engine.dispose()
""",
    )
)

REDIS_INVENTORY_PROBE = "\n".join(
    (
        PROBE_PREAMBLE,
        r"""
import redis

sys.path.insert(0, str(root / "scripts/operator/development-upgrade"))
from kp_dev_upgrade.coordinator import redis_inventory

assert pathlib.Path(redis_inventory.__code__.co_filename).resolve().is_relative_to(root)
client = redis.Redis.from_url(config["REDIS_URL"], socket_timeout=5, socket_connect_timeout=3)
try:
    print(json.dumps(redis_inventory(client)))
finally:
    client.close()
""",
    )
)

REDIS_CAPTURE_PROBE = "\n".join(
    (
        PROBE_PREAMBLE,
        r"""
import redis
from kp_contracts.queue import JobQueue

sys.path.insert(0, str(root / "scripts/operator/development-upgrade"))
from kp_dev_upgrade.coordinator import redis_inventory

assert pathlib.Path(redis_inventory.__code__.co_filename).resolve().is_relative_to(root)
client = redis.Redis.from_url(config["REDIS_URL"], socket_timeout=5, socket_connect_timeout=3)
queue = JobQueue(config["REDIS_URL"])
try:
    sentinel = request["sentinel"]
    assert client.set(sentinel["key"], sentinel["value"], nx=True)
    assert client.get(sentinel["key"]) == sentinel["value"].encode()
    prior = queue.read_audit_anchor_heartbeat()
    key = "offhost-recovery:" + request["run_id"]
    job = queue.publish("audit-anchor", {}, idempotency_key=key)
    ready = "kp:queue:{audit-anchor}"
    entries = client.lrange(ready, 0, 10000)
    assert len(entries) < 10000
    matches = [raw for raw in entries if json.loads(raw)["id"] == job]
    assert len(matches) == 1
    assert json.loads(matches[0])["idempotency_key"] == key
    assert (
        client.config_get("dir").get("dir") == "/data"
        and client.config_get("dbfilename").get("dbfilename") == "dump.rdb"
    )
    assert not client.info("persistence")["rdb_bgsave_in_progress"]
    assert client.bgsave()
    until = min(time.time() + 60, request["deadline"] - 2)
    while time.time() < until:
        state = client.info("persistence")
        if not state["rdb_bgsave_in_progress"]:
            assert state["rdb_last_bgsave_status"] == "ok"
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("rdb_deadline")
    print(
        json.dumps(
            {
                "sentinel": sentinel,
                "maintenance": {
                    "topic": "audit-anchor",
                    "id": job,
                    "idempotency_key": key,
                    "acknowledgment": True,
                    "payload": {},
                    "ready_key": ready,
                    "envelope_sha256": hashlib.sha256(matches[0]).hexdigest(),
                    "prior_heartbeat": None if prior is None else prior.isoformat(),
                },
                "inventory": redis_inventory(client),
            }
        )
    )
finally:
    queue.close()
    client.close()
""",
    )
)


def _sentinel_spec(value: dict[str, Any] | None) -> None:
    if value is not None:
        require(
            bool(re.fullmatch("kp_recovery_sentinel_[0-9a-f]{16}", value.get("table", ""))), "sentinel_table_invalid"
        )
        require(
            value.get("key_column") == "sentinel_key" and value.get("value_column") == "sentinel_value",
            "sentinel_columns_invalid",
        )
        require(
            all(isinstance(value.get(key), str) and len(value[key]) <= 80 for key in ("key", "value")),
            "sentinel_value_invalid",
        )


def read_database_state(
    source: Path, *, deadline: float, evidence: Path, sentinel: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Caller must first bind source bytes; return only hashes/counts and task markers."""
    _sentinel_spec(sentinel)
    return _probe(source, DATABASE_PROBE, {"sentinel": sentinel}, deadline, evidence)


def read_redis_inventory(source: Path, *, deadline: float, evidence: Path) -> dict[str, Any]:
    """Same hashed logical/absolute-expiry projection as the reviewed upgrade tool."""
    return _probe(source, REDIS_INVENTORY_PROBE, {}, deadline, evidence)


def _configuration(source: Path, deadline: float, evidence: Path) -> dict[str, str]:
    values = _probe(source, PROBE_PREAMBLE + "\nprint(json.dumps(config))\n", {}, deadline, evidence)
    require(
        not any(key.startswith(("PG", "PYTHON", "LD_", "UV_")) for key in values), "configuration_resolution_override"
    )
    require(
        not {"PATH", "HOME", "VIRTUAL_ENV", "BASH_ENV", "ENV", "DOCKER_CONTEXT"} & values.keys(),
        "configuration_resolution_override",
    )
    for key, value in values.items():
        if "DATABASE_URL" in key or "REDIS_URL" in key:
            parsed = urlsplit(value)
            is_test = key == "DATABASE_URL_TEST"
            redis_url = "REDIS_URL" in key
            require(
                parsed.hostname in {"localhost", "127.0.0.1", "::1"} and not parsed.query and not parsed.fragment,
                "configuration_connection_outside_a",
            )
            require(
                parsed.scheme in ({"redis"} if redis_url else {"postgresql", "postgresql+psycopg"}),
                "configuration_connection_scheme",
            )
            require(parsed.port in ({None, 6379} if redis_url else {None, 5432}), "configuration_connection_port")
            require(
                parsed.path in ({"", "/0"} if redis_url else {"/kingphisher_test"} if is_test else {"/kingphisher"}),
                "configuration_connection_database",
            )
    require({"DATABASE_URL", "REDIS_URL"} <= values.keys(), "configuration_connections_missing")
    require(values.get("DOCKER_HOST", A_SOCKET) == A_SOCKET, "configuration_selects_b")
    require(values.get("KP_WORKER_AUDIT_ANCHOR_PROVIDER") == "local_worm", "nonlocal_witness_not_supported")
    for key in ("KP_WORKER_AUDIT_ANCHOR_LOCAL_DIR", "KP_AI_GATEWAY_PROVIDER_STATE_FILE", "AZURE_GRAPH_CERT_PATH"):
        if raw := values.get(key):
            path = canonical(Path(raw) if Path(raw).is_absolute() else source / raw)
            require(path.is_relative_to(source / "data"), "protected_file_outside_snapshot")
    return values


def _copy_state(source: Path, snapshot: Path, deadline: float) -> dict[str, dict[str, Any]]:
    require(canonical(source / "data").is_dir(), "state_data_directory_missing")
    paths = [source / ".env"]
    for index, path in enumerate((source / "data").rglob("*")):
        require(index < MAX_FILES and remaining(deadline) > 0, "state_file_count_bound")
        paths.append(path)
    if os.path.lexists(source / "docker-compose.override.yml"):
        paths.append(source / "docker-compose.override.yml")
    require(len(paths) <= MAX_FILES, "state_file_count_bound")
    total = 0
    files = {}
    private_directory(snapshot / "state", create=True)
    for path in sorted(paths):
        remaining(deadline)
        require(not path.is_symlink(), "state_link_refused")
        if path.is_dir():
            continue
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "state_object_kind_refused")
        total += info.st_size
        require(total <= MAX_CLEAR_BYTES, "state_bytes_bound")
        relative = "state/" + relative_name(path.relative_to(source).as_posix())
        target = snapshot / relative
        for directory in reversed(list(target.parent.parents)):
            if directory.is_relative_to(snapshot) and not directory.exists():
                private_directory(directory, create=True)
        if not target.parent.exists():
            private_directory(target.parent, create=True)
        private_bytes(target, path.read_bytes(), executable=bool(info.st_mode & 0o111))
        require(sha256(target) == sha256(path) and path.stat().st_size == info.st_size, "state_changed_during_capture")
        files[relative] = {
            "sha256": sha256(target),
            "bytes": info.st_size,
            "mode": "0700" if info.st_mode & 0o111 else "0600",
        }
    return files


def _wait_data_services(source: Path, postgres: str, deadline: float, evidence: Path) -> None:
    until = min(deadline - 5, time.time() + 60)
    while time.time() < until:
        try:
            _docker(["exec", postgres, "pg_isready", "-U", "kingphisher", "-d", "kingphisher"], deadline, evidence)
            result = _probe(
                source,
                PROBE_PREAMBLE + "\nimport redis\n"
                "c=redis.Redis.from_url(config['REDIS_URL'],socket_timeout=3,socket_connect_timeout=2)\n"
                "try: print(json.dumps({'ready':c.ping()}))\nfinally: c.close()\n",
                {},
                deadline,
                evidence,
            )
            if result.get("ready") is True:
                return
        except RecoveryError as error:
            if str(error) not in {"command_failed", "command_timed_out"}:
                raise
        time.sleep(0.2)
    raise RecoveryError("data_service_readiness_deadline")


def capture(request: dict[str, Any]) -> dict[str, Any]:
    source, output, deadline = _request(request)
    verify_source(source, request["source_git_manifest"], deadline)
    containers, volumes, prior = _proofs(request, source)
    private_directory(output, create=True)
    diagnostics = private_directory(output / "diagnostics", create=True)
    snapshot = private_directory(output / "snapshot", create=True)
    _quiescent(source, deadline, diagnostics)
    current = _engine(containers, volumes, request["expected_engine"], deadline, diagnostics)
    config = _configuration(source, deadline, diagnostics)
    for service in ("postgres", "redis"):
        if not current[service]["State"]["Running"]:
            _docker(["start", current[service]["Id"]], deadline, diagnostics)
    current = _engine(containers, volumes, request["expected_engine"], deadline, diagnostics)
    require(all(current[key]["State"]["Running"] for key in ("postgres", "redis")), "a_data_services_not_running")
    _wait_data_services(source, current["postgres"]["Id"], deadline, diagnostics)
    _quiescent(source, deadline, diagnostics)
    run_id, nonce = request["run_id"], str(uuid.uuid4())
    sentinel = {
        "table": "kp_recovery_sentinel_" + hashlib.sha256(run_id.encode()).hexdigest()[:16],
        "key": run_id,
        "value": nonce,
        "key_column": "sentinel_key",
        "value_column": "sentinel_value",
    }
    database = _probe(
        source,
        DATABASE_PROBE,
        {"sentinel": sentinel, "create_sentinel": True, "previous_audit": prior},
        deadline,
        diagnostics,
    )
    require(database["schema_head"] == request["application"]["schema_head"], "source_schema_mismatch")
    file_relative = "data/recovery/offhost-" + run_id + "/sentinel"
    require(
        canonical(source / "data").is_dir() and canonical(source / "data/recovery").is_dir(),
        "recovery_directory_missing",
    )
    private_directory((source / file_relative).parent, create=True)
    private_bytes(source / file_relative, nonce.encode())
    redis = _probe(
        source,
        REDIS_CAPTURE_PROBE,
        {"run_id": run_id, "sentinel": {"key": "kp:recovery:offhost:" + run_id, "value": nonce}, "deadline": deadline},
        deadline,
        diagnostics,
    )
    for name, argv in (
        ("globals.sql", ["pg_dumpall", "--no-password", "-U", "kingphisher", "--globals-only"]),
        ("postgres.dump", ["pg_dump", "--no-password", "-U", "kingphisher", "-d", "kingphisher", "--format=custom"]),
    ):
        _docker(["exec", current["postgres"]["Id"], *argv], deadline, diagnostics, output=snapshot / name, record=False)
    require((snapshot / "postgres.dump").stat().st_size <= MAX_CLEAR_BYTES, "database_dump_bound")
    require((snapshot / "globals.sql").stat().st_size <= 8 * 1024**2, "database_globals_bound")
    _docker(
        ["exec", "-i", current["postgres"]["Id"], "pg_restore", "--list"],
        deadline,
        diagnostics,
        input_data=(snapshot / "postgres.dump").read_bytes(),
        record=False,
    )
    _docker(
        ["exec", current["redis"]["Id"], "redis-check-rdb", "/data/dump.rdb"],
        deadline,
        diagnostics,
        record=False,
    )
    _docker(
        ["exec", current["redis"]["Id"], "cat", "/data/dump.rdb"],
        deadline,
        diagnostics,
        output=snapshot / "redis.rdb",
        record=False,
    )
    private_json(snapshot / "redis-inventory.json", redis["inventory"])
    require(
        read_database_state(source, deadline=deadline, evidence=diagnostics, sentinel=sentinel) == database,
        "database_changed_during_capture",
    )
    after_inventory = read_redis_inventory(source, deadline=deadline, evidence=diagnostics)
    # Natural expiry may remove keys, but surviving values and all persistent
    # state must agree with the exact logical state in the RDB capture.
    now = int(time.time() * 1000)
    for key, expected in redis["inventory"].items():
        if expected["expires_ms"] is None or expected["expires_ms"] > now + 2000:
            require(
                key in after_inventory and after_inventory[key]["sha256"] == expected["sha256"],
                "redis_changed_during_capture",
            )
    require(set(after_inventory) <= set(redis["inventory"]), "redis_changed_during_capture")
    files = _copy_state(source, snapshot, deadline)
    for name in ("globals.sql", "postgres.dump", "redis.rdb", "redis-inventory.json"):
        path = snapshot / name
        require(path.stat().st_size > 0, "checkpoint_file_empty")
        files[name] = {"sha256": sha256(path), "bytes": path.stat().st_size, "mode": "0600"}
    require(
        sum(item["bytes"] for item in files.values()) <= MAX_CLEAR_BYTES and len(files) <= MAX_FILES,
        "snapshot_total_bound",
    )
    _quiescent(source, deadline, diagnostics)
    _engine(containers, volumes, request["expected_engine"], deadline, diagnostics)
    verify_source(source, request["source_git_manifest"], deadline)
    _proofs(request, source)
    manifest = {
        "schema": SNAPSHOT_SCHEMA,
        "run_id": run_id,
        "scope": "synthetic-qualification",
        "created_at": time.time(),
        "application": {**request["application"], "source_root": str(source)},
        "source": {
            "hostname": request["expected_hostname"],
            "vm_id": request["expected_vm_id"],
            "engine_id": request["expected_engine"]["id"],
            "docker_host": A_SOCKET,
            "docker_root": "/var/lib/docker",
            "containers": containers,
        },
        "data": {
            "database": database,
            "redis": {
                "inventory": "redis-inventory.json",
                "sentinel": redis["sentinel"],
                "maintenance": redis["maintenance"],
            },
            "file_sentinel": {"path": file_relative, "value": nonce, "sha256": sha256(source / file_relative)},
            "protected_purposes": purpose_fingerprints(config),
        },
        "files": files,
    }
    private_json(snapshot / "manifest.json", manifest)
    private_json(
        output / "captured.json",
        {"passed": True, "snapshot": str(snapshot), "manifest_sha256": sha256(snapshot / "manifest.json")},
    )
    return {"snapshot": str(snapshot), "manifest": manifest}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("--execute-after-review", action="store_true")
    args = parser.parse_args()
    if not args.execute_after_review:
        print("PLAN ONLY: A-only synthetic capture; no files, services or connections changed.")
        return 0
    try:
        private_file(args.request)
        result = capture(read_json(args.request))
        print(json.dumps({"passed": True, "snapshot": result["snapshot"]}))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, RecoveryError) else type(error).__name__
        print("CAPTURE BLOCKED: " + code + "; preserve all partial assets.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
