"""Synthetic source identity/capture guards; no real service or connection runs."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "scripts/operator/recovery-qualification"
TEST_VM_ID = (
    "/subscriptions/169644fd-c81d-4935-af55-5770f8271022/resourceGroups/"
    "rg-kp-cleanlinux-20261106-3lkij1-v4/providers/Microsoft.Compute/virtualMachines/"
    "vm-kp-cleanlinux-20261106-3lkij1-v4"
)
sys.path.insert(0, str(TOOLS))
import common  # noqa: E402


def load_module():
    spec = importlib.util.spec_from_file_location("offhost_source_test_module", TOOLS / "source_capture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


@pytest.fixture
def source_case(tmp_path, monkeypatch):
    module = load_module()
    root = tmp_path / "qualification"
    source = root / "clean-target"
    source.mkdir(parents=True)
    (source / "data/recovery").mkdir(parents=True)
    (source / "data/run").mkdir()
    (source / "data/audit-anchors").mkdir()
    (source / "data/recovery/original-proof").write_bytes(b"preserve prior evidence")
    (source / "data/run/provider-state.json").write_bytes(b"private synthetic provider state")
    (source / ".env").write_bytes(b"fixture private configuration")
    (source / ".env").chmod(0o600)
    manifest = {}
    for name, payload, mode in (
        ("pyproject.toml", b"qualified package metadata", "100644"),
        ("scripts/install.sh", b"qualified installer", "100755"),
    ):
        path = source / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o755 if mode == "100755" else 0o644)
        manifest[name] = {
            "blob": hashlib.sha1(
                b"blob " + str(len(payload)).encode() + b"\0" + payload, usedforsecurity=False
            ).hexdigest(),
            "mode": mode,
        }
    evidence = root / "evidence"
    evidence.mkdir()
    descriptors, inventory, rows = [], [], []
    volumes = [
        {
            "Name": module.PROJECT + "_" + service + "_data",
            "CreatedAt": "qualified-time",
            "Mountpoint": "/var/lib/docker/volumes/" + service,
            "Labels": {"com.docker.compose.project": module.PROJECT},
        }
        for service in ("postgres", "redis")
    ]
    for index, service in enumerate(common.SERVICES, 1):
        identifier, image = f"{index:064x}", "sha256:" + f"{index + 10:064x}"
        mounts = (
            [{"Type": "volume", "Name": module.PROJECT + "_" + service + "_data"}]
            if service in {"postgres", "redis"}
            else []
        )
        row = {
            "id": identifier,
            "image": image,
            "created": "qualified-time",
            "name": f"/{module.PROJECT}-{service}-1",
            "mounts": mounts,
            "service": service,
        }
        inventory.append({key: row[key] for key in ("id", "image", "name", "service")})
        inventory[-1]["image_reference"] = "qualified/" + service + "@" + image
        descriptors.append({**row, "image_reference": inventory[-1]["image_reference"]})
        rows.append(
            {
                "Id": identifier,
                "Image": image,
                "Created": row["created"],
                "Name": row["name"],
                "Mounts": mounts,
                "Config": {
                    "Image": inventory[-1]["image_reference"],
                    "Env": ["SECRET=must-not-log-inspect"],
                    "Labels": {"com.docker.compose.project": module.PROJECT, "com.docker.compose.service": service},
                },
                "State": {"Running": False},
            }
        )
    final = {
        "sequence": 42,
        "event_hash": "f" * 64,
        "keys": {},
        "recipients": {},
        "database_revision": "0060_tracking_runtime_locks",
        "preservation_verified": True,
    }
    proof_values = {
        "reboot_after": {
            "engine": {
                "ID": "qualified-engine",
                "DockerRootDir": "/var/lib/docker",
                "ServerVersion": "qualified-version",
            },
            "containers": [
                {key: value for key, value in row.items() if key != "image_reference"} for row in descriptors
            ],
            "volumes": volumes,
            "configuration_sha256": common.sha256(source / ".env"),
        },
        "container_inventory": inventory,
        "preserved_before_b": {
            "ids": [row["id"] for row in descriptors],
            "volumes": volumes,
            "containers_stopped_not_removed": True,
            "daemon_and_socket_inactive_runtime_masked": True,
        },
        "final_state": final,
        "source_proof": {
            "source_sha": "a" * 40,
            "git_blobs_and_modes": True,
            "objects": len(manifest),
            "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        },
    }
    proofs = {}
    for key, basename in module.PROOFS.items():
        path = evidence / basename
        write_json(path, proof_values[key])
        proofs[key] = {"path": str(path), "sha256": common.sha256(path)}
    request = {
        "schema": common.SOURCE_REQUEST_SCHEMA,
        "run_id": "qualification20261107",
        "scope": "synthetic-qualification",
        "deadline": time.time() + 600,
        "source_mode": "A",
        "expected_hostname": "qualified-host",
        "expected_vm_id": TEST_VM_ID,
        "source_root": str(source),
        "output": str(root / "offhost-capture-new"),
        "application": {
            "bundle_commit": "a" * 40,
            "runtime_commit": common.RUNTIME_COMMIT,
            "schema_head": final["database_revision"],
        },
        "expected_engine": {"id": "qualified-engine", "root": "/var/lib/docker", "socket": module.A_SOCKET},
        "expected_containers": descriptors,
        "source_git_manifest": manifest,
        "proofs": proofs,
    }
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "B_SOCKET", root / "missing-B.sock")
    proc = root / "proc"
    proc.mkdir()
    monkeypatch.setattr(module, "PROC", proc)
    monkeypatch.setattr(module, "CGROUPS", root / "cgroups")
    monkeypatch.setattr(module.socket, "gethostname", lambda: "qualified-host")
    monkeypatch.setattr(module, "_vm_identity", lambda _: TEST_VM_ID)
    config = {
        "DATABASE_URL": "postgresql+psycopg://kingphisher:private@localhost:5432/kingphisher",
        "DATABASE_URL_TEST": "postgresql://kingphisher:private@localhost:5432/kingphisher_test",
        "REDIS_URL": "redis://:private@localhost:6379/0",
        "KP_WORKER_AUDIT_ANCHOR_PROVIDER": "local_worm",
        "KP_WORKER_AUDIT_ANCHOR_LOCAL_DIR": "data/audit-anchors",
        "OPERATOR_API_CIPHERTEXT_KEK": "synthetic-key",
        "OPERATOR_API_CONSOLE_JWT_SECRET": "synthetic-secret",
    }
    calls, starts = [], []
    state = {
        "schema_head": final["database_revision"],
        "table_counts": {"audit_events": 42},
        "audit": {"sequence": 42, "event_hash": "f" * 64, "signature": "signed-head", "audit_verified": True},
        "ciphertexts": {"recipients.mailbox": {"count": 3, "sha256": "d" * 64}},
        "sentinel": None,
    }
    logical = {"e" * 64: {"sha256": "c" * 64, "expires_ms": None}}

    def run(argv, _deadline, _evidence, **kwargs):
        calls.append((argv, kwargs))
        assert argv[:2] == ["systemctl", "list-units"]
        return b""

    def docker(argv, _deadline, _evidence, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == "info":
            return json.dumps(
                {
                    "ID": "qualified-engine",
                    "DockerRootDir": "/var/lib/docker",
                    "OSType": "linux",
                    "Architecture": "amd64",
                }
            ).encode()
        if argv[0] == "ps":
            return "\n".join(row["Id"] for row in rows).encode()
        if argv[0] == "inspect":
            assert kwargs.get("record") is False
            return json.dumps(rows).encode()
        if argv[:2] == ["volume", "inspect"]:
            return json.dumps(volumes).encode()
        if argv[0] == "start":
            assert len(argv) == 2
            starts.append(argv[1])
            next(row for row in rows if row["Id"] == argv[1])["State"]["Running"] = True
            return argv[1].encode()
        if "output" in kwargs:
            assert kwargs.get("record") is False
            common.private_bytes(kwargs["output"], b"private synthetic logical dump")
            return b""
        assert argv[0] == "exec" and any(name in argv for name in ("pg_isready", "pg_restore", "redis-check-rdb"))
        return b"ready"

    def probe(_source, program, payload, _deadline, _evidence):
        assert _source == source
        if program == module.DATABASE_PROBE:
            if payload.get("create_sentinel"):
                state["table_counts"][payload["sentinel"]["table"]] = 1
                state["sentinel"] = payload["sentinel"]
            return copy.deepcopy(state)
        if program == module.REDIS_CAPTURE_PROBE:
            return {
                "inventory": logical,
                "sentinel": payload["sentinel"],
                "maintenance": {
                    "topic": "audit-anchor",
                    "id": "job-id",
                    "idempotency_key": "offhost-recovery:" + request["run_id"],
                    "acknowledgment": True,
                    "payload": {},
                    "ready_key": "kp:queue:{audit-anchor}",
                    "envelope_sha256": "b" * 64,
                    "prior_heartbeat": None,
                },
            }
        if program == module.REDIS_INVENTORY_PROBE:
            return copy.deepcopy(logical)
        if "c.ping()" in program:
            return {"ready": True}
        return config

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(module, "_docker", docker)
    monkeypatch.setattr(module, "_probe", probe)
    return SimpleNamespace(
        module=module,
        request=request,
        source=source,
        root=root,
        rows=rows,
        volumes=volumes,
        config=config,
        calls=calls,
        starts=starts,
        state=state,
        logical=logical,
        original={path: path.read_bytes() for path in evidence.iterdir()},
    )


def test_default_plan_does_not_read_request_or_touch_any_runtime(monkeypatch, capsys):
    module = load_module()
    monkeypatch.setattr(sys, "argv", ["source_capture.py", "/does-not-exist/private-request.json"])
    monkeypatch.setattr(module, "capture", lambda _: pytest.fail("plan executed capture"))
    assert module.main() == 0
    assert "PLAN ONLY" in capsys.readouterr().out


def dual_mount_engine_case(case):
    """A PostgreSQL initializer bind plus data volume, as on the actual source."""
    expected = copy.deepcopy(case.request["expected_containers"])
    postgres = next(row for row in expected if row["service"] == "postgres")
    postgres["mounts"] = [
        {
            "Type": "bind",
            "Source": str(case.source / "infrastructure/containers/postgres-init"),
            "Destination": "/docker-entrypoint-initdb.d",
            "Mode": "ro",
            "RW": False,
            "Propagation": "rprivate",
        },
        {
            "Type": "volume",
            "Name": case.module.PROJECT + "_postgres_data",
            "Driver": "local",
            "Source": "/var/lib/docker/volumes/qualified-postgres/_data",
            "Destination": "/var/lib/postgresql/data",
            "Mode": "rw",
            "RW": True,
            "Propagation": "",
        },
    ]
    actual = next(row for row in case.rows if row["Id"] == postgres["id"])
    actual["Mounts"] = copy.deepcopy(postgres["mounts"])
    return expected, postgres, actual


def test_container_start_may_reorder_mounts_without_changing_any_identity(source_case):
    case = source_case
    expected, postgres, actual = dual_mount_engine_case(case)
    first = case.module._engine(
        expected, case.volumes, case.request["expected_engine"], case.request["deadline"], case.root
    )
    assert first["postgres"]["State"]["Running"] is False
    case.module._docker(["start", postgres["id"]], case.request["deadline"], case.root)
    actual["Mounts"].reverse()
    second = case.module._engine(
        expected, case.volumes, case.request["expected_engine"], case.request["deadline"], case.root
    )
    assert second["postgres"]["State"]["Running"] is True
    assert case.starts == [postgres["id"]]


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "destination",
        "driver",
        "name",
        "mode",
        "rw",
        "propagation",
        "type",
        "missing",
        "null",
        "extra",
        "duplicate",
        "bool-number",
    ],
)
def test_mount_reordering_never_hides_mount_identity_or_type_changes(source_case, mutation):
    case = source_case
    expected, _postgres, actual = dual_mount_engine_case(case)
    actual["Mounts"].reverse()
    volume, bind = actual["Mounts"]
    fields = {
        "source": "Source",
        "destination": "Destination",
        "driver": "Driver",
        "name": "Name",
        "mode": "Mode",
        "rw": "RW",
        "propagation": "Propagation",
        "type": "Type",
    }
    if mutation in fields:
        key = fields[mutation]
        volume[key] = False if key == "RW" else "changed"
    elif mutation == "missing":
        del volume["Mode"]
    elif mutation == "null":
        bind["Name"] = None
    elif mutation == "extra":
        volume["UnknownMountAttribute"] = "changed"
    elif mutation == "duplicate":
        actual["Mounts"].append(copy.deepcopy(volume))
    else:
        bind["RW"] = 0
    with pytest.raises(common.RecoveryError, match="a_container_identity_changed"):
        case.module._engine(
            expected, case.volumes, case.request["expected_engine"], case.request["deadline"], case.root
        )
    assert not case.starts


@pytest.mark.parametrize(
    "vm_id",
    (
        TEST_VM_ID.replace("169644fd", "269644fd"),
        TEST_VM_ID.replace("resourceGroups/rg-kp-cleanlinux", "resourceGroups/rg-unrelated"),
        TEST_VM_ID.replace("virtualMachines/vm-kp-cleanlinux", "virtualMachines/vm-unrelated"),
        TEST_VM_ID.replace(
            "virtualMachines/vm-kp-cleanlinux-20261106-3lkij1-v4", "virtualMachines/vm-kp-cleanlinux-20261106-3lkij1-v5"
        ),
        TEST_VM_ID.replace("-v4", "-v3"),
        TEST_VM_ID.replace("-v4", "-v1000"),
    ),
)
def test_wrong_namespace_or_unpaired_vm_versions_fail_before_identity_probe(source_case, monkeypatch, vm_id):
    case = source_case
    case.request["expected_vm_id"] = vm_id
    monkeypatch.setattr(case.module, "_vm_identity", lambda _: pytest.fail("invalid VM reached IMDS"))
    with pytest.raises(common.RecoveryError, match="source_vm_outside_task"):
        case.module.capture(case.request)
    assert not case.calls and not Path(case.request["output"]).exists()


def test_explicit_qualified_later_vm_is_supported_without_automatic_selection(source_case, monkeypatch):
    case = source_case
    selected = TEST_VM_ID.replace("-v4", "-v5")
    case.request["expected_vm_id"] = selected
    monkeypatch.setattr(case.module, "_vm_identity", lambda _: selected)
    assert case.module.capture(case.request)["manifest"]["source"]["vm_id"] == selected


def test_valid_namespace_with_wrong_actual_imds_identity_is_refused(source_case, monkeypatch):
    case = source_case
    monkeypatch.setattr(case.module, "_vm_identity", lambda _: TEST_VM_ID.replace("-v4", "-v5"))
    with pytest.raises(common.RecoveryError, match="source_vm_identity_mismatch"):
        case.module.capture(case.request)
    assert not case.calls and not Path(case.request["output"]).exists()


def test_success_captures_complete_private_state_and_starts_only_two_recorded_services(source_case):
    case = source_case
    result = case.module.capture(case.request)
    snapshot = Path(result["snapshot"])
    manifest = result["manifest"]
    assert case.starts == [
        row["Id"] for row in case.rows if row["Config"]["Labels"]["com.docker.compose.service"] in {"postgres", "redis"}
    ]
    assert set(manifest["files"]) == {
        str(path.relative_to(snapshot))
        for path in snapshot.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    for name, expected in manifest["files"].items():
        path = snapshot / name
        assert expected == {"sha256": common.sha256(path), "bytes": path.stat().st_size, "mode": "0600"}
        assert path.stat().st_mode & 0o777 == 0o600
    assert (snapshot / "state/data/run/provider-state.json").read_bytes() == b"private synthetic provider state"
    assert (snapshot / "state/data/recovery/original-proof").read_bytes() == b"preserve prior evidence"
    assert (
        manifest["data"]["database"]["sentinel"]["value"]
        == manifest["data"]["redis"]["sentinel"]["value"]
        == manifest["data"]["file_sentinel"]["value"]
    )
    assert manifest["data"]["redis"]["maintenance"]["acknowledgment"] is True
    assert manifest["data"]["protected_purposes"] == common.purpose_fingerprints(case.config)
    assert all(path.read_bytes() == original for path, original in case.original.items())
    assert "private@localhost" not in json.dumps(manifest) and "synthetic-key" not in json.dumps(manifest)
    assert not any(
        action in {"rm", "stop", "restart", "prune", "down", "dropdb"} for argv, _ in case.calls for action in argv
    )


@pytest.mark.parametrize(
    "field,value,code",
    (
        ("source_mode", "B", "source_scope"),
        ("scope", "real-data", "source_scope"),
        ("expected_hostname", "other", "hostname"),
        ("expected_vm_id", "other", "outside_task"),
        ("deadline", 0, "deadline"),
    ),
)
def test_wrong_request_stops_before_any_new_asset_or_runtime_call(source_case, field, value, code):
    case = source_case
    case.request[field] = value
    with pytest.raises(common.RecoveryError, match=code):
        case.module.capture(case.request)
    assert not case.calls and not Path(case.request["output"]).exists()


@pytest.mark.parametrize("change", ("bytes", "mode", "proof", "config", "descriptor", "manifest_subset"))
def test_source_or_provenance_drift_is_refused_before_runtime_calls(source_case, change):
    case = source_case
    if change == "bytes":
        (case.source / "scripts/install.sh").write_bytes(b"changed installer")
    elif change == "mode":
        (case.source / "scripts/install.sh").chmod(0o644)
    elif change == "proof":
        case.request["proofs"]["reboot_after"]["sha256"] = "0" * 64
    elif change == "config":
        (case.source / ".env").write_bytes(b"changed private config")
    elif change == "manifest_subset":
        case.request["source_git_manifest"] = {
            "scripts/install.sh": case.request["source_git_manifest"]["scripts/install.sh"]
        }
    else:
        case.request["expected_containers"] = copy.deepcopy(case.request["expected_containers"])
        case.request["expected_containers"][0]["image"] = "sha256:" + "0" * 64
    with pytest.raises(common.RecoveryError):
        case.module.capture(case.request)
    assert not case.calls and not Path(case.request["output"]).exists()


@pytest.mark.parametrize("change", ("image", "mount", "volume"))
def test_engine_container_or_volume_drift_prevents_any_start(source_case, change):
    case = source_case
    if change == "image":
        case.rows[0]["Image"] = "sha256:" + "0" * 64
    elif change == "mount":
        case.rows[0]["Mounts"] = [{"Type": "volume", "Name": "unrelated"}]
    else:
        case.volumes[0] = {**case.volumes[0], "Mountpoint": "/unrelated"}
    with pytest.raises(common.RecoveryError):
        case.module.capture(case.request)
    assert not case.starts


@pytest.mark.parametrize("hazard", ("B_socket", "stale_pid", "native_process", "B_process"))
def test_source_quiescence_refuses_unknown_or_live_state_without_service_actions(source_case, hazard):
    case = source_case
    if hazard == "B_socket":
        case.module.B_SOCKET.write_bytes(b"retained ambiguous endpoint")
    elif hazard == "stale_pid":
        (case.source / "data/run/operator-api.pid").write_text("999999\n")
    else:
        process = case.module.PROC / "123"
        process.mkdir()
        (process / "cwd").symlink_to(case.source)
        (process / "cmdline").write_bytes(
            b"python\0-m\0kp_workers"
            if hazard == "native_process"
            else b"dockerd\0--config-file\0/srv/kp-cleanlinux/upgrade-daemon.json"
        )
    with pytest.raises(common.RecoveryError):
        case.module.capture(case.request)
    assert not case.starts


def test_active_task_unit_prevents_any_container_action(source_case, monkeypatch):
    case = source_case

    def run(argv, *_a, **_kw):
        if argv[1] == "list-units":
            return b"kp-cleanlinux-upgrade-engine.service loaded active running B\n"
        return b"ActiveState=active\nMainPID=777\nControlGroup=/system.slice/kp-cleanlinux-upgrade-engine.service\n"

    monkeypatch.setattr(case.module, "_run", run)
    with pytest.raises(common.RecoveryError, match="application_unit_live"):
        case.module.capture(case.request)
    assert not case.starts


@pytest.mark.parametrize(
    "alias,value",
    (
        ("KP_WORKER_DATABASE_URL_DELIVERY", "postgresql://private@external:5432/kingphisher"),
        ("PGHOST", "external"),
        ("DOCKER_HOST", "unix:///run/kp-cleanlinux-upgrade-docker/docker.sock"),
    ),
)
def test_configuration_cannot_redirect_capture_from_A(source_case, alias, value):
    case = source_case
    case.config[alias] = value
    with pytest.raises(common.RecoveryError):
        case.module.capture(case.request)
    assert not case.starts


def test_state_link_is_never_followed_and_partial_dump_is_preserved(source_case):
    case = source_case
    outside = case.root / "unrelated-secret"
    outside.write_bytes(b"must remain outside snapshot")
    (case.source / "data/recovery/link").symlink_to(outside)
    with pytest.raises(common.RecoveryError, match="state_link_refused"):
        case.module.capture(case.request)
    partial = Path(case.request["output"]) / "snapshot"
    assert (partial / "postgres.dump").exists()
    assert not (partial / "state/data/recovery/link").exists()
    assert outside.read_bytes() == b"must remain outside snapshot"


def test_existing_output_and_all_old_assets_are_preserved(source_case):
    case = source_case
    output = Path(case.request["output"])
    output.mkdir()
    (output / "prior-evidence").write_bytes(b"retain")
    with pytest.raises(common.RecoveryError, match="namespace_already_exists"):
        case.module.capture(case.request)
    assert not case.calls and (output / "prior-evidence").read_bytes() == b"retain"


def test_failed_dump_retains_prior_files_without_cleanup(source_case, monkeypatch):
    case = source_case
    original = case.module._docker

    def failing(argv, *args, **kwargs):
        if "pg_dump" in argv:
            raise common.RecoveryError("command_failed")
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(case.module, "_docker", failing)
    with pytest.raises(common.RecoveryError, match="command_failed"):
        case.module.capture(case.request)
    assert (Path(case.request["output"]) / "snapshot/globals.sql").exists()
    assert all(path.read_bytes() == original for path, original in case.original.items())


def test_probe_uses_verified_source_interpreter_and_never_records_private_output(source_case, monkeypatch):
    case = source_case
    recorded = []

    def run(argv, _deadline, _evidence, **kwargs):
        recorded.append((argv, kwargs))
        return b'{"schema_head":"0060_tracking_runtime_locks"}'

    monkeypatch.setattr(case.module, "_run", run)
    # Call the original probe with only its command boundary replaced.
    module = load_module()
    monkeypatch.setattr(module, "_run", run)
    assert (
        module.read_database_state(case.source, deadline=case.request["deadline"], evidence=case.root)["schema_head"]
        == "0060_tracking_runtime_locks"
    )
    argv, options = recorded[0]
    assert argv[0] == str(case.source / ".venv/bin/python") and options["record"] is False
    assert options["cwd"] == case.source and "input_data" in options


def test_all_fixed_source_venv_programs_compile_without_importing_application():
    module = load_module()
    for name in ("DATABASE_PROBE", "REDIS_CAPTURE_PROBE", "REDIS_INVENTORY_PROBE"):
        compile(getattr(module, name), name, "exec")


def test_bad_sentinel_identifier_cannot_become_sql(source_case):
    case = source_case
    module = load_module()
    with pytest.raises(common.RecoveryError, match="sentinel_table_invalid"):
        module.read_database_state(
            case.source,
            deadline=case.request["deadline"],
            evidence=case.root,
            sentinel={"table": "x;DROP TABLE recipients"},
        )
