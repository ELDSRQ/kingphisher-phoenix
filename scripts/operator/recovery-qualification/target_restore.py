"""Restore one authenticated synthetic snapshot on a fresh, explicitly bound target.

Default CLI mode is a plan. Docker/database/application operations require the
explicit execution flag. Every created resource is retained, including failures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import socket
import stat
import time
from pathlib import Path
from typing import Any

from common import (
    APP_CHILDREN,
    MAX_FILES,
    RUNTIME_COMMIT,
    SERVICES,
    TARGET_REQUEST_SCHEMA,
    RecoveryError,
    canonical,
    clean_environment,
    command,
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

PROJECT = "phishing-awareness-platform"
SOCKET = "unix:///var/run/docker.sock"
ROLE_STATEMENT = b"CREATE ROLE kingphisher;\n"
CONTAINER_SOCKET = "/tmp/offhost-redis.sock"  # noqa: S108 - private network-none container tmpfs, not host /tmp
CONTAINER_TMPFS = "/tmp:rw,noexec,nosuid,nodev"  # noqa: S108 - container mount specification


def verify_source(root: Path, manifest: dict[str, Any], *, canonical_modes: bool = False) -> None:
    canonical(root)
    require(root.is_dir() and 0 < len(manifest) <= MAX_FILES, "source_manifest_invalid")
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in list(dirs):
            path = Path(directory) / name
            if path.parent == root and name in {".venv", "data", ".git", "node_modules"}:
                dirs.remove(name)
            elif path.is_symlink():
                actual.add(path.relative_to(root).as_posix())
                dirs.remove(name)
        for name in files:
            path = Path(directory) / name
            if path.parent == root and name in {".env", "docker-compose.override.yml"}:
                continue
            actual.add(path.relative_to(root).as_posix())
        require(len(actual) <= MAX_FILES, "source_inventory_bound")
    require(actual == set(manifest), "source_has_missing_or_unqualified_files")
    for name, item in manifest.items():
        relative_name(name)
        require(
            not {".env", "data", ".venv", ".git", "node_modules"}.intersection(name.split("/")), "source_scope_invalid"
        )
        path = root / name
        mode = item.get("mode")
        if mode == "120000":
            require(path.is_symlink() and path.resolve().is_relative_to(root), "source_symlink_escapes")
            data = os.readlink(path).encode()
        else:
            canonical(path)
            require(path.is_file() and mode in {"100644", "100755"}, "source_file_kind_invalid")
            require(bool(path.stat().st_mode & 0o111) == (mode == "100755"), "source_executable_drift")
            require(not path.stat().st_mode & 0o022, "source_writable_by_others")
            if canonical_modes:
                require(
                    stat.S_IMODE(path.stat().st_mode) == (0o755 if mode == "100755" else 0o644),
                    "source_code_mode_drift",
                )
            data = path.read_bytes()
        digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False).hexdigest()
        require(digest == item.get("blob"), "source_git_blob_drift")
    require(
        {"scripts/install.sh", "scripts/verify_install.sh", "docker-compose.yml"} <= manifest.keys(),
        "source_entrypoints_missing",
    )


def canonicalize_source(root: Path, manifest: dict[str, Any]) -> None:
    """Git code is public0644/0755 even under private execution umask077.

    This changes only verified NEW target code. Private state and code symlinks
    retain their separate modes. In particular PostgreSQL bind initializers must
    remain readable/traversable by the container account.
    """
    verify_source(root, manifest)
    for name, item in manifest.items():
        path = root / name
        if item["mode"] != "120000":
            path.chmod(0o755 if item["mode"] == "100755" else 0o644)
        for parent in path.parents:
            if parent == root:
                break
            canonical(parent).chmod(0o755)
    verify_source(root, manifest, canonical_modes=True)


def globals_without_bootstrap_role(raw: bytes) -> bytes:
    require(raw.count(ROLE_STATEMENT) == 1, "bootstrap_role_statement_not_exactly_once")
    lines = raw.splitlines(keepends=True)
    require(sum(line == ROLE_STATEMENT for line in lines) == 1, "bootstrap_role_statement_not_exact")
    # Retain every ALTER ROLE, password, ownership and privilege statement.
    return b"".join(line for line in lines if line != ROLE_STATEMENT)


def compare_redis(before: dict[str, Any], after: dict[str, Any], *, now_ms: int) -> None:
    require(not set(after) - set(before), "redis_unexpected_keys")
    for key, expected in before.items():
        actual = after.get(key)
        expiry = expected["expires_ms"]
        if actual is None:
            require(expiry is not None and expiry <= now_ms, "redis_missing_unexpired_key")
            continue
        require(actual["sha256"] == expected["sha256"], "redis_value_drift")
        require((expiry is None) == (actual["expires_ms"] is None), "redis_expiry_kind_drift")
        if expiry is not None:
            require(abs(expiry - actual["expires_ms"]) <= 1000, "redis_expiry_drift")


def retarget_config(raw: bytes, old: str, new: str) -> tuple[bytes, list[str]]:
    """Only absolute, source-root-prefixed path-purpose assignments may change."""
    changed = []
    result = []
    for line in raw.decode().splitlines(keepends=True):
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*?)(\r?\n)?$", line)
        if match and match[1].endswith(("_PATH", "_FILE", "_DIR")):
            value = match[2]
            quote = value[:1] if value[:1] in {'"', "'"} else ""
            prefix = quote + old
            if value.startswith(prefix) and value[len(prefix) : len(prefix) + 1] in {"", "/", quote}:
                line = match[1] + "=" + quote + new + value[len(prefix) :] + (match[3] or "")
                changed.append(match[1])
        result.append(line)
    return "".join(result).encode(), changed


def write_private_state(path: Path, raw: bytes, *, executable: bool, app_uid: int) -> None:
    canonical(path)
    parent = canonical(path.parent)
    info = parent.stat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid in {os.geteuid(), app_uid} and not info.st_mode & 0o077,
        "new_state_parent_not_private_owned",
    )
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700 if executable else 0o600), "wb"
    ) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def validate_process_bindings(root: Path, *, proc: Path = Path("/proc"), uid: int) -> dict[str, int]:
    result = {}
    for name in APP_CHILDREN:
        pidfile = root / "data/run" / (name + ".pid")
        canonical(pidfile)
        value = pidfile.read_text().strip()
        require(re.fullmatch(r"[1-9][0-9]*", value), "native_child_pid_invalid")
        process = proc / value
        require(process.stat().st_uid == uid and (process / "cwd").resolve() == root, "native_child_owner_or_cwd_drift")
        arguments = (process / "cmdline").read_bytes().decode().split("\0")
        arguments = [value for value in arguments if value]
        tail = ["kp-worker", name.removeprefix("worker-")] if name.startswith("worker-") else ["kp-" + name]
        # Qualified supervisor PID files name UV wrappers, not Python children.
        require(arguments == ["uv", "run", "--frozen", "--no-sync", *tail], "native_child_command_drift")
        virtual_env = [
            item.removeprefix(b"VIRTUAL_ENV=")
            for item in (process / "environ").read_bytes().split(b"\0")
            if item.startswith(b"VIRTUAL_ENV=")
        ]
        require(virtual_env == [str(root / ".venv").encode()], "native_child_environment_drift")
        result[name] = int(value)
    require(len(set(result.values())) == len(APP_CHILDREN), "native_child_pid_reused")
    return result


class Target:
    def __init__(self, request: dict[str, Any]):
        require(
            request.get("schema") == TARGET_REQUEST_SCHEMA and request.get("scope") == "synthetic-qualification",
            "target_request_scope_invalid",
        )
        self.request = request
        self.deadline = float(request["deadline"])
        require(0 < remaining(self.deadline) <= 2700, "target_work_budget_invalid")
        self.root = canonical(Path(request["source_root"]))
        self.output = unused(Path(request["output"]))
        require(
            not self.output.is_relative_to(self.root) and not self.root.is_relative_to(self.output),
            "source_and_evidence_overlap",
        )
        self.app = request["application"]
        require(self.app["runtime_commit"] == RUNTIME_COMMIT, "runtime_commit_unqualified")
        require(re.fullmatch(r"[0-9a-f]{40}", self.app["bundle_commit"]), "bundle_commit_invalid")
        self.run_id = request["run_id"]
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", self.run_id), "run_id_invalid")
        self.suffix = hashlib.sha256(self.run_id.encode()).hexdigest()[:16]
        self.engine = request["expected_engine"]
        require(self.engine["socket"] == SOCKET, "target_docker_socket_unreviewed")
        self.user = pwd.getpwnam(request["app_user"])
        require(self.user.pw_name == "kpqual" and self.user.pw_uid > 0, "app_user_unreviewed")
        home = canonical(Path(self.user.pw_dir))
        require(home.is_dir() and home.stat().st_uid == self.user.pw_uid, "app_home_owner_invalid")
        self.env = clean_environment(
            {
                "DOCKER_HOST": SOCKET,
                "HOME": str(home),
                "USER": self.user.pw_name,
                "LOGNAME": self.user.pw_name,
                "COMPOSE_PROJECT_NAME": PROJECT,
                # Bootstrap installs its hash-pinned uv here; a direct Python
                # invocation does not activate that separate tools environment.
                "PATH": str(self.root.parent / "tools/uv-venv/bin")
                + ":"
                + str(self.root / ".venv/bin")
                + ":"
                + os.environ.get("PATH", "/usr/bin:/bin"),
            }
        )
        attestation = request["source_deallocated"]
        require(
            attestation.get("verified") is True
            and re.fullmatch(r"[0-9a-f]{64}", attestation.get("receipt_sha256", "")),
            "source_deallocation_attestation_missing",
        )
        for name in (".env", "data", "docker-compose.override.yml"):
            unused(self.root / name)
        verify_source(self.root, request["source_git_manifest"])
        require(self.root.stat().st_uid in {os.geteuid(), self.user.pw_uid}, "new_source_owner_unexpected")
        private_directory(self.output.parent)
        self.bound = False
        self.model: dict[str, Any] = {}
        self.manifest: dict[str, Any] = {}
        self.snapshot = self.output / "snapshot"
        self.config: dict[str, Any] = {}
        self.containers: dict[str, str] = {}
        self.started = time.time()

    def call(
        self,
        argv: list[str],
        *,
        limit: float = 120,
        sensitive: bool = False,
        data: bytes | None = None,
        env: dict[str, str] | None = None,
    ) -> bytes:
        return command(
            argv,
            timeout=min(limit, remaining(self.deadline, reserve=5)),
            cwd=self.root,
            env=self.env | (env or {}),
            input_data=data,
            evidence=self.output if self.bound else None,
            record=self.bound and not sensitive,
        )

    def docker(self, *args: str, **kwargs: Any) -> bytes:
        return self.call(["docker", "--host", SOCKET, *args], **kwargs)

    def compose(self, *args: str, **kwargs: Any) -> bytes:
        return self.docker("compose", "--project-directory", str(self.root), *args, **kwargs)

    def app_python(self, script: str, *, data: bytes | None = None, sensitive: bool = False) -> dict[str, Any]:
        raw = self.call(
            [
                "runuser",
                "-u",
                self.user.pw_name,
                "--",
                str(self.root / ".venv/bin/python"),
                "-c",
                script,
                str(self.root),
            ],
            data=data,
            sensitive=sensitive,
        )
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise RecoveryError("application_probe_not_object")
        return result

    def fresh(self) -> None:
        require(socket.gethostname() == self.request["expected_hostname"], "target_hostname_mismatch")
        actual = self.call(
            [
                "curl",
                "--noproxy",
                "*",
                "--connect-timeout",
                "2",
                "--max-time",
                "5",
                "-fsS",
                "-H",
                "Metadata:true",
                "http://169.254.169.254/metadata/instance/compute/resourceId?api-version=2021-02-01&format=text",
            ]
        )
        require(
            actual.decode().strip().lower() == self.request["expected_vm_id"].lower(), "target_vm_identity_mismatch"
        )
        info = json.loads(self.docker("info", "--format", "{{json .}}"))
        require(
            info["ID"] == self.engine["id"] and info["DockerRootDir"] == self.engine["root"],
            "target_engine_identity_mismatch",
        )
        require(
            info.get("Architecture") == "x86_64" and info.get("OSType") == "linux", "target_engine_platform_unqualified"
        )
        require(not self.docker("ps", "--all", "--quiet").strip(), "target_has_existing_containers")
        require(not self.docker("volume", "ls", "--quiet").strip(), "target_has_existing_volumes")
        # No source chmod, output creation, extraction or container mutation may
        # occur until every host/VM/engine/freshness check above has succeeded.
        private_directory(self.output, create=True)
        self.bound = True
        private_json(
            self.output / "fresh-engine.json",
            {"id": info["ID"], "root": info["DockerRootDir"], "vm_id": self.request["expected_vm_id"], "fresh": True},
        )

    def prepare_source(self) -> None:
        require(self.bound, "target_not_bound_before_source_mutation")
        canonicalize_source(self.root, self.request["source_git_manifest"])
        self.root.chmod(0o700)

    def decrypt(self) -> None:
        from artifacts import decrypt_snapshot

        result = decrypt_snapshot(
            Path(self.request["cipher_path"]),
            Path(self.request["identity_path"]),
            self.snapshot,
            self.request["expected_cipher_sha256"],
            age_command=self.request.get("age_command", "age"),
            deadline=self.deadline,
        )
        self.manifest = result["manifest"]
        require(
            self.manifest["scope"] == "synthetic-qualification" and self.manifest["run_id"] == self.run_id,
            "snapshot_scope_or_run_mismatch",
        )
        for name in ("bundle_commit", "runtime_commit", "schema_head"):
            require(self.manifest["application"][name] == self.app[name], "snapshot_application_binding_mismatch")
        require(result["sha256"] == self.request["expected_cipher_sha256"], "cipher_receipt_drift")
        private_json(
            self.output / "decryption.json",
            {
                "cipher_sha256": result["sha256"],
                "cipher_bytes": result["bytes"],
                "sender_authenticated_by_controller_digest": True,
            },
        )

    def restore_files(self) -> None:
        old = self.manifest["application"]["source_root"]
        require(Path(old).is_absolute() and old != str(self.root), "source_root_retarget_invalid")
        records = {}
        for name, item in self.manifest["files"].items():
            if not name.startswith("state/"):
                continue
            relative = relative_name(name.removeprefix("state/"))
            require(
                relative == ".env" or relative == "docker-compose.override.yml" or relative.startswith("data/"),
                "restore_file_scope_invalid",
            )
            source = private_file(self.snapshot / name)
            raw = source.read_bytes()
            require(
                hashlib.sha256(raw).hexdigest() == item["sha256"] and len(raw) == item["bytes"],
                "snapshot_file_changed_after_decrypt",
            )
            changed: list[str] = []
            if relative == ".env":
                raw, changed = retarget_config(raw, old, str(self.root))
            if relative == "docker-compose.override.yml":
                # Structured rewrite is delegated to the verified source venv;
                # no arbitrary YAML tags or generic text replacement is used.
                raw = self.retarget_override(raw, old)
            target = self.root / relative
            for parent in reversed(target.parent.relative_to(self.root).parents):
                if str(parent) != ".":
                    (self.root / parent).mkdir(mode=0o700, exist_ok=True)
            target.parent.mkdir(mode=0o700, exist_ok=True)
            require(item["mode"] in {"0600", "0700"}, "state_file_mode_unreviewed")
            write_private_state(target, raw, executable=item["mode"] == "0700", app_uid=self.user.pw_uid)
            require(sha256(target) == hashlib.sha256(raw).hexdigest(), "restored_file_readback_drift")
            records[relative] = {
                "source_sha256": item["sha256"],
                "restored_sha256": sha256(target),
                "retargeted": changed,
            }
        require(
            ".env" in records and any(name.startswith("data/") for name in records), "restored_private_state_missing"
        )
        self.chown_new_source()
        self.call(["runuser", "-u", self.user.pw_name, "--", "test", "-x", str(self.root)])
        self.config = self.app_python(CONFIG_PROBE, sensitive=True)
        require(
            all(
                not (
                    key.endswith(("_PATH", "_FILE", "_DIR"))
                    and isinstance(value, str)
                    and (value == old or value.startswith(old + "/"))
                )
                for key, value in self.config.items()
            ),
            "configuration_path_not_retargeted",
        )
        require(
            purpose_fingerprints(self.config) == self.manifest["data"]["protected_purposes"],
            "protected_purpose_fingerprints_drift",
        )
        sentinel = self.manifest["data"]["file_sentinel"]
        file = self.root / relative_name(sentinel["path"])
        require(
            sha256(file) == sentinel["sha256"] and file.read_text().strip() == sentinel["value"],
            "file_sentinel_missing_or_changed",
        )
        self.restored_files = records
        private_json(self.output / "restored-files.json", records)

    def chown_new_source(self) -> None:
        for path in [self.root, *self.root.rglob("*")]:
            require(path.is_symlink() or path.resolve().is_relative_to(self.root), "new_source_path_escapes")
            os.chown(path, self.user.pw_uid, self.user.pw_gid, follow_symlinks=False)

    def retarget_override(self, raw: bytes, old: str) -> bytes:
        result = self.call(
            [str(self.root / ".venv/bin/python"), "-c", OVERRIDE_PROBE, old, str(self.root)], data=raw, sensitive=True
        )
        return result

    def configure_compose(self) -> None:
        self.model = json.loads(self.compose("config", "--format", "json", sensitive=True))
        require(self.model.get("name") == PROJECT, "compose_project_not_canonical")
        require(
            set(self.model.get("volumes", {})) == {"postgres_data", "redis_data"}, "compose_extra_volumes_unreviewed"
        )
        require(set(SERVICES) <= self.model["services"].keys(), "compose_services_missing")
        optional_profiles = {"otel-collector": ["observability"], "ai-gateway": ["ai"]}
        require(set(self.model["services"]) <= {*SERVICES, *optional_profiles}, "compose_unqualified_services")
        for service_name, service in self.model["services"].items():
            if service_name in optional_profiles:
                require(
                    service.get("profiles") == optional_profiles[service_name], "compose_optional_profile_unreviewed"
                )
            require(
                not service.get("privileged") and not service.get("network_mode") and not service.get("devices"),
                "compose_host_privilege_unreviewed",
            )
            for port in service.get("ports", []):
                require(port.get("host_ip") == "127.0.0.1", "compose_public_binding_forbidden")
            for mount in service.get("volumes", []):
                if mount.get("type") == "bind":
                    path = canonical(Path(mount["source"]))
                    require(path.is_relative_to(self.root) and path.exists(), "compose_bind_outside_qualified_source")
                elif mount.get("type") == "volume":
                    expected = {
                        "postgres": ("postgres_data", "/var/lib/postgresql/data"),
                        "redis": ("redis_data", "/data"),
                    }
                    require(
                        service_name in expected
                        and (mount.get("source"), mount.get("target")) == expected[service_name],
                        "compose_named_volume_mount_unreviewed",
                    )
                else:
                    require(mount.get("type") == "tmpfs", "compose_mount_type_unreviewed")
        for name in ("postgres_data", "redis_data"):
            volume = self.model["volumes"][name]
            require(
                not volume.get("external")
                and volume["name"] == PROJECT + "_" + name
                and volume.get("driver") in {None, "local"}
                and not volume.get("driver_opts"),
                "compose_volume_scope_unreviewed",
            )
        for name in ("postgres", "redis"):
            require(
                re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", self.model["services"][name]["image"]),
                "stateful_image_not_pinned",
            )

    def canonical_container(self, service: str) -> tuple[str, str]:
        identifier = self.compose("ps", "--all", "--quiet", service).decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", identifier), "canonical_container_id_invalid")
        row = json.loads(self.docker("inspect", identifier, sensitive=True))[0]
        labels = row["Config"]["Labels"]
        require(
            labels.get("com.docker.compose.project") == PROJECT and labels.get("com.docker.compose.service") == service,
            "canonical_container_scope_drift",
        )
        require(
            not row["State"]["Running"] and row["Config"]["Image"] == self.model["services"][service]["image"],
            "canonical_container_started_or_image_drift",
        )
        target = "/data" if service == "redis" else "/var/lib/postgresql/data"
        if service == "redis":
            require(len(row["Mounts"]) == 1, "canonical_extra_mounts_unreviewed")
        else:
            binds = [mount for mount in row["Mounts"] if mount["Type"] == "bind"]
            require(
                len(row["Mounts"]) == 2
                and len(binds) == 1
                and binds[0]["Destination"] == "/docker-entrypoint-initdb.d"
                and binds[0]["Source"] == str(self.root / "infrastructure/containers/postgres-init")
                and binds[0].get("RW") is False,
                "canonical_extra_mounts_unreviewed",
            )
        mounts = [mount for mount in row["Mounts"] if mount["Destination"] == target]
        expected = PROJECT + ("_redis_data" if service == "redis" else "_postgres_data")
        require(
            len(mounts) == 1 and mounts[0]["Type"] == "volume" and mounts[0]["Name"] == expected,
            "canonical_volume_binding_drift",
        )
        volume = json.loads(self.docker("volume", "inspect", expected))[0]
        require(volume.get("Driver") == "local" and not volume.get("Options"), "canonical_volume_driver_unreviewed")
        require(
            volume.get("Labels", {}).get("com.docker.compose.project") == PROJECT
            and volume.get("Labels", {}).get("com.docker.compose.volume") == service + "_data",
            "canonical_volume_labels_unreviewed",
        )
        mountpoint = canonical(Path(volume["Mountpoint"]))
        require(
            mountpoint.is_relative_to(Path(self.engine["root"]) / "volumes") and not any(mountpoint.iterdir()),
            "new_volume_not_empty_or_bound",
        )
        self.containers[service] = identifier
        return identifier, expected

    def helper(
        self,
        kind: str,
        service: str,
        volume: str,
        *,
        extra: list[str],
        arguments: list[str],
        env: dict[str, str] | None = None,
    ) -> str:
        image = self.model["services"][service]["image"]
        destination = "/data" if service == "redis" else "/var/lib/postgresql/data"
        name = "kp-offhost-" + kind + "-" + self.suffix
        identifier = (
            self.docker(
                "create",
                "--name",
                name,
                "--network",
                "none",
                "--label",
                "kp.offhost.run=" + self.run_id,
                "--label",
                "kp.offhost.kind=" + kind,
                "--mount",
                f"type=volume,source={volume},target={destination}",
                *extra,
                image,
                *arguments,
                env=env or {},
                sensitive=True,
            )
            .decode()
            .strip()
        )
        require(re.fullmatch(r"[0-9a-f]{64}", identifier), "helper_id_invalid")
        row = json.loads(self.docker("inspect", identifier, sensitive=True))[0]
        require(
            row["Id"] == identifier and row["Name"] == "/" + name and row["Config"]["Image"] == image,
            "helper_identity_drift",
        )
        require(
            row["Config"]["Labels"].get("kp.offhost.run") == self.run_id and row["HostConfig"]["NetworkMode"] == "none",
            "helper_scope_or_network_drift",
        )
        require(
            len(row["Mounts"]) == 1
            and row["Mounts"][0]["Type"] == "volume"
            and row["Mounts"][0]["Name"] == volume
            and row["Mounts"][0]["Destination"] == destination,
            "helper_volume_drift",
        )
        return identifier

    def wait(self, operation: Any, *, seconds: float = 90, accept_empty: bool = False) -> Any:
        end = min(self.deadline - 5, time.time() + seconds)
        while time.time() < end:
            try:
                result = operation()
            except RecoveryError as error:
                if str(error) != "command_failed":
                    raise
                result = None
            if result or (accept_empty and result is not None):
                return result
            time.sleep(1)
        raise RecoveryError("target_readiness_deadline")

    def pg_json(self, identifier: str, sql: str) -> Any:
        raw = self.docker(
            "exec",
            identifier,
            "psql",
            "-X",
            "-U",
            "kingphisher",
            "-d",
            "kingphisher",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
            sensitive=True,
        )
        return json.loads(raw)

    def restore_postgres(self, volume: str) -> None:
        environment = self.model["services"]["postgres"]["environment"]
        require(
            environment["POSTGRES_USER"] == "kingphisher" and environment["POSTGRES_DB"] == "kingphisher",
            "postgres_bootstrap_identity_unreviewed",
        )
        helper = self.helper(
            "postgres-restore",
            "postgres",
            volume,
            extra=["--env", "POSTGRES_USER", "--env", "POSTGRES_DB", "--env", "POSTGRES_PASSWORD"],
            arguments=[],
            env={key: environment[key] for key in ("POSTGRES_USER", "POSTGRES_DB", "POSTGRES_PASSWORD")},
        )
        self.docker("start", helper)
        self.wait(lambda: self.pg_json(helper, "SELECT 1") == 1)
        roles = self.pg_json(
            helper,
            "SELECT coalesce(json_agg(rolname ORDER BY rolname),'[]') FROM pg_roles WHERE rolname NOT LIKE 'pg_%'",
        )
        require(roles == ["kingphisher"], "postgres_bootstrap_has_extra_roles")
        tables = self.pg_json(helper, "SELECT count(*) FROM pg_tables WHERE schemaname='public'")
        require(tables == 0, "postgres_restore_database_not_empty")
        raw = private_file(self.snapshot / "globals.sql").read_bytes()
        filtered = globals_without_bootstrap_role(raw)
        self.docker(
            "exec",
            "-i",
            helper,
            "psql",
            "-X",
            "-U",
            "kingphisher",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            data=filtered,
            sensitive=True,
        )
        self.docker(
            "exec",
            "-i",
            helper,
            "pg_restore",
            "-U",
            "kingphisher",
            "-d",
            "kingphisher",
            "--exit-on-error",
            "--single-transaction",
            data=private_file(self.snapshot / "postgres.dump").read_bytes(),
            limit=300,
            sensitive=True,
        )
        private_json(
            self.output / "postgres-restore.json",
            {
                "helper_id": helper,
                "volume": volume,
                "globals_sha256": hashlib.sha256(raw).hexdigest(),
                "filtered_sha256": hashlib.sha256(filtered).hexdigest(),
                "only_bootstrap_create_role_omitted": True,
            },
        )
        self.docker("stop", "--time", "30", helper)
        require(
            not json.loads(self.docker("inspect", helper, sensitive=True))[0]["State"]["Running"],
            "postgres_helper_not_stopped",
        )
        self.docker("start", self.containers["postgres"])
        self.wait(lambda: self.pg_json(self.containers["postgres"], "SELECT 1") == 1)

    def redis_cli(self, helper: str, *args: str) -> bytes:
        return self.docker("exec", helper, "redis-cli", "-s", CONTAINER_SOCKET, "--raw", *args)

    def restore_redis(self, volume: str) -> None:
        permissions = self.helper(
            "redis-permissions",
            "redis",
            volume,
            extra=["--user", "0:0", "--entrypoint", "/bin/sh"],
            arguments=["-ec", "chown -R 999:999 /data; chmod 700 /data; chmod 600 /data/dump.rdb"],
        )
        self.docker(
            "cp", str(private_file(self.snapshot / "redis.rdb")), permissions + ":/data/dump.rdb", sensitive=True
        )
        self.docker("start", "--attach", permissions)
        permission_state = json.loads(self.docker("inspect", permissions, sensitive=True))[0]["State"]
        require(not permission_state["Running"] and permission_state["ExitCode"] == 0, "redis_permission_helper_failed")
        helper = self.helper(
            "redis-materializer",
            "redis",
            volume,
            extra=[
                "--user",
                "999:999",
                "--read-only",
                "--tmpfs",
                CONTAINER_TMPFS,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--pids-limit",
                "128",
            ],
            arguments=[
                "redis-server",
                "--dir",
                "/data",
                "--appendonly",
                "no",
                "--save",
                "",
                "--port",
                "0",
                "--unixsocket",
                CONTAINER_SOCKET,
                "--unixsocketperm",
                "700",
            ],
        )
        self.docker("start", helper)
        self.wait(lambda: self.redis_cli(helper, "PING").strip() == b"PONG")
        require(
            self.redis_cli(helper, "CONFIG", "SET", "appendonly", "yes").strip() == b"OK", "redis_aof_enable_failed"
        )

        def durable() -> bool:
            raw = self.redis_cli(helper, "INFO", "persistence").decode()
            info = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)
            return (
                info.get("aof_enabled") == "1"
                and info.get("aof_rewrite_in_progress") == "0"
                and info.get("aof_last_bgrewrite_status") == "ok"
                and int(info.get("aof_current_size", "0")) > 0
            )

        self.wait(durable)
        self.docker("stop", "--time", "30", helper)
        require(
            not json.loads(self.docker("inspect", helper, sensitive=True))[0]["State"]["Running"],
            "redis_helper_not_stopped",
        )
        self.docker("start", self.containers["redis"])
        private_json(
            self.output / "redis-materialization.json",
            {
                "permission_helper_id": permissions,
                "materializer_id": helper,
                "volume": volume,
                "aof_materialized": True,
                "all_helpers_retained": True,
            },
        )

    def verify_restored_state(self) -> None:
        from artifacts import validate_snapshot
        from source_capture import read_database_state, read_redis_inventory

        require(
            validate_snapshot(self.snapshot, deadline=self.deadline) == self.manifest, "snapshot_changed_before_startup"
        )
        verify_source(self.root, self.request["source_git_manifest"], canonical_modes=True)
        for name, item in self.restored_files.items():
            require(sha256(self.root / name) == item["restored_sha256"], "restored_private_file_drift_before_startup")
        expected = self.manifest["data"]["database"]
        database = read_database_state(
            self.root, deadline=self.deadline, evidence=self.output, sentinel=expected["sentinel"]
        )
        require(database == expected, "restored_database_counts_audit_ciphertext_or_sentinel_drift")
        inventory_file = self.manifest["data"]["redis"]["inventory"]
        require(inventory_file == "redis-inventory.json", "redis_inventory_scope_invalid")
        before = read_json(self.snapshot / inventory_file)
        after = self.wait(
            lambda: read_redis_inventory(self.root, deadline=self.deadline, evidence=self.output), accept_empty=True
        )
        compare_redis(before, after, now_ms=int(time.time() * 1000))
        maintenance = self.app_python(MAINTENANCE_PROBE, data=json.dumps(self.manifest["data"]["redis"]).encode())
        require(
            maintenance["ready_exact"] is True and maintenance["matching_queued"] == 1,
            "captured_maintenance_not_present_before_startup",
        )
        require(maintenance["redis_sentinel"] is True, "redis_acknowledged_sentinel_missing")
        self.prior_maintenance = maintenance
        # Private evidence is digests/counts only, never data keys or SQL dumps.
        private_json(
            self.output / "before-startup.json",
            {
                "database": database,
                "redis_keys": len(after),
                "redis_logical_inventory_verified": True,
                "maintenance": maintenance,
                "protected_fingerprints": purpose_fingerprints(self.config),
            },
        )

    def install(self) -> None:
        remaining(self.deadline, reserve=60)
        unit = "kp-offhost-restore-" + self.suffix
        self.call(
            [
                "systemd-run",
                "--unit",
                unit,
                "--service-type",
                "oneshot",
                "--remain-after-exit",
                "--no-block",
                "--property",
                "User=" + self.user.pw_name,
                "--property",
                "KillMode=control-group",
                "--property",
                "WorkingDirectory=" + str(self.root),
                "--property",
                "TimeoutStartSec=" + str(int(min(900, remaining(self.deadline, reserve=45)))),
                "--property",
                "TimeoutStopSec=45",
                "--property",
                "Environment="
                + " ".join(
                    key + "=" + self.env[key]
                    for key in (
                        "HOME",
                        "USER",
                        "LOGNAME",
                        "PATH",
                        "DOCKER_HOST",
                        "COMPOSE_PROJECT_NAME",
                        "PYTHONDONTWRITEBYTECODE",
                    )
                ),
                "/bin/bash",
                str(self.root / "scripts/install.sh"),
                "--skip-deps",
            ]
        )

        def installed() -> bool:
            status = self.call(["systemctl", "show", unit, "--property", "SubState", "--value"]).decode().strip()
            require(status not in {"failed", "dead"}, "installer_unit_failed")
            if status != "exited":
                return False
            require(
                self.call(["systemctl", "show", unit, "--property", "ExecMainStatus", "--value"]).strip() == b"0",
                "installer_exit_nonzero",
            )
            return True

        self.wait(installed, seconds=900)
        self.call(
            ["runuser", "-u", self.user.pw_name, "--", "/bin/bash", str(self.root / "scripts/verify_install.sh")],
            limit=120,
        )
        private_json(
            self.output / "installer.json",
            {
                "unit": unit,
                "app_user": self.user.pw_name,
                "skip_deps": True,
                "actual_installer_and_verifier_passed": True,
            },
        )

    def runtime_proof(self) -> dict[str, Any]:
        from source_capture import read_database_state

        for port in (8000, 8001):
            result = self.call(
                [
                    "curl",
                    "--noproxy",
                    "*",
                    "--connect-timeout",
                    "2",
                    "--max-time",
                    "5",
                    "-fsS",
                    f"http://127.0.0.1:{port}/readyz",
                ]
            )
            require(bool(result), "readiness_response_missing")
        expected_ui = self.root / "apps/operator-ui/src/console/app.js"
        actual_ui = self.call(
            [
                "curl",
                "--noproxy",
                "*",
                "--connect-timeout",
                "2",
                "--max-time",
                "5",
                "-fsS",
                "http://127.0.0.1:8000/console/app.js",
            ]
        )
        require(hashlib.sha256(actual_ui).hexdigest() == sha256(expected_ui), "served_ui_not_qualified_bytes")
        children = validate_process_bindings(self.root, uid=self.user.pw_uid)

        def consumed() -> Any:
            value = self.app_python(MAINTENANCE_PROBE, data=json.dumps(self.manifest["data"]["redis"]).encode())
            heartbeat = value.get("heartbeat_epoch")
            before = self.prior_maintenance.get("heartbeat_epoch")
            if value["matching_queued"] or value["matching_failed"]:
                require(not value["matching_failed"], "maintenance_failed_or_dead_lettered")
                return None
            return (
                value
                if isinstance(heartbeat, (int, float))
                and heartbeat >= self.application_started
                and (before is None or heartbeat > before)
                else None
            )

        maintenance = self.wait(consumed, seconds=120)
        prefix = self.app_python(
            AUDIT_PREFIX_PROBE, data=json.dumps(self.manifest["data"]["database"]["audit"]).encode()
        )
        require(prefix.get("verified") is True, "audit_prefix_not_preserved")
        final_database = read_database_state(
            self.root,
            deadline=self.deadline,
            evidence=self.output,
            sentinel=self.manifest["data"]["database"]["sentinel"],
        )
        require(final_database["schema_head"] == self.app["schema_head"], "runtime_schema_head_drift")
        require(
            final_database["ciphertexts"] == self.manifest["data"]["database"]["ciphertexts"],
            "runtime_ciphertext_decryption_drift",
        )
        require(
            final_database["sentinel"] == self.manifest["data"]["database"]["sentinel"], "runtime_pg_sentinel_drift"
        )
        final_config = self.app_python(CONFIG_PROBE, sensitive=True)
        require(
            purpose_fingerprints(final_config) == self.manifest["data"]["protected_purposes"],
            "runtime_protected_purposes_drift",
        )
        return {
            "readiness_endpoints": 2,
            "exact_ui_sha256": sha256(expected_ui),
            "native_children": children,
            "maintenance": maintenance,
            "audit_prefix": prefix,
            "schema_head": final_database["schema_head"],
        }

    def run(self) -> dict[str, Any]:
        self.fresh()
        self.prepare_source()
        self.decrypt()
        self.restore_files()
        self.configure_compose()
        # Qualify pinned images with the production gate before any canonical
        # resource creation. It never attaches a preserved Compose volume.
        self.call(
            [
                "runuser",
                "-u",
                self.user.pw_name,
                "--",
                "/bin/bash",
                str(self.root / "scripts/operator/base-image-qualification/run.sh"),
                "--timeout-seconds",
                "300",
            ],
            limit=900,
        )
        self.compose("create", "--no-build", "postgres", "redis", limit=300, sensitive=True)
        _postgres, pg_volume = self.canonical_container("postgres")
        _redis, redis_volume = self.canonical_container("redis")
        self.restore_postgres(pg_volume)
        self.restore_redis(redis_volume)
        self.verify_restored_state()
        private_json(
            self.output / "startup-authorized.json", {"all_pre_startup_data_checks_passed": True, "at": time.time()}
        )
        self.application_started = time.time()
        self.install()
        proof = self.runtime_proof()
        private_json(self.output / "runtime-proof.json", proof)
        result = {
            "schema": "kp.offhost-recovery.target-result.v1",
            "run_id": self.run_id,
            "passed": True,
            "scope": "synthetic-qualification",
            "application": self.app,
            "source_deallocated_controller_attestation": self.request["source_deallocated"],
            "restore_only_rto_seconds": round(time.time() - self.started, 3),
            "missing_acknowledged_sentinels": 0,
            "native_child_count": len(proof["native_children"]),
            "maintenance_consumed_with_fresh_anchor_heartbeat": True,
            "audit_prefix_verified": True,
            "cipher_sha256": self.request["expected_cipher_sha256"],
            "evidence": str(self.output),
            "all_target_assets_retained": True,
        }
        private_json(self.output / "result.json", result)
        return result


def restore(request: dict[str, Any]) -> dict[str, Any]:
    return Target(request).run()


CONFIG_PROBE = """import json,pathlib,sys
from dotenv import dotenv_values
print(json.dumps(dict(dotenv_values(pathlib.Path(sys.argv[1])/'.env'))))
"""

OVERRIDE_PROBE = """import sys,yaml
old,new=sys.argv[1:3]
document=yaml.safe_load(sys.stdin.buffer.read())
assert isinstance(document,dict) and set(document)<= {'services','volumes','name','networks'}
def path(value):
    if isinstance(value,str) and (value==old or value.startswith(old+'/')): return new+value[len(old):]
    if isinstance(value,str):
        candidate=value.split(':',1)[0]
        assert '..' not in candidate.split('/')
        assert not candidate.startswith('/') or candidate==new or candidate.startswith(new+'/')
    return value
for service in document.get('services',{}).values():
    assert isinstance(service,dict)
    for key in ('env_file','volumes'):
        values=service.get(key,[])
        if isinstance(values,str): values=[values]
        assert isinstance(values,list)
        for index,value in enumerate(values):
            if isinstance(value,str): values[index]=path(value)
            elif isinstance(value,dict) and key=='volumes': value['source']=path(value.get('source'))
            else: raise ValueError('unsupported_override_path')
        if key in service: service[key]=values
    build=service.get('build')
    if isinstance(build,str): service['build']=path(build)
    elif isinstance(build,dict) and 'context' in build: build['context']=path(build['context'])
    for key,value in service.get('environment',{}).items():
        if key.endswith(('_PATH','_FILE','_DIR')): service['environment'][key]=path(value)
output=yaml.safe_dump(document,sort_keys=True)
assert old not in output
sys.stdout.write(output)
"""

MAINTENANCE_PROBE = """import hashlib,json,pathlib,sys
from datetime import datetime
from dotenv import dotenv_values
import redis
root=pathlib.Path(sys.argv[1]); expected=json.load(sys.stdin)
values=dotenv_values(root/'.env')
client=redis.Redis.from_url(values['REDIS_URL'],socket_timeout=5,socket_connect_timeout=5)
job=expected['maintenance']
assert job['topic']=='audit-anchor' and job['acknowledgment'] is True and job['payload']=={}
ready=job['ready_key']; assert ready=='kp:queue:{audit-anchor}'
queued=failed=0; ready_exact=False
pools=((ready,'ready'),(ready+':processing','processing'),(ready+':delayed','delayed'),(ready+':dlq','failed'))
for name,kind in pools:
    raws=client.zrange(name,0,10000) if kind=='delayed' else client.lrange(name,0,10000)
    assert len(raws)<=10000
    assert sum(map(len,raws))<=16*1024**2
    for raw in raws:
        message=json.loads(raw)
        if message.get('id')==job['id']:
            assert message.get('idempotency_key')==job['idempotency_key'] and message.get('payload')=={}
            if kind=='failed': failed+=1
            else: queued+=1
            if kind=='ready': ready_exact=hashlib.sha256(raw).hexdigest()==job['envelope_sha256']
heartbeat=client.get('kp:audit:last_successful_anchor_at')
parsed=datetime.fromisoformat(heartbeat.decode()) if heartbeat else None
assert parsed is None or parsed.tzinfo is not None
epoch=parsed.timestamp() if parsed else None
sentinel=expected['sentinel']; value=client.get(sentinel['key'])
print(json.dumps({'matching_queued':queued,'matching_failed':failed,'ready_exact':ready_exact,
                  'heartbeat_epoch':epoch,'redis_sentinel':value==sentinel['value'].encode()}))
"""

AUDIT_PREFIX_PROBE = """import json,os,pathlib,sys
from dotenv import dotenv_values,load_dotenv
from kp_database.audit_store import AuditStore
from kp_database.session import create_db_engine
root=pathlib.Path(sys.argv[1]); expected=json.load(sys.stdin)
load_dotenv(root/'.env',override=True); values=dotenv_values(root/'.env')
store=AuditStore(create_db_engine(values['AUDIT_DATABASE_URL']),hmac_key=bytes.fromhex(values['OPERATOR_API_AUDIT_HMAC_KEY']))
assert not store.verify()
actual=store.hashes_by_sequence({expected['sequence']})
assert actual[expected['sequence']]==expected['event_hash']
print(json.dumps({'verified':True,'sequence':expected['sequence'],'event_hash':expected['event_hash']}))
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--execute-after-review", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute_after_review:
        print(
            json.dumps(
                {
                    "plan_only": True,
                    "scope": "synthetic-qualification",
                    "commands": 0,
                    "restores": False,
                    "preserves_all_assets": True,
                }
            )
        )
        return 0
    os.umask(0o077)
    try:
        request = read_json(private_file(args.request))
        print(json.dumps(restore(request), sort_keys=True))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, RecoveryError) else "target_restore_unexpected_failure"
        print(json.dumps({"passed": False, "reason": code, "all_partial_assets_preserved": True}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
