"""Only additive task resources on the exact reviewed native WSL2 engine."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from evidence import Evidence, QualificationFailure, loopback_url
from sqlalchemy.engine import URL

LABEL = "kp.fullstack.qualification"
SUBNET = ipaddress.ip_network("10.254.247.0/28")
REVIEWED_SUBNET_POOL = ipaddress.IPv4Network("10.254.247.0/24")
IMAGES = {
    "postgres": "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777",
    "redis": "redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2",
    "mailpit": "axllent/mailpit:v1.20@sha256:7eef0f38dbc85e4e264f2edf5d70fbb694826791e05cb2cae4fc9e3282f968f5",
}


def clean_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "KP_DISABLE_DOTENV": "1",
        "PYTHONUNBUFFERED": "1",
    }


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class Stack:
    def __init__(self, evidence: Evidence, source: Path, hostname: str, engine_id: str, subnet: str = str(SUBNET)):
        self.evidence, self.source = evidence, source.resolve()
        if evidence.root.is_relative_to(self.source):
            raise QualificationFailure("qualification evidence must be outside the staged source")
        selected = ipaddress.ip_network(subnet, strict=True)
        if (
            not isinstance(selected, ipaddress.IPv4Network)
            or selected.prefixlen != 28
            or not selected.subnet_of(REVIEWED_SUBNET_POOL)
        ):
            raise QualificationFailure("qualification subnet must be a canonical/28 inside reviewed10.254.247.0/24")
        self.subnet = selected
        self.evidence.json("network-profile.json", {"subnet": str(selected), "pool": str(REVIEWED_SUBNET_POOL)})
        self.hostname, self.engine_id = hostname, engine_id
        self.network = f"kp-fullstack-{evidence.run_id}"
        self.resources: dict[str, dict[str, Any]] = {}
        self.processes: dict[str, tuple[subprocess.Popen[bytes], str]] = {}
        self.environment = clean_environment()
        source_paths = [
            str(path.resolve())
            for group in ("packages", "apps")
            for path in sorted((self.source / group).glob("*/src"))
            if not path.is_symlink()
        ]
        if not source_paths:
            raise QualificationFailure("staged application source is unavailable")
        self.environment["PYTHONPATH"] = os.pathsep.join(source_paths)
        for source_path in reversed(source_paths):
            sys.path.insert(0, source_path)
        self.secrets = {
            name: secrets.token_hex(32)
            for name in (
                "postgres",
                "audit",
                "root",
                "cipher",
                "console",
                "recipient",
                "tracking",
                "training",
                "roe",
                "domain",
                "ledger",
                "import",
            )
        }
        self.passwords: dict[str, str] = {}
        self.urls: dict[str, str] = {}
        self.api_ports = {name: free_port() for name in ("operator", "tracking", "smtp")}
        self.evidence.json("private-secrets.json", self.secrets)

    def command(self, arguments: list[str], *, input: bytes | None = None, maximum: int = 60) -> bytes:
        result = subprocess.run(  # noqa: S603 - fixed native CLI and reviewed run-owned arguments
            arguments,
            input=input,
            capture_output=True,
            timeout=self.evidence.remaining(maximum),
            env=self.environment,
            check=False,
        )
        if result.returncode:
            raise QualificationFailure(f"bounded command failed: {Path(arguments[0]).name}")
        return result.stdout

    def docker(self, *arguments: str, input: bytes | None = None, maximum: int = 60) -> bytes:
        return self.command(
            ["docker", "--host", "unix:///var/run/docker.sock", *arguments], input=input, maximum=maximum
        )

    def preflight(self) -> None:
        if platform.system() != "Linux" or "microsoft" not in platform.release().lower():
            raise QualificationFailure("qualification must run inside the reviewed .105 WSL2 host")
        if socket.gethostname() != self.hostname or os.environ.get("DOCKER_CONTEXT"):
            raise QualificationFailure("host identity/context mismatch")
        if os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock") != "unix:///var/run/docker.sock":
            raise QualificationFailure("Docker endpoint mismatch")
        info = json.loads(
            self.docker(
                "info",
                "--format",
                '{"ID":{{json .ID}},"Name":{{json .Name}},'
                '"OSType":{{json .OSType}},"Architecture":{{json .Architecture}},'
                '"DockerRootDir":{{json .DockerRootDir}}}',
            )
        )
        if (
            info.get("ID") != self.engine_id
            or info.get("OSType") != "linux"
            or info.get("Architecture") not in {"x86_64", "amd64"}
        ):
            raise QualificationFailure("native engine identity mismatch")
        if any(word in str(info.get("Name", "")).lower() for word in ("desktop", "colima")):
            raise QualificationFailure("retired or desktop engine refused")
        networks = self.docker("network", "ls", "--format", "{{.ID}}").decode().splitlines()
        for identifier in networks:
            for network in json.loads(self.docker("network", "inspect", identifier)):
                for config in network.get("IPAM", {}).get("Config") or []:
                    if (
                        config.get("Subnet")
                        and ipaddress.ip_network(config["Subnet"]).version == 4
                        and self.subnet.overlaps(ipaddress.ip_network(config["Subnet"]))
                    ):
                        raise QualificationFailure("reviewed qualification subnet is occupied")
        for route in json.loads(self.command(["ip", "-j", "route", "show", "table", "all"])):
            destination = route.get("dst", "default")
            if destination != "default" and self.subnet.overlaps(ipaddress.ip_network(destination, strict=False)):
                raise QualificationFailure("qualification subnet overlaps a host route")
        if shutil.disk_usage(self.evidence.root).free < 5 * 1024**3:
            raise QualificationFailure("less than5GiB free; preserve all assets and stop")
        images = {kind: self.inspect_native_image(image) for kind, image in IMAGES.items()}
        self.evidence.json("images.json", images)
        self.evidence.json(
            "engine.json", {key: info.get(key) for key in ("ID", "Name", "OSType", "Architecture", "DockerRootDir")}
        )
        network_id = (
            self.docker(
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                str(self.subnet),
                "--label",
                f"{LABEL}={self.evidence.run_id}",
                self.network,
            )
            .decode()
            .strip()
        )
        self.evidence.event(
            "network_created",
            id=network_id,
            name=self.network,
            subnet=str(self.subnet),
            driver="bridge",
            internal=False,
        )
        records = json.loads(self.docker("network", "inspect", network_id))
        if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
            raise QualificationFailure("qualification network identity is malformed")
        network = records[0]
        if (
            network.get("Internal") is not False
            or network.get("Driver") != "bridge"
            or (network.get("Labels") or {}).get(LABEL) != self.evidence.run_id
        ):
            raise QualificationFailure("qualification network driver or ownership differs from reviewed bridge")
        self.evidence.json(
            "network.json",
            {
                "id": network_id,
                "name": self.network,
                "subnet": str(self.subnet),
                "driver": network["Driver"],
                "internal": network["Internal"],
                "egress_isolation_claimed": False,
            },
        )

    def inspect_native_image(self, image: str) -> dict[str, Any]:
        records = json.loads(self.docker("image", "inspect", image))
        if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
            raise QualificationFailure("qualification image inspection is malformed")
        record = records[0]
        if record.get("Os") != "linux" or record.get("Architecture") not in {"amd64", "x86_64"}:
            raise QualificationFailure("qualification image must be native linux/amd64")
        return {
            "reference": image,
            "id": record.get("Id"),
            "os": record["Os"],
            "architecture": record["Architecture"],
            "repo_digests": record.get("RepoDigests", []),
        }

    @staticmethod
    def service_bindings(record: dict[str, Any], expected: tuple[int, ...], kind: str) -> dict[int, int]:
        if (record.get("State") or {}).get("Running") is not True:
            raise QualificationFailure(f"qualification service is not running: {kind}")
        published = (record.get("NetworkSettings") or {}).get("Ports")
        if not isinstance(published, dict):
            raise QualificationFailure(f"qualification service has no published loopback ports: {kind}")
        if any(value and key not in {f"{port}/tcp" for port in expected} for key, value in published.items()):
            raise QualificationFailure(f"qualification service exposes an unexpected port: {kind}")
        bindings = {}
        for port in expected:
            values = published.get(f"{port}/tcp")
            if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
                raise QualificationFailure(f"qualification service is missing a required loopback port: {kind}:{port}")
            value = values[0]
            if value.get("HostIp") != "127.0.0.1":
                raise QualificationFailure(f"qualification service port is not explicit IPv4 loopback: {kind}:{port}")
            raw = value.get("HostPort")
            if not isinstance(raw, str) or not raw.isdecimal() or not 1 <= int(raw) <= 65535:
                raise QualificationFailure(f"qualification service has an invalid published port: {kind}:{port}")
            loopback_url(f"http://127.0.0.1:{raw}", {"http"})
            bindings[port] = int(raw)
        return bindings

    def create_services(self, prefix: str) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for kind, ports in (("postgres", (5432,)), ("redis", (6379,)), ("mailpit", (1025, 8025))):
            name = f"{self.network}-{prefix}-{kind}"
            volume = f"{name}-data"
            self.docker("volume", "create", "--label", f"{LABEL}={self.evidence.run_id}", volume)
            target = "/var/lib/postgresql/data" if kind == "postgres" else "/data"
            args = [
                "run",
                "-d",
                "--pull",
                "never",
                "--name",
                name,
                "--label",
                f"{LABEL}={self.evidence.run_id}",
                "--network",
                self.network,
                "--memory",
                "1g",
                "--cpus",
                "2",
                "--pids-limit",
                "256",
                "--mount",
                f"type=volume,src={volume},dst={target}",
            ]
            for port in ports:
                args += ["-p", f"127.0.0.1::{port}"]
            if kind == "postgres":
                env_file = self.evidence.root / f"{prefix}-postgres.env"
                fd = os.open(env_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "w") as stream:
                    stream.write(f"POSTGRES_PASSWORD={self.secrets['postgres']}\nPOSTGRES_DB=qualification\n")
                args += ["--env-file", str(env_file)]
            if kind == "mailpit":
                args += ["-e", "MP_DATABASE=/data/mailpit.db", "-e", "MP_MAX_MESSAGES=20000"]
            args += [IMAGES[kind]]
            if kind == "redis":
                args += ["redis-server", "--appendonly", "yes"]
            identifier = self.docker(*args).decode().strip()
            # Record the new identity before inspecting any readiness/port field,
            # so failed partial runs retain a usable resource inventory.
            result[kind] = {"id": identifier, "name": name, "volume": volume, "ports": {}}
            self.resources[name] = result[kind]
            self.evidence.event("resource_created", **result[kind], expected_ports=ports)
            self.owned(identifier)
            record = json.loads(self.docker("inspect", identifier))[0]
            bindings = self.service_bindings(record, ports, kind)
            result[kind]["ports"] = bindings
            self.evidence.event("resource_ready", **result[kind])
        self.evidence.json(f"{prefix}-resources.json", result)
        return result

    def owned(self, identifier: str) -> None:
        if identifier not in {record["id"] for record in self.resources.values()}:
            raise QualificationFailure("resource is not owned by this run")
        record = json.loads(self.docker("inspect", identifier))[0]
        if record["Config"]["Labels"].get(LABEL) != self.evidence.run_id:
            raise QualificationFailure("resource ownership label mismatch")

    def mutate(self, action: str, identifier: str, *args: str, input: bytes | None = None) -> bytes:
        self.owned(identifier)
        if action not in {"stop", "start", "exec", "cp"}:
            raise QualificationFailure("resource mutation is not allowlisted")
        if action == "cp":
            raise QualificationFailure("copy requires explicit direction helper")
        if action == "stop":
            return self.docker(action, *args, identifier, input=input)
        return self.docker(action, identifier, *args, input=input)

    def connection_urls(self, services: dict[str, Any]) -> URL:
        port = services["postgres"]["ports"][5432]
        base = URL.create(
            "postgresql+psycopg",
            username="postgres",
            password=self.secrets["postgres"],
            host="127.0.0.1",
            port=port,
            database="qualification",
        )
        return base

    def bootstrap(self, services: dict[str, Any]) -> URL:
        from kp_database.grants import RUNTIME_ROLES
        from sqlalchemy import create_engine, text

        base = self.connection_urls(services)
        deadline = time.monotonic() + self.evidence.remaining(120)
        while True:
            try:
                engine = create_engine(base, connect_args={"connect_timeout": 2})
                with engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
                engine.dispose()
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise QualificationFailure("fresh PostgreSQL readiness deadline") from None
                time.sleep(0.5)
        env = dict(
            self.environment,
            DATABASE_URL=base.render_as_string(hide_password=False),
            AUDIT_WRITER_PASSWORD=self.secrets["audit"],
            AUDIT_ROOT_KEY=self.secrets["root"],
            KP_ALEMBIC_INI=str(self.source / "packages/database/alembic.ini"),
        )
        for workload, role in RUNTIME_ROLES.items():
            password = self.passwords.setdefault(workload, secrets.token_hex(24))
            env[f"KP_DB_PASSWORD_{workload.upper().replace('-', '_')}"] = password
            self.urls[workload] = base.set(username=role, password=password).render_as_string(hide_password=False)
        log = self.evidence.root / "bootstrap-private.log"
        with log.open("xb") as stream:
            process = subprocess.run(  # noqa: S603 - current interpreter and reviewed source bootstrap
                [sys.executable, str(self.source / "scripts/azure_migrate.py")],
                env=env,
                cwd=self.source,
                stdout=stream,
                stderr=stream,
                timeout=self.evidence.remaining(180),
                check=False,
            )
        if process.returncode:
            raise QualificationFailure("fresh runtime-role bootstrap failed; inspect private bootstrap log")
        self.evidence.json("private-role-urls.json", self.urls)
        return base

    def spawn(self, name: str, arguments: list[str], environment: dict[str, str]) -> None:
        if name in self.processes:
            raise QualificationFailure("process name is already owned")
        output = (self.evidence.root / f"{name}.log").open("xb")
        process = subprocess.Popen(  # noqa: S603 - fixed application entrypoints in run-owned processes
            arguments, cwd=self.source, env=environment, stdout=output, stderr=output, start_new_session=True
        )
        output.close()
        stamp = self.process_stamp(process.pid)
        self.processes[name] = process, stamp
        self.evidence.event("process_started", name=name, pid=process.pid, start_ticks=stamp)

    @staticmethod
    def process_stamp(pid: int) -> str:
        return Path(f"/proc/{pid}/stat").read_text().split()[21]

    def quiesce(self, only: set[str] | None = None) -> None:
        # Shutdown has its own bounded grace period even after the work deadline.
        # Attempt every owned process; one refusal cannot skip the others.
        shutdown_until = time.monotonic() + 30
        failures = []
        selected = {name: owned for name, owned in self.processes.items() if only is None or name in only}
        signalled = set()
        for name, (process, stamp) in selected.items():
            if process.poll() is not None:
                continue
            try:
                if self.process_stamp(process.pid) != stamp:
                    failures.append(name)
                    continue
                process.terminate()
                signalled.add(name)
            except OSError:
                if process.poll() is None:
                    failures.append(name)
        for name, (process, _stamp) in selected.items():
            if name in signalled:
                try:
                    process.wait(timeout=max(0.01, shutdown_until - time.monotonic()))
                except subprocess.TimeoutExpired:
                    failures.append(name)
            if process.poll() is None:
                continue
            self.evidence.event("process_quiesced", name=name, returncode=process.returncode)
            del self.processes[name]
        if failures:
            raise QualificationFailure("owned process quiescence incomplete; preserve identities and inspect")

    def start_applications(self, services: dict[str, Any], prefix: str) -> dict[str, str]:
        from kp_database.grants import RUNTIME_ROLES

        base = self.connection_urls(services)
        for workload, role in RUNTIME_ROLES.items():
            self.urls[workload] = base.set(username=role, password=self.passwords[workload]).render_as_string(
                hide_password=False
            )
        audit = base.set(username="audit_writer", password=self.secrets["audit"]).render_as_string(hide_password=False)
        redis_url = f"redis://127.0.0.1:{services['redis']['ports'][6379]}/0"
        tracking = f"http://127.0.0.1:{self.api_ports['tracking']}"
        operator = f"http://127.0.0.1:{self.api_ports['operator']}"
        loopback_url(redis_url, {"redis"})
        loopback_url(tracking, {"http"})
        loopback_url(operator, {"http"})
        anchor = self.evidence.root / f"{prefix}-anchor-evidence"
        anchor.mkdir(mode=0o700, exist_ok=True)
        env = dict(
            self.environment,
            KP_PROFILE="local-dev",
            KP_DEV_STACK="0",
            KP_ROE_SIGNING_KEY=self.secrets["roe"],
            TRACKING_TOKEN_HMAC_KEY=self.secrets["tracking"],
            TRAINING_TOKEN_HMAC_KEY=self.secrets["training"],
            KP_ALLOWED_RECIPIENT_DOMAINS="qualification.test",
            OPERATOR_APPROVAL_POLICY="enforce",
        )
        shared = {
            "DATABASE_URL": self.urls["operator"],
            "AUDIT_DATABASE_URL": audit,
            "CIPHERTEXT_KEK": self.secrets["cipher"],
            "REDIS_URL": redis_url,
            "APPROVAL_POLICY": "enforce",
            "TRAINING_DOMAINS": "qualification.test,127.0.0.1",
            "AWARENESS_PSEUDONYM_KEY": self.secrets["ledger"],
            "AWARENESS_PSEUDONYM_KEY_VERSION": "qualification-v1",
        }
        for key, value in shared.items():
            env[f"OPERATOR_API_{key}"] = value
            env[f"KP_WORKER_{key}"] = value
        env.update(
            OPERATOR_API_CONSOLE_JWT_SECRET=self.secrets["console"],
            OPERATOR_API_DOMAIN_VERIFICATION_KEY=self.secrets["domain"],
            OPERATOR_API_RECIPIENT_IMPORT_DIGEST_KEY=self.secrets["import"],
            OPERATOR_API_RECIPIENT_HASH_SALT=self.secrets["recipient"],
            OPERATOR_API_TRACKING_BASE_URL=tracking,
            OPERATOR_API_TRAINING_BASE_URL=f"{tracking}/v1/training/awareness",
            OPERATOR_API_OIDC_REDIRECT_URI=f"{operator}/api/v1/console/oidc/callback",
            OPERATOR_API_CONFIG_STORE="env_file",
            OPERATOR_API_OIDC_MODE="dev",
            OPERATOR_API_RATE_LIMIT_USER_PER_MIN="10000",
            OPERATOR_API_RATE_LIMIT_IP_PER_MIN="20000",
            OPERATOR_API_AGGREGATION_SCHEDULER_ENABLED="false",
            OPERATOR_API_ENV_FILE=str(self.evidence.root / "unused-private.env"),
            TRACKING_API_DATABASE_URL=self.urls["tracking"],
            TRACKING_API_REDIS_URL=redis_url,
            TRACKING_API_RATE_LIMIT_BACKEND="redis",
            TRACKING_API_RATE_LIMIT_IP_PER_MIN="20000",
            TRACKING_API_RATE_LIMIT_GLOBAL_PER_MIN="30000",
            TRACKING_API_RATE_LIMIT_TOKEN_PER_MIN=str(20),
            TRACKING_API_TRAINING_BASE_URL=f"{tracking}/v1/training/awareness",
            KP_WORKER_AUDIT_ANCHOR_PROVIDER="local_worm",
            KP_WORKER_AUDIT_ANCHOR_LOCAL_DIR=str(anchor),
            KP_WORKER_AUDIT_ANCHOR_INTERVAL_SECONDS="60",
            KP_WORKER_RETENTION_INTERVAL_SECONDS="60",
            KP_WORKER_QUEUE_RECONCILE_ENABLED="true",
            KP_WORKER_QUEUE_RECONCILE_INTERVAL_SECONDS="30",
            KP_WORKER_SMTP_ADDRESS=f"127.0.0.1:{self.api_ports['smtp']}",
            KP_WORKER_MAILPIT_SMTP=f"127.0.0.1:{self.api_ports['smtp']}",
            KP_WORKER_MAILPIT_API_URL=f"http://127.0.0.1:{services['mailpit']['ports'][8025]}",
            KP_WORKER_SMTP_SENDER="training@qualification.test",
            KP_WORKER_SENDING_DOMAINS="qualification.test",
            KP_WORKER_TRACKING_BASE_URL=tracking,
            KP_WORKER_TRAINING_BASE_URL=f"{tracking}/v1/training/awareness",
            KP_WORKER_POLL_SECONDS="1",
            KP_WORKER_PROVIDER_TIMEOUT_SECONDS="10",
            KP_WORKER_RECIPIENT_HASH_SALT=self.secrets["recipient"],
        )
        for workload in RUNTIME_ROLES:
            env[f"KP_WORKER_DATABASE_URL_{workload.upper().replace('-', '_')}"] = self.urls[workload]
        self.evidence.json(f"{prefix}-private-application-environment.json", env)
        control = self.evidence.root / "smtp-mode"
        if not control.exists():
            control.write_text("pass")
        script = Path(__file__).resolve().parent / "smtp_proxy.py"
        self.spawn(
            f"{prefix}-smtp",
            [
                sys.executable,
                str(script),
                "--port",
                str(self.api_ports["smtp"]),
                "--upstream-port",
                str(services["mailpit"]["ports"][1025]),
                "--control",
                str(control),
                "--journal",
                str(self.evidence.root / "smtp-journal.jsonl"),
            ],
            self.environment,
        )
        for name, module in (("operator", "kp_operator_api.main:app"), ("tracking", "kp_tracking_api.main:app")):
            shared_names = {
                "KP_PROFILE",
                "KP_DEV_STACK",
                "KP_ROE_SIGNING_KEY",
                "KP_ALLOWED_RECIPIENT_DOMAINS",
                "OPERATOR_APPROVAL_POLICY",
                "TRACKING_TOKEN_HMAC_KEY",
                "TRAINING_TOKEN_HMAC_KEY",
            }
            application_prefix = "OPERATOR_API_" if name == "operator" else "TRACKING_API_"
            application_env = {
                key: value
                for key, value in env.items()
                if key in self.environment or key in shared_names or key.startswith(application_prefix)
            }
            self.spawn(
                f"{prefix}-{name}",
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    module,
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(self.api_ports[name]),
                    "--no-access-log",
                ],
                application_env,
            )
        for role in ("delivery", "retention", "audit-anchor"):
            role_key = f"KP_WORKER_DATABASE_URL_{role.upper().replace('-', '_')}"
            role_env = {
                key: value
                for key, value in env.items()
                if key in self.environment or key in shared_names or key.startswith("KP_WORKER_")
            }
            role_env = {
                key: value
                for key, value in role_env.items()
                if not key.startswith("KP_WORKER_DATABASE_URL_") or key == role_key
            }
            role_env.update(KP_WORKER_ROLES=role, KP_WORKER_DATABASE_URL=self.urls[role])
            if role == "audit-anchor":
                role_env["KP_WORKER_AUDIT_DATABASE_URL"] = self.urls[role]
            self.spawn(f"{prefix}-worker-{role}", [sys.executable, "-m", "kp_workers", "supervise"], role_env)
        return {
            "operator": operator,
            "tracking": tracking,
            "redis": redis_url,
            "mailpit": f"http://127.0.0.1:{services['mailpit']['ports'][8025]}",
        }

    def load_recovered_configuration(self, directory: Path) -> dict[str, Any]:
        """Rehydrate only verified, exclusively copied synthetic checkpoint files."""
        from kp_database.grants import RUNTIME_ROLES
        from sqlalchemy.engine import make_url

        self.secrets, self.passwords, self.urls = {}, {}, {}
        loaded = json.loads((directory / "private-secrets.json").read_text())
        required = {
            "postgres",
            "audit",
            "root",
            "cipher",
            "console",
            "recipient",
            "tracking",
            "training",
            "roe",
            "domain",
            "ledger",
            "import",
        }
        if set(loaded) != required or any(
            not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value) for value in loaded.values()
        ):
            raise QualificationFailure("recovered synthetic key configuration is malformed")
        self.secrets = loaded
        role_urls = json.loads((directory / "private-role-urls.json").read_text())
        if set(role_urls) != set(RUNTIME_ROLES):
            raise QualificationFailure("recovered runtime-role configuration is incomplete")
        for workload, raw in role_urls.items():
            parsed = make_url(raw)
            if parsed.username != RUNTIME_ROLES[workload] or not parsed.password:
                raise QualificationFailure("recovered runtime-role identity is malformed")
            self.passwords[workload] = parsed.password
        app: dict[str, Any] = json.loads((directory / "source-private-application-environment.json").read_text())
        operator = urlsplit(app["OPERATOR_API_OIDC_REDIRECT_URI"])
        tracking = urlsplit(app["OPERATOR_API_TRACKING_BASE_URL"])
        smtp = urlsplit("smtp://" + app["KP_WORKER_SMTP_ADDRESS"])
        if any(endpoint.hostname != "127.0.0.1" or not endpoint.port for endpoint in (operator, tracking, smtp)):
            raise QualificationFailure("recovered endpoint identity is malformed")
        self.api_ports = {
            "operator": int(operator.port or 0),
            "tracking": int(tracking.port or 0),
            "smtp": int(smtp.port or 0),
        }
        return app
