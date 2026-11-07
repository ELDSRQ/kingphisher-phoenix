"""Hermetic preservation, evidence and SMTP protocol qualification checks."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/operator/fullstack-qualification"))
from campaign import Campaigns
from evidence import Evidence, Profile, QualificationFailure, loopback_url, percentile
from run import source_manifest
from smtp_proxy import Handler, address
from stack import IMAGES, Stack


@pytest.fixture
def restarted_services(tmp_path, monkeypatch):
    from kp_database.grants import RUNTIME_ROLES

    root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr("stack.free_port", lambda: 33333)
    evidence = Evidence(tmp_path / "run", "synthetic", Profile())
    stack = Stack(evidence, root, "host", "engine")
    stack.passwords = {workload: "synthetic-role-only" for workload in RUNTIME_ROLES}
    services = {"postgres": {"id": "owned-pg", "ports": {5432: 35432}}}
    records, mutations = {}, []
    for kind, ports in (("redis", {6379: 36400}), ("mailpit", {1025: 36401, 8025: 36402})):
        name = f"{stack.network}-restored-{kind}"
        services[kind] = {"id": f"owned-{kind}", "name": name, "volume": f"{name}-data", "ports": ports}
        stack.resources[name] = services[kind]
        records[services[kind]["id"]] = {
            "Id": services[kind]["id"],
            "Name": f"/{name}",
            "Config": {"Labels": {"kp.fullstack.qualification": "synthetic"}, "Image": IMAGES[kind]},
            "Image": f"sha256:synthetic-{kind}",
            "State": {"Running": True},
            "Mounts": [{"Type": "volume", "Name": services[kind]["volume"], "Destination": "/data"}],
            "NetworkSettings": {
                "Ports": {
                    f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host)}] for port, host in ports.items()
                }
            },
        }
    initial = evidence.json("restored-resources.json", services).read_bytes()

    def docker(*args, **kwargs):
        if args[0] == "inspect":
            return json.dumps([records[args[1]]]).encode()
        mutations.append((args, kwargs))
        if args[0] == "stop":
            records[args[-1]]["State"]["Running"] = False
        elif args[0] == "start":
            record = records[args[1]]
            record["State"]["Running"] = True
            for bindings in record["NetworkSettings"]["Ports"].values():
                bindings[0]["HostPort"] = str(int(bindings[0]["HostPort"]) + 100)
        elif args[0] == "cp":
            assert args[1] == "-" and kwargs["input"] == b"preserved synthetic snapshot"
        else:
            raise AssertionError(args)
        return b""

    monkeypatch.setattr(stack, "docker", docker)
    return SimpleNamespace(stack=stack, services=services, records=records, mutations=mutations, initial=initial)


def test_restarted_bindings_reach_cache_app_and_proxy_urls_without_replacing_resources(restarted_services, monkeypatch):
    from recovery import restart_restored_service, verify_restored_redis

    value = restarted_services
    original = copy.deepcopy(value.services)
    for kind in ("redis", "mailpit"):
        restart_restored_service(value.stack, value.services, kind, b"preserved synthetic snapshot")
    cache_urls, closed = [], []

    class Cache:
        def get(self, key):
            assert key == "kp:qualification:acknowledged-sentinel"
            return b"acknowledged"

        def close(self):
            closed.append(True)

    def restored_cache(url, **kwargs):
        cache_urls.append(url)
        assert url == "redis://127.0.0.1:36500/0"  # old cached36400 must never be used
        assert kwargs == {"socket_timeout": 3, "socket_connect_timeout": 3}
        return Cache()

    monkeypatch.setattr("recovery.redis.Redis.from_url", restored_cache)
    verify_restored_redis(value.stack, value.services, "acknowledged")
    assert cache_urls == ["redis://127.0.0.1:36500/0"] and closed == [True]
    captured = {}
    monkeypatch.setattr(value.stack, "spawn", lambda name, args, env: captured.setdefault(name, (args, env)))
    endpoints = value.stack.start_applications(value.services, "restored")
    assert endpoints["redis"] == "redis://127.0.0.1:36500/0"
    assert endpoints["mailpit"] == "http://127.0.0.1:36502"
    assert captured["restored-operator"][1]["OPERATOR_API_REDIS_URL"] == endpoints["redis"]
    assert captured["restored-tracking"][1]["TRACKING_API_REDIS_URL"] == endpoints["redis"]
    assert captured["restored-worker-delivery"][1]["KP_WORKER_REDIS_URL"] == endpoints["redis"]
    assert captured["restored-worker-delivery"][1]["KP_WORKER_MAILPIT_API_URL"] == endpoints["mailpit"]
    proxy = captured["restored-smtp"][0]
    assert proxy[proxy.index("--upstream-port") + 1] == "36501"
    for kind in ("redis", "mailpit"):
        assert {key: value.services[kind][key] for key in ("id", "name", "volume")} == {
            key: original[kind][key] for key in ("id", "name", "volume")
        }
        assert value.stack.resources[value.services[kind]["name"]] is value.services[kind]
    assert (value.stack.evidence.root / "restored-resources.json").read_bytes() == value.initial
    receipts = sorted(value.stack.evidence.root.glob("restored-*-post-restart-bindings-*.json"))
    assert len(receipts) == 2
    for receipt in receipts:
        document = json.loads(receipt.read_text())
        assert document["before"]["id"] == document["after"]["id"]
        assert document["before"]["volume"] == document["after"]["volume"]
        assert document["before"]["ports"] != document["after"]["ports"]
    assert [args[0] for args, _ in value.mutations] == ["stop", "cp", "start", "stop", "cp", "start"]


@pytest.mark.parametrize(
    "unsafe",
    [
        "missing",
        "wildcard",
        "ipv6",
        "unexpected",
        "wrong_id",
        "wrong_label",
        "wrong_volume",
        "wrong_image",
        "wrong_name",
        "protected",
        "stopped",
        "missing_mailpit",
    ],
)
def test_refresh_rejects_unsafe_or_changed_identity_without_fallback_or_manifest_rewrite(restarted_services, unsafe):
    value = restarted_services
    kind = "mailpit" if unsafe == "missing_mailpit" else "redis"
    service = value.services[kind]
    before = copy.deepcopy(service)
    record = value.records[service["id"]]
    if unsafe == "missing":
        record["NetworkSettings"]["Ports"] = None
    elif unsafe in {"wildcard", "ipv6"}:
        record["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostIp"] = "0.0.0.0" if unsafe == "wildcard" else "::1"  # noqa: S104 - rejected fixture
    elif unsafe == "unexpected":
        record["NetworkSettings"]["Ports"]["9999/tcp"] = [{"HostIp": "127.0.0.1", "HostPort": "36503"}]
    elif unsafe == "wrong_id":
        record["Id"] = "foreign-container"
    elif unsafe == "wrong_label":
        record["Config"]["Labels"]["kp.fullstack.qualification"] = "foreign-run"
    elif unsafe == "wrong_volume":
        record["Mounts"][0]["Name"] = "foreign-volume"
    elif unsafe == "wrong_image":
        record["Config"]["Image"] = "foreign:latest"
    elif unsafe == "wrong_name":
        record["Name"] = "/foreign-container"
    elif unsafe == "protected":
        record["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"] = "51459"
    elif unsafe == "stopped":
        record["State"]["Running"] = False
    else:
        del record["NetworkSettings"]["Ports"]["8025/tcp"]
    with pytest.raises(QualificationFailure):
        value.stack.refresh_service_bindings(service, kind)
    assert service == before and value.mutations == []
    assert not list(value.stack.evidence.root.glob("restored-*-post-restart-bindings-*.json"))
    assert (value.stack.evidence.root / "restored-resources.json").read_bytes() == value.initial


def test_old_cached_port_failure_is_closed_by_guarded_refresh(restarted_services, monkeypatch):
    from recovery import verify_restored_redis

    value = restarted_services
    service = value.services["redis"]
    value.stack.mutate("stop", service["id"], "--time", "15")
    value.stack.mutate("start", service["id"])
    assert service["ports"][6379] == 36400

    def connect(url, **kwargs):
        if url != "redis://127.0.0.1:36500/0":
            raise AssertionError("stale endpoint cannot reach the restored Redis")
        return SimpleNamespace(get=lambda _: b"acknowledged", close=lambda: None)

    monkeypatch.setattr("recovery.redis.Redis.from_url", connect)
    with pytest.raises(AssertionError, match="stale endpoint"):
        verify_restored_redis(value.stack, value.services, "acknowledged")
    value.stack.refresh_service_bindings(service, "redis")
    verify_restored_redis(value.stack, value.services, "acknowledged")
    assert service["ports"][6379] == 36500


def test_restore_restart_rejects_unregistered_record_before_any_mutation(restarted_services):
    from recovery import restart_restored_service

    value = restarted_services
    forged = {"redis": dict(value.services["redis"])}
    with pytest.raises(QualificationFailure, match="recorded restore target"):
        restart_restored_service(value.stack, forged, "redis", b"preserved synthetic snapshot")
    assert value.mutations == []


def test_each_restart_appends_a_new_binding_receipt_without_replacing_prior_evidence(restarted_services):
    value = restarted_services
    service = value.services["redis"]
    receipts = []
    for _ in range(2):
        value.stack.mutate("stop", service["id"], "--time", "15")
        value.stack.mutate("start", service["id"])
        value.stack.refresh_service_bindings(service, "redis")
        receipts.append(sorted(value.stack.evidence.root.glob("restored-redis-post-restart-bindings-*.json"))[-1])
    assert receipts[0] != receipts[1]
    first, second = (json.loads(path.read_text()) for path in receipts)
    assert first["before"]["ports"] == {"6379": 36400} and first["after"]["ports"] == {"6379": 36500}
    assert second["before"]["ports"] == {"6379": 36500} and second["after"]["ports"] == {"6379": 36600}
    assert first["after"]["id"] == second["after"]["id"] == service["id"]
    assert (value.stack.evidence.root / "restored-resources.json").read_bytes() == value.initial


def test_evidence_is_exclusive_private_and_profile_is_declared_first(tmp_path):
    output = tmp_path / "run"
    evidence = Evidence(output, "synthetic", Profile())
    profile = json.loads((output / "profile.json").read_text())
    assert profile["recipients"] == [125, 1250]
    assert profile["soak_seconds"] == 300 and profile["total_seconds"] == 1800
    assert profile["drain_seconds"] == 600 and profile["api_p95_seconds"] == 1
    assert profile["critical_seconds"] == 2 and profile["rto_seconds"] == 900
    assert (output / "profile.json").stat().st_mode & 0o777 == 0o600
    assert output.stat().st_mode & 0o777 == 0o700
    evidence.json("result.json", {"original": True})
    with pytest.raises(FileExistsError):
        evidence.json("result.json", {"replacement": True})
    with pytest.raises(FileExistsError):
        Evidence(output, "other", Profile())
    assert json.loads((output / "result.json").read_text()) == {"original": True}


def test_absolute_deadline_prevents_additional_work(tmp_path, monkeypatch):
    evidence = Evidence(tmp_path / "run", "synthetic", Profile())
    monkeypatch.setattr("evidence.time.monotonic", lambda: evidence.started + 1801)
    with pytest.raises(QualificationFailure, match="deadline"):
        evidence.remaining()


@pytest.mark.parametrize(
    "value",
    [
        "redis://localhost:12345",
        "redis://127.0.0.1:5432",
        "redis://127.0.0.1:51458",
        "redis://remote.test:12345",
        "redis://127.0.0.1:12345/0?redirect=1",
    ],
)
def test_preserved_or_external_endpoints_are_refused(value):
    with pytest.raises(QualificationFailure):
        loopback_url(value, {"redis"})


def test_controller_refused_before_any_docker_call(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "packages/example/src").mkdir(parents=True)
    (source / "apps").mkdir()
    evidence = Evidence(tmp_path / "run", "synthetic", Profile())
    monkeypatch.setattr("stack.free_port", lambda: 33333)
    stack = Stack(evidence, source, "reviewed", "engine")
    calls = []
    monkeypatch.setattr(stack, "docker", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr("stack.platform.system", lambda: "Darwin")
    with pytest.raises(QualificationFailure, match="WSL2"):
        stack.preflight()
    assert calls == []
    with pytest.raises(QualificationFailure, match="not owned"):
        stack.mutate("stop", "unrelated-container")
    assert calls == []


def test_source_manifest_excludes_credentials_data_and_symlinks(tmp_path):
    (tmp_path / "uv.lock").write_text("immutable-lock")
    (tmp_path / "pyproject.toml").write_text("[project]")
    source = tmp_path / "apps/example/src"
    source.mkdir(parents=True)
    (source / "app.py").write_text("pass")
    (source / ".env.py").write_text("private")
    data = source / "data"
    data.mkdir()
    (data / "private.py").write_text("private")
    (source / "linked.py").symlink_to(data / "private.py")
    manifest = source_manifest(tmp_path)
    assert set(manifest) == {"uv.lock", "pyproject.toml", "apps/example/src/app.py"}


@pytest.mark.parametrize(
    "command",
    [
        "MAIL FROM:<person@example.com>",
        "RCPT TO:<person@127.0.0.1>",
        "MAIL FROM:<person@qualification.test.attacker.com>",
    ],
)
def test_fault_proxy_refuses_external_envelopes(command):
    with pytest.raises(ValueError):
        address(command)


@pytest.mark.parametrize("mode", ["pass", "delay", "reject", "disconnect_after_accept"])
def test_real_smtp_protocol_fault_modes_are_bounded_and_accounted(monkeypatch, mode):
    sent, recorded = [], []

    class Upstream:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("127.0.0.1", 33334, 10)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def sendmail(self, sender, recipients, body):
            sent.append((sender, recipients, body))
            return {}

    monkeypatch.setattr("smtp_proxy.smtplib.SMTP", Upstream)
    monkeypatch.setattr("smtp_proxy.time.sleep", lambda seconds: None)
    handler = SimpleNamespace(
        server=SimpleNamespace(
            slots=threading.BoundedSemaphore(1),
            upstream_port=33334,
            mode=lambda: mode,
            record=lambda **value: recorded.append(value),
        ),
        request=SimpleNamespace(settimeout=lambda seconds: None),
        rfile=io.BytesIO(
            b"EHLO qualification\r\nMAIL FROM:<training@qualification.test>\r\n"
            b"RCPT TO:<subject@qualification.test>\r\nDATA\r\n"
            b"Subject: synthetic\r\n\r\n..escaped\r\n.\r\nQUIT\r\n"
        ),
        wfile=io.BytesIO(),
    )
    Handler.handle(handler)
    if mode == "reject":
        assert not sent and b"451" in handler.wfile.getvalue()
        assert recorded == [{"mode": mode, "accepted": False, "recipients": ["subject@qualification.test"]}]
    else:
        assert len(sent) == 1 and b"\r\n.escaped\r\n" in sent[0][2]
        accepted = [row for row in recorded if row.get("accepted")]
        assert len(accepted) == 1 and len(accepted[0]["fingerprint"]) == 64
        assert (b"250 sink accepted" in handler.wfile.getvalue()) == (mode != "disconnect_after_accept")


def test_no_latency_samples_cannot_establish_a_pass():
    with pytest.raises(QualificationFailure):
        percentile([])
    assert percentile([3, 1, 2], 0.95) == 3


@pytest.mark.parametrize("subnet", ["10.254.246.0/28", "10.254.247.0/24", "10.254.247.1/28", "::/28"])
def test_only_explicit_canonical_reviewed_subnets_are_accepted(tmp_path, subnet):
    evidence = Evidence(tmp_path / "run", "synthetic", Profile())
    with pytest.raises((QualificationFailure, ValueError)):
        Stack(evidence, tmp_path, "reviewed", "engine", subnet)


def test_mismatched_ownership_label_prevents_stop_even_for_recorded_id(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "packages/example/src").mkdir(parents=True)
    (source / "apps").mkdir()
    monkeypatch.setattr("stack.free_port", lambda: 33333)
    stack = Stack(Evidence(tmp_path / "run", "synthetic", Profile()), source, "host", "engine")
    stack.resources["owned-name"] = {"id": "recorded-id"}
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        return json.dumps([{"Config": {"Labels": {"kp.fullstack.qualification": "other-run"}}}]).encode()

    monkeypatch.setattr(stack, "docker", docker)
    with pytest.raises(QualificationFailure, match="label"):
        stack.mutate("stop", "recorded-id")
    assert calls == [("inspect", "recorded-id")]


def test_generated_app_settings_and_process_credentials_are_scoped(tmp_path, monkeypatch):
    from kp_database.grants import RUNTIME_ROLES

    root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr("stack.free_port", lambda: 33333)
    stack = Stack(Evidence(tmp_path / "run", "synthetic", Profile()), root, "host", "engine")
    stack.passwords = {workload: "synthetic-role-only" for workload in RUNTIME_ROLES}
    captured = {}
    monkeypatch.setattr(stack, "spawn", lambda name, arguments, environment: captured.setdefault(name, environment))
    services = {
        "postgres": {"ports": {5432: 33334}},
        "redis": {"ports": {6379: 33335}},
        "mailpit": {"ports": {1025: 33336, 8025: 33337}},
    }
    stack.start_applications(services, "source")
    assert not any("DATABASE_URL" in name for name in captured["source-smtp"])
    assert not any(name.startswith("KP_WORKER_") for name in captured["source-operator"])
    assert not any(name.startswith("OPERATOR_API_") for name in captured["source-worker-delivery"])
    role_urls = [name for name in captured["source-worker-delivery"] if name.startswith("KP_WORKER_DATABASE_URL_")]
    assert role_urls == ["KP_WORKER_DATABASE_URL_DELIVERY"]
    assert "kp_worker_audit_anchor" in captured["source-worker-audit-anchor"]["KP_WORKER_AUDIT_DATABASE_URL"]
    for process_name, script in (
        (
            "source-operator",
            "from kp_operator_api.config import OperatorApiSettings; s=OperatorApiSettings(); "
            "assert s.approval_policy.value=='enforce'; print('validated')",
        ),
        (
            "source-worker-delivery",
            "from kp_workers.config import WorkerSettings; s=WorkerSettings(worker_name='delivery'); "
            "assert s.approval_policy.value=='enforce'; assert 'kp_worker_delivery' in s.database_url; "
            "print('validated')",
        ),
    ):
        result = subprocess.run(  # noqa: S603 - fixed settings-only script and generated synthetic environment
            [sys.executable, "-c", script],
            env=captured[process_name],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "validated"
    stack.evidence.json("private-role-urls.json", stack.urls)
    recovered = tmp_path / "recovered-config"
    recovered.mkdir()
    for name in ("private-secrets.json", "private-role-urls.json", "source-private-application-environment.json"):
        (recovered / name).write_bytes((stack.evidence.root / name).read_bytes())
    original_cipher = stack.secrets["cipher"]
    stack.secrets["cipher"] = "wrong-live-controller-value"
    stack.passwords.clear()
    stack.api_ports = {"operator": 1, "tracking": 2, "smtp": 3}
    stack.load_recovered_configuration(recovered)
    assert stack.secrets["cipher"] == original_cipher
    assert stack.passwords["delivery"] == "synthetic-role-only"
    assert stack.api_ports == {"operator": 33333, "tracking": 33333, "smtp": 33333}


def test_expired_work_deadline_still_quiesces_all_owned_processes(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "packages/example/src").mkdir(parents=True)
    (source / "apps").mkdir()
    monkeypatch.setattr("stack.free_port", lambda: 33333)
    stack = Stack(Evidence(tmp_path / "run", "synthetic", Profile()), source, "host", "engine")
    observed = []

    class Process:
        def __init__(self, pid):
            self.pid, self.returncode = pid, None

        def poll(self):
            return self.returncode

        def terminate(self):
            observed.append(self.pid)

        def wait(self, timeout):
            assert 0 < timeout <= 30
            self.returncode = 0

    stack.processes = {name: (Process(index), "reviewed") for index, name in enumerate(("first", "second"))}
    monkeypatch.setattr(stack, "process_stamp", lambda pid: "reviewed")
    monkeypatch.setattr(
        stack.evidence, "remaining", lambda *args: (_ for _ in ()).throw(QualificationFailure("expired"))
    )
    stack.quiesce()
    assert observed == [0, 1] and not stack.processes


def test_drain_rejects_extra_queued_assignment_despite_expected_acceptances():
    campaigns = object.__new__(Campaigns)
    campaigns.evidence = SimpleNamespace(profile=Profile(), remaining=lambda maximum: maximum)
    campaigns.observe = lambda campaign: {"ACCEPTED": 1, "QUEUED": 1}
    with pytest.raises(QualificationFailure, match="cardinality"):
        campaigns.drain({"id": "synthetic", "label": "baseline", "size": 1})


def test_drain_stops_immediately_after_delivery_exhausts_retries(monkeypatch):
    campaigns = object.__new__(Campaigns)
    campaigns.evidence = SimpleNamespace(profile=Profile(), remaining=lambda maximum=None: maximum or 1800)
    campaigns.observe = lambda campaign: {"QUEUED": 3}
    campaigns.delivery_dead_letters = lambda: 1

    def unexpected_wait(seconds):
        raise AssertionError("a dead-lettered delivery cannot make progress by waiting")

    monkeypatch.setattr("campaign.time.sleep", unexpected_wait)
    with pytest.raises(QualificationFailure, match="delivery exhausted retries"):
        campaigns.drain({"id": "synthetic", "label": "baseline", "size": 3})


@pytest.mark.parametrize("wrong_envelope", (False, True))
def test_sink_headers_and_envelope_journal_must_both_match_exact_roster(tmp_path, wrong_envelope):
    campaigns = object.__new__(Campaigns)
    campaigns.evidence = SimpleNamespace(root=tmp_path, event=lambda *args, **kwargs: None)
    campaigns.campaigns = [{"label": "baseline", "size": 1}]
    campaigns.endpoints = {"mailpit": "http://127.0.0.1:33333"}
    response = SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {"messages": [{"To": [{"Address": "baseline-0@qualification.test"}]}]},
    )
    campaigns.client = SimpleNamespace(get=lambda *args, **kwargs: response)
    envelope = "different-0@qualification.test" if wrong_envelope else "baseline-0@qualification.test"
    (tmp_path / "smtp-journal.jsonl").write_text(json.dumps({"accepted": True, "recipients": [envelope]}) + "\n")
    if wrong_envelope:
        with pytest.raises(QualificationFailure, match="envelope acceptance scope"):
            campaigns.verify_sink_accounting()
    else:
        assert campaigns.verify_sink_accounting() == 1


@pytest.mark.parametrize("scenario", ("missing", "missing_mailpit", "wildcard", "stopped", "valid"))
def test_service_creation_preserves_identity_before_port_or_running_failure(tmp_path, monkeypatch, scenario):
    source = tmp_path / "source"
    (source / "packages/example/src").mkdir(parents=True)
    (source / "apps").mkdir()
    monkeypatch.setattr("stack.free_port", lambda: 33333)
    evidence = Evidence(tmp_path / "run", "synthetic", Profile())
    stack = Stack(evidence, source, "host", "engine")
    created, calls = {}, []

    def docker(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("volume", "create"):
            return args[-1].encode()
        if args[0] == "run":
            kind = args[args.index("--name") + 1].rsplit("-", 1)[-1]
            identifier = f"task-{kind}"
            ports = (1025, 8025) if kind == "mailpit" else ((5432,) if kind == "postgres" else (6379,))
            requested = [args[index + 1] for index, value in enumerate(args) if value == "-p"]
            assert requested == [f"127.0.0.1::{port}" for port in ports]
            created[identifier] = {
                "Config": {"Labels": {"kp.fullstack.qualification": "synthetic"}},
                "State": {"Running": scenario != "stopped"},
                "NetworkSettings": {
                    "Ports": None
                    if scenario == "missing"
                    else {
                        f"{port}/tcp": [
                            {
                                "HostIp": "0.0.0.0" if scenario == "wildcard" else "127.0.0.1",  # noqa: S104 - refusal fixture
                                "HostPort": str(33000 + port),
                            }
                        ]
                        for port in ports
                    }
                },
            }
            if scenario == "missing_mailpit" and kind == "mailpit":
                del created[identifier]["NetworkSettings"]["Ports"]["8025/tcp"]
            return identifier.encode()
        if args[0] == "inspect":
            return json.dumps([created[args[1]]]).encode()
        raise AssertionError(args)

    monkeypatch.setattr(stack, "docker", docker)
    if scenario == "valid":
        services = stack.create_services("source")
        assert set(services) == {"postgres", "redis", "mailpit"}
        assert services["mailpit"]["ports"] == {1025: 34025, 8025: 41025}
    else:
        with pytest.raises(QualificationFailure):
            stack.create_services("source")
        assert any(record["id"] == "task-postgres" for record in stack.resources.values())
        journal = [json.loads(line) for line in (evidence.root / "journal.jsonl").read_text().splitlines()]
        assert any(row["phase"] == "resource_created" and row["id"] == "task-postgres" for row in journal)
        if scenario == "missing_mailpit":
            assert "task-mailpit" in created
        else:
            assert "task-redis" not in created
    assert not any(call[0] in {"stop", "start", "rm", "exec"} for call in calls)


@pytest.mark.parametrize(
    ("system", "architecture", "allowed"),
    (("linux", "amd64", True), ("linux", "arm64", False), ("darwin", "amd64", False)),
)
def test_cached_pinned_image_requires_native_linux_amd64(tmp_path, monkeypatch, system, architecture, allowed):
    source = tmp_path / "source"
    (source / "packages/example/src").mkdir(parents=True)
    (source / "apps").mkdir()
    monkeypatch.setattr("stack.free_port", lambda: 33333)
    stack = Stack(Evidence(tmp_path / "run", "synthetic", Profile()), source, "host", "engine")
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        return json.dumps([{"Os": system, "Architecture": architecture, "Id": "sha256:synthetic"}]).encode()

    monkeypatch.setattr(stack, "docker", docker)
    if allowed:
        assert stack.inspect_native_image("postgres@sha256:synthetic")["architecture"] == "amd64"
    else:
        with pytest.raises(QualificationFailure, match="native linux/amd64"):
            stack.inspect_native_image("postgres@sha256:synthetic")
    assert calls == [("image", "inspect", "postgres@sha256:synthetic")]
