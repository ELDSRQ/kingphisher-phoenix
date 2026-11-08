"""Hermetic artifact proofs: fake age protocol and in-memory HTTPS transports."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import json
import os
import ssl
import sys
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/operator/recovery-qualification"))
import artifacts  # noqa: E402
from common import (  # noqa: E402
    RUNTIME_COMMIT,
    SNAPSHOT_SCHEMA,
    RecoveryError,
    private_bytes,
    private_directory,
    private_json,
)

RECIPIENT = "age1" + "q" * 58
SECRET = "AGE-SECRET-KEY-1" + "Q" * 58
PREFIX = b"fake-age-v1\n"
HOST = "syntheticaccount.blob.core.windows.net"
URL = f"https://{HOST}/synthetic/run/snapshot.age?sv=private&sig=NEVER-LOG-THIS"


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def snapshot(tmp_path):
    root = private_directory(tmp_path / "snapshot", create=True)
    payloads = {
        "postgres.dump": b"synthetic custom PostgreSQL dump",
        "globals.sql": b"-- synthetic roles\n",
        "redis.rdb": b"synthetic RDB",
        "redis-inventory.json": b'{"synthetic":"logical hash"}',
        "state/.env": b"SYNTHETIC_PASSWORD=only-test-state\n",
        "state/data/recovery/sentinel.txt": b"acknowledged synthetic file",
    }
    for name, data in payloads.items():
        path = root / name
        parent = root
        for part in path.parent.relative_to(root).parts:
            parent /= part
            parent.mkdir(mode=0o700, exist_ok=True)
        private_bytes(path, data)
    manifest = {
        "schema": SNAPSHOT_SCHEMA,
        "run_id": "synthetic-artifact-proof",
        "scope": "synthetic-qualification",
        "created_at": "2026-11-07T00:00:00Z",
        "application": {
            "bundle_commit": "a" * 40,
            "runtime_commit": RUNTIME_COMMIT,
            "schema_head": "0060_delivery_authority_locks",
            "source_root": "/srv/kp-cleanlinux/clean-target",
        },
        "source": {"hostname": "synthetic-source"},
        "data": {"sentinel": "acknowledged-synthetic"},
        "files": {
            name: {"sha256": digest(data), "bytes": len(data), "mode": "0600"} for name, data in payloads.items()
        },
    }
    private_json(root / "manifest.json", manifest)
    return SimpleNamespace(root=root, manifest=manifest, payloads=payloads)


@pytest.fixture
def crypto(tmp_path):
    identity = tmp_path / "identity.age"
    private_bytes(identity, ("# synthetic identity for fake CLI only\n" + SECRET + "\n").encode())
    executable = tmp_path / "fake-age"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json,pathlib,shutil,sys,time\n"
        "root=pathlib.Path(__file__).parent\n"
        "mode=(root/'mode').read_text() if (root/'mode').exists() else ''\n"
        "with (root/'fake-argv.jsonl').open('a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
        "if mode=='hang': time.sleep(30)\n"
        "if mode=='fail' or (mode=='fail-encrypt' and '--encrypt' in sys.argv):\n"
        "    sys.stderr.write('PRIVATE-IDENTITY-OR-SAS-MUST-NEVER-APPEAR'); sys.exit(7)\n"
        "if '--decrypt' in sys.argv:\n"
        "    key=pathlib.Path(sys.argv[sys.argv.index('--identity')+1]).read_text()\n"
        "    assert 'AGE-SECRET-KEY-1' in key\n"
        "    assert sys.stdin.buffer.readline()==b'fake-age-v1\\n'\n"
        "else: sys.stdout.buffer.write(b'fake-age-v1\\n'); sys.stdout.buffer.flush()\n"
        "shutil.copyfileobj(sys.stdin.buffer,sys.stdout.buffer,65536)\n"
    )
    executable.chmod(0o700)
    return SimpleNamespace(
        identity=identity, command=str(executable), mode=tmp_path / "mode", argv=tmp_path / "fake-argv.jsonl"
    )


def encrypted(snapshot, crypto, tmp_path):
    output = tmp_path / "snapshot.age"
    receipt = artifacts.encrypt_snapshot(
        snapshot.root, output, RECIPIENT, age_command=crypto.command, deadline=time.time() + 15
    )
    return output, receipt


def tar_payload(snapshot, extra=(), *, manifest=None, mutate=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:") as archive:
        data = json.dumps(manifest or snapshot.manifest).encode()
        rows = [("manifest.json", tarfile.REGTYPE, data, 0o600)]
        rows += [(name, tarfile.REGTYPE, content, 0o600) for name, content in snapshot.payloads.items()]
        rows += list(extra)
        for name, kind, data, mode in rows:
            item = tarfile.TarInfo(name)
            item.type, item.mode, item.size = kind, mode, len(data)
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                item.linkname = "../../outside"
                item.size = 0
            if mutate:
                mutate(item)
            archive.addfile(item, io.BytesIO(data) if item.isfile() else None)
    return gzip.compress(raw.getvalue(), mtime=0)


def private_cipher(tmp_path, payload):
    path = tmp_path / "input.age"
    private_bytes(path, PREFIX + payload)
    return path, digest(path.read_bytes())


def test_valid_private_snapshot_and_executable_state(snapshot):
    executable = snapshot.root / "state/data/helper"
    private_bytes(executable, b"synthetic executable", executable=True)
    snapshot.manifest["files"]["state/data/helper"] = {
        "sha256": digest(executable.read_bytes()),
        "bytes": executable.stat().st_size,
        "mode": "0700",
    }
    (snapshot.root / "manifest.json").write_text(json.dumps(snapshot.manifest))
    assert artifacts.validate_snapshot(snapshot.root) == snapshot.manifest


@pytest.mark.parametrize("defect", ["extra", "missing", "hash", "mode", "symlink", "hardlink", "extra-dir", "age-key"])
def test_snapshot_rejects_scope_and_file_identity_drift(snapshot, tmp_path, defect):
    path = snapshot.root / "postgres.dump"
    if defect == "extra":
        private_bytes(snapshot.root / "other", b"unexpected")
    elif defect == "missing":
        path.rename(snapshot.root / "absent")
    elif defect == "hash":
        path.write_bytes(b"X" * path.stat().st_size)
    elif defect == "mode":
        path.chmod(0o644)
    elif defect == "extra-dir":
        (snapshot.root / "empty-extra").mkdir()
    elif defect == "age-key":
        path.write_bytes(SECRET.encode())
        snapshot.manifest["files"]["postgres.dump"] = {
            "sha256": digest(path.read_bytes()),
            "bytes": path.stat().st_size,
            "mode": "0600",
        }
        (snapshot.root / "manifest.json").write_text(json.dumps(snapshot.manifest))
    elif defect == "symlink":
        (snapshot.root / "state/data/link").symlink_to(tmp_path / "outside")
    else:
        os.link(path, snapshot.root / "state/data/hardlink")
    with pytest.raises(RecoveryError):
        artifacts.validate_snapshot(snapshot.root)


@pytest.mark.parametrize("change", ["scope", "runtime", "files-type", "mode-type", "missing-purpose", "duplicate-json"])
def test_manifest_invalidity_fails_closed(snapshot, change):
    if change == "scope":
        snapshot.manifest["scope"] = "normal-development-data"
    elif change == "runtime":
        snapshot.manifest["application"]["runtime_commit"] = "b" * 40
    elif change == "files-type":
        snapshot.manifest["files"] = []
    elif change == "mode-type":
        snapshot.manifest["files"]["postgres.dump"]["mode"] = []
    elif change == "missing-purpose":
        del snapshot.manifest["data"]
    else:
        (snapshot.root / "manifest.json").write_bytes(b'{"schema":"one","schema":"two"}')
    if change != "duplicate-json":
        (snapshot.root / "manifest.json").write_text(json.dumps(snapshot.manifest))
    with pytest.raises(RecoveryError):
        artifacts.validate_snapshot(snapshot.root)


def test_fake_age_roundtrip_validates_all_files_before_new_extraction(snapshot, crypto, tmp_path, capsys):
    cipher, receipt = encrypted(snapshot, crypto, tmp_path)
    destination = tmp_path / "restored"
    result = artifacts.decrypt_snapshot(
        cipher, crypto.identity, destination, receipt["sha256"], age_command=crypto.command, deadline=time.time() + 15
    )
    assert result["manifest"] == snapshot.manifest
    assert artifacts.validate_snapshot(destination) == snapshot.manifest
    assert cipher.stat().st_mode & 0o777 == 0o600
    assert all((destination / name).read_bytes() == content for name, content in snapshot.payloads.items())
    assert SECRET not in crypto.argv.read_text()  # age receives an inherited fd path, not a key value
    assert not capsys.readouterr().out


@pytest.mark.parametrize("expected", ["", "not-a-sha", "A" * 64, "0" * 64])
def test_restore_requires_authenticated_exact_cipher_digest_before_any_destination(
    snapshot, crypto, tmp_path, expected
):
    cipher, _ = encrypted(snapshot, crypto, tmp_path)
    before = crypto.argv.read_bytes()
    destination = tmp_path / "must-not-exist"
    with pytest.raises(RecoveryError):
        artifacts.decrypt_snapshot(
            cipher, crypto.identity, destination, expected, age_command=crypto.command, deadline=time.time() + 15
        )
    assert not destination.exists() and crypto.argv.read_bytes() == before


@pytest.mark.parametrize("operation", ["encrypt", "decrypt", "rewrap"])
def test_existing_output_assets_are_never_overwritten(snapshot, crypto, tmp_path, operation):
    cipher, receipt = encrypted(snapshot, crypto, tmp_path)
    output = tmp_path / "preserved"
    private_bytes(output, b"preserved asset")
    with pytest.raises(RecoveryError):
        if operation == "encrypt":
            artifacts.encrypt_snapshot(
                snapshot.root, output, RECIPIENT, age_command=crypto.command, deadline=time.time() + 15
            )
        elif operation == "decrypt":
            artifacts.decrypt_snapshot(
                cipher,
                crypto.identity,
                output,
                receipt["sha256"],
                age_command=crypto.command,
                deadline=time.time() + 15,
            )
        else:
            artifacts.rewrap(
                cipher,
                crypto.identity,
                RECIPIENT,
                output,
                receipt["sha256"],
                age_command=crypto.command,
                deadline=time.time() + 15,
            )
    assert output.read_bytes() == b"preserved asset"


@pytest.mark.parametrize("kind", ["symlink", "public", "invalid"])
def test_invalid_private_identity_fails_before_extract(snapshot, crypto, tmp_path, kind):
    cipher, receipt = encrypted(snapshot, crypto, tmp_path)
    identity = crypto.identity
    if kind == "symlink":
        identity = tmp_path / "linked-identity"
        identity.symlink_to(crypto.identity)
    elif kind == "public":
        identity.chmod(0o644)
    else:
        identity.write_text("not a classic identity")
    with pytest.raises(RecoveryError):
        artifacts.decrypt_snapshot(
            cipher,
            identity,
            tmp_path / "restored",
            receipt["sha256"],
            age_command=crypto.command,
            deadline=time.time() + 15,
        )
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize(
    "name,kind,content,mode",
    [
        ("../escape", tarfile.REGTYPE, b"bad", 0o600),
        ("state/data/link", tarfile.SYMTYPE, b"", 0o600),
        ("state/data/link", tarfile.LNKTYPE, b"", 0o600),
        ("state/data/device", tarfile.CHRTYPE, b"", 0o600),
        (".env", tarfile.REGTYPE, b"bad", 0o600),
        ("state/data/.venv/code", tarfile.REGTYPE, b"bad", 0o600),
        ("postgres.dump", tarfile.REGTYPE, b"duplicate", 0o600),
        ("state/data/unmanifested", tarfile.REGTYPE, b"extra", 0o600),
    ],
)
def test_malicious_tar_fails_complete_validation_before_destination(
    snapshot, crypto, tmp_path, name, kind, content, mode
):
    cipher, sha = private_cipher(tmp_path, tar_payload(snapshot, [(name, kind, content, mode)]))
    with pytest.raises(RecoveryError):
        artifacts.decrypt_snapshot(
            cipher, crypto.identity, tmp_path / "restored", sha, age_command=crypto.command, deadline=time.time() + 15
        )
    assert not (tmp_path / "restored").exists() and not (tmp_path / "escape").exists()


@pytest.mark.parametrize("defect", ["file-hash", "file-mode", "truncated", "trailing-tar", "age-key"])
def test_archive_integrity_or_identity_payload_failure_prevents_extraction(snapshot, crypto, tmp_path, defect):
    mutate = None
    if defect == "file-hash":
        snapshot.manifest["files"]["postgres.dump"]["sha256"] = "0" * 64
    elif defect == "file-mode":

        def mutate(member):
            if member.name == "postgres.dump":
                member.mode = 0o644
    elif defect == "age-key":
        snapshot.payloads["postgres.dump"] = SECRET.encode()
        snapshot.manifest["files"]["postgres.dump"] = {
            "sha256": digest(SECRET.encode()),
            "bytes": len(SECRET),
            "mode": "0600",
        }
    payload = tar_payload(snapshot, mutate=mutate)
    if defect == "truncated":
        payload = payload[:-8]
    elif defect == "trailing-tar":
        payload = gzip.compress(gzip.decompress(payload) + gzip.decompress(payload), mtime=0)
    cipher, sha = private_cipher(tmp_path, payload)
    with pytest.raises(RecoveryError):
        artifacts.decrypt_snapshot(
            cipher, crypto.identity, tmp_path / "restored", sha, age_command=crypto.command, deadline=time.time() + 15
        )
    assert not (tmp_path / "restored").exists()


def test_rewrap_streams_without_plaintext_disk_and_preserves_originals(snapshot, crypto, tmp_path, capsys):
    cipher, receipt = encrypted(snapshot, crypto, tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
    output = tmp_path / "target.age"
    result = artifacts.rewrap(
        cipher,
        crypto.identity,
        RECIPIENT,
        output,
        receipt["sha256"],
        age_command=crypto.command,
        deadline=time.time() + 15,
    )
    assert result["sha256"] == digest(output.read_bytes())
    assert set(path.name for path in tmp_path.iterdir() if path.is_file()) - set(before) == {"target.age"}
    assert all((tmp_path / name).read_bytes() == value for name, value in before.items() if name != crypto.argv.name)
    assert not capsys.readouterr().out
    restored = tmp_path / "target-restored"
    artifacts.decrypt_snapshot(
        output, crypto.identity, restored, result["sha256"], age_command=crypto.command, deadline=time.time() + 15
    )
    assert artifacts.validate_snapshot(restored) == snapshot.manifest


def test_crypto_failure_keeps_partial_cipher_and_redacts_raw_errors(snapshot, crypto, tmp_path, capsys):
    crypto.mode.write_text("fail")
    output = tmp_path / "partial.age"
    with pytest.raises(RecoveryError):
        artifacts.encrypt_snapshot(
            snapshot.root, output, RECIPIENT, age_command=crypto.command, deadline=time.time() + 15
        )
    assert output.exists() and output.stat().st_mode & 0o777 == 0o600
    observed = capsys.readouterr()
    assert not observed.out and not observed.err


def test_crypto_timeout_is_bounded_and_retains_partial(snapshot, crypto, tmp_path):
    crypto.mode.write_text("hang")
    started = time.monotonic()
    output = tmp_path / "partial.age"
    with pytest.raises(RecoveryError):
        artifacts.encrypt_snapshot(
            snapshot.root, output, RECIPIENT, age_command=crypto.command, deadline=time.time() + 2.3
        )
    assert time.monotonic() - started < 4 and output.exists()


class Response:
    def __init__(self, status=200, body=b"synthetic ciphertext", headers=None):
        self.status, self.data = status, io.BytesIO(body)
        self.headers = {"Content-Length": str(len(body)), "ETag": '"0xABC123"', **(headers or {})}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, size):
        return self.data.read(size)


@pytest.fixture
def transport(monkeypatch):
    state = SimpleNamespace(calls=[], sent=b"", headers={}, response=Response())

    class Connection:
        def __init__(self, host, port, *, timeout, context):
            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            assert host == HOST and port == 443 and 0 < timeout <= 15
            state.calls.append((host, port))
            self.sock = SimpleNamespace(settimeout=lambda value: state.calls.append(("timeout", value)))
            self.timeout = timeout

        def putrequest(self, method, target):
            state.calls.append((method, target))

        def putheader(self, key, value):
            state.headers[key] = value

        def endheaders(self):
            pass

        def send(self, block):
            state.sent += block

        def getresponse(self):
            return state.response

        def request(self, method, target):
            self.putrequest(method, target)

        def close(self):
            state.closed = True

    monkeypatch.setattr(artifacts.http.client, "HTTPSConnection", Connection)
    return state


def test_upload_is_conditional_direct_tls_and_returns_only_safe_receipt(tmp_path, transport, monkeypatch, capsys):
    monkeypatch.setenv("HTTPS_PROXY", "https://untrusted.proxy.invalid")
    path = tmp_path / "cipher.age"
    private_bytes(path, b"synthetic ciphertext")
    transport.response = Response(status=201)
    result = artifacts.upload_cipher(path, URL, HOST, deadline=time.time() + 5)
    assert transport.headers["If-None-Match"] == "*" and transport.headers["x-ms-blob-type"] == "BlockBlob"
    assert transport.sent == path.read_bytes() and result == {
        "sha256": digest(path.read_bytes()),
        "bytes": path.stat().st_size,
        "etag": '"0xABC123"',
    }
    assert "sig" not in json.dumps(result) and not capsys.readouterr().out


@pytest.mark.parametrize(
    "url",
    [
        "http://syntheticaccount.blob.core.windows.net/cipher/snapshot?sig=private",
        "https://different.blob.core.windows.net/cipher/snapshot?sig=private",
        f"https://user@{HOST}/cipher/snapshot?sig=private",
        f"https://{HOST}:444/cipher/snapshot?sig=private",
        f"https://{HOST}/cipher/../normal?sig=private",
        f"https://{HOST}/cipher/%2e%2e/normal?sig=private",
        f"https://{HOST}/cipher/snapshot?sig=private#fragment",
        f"https://{HOST}/cipher/snapshot",
    ],
)
def test_out_of_scope_urls_refuse_before_any_connection(tmp_path, transport, url):
    path = tmp_path / "cipher.age"
    private_bytes(path, b"ciphertext")
    with pytest.raises(RecoveryError):
        artifacts.upload_cipher(path, url, HOST, deadline=time.time() + 5)
    assert not transport.calls


@pytest.mark.parametrize("status", [301, 302, 307, 412, 500])
def test_upload_never_redirects_or_overwrites_existing_blob(tmp_path, transport, status):
    path = tmp_path / "cipher.age"
    private_bytes(path, b"ciphertext")
    transport.response = Response(status=status)
    with pytest.raises(RecoveryError, match="blob_conditional_create_failed") as observed:
        artifacts.upload_cipher(path, URL, HOST, deadline=time.time() + 5)
    assert sum(call == (HOST, 443) for call in transport.calls) == 1
    assert "NEVER-LOG" not in str(observed.value)


def test_download_validates_authenticated_cipher_and_exclusive_private_output(tmp_path, transport):
    output = tmp_path / "cipher.age"
    payload = b"synthetic ciphertext"
    result = artifacts.download_cipher(URL, HOST, output, digest(payload), deadline=time.time() + 5)
    assert result["sha256"] == digest(payload) and output.read_bytes() == payload
    assert output.stat().st_mode & 0o777 == 0o600
    calls = list(transport.calls)
    with pytest.raises(RecoveryError):
        artifacts.download_cipher(URL, HOST, output, digest(payload), deadline=time.time() + 5)
    assert transport.calls == calls and output.read_bytes() == payload


@pytest.mark.parametrize("defect", ["redirect", "oversized", "missing-size", "wrong-size", "wrong-sha", "bad-etag"])
def test_download_malformed_or_unauthenticated_transfer_fails_and_retains_partials(
    tmp_path, transport, monkeypatch, defect
):
    headers = {}
    if defect == "oversized":
        headers["Content-Length"] = "999999999999"
    elif defect == "missing-size":
        headers["Content-Length"] = ""
    elif defect == "wrong-size":
        headers["Content-Length"] = "2"
    elif defect == "bad-etag":
        headers["ETag"] = "NEVER-LOG-THIS?sig=private"
    transport.response = Response(status=302 if defect == "redirect" else 200, headers=headers)
    output = tmp_path / "partial.age"
    sha = "0" * 64 if defect == "wrong-sha" else digest(b"synthetic ciphertext")
    with pytest.raises(RecoveryError) as observed:
        artifacts.download_cipher(URL, HOST, output, sha, deadline=time.time() + 5)
    assert "NEVER-LOG" not in str(observed.value)
    if defect in {"wrong-size", "wrong-sha"}:
        assert output.exists()
    else:
        assert not output.exists()


def test_transport_errors_never_include_sas_in_public_error(tmp_path, transport, monkeypatch):
    def fail(*_a):
        raise http.client.HTTPException(URL)

    monkeypatch.setattr(Response, "read", fail)
    with pytest.raises(RecoveryError, match="^blob_download_failed$") as observed:
        artifacts.download_cipher(
            URL, HOST, tmp_path / "partial", digest(b"synthetic ciphertext"), deadline=time.time() + 5
        )
    assert "NEVER-LOG" not in str(observed.value)


def test_expired_deadlines_do_not_create_artifacts_or_connections(snapshot, crypto, tmp_path, transport):
    with pytest.raises(RecoveryError):
        artifacts.encrypt_snapshot(
            snapshot.root, tmp_path / "expired.age", RECIPIENT, age_command=crypto.command, deadline=0
        )
    with pytest.raises(RecoveryError):
        artifacts.download_cipher(URL, HOST, tmp_path / "expired-download", "0" * 64, deadline=0)
    assert (
        not (tmp_path / "expired.age").exists() and not (tmp_path / "expired-download").exists() and not transport.calls
    )


def test_plaintext_archive_is_deterministic_with_fake_age_and_private_extraction(snapshot, crypto, tmp_path):
    first, receipt = encrypted(snapshot, crypto, tmp_path)
    second = tmp_path / "second.age"
    artifacts.encrypt_snapshot(snapshot.root, second, RECIPIENT, age_command=crypto.command, deadline=time.time() + 15)
    assert first.read_bytes() == second.read_bytes()
    restored = tmp_path / "restored"
    artifacts.decrypt_snapshot(
        first, crypto.identity, restored, receipt["sha256"], age_command=crypto.command, deadline=time.time() + 15
    )
    assert all(path.stat().st_mode & 0o777 == 0o700 for path in restored.rglob("*") if path.is_dir())


def test_encryption_output_cannot_mutate_the_validated_snapshot_tree(snapshot, crypto):
    output = snapshot.root / "cipher.age"
    with pytest.raises(RecoveryError, match="cipher_output_inside_snapshot"):
        artifacts.encrypt_snapshot(
            snapshot.root, output, RECIPIENT, age_command=crypto.command, deadline=time.time() + 15
        )
    assert not output.exists() and artifacts.validate_snapshot(snapshot.root) == snapshot.manifest


def test_identity_detection_carries_across_stream_chunk_boundaries(snapshot):
    path = snapshot.root / "postgres.dump"
    payload = b"x" * (artifacts.CHUNK - 4) + SECRET.encode()
    path.write_bytes(payload)
    snapshot.manifest["files"]["postgres.dump"] = {"sha256": digest(payload), "bytes": len(payload), "mode": "0600"}
    (snapshot.root / "manifest.json").write_text(json.dumps(snapshot.manifest))
    with pytest.raises(RecoveryError, match="snapshot_contains_age_identity"):
        artifacts.validate_snapshot(snapshot.root)


def test_crypto_size_bound_keeps_partial_cipher(snapshot, crypto, tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, "MAX_CIPHER_BYTES", 20)
    output = tmp_path / "partial.age"
    with pytest.raises(RecoveryError, match="cipher_size_bound"):
        artifacts.encrypt_snapshot(
            snapshot.root, output, RECIPIENT, age_command=crypto.command, deadline=time.time() + 15
        )
    assert output.exists() and output.stat().st_size <= 20


@pytest.mark.parametrize("operation", ["upload", "download"])
def test_tls_connection_failures_are_redacted_and_create_no_download(tmp_path, transport, monkeypatch, operation):
    def fail(*_a, **_kw):
        raise OSError(URL)

    monkeypatch.setattr(artifacts.http.client, "HTTPSConnection", fail)
    path = tmp_path / "cipher.age"
    private_bytes(path, b"synthetic ciphertext")
    output = tmp_path / "download.age"
    with pytest.raises(RecoveryError, match=f"^blob_{operation}_failed$") as observed:
        if operation == "upload":
            artifacts.upload_cipher(path, URL, HOST, deadline=time.time() + 5)
        else:
            artifacts.download_cipher(URL, HOST, output, digest(path.read_bytes()), deadline=time.time() + 5)
    assert "NEVER-LOG" not in str(observed.value) and not output.exists()


def test_optional_override_and_regular_zero_length_state_roundtrip(snapshot, crypto, tmp_path):
    for name, payload in (("state/docker-compose.override.yml", b"services: {}\n"), ("state/data/empty", b"")):
        private_bytes(snapshot.root / name, payload)
        snapshot.payloads[name] = payload
        snapshot.manifest["files"][name] = {"sha256": digest(payload), "bytes": len(payload), "mode": "0600"}
    (snapshot.root / "manifest.json").write_text(json.dumps(snapshot.manifest))
    cipher, receipt = encrypted(snapshot, crypto, tmp_path)
    result = artifacts.decrypt_snapshot(
        cipher,
        crypto.identity,
        tmp_path / "restored",
        receipt["sha256"],
        age_command=crypto.command,
        deadline=time.time() + 15,
    )
    assert result["manifest"] == snapshot.manifest


def test_encoded_control_character_in_blob_path_refuses_before_connect(tmp_path, transport):
    path = tmp_path / "cipher.age"
    private_bytes(path, b"synthetic ciphertext")
    with pytest.raises(RecoveryError, match="blob_path_invalid"):
        artifacts.upload_cipher(path, f"https://{HOST}/container/%0aobject?sig=private", HOST, deadline=time.time() + 5)
    assert not transport.calls


def test_impossible_file_directory_manifest_rejected_before_any_extraction(snapshot, crypto, tmp_path):
    for name in ("state/data/collision", "state/data/collision/child"):
        snapshot.payloads[name] = b"synthetic collision proof"
        snapshot.manifest["files"][name] = {
            "sha256": digest(snapshot.payloads[name]),
            "bytes": len(snapshot.payloads[name]),
            "mode": "0600",
        }
    cipher, sha = private_cipher(tmp_path, tar_payload(snapshot))
    with pytest.raises(RecoveryError, match="snapshot_file_directory_collision"):
        artifacts.decrypt_snapshot(
            cipher,
            crypto.identity,
            tmp_path / "must-not-exist",
            sha,
            age_command=crypto.command,
            deadline=time.time() + 15,
        )
    assert not (tmp_path / "must-not-exist").exists()


def test_encryption_prevalidation_digest_honors_deadline_before_crypto_or_output(
    snapshot, crypto, tmp_path, monkeypatch
):
    now = time.time()
    clock = {"now": now}
    original_open = Path.open
    target = snapshot.root / "postgres.dump"

    class DelayedRead:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.stream.close()

        def read(self, count):
            clock["now"] += 4
            return self.stream.read(count)

    def open_with_delay(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        return DelayedRead(stream) if path == target else stream

    monkeypatch.setattr(Path, "open", open_with_delay)
    monkeypatch.setattr(artifacts.time, "time", lambda: clock["now"])
    output = tmp_path / "must-not-exist.age"
    with pytest.raises(RecoveryError, match="operation_deadline_reached"):
        artifacts.encrypt_snapshot(snapshot.root, output, RECIPIENT, age_command=crypto.command, deadline=now + 3)
    assert not output.exists() and not crypto.argv.exists()


@pytest.mark.parametrize(
    "pax",
    [
        {"comment": "X" * 65536},
        {"comment": "small ignored metadata must also fail"},
        {"size": "99999999"},
        {"mtime": "1234567890.5"},
        {"path": "state/data/" + "x" * 10000},
        {"path": "../escape"},
    ],
)
def test_pax_metadata_is_rejected_before_tarfile_allocation(snapshot, crypto, tmp_path, monkeypatch, pax):
    payload = tar_payload(snapshot, mutate=lambda member: setattr(member, "pax_headers", pax))
    cipher, sha = private_cipher(tmp_path, payload)
    monkeypatch.setattr(artifacts, "MAX_CLEAR_BYTES", 4096)
    monkeypatch.setattr(artifacts, "MAX_MANIFEST_BYTES", 8192)

    def parser_must_not_receive_extension(*_a, **_kw):
        pytest.fail("unverified PAX reached tarfile allocation")

    monkeypatch.setattr(tarfile.TarInfo, "_proc_pax", parser_must_not_receive_extension)
    with pytest.raises(RecoveryError):
        artifacts.decrypt_snapshot(
            cipher,
            crypto.identity,
            tmp_path / "must-not-exist",
            sha,
            age_command=crypto.command,
            deadline=time.time() + 15,
        )
    assert not (tmp_path / "must-not-exist").exists()


@pytest.mark.parametrize("field", ["comment", "uname"])
def test_age_identity_in_ignored_metadata_cannot_enter_restore(snapshot, crypto, tmp_path, field):
    def metadata(member):
        if field == "comment":
            member.pax_headers = {"comment": SECRET}
        else:
            member.uname = SECRET

    cipher, sha = private_cipher(tmp_path, tar_payload(snapshot, mutate=metadata))
    with pytest.raises(RecoveryError, match="snapshot_contains_age_identity"):
        artifacts.decrypt_snapshot(
            cipher,
            crypto.identity,
            tmp_path / "must-not-exist",
            sha,
            age_command=crypto.command,
            deadline=time.time() + 15,
        )
    assert not (tmp_path / "must-not-exist").exists()


def test_generated_long_path_pax_remains_supported(snapshot, crypto, tmp_path):
    name = "state/data/" + "/".join(["long-component"] * 12) + "/synthetic-state"
    path = snapshot.root / name
    parent = snapshot.root
    for component in path.parent.relative_to(snapshot.root).parts:
        parent /= component
        parent.mkdir(mode=0o700, exist_ok=True)
    payload = b"long path synthetic evidence"
    private_bytes(path, payload)
    snapshot.manifest["files"][name] = {"sha256": digest(payload), "bytes": len(payload), "mode": "0600"}
    (snapshot.root / "manifest.json").write_text(json.dumps(snapshot.manifest))
    cipher, receipt = encrypted(snapshot, crypto, tmp_path)
    artifacts.decrypt_snapshot(
        cipher,
        crypto.identity,
        tmp_path / "restored",
        receipt["sha256"],
        age_command=crypto.command,
        deadline=time.time() + 15,
    )
    assert (tmp_path / "restored" / name).read_bytes() == payload


def test_private_age_identity_in_manifest_metadata_is_rejected_before_encryption(snapshot, crypto, tmp_path):
    snapshot.manifest["ignored-metadata"] = SECRET
    (snapshot.root / "manifest.json").write_text(json.dumps(snapshot.manifest))
    with pytest.raises(RecoveryError, match="snapshot_contains_age_identity"):
        artifacts.encrypt_snapshot(
            snapshot.root,
            tmp_path / "must-not-exist.age",
            RECIPIENT,
            age_command=crypto.command,
            deadline=time.time() + 15,
        )
    assert not (tmp_path / "must-not-exist.age").exists() and not crypto.argv.exists()


@pytest.mark.parametrize("kind", [tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE])
def test_other_tar_extensions_are_rejected_before_extraction(snapshot, crypto, tmp_path, kind):
    cipher, sha = private_cipher(tmp_path, tar_payload(snapshot, [("state/data/extension", kind, b"ignored", 0o600)]))
    with pytest.raises(RecoveryError):
        artifacts.decrypt_snapshot(
            cipher,
            crypto.identity,
            tmp_path / "must-not-exist",
            sha,
            age_command=crypto.command,
            deadline=time.time() + 15,
        )
    assert not (tmp_path / "must-not-exist").exists()


@pytest.mark.parametrize("dump_bytes", [2048, 12288])
def test_standard_tar_record_padding_roundtrips(snapshot, crypto, tmp_path, dump_bytes):
    payload = b"p" * dump_bytes
    snapshot.payloads["postgres.dump"] = payload
    snapshot.manifest["files"]["postgres.dump"] = {"sha256": digest(payload), "bytes": len(payload), "mode": "0600"}
    cipher, sha = private_cipher(tmp_path, tar_payload(snapshot))
    result = artifacts.decrypt_snapshot(
        cipher, crypto.identity, tmp_path / "restored", sha, age_command=crypto.command, deadline=time.time() + 15
    )
    assert result["manifest"] == snapshot.manifest
    assert (tmp_path / "restored/postgres.dump").read_bytes() == payload


def test_generated_encryption_accepts_twenty_one_eof_padding_blocks(snapshot, crypto, tmp_path):
    # Find a real record alignment from the actual manifest serialization,
    # rather than fabricating end padding that our encryptor never produces.
    for blocks in range(1, 41):
        payload = b"p" * (blocks * tarfile.BLOCKSIZE)
        snapshot.manifest["files"]["postgres.dump"] = {"sha256": digest(payload), "bytes": len(payload), "mode": "0600"}
        manifest_bytes = (json.dumps(snapshot.manifest, sort_keys=True, indent=2) + "\n").encode()
        sizes = [len(manifest_bytes), *(item["bytes"] for item in snapshot.manifest["files"].values())]
        occupied_blocks = len(sizes) + sum((size + 511) // 512 for size in sizes)
        if occupied_blocks % 20 == 19:
            break
    else:
        pytest.fail("fixture could not construct a standard tar record boundary")
    (snapshot.root / "postgres.dump").write_bytes(payload)
    (snapshot.root / "manifest.json").write_bytes(manifest_bytes)
    cipher, receipt = encrypted(snapshot, crypto, tmp_path)
    clear_tar = gzip.decompress(cipher.read_bytes()[len(PREFIX) :])
    assert (len(clear_tar) - len(clear_tar.rstrip(b"\0"))) // tarfile.BLOCKSIZE == 21
    artifacts.decrypt_snapshot(
        cipher,
        crypto.identity,
        tmp_path / "restored",
        receipt["sha256"],
        age_command=crypto.command,
        deadline=time.time() + 15,
    )
    assert (tmp_path / "restored/postgres.dump").read_bytes() == payload


def test_excessive_tar_padding_still_fails_before_destination(snapshot, crypto, tmp_path):
    raw = gzip.decompress(tar_payload(snapshot)) + b"\0" * (tarfile.RECORDSIZE + tarfile.BLOCKSIZE)
    cipher, sha = private_cipher(tmp_path, gzip.compress(raw, mtime=0))
    with pytest.raises(RecoveryError, match="padding_bound|trailing_data"):
        artifacts.decrypt_snapshot(
            cipher,
            crypto.identity,
            tmp_path / "must-not-exist",
            sha,
            age_command=crypto.command,
            deadline=time.time() + 15,
        )
    assert not (tmp_path / "must-not-exist").exists()
