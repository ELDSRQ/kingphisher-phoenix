"""Private synthetic backup streams; no crypto output, identity or SAS is logged."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import http.client
import json
import os
import re
import ssl
import stat
import subprocess
import tarfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO, cast
from urllib.parse import unquote, urlsplit

from common import (
    MAX_CIPHER_BYTES,
    MAX_CLEAR_BYTES,
    MAX_FILES,
    MAX_MANIFEST_BYTES,
    RUNTIME_COMMIT,
    SNAPSHOT_SCHEMA,
    RecoveryError,
    canonical,
    clean_environment,
    private_directory,
    private_file,
    relative_name,
    remaining,
    require,
    unused,
)

CHUNK = 64 * 1024
MANDATORY = {"postgres.dump", "globals.sql", "redis.rdb", "redis-inventory.json", "state/.env"}
IDENTITY_MARKER = b"AGE-SECRET-KEY-"
MAX_PAX_BYTES = 8 * 1024


def _sha(value: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "expected_cipher_sha256_required")
    return value


def _recipient(value: str) -> str:
    require(
        isinstance(value, str) and re.fullmatch(r"age1[ac-hj-np-z02-9]{58}", value), "classic_age_recipient_required"
    )
    return value


def _name(value: str) -> str:
    relative_name(value)
    require(
        value in MANDATORY
        or value in {"manifest.json", "state/docker-compose.override.yml"}
        or value.startswith("state/data/"),
        "snapshot_member_outside_synthetic_layout",
    )
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "snapshot_manifest_duplicate_key")
        result[key] = value
    return result


def _manifest(raw: bytes) -> dict[str, Any]:
    require(len(raw) <= MAX_MANIFEST_BYTES, "snapshot_manifest_bound")
    require(IDENTITY_MARKER not in raw, "snapshot_contains_age_identity")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, RecursionError, UnicodeError):
        raise RecoveryError("snapshot_manifest_invalid_json") from None
    require(isinstance(value, dict), "snapshot_manifest_not_object")
    require(
        value.get("schema") == SNAPSHOT_SCHEMA
        and value.get("scope") == "synthetic-qualification"
        and {"run_id", "created_at", "application", "source", "data", "files"} <= value.keys(),
        "snapshot_manifest_identity_invalid",
    )
    require(
        isinstance(value["run_id"], str) and 0 < len(value["run_id"]) <= 128,
        "snapshot_run_id_invalid",
    )
    require(
        all(isinstance(value[key], dict) and value[key] for key in ("application", "source", "data")),
        "snapshot_metadata_missing",
    )
    application = value["application"]
    require(
        application.get("runtime_commit") == RUNTIME_COMMIT
        and isinstance(application.get("bundle_commit"), str)
        and re.fullmatch(r"[0-9a-f]{40}", application["bundle_commit"])
        and isinstance(application.get("schema_head"), str)
        and application["schema_head"]
        and application.get("source_root") == "/srv/kp-cleanlinux/clean-target",
        "snapshot_application_identity_invalid",
    )
    files = value["files"]
    require(isinstance(files, dict) and files.keys() >= MANDATORY and len(files) <= MAX_FILES, "snapshot_files_invalid")
    total = 0
    for name, item in files.items():
        _name(name)
        require(name != "manifest.json", "manifest_cannot_manifest_itself")
        require(isinstance(item, dict) and set(item) == {"sha256", "bytes", "mode"}, "snapshot_file_metadata_invalid")
        require(
            isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]),
            "snapshot_file_sha_invalid",
        )
        require(type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_CLEAR_BYTES, "snapshot_file_size_invalid")
        require(isinstance(item["mode"], str) and item["mode"] in {"0600", "0700"}, "snapshot_file_mode_invalid")
        total += item["bytes"]
    require(total <= MAX_CLEAR_BYTES, "snapshot_clear_byte_bound")
    require(not set(files).intersection(_ancestors(set(files))), "snapshot_file_directory_collision")
    return cast(dict[str, Any], value)


def _digest_stream(stream: BinaryIO, size: int, deadline: float | None = None) -> str:
    digest = hashlib.sha256()
    carry = b""
    consumed = 0
    while block := stream.read(min(CHUNK, size - consumed + 1)):
        if deadline is not None:
            remaining(deadline)
        consumed += len(block)
        require(consumed <= size, "snapshot_file_size_drift")
        require(IDENTITY_MARKER not in carry + block, "snapshot_contains_age_identity")
        carry = (carry + block)[-len(IDENTITY_MARKER) :]
        digest.update(block)
    require(consumed == size, "snapshot_file_size_drift")
    return digest.hexdigest()


def _ancestors(names: set[str]) -> set[str]:
    return {str(parent) for name in names for parent in Path(name).parents if str(parent) != "."}


def validate_snapshot(snapshot: Path, *, deadline: float | None = None) -> dict[str, Any]:
    """Verify the whole private synthetic tree without modifying any member."""
    if deadline is not None:
        remaining(deadline)
    private_directory(snapshot)
    manifest_path = private_file(snapshot / "manifest.json")
    require(manifest_path.stat().st_size <= MAX_MANIFEST_BYTES, "snapshot_manifest_bound")
    manifest = _manifest(manifest_path.read_bytes())
    expected = set(manifest["files"]) | {"manifest.json"}
    directories = _ancestors(expected)
    found: set[str] = set()
    total = 0
    for path in snapshot.rglob("*"):
        if deadline is not None:
            remaining(deadline)
        canonical(path)
        name = path.relative_to(snapshot).as_posix()
        info = path.stat()
        if stat.S_ISDIR(info.st_mode):
            require(name in directories, "snapshot_extra_directory")
            continue
        private_file(path)
        _name(name)
        require(name in expected and name not in found, "snapshot_extra_or_duplicate_file")
        found.add(name)
        require(len(found) <= MAX_FILES + 1, "snapshot_file_count_bound")
        if name == "manifest.json":
            continue
        item = manifest["files"][name]
        require(
            info.st_size == item["bytes"] and stat.S_IMODE(info.st_mode) == int(item["mode"], 8), "snapshot_file_drift"
        )
        total += info.st_size
        require(total <= MAX_CLEAR_BYTES, "snapshot_clear_byte_bound")
        with path.open("rb") as stream:
            require(_digest_stream(stream, info.st_size, deadline) == item["sha256"], "snapshot_file_sha_drift")
    require(found == expected, "snapshot_members_missing")
    return manifest


class _DecodedTarReader:
    """Bound decoded bytes and inspect extensions before tarfile can allocate."""

    def __init__(self, stream: BinaryIO, deadline: float):
        self.stream = stream
        self.deadline = deadline
        self.buffer = b""
        self.carry = b""
        self.total = 0
        self.headers = 0
        self.payload_left = 0
        self.zeros = 0
        self.pending_path = False
        self.eof = False
        # Include explicitly bounded regular-header/padding and optional PAX
        # overhead, rather than letting ignored metadata escape byte accounting.
        self.limit = (
            MAX_CLEAR_BYTES + MAX_MANIFEST_BYTES + MAX_FILES * (1024 + 512 + MAX_PAX_BYTES) + tarfile.RECORDSIZE
        )

    def _take(self, size: int) -> bytes:
        remaining(self.deadline)
        data = self.stream.read(size)
        remaining(self.deadline)
        self.total += len(data)
        require(self.total <= self.limit, "snapshot_decoded_tar_bound")
        require(IDENTITY_MARKER not in self.carry + data, "snapshot_contains_age_identity")
        self.carry = (self.carry + data)[-len(IDENTITY_MARKER) :]
        return data

    @staticmethod
    def _pax(raw: bytes) -> None:
        # Our deterministic writer needs only UTF-8/long-path records. Reject
        # comments, size overrides, global headers and other ignored metadata.
        offset = 0
        names: set[str] = set()
        while offset < len(raw):
            delimiter = raw.find(b" ", offset)
            require(delimiter != -1 and delimiter - offset <= 6, "snapshot_pax_record_invalid")
            length = raw[offset:delimiter]
            require(length.isdigit() and not length.startswith(b"0"), "snapshot_pax_record_invalid")
            end = offset + int(length)
            require(delimiter < end <= len(raw) and raw[end - 1 : end] == b"\n", "snapshot_pax_record_invalid")
            key, separator, value = raw[delimiter + 1 : end - 1].partition(b"=")
            require(key == b"path" and separator == b"=" and "path" not in names, "snapshot_pax_metadata_unsupported")
            try:
                path = value.decode("utf-8")
            except UnicodeError:
                raise RecoveryError("snapshot_pax_path_invalid") from None
            _name(path)
            names.add("path")
            offset = end
        require(names == {"path"}, "snapshot_pax_record_invalid")

    def _next(self) -> bytes:
        if self.payload_left:
            count = min(CHUNK, self.payload_left)
            data = self._take(count)
            require(len(data) == count, "snapshot_tar_payload_truncated")
            self.payload_left -= len(data)
            return data
        block = self._take(tarfile.BLOCKSIZE)
        if not block:
            require(self.zeros >= 2 and not self.pending_path, "snapshot_tar_end_missing")
            self.eof = True
            return b""
        require(len(block) == tarfile.BLOCKSIZE, "snapshot_tar_header_truncated")
        if not any(block):
            require(not self.pending_path, "snapshot_pax_without_file")
            self.zeros += 1
            # Two EOF blocks plus record rounding can span21zero blocks.
            # tarfile consumes the first before our separate tail bound runs.
            require(self.zeros <= tarfile.RECORDSIZE // tarfile.BLOCKSIZE + 1, "snapshot_tar_padding_bound")
            return block
        require(self.zeros == 0, "snapshot_tar_trailing_data")
        self.headers += 1
        require(self.headers <= MAX_FILES * 8 + 1, "snapshot_tar_member_bound")
        try:
            info = tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
        except tarfile.HeaderError:
            raise RecoveryError("snapshot_tar_header_invalid") from None
        require(info.size >= 0 and not info.linkname, "snapshot_tar_header_invalid")
        if info.type == tarfile.XHDTYPE:
            require(not self.pending_path and 0 < info.size <= MAX_PAX_BYTES, "snapshot_pax_extension_bound")
            require(info.name == "././@PaxHeader", "snapshot_pax_header_unsupported")
            count = ((info.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
            data = self._take(count)
            require(len(data) == count and not any(data[info.size :]), "snapshot_pax_payload_invalid")
            self._pax(data[: info.size])
            self.pending_path = True
            return block + data
        require(
            info.type in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE},
            "snapshot_tar_extension_unsupported",
        )
        require(not self.pending_path or info.isfile(), "snapshot_pax_without_file")
        self.pending_path = False
        require(info.size <= MAX_CLEAR_BYTES + MAX_MANIFEST_BYTES, "snapshot_clear_byte_bound")
        if info.isdir():
            require(info.size == 0, "snapshot_tar_directory_payload")
        self.payload_left = ((info.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
        return block

    def read(self, size: int = -1) -> bytes:
        require(0 < size <= CHUNK, "snapshot_tar_read_bound")
        while len(self.buffer) < size and not self.eof:
            self.buffer += self._next()
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


def _archive(stream: BinaryIO, *, deadline: float, destination: Path | None = None) -> dict[str, Any]:
    """Read to gzip EOF, including tar padding; never extract before validation."""
    seen: set[str] = set()
    directories: set[str] = set()
    records: dict[str, dict[str, Any]] = {}
    manifest: dict[str, Any] | None = None
    total = 0
    try:
        with (
            gzip.GzipFile(fileobj=stream, mode="rb") as zipped,
            tarfile.open(
                fileobj=cast(BinaryIO, _DecodedTarReader(cast(BinaryIO, zipped), deadline)), mode="r|", bufsize=512
            ) as archive,
        ):
            for member in archive:
                remaining(deadline)
                name = relative_name(member.name.rstrip("/") if member.isdir() else member.name)
                require(name not in seen, "snapshot_duplicate_tar_member")
                seen.add(name)
                require(len(seen) <= MAX_FILES * 8 + 1, "snapshot_tar_member_bound")
                if member.isdir():
                    require(member.mode == 0o700, "snapshot_directory_mode_invalid")
                    directories.add(name)
                    continue
                _name(name)
                require(member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}, "snapshot_tar_nonregular_member")
                require(member.mode in {0o600, 0o700} and member.size >= 0, "snapshot_tar_file_mode_or_size")
                total += member.size
                require(total <= MAX_CLEAR_BYTES + MAX_MANIFEST_BYTES, "snapshot_clear_byte_bound")
                data = archive.extractfile(member)
                require(data is not None, "snapshot_tar_payload_missing")
                if name == "manifest.json":
                    require(member.size <= MAX_MANIFEST_BYTES, "snapshot_manifest_bound")
                    raw = cast(BinaryIO, data).read()
                    require(IDENTITY_MARKER not in raw, "snapshot_contains_age_identity")
                    manifest = _manifest(raw)
                    if destination is not None:
                        _write_member(destination, name, member.mode, iter((raw,)))
                else:
                    verified = _ArchiveReader(cast(BinaryIO, data), deadline)
                    if destination is None:
                        for _ in _reader_blocks(verified):
                            pass
                    else:
                        _write_member(destination, name, member.mode, _reader_blocks(verified))
                    require(verified.count == member.size, "snapshot_tar_payload_size")
                    records[name] = {
                        "sha256": verified.digest.hexdigest(),
                        "bytes": verified.count,
                        "mode": f"{member.mode:04o}",
                    }
                    require(len(records) <= MAX_FILES, "snapshot_file_count_bound")
            # Read through the tar stream's buffer and gzip CRC/EOF. A
            # second archive or hidden nonzero trailing bytes are refused.
            padding = 0
            tail = cast(BinaryIO, archive.fileobj)
            while block := tail.read(CHUNK):
                remaining(deadline)
                padding += len(block)
                require(padding <= tarfile.RECORDSIZE and not any(block), "snapshot_tar_trailing_data")
        if manifest is None:
            raise RecoveryError("snapshot_manifest_missing")
        require(records == manifest["files"], "snapshot_tar_manifest_mismatch")
        require(directories <= _ancestors(set(records) | {"manifest.json"}), "snapshot_extra_directory")
        return manifest
    except (tarfile.TarError, EOFError, OSError, ValueError):
        raise RecoveryError("snapshot_archive_invalid") from None


def _write_member(destination: Path, name: str, mode: int, blocks: Iterator[bytes]) -> None:
    path = destination / name
    parent = destination
    for part in path.parent.relative_to(destination).parts:
        parent /= part
        parent.mkdir(mode=0o700, exist_ok=True)
        private_directory(parent)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as stream:
        for block in blocks:
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())


def _identity(path: Path) -> int:
    private_file(path)
    require(
        stat.S_IMODE(path.stat().st_mode) in {0o400, 0o600} and path.stat().st_size <= 16 * 1024,
        "age_identity_file_invalid",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        text = os.read(descriptor, 16 * 1024 + 1).decode("ascii")
        lines = [line for line in text.splitlines() if line and not line.startswith("#")]
        require(
            len(lines) == 1 and re.fullmatch(r"AGE-SECRET-KEY-1[AC-HJ-NP-Z02-9]{58}", lines[0]),
            "classic_age_identity_required",
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except (UnicodeError, RecoveryError):
        os.close(descriptor)
        raise RecoveryError("age_identity_file_invalid") from None


def _cipher(path: Path, expected: str | None = None, *, deadline: float) -> tuple[BinaryIO, str, int]:
    if expected is not None:
        _sha(expected)
    private_file(path)
    stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb")
    try:
        size = os.fstat(stream.fileno()).st_size
        require(0 < size <= MAX_CIPHER_BYTES, "cipher_size_bound")
        hasher = hashlib.sha256()
        consumed = 0
        while block := stream.read(CHUNK):
            remaining(deadline)
            consumed += len(block)
            require(consumed <= size, "cipher_changed_during_read")
            hasher.update(block)
        require(consumed == size, "cipher_changed_during_read")
        digest = hasher.hexdigest()
        require(expected is None or digest == expected, "cipher_sha256_mismatch")
        stream.seek(0)
        return stream, digest, size
    except Exception:
        stream.close()
        raise


@contextlib.contextmanager
def _age(
    command: str,
    arguments: list[str],
    deadline: float,
    *,
    stdin: BinaryIO | int = subprocess.PIPE,
    pass_fds: tuple[int, ...] = (),
) -> Iterator[subprocess.Popen[bytes]]:
    require(isinstance(command, str) and command and "\0" not in command, "age_command_invalid")
    seconds = min(1800, remaining(deadline, reserve=2))
    try:
        # Crypto streams intentionally bypass command diagnostics (record=False
        # semantics). Stderr is discarded, not retained or sent to a public log.
        process = subprocess.Popen(  # noqa: S603 - reviewed age argv; no shell or private key contents
            [command, *arguments],
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=clean_environment(),
            pass_fds=pass_fds,
        )
    except OSError:
        raise RecoveryError("age_could_not_start") from None
    expired = threading.Event()

    def terminate() -> None:
        expired.set()
        with contextlib.suppress(OSError):
            process.kill()

    timer = threading.Timer(seconds, terminate)
    timer.daemon = True
    timer.start()
    try:
        yield process
        process.wait(timeout=max(0.1, remaining(deadline)))
        require(not expired.is_set() and process.returncode == 0, "age_operation_failed_or_timed_out")
    except (OSError, subprocess.TimeoutExpired):
        raise RecoveryError("age_operation_failed_or_timed_out") from None
    finally:
        timer.cancel()
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=2)
        for pipe in (process.stdin, process.stdout):
            if pipe is not None:
                pipe.close()


def _output(path: Path) -> BinaryIO:
    private_directory(path.parent)
    unused(path)
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")


def _copy_cipher(stream: BinaryIO, output: BinaryIO, deadline: float) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    while block := stream.read(CHUNK):
        remaining(deadline)
        size += len(block)
        require(size <= MAX_CIPHER_BYTES, "cipher_size_bound")
        output.write(block)
        digest.update(block)
    output.flush()
    os.fsync(output.fileno())
    require(size > 0, "cipher_empty")
    return {"sha256": digest.hexdigest(), "bytes": size}


class _ArchiveReader:
    def __init__(self, stream: BinaryIO, deadline: float | None):
        self.stream = stream
        self.deadline = deadline
        self.digest = hashlib.sha256()
        self.count = 0
        self.carry = b""

    def read(self, size: int = -1) -> bytes:
        if self.deadline is not None:
            remaining(self.deadline)
        block = self.stream.read(size)
        require(IDENTITY_MARKER not in self.carry + block, "snapshot_contains_age_identity")
        self.carry = (self.carry + block)[-len(IDENTITY_MARKER) :]
        self.digest.update(block)
        self.count += len(block)
        return block


def _reader_blocks(reader: _ArchiveReader) -> Iterator[bytes]:
    while block := reader.read(CHUNK):
        yield block


def encrypt_snapshot(
    snapshot: Path, output: Path, recipient: str, *, age_command: str, deadline: float
) -> dict[str, Any]:
    remaining(deadline, reserve=2)
    _recipient(recipient)
    manifest = validate_snapshot(snapshot, deadline=deadline)
    require(not output.is_relative_to(snapshot), "cipher_output_inside_snapshot")
    manifest_sha = hashlib.sha256((snapshot / "manifest.json").read_bytes()).hexdigest()
    remaining(deadline, reserve=2)
    errors: list[Exception] = []
    with (
        _output(output) as destination,
        _age(age_command, ["--encrypt", "--recipient", recipient], deadline) as process,
    ):
        require(process.stdin is not None and process.stdout is not None, "age_pipe_missing")
        input_pipe, output_pipe = cast(BinaryIO, process.stdin), cast(BinaryIO, process.stdout)

        def produce() -> None:
            try:
                with (
                    gzip.GzipFile(filename="", fileobj=input_pipe, mode="wb", mtime=0) as zipped,
                    tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive,
                ):
                    for name in ["manifest.json", *sorted(manifest["files"])]:
                        remaining(deadline)
                        path = private_file(snapshot / name)
                        info = tarfile.TarInfo(name)
                        info.size = path.stat().st_size
                        info.mode = stat.S_IMODE(path.stat().st_mode)
                        with path.open("rb") as data:
                            verified = _ArchiveReader(data, deadline)
                            archive.addfile(info, cast(BinaryIO, verified))
                        expected = manifest_sha if name == "manifest.json" else manifest["files"][name]["sha256"]
                        require(
                            verified.count == info.size and verified.digest.hexdigest() == expected,
                            "snapshot_changed_during_encryption",
                        )
                        if name != "manifest.json":
                            require(
                                info.size == manifest["files"][name]["bytes"]
                                and info.mode == int(manifest["files"][name]["mode"], 8),
                                "snapshot_changed_during_encryption",
                            )
            except Exception as error:
                errors.append(error)
                with contextlib.suppress(OSError):
                    process.kill()
            finally:
                with contextlib.suppress(OSError):
                    input_pipe.close()

        writer = threading.Thread(target=produce, daemon=True)
        writer.start()
        try:
            receipt = _copy_cipher(output_pipe, destination, deadline)
        except Exception:
            with contextlib.suppress(OSError):
                process.kill()
            raise
        finally:
            if errors or process.poll() is not None:
                with contextlib.suppress(OSError):
                    process.kill()
            writer.join(timeout=max(0.1, min(2, deadline - time.time())))
        require(not writer.is_alive() and not errors, "snapshot_encryption_stream_failed")
    return {**receipt, "recipient": recipient}


def _decrypt_archive(
    cipher: BinaryIO, identity_fd: int, *, age_command: str, deadline: float, destination: Path | None = None
) -> dict[str, Any]:
    cipher.seek(0)
    os.lseek(identity_fd, 0, os.SEEK_SET)
    with _age(
        age_command,
        ["--decrypt", "--identity", f"/dev/fd/{identity_fd}"],
        deadline,
        stdin=cipher,
        pass_fds=(identity_fd,),
    ) as process:
        require(process.stdout is not None, "age_pipe_missing")
        return _archive(cast(BinaryIO, process.stdout), deadline=deadline, destination=destination)


def decrypt_snapshot(
    cipher: Path, identity: Path, destination: Path, expected_sha256: str, *, age_command: str, deadline: float
) -> dict[str, Any]:
    remaining(deadline, reserve=2)
    _sha(expected_sha256)
    private_directory(destination.parent)
    unused(destination)
    stream, digest, size = _cipher(cipher, expected_sha256, deadline=deadline)
    with stream, contextlib.ExitStack() as stack:
        identity_fd = _identity(identity)
        stack.callback(os.close, identity_fd)
        manifest = _decrypt_archive(stream, identity_fd, age_command=age_command, deadline=deadline)
        remaining(deadline, reserve=2)
        private_directory(destination, create=True)
        extracted = _decrypt_archive(
            stream, identity_fd, age_command=age_command, deadline=deadline, destination=destination
        )
        require(extracted == manifest, "snapshot_changed_between_validation_and_extraction")
        require(validate_snapshot(destination, deadline=deadline) == manifest, "restored_snapshot_validation_failed")
    return {"manifest": manifest, "destination": str(destination), "sha256": digest, "bytes": size}


def rewrap(
    cipher: Path,
    identity: Path,
    recipient: str,
    output: Path,
    expected_sha256: str,
    *,
    age_command: str,
    deadline: float,
) -> dict[str, Any]:
    remaining(deadline, reserve=2)
    _sha(expected_sha256)
    _recipient(recipient)
    private_directory(output.parent)
    unused(output)
    stream, _, _ = _cipher(cipher, expected_sha256, deadline=deadline)
    with stream, contextlib.ExitStack() as stack:
        identity_fd = _identity(identity)
        stack.callback(os.close, identity_fd)
        _decrypt_archive(stream, identity_fd, age_command=age_command, deadline=deadline)
        remaining(deadline, reserve=2)
        stream.seek(0)
        os.lseek(identity_fd, 0, os.SEEK_SET)
        with (
            _output(output) as destination,
            _age(
                age_command,
                ["--decrypt", "--identity", f"/dev/fd/{identity_fd}"],
                deadline,
                stdin=stream,
                pass_fds=(identity_fd,),
            ) as clear,
        ):
            require(clear.stdout is not None, "age_pipe_missing")
            clear_pipe = cast(BinaryIO, clear.stdout)
            with _age(age_command, ["--encrypt", "--recipient", recipient], deadline, stdin=clear_pipe) as encrypted:
                require(encrypted.stdout is not None, "age_pipe_missing")
                clear_pipe.close()
                receipt = _copy_cipher(cast(BinaryIO, encrypted.stdout), destination, deadline)
    return {**receipt, "recipient": recipient}


def _blob(url: str, expected_host: str) -> tuple[str, str]:
    require(
        isinstance(expected_host, str) and re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", expected_host),
        "blob_expected_host_invalid",
    )
    try:
        parsed = urlsplit(url)
        require(
            parsed.scheme == "https"
            and parsed.hostname == expected_host
            and parsed.port in {None, 443}
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
            and parsed.query,
            "blob_url_outside_reviewed_scope",
        )
        decoded = unquote(parsed.path)
        require(decoded.startswith("/") and len(decoded.split("/")) >= 3, "blob_path_invalid")
        relative_name(decoded[1:])
        require(not any(character in decoded for character in "\r\n\0"), "blob_path_invalid")
        require(not any(character in url for character in "\r\n\0"), "blob_url_invalid")
    except (ValueError, AttributeError):
        raise RecoveryError("blob_url_invalid") from None
    return expected_host, parsed.path + "?" + parsed.query


def _timeout(connection: http.client.HTTPSConnection, deadline: float) -> None:
    seconds = min(15, remaining(deadline))
    connection.timeout = seconds
    if connection.sock is not None:
        connection.sock.settimeout(seconds)


def _etag(response: http.client.HTTPResponse) -> str:
    value = response.getheader("ETag", "")
    require(isinstance(value, str) and re.fullmatch(r'"?0x[0-9a-fA-F]{1,32}"?', value), "blob_etag_invalid")
    return value


def upload_cipher(path: Path, url: str, expected_host: str, *, deadline: float) -> dict[str, Any]:
    host, target = _blob(url, expected_host)
    remaining(deadline)
    stream, digest, size = _cipher(path, deadline=deadline)
    connection = None
    try:
        connection = http.client.HTTPSConnection(
            host, 443, timeout=min(15, remaining(deadline)), context=ssl.create_default_context()
        )
        with stream:
            connection.putrequest("PUT", target)
            for key, value in {
                "If-None-Match": "*",
                "x-ms-blob-type": "BlockBlob",
                "x-ms-version": "2023-11-03",
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
            }.items():
                connection.putheader(key, value)
            _timeout(connection, deadline)
            connection.endheaders()
            transferred = hashlib.sha256()
            count = 0
            while block := stream.read(CHUNK):
                count += len(block)
                require(count <= size, "cipher_changed_during_upload")
                _timeout(connection, deadline)
                connection.send(block)
                transferred.update(block)
            require(count == size and transferred.hexdigest() == digest, "cipher_changed_during_upload")
            _timeout(connection, deadline)
            response = connection.getresponse()
            require(response.status == 201, "blob_conditional_create_failed")
            return {"sha256": digest, "bytes": size, "etag": _etag(response)}
    except (OSError, http.client.HTTPException):
        raise RecoveryError("blob_upload_failed") from None
    finally:
        stream.close()
        if connection is not None:
            connection.close()


def download_cipher(
    url: str, expected_host: str, output: Path, expected_sha256: str, *, deadline: float
) -> dict[str, Any]:
    _sha(expected_sha256)
    host, target = _blob(url, expected_host)
    remaining(deadline)
    private_directory(output.parent)
    unused(output)
    connection = None
    try:
        connection = http.client.HTTPSConnection(
            host, 443, timeout=min(15, remaining(deadline)), context=ssl.create_default_context()
        )
        connection.request("GET", target)
        _timeout(connection, deadline)
        response = connection.getresponse()
        require(response.status == 200, "blob_download_status_failed")
        length = response.getheader("Content-Length", "")
        require(isinstance(length, str) and re.fullmatch(r"[1-9][0-9]{0,12}", length), "blob_size_header_invalid")
        require(int(length) <= MAX_CIPHER_BYTES, "cipher_size_bound")
        etag = _etag(response)
        remaining(deadline)
        with _output(output) as destination:
            digest = hashlib.sha256()
            size = 0
            while True:
                _timeout(connection, deadline)
                block = response.read(CHUNK)
                if not block:
                    break
                size += len(block)
                require(size <= int(length) and size <= MAX_CIPHER_BYTES, "blob_size_drift")
                destination.write(block)
                digest.update(block)
            destination.flush()
            os.fsync(destination.fileno())
        require(size == int(length) and digest.hexdigest() == expected_sha256, "cipher_sha256_mismatch")
        return {"sha256": digest.hexdigest(), "bytes": size, "etag": etag}
    except (OSError, http.client.HTTPException):
        raise RecoveryError("blob_download_failed") from None
    finally:
        if connection is not None:
            connection.close()
