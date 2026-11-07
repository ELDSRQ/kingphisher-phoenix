"""Real loopback listener restarts; bounded sockets, threads and no upstream."""

from __future__ import annotations

import errno
import socket
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/operator/fullstack-qualification"))
from smtp_proxy import Server  # noqa: E402 - import the standalone qualification helper

TIMEOUT = 2


@contextmanager
def running_proxy(endpoint: tuple[str, int], directory: Path) -> Iterator[Server]:
    control = directory / "smtp-mode"
    control.write_text("pass")
    server = Server(endpoint, 1, control, directory / "smtp-journal.jsonl")
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        # shutdown() waits internally without a timeout. Bound that wait even
        # when a failing test never reached an active serve_forever iteration.
        stopper = threading.Thread(target=server.shutdown, daemon=True)
        stopper.start()
        stopper.join(TIMEOUT)
        server.server_close()
        thread.join(TIMEOUT)
        stopper.join(TIMEOUT)
        assert not stopper.is_alive() and not thread.is_alive(), "owned proxy did not stop within bounded joins"


def quit_and_read_server_eof(endpoint: tuple[str, int]) -> None:
    with socket.create_connection(endpoint, timeout=TIMEOUT) as client:
        client.settimeout(TIMEOUT)
        with client.makefile("rb") as replies:
            assert replies.readline(256) == b"220 qualification SMTP\r\n"
            client.sendall(b"QUIT\r\n")
            assert replies.readline(256) == b"221 bye\r\n"
            # The server actively closes first. Closing the client only after
            # its FIN puts the server's connection into the TIME_WAIT path
            # that previously prevented the recovery listener from rebinding.
            assert replies.read(1) == b""


def test_owned_proxy_rebinds_same_port_after_active_quit_close(tmp_path):
    with running_proxy(("127.0.0.1", 0), tmp_path) as first:
        endpoint = first.server_address
        quit_and_read_server_eof(endpoint)
    # No sleep, alternate port, fallback endpoint or retry loop is permitted.
    with running_proxy(endpoint, tmp_path) as restored:
        assert restored.server_address == endpoint
        quit_and_read_server_eof(endpoint)


def test_active_proxy_cannot_be_replaced_and_remains_usable(tmp_path):
    with running_proxy(("127.0.0.1", 0), tmp_path) as first:
        endpoint = first.server_address
        quit_and_read_server_eof(endpoint)
        if hasattr(socket, "SO_REUSEPORT"):
            assert first.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) == 0
        unexpected = None
        try:
            with pytest.raises(OSError) as denied:
                unexpected = Server(endpoint, 1, tmp_path / "smtp-mode", tmp_path / "other-journal.jsonl")
            assert denied.value.errno == errno.EADDRINUSE
        finally:
            if unexpected is not None:
                unexpected.server_close()
        quit_and_read_server_eof(endpoint)
