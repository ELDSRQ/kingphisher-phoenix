"""Bounded .test-only SMTP fault injector forwarding solely to loopback Mailpit."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import smtplib
import socketserver
import threading
import time
from pathlib import Path
from typing import Any

MODES = {"pass", "delay", "reject", "disconnect_after_accept"}
MAX_MESSAGE = 1024 * 1024
_ADDRESS = re.compile(r"[^<>\s@]+@(?:[a-z0-9-]+\.)+test\Z", re.I)


def address(command: str) -> str:
    match = re.search(r"<([^<>]+)>", command)
    value = match.group(1) if match else ""
    if not _ADDRESS.fullmatch(value):
        raise ValueError("only synthetic .test envelope addresses are accepted")
    return value


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, endpoint: tuple[str, int], upstream_port: int, control: Path, journal: Path) -> None:
        self.upstream_port, self.control, self.journal = upstream_port, control, journal
        self.slots = threading.BoundedSemaphore(16)
        self.write_lock = threading.Lock()
        super().__init__(endpoint, Handler)

    def mode(self) -> str:
        if self.control.stat().st_size > 128:
            raise ValueError("fault control exceeded bound")
        mode = self.control.read_text().strip()
        if mode not in MODES:
            raise ValueError("invalid fault mode")
        return mode

    def record(self, **value: Any) -> None:
        with self.write_lock, self.journal.open("a") as stream:
            stream.write(json.dumps({"at": time.time(), **value}) + "\n")


class Handler(socketserver.StreamRequestHandler):
    server: Server

    def handle(self) -> None:
        if not self.server.slots.acquire(blocking=False):
            return
        try:
            self.request.settimeout(15)
            self.wfile.write(b"220 qualification SMTP\r\n")
            sender = ""
            recipients: list[str] = []
            for _ in range(10000):
                raw = self.rfile.readline(8193)
                if not raw or len(raw) > 8192:
                    return
                command = raw.decode("ascii", errors="replace").strip()
                verb = command.split(" ", 1)[0].upper()
                if verb in {"EHLO", "HELO"}:
                    self.wfile.write(b"250 qualification\r\n")
                elif verb == "MAIL":
                    sender, recipients = address(command), []
                    self.wfile.write(b"250 sender accepted\r\n")
                elif verb == "RCPT":
                    if len(recipients) >= 1:
                        self.wfile.write(b"452 one recipient per message\r\n")
                    else:
                        recipients.append(address(command))
                        self.wfile.write(b"250 recipient accepted\r\n")
                elif verb == "DATA" and sender and len(recipients) == 1:
                    mode = self.server.mode()
                    if mode == "reject":
                        self.server.record(mode=mode, accepted=False, recipients=recipients)
                        self.wfile.write(b"451 qualification transient refusal\r\n")
                        continue
                    if mode == "delay":
                        self.server.record(mode=mode, event="fault_enter", recipients=recipients)
                        time.sleep(5)
                        self.server.record(mode=mode, event="fault_exit", recipients=recipients)
                    self.wfile.write(b"354 send message\r\n")
                    body = bytearray()
                    while len(body) <= MAX_MESSAGE:
                        line = self.rfile.readline(MAX_MESSAGE + 1)
                        if line == b".\r\n":
                            break
                        if not line:
                            return
                        body.extend(line[1:] if line.startswith(b"..") else line)
                    else:
                        return
                    fingerprint = hashlib.sha256(body).hexdigest()
                    with smtplib.SMTP("127.0.0.1", self.server.upstream_port, timeout=10) as upstream:
                        refused = upstream.sendmail(sender, recipients, bytes(body))
                    if refused:
                        self.wfile.write(b"451 sink refused message\r\n")
                        continue
                    self.server.record(mode=mode, accepted=True, recipients=recipients, fingerprint=fingerprint)
                    if mode == "disconnect_after_accept":
                        return
                    self.wfile.write(b"250 sink accepted\r\n")
                elif verb == "RSET":
                    sender, recipients = "", []
                    self.wfile.write(b"250 reset\r\n")
                elif verb == "QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                elif verb == "NOOP":
                    self.wfile.write(b"250 ok\r\n")
                else:
                    self.wfile.write(b"502 command unavailable\r\n")
        except (OSError, ValueError, smtplib.SMTPException):
            return
        finally:
            self.server.slots.release()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    args = parser.parse_args()
    with Server(("127.0.0.1", args.port), args.upstream_port, args.control, args.journal) as server:
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
