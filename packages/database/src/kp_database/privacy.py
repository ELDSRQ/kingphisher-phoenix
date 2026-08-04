"""Data-minimization helpers shared by the tracking API and migrations.

Implements the HIGH-17 / WS-9 retention minimization: event client IPs are
stored as a /24 (IPv4) or /64 (IPv6) prefix instead of the full address, and
user agents are truncated. The salted mailbox hash (WS-12) lives here too so
seeding, CSV import, and migrations agree on the exact construction.
"""

from __future__ import annotations

import hashlib
import ipaddress

CLIENT_IP_MAX = 45
USER_AGENT_MAX_LENGTH = 128


def minimize_ip(value: str | None) -> str | None:
    """Reduce an IP to a coarse prefix so events cannot re-identify a device.

    IPv4 addresses are truncated to the /24 network; IPv6 to the /64 prefix.
    Unparseable values (already-minimized or malformed) are returned unchanged.
    """
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return value[:CLIENT_IP_MAX]
    if isinstance(ip, ipaddress.IPv4Address):
        return str(ipaddress.IPv4Network((ip, 24), strict=False).network_address)
    return str(ipaddress.IPv6Network((ip, 64), strict=False).network_address)


def minimize_user_agent(value: str | None) -> str | None:
    if value is None:
        return None
    return value[:USER_AGENT_MAX_LENGTH]


def hash_mailbox(mailbox: str, salt: bytes) -> str:
    """Deterministic salted SHA-256 of a mailbox for dedup lookups (HIGH-08).

    Double-hashes so the persisted hash from the unsalted era can be re-salted
    in-place by the WS-12 migration without access to the plaintext (the
    recipient mailbox is CipherText-encrypted). With the salt unknown, a DB
    dump alone is not enough for offline dictionary/rainbow attacks.
    """
    inner = hashlib.sha256(mailbox.lower().encode("utf-8")).digest()
    return hashlib.sha256(salt + inner).hexdigest()
