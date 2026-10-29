"""Signed offline curated threat-bundle verification (W3-02).

An air-gapped or low-trust deployment cannot pull live feeds, so current threats
arrive as a *signed offline curated bundle*: a JSON envelope carrying a set of
artifact descriptors, a SHA-256 ``checksum`` of its canonical payload, and an
Ed25519 ``signature`` over that same canonical payload. Both the checksum and the
signature are verified **before** anything in the bundle is imported — a bundle
that fails either is refused whole, never partially applied.

This module is pure and offline: it parses and cryptographically verifies a
bundle, and (for the curator who assembles one) signs a payload. It performs no
network access and never interprets or fetches the artifact contents it carries;
turning a verified descriptor into a quarantined artifact with a safe preview is
the job of :mod:`kp_curation.threat_library`. Replay protection (refusing a
``bundle_id`` already imported) is enforced at that persistence boundary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Bounds: a hostile or malformed bundle must not be able to exhaust memory. A
# curated bundle is review material, not a bulk archive.
MAX_BUNDLE_BYTES = 8_000_000
MAX_ARTIFACTS = 500
MAX_TITLE_CHARS = 998
MAX_CONTENT_CHARS = 400_000
MAX_FIELD_CHARS = 2_048

_REQUIRED_ENVELOPE_KEYS = frozenset({"bundle_id", "created_at", "artifacts", "checksum", "signature"})
_PAYLOAD_KEYS = ("bundle_id", "created_at", "artifacts")


class BundleError(Exception):
    """Stable, content-free threat-bundle verification failure."""


@dataclass(frozen=True)
class BundleArtifact:
    """One verified artifact descriptor from a signed bundle (not yet made safe)."""

    title: str
    origin: str
    raw_html: str
    plain_text: str | None
    parser: str
    parser_version: str
    source: str
    observed_at: str


@dataclass(frozen=True)
class VerifiedBundle:
    """A bundle whose checksum and signature both verified."""

    bundle_id: str
    created_at: str
    checksum: str
    artifacts: tuple[BundleArtifact, ...]


def canonical_payload(payload: dict[str, Any]) -> bytes:
    """Deterministic, byte-stable serialization of the signed payload.

    Both the signer and the verifier derive the checksum and signature from this
    exact encoding, so key order and whitespace cannot change the bytes.
    """

    reduced = {key: payload[key] for key in _PAYLOAD_KEYS if key in payload}
    return json.dumps(reduced, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _checksum(canonical: bytes) -> str:
    return hashlib.sha256(canonical).hexdigest()


def sign_bundle(
    *,
    bundle_id: str,
    artifacts: list[dict[str, Any]],
    signing_key: bytes,
    created_at: datetime | str,
) -> dict[str, Any]:
    """Assemble a signed bundle envelope for ``artifacts`` (offline curator side).

    ``signing_key`` is a 32-byte Ed25519 private seed. The returned envelope is
    JSON-serializable and verifies under :func:`verify_bundle` with the matching
    public key.
    """

    created = created_at.isoformat() if isinstance(created_at, datetime) else str(created_at)
    payload = {"bundle_id": str(bundle_id), "created_at": created, "artifacts": list(artifacts)}
    canonical = canonical_payload(payload)
    private = Ed25519PrivateKey.from_private_bytes(signing_key)
    signature = private.sign(canonical)
    return {
        **payload,
        "checksum": _checksum(canonical),
        "signature": signature.hex(),
    }


def _coerce_artifact(raw: Any) -> BundleArtifact:
    if not isinstance(raw, dict):
        raise BundleError("bundle artifact is not an object")
    title = str(raw.get("title") or "").strip()
    raw_html = str(raw.get("raw_html") or "")
    plain_text_value = raw.get("plain_text")
    plain_text = str(plain_text_value) if plain_text_value is not None else None
    if not title or len(title) > MAX_TITLE_CHARS:
        raise BundleError("bundle artifact title is missing or too long")
    if not raw_html.strip() and not (plain_text or "").strip():
        raise BundleError("bundle artifact has no content")
    if len(raw_html) > MAX_CONTENT_CHARS or (plain_text is not None and len(plain_text) > MAX_CONTENT_CHARS):
        raise BundleError("bundle artifact content exceeds the supported boundary")
    origin = str(raw.get("origin") or "bundle").strip()[:MAX_FIELD_CHARS]
    parser = str(raw.get("parser") or "bundle").strip()[:MAX_FIELD_CHARS]
    parser_version = str(raw.get("parser_version") or "unknown").strip()[:MAX_FIELD_CHARS]
    source = str(raw.get("source") or "offline-bundle").strip()[:MAX_FIELD_CHARS]
    observed_at = str(raw.get("observed_at") or "").strip()[:MAX_FIELD_CHARS]
    return BundleArtifact(
        title=title[:MAX_TITLE_CHARS],
        origin=origin,
        raw_html=raw_html,
        plain_text=plain_text,
        parser=parser,
        parser_version=parser_version,
        source=source,
        observed_at=observed_at,
    )


def verify_bundle(raw: bytes | str, *, verify_key: bytes) -> VerifiedBundle:
    """Parse and cryptographically verify a signed offline curated bundle.

    Verifies the SHA-256 ``checksum`` and the Ed25519 ``signature`` over the
    canonical payload before returning any artifact. Raises :class:`BundleError`
    on any size, structure, checksum, or signature failure — the caller imports
    only what this returns, so a tampered or forged bundle never reaches import.
    """

    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(data) > MAX_BUNDLE_BYTES:
        raise BundleError("bundle exceeds the supported size boundary")
    try:
        envelope = json.loads(data)
    except (ValueError, UnicodeDecodeError) as error:
        raise BundleError("bundle is not valid JSON") from error
    if not isinstance(envelope, dict) or not set(envelope) >= _REQUIRED_ENVELOPE_KEYS:
        raise BundleError("bundle envelope is missing required fields")

    bundle_id = str(envelope["bundle_id"]).strip()
    created_at = str(envelope["created_at"]).strip()
    if not bundle_id or len(bundle_id) > 255:
        raise BundleError("bundle id is missing or too long")
    artifacts_raw = envelope["artifacts"]
    if not isinstance(artifacts_raw, list) or not artifacts_raw:
        raise BundleError("bundle carries no artifacts")
    if len(artifacts_raw) > MAX_ARTIFACTS:
        raise BundleError("bundle carries too many artifacts")

    canonical = canonical_payload({"bundle_id": bundle_id, "created_at": created_at, "artifacts": artifacts_raw})

    # Checksum first (cheap integrity), then the signature (authenticity).
    expected_checksum = _checksum(canonical)
    provided_checksum = str(envelope["checksum"]).strip().lower()
    if provided_checksum != expected_checksum:
        raise BundleError("bundle checksum does not match its payload")

    try:
        signature = bytes.fromhex(str(envelope["signature"]))
    except ValueError as error:
        raise BundleError("bundle signature is not valid hex") from error
    try:
        Ed25519PublicKey.from_public_bytes(verify_key).verify(signature, canonical)
    except InvalidSignature as error:
        raise BundleError("bundle signature verification failed") from error
    except ValueError as error:
        raise BundleError("bundle verification key is invalid") from error

    artifacts = tuple(_coerce_artifact(item) for item in artifacts_raw)
    return VerifiedBundle(
        bundle_id=bundle_id,
        created_at=created_at,
        checksum=expected_checksum,
        artifacts=artifacts,
    )
