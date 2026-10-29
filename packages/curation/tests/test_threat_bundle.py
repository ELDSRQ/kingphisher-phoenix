"""Signed offline curated threat-bundle verification invariants (W3-02).

Pins: a valid signed bundle verifies; a tampered payload (checksum), a forged or
wrong-key signature, and a malformed/oversized envelope are each refused; and the
canonical payload is order-stable. No network is ever used.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kp_curation.threat_bundle import (
    MAX_ARTIFACTS,
    BundleError,
    canonical_payload,
    sign_bundle,
    verify_bundle,
)

_SEED = bytes(range(32))


def _keys() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(_SEED)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _SEED, public


def _artifact() -> dict[str, object]:
    return {
        "title": "URGENT: verify your Microsoft 365 account",
        "origin": "bundle",
        "raw_html": '<p>Click <a href="https://evil.example/login">here</a></p>',
        "parser": "curated/1",
        "parser_version": "curated/1",
        "source": "offline-curated",
        "observed_at": "2026-10-20T00:00:00+00:00",
    }


def _signed(**overrides: object) -> dict[str, object]:
    seed, _ = _keys()
    envelope = sign_bundle(
        bundle_id="bundle-001",
        artifacts=[_artifact()],
        signing_key=seed,
        created_at="2026-10-20T00:00:00+00:00",
    )
    envelope.update(overrides)
    return envelope


def test_valid_bundle_verifies() -> None:
    _, public = _keys()
    verified = verify_bundle(json.dumps(_signed()).encode("utf-8"), verify_key=public)
    assert verified.bundle_id == "bundle-001"
    assert len(verified.artifacts) == 1
    assert verified.artifacts[0].title.startswith("URGENT")
    assert len(verified.checksum) == 64


def test_tampered_payload_fails_checksum() -> None:
    _, public = _keys()
    envelope = _signed()
    # Mutate an artifact after signing: the checksum no longer matches.
    envelope["artifacts"] = [{**_artifact(), "title": "benign newsletter"}]
    with pytest.raises(BundleError, match="checksum"):
        verify_bundle(json.dumps(envelope).encode("utf-8"), verify_key=public)


def test_forged_signature_is_rejected() -> None:
    _, public = _keys()
    # Re-checksum the tampered payload so only the signature check can catch it.
    envelope = _signed()
    envelope["artifacts"] = [{**_artifact(), "title": "attacker inserted"}]
    payload = {
        "bundle_id": envelope["bundle_id"],
        "created_at": envelope["created_at"],
        "artifacts": envelope["artifacts"],
    }
    envelope["checksum"] = hashlib.sha256(canonical_payload(payload)).hexdigest()
    with pytest.raises(BundleError, match="signature"):
        verify_bundle(json.dumps(envelope).encode("utf-8"), verify_key=public)


def test_wrong_public_key_is_rejected() -> None:
    other = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    with pytest.raises(BundleError, match="signature"):
        verify_bundle(json.dumps(_signed()).encode("utf-8"), verify_key=other)


def test_malformed_envelope_is_rejected() -> None:
    _, public = _keys()
    with pytest.raises(BundleError, match="JSON"):
        verify_bundle(b"{not json", verify_key=public)
    with pytest.raises(BundleError, match="required fields"):
        verify_bundle(json.dumps({"bundle_id": "x"}).encode("utf-8"), verify_key=public)


def test_empty_and_oversized_artifact_lists_rejected() -> None:
    seed, public = _keys()
    empty = sign_bundle(bundle_id="b", artifacts=[], signing_key=seed, created_at="2026-10-20T00:00:00+00:00")
    with pytest.raises(BundleError, match="no artifacts"):
        verify_bundle(json.dumps(empty).encode("utf-8"), verify_key=public)
    too_many = sign_bundle(
        bundle_id="b2",
        artifacts=[_artifact() for _ in range(MAX_ARTIFACTS + 1)],
        signing_key=seed,
        created_at="2026-10-20T00:00:00+00:00",
    )
    with pytest.raises(BundleError, match="too many"):
        verify_bundle(json.dumps(too_many).encode("utf-8"), verify_key=public)


def test_canonical_payload_is_key_order_stable() -> None:
    a = canonical_payload({"bundle_id": "b", "created_at": "t", "artifacts": []})
    b = canonical_payload({"artifacts": [], "created_at": "t", "bundle_id": "b"})
    assert a == b
