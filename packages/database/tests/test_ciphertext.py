"""Authenticated ciphertext format and staged key-rotation contracts."""

from __future__ import annotations

import base64
import os

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from kp_database.models import CipherText, CipherTextError

OLD_KEY = b"o" * 32
ACTIVE_KEY = b"a" * 32
OTHER_KEY = b"x" * 32


def _legacy_encrypt(value: str, key: bytes) -> str:
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ciphertext = encryptor.update(value.encode("utf-8")) + encryptor.finalize()
    return base64.urlsafe_b64encode(nonce + encryptor.tag + ciphertext).decode("ascii")


def _codec() -> CipherText:
    return CipherText()


def test_new_writes_are_versioned_and_use_only_the_active_key() -> None:
    CipherText.configure_keyring("active-2", ACTIVE_KEY, {"retired-1": OLD_KEY})

    blob = _codec().process_bind_param("sensitive@example.com", object())

    assert blob is not None
    assert blob.startswith("kpct.1.active-2.")
    assert "sensitive@example.com" not in blob
    assert _codec().process_result_value(blob, object()) == "sensitive@example.com"

    CipherText.configure_keyring("retired-1", OLD_KEY)
    with pytest.raises(CipherTextError, match="key identifier is unavailable"):
        _codec().process_result_value(blob, object())


def test_rotation_reads_versioned_and_legacy_values_with_a_prior_key() -> None:
    CipherText.configure_keyring("old", OLD_KEY)
    versioned_old = CipherText._encrypt("versioned-old")
    legacy_old = _legacy_encrypt("legacy-old", OLD_KEY)

    CipherText.configure_keyring("active", ACTIVE_KEY, {"old": OLD_KEY})

    assert CipherText._decrypt(versioned_old) == "versioned-old"
    assert CipherText._decrypt(legacy_old) == "legacy-old"
    assert CipherText._encrypt("new").startswith("kpct.1.active.")


def test_legacy_value_can_still_use_the_active_key() -> None:
    legacy = _legacy_encrypt("legacy-active", ACTIVE_KEY)
    CipherText.configure_keyring("active", ACTIVE_KEY)

    assert CipherText._decrypt(legacy) == "legacy-active"


def test_payload_and_authenticated_key_identifier_tampering_fail_closed() -> None:
    CipherText.configure_keyring("active", ACTIVE_KEY, {"other": OTHER_KEY})
    blob = CipherText._encrypt("do not disclose")
    header, version, key_id, payload = blob.split(".")
    raw = bytearray(base64.urlsafe_b64decode(payload))
    raw[-1] ^= 1
    tampered_payload = base64.urlsafe_b64encode(raw).decode("ascii")

    with pytest.raises(CipherTextError, match="^CipherText authentication failed$"):
        CipherText._decrypt(".".join((header, version, key_id, tampered_payload)))
    with pytest.raises(CipherTextError, match="^CipherText authentication failed$"):
        CipherText._decrypt(blob.replace(".active.", ".other."))


def test_format_domain_is_authenticated() -> None:
    CipherText.configure_keyring("active", ACTIVE_KEY)
    wrong_context_blob = CipherText._encrypt("context-bound", aad_domain=b"different-domain")

    with pytest.raises(CipherTextError, match="^CipherText authentication failed$"):
        CipherText._decrypt(wrong_context_blob)


def test_wrong_key_fails_without_leaking_ciphertext_or_key_material() -> None:
    CipherText.configure_keyring("active", ACTIVE_KEY)
    blob = CipherText._encrypt("sensitive-value")
    CipherText.configure_keyring("active", OTHER_KEY)

    with pytest.raises(CipherTextError) as caught:
        CipherText._decrypt(blob)

    assert str(caught.value) == "CipherText authentication failed"
    assert "sensitive-value" not in str(caught.value)
    assert blob not in str(caught.value)


@pytest.mark.parametrize(
    ("blob", "message"),
    [
        ("not-base64", "CipherText ciphertext is malformed"),
        ("kpct.1.active", "CipherText ciphertext is malformed"),
        ("kpct.1.bad$id.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", "CipherText ciphertext is malformed"),
        (
            "kpct.2.active.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "CipherText ciphertext version is unsupported",
        ),
    ],
)
def test_malformed_and_unknown_version_errors_are_stable(blob: str, message: str) -> None:
    CipherText.configure_keyring("active", ACTIVE_KEY)

    with pytest.raises(CipherTextError) as caught:
        CipherText._decrypt(blob)

    assert str(caught.value) == message


def test_unknown_key_identifier_fails_before_decryption() -> None:
    CipherText.configure_keyring("retired", OLD_KEY)
    blob = CipherText._encrypt("old-value")
    CipherText.configure_keyring("active", ACTIVE_KEY)

    with pytest.raises(CipherTextError) as caught:
        CipherText._decrypt(blob)

    assert str(caught.value) == "CipherText key identifier is unavailable"
    assert "retired" not in str(caught.value)


def test_legacy_configure_key_api_remains_compatible() -> None:
    CipherText.configure_key(ACTIVE_KEY)

    blob = CipherText._encrypt("compatible")

    assert blob.startswith("kpct.1.default.")
    assert CipherText._decrypt(blob) == "compatible"


@pytest.mark.parametrize(
    ("active_id", "active_key", "prior", "message"),
    [
        ("bad.id", ACTIVE_KEY, {}, "active key identifier is invalid"),
        ("active", b"short", {}, "active key must be 32 bytes"),
        ("active", ACTIVE_KEY, {"active": OLD_KEY}, "key identifiers must be unique"),
        ("active", ACTIVE_KEY, {"bad.id": OLD_KEY}, "prior key identifier is invalid"),
        ("active", ACTIVE_KEY, {"old": b"short"}, "prior keys must be 32 bytes"),
        ("active", ACTIVE_KEY, {"old": ACTIVE_KEY}, "key material must not be reused"),
        (
            "active",
            ACTIVE_KEY,
            {str(index): bytes([index]) * 32 for index in range(1, 6)},
            "supports at most four prior keys",
        ),
    ],
)
def test_keyring_configuration_is_bounded_and_validated(
    active_id: str,
    active_key: bytes,
    prior: dict[str, bytes],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CipherText.configure_keyring(active_id, active_key, prior)
