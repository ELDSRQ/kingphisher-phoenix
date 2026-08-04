"""re-salt recipient mailbox hashes

Revision ID: 0004_recipient_hash_salt
Revises: 0003_tracking_minimize
Create Date: 2026-08-03

WS-12 / HIGH-06: re-key the persisted `recipients.mailbox_sha256` dedup
hashes from the bare unsalted digest to a salted double-hash. Because the
recipient mailbox is CipherText-encrypted, the rewrite is done without
plaintext: the old persisted value IS the SHA-256 inner digest, so the new
hash is sha256(salt + bytes.fromhex(old)) — identical to `hash_mailbox`.

The salt comes from OPERATOR_API_RECIPIENT_HASH_SALT. On a fresh database
there are no rows, so a missing salt is not an error; existing rows are left
unchanged (and a warning is emitted) if it is absent.
"""

from __future__ import annotations

import hashlib
import os

from alembic import op
from sqlalchemy import text

revision = "0004_recipient_hash_salt"
down_revision = "0003_tracking_minimize"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(text("SELECT recipient_id, mailbox_sha256 FROM recipients")).mappings().all()
    if not rows:
        return
    salt_hex = os.environ.get("OPERATOR_API_RECIPIENT_HASH_SALT", "")
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        salt = b""
    if not salt:
        print("WARNING: OPERATOR_API_RECIPIENT_HASH_SALT unset/invalid; recipients.mailbox_sha256 not re-salted")
        return
    for row in rows:
        old = row["mailbox_sha256"]
        if len(old) != 64:
            continue
        inner = bytes.fromhex(old)
        new_hash = hashlib.sha256(salt + inner).hexdigest()
        bind.execute(
            text("UPDATE recipients SET mailbox_sha256 = :new WHERE recipient_id = :id"),
            {"new": new_hash, "id": row["recipient_id"]},
        )


def downgrade() -> None:
    # The unsalted digests are unrecoverable without the plaintext.
    pass
