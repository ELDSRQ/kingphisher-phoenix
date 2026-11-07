"""Bounded read-only old/new-code proof; outputs contain counts, never values."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import cast


def main() -> int:
    from kp_database import models
    from kp_database.audit_store import AuditStore
    from kp_database.base import Base
    from kp_database.session import create_db_engine
    from kp_operator_api.config import OperatorApiSettings
    from sqlalchemy import MetaData, Table, func, inspect, select, text
    from sqlalchemy.orm import Session

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    settings = OperatorApiSettings()
    models.CipherText.configure_keyring(*settings.require_cipher_keyring())
    engine = create_db_engine(settings.database_url)
    audit = create_db_engine(settings.audit_database_url)
    try:
        counts = {}
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            connection.execute(text("SET default_transaction_read_only=on"))
            connection.execute(text("SET statement_timeout='15s'"))
            schema = connection.scalar(text("SELECT version_num FROM alembic_version"))
            for name in inspect(connection).get_table_names(schema="public"):
                counts[name] = int(
                    connection.scalar(select(func.count()).select_from(Table(name, MetaData(), schema="public"))) or 0
                )
        encrypted = {}
        with Session(engine) as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            session.execute(text("SET LOCAL statement_timeout='30s'"))
            for mapper in Base.registry.mappers:
                if any(isinstance(column.type, models.CipherText) for column in mapper.columns):
                    rows = list(session.scalars(select(mapper.class_).limit(10001)))
                    if len(rows) > 10000:
                        raise RuntimeError("encrypted_probe_bound")
                    encrypted[cast(Table, mapper.local_table).name] = len(rows)
        legacy = settings.require_secret_key() if settings.audit_hmac_key else None
        if AuditStore(audit, legacy, intent_engine=engine).verify():
            raise RuntimeError("audit_verification_failed")
        import kp_database

        payload = {
            "passed": True,
            "schema": schema,
            "table_counts": counts,
            "encrypted_entities": encrypted,
            "audit_verified": True,
            "module_path": str(Path(kp_database.__file__).resolve()),
        }
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(payload, output, sort_keys=True)
        print("read-only compatibility proof passed")
        return 0
    except Exception:
        print("read-only compatibility proof failed; inspect worker-private log")
        return 1
    finally:
        engine.dispose()
        audit.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
