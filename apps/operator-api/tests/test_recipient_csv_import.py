from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import uuid4

import pytest
from kp_authorization.rbac import Principal, Role
from kp_database.base import Base
from kp_database.models import CipherText, Recipient
from kp_database.privacy import hash_mailbox
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.recipient_import import (
    MAX_RECIPIENT_CSV_BYTES,
    RecipientCsvError,
    parse_recipient_csv,
    validate_csv_text,
)
from kp_operator_api.routers import (
    RecipientImportApplyRequest,
    RecipientImportPreviewRequest,
    RecipientsImport,
    apply_recipients_csv,
    import_recipients_csv,
    preview_recipients_csv,
)
from kp_telemetry.errors import ConflictError, ValidationError_
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, OperationalError

SALT = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)
_postgres_available: bool | None = None


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    global _postgres_available
    if _postgres_available is None:
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            engine.dispose()
            _postgres_available = True
        except Exception:  # noqa: BLE001 - environment capability gate
            _postgres_available = False
    return _postgres_available


requires_postgres = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key="01" * 32,
        recipient_hash_salt=SALT.hex(),
        allowed_recipient_domains="example.com",
    )


class _Rows:
    def __init__(self, rows: list[Recipient]) -> None:
        self._rows = rows

    def __iter__(self):  # noqa: ANN204
        return iter(self._rows)


class _Dialect:
    def __init__(self, name: str) -> None:
        self.name = name


class _Bind:
    def __init__(self, dialect_name: str) -> None:
        self.dialect = _Dialect(dialect_name)


class _Session:
    def __init__(
        self,
        recipients: list[Recipient] | None = None,
        *,
        dialect_name: str = "sqlite",
        commit_error: Exception | None = None,
    ) -> None:
        self.recipients = list(recipients or [])
        self.added: list[Recipient] = []
        self.commits = 0
        self.rollbacks = 0
        self.executed: list[tuple[str, dict[str, object]]] = []
        self._bind = _Bind(dialect_name)
        self._commit_error = commit_error

    def get_bind(self) -> _Bind:
        return self._bind

    def execute(self, statement: object, params: dict[str, object]) -> None:
        self.executed.append((str(statement), params))

    def scalars(self, statement: object) -> _Rows:
        sql = str(statement)
        params = statement.compile().params  # type: ignore[attr-defined]
        mailbox_hashes = next(
            (
                set(value)
                for key, value in params.items()
                if key.startswith("mailbox_sha256_") and isinstance(value, list)
            ),
            set(),
        )
        active = [recipient for recipient in self.recipients if recipient.deleted_at is None]
        if "WHERE recipients.last_snapshot_source" in sql:
            active = [
                recipient
                for recipient in active
                if recipient.last_snapshot_source == "csv"
                and not recipient.directory_owned
                and recipient.directory_source is None
                and recipient.directory_object_id_hash is None
                and recipient.status is dm.RecipientStatus.ACTIVE
                and recipient.mailbox_sha256 not in mailbox_hashes
            ]
        else:
            active = [recipient for recipient in active if recipient.mailbox_sha256 in mailbox_hashes]
        return _Rows(active)

    def add(self, recipient: Recipient) -> None:
        self.added.append(recipient)
        self.recipients.append(recipient)

    def commit(self) -> None:
        if self._commit_error is not None:
            raise self._commit_error
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(self, **kwargs: object) -> None:
        self.events.append(kwargs)


def _principal() -> Principal:
    return Principal(str(uuid4()), {Role.ADMINISTRATOR})


def _postgres_test_sessions():  # noqa: ANN202
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    CipherText.configure_key(b"c" * 32)
    return engine, make_session_factory(engine)


def _recipient(
    mailbox: str,
    *,
    name: str,
    department: str,
    source: str | None = "csv",
    directory_owned: bool = False,
) -> Recipient:
    return Recipient(
        recipient_id=uuid4(),
        employee_key=mailbox,
        mailbox=mailbox,
        mailbox_sha256=hash_mailbox(mailbox, SALT),
        display_name=name,
        department=department,
        status=dm.RecipientStatus.ACTIVE,
        last_snapshot_source="microsoft365" if directory_owned else source,
        directory_source="microsoft365" if directory_owned else None,
        directory_object_id_hash="a" * 64 if directory_owned else None,
        directory_owned=directory_owned,
    )


def test_parser_detects_conventional_headers_and_resolves_safe_mapping() -> None:
    parsed = parse_recipient_csv(
        "Department,Email Address,Full Name\nEngineering,alice@example.com,Alice Example",
        requested_mapping={},
        default_department=None,
        salt=SALT,
        allowlist=frozenset({"example.com"}),
        unrestricted=False,
    )

    assert parsed.header_detected is True
    assert parsed.mapping == {"mailbox": 1, "display_name": 2, "department": 0}
    assert parsed.input_rows == 1
    assert parsed.recipients[0].mailbox == "alice@example.com"
    assert [column["label"] for column in parsed.columns] == ["Department", "Mailbox", "Name"]


def test_parser_uses_declared_arbitrary_headers_with_explicit_mapping() -> None:
    parsed = parse_recipient_csv(
        "Person label,Org grouping,Login destination\nAlice Example,Engineering,alice@example.com",
        requested_mapping={"mailbox": 2, "display_name": 0, "department": 1},
        default_department=None,
        salt=SALT,
        allowlist=frozenset({"example.com"}),
        unrestricted=False,
        header_mode="first_row",
    )

    assert parsed.header_detected is True
    assert parsed.mapping == {"mailbox": 2, "display_name": 0, "department": 1}
    assert parsed.input_rows == 1
    assert parsed.recipients[0].mailbox == "alice@example.com"
    assert [column["label"] for column in parsed.columns] == [
        "Column 1 — Person label",
        "Column 2 — Org grouping",
        "Column 3 — Login destination",
    ]


def test_parser_keeps_legacy_auto_detection_for_nonstandard_headers() -> None:
    parsed = parse_recipient_csv(
        "Login destination,Person label\nalice@example.com,Alice Example",
        requested_mapping={"mailbox": 0, "display_name": 1},
        default_department=None,
        salt=SALT,
        allowlist=frozenset({"example.com"}),
        unrestricted=False,
    )

    assert parsed.header_detected is False
    assert parsed.input_rows == 2
    assert parsed.invalid == 1
    assert len(parsed.recipients) == 1
    assert [column["label"] for column in parsed.columns] == ["Column 1", "Column 2"]


def test_legacy_route_keeps_create_only_conventional_header_behavior() -> None:
    session = _Session(dialect_name="postgresql")
    audit = _Audit()
    result = import_recipients_csv(
        RecipientsImport(csv_text="Email,Name\nalice@example.com,Alice Example"),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    assert result == {"created": 1, "skipped": 0, "blocked": 0, "errors": []}
    assert len(session.added) == 1
    assert "pg_advisory_xact_lock" in session.executed[0][0]
    options = audit.events[0]["detail"]["options"]  # type: ignore[index]
    assert options["header_mode"] == "auto"
    assert options["legacy_skip_only"] is True


def test_parser_returns_bounded_non_pii_row_errors() -> None:
    parsed = parse_recipient_csv(
        "Email,Name\nnot-a-mailbox,Invalid\nblocked@outside.test,Blocked\nalice@example.com,Alice\nALICE@example.com,Duplicate",
        requested_mapping={},
        default_department="Engineering",
        salt=SALT,
        allowlist=frozenset({"example.com"}),
        unrestricted=False,
    )

    assert (parsed.invalid, parsed.blocked, parsed.duplicate) == (1, 1, 1)
    assert [(issue.row, issue.code) for issue in parsed.errors] == [
        (2, "invalid_mailbox"),
        (3, "domain_not_allowed"),
        (5, "duplicate_mailbox"),
    ]
    assert "outside.test" not in str(parsed.errors)
    assert "alice@example.com" not in str(parsed.errors)


def test_parser_enforces_utf8_transport_bound() -> None:
    with pytest.raises(RecipientCsvError, match="UTF-8 bytes"):
        validate_csv_text("é" * (MAX_RECIPIENT_CSV_BYTES // 2 + 1))


def test_parser_enforces_record_count_bound() -> None:
    csv_text = "\n".join(f"user{index}@example.com" for index in range(5_001))
    with pytest.raises(RecipientCsvError, match="at most 5000 rows"):
        parse_recipient_csv(
            csv_text,
            requested_mapping={},
            default_department=None,
            salt=SALT,
            allowlist=frozenset({"example.com"}),
            unrestricted=False,
        )


def test_preview_and_apply_bind_exact_plan_and_soft_deactivate_only_csv_owned() -> None:
    existing = _recipient("existing@example.com", name="Old Name", department="Old")
    directory = _recipient(
        "directory@example.com",
        name="Directory Name",
        department="Directory",
        directory_owned=True,
    )
    missing_csv = _recipient("missing@example.com", name="Missing", department="Legacy")
    manual = _recipient("manual@example.com", name="Manual", department="Manual", source=None)
    session = _Session([existing, directory, missing_csv, manual])
    audit = _Audit()
    preview_body = RecipientImportPreviewRequest(
        csv_text=(
            "Email,Name,Department\n"
            "new@example.com,New Person,Engineering\n"
            "existing@example.com,Updated Name,Security\n"
            "directory@example.com,CSV Must Not Win,Wrong"
        ),
        merge_existing="update",
        deactivate_missing=True,
    )

    preview = preview_recipients_csv(
        preview_body,
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    assert preview["counts"] == {
        "created": 1,
        "updateable": 1,
        "existing": 1,
        "blocked": 0,
        "invalid": 0,
        "duplicate": 0,
        "deactivateable": 1,
    }
    assert session.added == []
    assert existing.display_name == "Old Name"
    assert directory.display_name == "Directory Name"
    assert "example.com" not in str(audit.events[0]["detail"])
    assert set(audit.events[0]["detail"]) == {"counts", "options", "preview_digest", "input_rows"}

    with pytest.raises(ValidationError_, match="second explicit confirmation"):
        apply_recipients_csv(
            RecipientImportApplyRequest(
                **preview_body.model_dump(exclude={"mapping"}),
                mapping=preview["mapping"],
                preview_digest=preview["preview_digest"],
                deactivate_missing_confirm=False,
            ),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            settings=_settings(),
            principal=_principal(),
        )

    result = apply_recipients_csv(
        RecipientImportApplyRequest(
            **preview_body.model_dump(exclude={"mapping"}),
            mapping=preview["mapping"],
            preview_digest=preview["preview_digest"],
            deactivate_missing_confirm=True,
        ),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    assert result["applied"] is True
    assert len(session.added) == 1
    assert session.added[0].last_snapshot_source == "csv"
    assert existing.display_name == "Updated Name"
    assert existing.department == "Security"
    assert directory.display_name == "Directory Name"
    assert directory.status is dm.RecipientStatus.ACTIVE
    assert missing_csv.status is dm.RecipientStatus.DEPARTED
    assert manual.status is dm.RecipientStatus.ACTIVE
    assert all(recipient.deleted_at is None for recipient in session.recipients)


def test_apply_acquires_stable_postgres_advisory_lock_before_replanning() -> None:
    session = _Session(dialect_name="postgresql")
    audit = _Audit()
    preview_body = RecipientImportPreviewRequest(csv_text="Email\nalice@example.com")
    preview = preview_recipients_csv(
        preview_body,
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    result = apply_recipients_csv(
        RecipientImportApplyRequest(
            **preview_body.model_dump(exclude={"mapping"}),
            mapping=preview["mapping"],
            preview_digest=preview["preview_digest"],
        ),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    assert result["applied"] is True
    statement, params = session.executed[0]
    assert "SELECT pg_advisory_xact_lock(:recipient_import_lock_key)" in statement
    assert params == {"recipient_import_lock_key": int.from_bytes(b"KPRCIMPT", "big")}


class _SerializationFailure(RuntimeError):
    sqlstate = "40001"


@pytest.mark.parametrize(
    ("dialect_name", "commit_error"),
    [
        ("sqlite", IntegrityError("insert", {}, RuntimeError("unique recipient"))),
        ("postgresql", OperationalError("commit", {}, _SerializationFailure("serialization lost"))),
    ],
)
def test_apply_translates_uniqueness_and_serialization_loss_to_repreview_conflict(
    dialect_name: str,
    commit_error: Exception,
) -> None:
    preview_body = RecipientImportPreviewRequest(csv_text="Email\nalice@example.com")
    preview = preview_recipients_csv(
        preview_body,
        session=_Session(),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )
    session = _Session(dialect_name=dialect_name, commit_error=commit_error)

    with pytest.raises(ConflictError, match="state changed concurrently; preview the import again"):
        apply_recipients_csv(
            RecipientImportApplyRequest(
                **preview_body.model_dump(exclude={"mapping"}),
                mapping=preview["mapping"],
                preview_digest=preview["preview_digest"],
            ),
            session=session,  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            settings=_settings(),
            principal=_principal(),
        )

    assert session.rollbacks == 1


def test_apply_rejects_changed_options_or_recipient_state() -> None:
    existing = _recipient("existing@example.com", name="Old", department="Old")
    session = _Session([existing])
    audit = _Audit()
    preview_body = RecipientImportPreviewRequest(
        csv_text="Email,Name\nexisting@example.com,New",
        merge_existing="skip",
    )
    preview = preview_recipients_csv(
        preview_body,
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    with pytest.raises(ConflictError, match="preview the import again"):
        apply_recipients_csv(
            RecipientImportApplyRequest(
                csv_text=preview_body.csv_text,
                merge_existing="update",
                preview_digest=preview["preview_digest"],
            ),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            settings=_settings(),
            principal=_principal(),
        )

    existing.department = "Changed after preview"
    with pytest.raises(ConflictError, match="preview the import again"):
        apply_recipients_csv(
            RecipientImportApplyRequest(
                **preview_body.model_dump(exclude={"mapping"}),
                mapping=preview["mapping"],
                preview_digest=preview["preview_digest"],
            ),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            settings=_settings(),
            principal=_principal(),
        )


def test_explicit_header_mode_is_bound_to_preview_and_apply_digest() -> None:
    missing_csv = _recipient("missing@example.com", name="Missing", department="Legacy")
    session = _Session([missing_csv])
    audit = _Audit()
    preview_body = RecipientImportPreviewRequest(
        csv_text="Person label,Org grouping,Login destination\nAlice Example,Engineering,alice@example.com",
        header_mode="first_row",
        mapping={"mailbox": 2, "display_name": 0, "department": 1},
        deactivate_missing=True,
    )
    preview = preview_recipients_csv(
        preview_body,
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    assert preview["header_mode"] == "first_row"
    assert preview["header_detected"] is True
    assert preview["counts"]["created"] == 1
    assert preview["counts"]["deactivateable"] == 1
    assert preview["can_apply"] is True
    assert "Login destination" in str(preview["columns"])
    assert "Login destination" not in str(audit.events[0]["detail"])
    assert audit.events[0]["detail"]["options"]["header_mode"] == "first_row"  # type: ignore[index]

    with pytest.raises(ConflictError, match="preview the import again"):
        apply_recipients_csv(
            RecipientImportApplyRequest(
                csv_text=preview_body.csv_text,
                header_mode="none",
                mapping=preview_body.mapping,
                preview_digest=preview["preview_digest"],
                deactivate_missing=True,
                deactivate_missing_confirm=True,
            ),
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            settings=_settings(),
            principal=_principal(),
        )

    result = apply_recipients_csv(
        RecipientImportApplyRequest(
            **preview_body.model_dump(),
            preview_digest=preview["preview_digest"],
            deactivate_missing_confirm=True,
        ),
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )
    assert result["applied"] is True
    assert len(session.added) == 1
    assert missing_csv.status is dm.RecipientStatus.DEPARTED


def test_deactivation_requires_a_clean_preview() -> None:
    session = _Session([_recipient("missing@example.com", name="Missing", department="Security")])
    preview_body = RecipientImportPreviewRequest(
        csv_text="Email\ninvalid\nblocked@outside.test",
        deactivate_missing=True,
    )
    preview = preview_recipients_csv(
        preview_body,
        session=session,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    assert preview["can_apply"] is False
    assert preview["counts"]["deactivateable"] == 0
    with pytest.raises(ConflictError, match="clean preview"):
        apply_recipients_csv(
            RecipientImportApplyRequest(
                **preview_body.model_dump(exclude={"mapping"}),
                mapping=preview["mapping"],
                preview_digest=preview["preview_digest"],
                deactivate_missing_confirm=True,
            ),
            session=session,  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            settings=_settings(),
            principal=_principal(),
        )


@pytest.mark.postgres
@requires_postgres
def test_postgres_concurrent_create_applies_serialize_to_one_commit() -> None:
    engine, sessions = _postgres_test_sessions()
    try:
        preview_body = RecipientImportPreviewRequest(csv_text="Email\nalice@example.com")
        with sessions() as session:
            preview = preview_recipients_csv(
                preview_body,
                session=session,
                audit=_Audit(),  # type: ignore[arg-type]
                settings=_settings(),
                principal=_principal(),
            )
        apply_body = RecipientImportApplyRequest(
            **preview_body.model_dump(exclude={"mapping"}),
            mapping=preview["mapping"],
            preview_digest=preview["preview_digest"],
        )

        def apply_once() -> str:
            with sessions() as session:
                try:
                    apply_recipients_csv(
                        apply_body,
                        session=session,
                        audit=_Audit(),  # type: ignore[arg-type]
                        settings=_settings(),
                        principal=_principal(),
                    )
                    return "applied"
                except ConflictError as exc:
                    assert "preview" in exc.message
                    return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(lambda _: apply_once(), range(2))) == ["applied", "conflict"]
        with sessions() as session:
            assert session.scalar(select(func.count()).select_from(Recipient)) == 1
    finally:
        engine.dispose()


@pytest.mark.postgres
@requires_postgres
def test_postgres_create_commits_before_deactivate_replan_or_forces_repreview() -> None:
    engine, sessions = _postgres_test_sessions()
    create_planned = Event()
    allow_create_commit = Event()
    deactivate_started = Event()

    class _BlockingAudit(_Audit):
        def record(self, **kwargs: object) -> None:
            super().record(**kwargs)
            create_planned.set()
            assert allow_create_commit.wait(timeout=10)

    try:
        with sessions() as session:
            session.add(_recipient("stale@example.com", name="Stale", department="Legacy"))
            session.commit()
        create_preview_body = RecipientImportPreviewRequest(csv_text="Email\nnew@example.com")
        deactivate_preview_body = RecipientImportPreviewRequest(
            csv_text="Email\nstale@example.com",
            deactivate_missing=True,
        )
        with sessions() as session:
            create_preview = preview_recipients_csv(
                create_preview_body,
                session=session,
                audit=_Audit(),  # type: ignore[arg-type]
                settings=_settings(),
                principal=_principal(),
            )
        with sessions() as session:
            deactivate_preview = preview_recipients_csv(
                deactivate_preview_body,
                session=session,
                audit=_Audit(),  # type: ignore[arg-type]
                settings=_settings(),
                principal=_principal(),
            )
        assert deactivate_preview["counts"]["deactivateable"] == 0
        create_apply = RecipientImportApplyRequest(
            **create_preview_body.model_dump(exclude={"mapping"}),
            mapping=create_preview["mapping"],
            preview_digest=create_preview["preview_digest"],
        )
        deactivate_apply = RecipientImportApplyRequest(
            **deactivate_preview_body.model_dump(exclude={"mapping"}),
            mapping=deactivate_preview["mapping"],
            preview_digest=deactivate_preview["preview_digest"],
            deactivate_missing_confirm=True,
        )

        def create() -> str:
            with sessions() as session:
                apply_recipients_csv(
                    create_apply,
                    session=session,
                    audit=_BlockingAudit(),  # type: ignore[arg-type]
                    settings=_settings(),
                    principal=_principal(),
                )
                return "applied"

        def deactivate() -> str:
            deactivate_started.set()
            with sessions() as session:
                try:
                    apply_recipients_csv(
                        deactivate_apply,
                        session=session,
                        audit=_Audit(),  # type: ignore[arg-type]
                        settings=_settings(),
                        principal=_principal(),
                    )
                    return "applied"
                except ConflictError as exc:
                    assert "preview" in exc.message
                    return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            create_future = pool.submit(create)
            assert create_planned.wait(timeout=10)
            deactivate_future = pool.submit(deactivate)
            assert deactivate_started.wait(timeout=10)
            allow_create_commit.set()
            assert create_future.result(timeout=10) == "applied"
            assert deactivate_future.result(timeout=10) == "conflict"

        with sessions() as session:
            rows = list(session.scalars(select(Recipient).order_by(Recipient.mailbox_sha256)))
            assert len(rows) == 2
            assert all(recipient.status is dm.RecipientStatus.ACTIVE for recipient in rows)
    finally:
        allow_create_commit.set()
        engine.dispose()


def test_preview_payload_is_count_only_and_never_contains_recipient_values() -> None:
    response = preview_recipients_csv(
        RecipientImportPreviewRequest(csv_text="Email,Name\nalice@example.com,Alice Example"),
        session=_Session(),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        settings=_settings(),
        principal=_principal(),
    )

    serialized = str(response)
    assert "alice@example.com" not in serialized
    assert "Alice Example" not in serialized
    assert response["counts"]["created"] == 1
    assert response["errors"] == []
