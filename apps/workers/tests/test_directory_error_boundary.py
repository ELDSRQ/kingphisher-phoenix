from __future__ import annotations

import uuid
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any

import pytest
from kp_workers import directory_jobs
from kp_workers.providers.graph import DirectorySyncResult, DirectoryUser, GraphRequestError, GraphRetryLimitError


class _Session:
    def __init__(self) -> None:
        self.commits = 0

    def commit(self) -> None:
        self.commits += 1


class _AuditStore:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **values: Any) -> None:
        self.records.append(values)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (GraphRetryLimitError("private retry URL"), "provider_retry_exhausted"),
        (GraphRequestError("Bearer do-not-persist"), "provider_request_failed"),
        (ValueError("/private/config/path"), "provider_response_invalid"),
        (TimeoutError("https://provider.invalid/private"), "provider_timeout"),
        (ConnectionError("password=do-not-persist"), "provider_connection_failed"),
        (RuntimeError("Traceback: do-not-persist"), "provider_fetch_failed"),
    ],
)
def test_directory_failure_codes_are_fixed_and_do_not_retain_exception_details(
    failure: Exception, expected: str
) -> None:
    assert directory_jobs._directory_error_code(failure) == expected


def test_preview_persists_only_fixed_failure_code(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "password=directory-secret https://provider.invalid/private/key.pem Traceback"
    failure_type = type("SecretDirectoryFailure", (RuntimeError,), {})
    failure = failure_type(secret)
    session = _Session()
    state = SimpleNamespace(
        cursor="encrypted-cursor",
        last_attempt_at=None,
        updated_at=None,
        status="never",
        last_error=None,
        last_counts={},
        pending_preview_id="preview",
        pending_preview_hash="hash",
        pending_payload="encrypted",
        pending_created_at=None,
        pending_expires_at=None,
        last_job_key=None,
        config_fingerprint="fingerprint",
    )
    audit = _AuditStore()
    settings = SimpleNamespace()
    context = SimpleNamespace(
        settings=settings,
        session_factory=lambda: nullcontext(session),
        audit_store=audit,
    )
    monkeypatch.setattr(
        directory_jobs,
        "_scope",
        lambda _ctx: ("scope", "fingerprint", "m365:source", ()),
    )
    monkeypatch.setattr(directory_jobs, "_state", lambda *_args, **_kwargs: state)

    def fail_fetch(*_args: Any, **_kwargs: Any) -> None:
        raise failure

    monkeypatch.setattr(directory_jobs, "_fetch", fail_fetch)

    with pytest.raises(failure_type):
        directory_jobs.preview_directory(
            context,
            requested_by="11111111-1111-4111-8111-111111111111",
            job_id="22222222-2222-4222-8222-222222222222",
        )

    assert state.status == "error"
    assert state.last_error == "provider_fetch_failed"
    assert state.last_counts == {"accepted": 0, "rejected": 0}
    assert state.pending_payload is None
    assert audit.records[-1]["detail"] == {"error_code": "provider_fetch_failed"}
    rendered = repr((state.last_error, audit.records))
    assert secret not in rendered
    assert "provider.invalid" not in rendered
    assert "private/key.pem" not in rendered
    assert "Traceback" not in rendered
    assert "SecretDirectoryFailure" not in rendered


def _directory_result(mailbox: str) -> DirectorySyncResult:
    return DirectorySyncResult(
        users=(
            DirectoryUser(
                employee_key=f"entra-{mailbox}",
                mailbox=mailbox,
                display_name="Learner",
                department="Security",
                account_enabled=True,
                user_type="Member",
                mail=mailbox,
                user_principal_name=mailbox,
            ),
        ),
        removals=(),
        cursor=f"cursor-{mailbox}",
        cursor_kind="delta",
        complete=True,
        truncated=False,
        rejected_count=0,
        pages=1,
    )


def _race_context() -> tuple[SimpleNamespace, SimpleNamespace, _Session, _AuditStore]:
    state = SimpleNamespace(
        cursor="starting-cursor",
        last_attempt_at=None,
        last_success_at=None,
        updated_at=None,
        status="never",
        last_error=None,
        last_counts={},
        last_job_key=None,
        config_fingerprint="fingerprint",
        pending_preview_id=None,
        pending_preview_hash=None,
        pending_payload=None,
        pending_created_at=None,
        pending_expires_at=None,
    )
    session = _Session()
    audit = _AuditStore()
    settings = SimpleNamespace(recipient_domain_allowlist=lambda: frozenset({"example.com"}))
    context = SimpleNamespace(
        settings=settings,
        session_factory=lambda: nullcontext(session),
        audit_store=audit,
    )
    return context, state, session, audit


def test_older_success_cannot_overwrite_newer_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    context, state, _session, audit = _race_context()
    monkeypatch.setattr(directory_jobs, "_scope", lambda _ctx: ("scope", "fingerprint", "m365:source", ()))
    monkeypatch.setattr(directory_jobs, "_state", lambda *_args, **_kwargs: state)
    fetches = 0

    def interleaved_fetch(_ctx: object, _cursor: str | None, _groups: tuple[str, ...]) -> tuple[Any, dict[str, Any]]:
        nonlocal fetches
        fetches += 1
        if fetches == 1:
            newer = directory_jobs.preview_directory(
                context,
                requested_by="33333333-3333-4333-8333-333333333333",
                job_id="44444444-4444-4444-8444-444444444444",
            )
            assert newer["status"] == "preview_ready"
            return _directory_result("older@example.com"), {}
        return _directory_result("newer@example.com"), {}

    monkeypatch.setattr(directory_jobs, "_fetch", interleaved_fetch)

    older = directory_jobs.preview_directory(
        context,
        requested_by="11111111-1111-4111-8111-111111111111",
        job_id="22222222-2222-4222-8222-222222222222",
    )

    assert older == {"status": "superseded", "counts": {}}
    assert state.status == "preview_ready"
    assert "newer@example.com" in state.pending_payload
    assert "older@example.com" not in state.pending_payload
    assert state.last_job_key == "44444444-4444-4444-8444-444444444444"
    assert len(audit.records) == 1
    assert audit.records[0]["detail"]["requested_by"] == "33333333-3333-4333-8333-333333333333"


def test_older_failure_cannot_clear_or_retry_newer_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    context, state, _session, audit = _race_context()
    monkeypatch.setattr(directory_jobs, "_scope", lambda _ctx: ("scope", "fingerprint", "m365:source", ()))
    monkeypatch.setattr(directory_jobs, "_state", lambda *_args, **_kwargs: state)
    fetches = 0

    def interleaved_fetch(_ctx: object, _cursor: str | None, _groups: tuple[str, ...]) -> tuple[Any, dict[str, Any]]:
        nonlocal fetches
        fetches += 1
        if fetches == 1:
            newer = directory_jobs.preview_directory(
                context,
                requested_by="33333333-3333-4333-8333-333333333333",
                job_id="44444444-4444-4444-8444-444444444444",
            )
            assert newer["status"] == "preview_ready"
            raise RuntimeError("password=obsolete https://provider.invalid/private Traceback")
        return _directory_result("newer@example.com"), {}

    monkeypatch.setattr(directory_jobs, "_fetch", interleaved_fetch)

    older = directory_jobs.preview_directory(
        context,
        requested_by="11111111-1111-4111-8111-111111111111",
        job_id="22222222-2222-4222-8222-222222222222",
    )

    assert older == {"status": "superseded", "counts": {}}
    assert state.status == "preview_ready"
    assert state.last_error is None
    assert "newer@example.com" in state.pending_payload
    assert state.last_job_key == "44444444-4444-4444-8444-444444444444"
    assert len(audit.records) == 1
    assert audit.records[0]["action"] == "directory.preview"


@pytest.mark.parametrize(
    "payload",
    [
        "not-an-object",
        {"action": "preview", "job_id": "password=secret", "requested_by": "not-a-uuid"},
        {
            "action": "preview",
            "job_id": "22222222-2222-4222-8222-222222222222",
            "requested_by": "https://provider.invalid/private/token",
        },
        {
            "job_id": "22222222-2222-4222-8222-222222222222",
            "requested_by": "11111111-1111-4111-8111-111111111111",
        },
    ],
)
def test_directory_queue_rejects_malformed_untrusted_metadata_before_persistence(
    monkeypatch: pytest.MonkeyPatch, payload: object
) -> None:
    persisted = False

    def unexpected_scope(_ctx: object) -> tuple[str, str, str, tuple[str, ...]]:
        nonlocal persisted
        persisted = True
        raise AssertionError("directory state must not be touched")

    monkeypatch.setattr(directory_jobs, "_scope", unexpected_scope)

    with pytest.raises(RuntimeError, match="directory job"):
        directory_jobs.process_directory_sync(SimpleNamespace(), {"payload": payload})

    assert persisted is False


def test_stale_discard_job_cannot_remove_a_newer_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    current_preview_id = uuid.UUID("33333333-3333-4333-8333-333333333333")
    state = SimpleNamespace(
        pending_preview_id=current_preview_id,
        pending_preview_hash="current-hash",
        pending_payload="encrypted-current-payload",
        pending_created_at=None,
        pending_expires_at=None,
        status="preview_ready",
    )
    session = _Session()
    audit = _AuditStore()
    context = SimpleNamespace(
        session_factory=lambda: nullcontext(session),
        audit_store=audit,
    )
    monkeypatch.setattr(
        directory_jobs,
        "_scope",
        lambda _ctx: ("scope", "fingerprint", "m365:source", ()),
    )
    monkeypatch.setattr(directory_jobs, "_state", lambda *_args, **_kwargs: state)

    with pytest.raises(RuntimeError, match="missing, stale or already discarded"):
        directory_jobs.discard_directory_preview(
            context,
            preview_id="44444444-4444-4444-8444-444444444444",
            requested_by="11111111-1111-4111-8111-111111111111",
            job_id="22222222-2222-4222-8222-222222222222",
        )

    assert state.pending_preview_id == current_preview_id
    assert state.pending_payload == "encrypted-current-payload"
    assert state.status == "preview_ready"
    assert session.commits == 0
    assert audit.records == []
