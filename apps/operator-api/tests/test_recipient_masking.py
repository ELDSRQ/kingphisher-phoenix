"""UX-011 §1 — recipient pickers show a masked label, never a raw mailbox.

Display name + masked mailbox appear ONLY for the capability literally named
``view_named:results``. A ``manage:recipients``-only operator keeps the
department/uuid/status shape it always had. The mailbox is never returned raw;
the exact-address lookup matches a salted digest, never a substring.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from kp_authorization.rbac import Principal, Role
from kp_operator_api import routers


def _recipient() -> SimpleNamespace:
    return SimpleNamespace(
        recipient_id=uuid4(),
        department="Finance",
        status=SimpleNamespace(value="active"),
        is_test_account=False,
        display_name="Jane Doe",
        mailbox="jane@corp.example",
        mailbox_sha256="a" * 64,
    )


class _ListSession:
    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self._rows = rows
        self.scalars_statements: list[object] = []

    def scalar(self, _statement: object) -> int:
        return len(self._rows)

    def scalars(self, statement: object) -> list[SimpleNamespace]:
        self.scalars_statements.append(statement)
        return list(self._rows)


def _view_named() -> Principal:
    # security_approver holds VIEW_NAMED_RESULTS (and not MANAGE_RECIPIENTS).
    return Principal(str(uuid4()), {Role.SECURITY_APPROVER})


def _manage_only() -> Principal:
    # campaign_operator holds MANAGE_RECIPIENTS but not VIEW_NAMED_RESULTS.
    return Principal(str(uuid4()), {Role.CAMPAIGN_OPERATOR})


def test_view_named_holder_sees_masked_label() -> None:
    session = _ListSession([_recipient()])
    page = routers.list_recipients(
        limit=100, offset=0, mailbox=None, session=session, settings=object(), principal=_view_named()  # type: ignore[arg-type]
    )
    (item,) = page["items"]
    assert item["display_name"] == "Jane Doe"
    assert item["masked_mailbox"] == "j***@corp.example"
    assert "jane@corp.example" not in str(item)  # raw address never leaks


def test_manage_recipients_only_holder_sees_no_name_or_mailbox() -> None:
    session = _ListSession([_recipient()])
    page = routers.list_recipients(
        limit=100, offset=0, mailbox=None, session=session, settings=object(), principal=_manage_only()  # type: ignore[arg-type]
    )
    (item,) = page["items"]
    assert set(item) == {"recipient_id", "department", "status", "is_test_account"}
    assert "display_name" not in item
    assert "masked_mailbox" not in item


def test_exact_mailbox_lookup_matches_a_salted_digest_not_a_substring() -> None:
    session = _ListSession([_recipient()])
    settings = SimpleNamespace(require_recipient_hash_salt=lambda: b"0" * 16)
    page = routers.list_recipients(
        limit=100,
        offset=0,
        mailbox="Jane@Corp.Example",
        session=session,
        settings=settings,  # type: ignore[arg-type]
        principal=_view_named(),
    )
    assert page["total"] == 1
    assert page["truncated"] is False
    # The query filters on the indexed digest column, never a LIKE/substring.
    rendered = str(session.scalars_statements[-1]).lower()
    assert "mailbox_sha256" in rendered
    assert "like" not in rendered
