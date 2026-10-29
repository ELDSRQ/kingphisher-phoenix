"""Keep the operator-facing docs aligned with the canonical worker-role manifest.

KP-AUD-020 / KP-AUD-022-docs. The worker-role count and the reply-availability
statements in README.md, docs/OPERATOR-GUIDE.md, and
docs/D6-HUMAN-ACCEPTANCE-SCRIPT.md had drifted from the code: the docs claimed
ten worker roles (dropping ``reply-mailbox``) and that replies were
unavailable, when the reply-ingestion worker is in fact built and surfaced.

This test asserts the docs reflect the *single source of truth* for the worker
roles — ``kp_database.grants.RUNTIME_ROLES`` (the per-workload PostgreSQL login
matrix), minus the two non-worker runtime logins ``operator`` and ``tracking``.
That same set is mirrored by ``kp_workers.__main__.WORKERS`` and
``kp_contracts.queue.DEFAULT_QUEUE_TOPICS``; this test pins the docs to it so a
new or removed worker role fails here until the docs are regenerated.

It is intentionally lightweight and hermetic (no database, no network): it reads
the three docs from disk and the role set from pure in-memory data.
"""

from __future__ import annotations

from pathlib import Path

from kp_database import grants

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

#: Non-worker runtime logins in the grant matrix (the API and the tracking
#: boundary); everything else in RUNTIME_ROLES is a supervised worker role.
_NON_WORKER_RUNTIME_LOGINS = frozenset({"operator", "tracking"})


def _canonical_worker_roles() -> set[str]:
    return set(grants.RUNTIME_ROLES) - _NON_WORKER_RUNTIME_LOGINS


def _read(relative: str) -> str:
    return (REPOSITORY_ROOT / relative).read_text(encoding="utf-8")


def _normalized(text: str) -> str:
    """Lower-cased, whitespace-collapsed so wrapped prose matches one phrase."""
    return " ".join(text.split()).lower()


def test_canonical_registry_has_eleven_worker_roles() -> None:
    # Guards the premise of this task: the manifest defines eleven worker roles,
    # and reply-mailbox is one of them.
    roles = _canonical_worker_roles()
    assert len(roles) == 11, sorted(roles)
    assert "reply-mailbox" in roles


def test_readme_lists_every_canonical_worker_role() -> None:
    readme = _read("README.md")
    missing = sorted(role for role in _canonical_worker_roles() if role not in readme)
    assert not missing, f"README.md does not mention worker roles: {missing}"


def test_readme_states_eleven_worker_roles() -> None:
    readme = _normalized(_read("README.md"))
    assert "eleven worker roles" in readme
    # The stale count must not reappear as plain prose.
    assert "ten worker roles" not in readme


def test_operator_guide_reply_statement_is_accurate() -> None:
    guide = _normalized(_read("docs/OPERATOR-GUIDE.md"))
    # The old, false claim must be gone...
    assert "replies are currently unavailable" not in guide
    assert "reply ingestion has not been built" not in guide
    # ...and the reply capability must be described with its mode qualifier.
    assert "reply-mailbox" in guide
    assert "reply mailbox is configured" in guide


def test_d6_script_reply_statement_is_accurate() -> None:
    script = _normalized(_read("docs/D6-HUMAN-ACCEPTANCE-SCRIPT.md"))
    # The old, false claims must be gone...
    assert "replies are explicitly unavailable" not in script
    assert "reply monitoring is unavailable" not in script
    # ...replaced by the built-but-mode-gated description...
    assert "recipient-reply ingestion is built" in script
    assert "reply-mailbox" in script
    # ...while the human-acceptance gate stays open (never asserted as passed).
    assert "full requested readiness remains open" in script
