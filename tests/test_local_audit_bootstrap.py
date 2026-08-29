from __future__ import annotations

import hashlib
import hmac
import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from kp_auditing.audit import AuditWriter

SCRIPT = Path(__file__).parents[1] / "scripts" / "bootstrap_local_audit.py"


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("kp_local_audit_bootstrap", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _evidence(key: bytes) -> tuple[list[dict[str, Any]], dict[str, str]]:
    record = AuditWriter().append(
        actor="local-operator",
        action="campaign.created",
        object_type="campaign",
        object_id="example",
        detail={"safe": True},
        occurred_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    row = {**record.as_row(), "chain_version": 1}
    signature = hmac.new(key, record.event_hash.encode("ascii"), hashlib.sha256).hexdigest()
    return [row], {"event_hash": record.event_hash, "signature": signature}


def test_verified_legacy_chain_can_initialize_root() -> None:
    bootstrap = _module()
    key = b"k" * 32
    rows, head = _evidence(key)

    bootstrap.verify_legacy_chain(rows, head, key)


@pytest.mark.parametrize("tamper", ["event", "signature", "head"])
def test_unverified_preexisting_evidence_cannot_be_adopted(tamper: str) -> None:
    bootstrap = _module()
    key = b"k" * 32
    rows, head = _evidence(key)
    if tamper == "event":
        rows[0]["detail"] = {"safe": False}
    elif tamper == "signature":
        head["signature"] = "0" * 64
    else:
        head["event_hash"] = "f" * 64

    with pytest.raises(bootstrap.LocalAuditBootstrapError):
        bootstrap.verify_legacy_chain(rows, head, key)


def test_empty_database_without_head_can_initialize_root() -> None:
    bootstrap = _module()

    bootstrap.verify_legacy_chain([], None, b"k" * 32)


def test_empty_database_with_head_is_rejected() -> None:
    bootstrap = _module()

    with pytest.raises(bootstrap.LocalAuditBootstrapError):
        bootstrap.verify_legacy_chain([], {"event_hash": "0" * 64, "signature": "0" * 64}, b"k" * 32)


def test_launchers_bootstrap_audit_root_before_seed() -> None:
    scripts = Path(__file__).parents[1] / "scripts"
    for launcher in (scripts / "run_console.sh", scripts / "install.sh"):
        source = launcher.read_text(encoding="utf-8")
        bootstrap_index = source.index("python scripts/bootstrap_local_audit.py")
        seed_index = source.index("python scripts/seed.py")
        assert bootstrap_index < seed_index


def test_seed_stages_audit_intent_through_business_engine() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "seed.py").read_text(encoding="utf-8")

    assert "intent_engine=engine" in source
    assert "session=session" in source
    assert "CipherText.configure_keyring(DEV_KEK_ID, DEV_KEK, DEV_PRIOR_KEKS)" in source
    assert "CipherText.configure_key(DEV_KEK)" not in source
    assert "max_recipients=100_000" not in source
    assert source.count("max_recipients=10_000") == 2
    assert "configure_campaign_audience(session, campaign, definition)" in source
    assert "preview_campaign_audience(" in source
    assert "freeze_campaign_audience(session, campaign, preview" in source
    freeze_index = source.index("_freeze_seed_campaign(session, campaign, recipients, roe)")
    review_index = source.index("launch_gate = bind_campaign_launch_review(", freeze_index)
    approvals_index = source.index("_seed_approvals(", review_index)
    assert freeze_index < review_index < approvals_index


def test_local_bootstrap_grants_only_dispatch_and_evidence_read_to_audit_writer() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "GRANT SELECT ON TABLE audit_events, audit_chain_head TO audit_writer" in source
    assert "kp_dispatch_pending_audit(integer)" in source
    assert "kp_verify_audit_head() TO audit_writer" in source
    assert "REVOKE ALL PRIVILEGES ON TABLE audit_integrity_secret, transactional_outbox FROM audit_writer" in source
