"""Recipient confirmation exposes only test accounts in its exact preview."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from kp_database.campaign_service import AudiencePreviewRecipient
from kp_domain_models import models as dm
from kp_operator_api.routes import campaigns


def test_confirmation_test_accounts_are_scoped_to_the_validated_recipient_list(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    first, second = uuid4(), uuid4()
    preview = SimpleNamespace(
        campaign_id=uuid4(),
        audience_version=1,
        configuration_hash="configuration",
        preview_hash="preview",
        selected_count=3,
        excluded_counts={"roe": 1},
        sample_size=None,
        sample_seed=None,
        roe_id=uuid4(),
        over_limit=False,
        added_count=2,
        removed_count=0,
        unchanged_count=0,
        included=(
            AudiencePreviewRecipient(first, "hash-first", "f***@example.com", "Trial", dm.RecipientStatus.ACTIVE),
            AudiencePreviewRecipient(second, "hash-second", "s***@example.com", None, dm.RecipientStatus.ACTIVE),
        ),
    )
    monkeypatch.setattr(campaigns, "_get_campaign", lambda *_args: SimpleNamespace())
    monkeypatch.setattr(campaigns, "_audience_preview_for_request", lambda *_args: preview)

    class Session:
        def scalars(self, statement):  # type: ignore[no-untyped-def]
            compiled = statement.compile()
            assert [first, second] in compiled.params.values()
            assert "recipients.is_test_account IS true" in str(statement)
            assert "recipients.deleted_at IS NULL" in str(statement)
            assert dm.RecipientStatus.ACTIVE in compiled.params.values()
            return [first]

    result = campaigns.preview_campaign_audience_route(
        preview.campaign_id,
        request=SimpleNamespace(),
        session=Session(),
        principal=SimpleNamespace(),  # type: ignore[arg-type]
    )
    assert result["test_account_count"] == 1
    assert result["included_count"] == 2
    assert result["excluded_count"] == 1
    assert [item["is_test_account"] for item in result["recipients"]] == [True, False]
    assert [item["mailbox"] for item in result["recipients"]] == ["f***@example.com", "s***@example.com"]
    assert result["preview_hash"] == "preview"
