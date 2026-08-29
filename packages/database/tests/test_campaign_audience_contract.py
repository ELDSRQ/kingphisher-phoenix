from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from kp_database import campaign_service
from kp_database.campaign_service import AudienceDefinition, audience_definition_hash, normalize_audience_definition
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError


def test_audience_definition_is_canonical_and_seeded() -> None:
    first = uuid.uuid4()
    second = uuid.uuid4()
    definition = AudienceDefinition(
        group_ids=(second, first, second),
        departments=("Security", " security ", "Finance"),
        statuses=(dm.RecipientStatus.ACTIVE, dm.RecipientStatus.ACTIVE),
        include_recipient_ids=(second, first),
        sample_size=2,
        sample_seed=" rsa-pilot-2026 ",
    )

    normalized = normalize_audience_definition(definition)

    assert normalized.group_ids == tuple(sorted({first, second}, key=str))
    assert normalized.include_recipient_ids == tuple(sorted({first, second}, key=str))
    assert normalized.sample_seed == "rsa-pilot-2026"
    assert audience_definition_hash(definition) == audience_definition_hash(normalized)


def test_random_sample_requires_explicit_seed() -> None:
    with pytest.raises(ValueError, match="sample_seed"):
        normalize_audience_definition(AudienceDefinition(sample_size=10))


def test_preview_rejects_an_internally_inconsistent_sample_definition(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Session:
        def get(self, _model: object, _identifier: object) -> object:
            return SimpleNamespace(legacy_requires_configuration=False)

    monkeypatch.setattr(
        campaign_service,
        "audience_definition",
        lambda _audience: AudienceDefinition(sample_size=1, sample_seed=None),
    )

    with pytest.raises(ConflictError, match="configuration is malformed"):
        campaign_service.preview_campaign_audience(
            _Session(),  # type: ignore[arg-type]
            SimpleNamespace(campaign_id=uuid.uuid4()),  # type: ignore[arg-type]
            allowed_domains=frozenset(),
            roe_options=(),
        )


def test_audience_selector_input_is_bounded() -> None:
    recipient_ids = tuple(uuid.uuid4() for _ in range(10_001))

    with pytest.raises(ValueError, match="10,000"):
        normalize_audience_definition(AudienceDefinition(include_recipient_ids=recipient_ids))
