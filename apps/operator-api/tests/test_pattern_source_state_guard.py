import inspect
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from kp_database.models import Source, SourceItem, SourceTerms
from kp_domain_models import models as dm
from kp_operator_api.routers import _require_active_pattern_source, approve_pattern
from kp_telemetry.errors import SafetyRejectionError

SOURCE_ITEM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SOURCE_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
TERMS_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


class _Session:
    def __init__(self, responses: dict[object, object | None]) -> None:
        self.responses = responses
        self.lookups: list[tuple[object, UUID, bool, bool]] = []

    def get(
        self,
        model: object,
        identifier: UUID,
        *,
        with_for_update: bool = False,
        populate_existing: bool = False,
    ) -> object | None:
        self.lookups.append((model, identifier, with_for_update, populate_existing))
        return self.responses.get(model)


def _pattern(source_item_id: object = str(SOURCE_ITEM_ID)) -> SimpleNamespace:
    return SimpleNamespace(attack_mapping={"source_item_id": source_item_id})


def _governance_graph() -> dict[object, object]:
    now = datetime.now(UTC)
    return {
        SourceItem: SimpleNamespace(
            source_id=SOURCE_ID,
            license_state_id=TERMS_ID,
            quarantine_state=dm.QuarantineState.ACTIVE,
            duplicate_of=None,
        ),
        Source: SimpleNamespace(source_id=SOURCE_ID, license_state_id=TERMS_ID, enabled=True),
        SourceTerms: SimpleNamespace(
            source_terms_id=TERMS_ID,
            source_id=SOURCE_ID,
            commercial_use_ok=True,
            automation_ok=True,
            redistribution_ok=True,
            retention_ok=True,
            terms_reviewed_at=now - timedelta(days=1),
            next_review_at=now + timedelta(days=1),
            enabled=True,
        ),
    }


def test_manual_pattern_without_source_provenance_keeps_existing_review_path() -> None:
    session = _Session({})

    _require_active_pattern_source(session, SimpleNamespace(attack_mapping={"difficulty": {"score": 2}}))

    assert session.lookups == []


def test_source_backed_pattern_requires_locked_active_nonduplicate_evidence() -> None:
    session = _Session(_governance_graph())

    _require_active_pattern_source(session, _pattern())

    assert session.lookups == [
        (SourceItem, SOURCE_ITEM_ID, True, False),
        (Source, SOURCE_ID, True, True),
        (SourceTerms, TERMS_ID, True, True),
    ]


@pytest.mark.parametrize(
    "source_item",
    [
        None,
        SimpleNamespace(quarantine_state=dm.QuarantineState.QUARANTINED, duplicate_of=None),
        SimpleNamespace(quarantine_state=dm.QuarantineState.REJECTED, duplicate_of=None),
        SimpleNamespace(quarantine_state=dm.QuarantineState.ACTIVE, duplicate_of=SOURCE_ITEM_ID),
    ],
)
def test_source_backed_pattern_fails_closed_when_evidence_is_not_curated(source_item: object | None) -> None:
    with pytest.raises(SafetyRejectionError, match="source evidence is unavailable or not active"):
        _require_active_pattern_source(_Session({SourceItem: source_item}), _pattern())


@pytest.mark.parametrize("source_item_id", [None, 7, "not-a-uuid"])
def test_source_backed_pattern_fails_closed_on_invalid_provenance(source_item_id: object) -> None:
    with pytest.raises(SafetyRejectionError, match="source evidence is unavailable or not active"):
        _require_active_pattern_source(_Session({}), _pattern(source_item_id))


@pytest.mark.parametrize("governance_failure", ["source_disabled", "terms_disabled", "terms_expired", "terms_rebound"])
def test_source_backed_pattern_requires_current_source_governance(governance_failure: str) -> None:
    graph = _governance_graph()
    source = graph[Source]
    terms = graph[SourceTerms]
    if governance_failure == "source_disabled":
        source.enabled = False
    elif governance_failure == "terms_disabled":
        terms.enabled = False
    elif governance_failure == "terms_expired":
        terms.next_review_at = datetime.now(UTC) - timedelta(seconds=1)
    else:
        source.license_state_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

    with pytest.raises(SafetyRejectionError, match="source governance is not current"):
        _require_active_pattern_source(_Session(graph), _pattern())


def test_pattern_approval_uses_source_then_pattern_lock_order_and_rechecks_provenance() -> None:
    source = inspect.getsource(approve_pattern)

    source_lock = source.index("_require_active_pattern_source(session, pattern_snapshot)")
    pattern_lock = source.index("with_for_update=True")
    provenance_recheck = source.index("_pattern_source_item_id(pattern) != source_item_id")

    assert source_lock < pattern_lock < provenance_recheck
    assert "populate_existing=True" in source
