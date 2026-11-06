from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import Response
from kp_operator_api import program_routes
from kp_operator_api.program_routes import ProgramIterationCreate, _adaptation_payload
from pydantic import ValidationError


@pytest.mark.parametrize("value", [True, False, "2", 1, 13, 2.0])
def test_iteration_request_requires_a_bounded_actual_integer(value) -> None:
    with pytest.raises(ValidationError):
        ProgramIterationCreate(expected_iteration=value)


def test_adaptation_response_does_not_expose_roster_ids_or_unknown_fields() -> None:
    item = SimpleNamespace(
        iteration_number=2,
        iteration_campaign_id=uuid4(),
        basis_campaign_id=uuid4(),
        signals={"accepted": 4, "human_clicked": 1, "private": "recipient-secret"},
        changes={
            "prior_level": 2,
            "next_level": 1,
            "difficulty_delta": -1,
            "rationale": "Synthetic counts",
            "private": "recipient-secret",
        },
        enrollment={
            "base_population": 5,
            "enrolled": 4,
            "excluded_opt_out_ids": ["recipient-secret"],
            "excluded_scanner_only_ids": ["scanner-secret"],
        },
    )

    result = _adaptation_payload(item)

    assert "recipient-secret" not in str(result)
    assert "scanner-secret" not in str(result)
    assert result["enrollment"] == {
        "base_population": 5,
        "enrolled": 4,
        "excluded_opt_out": 0,
        "excluded_scanner_only": 0,
    }
    assert result["content_changed"] is False
    assert result["scope"] == "enrollment_and_difficulty_metadata"


def test_manual_iteration_keeps_requesting_principal_and_audits_draft_only(monkeypatch) -> None:
    actor, program_id, campaign_id = uuid4(), uuid4(), uuid4()
    create = Mock(
        return_value=SimpleNamespace(
            created=True,
            reason="created",
            occurrence=SimpleNamespace(campaign_id=campaign_id),
            program=object(),
        )
    )
    monkeypatch.setattr(program_routes, "materialize_next_program_iteration", create)
    monkeypatch.setattr(program_routes, "_program_payload", lambda *_a, **_kw: {"state": "active"})
    audit, session, response = Mock(), Mock(), Response()

    result = program_routes.create_program_iteration(
        program_id,
        ProgramIterationCreate(expected_iteration=2),
        response,
        session=session,
        audit=audit,
        principal=SimpleNamespace(principal_id=str(actor)),
    )

    assert create.call_args.kwargs == {"program_id": program_id, "expected_iteration": 2, "created_by": actor}
    assert audit.record.call_args.kwargs["actor"] == str(actor)
    assert audit.record.call_args.kwargs["detail"]["state"] == "draft"
    session.commit.assert_called_once()
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    assert result["iteration_campaign_id"] == str(campaign_id)
