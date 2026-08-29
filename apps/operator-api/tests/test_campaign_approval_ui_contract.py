from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")


def test_console_explains_creator_plus_one_independent_approver() -> None:
    assert "The creator cannot approve either facet; one different authorized operator may complete both" in APP
    assert "One independent operator with both capabilities may complete both security and privacy facets" in APP
    assert "each decision remains separately recorded" in APP


def test_console_does_not_claim_a_third_person_is_required() -> None:
    assert "the two approvals must come from different people" not in APP
    assert "API enforces separate reviewers" not in APP
    assert "approval from different operators" not in APP
