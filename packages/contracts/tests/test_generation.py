import pytest
from kp_contracts.generation import (
    MAX_ATTACK_MAPPING_KEY_CHARS,
    MAX_GENERATED_BODY_CHARS,
    MAX_GENERATED_MODEL_ID_CHARS,
    MAX_GENERATED_SUBJECT_CHARS,
    MAX_GENERATION_REQUEST_BYTES,
    MAX_PATTERN_CONTEXT_FIELD_CHARS,
    MAX_PATTERN_LIST_ITEMS,
    TRAINING_URL_PLACEHOLDER,
    GenerationRequest,
    GenerationResponse,
    PatternContext,
)
from pydantic import ValidationError


def test_request_training_destination_is_a_non_navigable_literal_placeholder() -> None:
    request = GenerationRequest(
        pattern=PatternContext(pattern_id="pattern", lure_category="invoice"),
        as_of="2026-08-27T00:00:00+00:00",
    )

    assert request.training_url == TRAINING_URL_PLACEHOLDER
    assert "https://" not in request.model_dump_json()


def test_request_rejects_a_static_training_destination() -> None:
    with pytest.raises(ValidationError):
        GenerationRequest(
            pattern=PatternContext(pattern_id="pattern", lure_category="invoice"),
            as_of="2026-08-27T00:00:00+00:00",
            training_url="https://training.example/awareness",
        )


def test_request_context_rejects_oversized_fields_and_lists() -> None:
    with pytest.raises(ValidationError):
        PatternContext(
            pattern_id="pattern",
            lure_category="x" * (MAX_PATTERN_CONTEXT_FIELD_CHARS + 1),
        )
    with pytest.raises(ValidationError):
        PatternContext(
            pattern_id="pattern",
            lure_category="invoice",
            warning_cues=["cue"] * (MAX_PATTERN_LIST_ITEMS + 1),
        )


@pytest.mark.parametrize(
    "attack_mapping",
    [
        {"x" * (MAX_ATTACK_MAPPING_KEY_CHARS + 1): "value"},
        {1: "value"},
        {"score": float("inf")},
        {"object": object()},
        {"too_deep": {"a": {"b": {"c": {"d": "value"}}}}},
    ],
)
def test_request_context_rejects_unbounded_or_non_json_attack_mapping(attack_mapping: object) -> None:
    with pytest.raises(ValidationError):
        PatternContext.model_validate(
            {"pattern_id": "pattern", "lure_category": "invoice", "attack_mapping": attack_mapping}
        )


def test_request_rejects_aggregate_serialized_overflow() -> None:
    attack_mapping = {f"key-{index}": [["x" * 100 for _ in range(20)] for _ in range(20)] for index in range(32)}
    with pytest.raises(ValidationError, match="maximum serialized size"):
        GenerationRequest(
            pattern=PatternContext(pattern_id="pattern", lure_category="invoice", attack_mapping=attack_mapping),
            as_of="2026-08-27T00:00:00+00:00",
        )
    # Pin the boundary itself so an accidental multi-megabyte allowance cannot
    # silently turn the above adversarial case into accepted provider input.
    assert MAX_GENERATION_REQUEST_BYTES == 64 * 1024


def test_response_accepts_placeholder_in_both_message_bodies() -> None:
    response = GenerationResponse(
        subject="Security awareness exercise",
        plain_text=f"Review: {TRAINING_URL_PLACEHOLDER}",
        safe_html=f'<a href="{TRAINING_URL_PLACEHOLDER}">Review</a>',
        model_id="normal-model",
    )

    assert response.plain_text.endswith(TRAINING_URL_PLACEHOLDER)


def _valid_response_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "subject": "Security awareness exercise",
        "plain_text": f"Review: {TRAINING_URL_PLACEHOLDER}",
        "safe_html": f'<a href="{TRAINING_URL_PLACEHOLDER}">Review</a>',
        "model_id": "llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M",
    }
    payload.update(overrides)
    return payload


def test_response_schema_requires_model_id_for_schema_constrained_decoding() -> None:
    """The schema handed to a strict decoder must force the model identity.

    ``GenerationResponse.model_json_schema()`` is passed verbatim as an OpenAI
    ``response_format: {"type": "json_schema", ..., "strict": True}``. A field
    absent from ``required`` may be legitimately omitted by a fully compliant
    model, so the identity the worker pins against has to be listed there.
    """

    schema = GenerationResponse.model_json_schema()

    assert schema["required"] == ["subject", "plain_text", "safe_html", "model_id"]
    # No default: nothing in the schema may suggest a substitute identity.
    assert "default" not in schema["properties"]["model_id"]
    assert schema["properties"]["model_id"]["minLength"] == 1
    assert schema["properties"]["model_id"]["maxLength"] == MAX_GENERATED_MODEL_ID_CHARS


def test_response_rejects_an_omitted_model_id_instead_of_inventing_one() -> None:
    """An absent identity is a contract rejection, never a defaulted string.

    A silent default would be compared, constant-time, against the configured
    ``KP_WORKER_AI_MODEL_ID`` pin and persisted onto ``TemplateVersion.model_id``
    as though the gateway had reported it.
    """

    payload = _valid_response_payload()
    del payload["model_id"]

    with pytest.raises(ValidationError) as excinfo:
        GenerationResponse.model_validate(payload)

    errors = excinfo.value.errors()
    assert [error["loc"] for error in errors] == [("model_id",)]
    assert errors[0]["type"] == "missing"


def test_response_rejects_an_empty_model_id() -> None:
    """ "Present but empty" carries no identity and must not pass as one."""

    with pytest.raises(ValidationError):
        GenerationResponse.model_validate(_valid_response_payload(model_id=""))


def test_response_round_trips_a_supplied_model_id_unchanged() -> None:
    payload = _valid_response_payload()

    response = GenerationResponse.model_validate(payload)

    assert response.model_id == "llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M"
    assert response.model_dump() == payload
    # The persisted draft carries exactly what the gateway reported.
    assert GenerationResponse.model_validate(response.model_dump()).model_id == response.model_id


def test_response_limits_match_template_preview_and_database_boundaries() -> None:
    response = GenerationResponse(
        subject="s" * MAX_GENERATED_SUBJECT_CHARS,
        plain_text=TRAINING_URL_PLACEHOLDER + "p" * (MAX_GENERATED_BODY_CHARS - len(TRAINING_URL_PLACEHOLDER)),
        safe_html=TRAINING_URL_PLACEHOLDER + "h" * (MAX_GENERATED_BODY_CHARS - len(TRAINING_URL_PLACEHOLDER)),
        model_id="m" * MAX_GENERATED_MODEL_ID_CHARS,
    )

    assert len(response.subject) == 998
    assert len(response.plain_text) == 200_000
    assert len(response.safe_html) == 200_000
    assert len(response.model_id) == 128


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("subject", "s" * (MAX_GENERATED_SUBJECT_CHARS + 1)),
        ("plain_text", "p" * (MAX_GENERATED_BODY_CHARS + 1)),
        ("safe_html", "h" * (MAX_GENERATED_BODY_CHARS + 1)),
        ("model_id", "m" * (MAX_GENERATED_MODEL_ID_CHARS + 1)),
    ],
)
def test_response_rejects_content_beyond_storage_or_preview_limits(field: str, value: str) -> None:
    payload = {
        "subject": "Security awareness exercise",
        "plain_text": f"Review: {TRAINING_URL_PLACEHOLDER}",
        "safe_html": f'<a href="{TRAINING_URL_PLACEHOLDER}">Review</a>',
        "model_id": "normal-model",
        field: value,
    }

    with pytest.raises(ValidationError):
        GenerationResponse.model_validate(payload)
