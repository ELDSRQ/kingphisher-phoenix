"""Contract-first event schemas and validation.

Implements the reconstructed spec §9 and §11: a versioned JSON-Schema registry,
a typed envelope for every queue message, and an idempotency-key contract.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import jsonschema
from pydantic import BaseModel, ConfigDict, Field

SCHEMA_PATTERN = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+@\d+\.\d+$")

# Known event types mapped to schema files. New events require a registry entry.
_EVENT_SCHEMAS: dict[str, dict[str, Any]] = {
    "campaign.send_batch": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "campaign_id": {"type": "string", "format": "uuid"},
            "batch_size": {"type": "integer", "minimum": 1},
            "manifest_hash": {"type": "string", "minLength": 32},
        },
        "required": ["campaign_id", "batch_size", "manifest_hash"],
    },
    "campaign.recall": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "recall_campaign_id": {"type": "string", "format": "uuid"},
            "recall_of": {"type": "string", "format": "uuid"},
            "reason": {"type": "string"},
        },
        "required": ["recall_campaign_id", "recall_of"],
    },
    "events.tracking": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "event_id": {"type": "string", "format": "uuid"},
            "event_type": {"type": "string"},
            "token_prefix": {"type": "string", "minLength": 6, "maxLength": 6},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            "occurred_at": {"type": "string"},
        },
        "required": ["event_id", "event_type", "occurred_at"],
    },
    "reports.ingested": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "message_id": {"type": "string"},
            "kind": {"type": "string", "enum": ["real", "simulated"]},
            "sender_domain": {"type": "string"},
            "received_at": {"type": "string"},
        },
        "required": ["message_id", "kind"],
    },
    "retention.run": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "policy_id": {"type": "string", "format": "uuid"},
            "idempotency_key": {"type": "string"},
        },
        "required": ["policy_id", "idempotency_key"],
    },
    "training.remind": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "campaign_id": {"type": "string", "format": "uuid"},
            "age_days": {"type": "integer"},
        },
        "required": ["campaign_id"],
    },
}


class EventEnvelope(BaseModel):
    """§11.1 envelope. At-least-once delivery; exactly-once effect via idempotency_key."""

    model_config = ConfigDict(extra="forbid")

    # `schema` intentionally shadows pydantic's deprecated classmethod; type-ignore by design.
    schema: str = Field(description="schema name@version, e.g. campaign.send_batch@1.0")  # type: ignore[assignment]
    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    idempotency_key: str
    trace_id: UUID = Field(default_factory=uuid4)
    payload: dict[str, Any]


class SchemaRegistry:
    """Validates queue payloads against the versioned schema registry."""

    def __init__(self, schemas: dict[str, dict[str, Any]] | None = None) -> None:
        self._schemas = schemas or dict(_EVENT_SCHEMAS)

    @property
    def event_types(self) -> tuple[str, ...]:
        return tuple(self._schemas)

    def has(self, schema_name: str) -> bool:
        return schema_name in self._schemas

    def validate(self, schema_name: str, payload: dict[str, Any]) -> None:
        if not SCHEMA_PATTERN.match(schema_name):
            raise ContractError(f"invalid schema name: {schema_name!r}")
        base_name = schema_name.split("@", 1)[0]
        if base_name not in self._schemas:
            raise ContractError(f"unknown schema: {schema_name}")
        jsonschema.validate(instance=payload, schema=self._schemas[base_name])

    def validate_envelope(self, envelope: EventEnvelope) -> None:
        self.validate(envelope.schema, envelope.payload)


class ContractError(ValueError):
    """Raised on schema or envelope contract violations (KP-010)."""


def build_envelope(schema: str, idempotency_key: str, payload: dict[str, Any]) -> EventEnvelope:
    if not SCHEMA_PATTERN.match(schema):
        raise ContractError(f"invalid schema name: {schema!r}")
    return EventEnvelope(schema=schema, idempotency_key=idempotency_key, payload=payload)


def schema_json(schema_name: str) -> str:
    """Return the canonical schema document for a schema name (no version suffix)."""
    base_name = schema_name.split("@", 1)[0]
    if base_name not in _EVENT_SCHEMAS:
        raise ContractError(f"unknown schema: {schema_name}")
    return json.dumps(_EVENT_SCHEMAS[base_name], indent=2)
