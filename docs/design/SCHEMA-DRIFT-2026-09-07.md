# ORM ↔ migration schema drift (2026-09-07)

**Status:** 1 real defect (fix landed here), 5 false positives (recommendation, not fixed).
**Found by:** `packages/database/tests/test_migration_autogenerate_drift.py::test_head_schema_has_no_pending_model_additions`,
run against a real PostgreSQL for the first time on 2026-09-07.
**Why it went unnoticed:** the drift test is new (added by AUD-002 this session) and is
`postgres`-marked, so it never ran in the hermetic suite; the postgres gate itself was
manual-only until OPS-002 wired it into CI, and had never passed.

## What the test reported

`compare_metadata()` against a migrated-to-head database returned six pending changes:

```
add_constraint  UniqueConstraint(delivery_provider_events.external_event_id_hash)
add_constraint  UniqueConstraint(delivery_report_correlations.recipient_assignment_id)
add_constraint  UniqueConstraint(delivery_report_correlations.verifier_hash)
add_constraint  UniqueConstraint(training_assignments.training_token_hash)
add_constraint  UniqueConstraint(training_assignments.training_completion_token_hash)
modify_type     training_resources.knowledge_options  JSON -> JSONB
```

## Verification method

The shared `kingphisher_test` database is **not** authoritative — parts of the suite have
historically built it with `Base.metadata.create_all()`, which reproduces the ORM rather than
the migrations, so it agrees with the ORM by construction. Every claim below was instead checked
on a **freshly created database migrated with `alembic upgrade head`**:

```
createdb kp_driftcheck && DATABASE_URL=<url> python -m alembic upgrade head
```

then inspected via `pg_constraint` / `pg_indexes` / `information_schema.columns`.

## Finding 1 (REAL) — `training_resources.knowledge_options` is `json`, the ORM says `jsonb`

| Source | Type |
|---|---|
| `packages/database/alembic/versions/0033_training_knowledge_check.py` | `sa.Column("knowledge_options", sa.JSON(), nullable=True)` → PostgreSQL `json` |
| `packages/database/src/kp_database/models.py:1200` | `mapped_column(JSONB, nullable=True)` → PostgreSQL `jsonb` |

Confirmed on the freshly-migrated database: `information_schema.columns.data_type = 'json'`.

**Why it matters.** `json` and `jsonb` are different types, not aliases:

- `jsonb` supports GIN indexing and the containment operators (`@>`, `?`); `json` does not. Any
  future index or containment query on this column silently has no plan to use.
- Equality works on `jsonb` but **not** on `json` (PostgreSQL provides no `json` equality
  operator), so a `WHERE knowledge_options = …` or a `DISTINCT`/`GROUP BY` over the column
  raises `operator does not exist: json = json` at runtime rather than at deploy time.
- SQLAlchemy emits `jsonb`-typed bind parameters and casts for a `JSONB` column. Today the
  round-trip happens to work because psycopg adapts both, but the mismatch is latent: the ORM's
  declared contract is not what the database enforces.

This column carries the training knowledge-check answer options, read back to render the quiz.
It is not a security boundary, but it is a correctness contract the database does not currently
honour.

**Fix:** migration `0037_knowledge_options_jsonb` — `ALTER TABLE training_resources ALTER COLUMN
knowledge_options TYPE jsonb USING knowledge_options::jsonb`. Data-preserving and reversible
(the downgrade casts back to `json`).

## Finding 2 (FALSE POSITIVE ×5) — the unique constraints already exist

All five constraints are present in a freshly-migrated database:

| Column | `pg_constraint` (u/p) | unique index |
|---|---|---|
| `delivery_provider_events.external_event_id_hash` | 1 | 1 |
| `delivery_report_correlations.recipient_assignment_id` | 2 | 2 |
| `delivery_report_correlations.verifier_hash` | 1 | 1 |
| `training_assignments.training_token_hash` | 1 | 1 |
| `training_assignments.training_completion_token_hash` | 1 | 1 |

So **integrity is intact** — this is autogenerate noise, not a missing constraint. That matters,
because a genuinely missing unique constraint on `training_token_hash` /
`training_completion_token_hash` (training bearer identity) or on
`external_event_id_hash` (provider-receipt idempotency, i.e. double-processing a delivery
receipt) would be serious. It is not the case here.

The noise comes from Alembic comparing an ORM column-level `unique=True` (which renders as an
anonymous `UniqueConstraint`) against a reflected, *named* constraint/index it cannot associate
with the model declaration, even though `MetaData(naming_convention=NAMING_CONVENTION)` is set
(`packages/database/src/kp_database/base.py:16`) — several of these predate the convention.

**Recommended fix (NOT done here — it should be a deliberate, separately reviewed change):**
prefer one of

1. declare these as explicit named `UniqueConstraint(...)` in `__table_args__` so the model and
   the migration agree on a name; or
2. teach the drift test's comparison to ignore an `add_constraint` whose columns are already
   covered by an existing unique constraint or unique index (the test already filters `remove_*`
   for DB-managed objects it deliberately does not model).

Option 1 is the honest fix; option 2 alone would mask a genuinely missing constraint and should
only supplement it.

## Provenance

The `unique=True` declarations trace to `d25313d` ("Wave 38 checkpoint: retention integration at
head 0032 with ORM parity") — **before** the 2026-09 review wave. The `knowledge_options`
mismatch dates to migration `0033`. Neither was introduced by the 2026-09 tasks; the new drift
test simply detected them for the first time.

## Related

- `docs/design/TST-002-TEST-EFFECT-UPLIFT.md` — why postgres fixtures now build from the real
  migration chain rather than `create_all()`, which is what makes drift like this observable.
- `docs/WAVE-BUILD-PLAN.md` — postgres gate status.
