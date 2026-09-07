# AUD-003: the audit chain did not bind its own columns (2026-09)

Status: **confirmed real, fixed**. Verified by execution against a real
PostgreSQL 16.14 server, on disposable databases taken to Alembic head by the
real migration chain — not by reading code.

## The claim under investigation

> Under the migrated schema, audit events are written by
> `kp_dispatch_audit_outbox` at `chain_version = 2`, and `AuditStore.verify()`
> re-hashes the STORED `canonical_payload` for v2 rows. An UPDATE that tampers
> with the actor/action/detail COLUMNS is therefore invisible to verification,
> because `verify()` never rebuilds canonical bytes from the columns and
> compares.

## Verdict: REAL

Nothing bound the columns to `canonical_payload`. Confirmed on three axes:

1. **No database-side binding exists.** `audit_events` has no trigger, no rule,
   no generated column and no CHECK constraint tying `actor`/`action`/
   `object_*`/`detail`/`occurred_at`/`origin_role` to `canonical_payload`.
   `kp_dispatch_audit_outbox` (migration `0020_transactional_audit_outbox`) is
   the only definition of the writer anywhere in the tree, and it simply INSERTs
   the columns and the canonical text side by side. Nothing revisits them.
2. **`verify()` never rebuilt canonical from the columns.** The v2 branch hashed
   `prev_hash || canonical_payload || nonce`, so it bound exactly those three
   values and nothing else.
3. **Demonstrated end to end.** On a migrated disposable database: record one
   v2 event, `verify() == []`; `UPDATE audit_events SET actor='attacker',
   action='campaign.delete', detail='{"scope":"everything"}'`; `verify()`
   **still returned `[]`**.

### It was worse than reported

The read path and the integrity path disagreed silently. In the same run,
after the column-only UPDATE:

```
post-tamper verify():   []
post-tamper list_events(): [{'actor': 'attacker', 'action': 'campaign.delete',
                             'detail': {'scope': 'everything'}, ...}]
```

`list_events()` — what an operator, an export, or an investigator actually
reads — served the rewritten record while the chain certified itself intact.
The tamper-evidence property was not merely weak on those columns; it actively
vouched for the forged version. The exposure also covers `object_type`,
`object_id`, `occurred_at` and `origin_role`, not just the three fields named in
the report.

Chain-v1 rows were never affected: the v1 branch already rebuilds canonical
bytes from the columns via `canonical_bytes(...)`. The regression arrived with
the v2 (database-resident) writer, and the previous test fixture could not see
it because `create_all()` produced v1 rows.

## The fix

`verify()` now rebuilds the v2 canonical payload from the row's own columns and
compares it to the stored `canonical_payload` before hashing. A mismatch is
reported as `columns do not match recorded canonical evidence at <row>`.

The rebuild is evaluated **in the database, by the same expression the writer
uses** (`kp_database.audit_store._v2_canonical_from_columns`). This is the point
the original code comment deferred on, and it is why the fix is safe: the
canonical text is `jsonb_build_object(...)::text`, so its key ordering, number
normalisation, unicode escaping and separator style are PostgreSQL `jsonb`'s,
not `json.dumps`'. Re-emitting those bytes from Python would have produced
false integrity failures across the whole chain. Asking the same server to
evaluate the same expression cannot.

Detection is now strictly stronger and never weaker:

* the previous `prev_hash`/`nonce`/`canonical_payload` hash check is unchanged
  and still runs — a `canonical_payload` rewrite is now reported twice, once by
  each check;
* a v2 row with a NULL `canonical_payload` is reported instead of raising a
  `TypeError` out of `verify()` (previously it crashed the whole verification);
* no new write capability is introduced anywhere. The change is one extra
  read-only expression in an existing `SELECT`.

### The `origin_role` wrinkle (deliberate, and the one residual gap)

`AUDIT_ANCHOR_COLUMN_GRANTS` in `kp_database/grants.py` gives the read-only
audit-anchor role column-scoped `SELECT` on `audit_events` covering every
canonical field **except `origin_role`**, and that role runs `verify()` (via
`kp_workers.audit_anchor_jobs.verified_audit_head`). PostgreSQL checks column
privileges for every referenced column, so naming `origin_role` unconditionally
would have turned the anchor worker's verification into a permission error —
trading a tamper-evidence gap for an outage.

`verify()` therefore probes `has_column_privilege(...)` once and binds
`origin_role` from the column when the reader can see it (`audit_writer`, i.e.
the operator-API scheduler and `scripts/verify_audit.py`), falling back to
taking that one field from the recorded canonical text when it cannot. Every
other canonical field is bound from the columns in both cases.

**Residual gap, needs a decision:** for a reader that cannot see `origin_role`
— today, the audit-anchor role — an UPDATE of the `origin_role` column *alone*
is still not reported, even though `list_events()` surfaces that column. Closing
it means adding `"origin_role"` to `AUDIT_ANCHOR_COLUMN_GRANTS["audit_events"]`
(plus the bootstrap/grant re-issue and the emitter/probe agreement that file
guards). `grants.py` was outside this change's write allowlist, so it was not
touched. `origin_role` is a role name, not evidence content or PII, so granting
`SELECT` on it to a read-only evidence reader looks uncontroversial — but it is
a privilege change and belongs to whoever owns the grant surface.

## Evidence

Every result below was produced against the live PostgreSQL 16.14 instance, on
`isolated_migrated_database(...)` databases built by `alembic upgrade head` and
dropped afterwards. No test assertion was weakened.

Before the fix, one event, column-only UPDATE:

```
baseline verify():      []
post-tamper verify():   []          <-- tamper invisible
VERDICT: GAP REAL (tamper undetected)
```

After the fix, five events chosen to stress `jsonb` text normalisation (empty
detail, nested objects/arrays/nulls, floats, a 13-digit integer, unicode and
embedded quotes/backslashes, keys that sort differently by length than
alphabetically), each tamper applied and then reverted:

```
baseline verify(): []
baseline mismatches (column path, payload path): ([], [])     <-- no false positives
actor       column: verify()=1 problem(s)  column_path=[hit]  payload_path=[hit]
action      column: verify()=1 problem(s)  column_path=[hit]  payload_path=[hit]
object_id   column: verify()=1 problem(s)  column_path=[hit]  payload_path=[hit]
detail      column: verify()=1 problem(s)  column_path=[hit]  payload_path=[hit]
occurred_at column: verify()=1 problem(s)  column_path=[hit]  payload_path=[hit]
origin_role column: verify()=1 problem(s)  column_path=[hit]  payload_path=[]   <-- documented residual
canonical_payload tamper -> 2 problems (binding + hash)
```

Each revert returned `verify()` to `[]`, so the check is exact rather than
sticky.

The column-scoped path was additionally exercised for privilege (not just
semantics) by `packages/database/tests/test_audit_anchor_permissions.py::
test_anchor_role_can_verify_and_snapshot_but_cannot_mutate_or_read_secrets`,
which builds the real column-grant set and calls `verify()`. It passes.

## Regression test

`packages/database/tests/test_audit_store.py::
test_verify_detects_tampering_with_recorded_chain_material` now covers both
directions: the column-only rewrite (which additionally asserts that
`canonical_payload` was left intact, so the hash check alone cannot be what
catches it, and that `list_events()` would have served the forged actor), and
the existing `canonical_payload` rewrite.

That test connects as `audit_writer`, whose login is currently unusable on the
development server (see below), so it could not be executed here. Its assertions
were instead executed verbatim against the same migrated schema through the
migration credential, with the store constructed exactly as `_bound_store` does
(no legacy HMAC key, so the owner-only direct-INSERT fallback stays off and
every event goes through the migrated `kp_dispatch_*` functions). It passes.

## Blocked: the 5 PostgreSQL gate failures are one environment fault

All five failures share a single root cause, and none of them is a code defect:

```
psycopg.OperationalError: connection failed: FATAL:
  password authentication failed for user "audit_writer"
```

* `test_audit_store.py` — all four tests, at the first `audit.record(...)`.
* `test_outbox_postgres.py::test_post_commit_dispatch_completes_queue_and_audit_intents`
  — same, via the `audit_engine` its store dispatches through; the visible
  `assert queue.messages == []` is downstream of the failed post-commit callback.

The `audit_writer` role exists and has `LOGIN` with a SCRAM verifier set, but
the password is not `audit_writer`. That value is what `.env`, `.env.example`,
`infrastructure/containers/postgres-init/001-roles.sh` (via
`AUDIT_WRITER_PASSWORD`) and both CI workflows all use, so **the server has
drifted from every checked-in source of truth** — the role was almost certainly
created by an earlier container init carrying a different `AUDIT_WRITER_PASSWORD`,
and `001-roles.sh` only creates it `IF NOT EXISTS`, so no later run corrects it.

Live services are currently connected to the `kingphisher` database as
`audit_writer`, so the working password exists somewhere in the deployed
environment. Recovering it requires host access, which this work was not
permitted to use.

**Decision needed (operator).** Either re-align the role with the checked-in
value on the development server:

```sql
ALTER ROLE audit_writer PASSWORD 'audit_writer';
```

(safe with respect to configuration — it makes the server match `.env`,
`.env.example` and CI — but it will break any live connection that reconnects
holding the current, drifted password), or supply the real password for
`AUDIT_DATABASE_URL_TEST`. Either unblocks all five tests. Nothing in the
application code needs to change for them.

These four `test_audit_store.py` failures are the long-standing baseline
(4 failed / 88 passed at `811bba0`); the `test_outbox_postgres.py` one has the
same cause. The sixth failure in the gate,
`test_migration_autogenerate_drift.py::test_head_schema_has_no_pending_model_additions`,
is unrelated and was not investigated here.
