# ARC-002 Item 2 — god-module decomposition wave

**Scope:** ARC-002 Item 2 only (see `docs/design/SIMPLIFICATION-ARC-002.md`). Item 1 Phase 1 is
already landed (`d254e9c`); Item 1 Phase 2 and Item 3 are **not** in this wave.
**Launched onto a deliberately quiet tree:** `24d6362`, CI green on both jobs, no other agents
running, working tree clean. This is maintenance-only — no feature work runs alongside it.

## Why a dedicated wave

Every target is a hot file that absorbed security-critical change in the 2026-09 waves
(`routers.py`: AUT-002, UX-011, §2b proof send; `jobs.py`: DEL-002, AUT-002, §2b). Running a
large behaviour-preserving refactor concurrently with feature work is how conflict-resolution
mistakes happen — this session already produced two (a reverted `srcdoc` preview and a shadowed
`reason` variable) from exactly that pressure. So: nothing else in flight.

## Current sizes

| File | Lines |
|---|---|
| `apps/operator-api/src/kp_operator_api/routers.py` | 5,301 |
| `apps/operator-api/src/kp_operator_api/console.py` | 3,696 |
| `apps/workers/src/kp_workers/jobs.py` | 2,673 |

## Conflict matrix

`routers.py` and `console.py` are different files but **both register in `main.py`**
(`main.py:46,49` imports; `main.py:666,671` `include_router`) and both are covered by
`test_route_authorization_inventory.py`. Splitting either edits both. They therefore **conflict**
and must not run concurrently. `jobs.py` is in a different application and shares no file with
them.

| Task | Writes | Conflicts with |
|---|---|---|
| **M1-A** routers.py split | `routers.py`, new `routes/*.py`, `main.py`, operator-api tests | M2-B |
| **M1-C** process_delivery split | `jobs.py`, workers tests | — |
| **M2-B** console.py split | `console.py`, new modules, `main.py`, operator-api tests | M1-A |

**Schedule:** M1-A ∥ M1-C (disjoint) → land → M2-B on the freed tree.

## Invariants every task must hold

1. **Pure moves.** No logic change, no renamed behaviour, no altered validation. Splitting only.
2. **The authorization surface cannot move.** `test_route_authorization_inventory.py` is the
   guard: the same routes with the same capabilities, unchanged. A pure move keeps it untouched.
3. **The delivery gate SEQUENCE is a safety invariant** (`SIMPLIFICATION-ARC-002.md` says so
   explicitly). M1-C may reorganise `process_delivery` into phases but must not reorder which gate
   runs when, nor which recipients are gated.
4. **No security-relevant helper may be duplicated** while splitting — extract or import, never
   copy. (Item 4 of the design doc exists precisely because drifted copies already cost the
   operator a middleware.)
5. **All three CI gates run locally before proposing:** `make lint`, `make typecheck`,
   `scripts/run-hermetic-tests.sh all`. This session lost several hours to gating on `make test`
   alone, which runs none of the other two.

## The proposed hoist — ATTEMPTED, PROVEN UNSAFE, REFUSED (2026-09-07)

This plan originally told M1-C to hoist `_launch_delivery_gate_reason` out of the per-assignment
loop, on the assumption it was a redundant re-computation. **That assumption is wrong. Do not
re-attempt it.**

`_claim_delivery` and `_durable_delivery_correlation` each `session.commit()` inside the loop,
*before* the gate re-check. Every iteration is therefore a NEW transaction that re-acquires
`CampaignLaunchGate ... FOR UPDATE`. The in-loop call is a concurrency/time re-check — the
launch-gate member of the deliberate stop-race trio (campaign state -> launch gate -> emergency
stop) that sits between the claim and the provider call. Hoisting it blinds delivery to a gate
that expires (`canary_expires_at <= now`), is flipped to `canary_failed` by a concurrent
`_refresh_canary_evidence`, or whose canary manifest changes mid-batch.

Demonstrated empirically, not merely argued: with the hoist applied,
`test_launch_gate_is_re_evaluated_for_every_recipient_of_a_batch` failed
`assert [True, True, True] == [True]` — the worker **sent real mail to all three recipients of a
batch whose gate was revoked after the first**. The pre-existing sequence guard
(`test_campaign_canary_gate.py::test_worker_rechecks_gate_before_initial_and_per_assignment_provider_boundaries`)
also failed. The experiment was reverted; regression tests pinning this now live in
`apps/workers/tests/test_delivery_gate_hoist.py`.

**The underlying cost is real and still open.** Up to 10k canary rows are read and hashed per
recipient. Safe directions that do NOT weaken the gate: push the drift comparison into SQL (a
digest aggregate or an `EXISTS` against a stored hash column), or narrow the row scan. Both are
rewrites of `_launch_delivery_gate_reason` rather than a move, so they belong to a separate,
reviewed task — not to a decomposition wave.

## The `_launch_delivery_gate_reason` cost — MEASURED, and deliberately NOT optimised (2026-09-07)

The hoist was refused as unsafe (above). The follow-up was to push the work into SQL instead.
That was implemented and run, and is **declined**. `jobs.py` is unchanged.

**The cost is real and now measured**, per recipient per loop iteration against a 10k-row manifest:

| | today |
|---|---|
| manifest rows read | 10,000 |
| Python CPU | 11.4 ms (8.53 ms building a 1,080,028-byte canonical JSON; sha256 itself is 0.47 ms) |

At `delivery_batch_size` 200 that is ~2,000,000 rows and ~2.3 s of Python per batch. A SQL
digest would cut rows read ~5000× (to one aggregate row plus one membership count).

**Why it is declined anyway:**

1. **It would duplicate a security-critical hash in a second language.**
   `gate.canary_manifest_hash` is
   `sha256(json.dumps({...}, sort_keys=True, separators=(",",":"), ensure_ascii=True))`.
   Reproducing that in PostgreSQL means reimplementing Python's canonical-JSON encoder:
   `to_json` does not escape non-ASCII where `ensure_ascii=True` does, and
   `json_build_array`/`jsonb` insert spaces and reorder keys. It happens to agree for today's
   data, but equality would rest on a data assumption (the column only constrains
   `length(recipient_hash) = 64`), not on the schema. That is precisely invariant 4 of this
   document — the invariant that exists because drifted copies of a security helper already cost
   this codebase a middleware.
2. **Equivalence cannot be verified here.** The digest is inert under the hermetic stubs, and
   `make test-postgres` needs Docker, which does not run on the controller. Landing it would mean
   shipping an unverified rewrite of the launch gate.
3. **The scale does not justify the risk.** The documented target is 125 recipients. Measurable,
   not pathological.

**What landed instead:** `apps/workers/tests/test_launch_gate_reason_golden.py` — 58 cases pinning
every refusal branch behaviourally through the real entry point (exact reason string, gate state
flip, `updated_at` touch, branch precedence), mutation-tested with five semantic mutants all
killed. This filled a genuine gap: twelve of the sixteen reasons were previously asserted only by
source-text grep. It is also the equivalence oracle any future SQL version must satisfy.

**If this is ever revisited** (i.e. scale grows well past 125), the prerequisites are: put the SQL
digest expression *next to* `campaign_canary_manifest_hash` in `packages/database` so the two
forms are maintained together rather than duplicated; make `_GateSession` in
`test_delivery_gate_hoist.py` statement-aware (it currently returns a bare `list`, so any
aggregate/`EXISTS` form fails on `.one()`); and add a `postgres`-marked equivalence test that runs
in CI.

## Out of scope

Item 1 Phase 2 (retiring GUI GitHub-dispatch for runbook scripts), Item 3 (Postgres-only queue
evaluation), and any feature work.
