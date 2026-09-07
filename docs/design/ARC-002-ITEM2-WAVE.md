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

## The one intentional behaviour change

`_launch_delivery_gate_reason` is currently evaluated inside the per-assignment loop, re-reading
and re-hashing a canary manifest of up to 10k rows **per recipient**. M1-C hoists it out. That
changes performance, not outcomes: the set of gated recipients must be identical, and the task
must prove it.

## Out of scope

Item 1 Phase 2 (retiring GUI GitHub-dispatch for runbook scripts), Item 3 (Postgres-only queue
evaluation), and any feature work.
