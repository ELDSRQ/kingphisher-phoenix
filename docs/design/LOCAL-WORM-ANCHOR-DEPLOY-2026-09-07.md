# Local WORM audit anchor — deployed on .105 (2026-09-07)

**Status:** DEPLOYED and producing anchors. Supersedes the claim in
`NEXT_SESSION_HANDOFF.md` that local WORM anchors were already running — the
`AZURE-RESIDENCY-AUDIT-2026-09.md` finding was correct: they were not.

## What was actually wrong

`/root/kingphisher-phoenix` on `.105` is a **plain non-git copy**, and it was a
snapshot from roughly 2026-09-05. It predated AUD-003 entirely: `worker-audit-anchor`
was absent from `scripts/supervisor.py`, as were `proof_send` and the `KP_DEV_STACK`
handling. The anchor was not "misconfigured" — the code that runs it was not there.

## Deployment performed

1. **Snapshot for rollback** — `/root/kp-preworm-<UTC>.tar.gz` (4.7 GB; it includes the
   Qwen GGUF under `data/`. Delete it once you are satisfied: `rm /root/kp-preworm-*.tar.gz`).
2. **Synced HEAD's tracked files** — `git archive --format=tar HEAD | ssh … "wsl -e tar xf - -C /root/kingphisher-phoenix"`.
   Tracked files only, so untracked `.env`, `.venv/` and `data/` survive. Verified `.env`
   and `KP_DEV_STACK=1` were preserved.
3. **`uv sync --frozen --all-packages`** — note `uv` is NOT on the non-interactive PATH;
   it lives at `/root/.local/bin/uv`, so `export PATH="/root/.local/bin:$PATH"` first.
4. **Migrated the database 0033 → 0038.** See the defect below — this step breaks the
   audit chain on an existing install until grants are re-applied.
5. **Configured the local WORM provider** in `.env`:
   ```
   KP_WORKER_AUDIT_ANCHOR_PROVIDER=local_worm
   KP_WORKER_AUDIT_ANCHOR_LOCAL_DIR=/root/kp-audit-anchors
   KP_WORKER_AUDIT_ANCHOR_INTERVAL_SECONDS=300
   ```
   The directory is deliberately **outside the repo tree** so a repo re-sync cannot
   truncate the evidence, and so it can later be moved onto a genuinely separate,
   immutable volume — which is the only thing that makes "WORM" more than a name.
6. **Restarted the supervisor** — 11 children, including `worker-audit-anchor`.

## Verified

- Anchor written: `/root/kp-audit-anchors/v1/00000000000000002584-8f5509785d8fb83d9cfe47a53ce4ae580c4890ecd325e9f2ed8f8ab0a90abdd7.json`
  (sequence + chain-head hash, the AUD-003 shape).
- `operator /readyz` 200, `tracking /readyz` 200, `/console/` 200.
- Operator log reports `audit_chain_verified`.

## DEFECT FOUND — migration 0035 strips audit_writer on an EXISTING install

Mid-deploy the operator returned **503** with `audit_chain_verification_error`
(`ProgrammingError: permission denied for table audit_events`).

`0035_audit_owner_separation` transfers ownership of `audit_events` and
`audit_chain_head` to the NOLOGIN `audit_owner`. Transferring ownership **removes the
previous owner's implicit privileges**, and the migration does not re-grant the LOGIN
`audit_writer`. On a *fresh* install this is invisible, because
`infrastructure/containers/postgres-init/001-roles.sh` runs at container init and
issues the grants. On an **existing** install, upgrading past 0035 leaves `audit_writer`
with no SELECT/INSERT at all, and every audit-chain verification fails closed.

Measured immediately after the upgrade:

| privilege | before re-grant |
|---|---|
| `audit_events` SELECT | false |
| `audit_events` INSERT | false |
| `audit_chain_head` SELECT | false |

Recovered with the grants a deploy applies (least privilege preserved — DELETE stays
denied):

```sql
GRANT USAGE ON SCHEMA public TO audit_writer;
GRANT SELECT, INSERT ON public.audit_events, public.audit_chain_head TO audit_writer;
GRANT UPDATE ON public.audit_chain_head TO audit_writer;
```

(Apply with `docker exec -i …` — without `-i`, stdin never reaches `psql` and the
heredoc silently does nothing while appearing to succeed.)

**This is a real upgrade-path defect, not a local quirk.** Anyone applying 0035 to a
live database hits it. It is tracked as **AUD-004** in `docs/WAVE-BUILD-PLAN.md`. The
fix belongs in the migration (re-grant after `OWNER TO`, guarded on the role existing),
with a test that upgrades a database *through* 0035 and asserts `audit_writer` retains
SELECT/INSERT and still lacks DELETE.

## Caveats — what this is NOT

The local provider's own docstring disclaims equivalence with locked-immutability blob
storage, and that disclaimer stands. `/root/kp-audit-anchors` is an ordinary directory
on the same host and filesystem as the application: root can delete it, and deleting it
silently restarts the chain. It is tamper-*evident* only to the extent that whoever
holds the evidence is not the attacker. Treat it as a local development and
demonstration facility, not as the compliance-grade witness the Azure locked container
provides.
