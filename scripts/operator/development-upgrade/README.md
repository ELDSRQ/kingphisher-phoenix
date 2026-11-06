# Additive development runtime upgrade on the current WSL2 worker

This coordinator is for the existing `/home/builder/phishing-awareness-platform`
development runtime on `.105` only. It has not been executed against that runtime.
The reviewed engine, seven existing container IDs, original source revision,
unit and loopback database endpoints are checked before any normal action. A
different host, engine, source, mount identity, service override, configuration,
nonterminal send or pending outbox blocks progress. It never selects another
Docker context.

Use the exact final qualified source, after CI, final image and native full-stack
gates. An operator supplies a private JSON source manifest with this shape:

```json
{
  "commit": "<exact 40-character final commit>",
  "schema_head": "<single Alembic head of that source>",
  "gates": {"ci": true, "images": true, "fullstack": true},
  "files": {"pyproject.toml": "<sha256>", "uv.lock": "<sha256>", "scripts/supervisor.py": "<sha256>"}
}
```

`files` must contain the complete qualified source and browser assets, including
this coordinator; the abbreviated example is not a release manifest. Manifest
members cannot include `.git`, `.venv`, `.env`, `data`, symlinks or parent paths.
Record its SHA-256 separately. The coordinator verifies all listed bytes and
uses the manifest's dynamically validated Alembic head; it does not pin a stale
schema revision. Gate booleans are an operator assertion linked to the final
commit, not a substitute for the actual private gate receipts.

Run each phase separately on `.105`, using an already available interpreter
with this project's dependencies. The coordinator itself must be the reviewed
version. Without `--execute` every invocation is a plan-only no-op, including
target probes. Namespace example:

```text
python scripts/operator/development-upgrade/run.py prepare \
  --run /home/builder/qualification/development-upgrade-20261106T190000Z-abc12345 \
  --source /home/builder/qualification/<exact-qualified-source> \
  --manifest /home/builder/qualification/<private-manifest.json> \
  --manifest-sha256 <sha256> --commit <final-commit> --execute
```

After prepare, the remaining commands take only the same `--run` and explicit
`--execute`. No phase implicitly invokes the next:

1. `prepare` copies the qualified files into a new private release under
   `/home/builder/kp-runtime-releases/<commit>-<run-suffix>/source`, makes a fresh
   frozen workspace environment there, copies the original private `.env` and
   binds only the new `data` symlink to the existing project's data directory.
   The source checkout, old `.venv`, `.env`, unit, override and data are untouched.
   Only the new release environment is synchronized. Existing names fail closed.
   Before creating the release, read-only preflight checks encrypted entity row
   counts, Redis key/memory totals, archive file counts/symlinks and computed free
   space. Required headroom includes 8 GiB plus twice the project archive size,
   three times PostgreSQL database size and four times Redis memory. The same
   checks repeat before stopping the service, so a predictable unsupported layout
   or size bound does not strand the running application.
2. `checkpoint` first checks the workload boundary, stops only the existing
   native `kp-supervisor.service`, confirms its cgroup is empty, and repeats the
   boundary check. PostgreSQL custom dump and globals, a completed Redis RDB,
   `.env`, override, complete project `data` (including logs and audit witnesses)
   and the original unit are captured privately on the worker. Per-file archive
   hashes, database counts/audit head and hashed Redis values/expiries bind the
   checkpoint. Live private payloads must stay on the worker.
   Read-only queue statistics for every canonical topic are recorded before stop
   and after quiescence. Delivery, reply-mailbox and alert ready/processing/delayed
   counts must all be zero. Dead letters and maintenance work are reported and
   preserved, never cleared/replayed. The checkpoint hash in the later review
   receipt binds this concrete queue snapshot; counts are rechecked at cutover.
   The active service's cgroup identity must be captured before stopping. If
   systemd clears `ControlGroup` after stop, all surviving captured service
   cgroups and descendants are still checked for remaining processes.
3. `rehearse` keeps the normal application stopped. It creates fresh uniquely
   named, labeled PostgreSQL and Redis volumes/containers from the existing
   native image IDs, publishing only random loopback ports. No existing volume
   is reused. Globals and the database are restored before the exact source
   head is applied to the clone. Original table counts must survive. Both the
   old and new interpreters must read/decrypt all encrypted entity types and
   verify the audit chain on the clone, with read-only database sessions.
   The Redis RDB passes `redis-check-rdb` and is actually loaded into a separate
   Redis instance; persistent values and unexpired keys must match. Expiry while
   stopped is allowed. No application worker or provider call runs on a clone.
4. Review the private checkpoint, rehearsal and existing workload before
   `cutover`. In particular, resuming workers can resume existing lifecycle,
   retention, reminder, directory and provider work; rehearsal does not execute
   or qualify those side effects. Record the concrete review privately as
   `reviewed-cutover.json` in the run directory:

   ```json
   {"passed": true, "commit": "<same-final-commit>",
    "checkpoint_sha256": "<sha256 of checkpoint.json>",
    "rehearsal_sha256": "<sha256 of rehearsal.json>",
    "scope": "additive_schema_and_resume_existing_native_runtime"}
   ```

   `cutover` rechecks the exact private checkpoint/source/configuration and
   quiescence, applies only the exact forward Alembic head in place, and checks
   original row counts again. It adds one uniquely owned service drop-in, then
   reloads and starts that one native service. The drop-in runs the new Python
   with a clean environment and pins the new source, venv and private `.env`.
   The original unit remains unchanged. The existing PostgreSQL and Redis
   containers, IDs, mounts, databases and data directory retain their identities.
   Immediately before migration, a fresh bounded logical Redis inventory must
   also match the checkpoint, allowing natural expiry only. Unchanged queue
   counts alone cannot authorize changed maintenance payloads or other state.
   The clean service environment explicitly pins
   `DOCKER_HOST=unix:///var/run/docker.sock`; copied configuration with a
   conflicting host/context/TLS/config path is refused before service stop.
   All database aliases, including `KP_WORKER_DATABASE_URL_<ROLE>`, are checked
   case-insensitively. Ambiguous case duplicates and copied or ambient libpq
   `PG*` overrides fail closed before direct database preflight or service stop.
5. `verify` checks the owned drop-in, unchanged container/mount identities,
   audit and ciphertext readability, both API readiness endpoints, the exact
   served UI bytes and all thirteen child processes' source/venv identities.
   It does not create campaigns or send business messages.

All commands have phase and subprocess deadlines. A failed phase preserves
every file/container/volume and may intentionally leave the normal application
stopped. Inspect private receipts before any further action; there is no
automatic retry that overwrites a partial checkpoint, resource or service file.
The Redis checkpoint invokes `BGSAVE` on the existing normal Redis but never
replaces its volume or reloads it. No password rotation, role bootstrap, seed,
installer, Compose, image pull, cleanup, downgrade or automatic database restore
exists in this workflow. Failed or completed rehearsal assets remain preserved.

The old-code proof establishes read/decryption/audit compatibility only. It does
not establish that old application code enforces newly introduced security
state, supports new feature writes or provides a safe write rollback after
cutover. The original source/environment/unit remain available for a separately
reviewed recovery plan. Do not automatically restart old code against a changed
database or downgrade migrations (the retention-hold migration forbids it).

The coordinator deliberately stops at unsupported layouts: external data/key
symlinks in the archive, a nonlocal database, unexpected role/config resolution,
more than 500,000 Redis keys or 256 MiB Redis memory, more than 20,000 archive
files, an encrypted entity type exceeding 10,000 rows, or inadequate disk.
Redis inventory uses batches of at most 500 keys, a 120-second deadline and a
512 MiB logical-value budget. Type-aware canonical hashing preserves list,
sorted-set and stream order while ignoring hash/set storage ordering. Raw stream
field pairs retain duplicates. Redis modules are refused during preflight.
Its private hashed inventory is a separate
checkpoint file, supporting the observed 150,042-key development dataset.
Preserve the evidence and extend the reviewed
scope if needed; do not clean assets to make the upgrade fit. Mailpit and other
infrastructure containers are preserved in place; this is a development runtime
upgrade, not a clean-machine or production disaster-recovery qualification.

Hermetic checks:

```text
pytest tests/test_development_upgrade_preservation.py
ruff check scripts/operator/development-upgrade tests/test_development_upgrade_preservation.py
mypy scripts/operator/development-upgrade apps/operator-api/src/kp_operator_api/config.py
```
